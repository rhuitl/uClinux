// $Id: util.c,v 1.14 2005/03/29 15:49:58 ensc Exp $    --*- c++ -*--

// Copyright (C) 2002,2003,2004 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
//  
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//  
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//  
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
//  

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include "util.h"
#include "wrappers.h"
#include "ip-sentinel.h"
#include "parameters.h"
#include "fmt.h"

#include <netinet/ether.h>
#include <unistd.h>
#include <assert.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <time.h>

static struct ether_addr const	DEFAULT_MAC = { RANDOM_MAC_BASE };

void
writeMsgTimestamp(int fd)
{
  struct timeval                tv;

  if (fd==-1) return;
  
  (void)gettimeofday(&tv, 0);
  
  {
#ifdef ENABLE_LOGGING
    char                        buffer[16];
    time_t                      aux;
    struct tm                   tmval;
    size_t			fill_cnt = 1;
    
    (void)localtime_r(&tv.tv_sec, &tmval);
    if (strftime(buffer, sizeof buffer, "%T", &tmval)>0) {
      Vwrite(fd, buffer, strlen(buffer));
      
      aux  = tv.tv_usec;
      aux |= 1; // Prevent 'aux==0' which will cause an endless-loop below
      assert(aux>0);
  
      while (aux<100000) { ++fill_cnt; aux *= 10; }
      Vwrite(fd, "000000", fill_cnt-1);
      writeUInt(fd, static_cast(unsigned int)(tv.tv_usec));
    }
    else
#endif
    {
      char			buf[64];
      size_t			l = fmt_tai64n(buf, &tv);

      Vwrite(fd, buf, l);
    }
  }
}

void
writeUInt(int fd, unsigned int val)
{
  char			buf[sizeof(val)*3 + 3];
  size_t		l = fmt_uint(buf, val);

  Vwrite(fd, buf, l);
}

void
writeIP(int fd, struct in_addr ip)
{
  char const	*ip_str = inet_ntoa(ip);
  Vwrite(fd, ip_str, strlen(ip_str));
}

struct ether_addr *
xether_aton_r(char const *asc, struct ether_addr *addr)
{
  char const *mac;

  if (strcmp(asc, "LOCAL") ==0) {
    memcpy(addr, &local_mac_address, sizeof(*addr));
    return addr;
  }
  
  if      (strcmp(asc, "802.1d")==0) mac = "01:80:C2:00:00:00";
  else if (strcmp(asc, "802.3x")==0) mac = "01:80:C2:00:00:01";
  else mac = asc;

  return ether_aton_r(mac, addr);
}


void
Util_setRandomMac(struct ether_addr *res)
{
  time_t		t   = time(0);
  size_t const		idx = RANDOM_MAC_OCTET;

  *res                       = DEFAULT_MAC;
  res->ether_addr_octet[idx] = (rand()%BLACKLIST_RAND_COUNT +
				t/BLACKLIST_RAND_PERIOD)%256;
}
