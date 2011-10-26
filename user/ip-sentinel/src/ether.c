// $Id: ether.c,v 1.8 2004/12/23 00:44:18 ensc Exp $    --*- c++ -*--

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

#include <net/ethernet.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>

static bool const	allow_leading_zeros = true;

#if defined(__dietlibc__) && !defined(HAVE_DIET_ETHER_ATON_R)
struct ether_addr *
ether_aton_r(const char *asc, struct ether_addr *addr)
{
  char const	*start;
  size_t	pos = 0;
  uint8_t *	res_pos = addr->ether_addr_octet+0;

  *res_pos = 0;

  assert(addr!=0);
  memset(addr, 0, sizeof *addr);
  
  for (start=asc; *start!='\0' && pos<6; ++start) {
    char	c   = *start;
    int		val = -1;
    
    if      (c>='0' && c<='9') val = c-'0';
    else if (c>='a' && c<='f') val = c-'a' + 10;
    else if (c>='A' && c<='F') val = c-'A' + 10;
    else if (c==':') {
      ++res_pos;
      ++pos;
      continue;
    }

    if (*res_pos>=16) return 0;	// overflow
    *res_pos <<= 4;
    *res_pos  += val;
  }

  if (pos==5 && *start=='\0') return addr;
  else                        return 0;
}
#endif

#if defined(__dietlibc__) && !defined(HAVE_DIET_ETHER_NTOA)

static char const	DEC2HEX[] = "0123456789abcdef";

char *
ether_ntoa(struct ether_addr const *addr)
{
  static char		buffer[18];
  char *		buf_ptr = buffer;
  uint8_t const *	pos = addr->ether_addr_octet+0;
  
  for (; pos<addr->ether_addr_octet+6; ++pos) {
    char	c = DEC2HEX[*pos>>4];

    if (allow_leading_zeros || c!='0') *buf_ptr++ = c;
    *buf_ptr++ = DEC2HEX[*pos & 0x0F];
    *buf_ptr++ = ':';
  }

  assert(buf_ptr == buffer+sizeof(buffer));
  buf_ptr[-1] = '\0';

  return buffer;
}
#endif
