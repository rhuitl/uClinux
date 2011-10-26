// $Id: simulate.c,v 1.8 2004/12/23 00:44:18 ensc Exp $    --*- c++ -*--

// Copyright (C) 2003,2004 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
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

#include "worker.h"
#include "arguments.h"
#include "blacklist.h"
#include "jobinfo.h"
#include "util.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <alloca.h>

int const	FD = 10;

struct ether_addr	local_mac_address = { { 127,0,0,1,0,0 } };

static void
xinet_aton(char const *cp, void *inp)
{
  if (inet_aton(cp, inp)==0) {
    WRITE_MSGSTR(2, "invalid IP ");
    WRITE_MSG   (2, cp);
    WRITE_MSGSTR(2, "\n");
    exit(1);
  }
}

static void
xether_aton(char const *asc, void *addr)
{
  if (xether_aton_r(asc,addr)==0) {
    WRITE_MSGSTR(2, "invalid MAC ");
    WRITE_MSG   (2, asc);
    WRITE_MSGSTR(2, "\n");
    exit(1);
  }
}

static void
printRequest(int fd, char const *spa, char const *sha, char const *tpa, char const *tha)
{
  WRITE_MSGSTR(fd, "[");
  WRITE_MSG   (fd, spa);
  WRITE_MSGSTR(fd, ",");
  WRITE_MSG   (fd, sha);
  WRITE_MSGSTR(fd, ", ");
  WRITE_MSG   (fd, tpa);
  WRITE_MSGSTR(fd, ",");
  WRITE_MSG   (fd, tha);
  WRITE_MSGSTR(fd, "]\n");
}

static void swap(void *a, void *b, size_t len)
{
  void	*tmp = alloca(len);

  memcpy(tmp, a, len);
  memcpy(a,   b, len);
  memcpy(b, tmp, len);
}

int main(int argc, char *argv[])
{
  struct Arguments		arguments;
  struct Worker			worker;
  BlackList			cfg;
  struct ether_addr const	*mac;
  char				spa[64], sha[64], tpa[64], tha[64];

  parseOptions(argc, argv, &arguments);
  Arguments_fixupOptions(&arguments);

  BlackList_init(&cfg, &arguments);

  worker.fd     = -1;
  worker.sock   = -1;
  worker.if_idx = -1;
  worker.llmac  = arguments.llmac;


  BlackList_print(&cfg, FD);
  WRITE_MSGSTR(FD, "\n");
  
  while (scanf("%s %s %s %s", spa, sha, tpa, tha)>0) {
    enum { stNORMAL, stREVERSE, stEXIT }	state = stNORMAL;

    if (spa[0]=='\0') continue;

    while (state!=stEXIT) {
      struct RequestInfo	rq;
      struct ScheduleInfo	job;
      struct ether_arp * const	arp = &rq.request;

      struct BlackListQuery	query_dst = {
	.ip  = (struct in_addr const *)arp->arp_tpa,
	.mac = 0
      };

      struct BlackListQuery	query_src = {
	.ip  = (struct in_addr const *)arp->arp_spa,
	.mac = (struct ether_addr const *)&rq.request.arp_sha,
      };
      
      switch (state) {
	case stNORMAL	:  break;
	case stREVERSE	:  swap(spa, tpa, sizeof spa); swap(sha, tha, sizeof tha); break;
	case stEXIT	:
	default		:  assert(false);
      }

      ++state;

      xinet_aton (spa, arp->arp_spa);
      xether_aton(sha, arp->arp_sha);
      xinet_aton (tpa, arp->arp_tpa);
      xether_aton(tha, arp->arp_tha);

      printRequest(FD, spa, sha, tpa, tha);

      WRITE_MSGSTR(FD, "  DST: ");
      mac = BlackList_getMac(&cfg, &query_dst);
      if (mac==0) WRITE_MSGSTR(FD, "MISS\n");
      else {
	rq.mac  = *mac;
	rq.type = jobDST;

	Worker_debugFillPacket(&worker, &job, &rq);
	Worker_printScheduleInfo(FD, &job);

	assert(!Worker_debugPoisonJob(&job, &rq));
      }

      WRITE_MSGSTR(FD, "  SRC: ");
      mac = BlackList_getMac(&cfg, &query_src);
      if (query_src.ip->s_addr==0) WRITE_MSGSTR(FD, "MISS (DAD)\n");
      else if (mac==0) WRITE_MSGSTR(FD, "MISS\n");
      else {
	rq.mac  = *mac;
	rq.type = jobSRC;
	if (query_src.poison_mac) {
	  rq.poison_mac.f = true;
	  rq.poison_mac.v = *query_src.poison_mac;
	}
	else
	  rq.poison_mac.f = false;

	Worker_debugFillPacket(&worker, &job, &rq);
	Worker_printScheduleInfo(FD, &job);
	
	WRITE_MSGSTR(FD, "  POI: ");
	if (Worker_debugPoisonJob(&job, &rq)) Worker_printScheduleInfo(FD, &job);
	else assert(false);
      }

      WRITE_MSGSTR(FD, "\n");
    }
  }

  return 0;
}
