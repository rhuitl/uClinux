// $Id: worker.h,v 1.4 2005/03/08 00:04:46 ensc Exp $    --*- c++ -*--

// Copyright (C) 2003 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
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

#ifndef H_IPSENTINEL_WORKER_H
#define H_IPSENTINEL_WORKER_H

#include "arguments.h"

struct RequestInfo;

struct Worker
{
      // the main -> worker pipe
    int			fd;

      // true iff packages coming *from* intruders shall result in a poisoning
      // of the intruders ip
    bool		do_poison;
    
      // the SOCKRAW socket
    int			sock;
      // the if-idx of the SOCKRAW socket
    int			if_idx;
      // the link-level mac-address sent when the arp-request
      // is coming *from* the intruder
    struct TaggedMac	llmac;

      // the action-command
    char const *	action_cmd;
};

void	Worker_init(struct Worker *, struct Arguments const *,
		    int sock, int if_idx);
void	Worker_free(struct Worker *);
void	Worker_sendJob(struct Worker *, struct RequestInfo const *);

#ifdef ENSC_TESTSUITE
struct ScheduleInfo;

void	Worker_printScheduleInfo(int fd, struct ScheduleInfo const *job);
void	Worker_debugFillPacket(struct Worker const *worker,
			       struct ScheduleInfo *job,
			       struct RequestInfo const *rq);
bool	Worker_debugPoisonJob(struct ScheduleInfo *job,
			      struct RequestInfo const *rq);
#endif

#endif	//  H_IPSENTINEL_WORKER_H
