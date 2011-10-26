// $Id: blacklist.h,v 1.10 2004/12/23 00:44:18 ensc Exp $    --*- c++ -*--

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

#ifndef H_IPSENTINEL_BLACKLIST_H
#define H_IPSENTINEL_BLACKLIST_H

#include "ensc_vector/vector.h"

#include <netinet/in.h>
#include <net/ethernet.h>
#include <time.h>
#include <stdbool.h>

struct Arguments;

typedef struct {
    struct Vector		ip_list;
    struct Vector		net_list;
    char const *		filename;
    time_t			last_mtime;

    struct Arguments const *	args_;
} BlackList;


  // WORKAROUND: the const's are disabled for now because of a gcc
  // optimization bug; for details, see
  // https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=110966
struct BlackListQuery {
    struct ether_addr			result_buffer_;
    struct in_addr const * /*const*/	ip;		/* in */
    struct ether_addr const * /*const*/	mac;		/* in */
    struct ether_addr const *		poison_mac;	/* out */
};


struct ether_addr const *
BlackList_getMac(BlackList const *lst, struct BlackListQuery *query);

void		BlackList_init(BlackList *lst, struct Arguments const *args);
void		BlackList_free(BlackList *);
void		BlackList_softUpdate(BlackList *lst);
void		BlackList_update(BlackList *lst);

#if !defined(NDEBUG) || defined(ENSC_TESTSUITE)
void		BlackList_print(BlackList *lst, int fd);
#endif


#endif	//  H_IPSENTINEL_BLACKLIST_H
