/*
 * (C) 2005 by Pablo Neira Ayuso <pablo@eurodev.net>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#ifndef _LIBNETFILTER_CONNTRACK_L3EXTENSIONS_H_
#define _LIBNETFILTER_CONNTRACK_L3EXTENSIONS_H_

#include "linux_list.h"

struct nfct_l3proto {
	struct list_head head;
	
	char 		*name;
	u_int16_t 	protonum;
	char		*version;
	
	void (*parse_proto)(struct nfattr **, struct nfct_tuple *);
	void (*build_tuple_proto)(struct nfnlhdr *, int, struct nfct_tuple *);
	int (*print_proto)(char *, struct nfct_tuple *);
	int (*compare)(struct nfct_conntrack *, struct nfct_conntrack *,
		       unsigned int);
};

extern void nfct_register_l3proto(struct nfct_l3proto *h);

#endif
