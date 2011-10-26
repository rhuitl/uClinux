/* Copyright 2008 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * This program is free software; you can redistribute it and/or modify   
 * it under the terms of the GNU General Public License as published by   
 * the Free Software Foundation; either version 2 of the License, or      
 * (at your option) any later version.                                    
 *                                                                         
 * This program is distributed in the hope that it will be useful,        
 * but WITHOUT ANY WARRANTY; without even the implied warranty of         
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          
 * GNU General Public License for more details.                           
 *                                                                         
 * You should have received a copy of the GNU General Public License      
 * along with this program; if not, write to the Free Software            
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <stdio.h>				/* *printf */
#include <string.h>				/* mem*, str* */
#include <stdlib.h>				/* qsort */

#include "ipset.h"

#include <linux/netfilter_ipv4/ip_set_urlfrag.h>


#define OPT_CREATE_HASHSIZE	0x01U
#define OPT_CREATE_PROBES	0x02U
#define OPT_CREATE_RESIZE	0x04U
#define OPT_CREATE_NETWORK	0x08U
#define OPT_CREATE_FROM		0x10U
#define OPT_CREATE_TO		0x20U



/* To output the set we need some helpers */

#define FLAG_SORT	1
#define FLAG_SAVE	2

struct node_info {
	unsigned int	node;
	char		ch;
};


/* Initialize the create. */
static void urlfrag_create_init(void *data) {
	struct ip_set_req_urlfrag_create *mydata = data;

	DP("create INIT");
	mydata->flags = 0;
}

/* Function which parses command options; returns true if it ate an option */
static int urlfrag_create_parse(int c, char *argv[] UNUSED, void *data, unsigned *flags) {
	return 0;
}

/* Final check; exit if not ok. */
static void urlfrag_create_final(void *data, unsigned int flags) {
}


/* Create commandline options */
static const struct option create_opts[] = {
	{NULL},
};

/* Add, del, test parser */
static ip_set_ip_t adt_parser(int cmd, const char *arg, void *data) {
	struct ip_set_req_urlfrag *mydata = data;

	strncpy(mydata->frag, arg, IPSET_FRAG_LEN-1);
	mydata->frag[IPSET_FRAG_LEN-1] = '\0';
	return 1;
};

/*
 * Print and save
 */
static void urlfrag_initheader(struct set *set, const void *data) {
	const struct ip_set_req_urlfrag_create *header = data;
	struct ip_set_urlfrag *map = set->settype->header;

	memset(map, 0, sizeof(struct ip_set_urlfrag));
	map->flags = header->flags;
}

static void urlfrag_printheader(struct set *set, unsigned options) {
	printf("\n");
}

static int dump_cmp(const void *v1, const void *v2) {
	const struct node_info *n1 = (const struct node_info *)v1;
	const struct node_info *n2 = (const struct node_info *)v2;
	if (n1->ch > n2->ch)
		return 1;
	if (n1->ch == n2->ch)
		return 0;
	return -1;
}

static void dump(unsigned int node, struct ip_set_urlfrag *trie, int flags, short widx, char word[], char *name) {
	int numarc;
	unsigned int n;
	int i;

	if (node >= trie->nodecount)
		return;

	/* Figure out how many arcs from this branch */
	for (numarc = 1, n = node; !IsLastArc(trie, n); n = Next(trie, n))
		numarc++;

	/* Create a table of arcs */
	struct node_info arcs[numarc];

	i = 0;
	for (i = 0, n = node; ; n = Next(trie, n)) {
		arcs[i].node = n;
		arcs[i++].ch = Letter(trie, n);
		if (IsLastArc(trie, n))
			break;
	}

	/* Optionally sort the table of arcs */
	if (flags & FLAG_SORT)
		qsort(arcs, numarc, sizeof(struct node_info), &dump_cmp);

	/* Output the table of arcs and recurse if required */
	for (i=0; i<numarc; i++) {
		n = arcs[i].node;
		word[widx] = arcs[i].ch;
		if (IsWord(trie, n)) {
			word[widx+1] = '\0';
			if (flags & FLAG_SAVE) {
				printf("-A %s %s\n", name, word);
			} else {
				printf("%s\n", word);
			}
		}
		if (Arc(trie, n))
			dump(Arc(trie, n), trie, flags, widx+1, word, name);
	}
}

static void urlfrag_printips(struct set *set, void *data, u_int32_t len, unsigned options, char dont_align) {
	struct ip_set_urlfrag *trie = data;
	char word[IPSET_FRAG_LEN];

	dump(0, trie, 0, 0, word, set->name);
}

static void urlfrag_printips_sorted(struct set *set, void *data, u_int32_t len, unsigned options, char dont_align) {
	struct ip_set_urlfrag *trie = data;
	char word[IPSET_FRAG_LEN];

	dump(0, trie, FLAG_SORT, 0, word, set->name);
}

static void urlfrag_saveheader(struct set *set, unsigned options) {
	printf("-N %s %s\n", set->name, set->settype->typename);
}

/* Print save for an IP */
static void urlfrag_saveips(struct set *set, void *data, u_int32_t len, unsigned options, char dont_align) {
	struct ip_set_urlfrag *trie = data;
	char word[IPSET_FRAG_LEN];

	dump(0, trie, FLAG_SAVE, 0, word, set->name);
}

static void urlfrag_usage(void) {
	printf("-N set urlfrag\n"
	     "-A set fragment\n"
	     "-D set fragment\n"
	     "-T set fragment\n");
}

static struct settype settype_urlfrag = {
	.typename = SETTYPE_NAME,
	.protocol_version = IP_SET_PROTOCOL_VERSION,

	/* Create */
	.create_size = sizeof(struct ip_set_req_urlfrag_create),
	.create_init = urlfrag_create_init,
	.create_parse = urlfrag_create_parse,
	.create_final = urlfrag_create_final,
	.create_opts = create_opts,

	/* Add/del/test */
	.adt_size = sizeof(struct ip_set_req_urlfrag),
	.adt_parser = &adt_parser,

	/* Printing */
	.header_size = sizeof(struct ip_set_urlfrag),
	.initheader = urlfrag_initheader,
	.printheader = urlfrag_printheader,
	.printips = urlfrag_printips,
	.printips_sorted = urlfrag_printips_sorted,
	.saveheader = urlfrag_saveheader,
	.saveips = urlfrag_saveips,
	
	.usage = urlfrag_usage,
};

CONSTRUCTOR(urlfrag) {
	settype_register(&settype_urlfrag);

}
