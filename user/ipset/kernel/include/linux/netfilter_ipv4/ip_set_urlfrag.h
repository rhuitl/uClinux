#ifndef __IP_SET_URLFRAG_H
#define __IP_SET_URLFRAG_H

#include <linux/netfilter_ipv4/ip_set.h>

#define SETTYPE_NAME "urlfrag"

#define IPSET_FRAG_LEN			1024	/* Maximum length of a fragment */

#define IPSET_FRAG_COMPACTED		1

/* Define the basic TRIE node */
#define IPSET_FRAG_IWBITS		1
#define IPSET_FRAG_ARCBITS		18
#define IPSET_FRAG_CHARBITS		8

#ifndef __KERNEL__
#define Node(d, node)		((d)->_nodes + node)
#endif
#define IsWord(d, node)		(Node(d, node)->word)
#define IsLastArc(d, node)	(Node(d, node)->next == 0)
#define IsLeaf(d, node)		(Node(d, node)->arc == 0)
#define Letter(d, node)		(Node(d, node)->letter)
#define Arc(d, node)		(Node(d, node)->arc)
#define Next(d, node)		(Node(d, node)->next)
#define Data(d, node)		(Node(d, node)->data)

#define IPSET_FRAG_TRIE_SIZE		(1<<IPSET_FRAG_ARCBITS)

struct __attribute__ ((__packed__)) urlfrag_node {
	char letter;
	unsigned arc:IPSET_FRAG_ARCBITS;
	unsigned next:IPSET_FRAG_ARCBITS;
	unsigned word:IPSET_FRAG_IWBITS;
};


struct ip_set_urlfrag {
	u_int32_t nodecount;
	u_int32_t flags;
#ifdef __KERNEL__
	struct urlfrag_node *_nodes[0];
#else
	struct urlfrag_node _nodes[0]; 
#endif
};

struct ip_set_req_urlfrag_create {
	u_int32_t flags;
};

struct ip_set_req_urlfrag {
	ip_set_ip_t ip;
	char frag[IPSET_FRAG_LEN];
};

#endif	/* __IP_SET_URLFRAG_H */
