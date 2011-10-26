/* Copyright (C) 2009 Dr Paul Dale <pauli@snapgear.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* Kernel module implementing an integer set type as a bitmap */

#include <linux/module.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <asm/uaccess.h>
#include <asm/bitops.h>
#include <linux/spinlock.h>

#include <net/ip.h>

#include <linux/netfilter_ipv4/ip_set_urlfrag.h>

#define NodeSize	(sizeof(struct urlfrag_node))
#define NodesPerPage	(PAGE_SIZE / NodeSize)
#define Pages(nodes)	DIV_ROUND_UP((nodes), NodesPerPage)
#define Node(d, node)	((d)->_nodes[(node)/NodesPerPage] + (node)%NodesPerPage)


extern inline const char *authd_url(const struct sk_buff *skb) {
	return skb->sk->sk_authd_url;
}


extern inline ip_set_ip_t get_nothing(const struct sk_buff *skb, const u_int32_t *f) {
	return 0;
}


static inline int urlfrag_test(struct ip_set *set, ip_set_ip_t ignored,
				const char *url)
{
	struct ip_set_urlfrag *trie = set->data;

	if (trie->nodecount == 0 || *url == '\0')
		return 0;

	for (;*url != '\0'; url++) {
		const char *w = url;
		unsigned int node = 0;
		for (;;) {
			if (Letter(trie, node) == *w) {
				if (IsWord(trie, node)) {
					return !0;
				}
				if(*++w == '\0')
					break;
				node = Arc(trie, node);
				if (node == 0)
					break;
			} else {
				if(IsLastArc(trie, node))
					break;
				node = Next(trie, node);
			}
		}
	}
	return 0;
}

#define KADT_CONDITION							\
	const char *url = authd_url(skb);				\
									\
	if (url == NULL)						\
		return 0;
	
UADT(urlfrag, test, req->frag)
KADT(urlfrag, test, get_nothing, url)


static unsigned int GetNewNode(struct ip_set_urlfrag *trie, char ch) {
	unsigned int node;

	if (trie->nodecount >= IPSET_FRAG_TRIE_SIZE)
		return -1;

	if (trie->nodecount % NodesPerPage == 0) {
		unsigned int page = trie->nodecount / NodesPerPage;
		trie->_nodes[page] = (struct urlfrag_node *)get_zeroed_page(GFP_ATOMIC);
		if (!trie->_nodes[page])
			return -1;
	}

	node = trie->nodecount++;
	Letter(trie, node) = ch;
	return node;
}


static inline int urlfrag_add(struct ip_set *set, ip_set_ip_t num, const char *word) {
	struct ip_set_urlfrag *trie = set->data;
	unsigned int node = 0, node2;

	if (word == NULL || *word == '\0')
		return -EINVAL;

	if(trie->nodecount == node) {
		node = GetNewNode(trie, *word);
		if (node == -1)
			return -ENOMEM;
	}
	while (*word != '\0') {
		if (Letter(trie, node) == *word) {
			/* Early exit if already in TRIE */
			if (IsWord(trie, node)) {
				return 0;
			}
			word++;
			if (*word == '\0') break;
			node2 = Arc(trie, node);
			if (node2 == 0) {
				node2 = GetNewNode(trie, *word);
				if (node2 == -1)
					return -ENOMEM;
				Arc(trie, node) = node2;
			}
			node = node2;
		} else {
			node2 = Next(trie, node);
			if (node2 == 0) {
				node2 = GetNewNode(trie, *word);
				if (node2 == -1)
					return -ENOMEM;
				Next(trie, node) = node2;
			}
			node = node2;
		}
	}
	Arc(trie, node) = 0;
	Node(trie, node)->word = 1;
	return 0;
}

UADT(urlfrag, add, req->frag)
KADT(urlfrag, add, get_nothing, NULL)

static inline int urlfrag_del(struct ip_set *set, ip_set_ip_t num, const char *w) {
	struct ip_set_urlfrag *trie = set->data;
	unsigned int node = 0;

	if (trie->nodecount == 0 || w == NULL || *w == '\0')
		return -EEXIST;
	for (;;) {
		if (Letter(trie, node) == *w) {
			if (*++w == '\0')
				break;
			node = Arc(trie, node);
		} else if (IsLastArc(trie, node))
			return -EEXIST;
		else
			node = Next(trie, node);
	}

	if (!IsWord(trie, node))
		return -EEXIST;
	Node(trie, node)->word = 0;
	return 0;
}

UADT(urlfrag, del, req->frag)
KADT(urlfrag, del, get_nothing, NULL)


static int urlfrag_create(struct ip_set *set, const void *data, u_int32_t size) {
	struct ip_set_urlfrag *trie;
	size_t bytes;

	bytes = sizeof(*trie) +
		sizeof(trie->_nodes[0]) * Pages(IPSET_FRAG_TRIE_SIZE);
	trie = kmalloc(bytes, GFP_KERNEL);
	if (!trie) {
		DP("out of memory for %zu bytes", bytes);
		return -ENOMEM;
	}
	trie->nodecount = 0;
	trie->flags = 0;
	set->data = trie;
	return 0;
}

static void urlfrag_free_pages(struct ip_set_urlfrag *trie) {
	unsigned int page;

	for (page = 0; page < Pages(trie->nodecount); page++)
		free_page((unsigned long)trie->_nodes[page]);
}

static void urlfrag_destroy(struct ip_set *set) {
	struct ip_set_urlfrag *trie = set->data;

	urlfrag_free_pages(trie);
	kfree(trie);
	set->data = NULL;
}


/* Empty the set.
 */
static void urlfrag_flush(struct ip_set *set) {
	struct ip_set_urlfrag *trie = set->data;
	urlfrag_free_pages(trie);
	trie->nodecount = 0;
}


/* Return the header used to create the set.
 * In our case, this means the flags since we've no other parameters.
 */
static void urlfrag_list_header(const struct ip_set *set, void *data) {
}


/* Count the number of entries in the trie.
 * Since we're not doing tail reduction, this equates to running through
 * all the nodes and locating that tagged as end of words.
 */
static int urlfrag_list_members_size(const struct ip_set *set, char dont_align) {
	const struct ip_set_urlfrag *trie = set->data;

	return sizeof(struct ip_set_urlfrag) +
		sizeof(struct urlfrag_node) * trie->nodecount;
}


static void urlfrag_list_members(const struct ip_set *set, void *data, char dont_align) {
	const struct ip_set_urlfrag *trie = set->data;
	unsigned int node;
	void *p = data;

	memcpy(p, trie, sizeof(*trie));
	p += sizeof(*trie);
	for (node = 0; node < trie->nodecount; node++) {
		const struct urlfrag_node *n = Node(trie, node);
		memcpy(p, n, sizeof(*n));
		p += sizeof(*n);
	}
}

struct ip_set_type ip_set_urlfrag = {					
	.typename		= "urlfrag",
	.features		= IPSET_DATA_SINGLE,
	.protocol_version	= IP_SET_PROTOCOL_VERSION,
	.create			= &urlfrag_create,
	.destroy		= &urlfrag_destroy,
	.flush			= &urlfrag_flush,
	.reqsize		= sizeof(struct ip_set_req_urlfrag),
	.addip			= &urlfrag_uadd,
	.addip_kernel		= &urlfrag_kadd,
	.delip			= &urlfrag_udel,
	.delip_kernel		= &urlfrag_kdel,
	.testip			= &urlfrag_utest,
	.testip_kernel		= &urlfrag_ktest,
	.header_size		= sizeof(struct ip_set_req_urlfrag_create),
	.list_header		= &urlfrag_list_header,
	.list_members_size	= &urlfrag_list_members_size,
	.list_members		= &urlfrag_list_members,
	.me			= THIS_MODULE,
};

MODULE_LICENSE("GPL ");
MODULE_AUTHOR("Dr Paul Dale");
MODULE_DESCRIPTION("urlfrag type of IP sets");

REGISTER_MODULE(urlfrag)
