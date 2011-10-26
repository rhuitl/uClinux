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

#include <linux/netfilter_ipv4/ip_set_polynum.h>

static inline ip_set_ip_t get_polynum_count(const struct sk_buff *skb, const u_int32_t *flags) {
	__u32 *p = NULL;

	if (skb == NULL || skb->sk == NULL)
		return 0;

	if (flags[0] & IPSET_GROUPS)
		p = skb->sk->sk_authd_groups;
	else if (flags[0] & IPSET_TS_CATS)
		p = skb->sk->sk_authd_ts_categories;
	if (p != NULL)
		return *p;
	return 0;
}

static inline const ip_set_ip_t *get_polynum_list(const struct sk_buff *skb, const u_int32_t *flags) {
	__u32 *p = NULL;

	if (skb == NULL || skb->sk == NULL)
		return NULL;

	if (flags[0] & IPSET_GROUPS)
		p = skb->sk->sk_authd_groups;
	else if (flags[0] & IPSET_TS_CATS)
		p = skb->sk->sk_authd_ts_categories;
	if (p != NULL)
		return p+1;
	return NULL;
}


static inline int polynum_test(const struct ip_set *set, ip_set_ip_t ignored, int num, const ip_set_ip_t *list, const struct sk_buff *skb)
{
	const struct ip_set_polynum *map = set->data;
	int i;

	DP("set: %s, num:%u", set->name, num);
	for (i=0; i<num; i++) {
		const ip_set_ip_t e = list[i];

		DP("set: %s, elem[%d]:%u", set->name, i, e);
		if (e >= map->first_ip && e <= map->last_ip &&
				test_bit(e - map->first_ip, map->members)) {
			if (skb != NULL)
				skb->sk->sk_polynum_match = e;
			return !0;
		}
	}
	if (skb != NULL)
		skb->sk->sk_polynum_match = 0;
	return 0;
}

#define KADT_CONDITION							\
	const ip_set_ip_t *list = get_polynum_list(skb, flags);	\
									\
	if (list == NULL)						\
		return 0;
	
UADT(polynum, test, 1, &req->ip, NULL)
KADT(polynum, test, get_polynum_count, ip, list, skb)

static inline int
polynum_add(struct ip_set *set, ip_set_ip_t num)
{
	struct ip_set_polynum *map = set->data;

	if (num < map->first_ip || num > map->last_ip)
		return -ERANGE;
	if (test_and_set_bit(num - map->first_ip, map->members))
		return -EEXIST;
		
	DP("num %u", num);
	return 0;
}

UADT(polynum, add)
KADT(polynum, add, get_polynum_count)

static inline int
polynum_del(struct ip_set *set, ip_set_ip_t num)
{
	struct ip_set_polynum *map = set->data;

	if (num < map->first_ip || num > map->last_ip)
		return -ERANGE;
	if (!test_and_clear_bit(num - map->first_ip, map->members))
		return -EEXIST;
		
	DP("num %u", num);
	return 0;
}

UADT(polynum, del)
KADT(polynum, del, get_polynum_count)

static inline int
__polynum_create(const struct ip_set_req_polynum_create *req,
		 struct ip_set_polynum *map)
{
	if (req->to - req->from > MAX_RANGE) {
		ip_set_printk("range too big, %d elements (max %d)",
			      req->to - req->from + 1, MAX_RANGE+1);
		return -ENOEXEC;
	}
	return bitmap_bytes(req->from, req->to);
}

BITMAP_CREATE(polynum)
BITMAP_DESTROY(polynum)
BITMAP_FLUSH(polynum)

static inline void
__polynum_list_header(const struct ip_set_polynum *map,
		      struct ip_set_req_polynum_create *header)
{
}

BITMAP_LIST_HEADER(polynum)
BITMAP_LIST_MEMBERS_SIZE(polynum, struct ip_set_req_polynum,
			 (map->last_ip - map->first_ip + 1),
			 test_bit(i, map->members))

static void
polynum_list_members(const struct ip_set *set, void *data, char dont_align)
{
	const struct ip_set_polynum *map = set->data;
	uint32_t i, n = 0;
	ip_set_ip_t *d;

	if (dont_align) {
		memcpy(data, map->members, map->size);
		return;
	}

	for (i = 0; i < map->last_ip - map->first_ip + 1; i++)
		if (test_bit(i, map->members)) {
			d = data + n * IPSET_ALIGN(sizeof(ip_set_ip_t));
			*d = map->first_ip + i;
			n++;
		}
}

IP_SET_TYPE(polynum, IPSET_TYPE_PORT | IPSET_DATA_SINGLE)

MODULE_LICENSE("GPL ");
MODULE_AUTHOR("Dr Paul Dale");
MODULE_DESCRIPTION("polynum type of IP sets");

REGISTER_MODULE(polynum)
