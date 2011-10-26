#ifndef _SLIST_H_
#define _SLIST_H_

#include "linux_list.h"

#define INIT_SLIST_HEAD(ptr) ((ptr).next = NULL)

struct slist_head {
	struct slist_head *next;
};

static inline int slist_empty(const struct slist_head *h)
{
	return !h->next;
}

static inline void slist_del(struct slist_head *t, struct slist_head *prev)
{
	prev->next = t->next;
	t->next = LIST_POISON1;
}

static inline void slist_add(struct slist_head *head, struct slist_head *t)
{
	struct slist_head *tmp = head->next;
	head->next = t;
	t->next = tmp;
}

#define slist_entry(ptr, type, member) container_of(ptr,type,member)

#define slist_for_each(pos, head) \
	for (pos = (head)->next; pos && ({ prefetch(pos.next); 1; }); \
	     pos = pos->next)

#define slist_for_each_safe(pos, prev, next, head) \
	for (pos = (head)->next, prev = (head); \
	     pos && ({ next = pos->next; 1; }); \
	     ({ prev = (prev->next != next) ? prev->next : prev; }), pos = next)

#endif
