/*
 * (C) 2006-2007 by Pablo Neira Ayuso <pablo@netfilter.org>
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Description: generic hash table implementation
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include "slist.h"
#include "hash.h"


struct hashtable_node *hashtable_alloc_node(int datasize, void *data)
{
	struct hashtable_node *n;
	int size = sizeof(struct hashtable_node) + datasize;

	n = malloc(size);
	if (!n)
		return NULL;
	memset(n, 0, size);
	memcpy(n->data, data, datasize);

	return n;
}

void hashtable_destroy_node(struct hashtable_node *h)
{
	free(h);
}

struct hashtable *
hashtable_create(int hashsize, int limit, int datasize,
		 u_int32_t (*hash)(const void *data, struct hashtable *table),
		 int (*compare)(const void *data1, const void *data2))
{
	int i;
	struct hashtable *h;
	struct hashtype *t;
	int size = sizeof(struct hashtable)
		   + hashsize * sizeof(struct slist_head);

	h = (struct hashtable *) malloc(size);
	if (!h) {
		errno = ENOMEM;
		return NULL;
	}

	memset(h, 0, size);
	for (i=0; i<hashsize; i++)
		INIT_SLIST_HEAD(h->members[i]);

	h->hashsize = hashsize;
	h->limit = limit;
	h->datasize = datasize;
	h->hash = hash;
	h->compare = compare;

	return h;
}

void hashtable_destroy(struct hashtable *h)
{
	hashtable_flush(h);
	free(h);
}

void *hashtable_add(struct hashtable *table, void *data)
{
	struct slist_head *e;
	struct hashtable_node *n;
	u_int32_t id;
	int i;

	/* hash table is full */
	if (table->count >= table->limit) {
		errno = ENOSPC;
		return NULL;
	}

	id = table->hash(data, table);

	slist_for_each(e, &table->members[id]) {
		n = slist_entry(e, struct hashtable_node, head);
		if (table->compare(n->data, data)) {
			errno = EEXIST;
			return NULL;
		}
	}

	n = hashtable_alloc_node(table->datasize, data);
	if (n == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	slist_add(&table->members[id], &n->head);
	table->count++;

	return n->data;
}

void *hashtable_test(struct hashtable *table, const void *data)
{
	struct slist_head *e;
	u_int32_t id;
	struct hashtable_node *n;
	int i;

	id = table->hash(data, table);

	slist_for_each(e, &table->members[id]) {
		n = slist_entry(e, struct hashtable_node, head);
		if (table->compare(n->data, data))
			return n->data;
	}

	errno = ENOENT;
	return NULL;
}

int hashtable_del(struct hashtable *table, void *data)
{
	struct slist_head *e, *next, *prev;
	u_int32_t id;
	struct hashtable_node *n;
	int i;

	id = table->hash(data, table);

	slist_for_each_safe(e, prev, next, &table->members[id]) {
		n = slist_entry(e, struct hashtable_node, head);
		if (table->compare(n->data, data)) {
			slist_del(e, prev);
			hashtable_destroy_node(n);
			table->count--;
			return 0;
		}
	}
	errno = ENOENT;
	return -1;
}

int hashtable_flush(struct hashtable *table)
{
	int i;
	struct slist_head *e, *next, *prev;
	struct hashtable_node *n;

	for (i=0; i < table->hashsize; i++)
		slist_for_each_safe(e, prev, next, &table->members[i]) {
			n = slist_entry(e, struct hashtable_node, head);
			slist_del(e, prev);
			hashtable_destroy_node(n);
		}

	table->count = 0;
	
	return 0;
}

int hashtable_iterate(struct hashtable *table, void *data,
		      int (*iterate)(void *data1, void *data2))
{
	int i;
	struct slist_head *e, *next, *prev;
	struct hashtable_node *n;

	for (i=0; i < table->hashsize; i++) {
		slist_for_each_safe(e, prev, next, &table->members[i]) {
			n = slist_entry(e, struct hashtable_node, head);
			if (iterate(data, n->data) == -1)
				return -1;
		}
	}
	return 0;
}

unsigned int hashtable_counter(struct hashtable *table)
{
	return table->count;
}
