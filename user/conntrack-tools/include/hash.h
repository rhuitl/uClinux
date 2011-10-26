#ifndef _NF_SET_HASH_H_
#define _NF_SET_HASH_H_

#include <unistd.h>
#include <sys/types.h>
#include "slist.h"
#include "linux_list.h"

struct hashtable;
struct hashtable_node;

struct hashtable {
	u_int32_t hashsize;
	u_int32_t limit;
	u_int32_t count;
	u_int32_t initval;
	u_int32_t datasize;
	
	u_int32_t	(*hash)(const void *data, struct hashtable *table);
	int		(*compare)(const void *data1, const void *data2);

	struct slist_head 	members[0];
};

struct hashtable_node {
	struct slist_head head;
	char data[0];
};

struct hashtable_node *hashtable_alloc_node(int datasize, void *data);
void hashtable_destroy_node(struct hashtable_node *h);

struct hashtable *
hashtable_create(int hashsize, int limit, int datasize,
		 u_int32_t (*hash)(const void *data, struct hashtable *table),
		 int (*compare)(const void *data1, const void *data2));
void hashtable_destroy(struct hashtable *h);

void *hashtable_add(struct hashtable *table, void *data);
void *hashtable_test(struct hashtable *table, const void *data);
int hashtable_del(struct hashtable *table, void *data);
int hashtable_flush(struct hashtable *table);
int hashtable_iterate(struct hashtable *table, void *data,
		      int (*iterate)(void *data1, void *data2));
unsigned int hashtable_counter(struct hashtable *table);

#endif
