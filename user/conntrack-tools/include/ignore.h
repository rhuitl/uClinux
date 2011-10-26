#ifndef _IGNORE_H_
#define _IGNORE_H_

struct ignore_pool {
	struct hashtable *h;
};

struct ignore_pool *ignore_pool_create(u_int8_t family);
void ignore_pool_destroy(struct ignore_pool *ip);
int ignore_pool_add(struct ignore_pool *ip, void *data);

#endif
