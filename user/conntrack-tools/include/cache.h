#ifndef _CACHE_H_
#define _CACHE_H_

#include <sys/types.h>
#include <time.h>

/* cache features */
enum {
	NO_FEATURES = 0,

	TIMER_FEATURE = 0,
	TIMER = (1 << TIMER_FEATURE),

	LIFETIME_FEATURE = 2,
	LIFETIME = (1 << LIFETIME_FEATURE),

	__CACHE_MAX_FEATURE
};
#define CACHE_MAX_FEATURE __CACHE_MAX_FEATURE

struct cache;
struct us_conntrack;

struct cache_feature {
	size_t size;
	void (*add)(struct us_conntrack *u, void *data);
	void (*update)(struct us_conntrack *u, void *data);
	void (*destroy)(struct us_conntrack *u, void *data);
	int  (*dump)(struct us_conntrack *u, void *data, char *buf, int type);
};

extern struct cache_feature lifetime_feature;
extern struct cache_feature timer_feature;

#define CACHE_MAX_NAMELEN 32

struct cache {
	char name[CACHE_MAX_NAMELEN];
	struct hashtable *h;

	unsigned int num_features;
	struct cache_feature **features;
	unsigned int feature_type[CACHE_MAX_FEATURE];
	unsigned int *feature_offset;
	struct cache_extra *extra;
	unsigned int extra_offset;

        /* statistics */
	unsigned int add_ok;
	unsigned int del_ok;
	unsigned int upd_ok;

	unsigned int add_fail;
	unsigned int del_fail;
	unsigned int upd_fail;

	unsigned int commit_ok;
	unsigned int commit_exist;
	unsigned int commit_fail;

	unsigned int flush;
};

struct cache_extra {
	unsigned int size;

	void (*add)(struct us_conntrack *u, void *data);
	void (*update)(struct us_conntrack *u, void *data);
	void (*destroy)(struct us_conntrack *u, void *data);
};

struct nf_conntrack;

struct cache *cache_create(char *name, unsigned int features, u_int8_t proto, struct cache_extra *extra);
void cache_destroy(struct cache *e);

struct us_conntrack *cache_add(struct cache *c, struct nf_conntrack *ct);
struct us_conntrack *cache_update(struct cache *c, struct nf_conntrack *ct);
struct us_conntrack *cache_update_force(struct cache *c, struct nf_conntrack *ct);
int cache_del(struct cache *c, struct nf_conntrack *ct);
int cache_test(struct cache *c, struct nf_conntrack *ct);
void cache_stats(struct cache *c, int fd);
struct us_conntrack *cache_get_conntrack(struct cache *, void *);
void *cache_get_extra(struct cache *, void *);
void cache_iterate(struct cache *c, void *data, int (*iterate)(void *data1, void *data2));

/* iterators */
void cache_dump(struct cache *c, int fd, int type);
void cache_commit(struct cache *c);
void cache_flush(struct cache *c);
void cache_bulk(struct cache *c);

#endif
