#ifndef _FLOW_CACHE_H
#define _FLOW_CACHE_H

#include "flow.h"
#include "sfxhash.h"

#ifndef UINT64
#define UINT64 unsigned long long
#endif

typedef struct _FCSTAT
{
    UINT64 find_ops;
    UINT64 reversed_ops;
    UINT64 find_success;
    UINT64 find_fail;
    UINT64 new_flows;
    UINT64 released_flows;
} FCSTAT;

typedef struct _FLOWCACHE
{
    SFXHASH *ipv4_table;
    /* statistics */
    FCSTAT total;            /* statistics for everything */
    FCSTAT per_proto[256];   /* statistics kept per protocol */
    unsigned int max_flowbits_bytes;
} FLOWCACHE;


int flowcache_init(FLOWCACHE *flowcachep, unsigned int rows, int memcap,
                   int datasize, FLOWHASHID hashid);
int flowcache_destroy(FLOWCACHE *flowcachep);
int flowcache_releaseflow(FLOWCACHE *flowcachep, FLOW **flowpp);
int flowcache_newflow(FLOWCACHE *flowcachep, FLOWKEY *keyp, FLOW **flowpp);
int flowcache_find(FLOWCACHE *flowcachep, FLOWKEY *keyp,
                   FLOW **flowpp, int *direction);

void flowcache_stats(FILE *stream, FLOWCACHE *flowcachep);

int flowcache_overhead_bytes(FLOWCACHE *fcp);

int flowcache_memcap(FLOWCACHE *fcp);
int flowcache_row_count(FLOWCACHE *fcp);

/* utilty functions */
const char *flowcache_pname(FLOW_POSITION position);

#endif /* _FLOW_CACHE_H */
