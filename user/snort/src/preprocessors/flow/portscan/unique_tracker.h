#ifndef _UNIQUE_TRACKER_H
#define _UNIQUE_TRACKER_H

#include "flow.h"
#include "sfxhash.h"

typedef enum {
    UT_OLD,
    UT_NEW
} UT_TYPE;


typedef struct _UNIQUE_TRACKER
{
    SFXHASH *ipv4_table;
} UNIQUE_TRACKER;

int ut_init(UNIQUE_TRACKER *utp, unsigned int rows, int memcap);
int ut_destroy(UNIQUE_TRACKER *utp);
int ut_check(UNIQUE_TRACKER *utp, FLOWKEY *keyp, UT_TYPE *retval);
void ut_stats(UNIQUE_TRACKER *utp, int dumpall);
int ut_memcap(UNIQUE_TRACKER *utp);
int ut_row_count(UNIQUE_TRACKER *utp);
int ut_overhead_bytes(UNIQUE_TRACKER *sbp);
#endif /* _UNIQUE_TRACKER_H */

