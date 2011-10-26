/**
 * @file   unique_tracker.c
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Fri Jun  6 10:32:17 2003
 * 
 * @brief  track the uniqueness of an address's connections
 * 
 * This "uniqueness tracker" is meant to give a long running view of
 * what is unique to a particular session.
 *
 * It's basically a hash of everything in the FLOWKEY save for the
 * source port.  This should be hit for every "new connection".
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "unique_tracker.h"
#include "sfxhash.h"

typedef struct _UT_KEY
{
    u_int32_t sip;
    u_int32_t dip;
    u_int16_t dport;
    char     protocol;
} UT_KEY;

static UT_KEY s_ut_key; /* static entry that will always be zeroed out at init */
static int s_debug = 0;

/* utility */
static void ut_init_entry(void);


int ut_init(UNIQUE_TRACKER *utp, unsigned int rows, int memcap)
{
    if(!utp)
        return FLOW_ENULL;

    ut_init_entry();
    
    memset(utp, 0, sizeof(UNIQUE_TRACKER));
    
    /* what size should we do? */
    utp->ipv4_table = sfxhash_new(rows,             /* # of rows in HT*/
                                  sizeof(UT_KEY),    /* size of the key  */
                                  0,                 /* data size */
                                  memcap,            /* how much memory is alloted */
                                  1,                 /* auto recover nodes */
                                  NULL,              /* autorecovery function */
                                  NULL,              /* free function for the data */
                                  1);                /* recycle old nodes */

    if(utp->ipv4_table == NULL)
    {
        if(s_debug)
            flow_printf("ran out of memory!\n");
        return FLOW_ENOMEM;
    }

    return FLOW_SUCCESS;
}

/** 
 * Destroy a table completely
 * 
 * @param utp table to kill
 * 
 * @return FLOW_SUCCESS when table is gone
 */
int ut_destroy(UNIQUE_TRACKER *utp)
{
    if(!utp)
        return FLOW_ENULL;

    if(!utp->ipv4_table)
        return FLOW_SUCCESS;

    sfxhash_delete(utp->ipv4_table);
    
    return FLOW_SUCCESS;
}

/** 
 * Determine if a flowkey is sufficiently unique to be called new
 *
 * This assumes that sfxhash_add performs a splay to the top on an
 * INTABLE add.  This must be updated if that's ever changed.
 *
 * @param utp tracker to use
 * @param keyp key to check
 * @param 
 * @return FLOW_SUCCESS if the check went OK
 */
int ut_check(UNIQUE_TRACKER *utp, FLOWKEY *keyp, UT_TYPE *retval)
{
    int ret;
    UT_KEY *utkeyp = &s_ut_key;  /* always a key that has been initialize */

    if(!retval || !utp || !utp->ipv4_table)
        return FLOW_ENULL;

    utkeyp->protocol = keyp->protocol;
    utkeyp->sip      = keyp->init_address;
    utkeyp->dip      = keyp->resp_address;
    utkeyp->dport    = keyp->resp_port;

    ret = sfxhash_add(utp->ipv4_table, utkeyp, NULL);

    switch(ret)
    {
    case SFXHASH_NOMEM:
        /* NOMEM means that we would add it if we could but we're
         *  hard-core out of space.  So, just assume we added it.
         */
    case SFXHASH_OK:
        *retval = UT_NEW;
        break;
    case SFXHASH_INTABLE:
        *retval = UT_OLD;
        break;
    }

    return FLOW_SUCCESS;        
}

    

/** 
 * initialize the static s_init_key variable once and only once.This
 * is used to zero out the key so that if the compiler pads the
 * structure, we still have 0's in this keylookup.
 * 
 */
static void ut_init_entry(void)
{
    static int init_once = 1;

    if(init_once)
    {
        init_once = 0;
        memset(&s_ut_key, 0, sizeof(UT_KEY));
    }
}

/** 
 * Print out the entirety of the unique tracker
 * 
 * @param ssp unique tracker
 */
void unique_tracker_dump(UNIQUE_TRACKER *ssp)
{
    SFXHASH_NODE *nodep;
    char buf[32 + 1];
    
    if(ssp && ssp->ipv4_table)
    {
        for( nodep = sfxhash_ghead(ssp->ipv4_table);
             nodep != NULL;
             nodep = sfxhash_gnext(nodep) )
        {
            UT_KEY *kp = (UT_KEY *) nodep->key;

            snprintf(buf, 32, "%15s", inet_ntoa(*(struct in_addr *)&kp->sip));
            buf[32] = '\0';
            
            flow_printf("%s -> (proto:%d %s:%d)\n",
                        buf,
                        kp->protocol,
                        inet_ntoa(*(struct in_addr *)&kp->dip),
                        kp->dport);
        }
    }
    else
    {
        flow_printf("nothing to dump!\n");
    }
}


/** 
 * 
 * 
 * @param utp unique tracker ptr
 * @param dumpall if 1, dump the contents of the tracker
 */
void ut_stats(UNIQUE_TRACKER *utp, int dumpall)
{
    unsigned total   = sfxhash_find_total(utp->ipv4_table);
    unsigned fail    = sfxhash_find_fail(utp->ipv4_table);
    unsigned success = sfxhash_find_success(utp->ipv4_table);
    
    flow_printf("UNIQUE_TRACKER STATS\n");
    flow_printf("   Memcap: %u  Overhead Bytes: %u\n",
                ut_memcap(utp), ut_overhead_bytes(utp));
    
    flow_printf("   Finds: %u (Sucessful: %u(%%%lf) Unsucessful: %u(%%%lf))\n",
                total,
                success, calc_percent(success,total),
                fail, calc_percent(fail,total));

    flow_printf("   Nodes: %u\n", sfxhash_count(utp->ipv4_table));
    
    flow_printf("   Recovered Nodes: %u\n", sfxhash_anr_count(utp->ipv4_table));

    if(dumpall)
        unique_tracker_dump(utp);
        
}


/** 
 * get the memcap
 * 
 * @param utp ptr to get the memcap of something
 * 
 * @return memcap or -1
 */
int ut_memcap(UNIQUE_TRACKER *utp)
{
    if(utp != NULL && utp->ipv4_table != NULL)        
        return utp->ipv4_table->mc.memcap;

    return -1;            
}

/** 
 * get the # of rows in table
 * 
 * @param sbp ut ptr to return the memcap of
 * 
 * @return nrows or -1
 */
int ut_row_count(UNIQUE_TRACKER *utp)
{
    if(utp != NULL && utp->ipv4_table != NULL)        
        return utp->ipv4_table->nrows;

    return -1;            
}

/** 
 * get the overhead # of bytes
 * 
 * @param sbp UNIQUE_TRACKER ptr to return the memcap of
 * 
 * @return nrows or -1
 */
int ut_overhead_bytes(UNIQUE_TRACKER *sbp)
{
    if(sbp != NULL && sbp->ipv4_table != NULL)
        return sfxhash_overhead_bytes(sbp->ipv4_table);

    return -1;            
}

