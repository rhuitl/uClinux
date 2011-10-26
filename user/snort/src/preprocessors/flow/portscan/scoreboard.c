#include "scoreboard.h"
#include "util_math.h" /* calc % */

static SCORE_ENTRY s_init_entry; /* static entry that will always be zeroed out at init */

/* utility */
static void sb_init_entry(void);
static int scoreboard_anrfree(void *key, void *data);
static int scoreboard_usrfree(void *key, void *data);

static INLINE int scoreboard_lru(SCOREBOARD *sbp, SCORE_ENTRY **sepp);
static INLINE int scoreboard_mru(SCOREBOARD *sbp, SCORE_ENTRY **sepp);


/** 
 * Create a new scoreboard for tracking nodes.
 * 
 * @param sbp scoreboard to initialize
 * @param at_thr active talker thresholds
 * @param sc_thr scanner thresholds (may not be needed)
 * @param kind tracker location for this table 
 * @param description table description
 * @param rows number of rows to populate the initial HASHTABLE() with
 * @param memcap bytes we can spend on this scoreboard
 * 
 * @return FLOW_SUCCESS on success, else failure
 */
int scoreboard_init(SCOREBOARD *sbp,
                    char *description,
                    TRACKER_POSITION kind,
                    unsigned int rows,
                    int memcap)
{
    
    if(!sbp || !description)
    {
        return FLOW_ENULL;
    }
    
    if(rows < 1)
        return FLOW_EINVALID;

    if(memcap < (sizeof(SCORE_ENTRY) + sizeof(SFXHASH_NODE)))
        return FLOW_EINVALID;

    /* initialize s_init_entry*/
    sb_init_entry();

    memset(sbp, 0, sizeof(SCOREBOARD));

    snprintf(sbp->description, SDESC_SIZE - 1, description);
    sbp->description[SDESC_SIZE - 1] = '\0';
     
    /* what size should we do? */
    sbp->ipv4_table = sfxhash_new(rows,               /* # of rows in HT*/
                                  sizeof(u_int32_t),    /* size of the key  */
                                  sizeof(SCORE_ENTRY), /* data size */
                                  memcap,              /* how much memory is alloted */
                                  1,                   /* auto recover nodes */
                                  scoreboard_anrfree, /* autorecovery function */
                                  scoreboard_usrfree, /* free function for the data */
                                  1);                 /* recycle old nodes */

    if(sbp->ipv4_table == NULL)
    {
        flow_printf("Unable to create scoreboard table!\n");
        return FLOW_ENOMEM;
    }

    sbp->kind = kind;

    return FLOW_SUCCESS;
}

int scoreboard_destroy(SCOREBOARD *sbp)
{
    if(!sbp || !sbp->ipv4_table)
    {
        return FLOW_ENULL;
    }

    sfxhash_delete(sbp->ipv4_table);

    sbp->ipv4_table = NULL;
    
    return FLOW_SUCCESS;    
}

int scoreboard_add(SCOREBOARD *sbp, u_int32_t *address, SCORE_ENTRY **sepp)
{
    int ret;
    
    if(!sbp)
    {
        return FLOW_ENULL;
    }

    ret = sfxhash_add(sbp->ipv4_table, address, &s_init_entry);

    switch(ret)
    {
    case SFXHASH_OK:
        if(scoreboard_mru(sbp,sepp) != FLOW_SUCCESS)
        {
            /* something's wrong because we just added this thing!\n */
            flow_printf("sba: Unable to find a key I just added!\n");
            return FLOW_BADJUJU;
        }

        return FLOW_SUCCESS;
        
    case SFXHASH_NOMEM:
        return FLOW_ENOMEM;
    case SFXHASH_INTABLE:
    default:
        return FLOW_EINVALID;
    }
  
    return FLOW_SUCCESS;    
}

/** 
 * Remove a node from the scoreboard
 * 
 * @param sbp scoreboard to modify
 * @param address address to remove
 * 
 * @return FLOW_SUCCESS on success
 */
int scoreboard_remove(SCOREBOARD *sbp, u_int32_t *address)
{
    if(!sbp)
    {
        return FLOW_ENULL;
    }

    if(sfxhash_remove(sbp->ipv4_table, address) != 0)
    {
        return FLOW_NOTFOUND;
    }
    
    return FLOW_SUCCESS;    
}

int scoreboard_find(SCOREBOARD *sbp, u_int32_t *address, SCORE_ENTRY **sepp)
{
    if(!sbp || !address || !sepp)
        return FLOW_ENULL;

    /* printf("looking for %s\n", inet_ntoa(*(struct in_addr *) address)); */

    *sepp = sfxhash_find(sbp->ipv4_table, address);

    if(*sepp == NULL)
        return FLOW_NOTFOUND;
    
    return FLOW_SUCCESS;
}

/** 
 * Move a scoreboard entry from one table to the other
 *
 * @todo This actually can probably be done faster with the rindex
 *       stuff and a SFXHASH_NODE interface.
 * 
 * @param dst where to move the address to
 * @param src where to move the address from
 * @param address the address to move
 * 
 * @return FLOW_SUCCESS on success
 */
int scoreboard_move(SCOREBOARD *dst, SCOREBOARD *src, u_int32_t *address)
{
    SCORE_ENTRY *src_entry, *dst_entry;
    
    if(!src || !dst)
    {
        return FLOW_ENULL;
    }

    if(scoreboard_find(src, address, &src_entry) != FLOW_SUCCESS)
    {
        return FLOW_NOTFOUND;
    }

    if(scoreboard_add(dst, address, &dst_entry) != FLOW_SUCCESS)
    {
        return FLOW_EINVALID;
    }

    memcpy(dst_entry,src_entry,sizeof(SCORE_ENTRY));

    dst_entry->position = dst->kind;
    
    if(scoreboard_remove(src, address) != FLOW_SUCCESS)
    {
        /* small problem here in that we have 2 versions of the same
           thing going on */           
        return FLOW_BADJUJU;
    }
    
    return FLOW_SUCCESS;
}

/** 
 * Print out the entirety of the scoreboard
 * 
 * @param ssp unique tracker
 */
void scoreboard_dump(SCOREBOARD *ssp)
{
    SFXHASH_NODE *nodep;

    if(ssp && ssp->ipv4_table)
    {
        for( nodep = sfxhash_ghead(ssp->ipv4_table);
             nodep != NULL;
             nodep = sfxhash_gnext(nodep) )
        {
            u_int32_t  *address = (u_int32_t *) nodep->key;
            SCORE_ENTRY *entry = (SCORE_ENTRY *) nodep->data;
            flowps_entry_print(entry, address);
        }
    }
    else
    {
        flow_printf("nothing to dump!\n");
    }
}


void scoreboard_stats(SCOREBOARD *sbp, int dumpall)
{
    unsigned total = sfxhash_find_total(sbp->ipv4_table);
    unsigned fail = sfxhash_find_fail(sbp->ipv4_table);
    unsigned success = sfxhash_find_success(sbp->ipv4_table);
    
    flow_printf("SCOREBOARD_STATS: %s\n", (char *) sbp->description);
    flow_printf("   Memcap: %u  Overhead Bytes: %u\n",
                sbp->ipv4_table->mc.memcap,
                sfxhash_overhead_bytes(sbp->ipv4_table));
    
    flow_printf("   Finds: %u (Sucessful: %u(%%%lf) Unsucessful: %u(%%%lf))\n",
                total,
                success, calc_percent(success,total),
                fail, calc_percent(fail,total));

    flow_printf("   Nodes: %u\n", sfxhash_count(sbp->ipv4_table));
    
    flow_printf("   Recovered Nodes: %u\n", sfxhash_anr_count(sbp->ipv4_table));
    flow_printf("   Score Entry Size:: %u\n", sizeof(SCORE_ENTRY));

    if(dumpall)
        scoreboard_dump(sbp);
}

/** 
 * initialize the static s_init_entry variable once and only
 * once. This is used to zero out the key so that if the compiler pads
 * the structure, we still have 0's in this keylookup.
 * 
 */
static void sb_init_entry(void)
{
    static int init_once = 1;

    if(init_once)
    {
        init_once = 0;
        memset(&s_init_entry, 0, sizeof(SCORE_ENTRY));
    }
    
}

/** 
 * Get the most recently used flow from the cache
 * 
 * @param sbp scoreboard to find
 * @param sepp score entry pointer to fill in
 * 
 * @return FLOW_SUCCESS on sucess
 */
static INLINE int scoreboard_mru(SCOREBOARD *sbp, SCORE_ENTRY **sepp)
{
    if(!sbp || !sepp)
        return FLOW_EINVALID;

    *sepp = sfxhash_mru(sbp->ipv4_table);

    if(*sepp == NULL)
        return FLOW_NOTFOUND;
    
    return FLOW_SUCCESS;
}

/** 
 * Get the least recently used flow from the cache
 * 
 * @param sbp scoreboard to find
 * @param sepp score entry pointer to fill in
 * 
 * @return FLOW_SUCCESS on sucess
 */
static INLINE int scoreboard_lru(SCOREBOARD *sbp, SCORE_ENTRY **sepp)
{
    if(!sbp || !sepp)
        return FLOW_EINVALID;

    *sepp = sfxhash_lru(sbp->ipv4_table);

    if(*sepp == NULL)
        return FLOW_NOTFOUND;
    
    return FLOW_SUCCESS;
}



/** 
 * Automatically recover nodes and make sure that all the other
 * references are taken care of.
 * 
 * @param key hash key
 * @param data scoreboard entry
 * 
 * @return 0 if this node can be removed
 */
static int scoreboard_anrfree(void *key, void *data)
{
    return 0;
}


/** 
 * Automatically recover nodes and make sure that all the other
 * references are taken care of.
 * 
 * @param key hash key
 * @param data scoreboard entry
 * 
 * @return 0 if this node can be removed
 */
static int scoreboard_usrfree(void *key, void *data)
{
    return 0;
}

/** 
 * get the memcap
 * 
 * @param sbp scoreboard ptr to return the memcap of
 * 
 * @return memcap or -1
 */
int scoreboard_memcap(SCOREBOARD *sbp)
{
    if(sbp != NULL && sbp->ipv4_table != NULL)        
        return sbp->ipv4_table->mc.memcap;

    return -1;            
}

/** 
 * get the row count
 * 
 * @param sbp scoreboard ptr to return the memcap of
 * 
 * @return nrows or -1
 */
int scoreboard_row_count(SCOREBOARD *sbp)
{
    if(sbp != NULL && sbp->ipv4_table != NULL)        
        return sbp->ipv4_table->nrows;

    return -1;            
}

/** 
 * get the overhead # of bytes
 * 
 * @param sbp scoreboard ptr to return the memcap of
 * 
 * @return nrows or -1
 */

int scoreboard_overhead_bytes(SCOREBOARD *sbp)
{
    if(sbp != NULL && sbp->ipv4_table != NULL)
        return sfxhash_overhead_bytes(sbp->ipv4_table);

    return -1;            

}
