/**
 * @file   flow_cache.c
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Fri Jun 20 09:04:51 2003
 * 
 * @brief  where flows are stored
 * 
 * The FlowCache is a memory-capped storage area for the FLOW
 * datatype.  It is inspired by spp_conversation, ipaudit, stream4 and
 * frag2. 
 *
 *
 * Each FLOW is uniquely identified by the 5-tuple (ipproto,sip,dip,sport,dport)
 *
 * Currently we only support IPV4 but new protocols will only require
 * the addition of additional protocol specific hash tables.  Ideally,
 * the API will stay the same and just do a switch on the key type to
 * support the various address families.
 *
 * This is meant to centralize the state management routines so that
 * it's easy to just worry about higher level protocols in other
 * modules.
 *
 * This is built on top of sfxhash currently and relies on it for
 * memory management. flow_hash.c contains the hashing keys 
 * 
 */
#define FLOW_PERF_FIX

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>

#include "flow_cache.h"
#include "flow_callback.h"
#include "flow_hash.h"
#include "bitop_funcs.h"

/* helper functions */
static int flowcache_anrfree( void *key, void *data);
static int flowcache_usrfree( void *key, void *data);

/* minor optimization functions */
static INLINE int flowcache_mru(FLOWCACHE *flowcachep, FLOW **flowpp);
static INLINE int flowcache_lru(FLOWCACHE *flowcachep, FLOW **flowpp);

/* statistics functions */
static INLINE int FCS_find(FLOWCACHE *flowcachecp, FLOWKEY *keyp);
static INLINE int FCS_revfind(FLOWCACHE *flowcachecp, FLOWKEY *keyp);
static INLINE int FCS_new(FLOWCACHE *flowcachecp, FLOWKEY *keyp);
static INLINE int FCS_find_success(FLOWCACHE *flowcachecp, FLOWKEY *keyp);
static INLINE int FCS_find_fail(FLOWCACHE *flowcachecp, FLOWKEY *keyp);

int flowcache_init(FLOWCACHE *flowcachep, unsigned int rows,
                   int memcap, int datasize, FLOWHASHID hashid)
{
    int ret;
    int real_datasize = 0;
    
    if(!flowcachep)
    {
        return FLOW_ENULL;
    }

    if(datasize < 0)
    {
        return FLOW_ENULL;
    }

    if(memcap <= (int)(datasize + sizeof(FLOW) + sizeof(SFXHASH_NODE)))
    {
        /* come on man, you gotta give me enough memory to store 1. */
        return FLOW_EINVALID;
    }

    if(rows < 1)
        return FLOW_EINVALID;

    /* zero out the struct for all the additional data strctures */
    memset(flowcachep, 0, sizeof(FLOWCACHE));

    /*
    **  If we have a datasize, then we need to decrement by 1 because
    **  the FLOWDATA already has one byte.
    */
    if(datasize)
    {
        real_datasize = datasize - 1;
    }

    /*
    **  datasize-1 because there is already 1 byte in the FLOWDATA
    **  structure.
    */
    flowcachep->ipv4_table =
        sfxhash_new(rows,                         /* # of nodes in HT*/
                    sizeof(FLOWKEY),              /* size of the key  */
                    sizeof(FLOW) + real_datasize, /* data size */
                    memcap,                       /* max memory */
                    1,                            /* auto recover nodes */
                    flowcache_anrfree,            /* autorecovery function */
                    flowcache_usrfree,            /* data free function*/
                    1);                           /* recycle old nodes */

    if(flowcachep->ipv4_table == NULL)
    {
        return FLOW_ENOMEM;
    }

    /* set our hash function to something that understands ipv4 flowkeys */
    switch(hashid)
    {
    case HASH1:
        ret = sfxhash_set_keyops(flowcachep->ipv4_table,
                                 flowkey_hashfcn1,
                                 flowkeycmp_fcn);
        break;
    case HASH2:
        ret = sfxhash_set_keyops(flowcachep->ipv4_table,
                                 flowkey_hashfcn2,
                                 flowkeycmp_fcn);
        break;
    default:
        ret = FLOW_EINVALID;
    }

    /* if setting the hash function or setting the comparison function fails,
       abort */
    if(ret != 0)
    {
        sfxhash_delete(flowcachep->ipv4_table);
        return FLOW_BADJUJU;
    }

    flowcachep->max_flowbits_bytes = (unsigned int)datasize;

    return FLOW_SUCCESS;
}

int flowcache_destroy(FLOWCACHE *flowcachep)
{
    if(!flowcachep)
    {
        return FLOW_ENULL;
    }

    sfxhash_delete(flowcachep->ipv4_table);

    flowcachep->ipv4_table = NULL;
    
    return FLOW_SUCCESS;
}

unsigned flowcache_overhead_blocks(FLOWCACHE *fcp)
{
    return sfxhash_overhead_blocks(fcp->ipv4_table);
}


int flowcache_releaseflow(FLOWCACHE *flowcachep, FLOW **flowpp)
{
    FLOWKEY *key;
    FLOWKEY search_key;
    
    if(!flowcachep || !flowpp || !(*flowpp))
    {
        return FLOW_ENULL;
    }

    /** @todo remove any associated data with the flow */

    key = &(*flowpp)->key;
    
    flowkey_normalize(&search_key, key);

    if(sfxhash_remove(flowcachep->ipv4_table, &search_key) != 0)
    {
        return FLOW_NOTFOUND;
    }

    /* we've successfully removed the node from the table */
    
    *flowpp = NULL;

    return FLOW_SUCCESS;
}

int init_flowdata(FLOWCACHE *fcp, FLOW *flowp)
{
    if(!flowp || !fcp)
        return 1;

    if(boInitStaticBITOP(&(flowp->data.boFlowbits), fcp->max_flowbits_bytes, 
                         flowp->data.flowb))
    {
        return 1;
    }

    return 0;
}

int flowcache_newflow(FLOWCACHE *flowcachep, FLOWKEY *keyp, FLOW **flowpp)
{
    static int run_once = 1;
#ifdef FLOW_PERF_FIX
    FLOW *newflow = NULL;
    SFXHASH_NODE *new_node = NULL;
#else
    static FLOW zeroflow;
#endif
    static FLOWKEY searchkey;
    int ret;
    
    if(!flowcachep || !keyp || !flowpp)
    {
        return FLOW_ENULL;
    }

    FCS_new(flowcachep, keyp);
    
    if(run_once)
    {
        /* all the time that we're running this, we're actually going
           to be filling in the key, and having zero'd out counters */ 
#ifndef FLOW_PERF_FIX
        memset(&zeroflow, 0, sizeof(FLOW));
#endif
        memset(&searchkey, 0, sizeof(FLOWKEY));        
        run_once = 0;
    }

    flowkey_normalize(&searchkey, keyp);
   
#ifdef FLOW_PERF_FIX
    /* This just eliminates a memcpy. */
    /* Since we're using auto node recovery, we should get a node back
     * here that has a data pointer. */
    /* flow_init resets the internal key & stats to zero. */
    new_node = sfxhash_get_node(flowcachep->ipv4_table, &searchkey);
    if (new_node && new_node->data)
    {
        newflow = new_node->data;
    
        if(flow_init(newflow, keyp->protocol,
                     keyp->init_address, keyp->init_port,
                     keyp->resp_address, keyp->resp_port))
        {
            return FLOW_ENULL;
        }
        ret = SFXHASH_OK;
    }
    else
    {
        ret = SFXHASH_NOMEM;
    }
#else
    if(flow_init(&zeroflow, keyp->protocol,
                 keyp->init_address, keyp->init_port,
                 keyp->resp_address, keyp->resp_port))
    {
        return FLOW_ENULL;
    }

    ret = sfxhash_add(flowcachep->ipv4_table, &searchkey, &zeroflow);
#endif

    switch(ret)
    {
    case SFXHASH_OK:
        if(flowcache_mru(flowcachep,flowpp) != FLOW_SUCCESS)
        {
            /* something's wrong because we just added this thing!\n */
            flow_printf("Unable to find a key I just added!\n");
            return FLOW_BADJUJU;
        }

        if(init_flowdata(flowcachep, *flowpp))
        {
            return FLOW_BADJUJU;
        }

        return FLOW_SUCCESS;
        
    case SFXHASH_NOMEM:
        return FLOW_ENOMEM;

    case SFXHASH_INTABLE:
    default:
        return FLOW_EINVALID;
    }
}

/** 
 * Get the most recently used flow from the cache
 * 
 * @param flowcachep flow cache to operate on
 * @param flowp where to put the flow
 * 
 * @return FLOW_SUCCESS on success
 */
static INLINE int flowcache_mru(FLOWCACHE *flowcachep, FLOW **flowpp)
{
    if(!flowcachep  || !flowpp)
        return FLOW_EINVALID;

    *flowpp = sfxhash_mru(flowcachep->ipv4_table);

    if(*flowpp == NULL)
        return FLOW_NOTFOUND;
    
    return FLOW_SUCCESS;
}

/** 
 * Get the least recently used flow from the cache
 * 
 * @param flowcachep flow cache to operate on
 * @param flowp where to put the flow
 * 
 * @return FLOW_SUCCESS on success
 */
static INLINE int flowcache_lru(FLOWCACHE *flowcachep, FLOW **flowpp)
{
    if(!flowcachep  || !flowpp)
        return FLOW_EINVALID;

    *flowpp = sfxhash_lru(flowcachep->ipv4_table);

    if(*flowpp == NULL)
        return FLOW_NOTFOUND;
    
    return FLOW_SUCCESS;
}

/** 
 * Look for the data in the flow tables.
 * 
 * @param flowcachep cache to look in
 * @param keyp pointer to searching key data
 * @param flowpp pointer to set with this module
 * @param direction pass back argument (FROM_INITIATOR or FROM_RESPONDER)
 * 
 * @return FLOW_SUCCESS on success, FLOW_NOTFOUND when not found, else usage error
 */
int flowcache_find(FLOWCACHE *flowcachep, FLOWKEY *keyp, FLOW **flowpp, int *direction)
{
    FLOWKEY search_key;
    FLOW *fp;

    int way;
    
    if(!flowcachep || !keyp || !flowpp || !direction)
    {
        return FLOW_ENULL;
    }
    
    FCS_find(flowcachep, keyp);

    /* give us a single search key that we can hash on */
    flowkey_normalize(&search_key, keyp);

    fp = sfxhash_find(flowcachep->ipv4_table, &search_key);
    
    if(fp == NULL)
    {
        /* we have failed. Nothing else to do here */
        *flowpp = NULL;

        FCS_find_fail(flowcachep, keyp);
        
        return FLOW_NOTFOUND;
    }
    else 
    {
        /* now, lets see which way this flow was stored.  Note, this
           has nothing to do with the search key as that is only good
           for searching */

        if(fp->key.init_address == keyp->init_address &&
           fp->key.init_port == keyp->init_port)
        {
            way = FROM_INITIATOR;
        }
        else
        {
            way = FROM_RESPONDER;
            FCS_revfind(flowcachep, &search_key);
        }
    }

    *direction = way;

    *flowpp = fp;

    FCS_find_success(flowcachep, keyp);
    return FLOW_SUCCESS;
}

/** 
 * map a position to a name
 * 
 * @param position where to return the name of
 * 
 * @return string reprenting position name
 */
const char *flowcache_pname(FLOW_POSITION position)
{
    static const char *position_names[] = {"FLOW_NEW",
                                           "FLOW_FIRST_BIDIRECTIONAL",
                                           "FLOW_ADDITIONAL",
                                           "FLOW_SHUTDOWN",
                                           "FLOW_INVALID" };

    if(position < FLOW_NEW || position >= FLOW_MAX)
    {
        return position_names[4];
    }

    return position_names[position];
}


/** 
 * Automatically recover nodes and make sure that all the other
 * references are taken care of.
 * 
 * @param key hash key
 * @param data ptr to FLOW data
 * 
 * @return 0 if this node can be removed
 */
static int flowcache_anrfree(void *key, void *data)
{
    FLOW *fp;

    if(data)
    {
        fp = (FLOW *) data;
        flow_callbacks(FLOW_SHUTDOWN, fp, 0, NULL);
    }
    
    return 0;
}


/** 
 * Automatically recover nodes and make sure that all the other
 * references are taken care of.
 * 
 * @param key hash key
 * @param data ptr to FLOW data
 * p
 * @return 0 if this node can be removed
 */
static int flowcache_usrfree(void *key, void *data)
{
#ifndef WIN32
    // printf("DEBUG: called %s\n", __func__);
#else
    // printf("DEBUG: called file %s line %d\n", __FILE__, __LINE__);
#endif

    return 0;
}


/* these are just helpers for the flowcache problems */


static INLINE int FCS_find(FLOWCACHE *flowcachecp, FLOWKEY *keyp)
{
    
    flowcachecp->total.find_ops++;
    flowcachecp->per_proto[keyp->protocol].find_ops++;
        
    return 0;
}

static INLINE int FCS_revfind(FLOWCACHE *flowcachecp, FLOWKEY *keyp)
{
    flowcachecp->total.reversed_ops++;
    flowcachecp->per_proto[keyp->protocol].reversed_ops++;
    return 0;
}

static INLINE int FCS_new(FLOWCACHE *flowcachecp, FLOWKEY *keyp)
{
    flowcachecp->total.new_flows++;
    flowcachecp->per_proto[keyp->protocol].new_flows++;
    return 0;
}

static INLINE int FCS_find_success(FLOWCACHE *flowcachecp, FLOWKEY *keyp)
{
    flowcachecp->total.find_success++;
    flowcachecp->per_proto[keyp->protocol].find_success++;
    return 0;
}

static INLINE int FCS_find_fail(FLOWCACHE *flowcachecp, FLOWKEY *keyp)
{
    flowcachecp->total.find_fail++;
    flowcachecp->per_proto[keyp->protocol].find_fail++;
    return 0;
}

void flowcache_stats(FILE *stream, FLOWCACHE *flowcachep)
{
    int could_hold;
    int i;
    time_t low_time = 0, high_time = 0, diff_time = 0;    
    int diff_hours = 0, diff_min = 0, diff_sec = 0;
    int diff_blocks = 0;
    FLOW *flow_mrup, *flow_lrup;

#ifdef INDEPTH_DEBUG
    printf("table max depth: %u\n",
           sfxhash_maxdepth(flowcachep->ipv4_table));
#endif /* INDEPTH_DEBUG */
        
    if((flowcache_mru(flowcachep, &flow_mrup) == FLOW_SUCCESS) &&
       (flowcache_lru(flowcachep, &flow_lrup) == FLOW_SUCCESS))
    {
        low_time = flow_lrup->stats.last_packet;
        high_time = flow_mrup->stats.last_packet;

        diff_time = high_time - low_time;

        diff_hours = diff_time / 3600;
        diff_min = (diff_time - (3600 * diff_hours)) / 60;
        diff_sec = diff_time % 60;
    }

    diff_blocks = flowcachep->ipv4_table->mc.nblocks -
        flowcache_overhead_blocks(flowcachep);


    //could_hold = flowcachep->ipv4_table->mc.memcap /
    //    (sizeof(FLOW) + sizeof(FLOWKEY) + sizeof(SFXHASH_NODE));

    /* this is a bad calculation -- should clean this up */
    if(diff_blocks > 0)
    {
        could_hold = (flowcachep->ipv4_table->mc.memused - flowcache_overhead_bytes(flowcachep)) / diff_blocks;
        could_hold = flowcachep->ipv4_table->mc.memcap / could_hold;
    }
    else
    {
        could_hold = diff_blocks;
    }

    flow_printf(",----[ FLOWCACHE STATS ]----------\n");
    flow_printf("Memcap: %u Overhead Bytes %u used(%%%lf)/blocks (%u/%u)\nOverhead blocks: %u Could Hold: (%u)\n",
                flowcachep->ipv4_table->mc.memcap,
                flowcache_overhead_bytes(flowcachep),
                calc_percent(flowcachep->ipv4_table->mc.memused,
                             flowcachep->ipv4_table->mc.memcap),
                flowcachep->ipv4_table->mc.memused,
                flowcachep->ipv4_table->mc.nblocks,
                flowcache_overhead_blocks(flowcachep),
                could_hold);
    
    flow_printf("IPV4 count: %u frees: %u\nlow_time: %u, high_time: %u,"
                " diff: %dh:%02d:%02ds\n",
                sfxhash_count(flowcachep->ipv4_table),
                sfxhash_anr_count(flowcachep->ipv4_table),
                (unsigned) low_time,
                (unsigned) high_time,
                diff_hours,diff_min,diff_sec);
    

    flow_printf("    finds: %llu reversed: %llu(%%%lf) \n    find_success: %llu "
                "find_fail: %llu\npercent_success: (%%%lf) new_flows: %llu\n",
                flowcachep->total.find_ops,
                flowcachep->total.reversed_ops,
                calc_percent64(flowcachep->total.reversed_ops,
                             flowcachep->total.find_ops),
                flowcachep->total.find_success,
                flowcachep->total.find_fail,
                calc_percent64(flowcachep->total.find_success,
                             flowcachep->total.find_ops),
                flowcachep->total.new_flows);
    
    for(i=0;i<256;i++)
    {
        if(flowcachep->per_proto[i].find_ops > 0)
        {
            flow_printf(" Protocol: %d (%%%lf)\n"
                        "   finds: %llu\n"
                        "   reversed: %llu(%%%lf)\n"
                        "   find_success: %llu\n"
                        "   find_fail: %llu\n"
                        "   percent_success: (%%%lf)\n"
                        "   new_flows: %llu\n",
                        i,
                        calc_percent64(flowcachep->per_proto[i].find_ops,
                                     flowcachep->total.find_ops),
                        flowcachep->per_proto[i].find_ops,
                        flowcachep->per_proto[i].reversed_ops,
                        calc_percent64(flowcachep->per_proto[i].reversed_ops,
                                     flowcachep->per_proto[i].find_ops),
                        flowcachep->per_proto[i].find_success,
                        flowcachep->per_proto[i].find_fail,
                        calc_percent64(flowcachep->per_proto[i].find_success,
                                     flowcachep->per_proto[i].find_ops),
                        flowcachep->per_proto[i].new_flows);
        }
    }
}

/** 
 * get the row count
 * 
 * @param sbp flowcache ptr to return the memcap of
 * 
 * @return nrows or -1
 */
int flowcache_row_count(FLOWCACHE *sbp)
{
    if(sbp != NULL && sbp->ipv4_table != NULL)        
        return sbp->ipv4_table->nrows;

    return -1;            
}

/** 
 * get the overhead # of bytes
 * 
 * @param sbp flowcache ptr to return the memcap of
 * 
 * @return nrows or -1
 */

int flowcache_overhead_bytes(FLOWCACHE *sbp)
{
    if(sbp != NULL && sbp->ipv4_table != NULL)
        return sfxhash_overhead_bytes(sbp->ipv4_table);

    return -1;            

}
