/* $Id$ */

/**
 * @file    spp_frag3.c
 * @author  Martin Roesch <roesch@sourcefire.com>
 * @date    Thu Sep 30 14:12:37 EDT 2004
 *
 * @brief   Frag3: IP defragmentation preprocessor for Snort. 
 */

/*
 ** Copyright (C) 2004 Sourcefire Inc.
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation; either version 2 of the License, or
 ** (at your option) any later version.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*
 * Notes: 
 * Frag3 sports the following improvements over frag2:
 *  - Target-based IP defragmentation, harder to evade
 *  - 8 Anomaly detection event types
 *  - Two separate memory management strategies to tailor
 *    performance for specific environments
 *  - Up to 250% faster than frag2.
 *
 *  The mechanism for processing frags is based on the Linux IP stack 
 *  implementation of IP defragmentation with proper amounts of paranoia
 *  and an IDS perspective applied.  Some of this code was derived from 
 *  frag2 originally, but it's basically unrecognizeable if you compare
 *  it to frag2 IMO.
 *
 *  I switched from using the UBI libs to using sfxhash and linked lists for 
 *  fragment management because I suspected that the management code was 
 *  the cause of performance issues that we were observing at Sourcefire 
 *  in certain customer situations.  Splay trees are cool and really hard
 *  to screw with from an attack perspective, but they also incur a lot 
 *  of overhead for managing the tree and lose the order of the fragments in 
 *  the FragTracker's fraglist, so I dropped them.  Originally the
 *  frag3 code was just supposed to migrate away from the splay tree system
 *  that I was using in frag2, but I figured since I was doing the work to
 *  pull out the splay trees I may as well solve some of the other problems
 *  we were seeing.  
 *
 *  Initial performance testing that I've done shows that frag3 can be as much
 *  as 250% faster than frag2, but we still need to do more testing and 
 *  optimization, we may be able to squeeze out some more performance.
 *
 *  Frag3 is also capable of performing "Target-based" IP defragmentation.  
 *  What this means practically is that frag3 can model the IP stack of a
 *  target on the network to avoid Ptacek-Newsham evasions of the IDS through
 *  sensor/target desynchronization.  In terms of implentation, this is
 *  reflected by passing a "context" into the defragmentation engine that has
 *  a specific configuration for a specific target type.  Windows can put
 *  fragments back together differently than Linux/BSD/etc, so we model that
 *  inside frag3 so we can't be evaded.
 *
 *  Configuration of frag3 is pretty straight forward, there's a global config
 *  that contains data about how the hash tables will be structured, what type
 *  of memory management to use and whether or not to generate alerts, then
 *  specific target-contexts are setup and bound to IP address sets.  Check
 *  the README file for specifics!
 */

/*  I N C L U D E S  ************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <rpc/types.h>

#include "bounds.h"
#include "generators.h"
#include "log.h"
#include "detect.h"
#include "decode.h"
#include "event.h"
#include "util.h"
#include "debug.h"
#include "plugbase.h"
#include "parser.h"
#include "mstring.h"
#include "checksum.h"
#include "perf.h"
#include "event_queue.h"
#include "timersub.h"
#include "fpcreate.h"

#include "sfutil/sflsq.h"
#include "sfutil/sfxhash.h"

#include "snort.h"
#include "snort_packet_header.h"

#include "profiler.h"

extern OptTreeNode *otn_tmp;

/*  D E F I N E S  **************************************************/

/* flags for the FragTracker->frag_flags field */
#define FRAG_GOT_FIRST      0x00000001
#define FRAG_GOT_LAST       0x00000002
#define FRAG_REBUILT        0x00000004
#define FRAG_BAD            0x00000008

#define FRAG_PRUNE_QUANTA   60          /* default frag timeout, 90-120 might 
                                         * be better values, can we do 
                                         * target-based quanta?
                                         */

#define FRAG_MEMCAP         4194304     /* default 4MB memcap */

#define FRAG3_TTL_LIMIT      5          /* default TTL, unnecessary in 
                                         * tgt-based systems? */
#define FRAG3_MIN_TTL        1          /* min acceptable ttl (should be 1?) */

/* target-based defragmentation policy enums */
#define FRAG_POLICY_FIRST       1
#define FRAG_POLICY_LINUX       2
#define FRAG_POLICY_BSD         3
#define FRAG_POLICY_BSD_RIGHT   4
#define FRAG_POLICY_LAST        5
#define FRAG_POLICY_WINDOWS     6 /* Combo of FIRST & LAST, depending on
                                   * overlap situation.
                                   */
#define FRAG_POLICY_SOLARIS     7 /* Combo of FIRST & LAST, depending on
                                   * overlap situation.
                                   */
#define FRAG_POLICY_DEFAULT     FRAG_POLICY_BSD

/* max packet size */
#define DATASIZE (ETHERNET_HEADER_LEN+IP_MAXPACKET)

/* max frags in a single frag tracker */
#define DEFAULT_MAX_FRAGS   8192

/* return values for CheckTimeout() */
#define FRAG_TIME_OK            0
#define FRAG_TIMEOUT            1

/* return values for Frag3Insert() */
#define FRAG_INSERT_OK          0
#define FRAG_INSERT_FAILED      1
#define FRAG_INSERT_REJECTED    2
#define FRAG_INSERT_TIMEOUT     3
#define FRAG_INSERT_ATTACK      4
#define FRAG_INSERT_ANOMALY     5
#define FRAG_INSERT_TTL         6

/* return values for Frag3CheckFirstLast() */
#define FRAG_FIRSTLAST_OK       0
#define FRAG_LAST_DUPLICATE     1

/* return values for Frag3Expire() */
#define FRAG_OK                 0
#define FRAG_TRACKER_TIMEOUT    1
#define FRAG_LAST_OFFSET_ADJUST 2

/* flag for detecting attacks/alerting */
#define FRAG3_DETECT_ANOMALIES  0x01

/*  D A T A   S T R U C T U R E S  **********************************/

/* global configuration data struct for this preprocessor */
typedef struct 
{
    u_int32_t max_frags;        /* max frags to track */
    u_int32_t memcap;           /* memcap for frag3 */
    u_int32_t static_frags;     /* static frag nodes to keep around */
    u_int8_t use_prealloc;      /* flag to indicate prealloc nodes in use */

} Frag3GlobalConfig;

/* runtime context for a specific instance of an engine */
typedef struct _Frag3Context
{
    u_int16_t frag_policy;  /* policy to use for target-based reassembly */
    int32_t frag_timeout; /* timeout for frags in this policy */

    u_int8_t min_ttl;       /* Minimum TTL to accept */
    u_int8_t ttl_limit;     /* Size of ttls to avoid detection on */

    char frag3_alerts;      /* Whether or not frag3 alerts are enabled */

    IpAddrSet *bound_addrs; /* addresses bound to this context */

} Frag3Context;

/* struct to manage an individual fragment */
typedef struct _Frag3Frag
{
    u_int8_t *data;     /* ptr to adjusted start position */
    u_int16_t size;     /* adjusted frag size */
    u_int16_t offset;   /* adjusted offset position */

    u_int8_t *fptr;     /* free pointer */
    u_int16_t flen;     /* free len, unneeded? */

    struct _Frag3Frag *prev;
    struct _Frag3Frag *next;

    int ord;
    char last;
} Frag3Frag;

/* key struct for the sfxhash */
typedef struct _fragkey
{
    u_int32_t sip;      /* src IP */
    u_int32_t dip;      /* dst IP */
    u_int16_t id;       /* IP ID */
    u_int8_t proto;     /* IP protocol */
} FRAGKEY;

/* Only track a certain number of alerts per session */
#define MAX_FRAG_ALERTS  8

/* tracker for a fragmented packet set */
typedef struct _FragTracker
{
    u_int32_t sip;          /* src IP */
    u_int32_t dip;          /* dst IP */
    u_int16_t id;           /* IP ID */
    u_int8_t protocol;      /* IP protocol */

    u_int8_t ttl;           /* ttl used to detect evasions */
    u_int8_t alerted;
    u_int32_t frag_flags;   /* bit field */

    u_int32_t frag_bytes;   /* number of fragment bytes stored, based 
                             * on aligned fragment offsets/sizes
                             */

    u_int32_t calculated_size; /* calculated size of reassembled pkt, based on 
                                * last frag offset
                                */

    u_int32_t frag_pkts;   /* nummber of frag pkts stored under this tracker */

    struct timeval frag_time; /* time we started tracking this frag */

    Frag3Frag *fraglist;      /* list of fragments */
    Frag3Frag *fraglist_tail; /* tail ptr for easy appending */
    int fraglist_count;       /* handy dandy counter */

    u_int32_t alert_gid[MAX_FRAG_ALERTS]; /* flag alerts seen in a frag list  */
    u_int32_t alert_sid[MAX_FRAG_ALERTS]; /* flag alerts seen in a frag list  */
    u_int8_t  alert_count;                /* count alerts seen in a frag list */

    u_int32_t ip_options_len;  /* length of ip options for this set of frags */
    u_int32_t ip_option_count; /* number of ip options for this set of frags */
    u_int8_t *ip_options_data; /* ip options from offset 0 packet */

    u_int32_t copied_ip_options_len;  /* length of 'copied' ip options */
    u_int32_t copied_ip_option_count; /* number of 'copied' ip options */

    Frag3Context *context;

    int ordinal;
    u_int32_t frag_policy;

} FragTracker;

/* statistics tracking struct */
typedef struct _Frag3Stats
{
    u_int32_t  total;
    u_int32_t  overlaps;
    u_int32_t  reassembles;
    u_int32_t  prunes;
    u_int32_t  timeouts;
    u_int32_t  fragtrackers_created;
    u_int32_t  fragtrackers_released;
    u_int32_t  fragtrackers_autoreleased;
    u_int32_t  fragnodes_created;
    u_int32_t  fragnodes_released;
    u_int32_t  discards;
    u_int32_t  anomalies;
    u_int32_t  alerts;

} Frag3Stats;


/*  G L O B A L S  **************************************************/
static Frag3GlobalConfig global_config;  /* global configuration struct */
static SFXHASH *f_cache;                 /* fragment hash table */
static Frag3Frag *prealloc_frag_list;    /* head for prealloc queue */

static char global_init_complete = 0;    /* flag to signal f_cache initialization */ 

static u_int32_t mem_in_use;             /* memory in use, used for self pres */

static u_int32_t prealloc_nodes_in_use;  /* counter for debug */
static int ten_percent;                  /* holder for self preservation data */

static Frag3Stats f3stats;               /* stats struct */
static u_int8_t stats_registered = 0;    /* make sure we only print stats once
                                            per run */

static u_int8_t frag3_registered = 0;    /* make sure we only register once per run */
static Frag3Context **frag3ContextList = NULL; /* List of Frag3 Contexts configured */
static u_int8_t numFrag3Contexts = 0;

static u_int8_t *frag_rebuild_buf = NULL;

#ifdef GRE
static u_int8_t *gre_frag_rebuild_buf = NULL;
#endif

/* enum for policy names */
static char *frag_policy_names[] = { "no policy!",
    "FIRST",
    "LINUX",
    "BSD",
    "BSD_RIGHT",
    "LAST",
    "WINDOWS",
    "SOLARIS"};

#ifdef PERF_PROFILING
PreprocStats frag3PerfStats;
PreprocStats frag3InsertPerfStats;
PreprocStats frag3RebuildPerfStats;
#endif

/*
 * external globals for startup
 */
extern char *file_name;             
extern int file_line;                
extern u_int snaplen;
extern SFPERF sfPerf;


/*  P R O T O T Y P E S  ********************************************/
static void Frag3ParseGlobalArgs(u_char *);
static void Frag3ParseArgs(u_char *, Frag3Context *);
static FragTracker *Frag3GetTracker(Packet *, FRAGKEY *);
static int Frag3NewTracker(Packet *p, FRAGKEY *fkey, Frag3Context *);
static int Frag3Insert(Packet *, FragTracker *, FRAGKEY *, Frag3Context *);
static void Frag3Rebuild(FragTracker *, Packet *);
static int INLINE Frag3IsComplete(FragTracker *);
static int Frag3HandleIPOptions(FragTracker *, Packet *);

/* deletion funcs */
static int Frag3Prune(FragTracker *);
static struct timeval *pkttime;    /* packet timestamp */
static void Frag3DeleteFrag(Frag3Frag *);
static void Frag3RemoveTracker(void *, void *);
static void Frag3DeleteTracker(FragTracker *);
static int Frag3AutoFree(void *, void *);
static int Frag3UserFree(void *, void *);

/* fraglist handler funcs */
static INLINE void Frag3FraglistAddNode(FragTracker *, Frag3Frag *, Frag3Frag *); 
static INLINE void Frag3FraglistDeleteNode(FragTracker *, Frag3Frag *);

/* prealloc queue handler funcs */
static INLINE Frag3Frag *Frag3PreallocPop();
static INLINE void Frag3PreallocPush(Frag3Frag *);

/* main preprocessor functions */
void Frag3Defrag(Packet *, void *);
void Frag3CleanExit(int, void *);
void Frag3Restart(int, void *);
void Frag3Init(u_char *);
void Frag3GlobalInit(u_char *);
void Frag3VerifyConfig(void);
void Frag3PostConfigInit(int, void*);

#ifdef DEBUG_FRAG3
/**
 * Print out a FragTracker structure
 *
 * @param ft Pointer to the FragTracker to print
 *
 * @return none
 */
static void PrintFragTracker(FragTracker *ft)
{
    LogMessage("FragTracker %p\n", ft);
    if(ft)
    {
        LogMessage("        sip: 0x%08X\n", ft->sip);
        LogMessage("        dip: 0x%08X\n", ft->dip);
        LogMessage("         id: %d\n", ft->id);
        LogMessage("      proto: 0x%X\n", ft->protocol);
        LogMessage("        ttl: %d\n", ft->ttl);
        LogMessage("    alerted: %d\n", ft->alerted);
        LogMessage(" frag_flags: 0x%X\n", ft->frag_flags);
        LogMessage(" frag_bytes: %d\n", ft->frag_bytes);
        LogMessage("  calc_size: %d\n", ft->calculated_size);
        LogMessage("  frag_pkts: %d\n", ft->frag_pkts);
        LogMessage("  frag_time: %lu %lu\n", ft->frag_time.tv_sec, 
                ft->frag_time.tv_usec);
        LogMessage("   fraglist: %p\n", ft->fraglist);
        LogMessage("    fl_tail: %p\n", ft->fraglist_tail);
        LogMessage("fraglst cnt: %d\n", ft->fraglist_count);
    }
}

/**
 * Print out a FragKey structure
 *
 * @param fkey Pointer to the FragKey to print
 *
 * @return none
 */
static void PrintFragKey(FRAGKEY *fkey)
{
    LogMessage("FragKey %p\n", fkey);

    if(fkey)
    {
        LogMessage("    sip: 0x%08X\n", fkey->sip);
        LogMessage("    dip: 0x%08X\n", fkey->dip);
        LogMessage("     id: %d\n", fkey->id);
        LogMessage("  proto: 0x%X\n", fkey->proto);
    }
}

/**
 * Print out a Frag3Frag structure
 *
 * @param f Pointer to the Frag3Frag to print
 *
 * @return none
 */
static void PrintFrag3Frag(Frag3Frag *f)
{
    LogMessage("Frag3Frag: %p\n", f);

    if(f)
    {
        LogMessage("    data: %p\n", f->data);
        LogMessage("    size: %d\n", f->size);
        LogMessage("  offset: %d\n", f->offset);
        LogMessage("    fptr: %p\n", f->fptr);
        LogMessage("    flen: %d\n", f->flen);
        LogMessage("    prev: %p\n", f->prev);
        LogMessage("    next: %p\n", f->next);
    }
}

#endif  /* DEBUG_FRAG3 */

/**
 * Print out the global runtime configuration
 *
 * @param None
 *
 * @return none
 */
static void Frag3PrintGlobalConfig()
{
    LogMessage("Frag3 global config:\n");
    LogMessage("    Max frags: %d\n", global_config.max_frags);
    if(!global_config.use_prealloc)
        LogMessage("    Fragment memory cap: %lu bytes\n", 
                (unsigned long)global_config.memcap);
    else
        LogMessage("    Preallocated frag nodes: %lu\n", 
                global_config.static_frags);
}


/**
 * Print out a defrag engine runtime context
 *
 * @param context Pointer to the context structure to print
 *
 * @return none
 */
static void Frag3PrintEngineConfig(Frag3Context *context)
{
    LogMessage("Frag3 engine config:\n");
    LogMessage("    Target-based policy: %s\n", 
            frag_policy_names[context->frag_policy]);
    LogMessage("    Fragment timeout: %d seconds\n", 
            context->frag_timeout);
    LogMessage("    Fragment min_ttl:   %d\n", context->min_ttl);
    LogMessage("    Fragment ttl_limit: %d\n", context->ttl_limit);
    LogMessage("    Fragment Problems: %X\n", context->frag3_alerts);
    //LogMessage("    Bound Addresses:\n");
    IpAddrSetPrint("    Bound Addresses: ", context->bound_addrs);
}

/**
 * Generate an event due to IP options being detected in a frag packet
 *
 * @param context Current run context
 *
 * @return none
 */
static INLINE void EventAnomIpOpts(Frag3Context *context)
{
    if(!(context->frag3_alerts & FRAG3_DETECT_ANOMALIES))
        return;

    SnortEventqAdd(GENERATOR_SPP_FRAG3,     /* GID */ 
            FRAG3_IPOPTIONS,         /* SID */
            1,                       /* rev */
            0,                       /* classification enum */
            3,                       /* priority (low) */
            FRAG3_IPOPTIONS_STR,     /* event message */
            NULL);                   /* rule info ptr */

   f3stats.alerts++;
}

/**
 * Generate an event due to a Teardrop-style attack detected in a frag packet
 *
 * @param context Current run context
 *
 * @return none
 */
static INLINE void EventAttackTeardrop(Frag3Context *context)
{
    if(!(context->frag3_alerts & FRAG3_DETECT_ANOMALIES))
        return;

    SnortEventqAdd(GENERATOR_SPP_FRAG3,     /* GID */ 
            FRAG3_TEARDROP,          /* SID */
            1,                       /* rev */
            0,                       /* classification enum */
            3,                       /* priority (low) */
            FRAG3_TEARDROP_STR,      /* event message */
            NULL);                   /* rule info ptr */

   f3stats.alerts++;
}

/**
 * Generate an event due to a fragment being too short, typcially based
 * on a non-last fragment that doesn't properly end on an 8-byte boundary
 *
 * @param context Current run context
 *
 * @return none
 */
static INLINE void EventAnomShortFrag(Frag3Context *context)
{
    if(!(context->frag3_alerts & FRAG3_DETECT_ANOMALIES))
        return;

    SnortEventqAdd(GENERATOR_SPP_FRAG3,   /* GID */ 
            FRAG3_SHORT_FRAG,             /* SID */
            1,                            /* rev */
            0,                            /* classification enum */
            3,                            /* priority (low) */
            FRAG3_SHORT_FRAG_STR,         /* event message */
            NULL);                        /* rule info ptr */

   f3stats.alerts++;
   f3stats.anomalies++;
}

/**
 * This fragment's size will end after the already calculated reassembled
 * fragment end, as in a Bonk/Boink/etc attack.
 *
 * @param context Current run context
 *
 * @return none
 */
static INLINE void EventAnomOversize(Frag3Context *context)
{
    if(!(context->frag3_alerts & FRAG3_DETECT_ANOMALIES))
        return;

    SnortEventqAdd(GENERATOR_SPP_FRAG3,/* GID */ 
            FRAG3_ANOMALY_OVERSIZE,  /* SID */
            1,                       /* rev */
            0,                       /* classification enum */
            3,                       /* priority (low) */
            FRAG3_ANOM_OVERSIZE_STR, /* event message */
            NULL);                   /* rule info ptr */

   f3stats.alerts++;
   f3stats.anomalies++;
}

/**
 * The current fragment will be inserted with a size of 0 bytes, that's
 * an anomaly if I've ever seen one.
 *
 * @param context Current run context
 *
 * @return none
 */
static INLINE void EventAnomZeroFrag(Frag3Context *context)
{
    if(!(context->frag3_alerts & FRAG3_DETECT_ANOMALIES))
        return;

    SnortEventqAdd(GENERATOR_SPP_FRAG3,/* GID */ 
            FRAG3_ANOMALY_ZERO,      /* SID */
            1,                       /* rev */
            0,                       /* classification enum */
            3,                       /* priority (low) */
            FRAG3_ANOM_ZERO_STR,     /* event message */
            NULL);                   /* rule info ptr */

   f3stats.alerts++;
   f3stats.anomalies++;
}

/**
 * The reassembled packet will be bigger than 64k, generate an event.
 *
 * @param context Current run context
 *
 * @return none
 */
static INLINE void EventAnomBadsizeLg(Frag3Context *context)
{
    if(!(context->frag3_alerts & FRAG3_DETECT_ANOMALIES))
        return;

    SnortEventqAdd(GENERATOR_SPP_FRAG3,/* GID */ 
            FRAG3_ANOMALY_BADSIZE_LG,   /* SID */
            1,                       /* rev */
            0,                       /* classification enum */
            3,                       /* priority (low) */
            FRAG3_ANOM_BADSIZE_LG_STR,  /* event message */
            NULL);                   /* rule info ptr */

   f3stats.alerts++;
   f3stats.anomalies++;
}

/**
 * Fragment size is negative after insertion (end < offset).
 *
 * @param context Current run context
 *
 * @return none
 */
static INLINE void EventAnomBadsizeSm(Frag3Context *context)
{
    if(!(context->frag3_alerts & FRAG3_DETECT_ANOMALIES))
        return;

    SnortEventqAdd(GENERATOR_SPP_FRAG3,/* GID */ 
            FRAG3_ANOMALY_BADSIZE_SM,  /* SID */
            1,                         /* rev */
            0,                         /* classification enum */
            3,                         /* priority (low) */
            FRAG3_ANOM_BADSIZE_SM_STR, /* event message */
            NULL);                     /* rule info ptr */

   f3stats.alerts++;
   f3stats.anomalies++;
}

/**
 * There is an overlap with this fragment, someone is probably being naughty.
 *
 * @param context Current run context
 *
 * @return none
 */
static INLINE void EventAnomOverlap(Frag3Context *context)
{
    if(!(context->frag3_alerts & FRAG3_DETECT_ANOMALIES))
        return;

    SnortEventqAdd(GENERATOR_SPP_FRAG3,/* GID */ 
            FRAG3_ANOMALY_OVLP,   /* SID */
            1,                    /* rev */
            0,                    /* classification enum */
            3,                    /* priority (low) */
            FRAG3_ANOM_OVLP_STR,  /* event message */
            NULL);                /* rule info ptr */

   f3stats.alerts++;
   f3stats.anomalies++;
}

/**
 * Main setup function to regiser frag3 with the rest of Snort.
 *
 * @param none
 *
 * @return none
 */
void SetupFrag3()
{
    RegisterPreprocessor("frag3_global", Frag3GlobalInit);
    RegisterPreprocessor("frag3_engine", Frag3Init);
    AddFuncToConfigCheckList(Frag3VerifyConfig);
    AddFuncToPostConfigList(Frag3PostConfigInit, NULL);
    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "Preprocessor: frag3 is setup...\n"););
}

/**
 * Global init function, handles setting up the runtime hash table and 
 * memory management mode.
 *
 * @param args argument string to process for config data
 *
 * @return none
 */
void Frag3GlobalInit(u_char *args)
{
    /*
     * setup default values
     */
    global_config.max_frags = DEFAULT_MAX_FRAGS;
    global_config.memcap = FRAG_MEMCAP;
    global_config.static_frags = 0;
    global_config.use_prealloc = 0;

    Frag3ParseGlobalArgs(args);

    /* 
     * we really only need one frag cache no matter how many different
     * contexts we have loaded
     */
    if(f_cache == NULL)
    {
        /* we keep FragTrackers in the hash table.. */
        int hashTableSize = (int) (global_config.max_frags * 1.4);
        int maxFragMem = global_config.max_frags * (
                            sizeof(FragTracker) + 
                            sizeof(SFXHASH_NODE) +
                            sizeof (FRAGKEY) +
                            sizeof(SFXHASH_NODE *));
        int tableMem = (hashTableSize + 1) * sizeof(SFXHASH_NODE *);
        int maxMem = maxFragMem + tableMem;
        f_cache = sfxhash_new(
                hashTableSize,       /* number of hash buckets */
                sizeof(FRAGKEY),     /* size of the key we're going to use */
                sizeof(FragTracker), /* size of the storage node */
                maxMem,              /* memcap for frag trackers */
                1,                   /* use auto node recovery */
                Frag3AutoFree,       /* anr free function */
                Frag3UserFree,       /* user free function */
                1);                  /* recycle node flag */
    }

    /*
     * can't proceed if we can't get a fragment cache
     */
    if(!f_cache)
    {
        LogMessage("WARNING: Unable to generate new sfxhash for frag3, "
                "defragmentation disabled!\n");
        return;
    }

    /* 
     * indicate that we've got a global config active 
     */
    global_init_complete = 1;

    /*
     * display the global config for the user
     */
    Frag3PrintGlobalConfig();

    return;
}

/**
 * Setup a frag3 engine context
 *
 * @param args list of configuration arguments
 *
 * @return none
 */
void Frag3Init(u_char *args)
{
    PreprocessFuncNode *pfn;    /* place to attach the runtime context */
    Frag3Context *context;      /* context pointer */ 

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "Initializing frag3\n"););

    context = (Frag3Context *) SnortAlloc(sizeof(Frag3Context));

    if(!global_init_complete)
    {
        FatalError("[!] Unable to configure frag3 engine!\n"
                "Frag3 global config has not been established, "
                "please issue a \"preprocessor frag3_global\" directive\n");
        return;
    }

    /*
     * setup default context config.  Thinking maybe we should go with 
     * FRAG_POLICY_FIRST or FRAG_POLICY_LINUX as the default instead of
     * BSD since Win32/Linux have a higher incidence of occurrence.  Anyone
     * with an opinion on the matter feel free to email me...
     */
    context->frag_policy = FRAG_POLICY_DEFAULT;
    context->frag_timeout = FRAG_PRUNE_QUANTA; /* 60 seconds */
    context->ttl_limit = FRAG3_TTL_LIMIT;
    context->min_ttl = FRAG3_MIN_TTL;
    context->frag3_alerts = 0;

    /* 
     * the IpAddrSet struct is initialized in Frag3ParseArgs
     */
    context->bound_addrs = NULL;

    /*
     * parse the configuration for this engine
     */
    Frag3ParseArgs(args, context);

    /*
     * register the preprocessor func node
     */
    if (!frag3_registered)
    {
        pfn = AddFuncToPreprocList(Frag3Defrag, PRIORITY_NETWORK, PP_FRAG3);
        if (pfn)
        {
            frag3_registered = 1;
            pfn->context = NULL;

            frag_rebuild_buf = (u_int8_t *)SnortAlloc(DATASIZE + SPARC_TWIDDLE);
#ifdef GRE
            gre_frag_rebuild_buf = (u_int8_t *)SnortAlloc(DATASIZE + SPARC_TWIDDLE);
#endif

        }
#ifdef PERF_PROFILING
        RegisterPreprocessorProfile("frag3", &frag3PerfStats, 0, &totalPerfStats);
        RegisterPreprocessorProfile("frag3insert", &frag3InsertPerfStats, 1, &frag3PerfStats);
        RegisterPreprocessorProfile("frag3rebuild", &frag3RebuildPerfStats, 1, &frag3PerfStats);
#endif
    }

    if(!stats_registered)
    {
        AddFuncToPreprocCleanExitList(Frag3CleanExit, NULL, PRIORITY_FIRST, PP_FRAG3);
        AddFuncToPreprocRestartList(Frag3Restart, NULL, PRIORITY_FIRST, PP_FRAG3);
        stats_registered = 1;
    }

    /* Now add this context to the internal list */
    if (frag3ContextList == NULL)
    {
        numFrag3Contexts = 1;
        frag3ContextList = (Frag3Context **)SnortAlloc(sizeof (Frag3Context *)
            * numFrag3Contexts);
    }
    else
    {
        Frag3Context **tmpContextList =
            (Frag3Context **)SnortAlloc(sizeof (Frag3Context *)
            * (++numFrag3Contexts));
        memcpy(tmpContextList, frag3ContextList,
            sizeof(Frag3Context *) * (numFrag3Contexts-1));
        free(frag3ContextList);
        
        frag3ContextList = tmpContextList;
    }
    frag3ContextList[numFrag3Contexts-1] = context;

    /*
     * print this engine config
     */
    Frag3PrintEngineConfig(context);

    return;
}

static int FragPolicyIdFromName(char *name)
{
    if (!name)
    {
        return FRAG_POLICY_DEFAULT;
    }

    if(!strcasecmp(name, "bsd"))
    {
        return FRAG_POLICY_BSD;
    }
    else if(!strcasecmp(name, "bsd-right"))
    {
        return FRAG_POLICY_BSD_RIGHT;
    }
    else if(!strcasecmp(name, "linux"))
    {
        return FRAG_POLICY_LINUX;
    }
    else if(!strcasecmp(name, "first"))
    {
        return FRAG_POLICY_FIRST;
    }
    else if(!strcasecmp(name, "windows"))
    {
        return FRAG_POLICY_WINDOWS;
    }
    else if(!strcasecmp(name, "solaris"))
    {
        return FRAG_POLICY_SOLARIS;
    }
    else if(!strcasecmp(name, "last"))
    {
        return FRAG_POLICY_LAST;
    }
    return FRAG_POLICY_DEFAULT;
}

/**
 * Verify frag3 setup is complete
 *
 * @param args list of configuration arguments
 *
 * @return none
 */
void Frag3VerifyConfig()
{
    if (global_init_complete && (numFrag3Contexts == 0))
        FatalError("Frag3VerifyConfig() policy engine required "
                   "but not configured.\n");
}

/**
 * Handle the preallocation of frags
 *
 * @param int unused
 *        void *arg unused inputs
 *        (these aren't used, just need to match function prototype)
 *
 * @return none
 */
void Frag3PostConfigInit(int unused, void*arg)
{
    Frag3Frag *tmp; /* for initializing the prealloc queue */
    unsigned int i;          /* counter */

    /* 
     * user has decided to prealloc the node structs for performance 
     */
    if(global_config.use_prealloc)
    {
        if (global_config.static_frags == 0)
        {
            global_config.static_frags = (u_int32_t)global_config.memcap /
                (sizeof(Frag3Frag) + sizeof(u_int8_t) * snaplen) + 1;
            ten_percent = global_config.static_frags >> 5;
        }

        for(i=0; i< global_config.static_frags; i++)
        {
            tmp = (Frag3Frag *) SnortAlloc(sizeof(Frag3Frag));
            tmp->fptr = (u_int8_t *) SnortAlloc(sizeof(u_int8_t) * snaplen);
            Frag3PreallocPush(tmp);
        }

        prealloc_nodes_in_use = 0;
    }
}

/**
 * Config parser for global config.  
 *
 * @param args List of configuration parameters
 *
 * @return none
 */
static void Frag3ParseGlobalArgs(u_char *args)
{
    char **toks;
    int num_toks;
    int i;
    char *index;
    char **stoks = NULL;
    int s_toks;

    if(args != NULL && strlen(args) != 0)
    {
        toks = mSplit(args, ",", 12, &num_toks, 0);

        i=0;

        while(i < num_toks)
        {
            index = toks[i];

            while(isspace((int)*index)) index++;

            stoks = mSplit(index, " ", 4, &s_toks, 0);

            if(!strcasecmp(stoks[0], "max_frags"))
            {
                if(isdigit((int)stoks[1][0]))
                {
                    global_config.max_frags = atoi(stoks[1]);
                }
                else
                {
                    LogMessage("WARNING %s(%d) => Bad max_frags in config "
                            "file, defaulting to %d frags\n", 
                            file_name, file_line, 
                            DEFAULT_MAX_FRAGS);

                    global_config.max_frags = DEFAULT_MAX_FRAGS;
                }

            }
            else if(!strcasecmp(stoks[0], "memcap"))
            {
#ifdef FRAG3_USE_MEMCAP
                if(stoks[1] && isdigit((int)stoks[1][0]))
                {
                    global_config.memcap = atoi(stoks[1]);

                    if(global_config.memcap < 16384)
                    {
                        LogMessage("WARNING %s(%d) => Ludicrous (<16k) memcap "
                                "size, setting to default (%d bytes)\n", 
                                file_name, file_line, FRAG_MEMCAP);

                        global_config.memcap = FRAG_MEMCAP;
                    }
                }
                else
                {
                    LogMessage("WARNING %s(%d) => Bad memcap in config file, "
                            "defaulting to %u bytes\n", file_name, file_line, 
                            FRAG_MEMCAP);

                    global_config.memcap = FRAG_MEMCAP;
                }

                /* ok ok, it's really 9.375%, sue me */
                ten_percent = ((global_config.memcap >> 5) + 
                               (global_config.memcap >> 6));
#else
                /* Use memcap to calculate prealloc_frag value */
                int memcap;
                if(stoks[1] && isdigit((int)stoks[1][0]))
                {
                    memcap = atoi(stoks[1]);

                    if(memcap < 16384)
                    {
                        LogMessage("WARNING %s(%d) => Ludicrous (<16k) memcap "
                                "size, setting to default (%d bytes)\n", 
                                file_name, file_line, FRAG_MEMCAP);

                        memcap = FRAG_MEMCAP;
                    }
                }
                else
                {
                    LogMessage("WARNING %s(%d) => Bad memcap in config file, "
                            "defaulting to %u bytes\n", file_name, file_line, 
                            FRAG_MEMCAP);

                    memcap = FRAG_MEMCAP;
                }

                global_config.use_prealloc = 1;
                global_config.memcap = memcap;
#endif
            }
            else if(!strcasecmp(stoks[0], "prealloc_frags"))
            {
                if(isdigit((int)stoks[1][0]))
                {
                    global_config.static_frags = atoi(stoks[1]);
                    global_config.use_prealloc = 1;

                    //ten_percent = ((global_config.static_frags >> 5) + 
                    //        (global_config.static_frags >> 6));
                    ten_percent = global_config.static_frags >> 5;
                }
                else
                {
                    LogMessage("WARNING %s(%d) => Bad prealloc_frags in config "
                            "file, defaulting to dynamic frag management\n",
                            file_name, file_line);

                    global_config.static_frags = 0;
                }
            }
            else
            {
                FatalError("%s(%d) => Invalid Frag3 global option (%s)\n",
                        file_name, file_line, index);
            }

            mSplitFree(&stoks, s_toks);

            i++;
        }
        mSplitFree(&toks, num_toks);
    }

    return;
}

/**
 * Config parser for engine context config.  
 *
 * @param args List of configuration parameters
 *
 * @return none
 */
static void Frag3ParseArgs(u_char *args, Frag3Context *context)
{
    char **toks;
    int num_toks;
    int i;
    char *index;

    if(args == NULL || strlen(args) == 0)
    {
        return;
    }
    else
    {
        int increment;
        toks = mSplit(args, " ", 13, &num_toks, 0);

        i=0;

        while(i < num_toks)
        {
            increment = 1;
            index = toks[i];

            if(!strcasecmp(index, "timeout"))
            {
                if(i+1 < num_toks && isdigit((int)toks[i+1][0]))
                {
                    context->frag_timeout = atoi(toks[i+1]);
                    increment = 2;
                }
                else
                {
                    LogMessage("WARNING %s(%d) => Bad timeout in config file, "
                            "defaulting to %d seconds\n", file_name, 
                            file_line, FRAG_PRUNE_QUANTA);

                    context->frag_timeout = FRAG_PRUNE_QUANTA;
                }
            }
            else if(!strcasecmp(index, "ttl_limit"))
            {
                if(i+1 >= num_toks || toks[i+1][0] == '\0')
                {
                    FatalError("%s(%d) => ttl_limit requires an integer "
                            "argument\n", file_name,file_line);
                }

                if(isdigit((int)toks[i+1][0]))
                {
                    context->ttl_limit = atoi(toks[i+1]);
                    increment = 2;
                }
                else
                {
                    LogMessage("WARNING %s(%d) => Bad TTL Limit"
                            "size, setting to default (%d\n", file_name, 
                            file_line, FRAG3_TTL_LIMIT);

                    context->ttl_limit = FRAG3_TTL_LIMIT;
                }
            }
            else if(!strcasecmp(index, "min_ttl"))
            {
                if(i+1 >= num_toks || toks[i+1][0] == '\0')
                {
                    FatalError("%s(%d) => min_ttl requires an integer "
                            "argument\n", file_name,file_line);
                }

                if(isdigit((int)toks[i+1][0]))
                {
                    context->min_ttl = atoi(toks[i+1]);
                    increment = 2;
                }
                else
                {
                    LogMessage("WARNING %s(%d) => Bad Min TTL "
                            "size, setting to default (%d\n", file_name, 
                            file_line, FRAG3_MIN_TTL);

                    context->min_ttl = FRAG3_MIN_TTL;
                }
            }
            else if(!strcasecmp(index, "detect_anomalies"))
            {
                context->frag3_alerts |= FRAG3_DETECT_ANOMALIES;
            }
            else if(!strcasecmp(index, "policy"))
            {
                if (i+1 >= num_toks)
                    FatalError("%s(%d) => policy requires a policy "
                            "identifier argument\n", file_name, file_line);

                context->frag_policy = FragPolicyIdFromName(toks[i+1]);

                if ((context->frag_policy == FRAG_POLICY_DEFAULT) &&
                    (strcasecmp(toks[i+1], "bsd")))
                {
                    FatalError("%s(%d) => Bad policy name \"%s\"\n",
                            file_name, file_line, toks[i+1]);
                }
                increment = 2;
            }
            else if(!strcasecmp(index, "bind_to"))
            {
                if (i+1 < num_toks)
                {
                    context->bound_addrs = IpAddrSetParse(toks[i+1]);
                    increment = 2;
                }
                else
                {
                    FatalError("%s(%d) => bind_to requires an IP list or "
                            "CIDR block argument\n", file_name, file_line);
                }
            }
            else
            {
                FatalError("%s(%d) => Invalid Frag3 engine option (%s)\n",
                        file_name, file_line, index);
            }

            i += increment;
        }

        mSplitFree(&toks, num_toks);

        if(context->bound_addrs == NULL)
        {
            /* allocate and initializes the IpAddrSet at the same time 
             * set to "any"
             */
            context->bound_addrs = (IpAddrSet *) SnortAlloc(sizeof(IpAddrSet));
        }
    }

    return;
}


/**
 * Main runtime entry point for Frag3
 *
 * @param p Current packet to process.
 * @param context Context for this defrag engine
 *
 * @return none
 */
void Frag3Defrag(Packet *p, void *context)
{
    FRAGKEY fkey;            /* fragkey for this packet */
    FragTracker *ft;         /* FragTracker to process the packet on */
    Frag3Context *f3context = NULL; /* engine context */
    int engineIndex;
    int insert_return = 0;   /* return value from the insert function */
    PROFILE_VARS;

    /*
     * check to make sure this preprocessor should run
     */
    if( (p == NULL) || 
            p->iph == NULL || !p->frag_flag ||
            (p->csum_flags & CSE_IP) ||
            (p->packet_flags & PKT_REBUILT_FRAG))
    {
        return;
    }

    /* Find an engine context for this packet */
    for (engineIndex = 0; engineIndex < numFrag3Contexts; engineIndex++)
    {
        f3context = frag3ContextList[engineIndex];
        
        /*
         * Does this engine context handle fragments to this IP address?
         */
        if(IpAddrSetContains(f3context->bound_addrs, p->iph->ip_dst))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                        "[FRAG3] Found engine context in IpAddrSet\n"););
            break;
        }
        else
        {
            f3context = NULL;
        }
    }

    if (!f3context)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                    "[FRAG3] Could not find Frag3 engine context "
                    "for IP %s\n", inet_ntoa(p->iph->ip_dst)););
        return;
    }

    /* Ugly HACK -- if frag offset is 0 & UDP, let that packet go
     * through the rest of the system.  This results in the
     * first packet going through detection.  If we do see
     * the rest of the frags, the contents of that first frag
     * will go through again with the defrag'd (built) packet.
     */
    if ((p->frag_offset != 0) || (p->iph->ip_proto != IPPROTO_UDP))
    {
        /*
         * This packet is fragmented, will either be dropped
         * or payload included in a rebuilt packet later.  Don't
         * process it further.
         */
         DisableDetect(p);
         SetPreprocBit(p, PP_SFPORTSCAN);
         SetPreprocBit(p, PP_PERFMONITOR);
         otn_tmp = NULL;
    }

#if 0
    /* 
     * fragments with IP options are bad, m'kay?
     */
    if(p->ip_options_len)
    {
        EventAnomIpOpts(f3context);
        f3stats.discards++;
        return;
    }
#endif

    /*
     * pkt's not going to make it to the target, bail 
     */
    if(p->iph->ip_ttl < f3context->min_ttl)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "[FRAG3] Fragment discarded due to low TTL "
                "[0x%X->0x%X], TTL: %d  " "Offset: %d Length: %d\n", 
                ntohl(p->iph->ip_src.s_addr), 
                ntohl(p->iph->ip_dst.s_addr), 
                p->iph->ip_ttl, p->frag_offset, 
                p->dsize););

        f3stats.discards++;
        return;
    }

    f3stats.total++;
    UpdateIPFragStats(&(sfPerf.sfBase), p->pkth->caplen);

    PREPROC_PROFILE_START(frag3PerfStats);

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                "\n++++++++++++++++++++++++++++++++++++++++++++++\n"););
    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                "[**] [FRAG3] Inspecting fragment...\n"););
    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                "[FRAG3] Got frag packet (mem use: %ld frag "
                "trackers: %d  p->pkt_flags: 0x%X "
                "prealloc nodes in use: %lu/%lu)\n", 
                mem_in_use,
                sfxhash_count(f_cache), 
                p->packet_flags, prealloc_nodes_in_use, 
                global_config.static_frags););

    /* zero the frag key */
    memset(&fkey, 0, sizeof(FRAGKEY));

#if 0
    /*
     * Check the memcap and clear some space if we're over the memcap
     */
    if(mem_in_use > global_config.memcap)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                    "memcap exceeded (%ld bytes in use), "
                    "calling Frag3Prune()\n", mem_in_use););
        Frag3Prune();
    }
#endif
    pkttime = (struct timeval *) &p->pkth->ts;

    /* 
     * try to get the tracker that this frag should go with 
     */
    if((ft = Frag3GetTracker(p, &fkey)) == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "Adding New FragTracker...\n"););

        /* 
         * first frag for this packet, start a new tracker 
         */
        Frag3NewTracker(p, &fkey, f3context);

        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                    "[FRAG3] mem use: %ld frag "
                    "trackers: %d  prealloc "
                    "nodes in use: %lu/%lu\n", 
                    mem_in_use,
                    sfxhash_count(f_cache), 
                    prealloc_nodes_in_use, 
                    global_config.static_frags););
        /* 
         * all done, return control to Snort
         */
        PREPROC_PROFILE_END(frag3PerfStats);
        return;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "Found frag tracker\n"););

    /*
     * insert the fragment into the FragTracker
     */
    if((insert_return = Frag3Insert(p, ft, &fkey, f3context)) != FRAG_INSERT_OK)
    {
        /*
         * we can pad this switch out for a variety of entertaining behaviors
         * later if we're so inclined
         */
        switch(insert_return)
        {
            case FRAG_INSERT_FAILED:
#ifdef DEBUG
                if(!pv.quiet_flag)
                {
                    LogMessage("WARNING: Insert into Fraglist failed, "
                            "(offset: %u)\n", p->frag_offset);
                }
#endif
                PREPROC_PROFILE_END(frag3PerfStats);
                return;
            case FRAG_INSERT_TTL:
                DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                        "[FRAG3] Fragment discarded due to large TTL Delta "
                        "[0x%X->0x%X], TTL: %d  orig TTL: %d "
                        "Offset: %d Length: %d\n", 
                        ntohl(p->iph->ip_src.s_addr), 
                        ntohl(p->iph->ip_dst.s_addr), 
                        p->iph->ip_ttl, ft->ttl, p->frag_offset, 
                        p->dsize););
                f3stats.discards++;
                PREPROC_PROFILE_END(frag3PerfStats);
                return;
            case FRAG_INSERT_ATTACK:
            case FRAG_INSERT_ANOMALY:
                f3stats.discards++;
                PREPROC_PROFILE_END(frag3PerfStats);
                return;
            case FRAG_INSERT_TIMEOUT:
#ifdef DEBUG
                if(!pv.quiet_flag)
                {
                    LogMessage("WARNING: Insert into Fraglist failed due to timeout, "
                            "(offset: %u)\n", p->frag_offset);
                }
#endif
                PREPROC_PROFILE_END(frag3PerfStats);
                return;
            default:
                break;
        }
    }

    p->fragtracker = (void *)ft;

    /* 
     * check to see if it's reassembly time 
     */
    if(Frag3IsComplete(ft))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                    "[*] Fragment is complete, rebuilding!\n"););

        /* 
         * if the frag completes but it's bad we're just going to drop it
         * instead of wasting time on putting it back together
         */
        if(!(ft->frag_flags & FRAG_BAD))
        {
            Frag3Rebuild(ft, p);

            if (p->frag_offset != 0 ||
                (p->iph->ip_proto != IPPROTO_UDP && ft->frag_flags & FRAG_REBUILT))
            {
                /* Need to reset some things here because the
                 * rebuilt packet will have reset the do_detect
                 * flag when it hits Preprocess.
                 */
                do_detect_content = do_detect = 0;
                otn_tmp = NULL;
                /* And unset the frag tracker for this packet since
                 * we're going to blow it away in a few usecs...
                 */
                p->fragtracker = NULL;
            }
        }

        Frag3RemoveTracker(&fkey, ft);

    }

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                "[FRAG3] Dumped fragtracker (mem use: %ld frag "
                "trackers: %d  prealloc "
                "nodes in use: %lu/%lu)\n", 
                mem_in_use,
                sfxhash_count(f_cache), 
                prealloc_nodes_in_use, 
                global_config.static_frags););

    PREPROC_PROFILE_END(frag3PerfStats);
    return;
}

/**
 * Check to see if a FragTracker has timed out
 *
 * @param current_time Time at this moment
 * @param start_time Time to compare current_time to
 * @param f3context Engine context
 *
 * @return status
 * @retval  FRAG_TIMEOUT Current time diff is greater than the current 
 *                       context's timeout value
 * @retval  FRAG_TIME_OK Current time diff is within the context's prune
 *                       window                      
 */
static INLINE int CheckTimeout(struct timeval *current_time, 
        struct timeval *start_time, 
        Frag3Context *f3context)
{
    struct timeval tv_diff; /* storage struct for the difference between 
                               current_time and start_time */

    TIMERSUB(current_time, start_time, &tv_diff);
    
    if(tv_diff.tv_sec >= f3context->frag_timeout)
    {
        return FRAG_TIMEOUT;
    }

    return FRAG_TIME_OK;
}

/**
 * Time-related expiration of fragments from the system.  Checks the current
 * FragTracker for timeout, then walks up the LRU list looking to see if 
 * anyone should have timed out.
 *
 * @param p Current packet (contains pointer to the current timestamp)
 * @param ft FragTracker to check for a timeout
 * @param fkey FragKey of the current FragTracker for sfxhash lookup
 * @param f3context Context of the defrag engine, contains the timeout value
 *
 * @return status
 * @retval FRAG_TRACKER_TIMEOUT The current FragTracker has timed out
 * @retval FRAG_OK The current FragTracker has not timed out
 */
static int Frag3Expire(
        Packet *p, 
        FragTracker *ft, 
        FRAGKEY *fkey, 
        Frag3Context *f3context)
{
#if 0
    struct timeval *fttime;     /* FragTracker timestamp */
    struct timeval *pkttime;    /* packet timestamp */
    FragTracker *tmpft;         /* temp pointer for moving thru the LRU queue */
#endif

    /*
     * Check the FragTracker that was passed in first
     */
    if(CheckTimeout(
                pkttime,
                &(ft)->frag_time, 
                f3context) == FRAG_TIMEOUT)
    {
        /*
         * Oops, we've timed out, whack the FragTracker
         */
#ifdef DEBUG_FRAG3
        if (DEBUG_FRAG & GetDebugLevel())
            LogMessage("(spp_frag3) Current Fragment dropped due to timeout! "
                "[0x%08X->0x%08X ID: %d]\n", ft->sip, ft->dip, ft->id);
#endif

        /*
         * Don't remove the tracker.
         * Remove all of the packets that are stored therein.
         *
         * If the existing tracker times out because of a delay
         * relative to the timeout
         */
        //Frag3RemoveTracker(fkey, ft);
        Frag3DeleteTracker(ft);

        f3stats.timeouts++;
        sfPerf.sfBase.iFragTimeouts++;

        return FRAG_TRACKER_TIMEOUT;
    }

#if 0
    /*
     * This doesn't really need to be done here!!!
     * We'll blow them away when we prune for memory reasons.
     */

    /* 
     * The current FragTracker hasn't timed out, check the LRU FragTrackers to
     * see if any of them need to go.
     */
    if((tmpft = (FragTracker*)sfxhash_lru(f_cache)))
    {
        fttime = &tmpft->frag_time;
        pkttime = (struct timeval *) &p->pkth->ts;

        while(tmpft && CheckTimeout(pkttime,fttime,f3context)==FRAG_TIMEOUT)
        {
            LogMessage("(spp_frag3) Fragment dropped due to timeout! "
                    "[0x%08X->0x%08X ID: %d]\n", tmpft->sip, tmpft->dip, 
                    tmpft->id);

            sfxhash_free_node(f_cache, sfxhash_lru_node(f_cache));

            f3stats.timeouts++;
            sfPerf.sfBase.iFragTimeouts++;

            if((tmpft = (FragTracker*)(sfxhash_lru(f_cache))))
            {
                fttime = &tmpft->frag_time;
            }
        }
    }
#endif

    /*
     * set the current FragTracker's timeout on our way out the door...
     */
    /* XXX Uh, I shouldn't be doing this should I???? */
    //ft->frag_time.tv_sec = p->pkth->ts.tv_sec;
    //ft->frag_time.tv_usec = p->pkth->ts.tv_usec;

    return FRAG_OK;
}

/**
 * Check to see if we've got the first or last fragment on a FragTracker and
 * set the appropriate frag_flags
 *
 * @param p Packet to get the info from
 * @param ft FragTracker to set the flags on 
 *
 * @return none
 */
static int INLINE Frag3CheckFirstLast(Packet *p, FragTracker *ft)
{
    u_int16_t fragLength;
    int retVal = FRAG_FIRSTLAST_OK;
    u_int16_t endOfThisFrag;


    /* set the frag flag if this is the first fragment */
    if(p->mf && p->frag_offset == 0)
    {
        ft->frag_flags |= FRAG_GOT_FIRST;

        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "Got first frag\n"););
    }
    else if((!p->mf) && (p->frag_offset > 0)) /* set for last frag too */
    {
        /* Use the actual length here, because packet may have been
        * truncated.  Don't want to try to copy more than we actually
        * captured. */
        fragLength = p->actual_ip_len - IP_HLEN(p->iph) * 4;
        endOfThisFrag = (p->frag_offset << 3) + fragLength;

        if (ft->frag_flags & FRAG_GOT_LAST)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "Got last frag again!\n"););
            switch (ft->frag_policy)
            {
                case FRAG_POLICY_BSD:
                case FRAG_POLICY_LINUX:
                case FRAG_POLICY_BSD_RIGHT:
                case FRAG_POLICY_LAST:
                case FRAG_POLICY_WINDOWS:
                case FRAG_POLICY_FIRST:
                    if (ft->calculated_size > endOfThisFrag)
                    {
                       /* Already have a 'last frag' with a higher
                        * end point.  Leave it as is.
                        *
                        * Some OS's do not respond at all -- we'll
                        * still try to rebuild anyway in that case,
                        * because there is really something wrong
                        * and we should look at it.
                        */
                        retVal = FRAG_LAST_DUPLICATE;
                    }
                    break;
                case FRAG_POLICY_SOLARIS:
                    if (ft->calculated_size > endOfThisFrag)
                    {
                       /* Already have a 'last frag' with a higher
                        * end point.  Leave it as is.
                        *
                        * Some OS's do not respond at all -- we'll
                        * still try to rebuild anyway in that case,
                        * because there is really something wrong
                        * and we should look at it.
                        */
                        retVal = FRAG_LAST_DUPLICATE;
                    }
                    else
                    {
                        /* Solaris does some weird stuff here... */
                        /* Usually, Solaris takes the higher end point.
                         * But in one strange case (when it hasn't seen
                         * any frags beyond the existing last frag), it
                         * actually appends that new last frag to the
                         * end of the previous last frag, regardless of
                         * the offset.  Effectively, it adjusts the
                         * offset of the new last frag to immediately
                         * after the existing last frag.
                         */
                        /* XXX: how to handle that case? punt?  */
                        retVal = FRAG_LAST_OFFSET_ADJUST;
                    }
                    break;
            }
        }

        ft->frag_flags |= FRAG_GOT_LAST;

        /*
         * If this is the last frag (and we don't have a frag that already
         * extends beyond this one), set the size that we're expecting.
         */
        if ((ft->calculated_size < endOfThisFrag) &&
            (retVal != FRAG_LAST_OFFSET_ADJUST))
        {
            ft->calculated_size = endOfThisFrag;

            DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "Got last frag, Bytes: %d, "
                    "Calculated size: %d\n",
                    ft->frag_bytes,
                    ft->calculated_size););
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "Frag Status: %s:%s\n", 
                ft->frag_flags&FRAG_GOT_FIRST?"FIRST":"No FIRST", 
                ft->frag_flags&FRAG_GOT_LAST?"LAST":"No LAST"););
    return retVal; 
}

/**
 * Lookup a FragTracker in the f_cache sfxhash table based on an input key
 *
 * @param p The current packet to get the key info from
 * @param fkey Pointer to a container for the FragKey
 *
 * @return Pointer to the FragTracker in the hash bucket or NULL if there is 
 *         no fragment in the hash bucket
 */
static FragTracker *Frag3GetTracker(Packet *p, FRAGKEY *fkey)
{
    FragTracker *returned; /* FragTracker ptr returned by the lookup */

    /* 
     * we have to setup the key first, downstream functions depend on
     * it being setup here
     */
    fkey->sip = p->iph->ip_src.s_addr;
    fkey->dip = p->iph->ip_dst.s_addr;
    fkey->id = p->iph->ip_id;
    fkey->proto = p->iph->ip_proto;

    /*
     * if the hash table is empty we're done
     */
    if(sfxhash_count(f_cache) == 0)
        return NULL;

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                "[*] Looking up FragTracker using key:\n"););

#ifdef DEBUG_FRAG3
    PrintFragKey(fkey);
#endif

    returned = (FragTracker *) sfxhash_find(f_cache, fkey);

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                "Frag3GetTracker returning %p for\n", returned););

    return returned;
}

/**
 * Handle IP Options in fragmented packets.
 *
 * @param ft Current frag tracker for this packet
 * @param p Current packet to check for options
 * @param context In case we get an anomaly
 *
 * @return status
 * @retval 0 on an error
 * @retval 1 on success
 */
static int Frag3HandleIPOptions(FragTracker *ft,
                                Packet *p)
{
    unsigned int i = 0;          /* counter */
    if(p->frag_offset == 0)
    {
        /*
         * This is the first packet.  If it has IP options,
         * save them off, so we can set them on the reassembled packet.
         */
        if (p->ip_options_len)
        {
            ft->ip_options_len = p->ip_options_len;
            ft->ip_option_count = p->ip_option_count;
            ft->ip_options_data = SnortAlloc(p->ip_options_len);
            memcpy(ft->ip_options_data, p->ip_options_data, p->ip_options_len);
        }
    }
    else
    {
        /* check that options match those from other non-offset 0 packets */

        /* XXX: could check each individual option here, but that
         * would be performance ugly.  So, we'll just check that the
         * option counts match.  Alert if invalid, but still include in
         * reassembly.
         */
        if (ft->copied_ip_option_count)
        {
            if (ft->copied_ip_option_count != p->ip_option_count)
            {
                EventAnomIpOpts(ft->context);
            }
        }
        else
        {
            ft->copied_ip_option_count = p->ip_option_count;
            for (i = 0;i< p->ip_option_count && i < IP_OPTMAX; i++)
            {
                /* Is the high bit set?  If not, weird anomaly. */
                if (!(p->ip_options[i].code & 0x80))
                    EventAnomIpOpts(ft->context);
            }
        }
    }
    return 1;
}

int FragGetPolicy(FragTracker *ft, Frag3Context *f3context)
{
    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
        "FragGetPolicy: Using configured default %d(%s)\n",
        f3context->frag_policy, frag_policy_names[f3context->frag_policy]););

    return f3context->frag_policy;
}


/**
 * Didn't find a FragTracker in the hash table, create a new one and put it
 * into the f_cache
 *
 * @param p Current packet to fill in FragTracker fields
 * @param fkey FragKey struct to use for table insertion
 *
 * @return status
 * @retval 0 on an error
 * @retval 1 on success
 */
static int Frag3NewTracker(Packet *p, FRAGKEY *fkey, Frag3Context *f3context)
{
    FragTracker *tmp;
    Frag3Frag *f = NULL;
    //int ret = 0;
    char *fragStart;
    u_int16_t fragLength;
    u_int16_t frag_end;
    SFXHASH_NODE *hnode;

    fragStart = (u_int8_t *)p->iph + IP_HLEN(p->iph) * 4;
    /* Use the actual length here, because packet may have been
     * truncated.  Don't want to try to copy more than we actually
     * captured. */
    fragLength = p->actual_ip_len - IP_HLEN(p->iph) * 4;
#ifdef DEBUG
    if (p->actual_ip_len != ntohs(p->iph->ip_len))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
               "IP Actual Length (%d) != specified length (%d), "
               "truncated packet (%d)?\n",
                p->actual_ip_len, ntohs(p->iph->ip_len), snaplen););
    }
#endif

    /* Just to double check */
    if (fragLength > snaplen)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "Overly large fragment %d 0x%x 0x%x %d\n",
                    fragLength, p->iph->ip_len, p->iph->ip_off,
                    p->frag_offset << 3););

        /* Ah, crap.  Return that tracker. */
        return 0;
    }
    /* Get a node from the hash table */
    hnode = sfxhash_get_node(f_cache, fkey);
    if (!hnode)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "Frag3NewTracker: sfxhash_get_node() failed\n"););

        return 0;
    }
    else
    {
        if (hnode->data)
        {
            tmp = hnode->data;
            memset(tmp, 0, sizeof(FragTracker));
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "Frag3NewTracker: sfxhash_get_node() failed\n"););

            return 0;
        }
    }

    /* 
     * setup the frag tracker 
     */
    tmp->sip = fkey->sip;
    tmp->dip = fkey->dip;
    tmp->id = fkey->id;
    tmp->protocol = fkey->proto;
    tmp->ttl = p->iph->ip_ttl; /* store the first ttl we got */
    tmp->calculated_size = 0;
    tmp->alerted = 0;
    tmp->frag_flags = 0;
    tmp->frag_bytes = 0;
    tmp->frag_pkts = 0;
    tmp->frag_time.tv_sec = p->pkth->ts.tv_sec;
    tmp->frag_time.tv_usec = p->pkth->ts.tv_usec;
    tmp->alert_count = 0;
    tmp->ip_options_len = 0;
    tmp->ip_option_count = 0;
    tmp->ip_options_data = NULL;
    tmp->copied_ip_options_len = 0;
    tmp->copied_ip_option_count = 0;
    tmp->context = f3context;
    tmp->ordinal = 0;
    tmp->frag_policy = FragGetPolicy(tmp, f3context);

    /* 
     * get our first fragment storage struct 
     */
    if(!global_config.use_prealloc)
    {
        if(mem_in_use > global_config.memcap)
        {
            if (Frag3Prune(tmp) == 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "Frag3NewTracker: Pruning failed\n"););

                return 0;
            }
        }

        f = (Frag3Frag *) SnortAlloc(sizeof(Frag3Frag));
        mem_in_use += sizeof(Frag3Frag);

        f->fptr = (u_int8_t *) SnortAlloc(fragLength);
        mem_in_use += fragLength;
    

    }
    else
    {
        while((f = Frag3PreallocPop()) == NULL)
        {
            if (Frag3Prune(tmp) == 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "Frag3NewTracker: Pruning failed\n"););

                return 0;
            }
        }
    }

    f3stats.fragnodes_created++;
    sfPerf.sfBase.iFragCreates++;
    sfPerf.sfBase.iCurrentFrags++;
    if (sfPerf.sfBase.iCurrentFrags > sfPerf.sfBase.iMaxFrags)
        sfPerf.sfBase.iMaxFrags = sfPerf.sfBase.iCurrentFrags;

    /* initialize the fragment list */
    tmp->fraglist = NULL;

    /*
     * setup the Frag3Frag struct with the current packet's data
     */
    memcpy(f->fptr, fragStart, fragLength);

    f->size = f->flen = fragLength;
    f->offset = p->frag_offset << 3;
    frag_end = f->offset + fragLength;
    f->ord = tmp->ordinal++;
    f->data = f->fptr;     /* ptr to adjusted start position */
    if (!p->mf)
    {
        f->last = 1;
    }
    else
    {
        /* 
         * all non-last frags are supposed to end on 8-byte boundries 
         */
        if(frag_end & 7)
        {
            /* 
             * bonk/boink/jolt/etc attack... 
             */
            DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                        "[..] Short frag (Bonk, etc) attack!\n"););

            EventAnomShortFrag(f3context);

            /* don't return, might still be interesting... */
        }

        /* can't have non-full fragments... */
        frag_end &= ~7;

        /* Adjust len to take into account the jolting/non-full fragment. */
        f->size = frag_end - f->offset;
    }

    /* insert the fragment into the frag list */
    tmp->fraglist = f;
    tmp->fraglist_tail = f;
    tmp->fraglist_count = 1;  /* XXX: Are these duplciates? */
    tmp->frag_pkts = 1;

    /*
     * mark the FragTracker if this is the first/last frag
     */
    Frag3CheckFirstLast(p, tmp);

    tmp->frag_bytes += fragLength;

    Frag3HandleIPOptions(tmp, p);

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                "[#] accumulated bytes on FragTracker: %d\n", 
                tmp->frag_bytes););

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "Initial fragment for tracker, ptr %p, offset %d, "
                "size %d\n", f, f->offset, f->size););

#ifdef DEBUG_FRAG3
    PrintFragKey(fkey);
#endif 

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "Calling sfxhash(add), overhead at %lu\n", 
                f_cache->overhead_bytes););

#if 0
    /* 
     * insert the frag tracker into the fragment hash 
     */
    if((ret = sfxhash_add(f_cache, fkey, &tmp)) != SFXHASH_OK)
    {
        if(ret == SFXHASH_INTABLE)
        {
            LogMessage("Key collision in sfxhash!\n");
        }

        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "Frag3NewTracker: sfxhash_add() failed\n"););

        return 0;
    }
#endif

    f3stats.fragtrackers_created++;
    pc.frag_trackers++;

    p->fragtracker = (void *)tmp;

    return 1;
}

/**
 * Handle the creation of the new frag node and list insertion.
 * Separating this from actually calculating the values.
 *
 * @param ft FragTracker to hold the packet
 * @param fragStart Pointer to start of the packet data
 * @param fragLength Length of packet data
 * @param len Length of this fragment
 * @param slide Adjustment to make to left side of data (for left overlaps)
 * @param trunc Adjustment to maek to right side of data (for right overlaps)
 * @param frag_offset Offset for this fragment
 * @prarm left FragNode prior to this one
 * @param retFrag this one after its inserted (returned)
 *
 * @return status
 * @retval FRAG_INSERT_FAILED Memory problem, insertion failed
 * @retval FRAG_INSERT_OK All okay
 */
static int AddFragNode(FragTracker *ft,
                Packet *p,
                Frag3Context *f3context,
                u_int8_t *fragStart,
                int16_t fragLength,
                char lastfrag,
                int16_t len,
                u_int16_t slide,
                u_int16_t trunc,
                u_int16_t frag_offset,
                Frag3Frag *left,
                Frag3Frag **retFrag)
{
    Frag3Frag *newfrag = NULL;  /* new frag container */
    int16_t newSize = len - slide - trunc;

    if (newSize <= 0)
    {
        /* 
         * zero size frag
         */
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
            "zero size frag after left & right trimming "
            "(len: %d  slide: %d  trunc: %d)\n", 
            len, slide, trunc););

        f3stats.discards++;

#ifdef DEBUG
        newfrag = ft->fraglist;
        while (newfrag)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                   "Size: %d, offset: %d, len %d, "
                   "Prev: 0x%x, Next: 0x%x, This: 0x%x, Ord: %d, %s\n",
                   newfrag->size, newfrag->offset,
                   newfrag->flen, newfrag->prev,
                   newfrag->next, newfrag, newfrag->ord,
                   newfrag->last ? "Last":""););
            newfrag = newfrag->next;
        }
#endif

        return FRAG_INSERT_ANOMALY;
    }

    /*
     * grab/generate a new frag node
     */
    if(!global_config.use_prealloc)
    {
        if(mem_in_use > global_config.memcap)
        {
            if (Frag3Prune(ft) == 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "Frag3Insert: Pruning failed\n"););

                return FRAG_INSERT_FAILED;
            }
        }

        /* 
         * build a frag struct to track this particular fragment 
         */
        newfrag = (Frag3Frag *) SnortAlloc(sizeof(Frag3Frag)); 
        mem_in_use += sizeof(Frag3Frag);

        /* 
         * allocate some space to hold the actual data 
         */
        newfrag->fptr = (u_int8_t*)SnortAlloc(fragLength);
        mem_in_use += fragLength;
    }
    else
    {
        /* 
         * fragments are preallocated, grab one from the list 
         */
        while((newfrag = Frag3PreallocPop()) == NULL)
        {
            if (Frag3Prune(ft) == 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "Frag3Insert: Pruning failed\n"););

                return FRAG_INSERT_FAILED;
            }
        }

        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                    "got newfrag (%p) from prealloc\n", newfrag););
    }

    f3stats.fragnodes_created++;

    newfrag->flen = fragLength;  
    memcpy(newfrag->fptr, fragStart, fragLength);
    newfrag->ord = ft->ordinal++;

    /* 
     * twiddle the frag values for overlaps
     */
    newfrag->data = newfrag->fptr + slide;
    newfrag->size = newSize;
    newfrag->offset = frag_offset;
    newfrag->last = lastfrag;

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                "[+] Adding new frag, offset %d, size %d\n"
                "   nf->data = nf->fptr(%p) + slide (%d)\n"
                "   nf->size = len(%d) - slide(%d) - trunc(%d)\n",
                newfrag->offset, newfrag->size, newfrag->fptr,
                slide, fragLength, slide, trunc););

    /*
     * insert the new frag into the list 
     */
    Frag3FraglistAddNode(ft, left, newfrag);

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                "[*] Inserted new frag %d@%d ptr %p data %p prv %p nxt %p\n", 
                newfrag->size, newfrag->offset, newfrag, newfrag->data,
                newfrag->prev, newfrag->next););

    /*
     * record the current size of the data in the fraglist
     */
    ft->frag_bytes += newfrag->size;

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                "[#] accumulated bytes on FragTracker %d, count"
                " %d\n", ft->frag_bytes, ft->fraglist_count););

    *retFrag = newfrag;
    return FRAG_INSERT_OK;
}

/**
 * Duplicate a frag node and insert it into the list.
 *
 * @param ft FragTracker to hold the packet
 * @prarm left FragNode prior to this one (to be dup'd)
 * @param retFrag this one after its inserted (returned)
 *
 * @return status
 * @retval FRAG_INSERT_FAILED Memory problem, insertion failed
 * @retval FRAG_INSERT_OK All okay
 */
static int DupFragNode(FragTracker *ft,
                Frag3Frag *left,
                Frag3Frag **retFrag)
{
    Frag3Frag *newfrag = NULL;  /* new frag container */

    /*
     * grab/generate a new frag node
     */
    if(!global_config.use_prealloc)
    {
        if(mem_in_use > global_config.memcap)
        {
            if (Frag3Prune(ft) == 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "Frag3Insert: Pruning failed\n"););

                return FRAG_INSERT_FAILED;
            }
        }

        /* 
         * build a frag struct to track this particular fragment 
         */
        newfrag = (Frag3Frag *) SnortAlloc(sizeof(Frag3Frag)); 
        mem_in_use += sizeof(Frag3Frag);

        /* 
         * allocate some space to hold the actual data 
         */
        newfrag->fptr = (u_int8_t*)SnortAlloc(left->flen);
        mem_in_use += left->flen;
    }
    else
    {
        /* 
         * fragments are preallocated, grab one from the list 
         */
        while((newfrag = Frag3PreallocPop()) == NULL)
        {
            if (Frag3Prune(ft) == 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "Frag3Insert: Pruning failed\n"););

                return FRAG_INSERT_FAILED;
            }
        }

        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                    "got newfrag (%p) from prealloc\n", newfrag););
    }

    f3stats.fragnodes_created++;

    newfrag->ord = ft->ordinal++;
    /* 
     * twiddle the frag values for overlaps
     */
    newfrag->flen = left->flen;
    memcpy(newfrag->fptr, left->fptr, newfrag->flen);
    newfrag->data = newfrag->fptr + (left->data - left->fptr);
    newfrag->size = left->size;
    newfrag->offset = left->offset;
    newfrag->last = left->last;

    /*
     * insert the new frag into the list 
     */
    Frag3FraglistAddNode(ft, left, newfrag);

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                "[*] Inserted new frag %d@%d ptr %p data %p prv %p nxt %p\n", 
                newfrag->size, newfrag->offset, newfrag, newfrag->data,
                newfrag->prev, newfrag->next););

    /*
     * record the current size of the data in the fraglist
     */
    ft->frag_bytes += newfrag->size;

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                "[#] accumulated bytes on FragTracker %d, count"
                " %d\n", ft->frag_bytes, ft->fraglist_count););

    *retFrag = newfrag;
    return FRAG_INSERT_OK;
}

/**
 * This is where the rubber hits the road.  Insert the new fragment's data 
 * into the current FragTracker's fraglist, doing anomaly detection and
 * handling overlaps in a target-based manner.
 *
 * @param p Current packet to insert
 * @param ft FragTracker to hold the packet
 * @param fkey FragKey with the current FragTracker's key info
 * @param f3context context of the current engine for target-based defrag info
 *
 * @return status
 * @retval FRAG_INSERT_TIMEOUT FragTracker has timed out and been dropped
 * @retval FRAG_INSERT_ATTACK  Attack detected during insertion
 * @retval FRAG_INSERT_ANOMALY Anomaly detected during insertion
 * @retval FRAG_INSERT_TTL Delta of TTL values beyond configured value
 * @retval FRAG_INSERT_OK Fragment has been inserted successfully
 */
static int Frag3Insert(Packet *p, FragTracker *ft, FRAGKEY *fkey, 
        Frag3Context *f3context)
{
    u_int16_t orig_offset;    /* offset specified in this fragment header */
    u_int16_t frag_offset;    /* calculated offset for this fragment */
    u_int16_t frag_end;       /* calculated end point for this fragment */
    int16_t trunc = 0;      /* we truncate off the tail */
    int32_t overlap = 0;    /* we overlap on either end of the frag */
    int16_t len = 0;        /* calculated size of the fragment */
    int16_t slide = 0;      /* slide up the front of the current frag */
    int done = 0;           /* flag for right-side overlap handling loop */
    int addthis = 1;           /* flag for right-side overlap handling loop */
    int i = 0;              /* counter */
    int delta = 0;
    int firstLastOk;
    int ret = FRAG_INSERT_OK;
    unsigned char lastfrag = 0; /* Set to 1 when this is the 'last' frag */
    unsigned char alerted_overlap = 0; /* Set to 1 when alerted */
    Frag3Frag *right = NULL; /* frag ptr for right-side overlap loop */
    Frag3Frag *newfrag = NULL;  /* new frag container */
    Frag3Frag *left = NULL;     /* left-side overlap fragment ptr */
    Frag3Frag *idx = NULL;      /* indexing fragment pointer for loops */
    Frag3Frag *dump_me = NULL;  /* frag ptr for complete overlaps to dump */
    u_int8_t *fragStart;
    int16_t fragLength;
    PROFILE_VARS;
    
    sfPerf.sfBase.iFragInserts++;

    PREPROC_PROFILE_START(frag3InsertPerfStats);

    /* 
     * check this fragtracker for expiration as well as 
     * the rest of the hash table
     */
    if(Frag3Expire(p, ft, fkey, f3context) == FRAG_TRACKER_TIMEOUT)
    {
        /* Time'd out FragTrackers are just purged of their packets.
         * Reset the timestamp per this packet.
         * And reset the rest of the tracker as if this is the
         * first packet on the tracker, and continue. */

        /* This fixes an issue raised on bugtraq relating to
         * timeout frags not getting purged correctly when
         * the entire set of frags show up later.
         */
        ft->frag_time.tv_sec = p->pkth->ts.tv_sec;
        ft->frag_time.tv_usec = p->pkth->ts.tv_usec;

        ft->ttl = p->iph->ip_ttl; /* store the first ttl we got */
        ft->calculated_size = 0;
        ft->alerted = 0;
        ft->frag_flags = 0;
        ft->frag_bytes = 0;
        ft->frag_pkts = 0;
        ft->alert_count = 0;
        ft->ip_options_len = 0;
        ft->ip_option_count = 0;
        ft->ip_options_data = NULL;
        ft->copied_ip_options_len = 0;
        ft->copied_ip_option_count = 0;
        ft->context = f3context;
        ft->ordinal = 0;

        //DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
        //            "[..] Deleting fragtracker due to timeout!\n"););

        //PREPROC_PROFILE_END(frag3InsertPerfStats);
        //return FRAG_INSERT_TIMEOUT;
    }

    delta = abs(ft->ttl - p->iph->ip_ttl);
    if (delta > f3context->ttl_limit)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                    "[..] Large TTL delta!\n"););

        PREPROC_PROFILE_END(frag3InsertPerfStats);
        return FRAG_INSERT_TTL;
    }

    /*
     * Check to see if this fragment is the first or last one and
     * set the appropriate flags and values in the FragTracker
     */
    firstLastOk = Frag3CheckFirstLast(p, ft);

    fragStart = (u_int8_t *)p->iph + IP_HLEN(p->iph) * 4;
    /* Use the actual length here, because packet may have been
     * truncated.  Don't want to try to copy more than we actually
     * captured. */
    len = fragLength = p->actual_ip_len - IP_HLEN(p->iph) * 4;
#ifdef DEBUG
    if (p->actual_ip_len != ntohs(p->iph->ip_len))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
               "IP Actual Length (%d) != specified length (%d), "
               "truncated packet (%d)?\n",
                p->actual_ip_len, ntohs(p->iph->ip_len), snaplen););
    }
#endif    

    /*
     * setup local variables for tracking this frag
     */
    orig_offset = frag_offset = p->frag_offset << 3;
    /* Reset the offset to handle the weird Solaris case */
    if (firstLastOk == FRAG_LAST_OFFSET_ADJUST)
        frag_offset = (u_int16_t)ft->calculated_size;
    frag_end = frag_offset + fragLength;

    /* 
     * might have last frag...
     */
    if(!p->mf)
    {
        if ((frag_end > ft->calculated_size) &&
            (firstLastOk == FRAG_LAST_OFFSET_ADJUST))
        {
            ft->calculated_size = frag_end;
        }

        //    ft->frag_flags |= FRAG_GOT_LAST;
        //    ft->calculated_size = (p->frag_offset << 3) + fragLength;
        lastfrag = 1;
    }
    else
    {
        u_int16_t oldfrag_end;
        /* 
         * all non-last frags are supposed to end on 8-byte boundries 
         */
        if(frag_end & 7)
        {
            /* 
             * bonk/boink/jolt/etc attack... 
             */
            DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                        "[..] Short frag (Bonk, etc) attack!\n"););

            EventAnomShortFrag(f3context);

            /* don't return, might still be interesting... */
        }

        /* can't have non-full fragments... */
        oldfrag_end = frag_end;
        frag_end &= ~7;

        /* Adjust len to take into account the jolting/non-full fragment. */
        len -= (oldfrag_end - frag_end);

        /*
         * if the end of this frag is greater than the max frag size we have a
         * problem
         */
        if(frag_end > ft->calculated_size)
        {
            if(ft->frag_flags & FRAG_GOT_LAST)
            {
                /* oversize frag attack */
                DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                            "[..] Oversize frag pkt!\n"););

                EventAnomOversize(f3context);

                PREPROC_PROFILE_END(frag3InsertPerfStats);
                return FRAG_INSERT_ANOMALY;
            }
            ft->calculated_size = frag_end;
        }
    }

    if(frag_end == frag_offset)
    {
        /* 
         * zero size frag... 
         */
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                    "[..] Zero size frag!\n"););

        if(f3context->frag3_alerts & FRAG3_DETECT_ANOMALIES)
        {
            EventAnomZeroFrag(f3context);
        }

        PREPROC_PROFILE_END(frag3InsertPerfStats);
        return FRAG_INSERT_ANOMALY;
    }

    if(ft->calculated_size > IP_MAXPACKET)
    {
        /* 
         * oversize pkt... 
         */
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                    "[..] Oversize frag!\n"););

            EventAnomBadsizeLg(f3context);

        ft->frag_flags |= FRAG_BAD;

        PREPROC_PROFILE_END(frag3InsertPerfStats);
        return FRAG_INSERT_ANOMALY;
    }

    /* 
     * This may alert on bad options, but we still want to
     * insert the packet
     */
    Frag3HandleIPOptions(ft, p);

    ft->frag_pkts++;

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                "Walking frag list (%d nodes), new frag %d@%d\n",
                ft->fraglist_count, fragLength, frag_offset););

    /* 
     * Need to figure out where in the frag list this frag should go
     * and who its neighbors are
     */
    for(idx = ft->fraglist; idx; idx = idx->next)
    {
        i++;
        right = idx;

        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                    "%d right o %d s %d ptr %p prv %p nxt %p\n", 
                    i, right->offset, right->size, right,
                    right->prev, right->next););

        if(right->offset >= frag_offset)
        {
            break;
        }

        left = right;
    }

    /* 
     * null things out if we walk to the end of the list 
     */
    if(idx == NULL) right = NULL;

    /* 
     * handle forward (left-side) overlaps... 
     */
    if(left)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                    "Dealing with previous (left) frag %d@%d\n", 
                    left->size, left->offset););

        /*
         * generate the overlap of the current packet fragment 
         * over this left-side fragment
         */
        /* NOTE: If frag_offset is really large, overlap can be
         * negative because its stored as a 32bit int.
         */
        overlap = left->offset + left->size - frag_offset;

        if(overlap > 0)
        {
            if(frag_end < ft->calculated_size ||
                    ((ft->frag_flags & FRAG_GOT_LAST) && 
                     frag_end != ft->calculated_size))
            {
                if (!p->mf)
                {
                    /* 
                     * teardrop attack... 
                     */
                    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                                "[..] Teardrop attack!\n"););

                    EventAttackTeardrop(f3context);

                    ft->frag_flags |= FRAG_BAD;

                    PREPROC_PROFILE_END(frag3InsertPerfStats);
                    return FRAG_INSERT_ATTACK;
                }
            }

            f3stats.overlaps++;

            /*
             * Ok, we've got an overlap so we need to handle it.
             *
             * The target-based modes here match the data generated by 
             * Paxson's Active Mapping paper as do the policy types.
             */
            switch(ft->frag_policy)
            {
                /* 
                 * new frag gets moved around 
                 */
                case FRAG_POLICY_LINUX:
                case FRAG_POLICY_FIRST:
                case FRAG_POLICY_WINDOWS:
                case FRAG_POLICY_SOLARIS:
                case FRAG_POLICY_BSD:
                    frag_offset += (int16_t)overlap;
                    slide = (int16_t)overlap;

                    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                                "left overlap, new frag moves: %d bytes, "
                                "slide: %d\n", overlap, slide););

                    if(frag_end <= frag_offset)
                    {
                        /* 
                         * zero size frag
                         */
                        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                                    "zero size frag"););

                        EventAnomZeroFrag(f3context);

                        PREPROC_PROFILE_END(frag3InsertPerfStats);
                        return FRAG_INSERT_ANOMALY;
                    }

                    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "left overlap, "
                                "truncating new pkt (slide: %d)\n", slide););

                    break;

                    /* 
                     * new frag stays where it is, overlapee (existing frag) 
                     * gets whacked 
                     */
                case FRAG_POLICY_BSD_RIGHT:
                    if (left->offset + left->size >= frag_offset + len)
                    {
                        /* BSD-right (HP Printers) favor new fragments with lower/equal
                         * offset, EXCEPT when the existing fragment ends with at a
                         * higher/equal offset.
                         */
                        frag_offset += (int16_t)overlap;
                        slide = (int16_t)overlap;
                        goto left_overlap_last;
                    }
                    /* fall through */
                case FRAG_POLICY_LAST:
                    if ((left->offset < frag_offset) && (left->offset + left->size > frag_offset + len))
                    {
                        /* The new frag is overlapped on both sides by an existing
                         * frag -- existing frag needs to be split and the new frag
                         * inserted in the middle.
                         * 
                         * Need to duplciate left.  Adjust that guys
                         * offset by + (frag_offset + len) and
                         * size by - (frag_offset + len - left->offset).
                         */
                        ret = DupFragNode(ft, left, &right);
                        if (ret != FRAG_INSERT_OK)
                        {
                            /* Some warning here,
                             * no, its done in AddFragNode */
                            PREPROC_PROFILE_END(frag3InsertPerfStats);
                            return ret;
                        }
                        left->size -= (int16_t)overlap;
                        ft->frag_bytes -= (int16_t)overlap;

                        right->offset = frag_offset + len;
                        right->size -= (frag_offset + len - left->offset);
                        right->data += (frag_offset + len - left->offset);
                        ft->frag_bytes -= (frag_offset + len - left->offset);
                    }
                    else
                    {
                        left->size -= (int16_t)overlap;
                        ft->frag_bytes -= (int16_t)overlap;
                    }

left_overlap_last:
                    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "[!!] left overlap, "
                                "truncating old pkt (offset: %d overlap: %d)\n",
                                left->offset, overlap););

                    if (left->size <= 0)
                    {
                        dump_me = left;

                        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "retrans, "
                                "dumping old frag (offset: %d overlap: %d)\n", 
                                dump_me->offset, overlap););

                        left = left->prev;

                        Frag3FraglistDeleteNode(ft, dump_me);
                    }

                    break;
            }

            /*
             * frag can't end before it begins...
             */
            if(frag_end < frag_offset)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                            "frag_end < frag_offset!"););

                if(f3context->frag3_alerts & FRAG3_DETECT_ANOMALIES)
                {
                    EventAnomBadsizeSm(f3context);
                }

                PREPROC_PROFILE_END(frag3InsertPerfStats);
                return FRAG_INSERT_ANOMALY;
            }
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "No left overlap!\n"););
        }
    }

    if ((u_int16_t)fragLength > snaplen)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "Overly large fragment %d 0x%x 0x%x %d\n",
                    fragLength, p->iph->ip_len, p->iph->ip_off,
                    p->frag_offset << 3););
        PREPROC_PROFILE_END(frag3InsertPerfStats);
        return FRAG_INSERT_FAILED;
    }

    /* 
     * handle tail (right-side) overlaps
     *
     * We have to walk thru all the right side frags until the offset of the
     * existing frag is greater than the end of the new frag
     */
    while(right && (right->offset < frag_end) && !done)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                    "Next (right)fragment %d@%d\n", 
                    right->size, right->offset););

#ifdef DEBUG_FRAG3
        PrintFrag3Frag(right);
#endif
        trunc = 0;
        overlap = frag_end - right->offset;

        if (overlap)
        {
            if(frag_end < ft->calculated_size ||
                    ((ft->frag_flags & FRAG_GOT_LAST) && 
                     frag_end != ft->calculated_size))
            {
                if (!p->mf)
                {
                    /* 
                     * teardrop attack... 
                     */
                    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                                "[..] Teardrop attack!\n"););

                    EventAttackTeardrop(f3context);

                    ft->frag_flags |= FRAG_BAD;

                    PREPROC_PROFILE_END(frag3InsertPerfStats);
                    return FRAG_INSERT_ATTACK;
                }
            }
        }

        /* 
         * partial right-side overlap, this will be the last frag to check 
         */
        if(overlap < right->size)
        {
            f3stats.overlaps++;

            DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                        "Right-side overlap %d bytes\n", overlap););

            /* 
             * once again, target-based policy processing
             */
            switch(ft->frag_policy)
            {
                /* 
                 * existing fragment gets truncated 
                 */
                case FRAG_POLICY_LAST:
                case FRAG_POLICY_LINUX:
                case FRAG_POLICY_BSD:
                    if ((ft->frag_policy == FRAG_POLICY_BSD) &&
                        (right->offset == frag_offset))
                    {
                        slide = (int16_t)(right->offset + right->size - frag_offset);
                        frag_offset += (int16_t)slide;
                    }
                    else
                    {
                        right->offset += (int16_t)overlap;
                        right->data += (int16_t)overlap;
                        right->size -= (int16_t)overlap;
                        ft->frag_bytes -= (int16_t)overlap;
                    }
                    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "[!!] right overlap, "
                                "truncating old frag (offset: %d, "
                                "overlap: %d)\n", right->offset, overlap);
                            DebugMessage(DEBUG_FRAG, 
                                "Exiting right overlap loop...\n"););
                    if (right->size <= 0)
                    {
                        dump_me = right;

                        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "retrans, "
                                "dumping old frag (offset: %d overlap: %d)\n", 
                                dump_me->offset, overlap););

                        right = right->next;

                        Frag3FraglistDeleteNode(ft, dump_me);
                    }
                    break;

                /* 
                 * new frag gets truncated 
                 */
                case FRAG_POLICY_FIRST:
                case FRAG_POLICY_WINDOWS:
                case FRAG_POLICY_SOLARIS:
                case FRAG_POLICY_BSD_RIGHT:
                    trunc = (int16_t)overlap;
                    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "[!!] right overlap, "
                                "truncating new frag (offset: %d "
                                "overlap: %d)\n", 
                                right->offset, overlap);
                            DebugMessage(DEBUG_FRAG, 
                                "Exiting right overlap loop...\n"););
                    break;
            }

            /*
             * all done, bail
             */
            done = 1;
        }
        else
        {
            /*
             * we've got a full overlap
             */
            if(!alerted_overlap && (f3context->frag3_alerts & FRAG3_DETECT_ANOMALIES))
            {
                /* 
                 * retrans/full overlap
                 */
                EventAnomOverlap(f3context);
                alerted_overlap = 1;
                f3stats.overlaps++;
            }

            /*
             * handle the overlap in a target-based manner
             */
            switch(ft->frag_policy)
            {
                /*
                 * overlap is treated differently if there is more
                 * data beyond the overlapped packet.
                 */
                case FRAG_POLICY_WINDOWS:
                case FRAG_POLICY_SOLARIS:
                case FRAG_POLICY_BSD:
                    /*
                     * Old packet is overlapped on both sides...
                     * Drop the old packet.  This follows a
                     * POLICY_LAST model.
                     */
                    if ((frag_end > right->offset + right->size) &&
                        (frag_offset < right->offset))
                    {
                        dump_me = right;
                        ft->frag_bytes -= right->size;

                        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "retrans, "
                                "dumping old frag (offset: %d overlap: %d)\n", 
                                dump_me->offset, overlap););

                        right = right->next;

                        Frag3FraglistDeleteNode(ft, dump_me);
                        break;
                    }
                    else
                    {
                        if ((ft->frag_policy == FRAG_POLICY_SOLARIS) ||
                            (ft->frag_policy == FRAG_POLICY_BSD))
                        {
                            /* SOLARIS & BSD only */
                            if ((frag_end == right->offset + right->size) &&
                                (frag_offset < right->offset))
                            {
                                /* If the frag overlaps an entire frag to the
                                 * right side of that frag, the old frag if
                                 * dumped -- this is a "policy last".
                                 */
                                goto right_overlap_last;
                            }
                        }
                    }
                    /* Otherwise, treat it as a POLICY_FIRST,
                     * and trim accordingly. */

                    /* ie, fall through to the next case */

                /* 
                 * overlap is rejected
                 */
                case FRAG_POLICY_FIRST:
                    /* fix for bug 17823 */
                    if (right->offset == frag_offset)
                    {
                        slide = (int16_t)(right->offset + right->size - frag_offset);
                        frag_offset += (int16_t)slide;
                        left = right;
                        right = right->next;
                    }
                    else
                    {
                        trunc = (int16_t)overlap;
                    }

                    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "right overlap, "
                                "rejecting new overlap data (overlap: %d, "
                                "trunc: %d)\n", overlap, trunc););

                    if (frag_end - trunc <= frag_offset)
                    {
                        /* 
                         * zero size frag
                         */
                        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                                    "zero size frag (len: %d  overlap: %d)\n", 
                                    fragLength, overlap););

                        f3stats.discards++;

                        PREPROC_PROFILE_END(frag3InsertPerfStats);
                        return FRAG_INSERT_ANOMALY;
                    }

                    {
                        u_int16_t curr_end;
                        /* Full overlapping an already received packet
                         * and there are more packets beyond that fully
                         * overlapped one.
                         * Arrgh.  Need to insert this guy in chunks.
                         */
                        ret = AddFragNode(ft, p, f3context, fragStart, fragLength, 0, len,
                                slide, trunc, frag_offset, left, &newfrag);
                        if (ret != FRAG_INSERT_OK)
                        {
                            /* Some warning here,
                             * no, its done in AddFragNode */
                            PREPROC_PROFILE_END(frag3InsertPerfStats);
                            return ret;
                        }

                        curr_end = newfrag->offset + newfrag->size;

                        /* Find the next gap that this one might fill in */
                        while (right &&
                            (curr_end == right->offset) &&
                            (right->offset < frag_end))
                        {
                            curr_end = right->offset + right->size;
                            left = right;
                            right = right->next;                            
                        }

                        if (right && (right->offset < frag_end))
                        {
                            /* Adjust offset to end of 'left' */
                            if (left)
                                frag_offset = left->offset + left->size;
                            else
                                frag_offset = orig_offset;

                            /* Overlapping to the left by a good deal now */
                            slide = frag_offset - orig_offset;
                            /*
                             * Reset trunc, in case the next one kicks us
                             * out of the loop.  This packet will become the
                             * right-most entry so far.  Don't truncate any
                             * further.
                             */
                            trunc = 0;
                            if (right)
                                continue;
                        }

                        if (curr_end < frag_end)
                        {
                            /* Insert this guy in his proper spot,
                             * adjust offset to the right-most endpoint
                             * we saw.
                             */
                            slide = left->offset + left->size - frag_offset;
                            frag_offset = curr_end;
                            trunc = 0;
                        }
                        else
                        {
                            addthis = 0;
                        }
                    }
                    break;

                    /* 
                     * retrans accepted, dump old frag 
                     */
right_overlap_last:
                case FRAG_POLICY_BSD_RIGHT:
                case FRAG_POLICY_LAST:
                case FRAG_POLICY_LINUX:
                    dump_me = right;
                    ft->frag_bytes -= right->size;

                    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "retrans, "
                                "dumping old frag (offset: %d overlap: %d)\n", 
                                dump_me->offset, overlap););

                    right = right->next;

                    Frag3FraglistDeleteNode(ft, dump_me);

                    break;
            }
        }
    }

    if (addthis)
    {
        ret = AddFragNode(ft, p, f3context, fragStart, fragLength, lastfrag, len,
                      slide, trunc, frag_offset, left, &newfrag);
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "Fully truncated right overlap\n"););
    }

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                "Frag3Insert(): returning normally\n"););

    PREPROC_PROFILE_END(frag3InsertPerfStats);
    return ret;
}

/**
 * Check to see if a FragTracker has met all of its completion criteria
 *
 * @param ft FragTracker to check
 *
 * @return status
 * @retval 1 If the FragTracker is ready to be rebuilt
 * @retval 0 If the FragTracker hasn't fulfilled its completion criteria
 */
static int INLINE Frag3IsComplete(FragTracker *ft)
{
    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                "[$] Checking completion criteria\n"););

    /*
     * check to see if the first and last frags have arrived
     */
    if((ft->frag_flags & FRAG_GOT_FIRST) &&
            (ft->frag_flags & FRAG_GOT_LAST))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                    "   Got First and Last frags\n"););

        /*
         * if we've accumulated enough data to match the calculated size
         * of the defragg'd packet, return 1
         */
        if(ft->frag_bytes == ft->calculated_size)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                        "   [!] frag_bytes = calculated_size!\n"););

            sfPerf.sfBase.iFragCompletes++;

            return 1;
        }

        if (ft->frag_bytes > ft->calculated_size)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                        "   [!] frag_bytes > calculated_size!\n"););

            sfPerf.sfBase.iFragCompletes++;

            return 1;
        }

        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                    "   Calc size (%d) != frag bytes (%d)\n",
                    ft->calculated_size, ft->frag_bytes););

        /*
         * no dice
         */
        return 0;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                "   Missing First or Last frags (frag_flags: 0x%X)\n", 
                ft->frag_flags););

    return 0;
}

/**
 * Reassemble the packet from the data in the FragTracker and reinject into
 * Snort's packet analysis system
 *
 * @param ft FragTracker to rebuild
 * @param p Packet to fill in pseudopacket IP structs
 *
 * @return none
 */
static void Frag3Rebuild(FragTracker *ft, Packet *p)
{
    u_int8_t *rebuild_ptr;  /* ptr to the start of the reassembly buffer */
    u_int8_t *rebuild_end;  /* ptr to the end of the reassembly buffer */
    Frag3Frag *frag;    /* frag pointer for managing fragments */
    u_int8_t new_ip_hlen = 0;
    u_int8_t save_ip_hlen = 0;
    Packet defrag_pkt;
    struct pcap_pkthdr dpkth;   /* BPF data */
    u_int8_t *dpkt = NULL;
    int datalink_header_len = 0;
    int ret = 0;
    PROFILE_VARS;

#ifdef GRE
    if (p->greh == NULL)
        dpkt = frag_rebuild_buf;
    else
        dpkt = gre_frag_rebuild_buf;
#else
    dpkt = frag_rebuild_buf;
#endif

    memset(&defrag_pkt, 0, sizeof(Packet));
    memset(&dpkth, 0, sizeof(struct pcap_pkthdr));
    memset(dpkt, 0, DATASIZE + SPARC_TWIDDLE);
    defrag_pkt.pkth = &dpkth;
    defrag_pkt.pkt = dpkt;
    defrag_pkt.pkt += SPARC_TWIDDLE;

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "Rebuilding pkt [0x%X:%d  0x%X:%d]\n", 
                p->iph->ip_src.s_addr, p->sp, 
                p->iph->ip_dst.s_addr, p->dp);
            DebugMessage(DEBUG_FRAG, "Calculated size: %d\n", 
                ft->calculated_size);
            DebugMessage(DEBUG_FRAG, "Frag Bytes: %d\n", ft->frag_bytes);
            );

    PREPROC_PROFILE_START(frag3RebuildPerfStats);
    /* 
     * set the timestamps on the rebuild packet 
     * from the last packet of the frag 
     */
    defrag_pkt.pkth->ts.tv_sec = p->pkth->ts.tv_sec;
    defrag_pkt.pkth->ts.tv_usec = p->pkth->ts.tv_usec;

    /* 
     * set the pointer to the end of the rebuild packet
     */
    rebuild_ptr = defrag_pkt.pkt;
    rebuild_end = defrag_pkt.pkt + DATASIZE;

    /*
     * If there are IP options for this reassembled frag, adjust
     * the IP Header length in the current packet here before
     * copying that into the rebuilt packet.
     */
    if (ft->ip_options_data && ft->ip_options_len)
    {
        save_ip_hlen = new_ip_hlen = IP_HLEN(p->iph);
        /*
         * New length is old length, less the options in this packet,
         * plus the options for the rebuilt fragment.  Option len
         * from packet & frag tracker are in bytes, header length
         * is in words, so shift it.
         */
        new_ip_hlen += (u_int8_t)((ft->ip_options_len - p->ip_options_len) >> 2);
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "Adjusting IP Header from %d to %d bytes\n",
                save_ip_hlen, new_ip_hlen););
        SET_IP_HLEN(p->iph, new_ip_hlen);
    }

    /* copy the packet data from the last packet of the frag */
#ifdef GIDS
    /* IPTABLES and IPFW don't have an ethernet header within their payloads */
    if (!InlineMode())
    {
#endif
        switch (datalink)
        {
        case DLT_EN10MB:
#ifdef DLT_I4L_IP
        case DLT_I4L_IP:
#endif
            datalink_header_len = ETHERNET_HEADER_LEN;
            if (p->eh)
            {
                ret = SafeMemcpy(rebuild_ptr, p->eh, datalink_header_len,
                                rebuild_ptr, rebuild_end);

                if (ret == SAFEMEM_ERROR)
                {
                    /*XXX: Log message, failed to copy */
                    ft->frag_flags = ft->frag_flags | FRAG_REBUILT;
                    return;
                }
            }
            else
            {
                EtherHdr *eh = (EtherHdr *)rebuild_ptr;
                eh->ether_type = htons(ETHERNET_TYPE_IP);
            }
            rebuild_ptr += datalink_header_len;
            break;

/* XXX: This a list of supported decoders (from snort.c).  However IP
 *      Fragmentation may not be supported for all of them.  Do as we
 *      used to do for now and put the IP Frame as the first byte.
 */
#if 0
        case DLT_IEEE802_11:
        case DLT_ENC: /* Encapsulated data */
        case DLT_IEEE802: /* Token Ring */
        case DLT_FDDI: /* FDDI */
        case DLT_CHDLC: /* Cisco HDLC */
        case DLT_SLIP: /* Serial Line Internet Protocol */
        case DLT_PPP: /* Point To Point Protocol */
        case DLT_PPP_SERIAL: /* PPP with full HDLC header */
        case DLT_LINUX_SLL:
        case DLT_PFLOG:
        case DLT_OLDPFLOG:
        case DLT_LOOP:
        case DLT_NULL:
        case DLT_RAW:
        case DLT_I4L_RAWIP:
        case DLT_I4L_CISCOHDLC:
            /* Need to add something to skip the correct number of bytes so
             * the IP frame is in the correct location for each of these
             * decoders. */
#endif
        default:
            /* This is incomplete and doesn't skip any bytes for the IP Frame */

            break;
        }
#ifdef GIDS
    }
#endif 

    /*
     * copy the ip header
     */
    ret = SafeMemcpy(rebuild_ptr, p->iph, sizeof(IPHdr),
                     rebuild_ptr, rebuild_end);

    if (ret == SAFEMEM_ERROR)
    {
        /*XXX: Log message, failed to copy */
        ft->frag_flags = ft->frag_flags | FRAG_REBUILT;
        return;
    }

    /* 
     * reset the ip header pointer in the rebuilt packet
     */
    defrag_pkt.iph = (IPHdr *)rebuild_ptr;

    /* and move the pointer to the beginning of the transport layer
     * of the rebuilt packet. */
    rebuild_ptr += sizeof(IPHdr);

    /*
     * if there are IP options, copy those in as well
     */
    if (ft->ip_options_data && ft->ip_options_len)
    {
        ret = SafeMemcpy(rebuild_ptr, ft->ip_options_data, ft->ip_options_len,
                         rebuild_ptr, rebuild_end);

        if (ret == SAFEMEM_ERROR)
        {
            /*XXX: Log message, failed to copy */
            ft->frag_flags = ft->frag_flags | FRAG_REBUILT;
            return;
        }

        /*
         * adjust the pointer to the beginning of the transport layer of the
         * rebuilt packet
         */
        rebuild_ptr += ft->ip_options_len;

        /*
         * Reset the current packet with its original IP Header length
         */
        SET_IP_HLEN(p->iph, save_ip_hlen);
    }
    else if (ft->copied_ip_options_len)
    {
        /* XXX: should we log a warning here?  there were IP options
         * copied across all fragments, EXCEPT the offset 0 fragment.
         */
    }

    /* 
     * clear the packet fragment fields 
     */ 
    defrag_pkt.iph->ip_off = 0x0000;
    defrag_pkt.frag_flag = 0;

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                "[^^] Walking fraglist:\n"););

    /* 
     * walk the fragment list and rebuild the packet 
     */
    for(frag = ft->fraglist; frag; frag = frag->next)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                    "   frag: %p\n"
                    "   frag->data: %p\n"
                    "   frag->offset: %d\n"
                    "   frag->size: %d\n"
                    "   frag->prev: %p\n"
                    "   frag->next: %p\n",
                    frag, frag->data, frag->offset, 
                    frag->size, frag->prev, frag->next););

        /*
         * We somehow got a frag that had data beyond the calculated
         * end. Don't want to include it.
         */
        if ((frag->offset + frag->size) > (u_int16_t)ft->calculated_size)
            continue;

        /* 
         * try to avoid buffer overflows...
         */
        if (frag->size)
        {
            ret = SafeMemcpy(rebuild_ptr+frag->offset, frag->data, frag->size, 
                             rebuild_ptr, rebuild_end);

            if (ret == SAFEMEM_ERROR)
            {
                /*XXX: Log message, failed to copy */
                ft->frag_flags = ft->frag_flags | FRAG_REBUILT;
                return;
            }
        }
    }

    /* 
     * set the new packet's capture length 
     */
    if((datalink_header_len + ft->calculated_size + sizeof(IPHdr)
                            + ft->ip_options_len) > 
            (IP_MAXPACKET-1))
    {
        /* don't let other pcap apps die when they process this file
         * -- yes this opens us up for 14 bytes at the end of the
         * giant packet.
         */
#ifdef DONT_TRUNCATE
        defrag_pkt.pkth->caplen = IP_MAXPACKET - 1;
#else /* DONT_TRUNCATE */
        defrag_pkt.pkth->caplen = datalink_header_len +
            ft->calculated_size + sizeof(IPHdr) + ft->ip_options_len ;
#endif /* DONT_TRUNCATE */
    }
    else
    {
        defrag_pkt.pkth->caplen = datalink_header_len +
            ft->calculated_size + sizeof(IPHdr) + ft->ip_options_len;
    }

    defrag_pkt.pkth->len = defrag_pkt.pkth->caplen;

    /* 
     * set the ip dgm length 
     */
    defrag_pkt.iph->ip_len = htons((short)(defrag_pkt.pkth->len-datalink_header_len));
    defrag_pkt.actual_ip_len = ntohs(defrag_pkt.iph->ip_len);

    /* 
     * tell the rest of the system that this is a rebuilt fragment 
     */
    defrag_pkt.packet_flags = PKT_REBUILT_FRAG;
    defrag_pkt.frag_flag = 0;
    defrag_pkt.iph->ip_csum = 0;

    /* 
     * calculate the ip checksum for the packet 
     */
    defrag_pkt.iph->ip_csum  = 
        in_chksum_ip((u_int16_t *)defrag_pkt.iph, sizeof(IPHdr) + ft->ip_options_len);

    pc.rebuilt_frags++;
    sfPerf.sfBase.iFragFlushes++;

    /* Rebuild is complete */
    PREPROC_PROFILE_END(frag3RebuildPerfStats);

    /* 
     * process the packet through the detection engine 
     */
    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                "Processing rebuilt packet:\n"););

    f3stats.reassembles++;

    UpdateIPReassStats(&(sfPerf.sfBase), defrag_pkt.pkth->caplen);

#ifdef DEBUG_FRAG3
    /*
     * Note, that this won't print out the IP Options or any other
     * data that is established when the packet is decoded.
     */
    if (DEBUG_FRAG & GetDebugLevel())
    {
        //ClearDumpBuf();
        printf("++++++++++++++++++Frag3 DEFRAG'd PACKET++++++++++++++\n");
        PrintIPPkt(stdout, defrag_pkt.iph->ip_proto, &defrag_pkt);
        printf("++++++++++++++++++Frag3 DEFRAG'd PACKET++++++++++++++\n");
        //ClearDumpBuf();
    }
#endif
    ProcessPacket(NULL, defrag_pkt.pkth, defrag_pkt.pkt, ft);

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                "Done with rebuilt packet, marking rebuilt...\n"););

    ft->frag_flags = ft->frag_flags | FRAG_REBUILT;
}

/**
 * Delete a Frag3Frag struct
 *
 * @param frag Fragment to delete
 *
 * @return none
 */
static void Frag3DeleteFrag(Frag3Frag *frag)
{
    /* 
     * delete the fragment either in prealloc or dynamic mode
     */
    if(!global_config.use_prealloc)
    {
        free(frag->fptr);
        mem_in_use -= frag->flen;

        free(frag);
        mem_in_use -= sizeof(Frag3Frag);
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "o %d s %d ptr %p prv %p nxt %p\n", 
                    frag->offset, frag->size, frag, frag->prev, frag->next););
        Frag3PreallocPush(frag);
    }

    f3stats.fragnodes_released++;
}

/**
 * Delete the contents of a FragTracker, in this instance that just means to 
 * dump the fraglist.  The sfxhash system deletes the actual FragTracker mem.
 *
 * @param ft FragTracker to delete
 *
 * @return none
 */
static void Frag3DeleteTracker(FragTracker *ft)
{
    Frag3Frag *idx = ft->fraglist;  /* pointer to the fraglist to delete */
    Frag3Frag *dump_me = NULL;      /* ptr to the Frag3Frag element to drop */

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                "Frag3DeleteTracker %d nodes to dump\n", ft->fraglist_count);); 

    /*
     * delete all the nodes in a fraglist
     */
    while(idx)
    {
        dump_me = idx;
        idx = idx->next;
        Frag3DeleteFrag(dump_me);
    }
    ft->fraglist = NULL;
    if (ft->ip_options_data)
    {
        free(ft->ip_options_data);
        ft->ip_options_data = NULL;
    }

    return;
}

/**
 * Remove a FragTracker from the f_cache hash table
 *
 * @param key FragKey of the FragTracker to be removed
 * @param data unused in this function
 *
 * @return none
 */
static void Frag3RemoveTracker(void *key, void *data)
{
    /* 
     * sfxhash maintains its own self preservation stuff/node freeing stuff
     */
    if(sfxhash_remove(f_cache, key) != SFXHASH_OK)
    {
        ErrorMessage("sfxhash_remove() failed in frag3!\n");
    }

    return;
}

/**
 * This is the auto-node-release function that gets handed to the sfxhash table
 * at initialization.  Handles deletion of sfxhash table data members.
 *
 * @param key FragKey of the element to be freed
 * @param data unused in this implementation
 *
 * Now Returns 0 because we want to say, yes, delete that hash entry!!!
 */
static int Frag3AutoFree(void *key, void *data)
{
    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                "Calling Frag3DeleteTracker()\n"););

    Frag3DeleteTracker((FragTracker *) data);

    sfPerf.sfBase.iFragDeletes++;
    sfPerf.sfBase.iFragAutoFrees++;
    sfPerf.sfBase.iCurrentFrags--;
    f3stats.fragtrackers_autoreleased++;

    return 0;
}

/**
 * This is the user free function that gets handed to the sfxhash table
 * at initialization.  Handles deletion of sfxhash table data members.
 *
 * @param key FragKey of the element to be freed
 * @param data unused in this implementation
 *
 * Now Returns 0 because we want to say, yes, delete that hash entry!!!
 */
static int Frag3UserFree(void *key, void *data)
{
    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, 
                "Calling Frag3DeleteTracker()\n"););

    Frag3DeleteTracker((FragTracker *) data);

    sfPerf.sfBase.iFragDeletes++;
    sfPerf.sfBase.iCurrentFrags--;
    f3stats.fragtrackers_released++;

    return 0;
}

/**
 * This function gets called either when we run out of prealloc nodes or when
 * the memcap is exceeded.  Its job is to free memory up in frag3 by deleting
 * old/stale data.  Currently implemented using a simple LRU pruning
 * technique, could probably benefit from having some sort of tail selection
 * randomization added to it.  Additonally, right now when we hit the wall we
 * try to drop at least enough memory to satisfy the "ten_percent" value.
 * Hopefully that's not too aggressive, salt to taste!
 *
 * @param none
 *
 * @return none
 */
static int Frag3Prune(FragTracker *not_me)
{
    SFXHASH_NODE *hnode;
    int found_this = 0;
    int pruned = 0;
#ifdef DEBUG
    /* Use these to print out whether the frag tracker has
     * expired or not.
     */
    FragTracker *ft;
    struct timeval *fttime;     /* FragTracker timestamp */
#endif

    sfPerf.sfBase.iFragFaults++;
    f3stats.prunes++;

    if(!global_config.use_prealloc)
    {
        //while(mem_in_use > (global_config.memcap-ten_percent))
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "(spp_frag3) Frag3Prune: Pruning by memcap! "););
        while((mem_in_use > global_config.memcap) ||
              (f_cache->count > (global_config.max_frags - 5)))
        {
            hnode = sfxhash_lru_node(f_cache);
            if(!hnode) 
            {
                break;
            }
                    
            if (hnode && hnode->data == not_me)
            {
                if (found_this)
                {
                    /* Uh, problem... we've gone through the entire list */
                    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                        "(spp_frag3) Frag3Prune: Pruning by memcap - empty list! "););
                    return pruned;
                }
                sfxhash_gmovetofront(f_cache, hnode);
                found_this = 1;
                continue;
            }
#ifdef DEBUG
            ft = hnode->data;
            fttime = &(ft->frag_time);

            if (CheckTimeout(pkttime,fttime,ft->context)==FRAG_TIMEOUT)
            {
                LogMessage("(spp_frag3) Frag3Prune: Fragment dropped (timeout)! "
                    "[0x%08X->0x%08X ID: %d Count: %d]\n", ft->sip, ft->dip, 
                    ft->id, ft->fraglist_count);
                f3stats.timeouts++;
                sfPerf.sfBase.iFragTimeouts++;
            }
            else
            {
                LogMessage("(spp_frag3) Frag3Prune: Fragment dropped (memory)! "
                    "[0x%08X->0x%08X ID: %d Count: %d]\n", ft->sip, ft->dip, 
                    ft->id, ft->fraglist_count);
            }
#endif
            Frag3RemoveTracker(hnode->key, hnode->data);
            //sfPerf.sfBase.iFragDeletes++;
            //f3stats.fragtrackers_released++;
            pruned++;
        }
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "(spp_frag3) Frag3Prune: Pruning by prealloc! "););
        while(prealloc_nodes_in_use>(global_config.static_frags-ten_percent))
        {
            hnode = sfxhash_lru_node(f_cache);
            if(!hnode) 
            {
                break;
            }

            if (hnode && hnode->data == not_me)
            {
                if (found_this)
                {
                    /* Uh, problem... we've gone through the entire list */
                    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                              "(spp_frag3) Frag3Prune: Pruning by prealloc - empty list! "););
                    return pruned;
                }
                sfxhash_gmovetofront(f_cache, hnode);
                found_this = 1;
                continue;
            }

#ifdef DEBUG
            ft = hnode->data;
            fttime = &(ft->frag_time);

            if (CheckTimeout(pkttime,fttime,ft->context)==FRAG_TIMEOUT)
            {
                LogMessage("(spp_frag3) Frag3Prune: Fragment dropped (timeout)! "
                    "[0x%08X->0x%08X ID: %d Count: %d]\n", ft->sip, ft->dip, 
                    ft->id, ft->fraglist_count);
                f3stats.timeouts++;
                sfPerf.sfBase.iFragTimeouts++;
            }
            else
            {
                LogMessage("(spp_frag3) Frag3Prune: Fragment dropped (memory)! "
                    "[0x%08X->0x%08X ID: %d Count: %d]\n", ft->sip, ft->dip, 
                    ft->id, ft->fraglist_count);
            }
#endif

            Frag3RemoveTracker(hnode->key, hnode->data);
            //sfPerf.sfBase.iFragDeletes++;
            //f3stats.fragtrackers_released++;
            pruned++;
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "(spp_frag3) Frag3Prune: Pruned %d nodes\n", pruned););
    return pruned;
}

/**
 * Print out the frag stats from this run
 *
 * @param none
 *
 * @return none
 */
void Frag3PrintStats()
{
    LogMessage("Frag3 statistics:\n");
    LogMessage("        Total Fragments: %lu\n", f3stats.total);
    LogMessage("      Frags Reassembled: %lu\n", f3stats.reassembles);
    LogMessage("               Discards: %lu\n", f3stats.discards);
    LogMessage("          Memory Faults: %lu\n", f3stats.prunes);
    LogMessage("               Timeouts: %lu\n", f3stats.timeouts);
    LogMessage("               Overlaps: %lu\n", f3stats.overlaps);
    LogMessage("              Anomalies: %lu\n", f3stats.anomalies);
    LogMessage("                 Alerts: %lu\n", f3stats.alerts);
    LogMessage("     FragTrackers Added: %lu\n", f3stats.fragtrackers_created);
    LogMessage("    FragTrackers Dumped: %lu\n", f3stats.fragtrackers_released);
    LogMessage("FragTrackers Auto Freed: %lu\n", f3stats.fragtrackers_autoreleased);
    LogMessage("    Frag Nodes Inserted: %lu\n", f3stats.fragnodes_created);
    LogMessage("     Frag Nodes Deleted: %lu\n", f3stats.fragnodes_released);

    LogMessage("===================================================="
            "===========================\n");
}

/**
 * Basic restart function required by preprocessors
 */
void Frag3Restart(int signal, void *foo)
{
    Frag3PrintStats();
    return;
}

/**
 * CleanExit func required by preprocessors
 */
void Frag3CleanExit(int signal, void *foo)
{
    int engineIndex;
    Frag3Context *f3context;

    Frag3PrintStats();

    for (engineIndex = 0; engineIndex < numFrag3Contexts; engineIndex++)
    {
        f3context = frag3ContextList[engineIndex];
        free(f3context);
    }

    /* Cleanup the list of Frag3 engine contexts */
    free(frag3ContextList);

    /* Free the rebuild buffer memory */
    if (frag_rebuild_buf != NULL)
        free(frag_rebuild_buf);

#ifdef GRE
    if (gre_frag_rebuild_buf != NULL)
        free(gre_frag_rebuild_buf);
#endif

    //sfxhash_delete(f_cache);
    //f_cache = NULL;

    return;
}

/**
 * Get a node from the prealloc_list
 *
 * @return pointer to a Frag3Frag preallocated structure or NULL if the list
 * is empty
 */
static INLINE Frag3Frag *Frag3PreallocPop()
{
    Frag3Frag *node;

    if(prealloc_frag_list)
    {
        node = prealloc_frag_list;
        prealloc_frag_list = prealloc_frag_list->next; 
        if (prealloc_frag_list)
        {
            prealloc_frag_list->prev = NULL;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                        "Using last prealloc frag node\n"););
        }
        node->next = NULL;
        node->prev = NULL;
        node->offset = 0;
        node->size = 0;
        node->flen = 0;
        node->last = 0;
    }
    else
    {
        return NULL;
    }

    if (!node->fptr)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                        "Frag3Frag fptr is NULL!\n"););
    }

    prealloc_nodes_in_use++;
    return node;
}

/** 
 * Put a prealloc node back into the prealloc_cache pool
 *
 * @param node Prealloc node to place back in the pool
 *
 * @return none
 */
static INLINE void Frag3PreallocPush(Frag3Frag *node)
{
    if (!prealloc_frag_list)
    {
        node->next = NULL;
        node->prev = NULL;
    }
    else
    {
        node->next = prealloc_frag_list;
        node->prev = NULL;
        prealloc_frag_list->prev = node;
    }

    prealloc_frag_list = node;
    node->data = NULL;
    if (!node->fptr)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                        "Frag3Frag fptr is NULL!\n"););
    }

    prealloc_nodes_in_use--;
    return;
}

/**
 * Plug a Frag3Frag into the fraglist of a FragTracker
 *
 * @param ft FragTracker to put the new node into
 * @param prev ptr to preceeding Frag3Frag in fraglist
 * @param next ptr to following Frag3Frag in fraglist
 * @param node ptr to node to put in list
 *
 * @return none
 */
static INLINE void Frag3FraglistAddNode(FragTracker *ft, Frag3Frag *prev, 
        Frag3Frag *node) 
{
    if(prev)
    {
        node->next = prev->next;
        node->prev = prev;
        prev->next = node;
        if (node->next)
            node->next->prev = node;
        else
            ft->fraglist_tail = node;
    }
    else
    {
        node->next = ft->fraglist;
        if (node->next)
            node->next->prev = node;
        else
            ft->fraglist_tail = node;
        ft->fraglist = node;
    }

    ft->fraglist_count++;
    return;
}

/**
 * Delete a Frag3Frag from a fraglist
 *
 * @param ft FragTracker to delete the frag from
 * @param node node to be deleted
 *
 * @return none
 */
static INLINE void Frag3FraglistDeleteNode(FragTracker *ft, Frag3Frag *node)
{
    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "Deleting list node %p (p %p n %p)\n",
                node, node->prev, node->next););

    if(node->prev)
        node->prev->next = node->next;
    else
        ft->fraglist = node->next;

    if(node->next)
        node->next->prev = node->prev;
    else
        ft->fraglist_tail = node->prev;

    Frag3DeleteFrag(node);
    ft->fraglist_count--;
}

/*
**  
**  NAME
**    fpAddFragAlert::
**
**  DESCRIPTION
**    This function flags an alert per frag tracker.
**
**  FORMAL INPUTS
**    Packet *     - the packet to inspect
**    OTNX *       - the rule that generated the alert
**
**  FORMAL OUTPUTS
**    int - 0 if not flagged
**          1 if flagged
**
*/
int fpAddFragAlert(Packet *p, OTNX *otnx)
{
    FragTracker *ft = p->fragtracker;

    if ( !ft )
        return 0;

    if ( !otnx )
        return 0;

    if ( !otnx->otn )
        return 0;

    /* Only track a certain number of alerts per session */
    if ( ft->alert_count >= MAX_FRAG_ALERTS )
        return 0;

    ft->alert_gid[ft->alert_count] = otnx->otn->sigInfo.generator;
    ft->alert_sid[ft->alert_count] = otnx->otn->sigInfo.id;
    ft->alert_count++;

    return 1;
}

/*
**  
**  NAME
**    fpFragAlerted::
**
**  DESCRIPTION
**    This function indicates whether or not an alert has been generated previously
**    in this session, but only if this is a rebuilt packet.
**
**  FORMAL INPUTS
**    Packet *     - the packet to inspect
**    OTNX *       - the rule that generated the alert
**
**  FORMAL OUTPUTS
**    int - 0 if alert NOT previously generated
**          1 if alert previously generated
**
*/
int fpFragAlerted(Packet *p, OTNX *otnx)
{
    FragTracker *ft = p->fragtracker;
    SigInfo *si = &otnx->otn->sigInfo;
    int      i;

    if ( !ft )
        return 0;

    for ( i = 0; i < ft->alert_count; i++ )
    {
        /*  If this is a rebuilt packet and we've seen this alert before, return
         *  that we have previously alerted on a non-rebuilt packet.
         */
        if ( (p->packet_flags & PKT_REBUILT_FRAG)
                && ft->alert_gid[i] == si->generator && ft->alert_sid[i] == si->id )
        {
            return 1;
        }
    }

    return 0;
}

