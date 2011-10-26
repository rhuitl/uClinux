/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 2003 Sourcefire, Inc.
**               Chris Green <cmg@sourcefire.com>
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

/* $Id$ */

/*  I N C L U D E S  ************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <rpc/types.h>
#include <string.h>
#include <ctype.h>

#include "decode.h"
#include "rules.h"
#include "debug.h"
#include "util.h"
#include "generators.h"
#include "log.h"
#include "snort.h"

#include "ubi_SplayTree.h"

/* @todo Move all inlines to one central place */
#ifndef DEBUG
    #ifndef INLINE
        #define INLINE inline
    #endif
#else
    #ifdef INLINE
        #undef INLINE
    #endif
    #define INLINE   
#endif /* DEBUG */

/*  D E F I N E S  **************************************************/
#define TAG_SESSION   1
#define TAG_HOST      2
#define TAG_HOST_SRC  3
#define TAG_HOST_DST  4

#define TAG_METRIC_SECONDS    0x1
#define TAG_METRIC_PACKETS    0x2
#define TAG_METRIC_BYTES      0x4
#define TAG_METRIC_UNLIMITED  0x8

#define MAX_TAG_NODES   256

/* by default we'll set a 5 minute timeout if we see no activity 
 * on a tag with a 'count' metric so that we prune dead sessions 
 * periodically since we're not doing TCP state tracking
 */
#define TAG_PRUNE_QUANTUM   300
#define TAG_MEMCAP          4194304  /* 4MB */


/*  D A T A   S T R U C T U R E S  **********************************/
typedef struct _PruneData
{
    u_int32_t pruned;
    u_int32_t time;
    ubi_trRootPtr tree;
} PruneData;

typedef struct _TagNode
{
    ubi_trNode Node;
    
    /* ip addrs */
    u_int32_t sip;
    u_int32_t dip;

    /* ports */
    u_int16_t sp;
    u_int16_t dp;

    /* transport proto */
    u_int8_t proto;

    /* number of packets/seconds/bytes to tag for */
    int seconds;
    int packets;
    int bytes;

    /* counters of number of packets tagged and max to
     * prevent Eventing DOS */
    int pkt_count;

    /* packets/seconds selector */
    int metric;

    /* session or host mode */
    int mode;

    /* last UNIX second that this node had a successful match */
    u_int32_t last_access;

    /* event id number for correlation with trigger events */
    u_int16_t event_id;
    struct timeval event_time;

    /* for later expansion... */
    OptTreeNode *otn;

} TagNode;

/*  G L O B A L S  **************************************************/
static ubi_trRoot host_tag_cache;
static ubi_trRootPtr host_tag_cache_ptr = &host_tag_cache;

static ubi_trRoot ssn_tag_cache;
static ubi_trRootPtr ssn_tag_cache_ptr = &ssn_tag_cache;

static u_int32_t last_prune_time;
static u_int32_t tag_alloc_faults;
static u_int32_t tag_memory_usage;

extern char check_tags_flag;
extern char *file_name;
extern int file_line;

/*  P R O T O T Y P E S  ********************************************/
static void *TagAlloc(unsigned long);
static int PruneTagCache(u_int32_t, int);
static int PruneTime(ubi_trRootPtr, u_int32_t);
static void TagSession(Packet *, TagData *, u_int32_t, u_int16_t);
static void TagHost(Packet *, TagData *, u_int32_t, u_int16_t);
static void AddTagNode(Packet *, TagData *, int, u_int32_t, u_int16_t);
static INLINE void SwapTag(TagNode *);


/* I should really make a generic function to do this... */
static void *TagAlloc(unsigned long size)
{
    void *tmp;

    tag_memory_usage += size;

    if(tag_memory_usage > TAG_MEMCAP)
    {
        /* aggressively prune */
        struct timeval tv;
        struct timezone tz;

        tag_alloc_faults++;

        gettimeofday(&tv, &tz);

        if(!PruneTagCache((u_int32_t)tv.tv_sec, 0))
        {
            /* if we can't prune due to time, just nuke 5 random sessions */
            PruneTagCache(0, 5);
        }
    }

    tmp = (void *) calloc(size, sizeof(char));

    if(tmp == NULL)
    {
        FatalError("TagAlloc(): Unable to allocate memory! (%d bytes in use)\n",
                    tag_memory_usage);
    }

    return tmp;
}

#ifdef DEBUG

/** 
 * Print out a tag node IFF we are current in debug_flow
 * 
 * @param np tagnode pointer to print
 */
static void PrintTagNode(TagNode *np)
{
    if(!DebugThis(DEBUG_FLOW))
    {
        return;
    }
    
    printf("+--------------------------------------------------------------\n");
    printf("| Ssn Counts: %u, Host Counts: %u\n",
           ssn_tag_cache.count,
           host_tag_cache.count);
    
    printf("| (%u) %x:%d -> %x:%d Metric: %u "
           "LastAccess: %u, event_id: %u mode: %u event_time.tv_sec: %u\n"
           "| Packets: %d, Bytes: %d, Seconds: %d\n",
           np->proto,
           np->sip, np->sp,
           np->dip, np->dp,
           np->metric,
           np->last_access,
           np->event_id,
           np->mode,
           np->event_time.tv_sec,
           np->packets,
           np->bytes,
           np->seconds);
    printf("+--------------------------------------------------------------\n");
}

#endif /* DEBUG */

/** 
 * swap the sips and dips, dp's and sp's
 * 
 * @param np TagNode ptr
 */
static INLINE void SwapTag(TagNode *np)
{
    u_int32_t tip;
    u_int16_t tport;

    tip = np->sip;
    np->sip = np->dip;
    np->dip = tip;

    tport = np->sp;
    np->sp = np->dp;
    np->dp = tport;
}


static int TagCompareSession(ubi_trItemPtr ItemPtr, ubi_trNodePtr NodePtr)
{
    TagNode *nTag;
    TagNode *iTag; 

    nTag = ((TagNode *)NodePtr);
    iTag = ((TagNode *)ItemPtr);

    if(nTag->sip < iTag->sip)
    {
        return 1;
    }
    else if(nTag->sip > iTag->sip)
    {
        return -1;
    }
        
    if(nTag->dip < iTag->dip)
    {
        return 1;
    }
    else if(nTag->dip > iTag->dip)
    {
        return -1;
    }

    if(nTag->sp < iTag->sp)
    {
        return 1;
    }
    else if(nTag->sp > iTag->sp)
    {
        return -1;
    }

    if(nTag->dp < iTag->dp)
    {
        return 1;
    }
    else if(nTag->dp > iTag->dp)
    {
        return -1;
    }

    return 0;
}


static int TagCompareHost(ubi_trItemPtr ItemPtr, ubi_trNodePtr NodePtr)
{
    TagNode *nTag;
    TagNode *iTag; 

    nTag = ((TagNode *)NodePtr);
    iTag = ((TagNode *)ItemPtr);

    if(nTag->sip < iTag->sip)
    {
        return 1;
    }
    else if(nTag->sip > iTag->sip)
    {
        return -1;
    }

    return 0;
}

void InitTag()
{
    (void)ubi_trInitTree(ssn_tag_cache_ptr,  /* ptr to the tree head */
                         TagCompareSession,  /* comparison function */
                         0);            /* don't allow overwrites/duplicates */

    (void)ubi_trInitTree(host_tag_cache_ptr, /* ptr to the tree head */
                         TagCompareHost,     /* comparison function */
                         0);            /* don't allow overwrites/duplicates */

}


static void TagSession(Packet *p, TagData *tag, u_int32_t time, u_int16_t event_id)
{
    DEBUG_WRAP(DebugMessage(DEBUG_FLOW, "TAGGING SESSION\n"););

    AddTagNode(p, tag, TAG_SESSION, time, event_id);
}


static void TagHost(Packet *p, TagData *tag, u_int32_t time, u_int16_t event_id)
{
    int mode; 

    DEBUG_WRAP(DebugMessage(DEBUG_FLOW, "TAGGING HOST\n"););

    switch(tag->tag_direction)
    {
        case TAG_HOST_DST:
            mode = TAG_HOST_DST;
            break;
        case TAG_HOST_SRC:
            mode = TAG_HOST_SRC;
            break;
        default:
            mode = TAG_HOST_SRC;
            break;
    }

    AddTagNode(p, tag, mode, time, event_id);
}

static void AddTagNode(Packet *p, TagData *tag, int mode, u_int32_t now, 
                u_int16_t event_id)
{
    TagNode *idx;  /* index pointer */
    TagNode *returned;
    ubi_trRootPtr tag_cache_ptr = NULL;

    DEBUG_WRAP(DebugMessage(DEBUG_FLOW, "Adding new Tag Head\n"););

    idx = (TagNode *) TagAlloc(sizeof(TagNode));

    idx->sip = p->iph->ip_src.s_addr;
    idx->dip = p->iph->ip_dst.s_addr;
    idx->sp = p->sp;
    idx->dp = p->dp;
    idx->proto = p->iph->ip_proto;
    idx->metric = tag->tag_metric;
    idx->last_access = now;
    idx->event_id = event_id;
    idx->event_time.tv_sec = p->pkth->ts.tv_sec;
    idx->event_time.tv_usec = p->pkth->ts.tv_usec;
    idx->mode = mode;
    idx->pkt_count = 0;
    
    if(idx->metric & TAG_METRIC_SECONDS)
    {
        /* set the expiration time for this tag */
        idx->seconds = now + tag->tag_seconds;
    }

    if(idx->metric & TAG_METRIC_BYTES)
    {
        /* set the expiration time for this tag */
        idx->bytes = tag->tag_bytes;
    }

    if(idx->metric & TAG_METRIC_PACKETS)
    {
        /* set the expiration time for this tag */
        idx->packets = tag->tag_packets;
    }

    DEBUG_WRAP(PrintTagNode(idx););
    
    if(mode == TAG_SESSION)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FLOW,"Session Tag!\n"););
        tag_cache_ptr = ssn_tag_cache_ptr;
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FLOW,"Host Tag!\n"););
        tag_cache_ptr = host_tag_cache_ptr;
    }
    
    /* check for duplicates */
    returned = (TagNode *) ubi_sptFind(tag_cache_ptr, 
                                       (ubi_btItemPtr)idx);
        
    if(returned == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FLOW,"Looking the other way!!\n"););
        SwapTag(idx);            
        returned = (TagNode *) ubi_sptFind(tag_cache_ptr, 
                                           (ubi_btItemPtr)idx);
        SwapTag(idx);
    }

    if(returned == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FLOW,"Inserting a New Tag!\n"););

        /* if we're supposed to be tagging the other side, swap it
           around -- Lawrence Reed */
        if(mode == TAG_HOST_DST)
        {
            SwapTag(idx);
        }

        if(ubi_sptInsert(tag_cache_ptr,
                         (ubi_btNodePtr)idx, (ubi_btNodePtr)idx, NULL) == FALSE)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FLOW,
                                    "sptInsert failed, that's going to "
                                    "make life difficult\n"););
            return;
        }
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FLOW,"Existing Tag found!\n"););

        if(idx->metric & TAG_METRIC_SECONDS)
            returned->seconds = idx->seconds;
        else
            returned->seconds += idx->seconds;

        /* get rid of the new tag since we are using an existing one */
        free(idx); 
        tag_memory_usage -= sizeof(TagNode);
    }

    DEBUG_WRAP(PrintTagNode(idx););
    
    return;
}


int CheckTagList(Packet *p, Event *event)
{
    TagNode idx;
    TagNode *returned = NULL;
    ubi_trRootPtr taglist = NULL;
    char create_event = 1;

    /* check for active tags */
    if(!ubi_trCount(host_tag_cache_ptr) && !ubi_trCount(ssn_tag_cache_ptr))
    {
        return 0;
    }

    if(p == NULL || p->iph == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FLOW, "bailing from CheckTagList, p->iph == NULL\n"););
        return 0;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_FLOW,"Host Tags Active: %d   Session Tags Active: %d\n", 
			    ubi_trCount(host_tag_cache_ptr), ubi_trCount(ssn_tag_cache_ptr)););

    DEBUG_WRAP(DebugMessage(DEBUG_FLOW, "[*] Checking session tag list (forward)...\n"););

    idx.sip = p->iph->ip_src.s_addr;
    idx.dip = p->iph->ip_dst.s_addr;
    idx.sp = p->sp;
    idx.dp = p->dp;

    /* check for session tags... */
    returned = (TagNode *) ubi_sptFind(ssn_tag_cache_ptr, (ubi_btItemPtr)&idx);

    if(returned == NULL)
    {
        idx.dip = p->iph->ip_src.s_addr;
        idx.sip = p->iph->ip_dst.s_addr;
        idx.dp = p->sp;
        idx.sp = p->dp;

        DEBUG_WRAP(DebugMessage(DEBUG_FLOW, "   Checking session tag list (reverse)...\n"););
        returned = (TagNode *) ubi_sptFind(ssn_tag_cache_ptr, 
                (ubi_btItemPtr)&idx);

        if(returned == NULL)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FLOW, "   Checking host tag list "
				    "(forward)...\n"););

            returned = (TagNode *) ubi_sptFind(host_tag_cache_ptr, 
                    (ubi_btItemPtr)&idx);

            if(returned == NULL)
            {
                /*
                **  Only switch sip, because that's all we check for
                **  the host tags.
                */
                idx.sip = p->iph->ip_src.s_addr;

                returned = (TagNode *) ubi_sptFind(host_tag_cache_ptr, 
                        (ubi_btItemPtr)&idx);
            }

            if(returned != NULL)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_FLOW,"   [*!*] Found host node\n"););
                taglist = host_tag_cache_ptr;
            }
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FLOW,"   [*!*] Found session node\n"););
            taglist = ssn_tag_cache_ptr;
        }
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FLOW,"   [*!*] Found session node\n"););
        taglist = ssn_tag_cache_ptr;
    }

    if(returned != NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FLOW, "    ! Found tag node !\n"););

        returned->last_access = p->pkth->ts.tv_sec;

        if(returned->metric & TAG_METRIC_SECONDS)
        {
            if(p->pkth->ts.tv_sec > returned->seconds)
            {
                returned->seconds = 0;
            }
        }

        if(returned->metric & TAG_METRIC_PACKETS)
        {
            /* decrement the packet count */
            returned->packets--;

            if (returned->packets < 0)
            {
                returned->packets = 0;
                create_event = 0;
            }
        }

        if(returned->metric & TAG_METRIC_BYTES)
        {
            returned->bytes -= (int) ntohs(p->iph->ip_len);

            if(returned->bytes < 0)
            {
                returned->bytes = 0;
            }
        }

        returned->pkt_count++;

        /* Check whether or not to actually log an event.
         * This is used to prevent a poorly written tag rule
         * from DOSing a backend event processors on high
         * bandwidth sensors. */
        if (!(returned->metric & (TAG_METRIC_PACKETS|TAG_METRIC_UNLIMITED)))
        {
            /* Use the global max. */
            /* If its non-0, check count for this tag node */
            if (pv.tagged_packet_limit &&
                returned->pkt_count > pv.tagged_packet_limit)
            {
                create_event = 0;
            }
        }

        if (create_event)
        {
            /* set the event info */
            SetEvent(event, GENERATOR_TAG, TAG_LOG_PKT, 1, 1, 1, 
                    returned->event_id);
            /* set event reference details */
            event->ref_time.tv_sec = returned->event_time.tv_sec;
            event->ref_time.tv_usec = returned->event_time.tv_usec;
            event->event_reference = returned->event_id | pv.event_log_id;
        }
        
        if(returned->bytes == 0 && returned->packets == 0 && 
                returned->seconds == 0)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FLOW,"    Prune condition met for tag, removing"
				    " from list\n"););
            returned = (TagNode *) ubi_sptRemove(taglist, 
                    (ubi_btNodePtr)returned);

            free(returned);
            tag_memory_usage -= sizeof(TagNode);
        }
    }

    if( (u_int)(p->pkth->ts.tv_sec) > last_prune_time + TAG_PRUNE_QUANTUM)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FLOW,
                                "Exceeded Prune Quantum, pruning tag trees\n"););
        PruneTagCache(p->pkth->ts.tv_sec, 0);
        last_prune_time = p->pkth->ts.tv_sec;
    }

    if((returned != NULL) && (create_event))
    {
        return 1;
    }

    return 0;
}


static int PruneTagCache(u_int32_t thetime, int mustdie)
{
    TagNode *idx;
    int pruned = 0;

    if(!mustdie)
    {
        if(ubi_trCount(ssn_tag_cache_ptr))
        {
            pruned = PruneTime(ssn_tag_cache_ptr, thetime);
        }

        if(ubi_trCount(host_tag_cache_ptr))
        {
            pruned += PruneTime(host_tag_cache_ptr, thetime);
        }

        return pruned;
    }
    else
    {
        while(mustdie > 0)
        {
            if(ubi_trCount(ssn_tag_cache_ptr))
            {
                idx = (TagNode *) 
                    ubi_btLeafNode((ubi_btNodePtr)ssn_tag_cache_ptr);
                mustdie--;
                free(idx);
                tag_memory_usage -= sizeof(TagNode);
            }

            if(ubi_trCount(host_tag_cache_ptr))
            {
                idx = (TagNode *) 
                    ubi_btLeafNode((ubi_btNodePtr)host_tag_cache_ptr);
                mustdie--;
                free(idx);
                tag_memory_usage -= sizeof(TagNode);
            }
        }

        return 0;

    }
}


static int PruneTime(ubi_trRootPtr tree, u_int32_t thetime)
{
    int pruned = 0;
    TagNode *idx;
    TagNode *savidx;
    TagNode *killme;

    idx = (TagNode *) ubi_btFirst((ubi_btNodePtr)tree);

    if(idx == NULL)
    {
        return 0;
    }

    do
    {
        if((idx->last_access+TAG_PRUNE_QUANTUM) < thetime)
        {
            savidx = idx;
            idx = (TagNode *) ubi_btNext((ubi_btNodePtr)idx);

            killme = (TagNode *) ubi_sptRemove(tree, (ubi_btNodePtr) savidx);

            free(killme);
            tag_memory_usage -= sizeof(TagNode);
            pruned++;
        }
        else
        {
            if(idx != NULL && ubi_trCount(tree))
            {
                idx = (TagNode *) ubi_btNext((ubi_btNodePtr)idx);
            }
            else
            {
                return pruned;
            }
        }
    } while(idx != NULL);

    return pruned;
}

void SetTags(Packet *p, OptTreeNode *otn, u_int16_t event_id)
{
   DEBUG_WRAP(DebugMessage(DEBUG_FLOW, "Setting tags\n"););

    if(otn != NULL && otn->tag != NULL)
    {
        if (otn->tag->tag_type != 0)
        {
            switch(otn->tag->tag_type)
            {
                case TAG_SESSION: 
                    DEBUG_WRAP(DebugMessage(DEBUG_FLOW,"Setting session tag:\n");
			       DebugMessage(DEBUG_FLOW,"SIP: 0x%X  SP: %d   DIP: 0x%X  "
					    "DP: %d\n", p->iph->ip_src.s_addr,p->sp,
					    p->iph->ip_dst.s_addr,p->dp););
		    
                    TagSession(p, otn->tag, p->pkth->ts.tv_sec, event_id);
                    break;

                case TAG_HOST:
                    DEBUG_WRAP(DebugMessage(DEBUG_FLOW,"Setting host tag:\n");
			       DebugMessage(DEBUG_FLOW,"SIP: 0x%X  SP: %d   DIP: 0x%X  "
					    "DP: %d\n", p->iph->ip_src.s_addr,p->sp,
					    p->iph->ip_dst.s_addr,p->dp););
                    TagHost(p, otn->tag, p->pkth->ts.tv_sec, event_id);
                    break;    
    
                default:
                    LogMessage("WARNING: Trying to tag with unknown "
                            "tag type!\n");
                    break;    
            }

            check_tags_flag = 0;
        }
    }

    return;
}



void ParseTag(char *args, OptTreeNode *otn)
{
    char *arg = args;
    int type = 0;
    int count = 0;
    int metric = 0;
    int packets = 0;
    int seconds = 0;
    int bytes = 0;
    int direction = 0;
    int i = 0;

    DEBUG_WRAP(DebugMessage(DEBUG_RULES, "Parsing tag args: %s\n", args););

    while ((arg = strtok( arg, " ,"))) 
    {
        DEBUG_WRAP(DebugMessage(DEBUG_RULES, "parsing tag tok: \"%s\"\n", arg););

        while(isspace((int)*arg))
        {
            arg++;
        }

        if(!strncasecmp(arg, "session", 7))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FLOW, "Setting type to SESSION\n"););
            type = TAG_SESSION;
        }
        else if(!strncasecmp(arg, "host", 4))
        {
            type = TAG_HOST;
        }
        else if(!strncasecmp(arg, "src", 3))
        {
            direction = TAG_HOST_SRC;
        }
        else if(!strncasecmp(arg, "dst", 3))
        {
            direction = TAG_HOST_DST;
        }
        else if(!strncasecmp(arg, "seconds", 7))
        {
            metric |= TAG_METRIC_SECONDS;
            seconds = count;
        }
        else if (!strncasecmp(arg, "packets", 7))
        {
            if (count)
            {
                metric |= TAG_METRIC_PACKETS;
                packets = count;
            }
            else
            {
                metric |= TAG_METRIC_UNLIMITED;
                /* Set count in case 'packets' is the last
                 * option parsed since 0 is a valid value now */
                count = -1;
            }
        }
        else if(!strncasecmp(arg, "bytes", 5))
        {
            metric |= TAG_METRIC_BYTES;
            bytes = count;
        }
        else if(isdigit((int) *arg))
        {
            count = atoi(arg);
        }
        else
        {
            FatalError("%s(%d) Unable to Parse Tag option: %s\n", file_name, file_line, arg);
        }

        arg = NULL;
        i++;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Set type: %d  metric: %x count: %d\n", type, 
                metric, count););

    /* check that we've got enough to set a tag with */
    if(type && metric && count)
    {
        otn->tag = (TagData *)SnortAlloc(sizeof(TagData));

        otn->tag->tag_type = type;
        otn->tag->tag_metric = metric;
        otn->tag->tag_seconds = seconds;
        otn->tag->tag_bytes = bytes;
        otn->tag->tag_packets = packets;
        otn->tag->tag_direction = direction;
    }

    if ((metric & TAG_METRIC_UNLIMITED) &&
        !(metric & (TAG_METRIC_BYTES|TAG_METRIC_SECONDS)))
    {
        FatalError("%s(%d) Invalid Tag options. 'packets' parameter '0' but\n"
                "neither seconds or bytes specified: %s\n",
                file_name, file_line, arg);
    }
    return;
}
