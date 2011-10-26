/* $Id$ */
/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 2002, Sourcefire, Inc.
**    Dan Roelker <droelker@sourcefire.com>
**    Marc Norton <mnorton@sourcefire.com>
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
**
** NOTES
**   5.7.02: Added interface for new detection engine. (Norton/Roelker)
**
*/

#define FASTPKT

/*  I N C L U D E S  **********************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "snort.h"
#include "detect.h"
#include "plugbase.h"
#include "debug.h"
#include "util.h"
#include "mstring.h"
#include "tag.h"
#include "pcrm.h"
#include "fpcreate.h"
#include "fpdetect.h"
#include "sfthreshold.h"
#include "event_wrapper.h"
#include "event_queue.h"
#include "stream_api.h"
#include "inline.h"
#include <config/autoconf.h>

/* XXX modularization violation */
#include "preprocessors/spp_flow.h"

#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats detectPerfStats;
#endif

/* #define ITERATIVE_ENGINE */

extern ListHead Alert;         /* Alert Block Header */
extern ListHead Log;           /* Log Block Header */
extern ListHead Pass;          /* Pass Block Header */
extern ListHead Activation;    /* Activation Block Header */
extern ListHead Dynamic;       /* Dynamic Block Header */
extern ListHead Drop;
#ifdef GIDS
extern ListHead SDrop;
extern ListHead Reject;
#endif /* GIDS */

extern RuleTreeNode *rtn_tmp;      /* temp data holder */
extern OptTreeNode *otn_tmp;       /* OptTreeNode temp ptr */
extern ListHead *head_tmp;         /* ListHead temp ptr */

extern RuleListNode *RuleLists;

extern int dynamic_rules_present;
extern int active_dynamic_nodes;

extern PreprocessFuncNode *PreprocessList;  /* Preprocessor function list */
extern OutputFuncNode *AlertList;   /* Alert function list */
extern OutputFuncNode *LogList; /* log function list */

/*
**  The HTTP decode structre
*/
extern HttpUri UriBufs[URI_COUNT];

int do_detect;
int do_detect_content;
u_int16_t event_id;
char check_tags_flag;

void printRuleListOrder(RuleListNode * node);
static int CheckTagging(Packet *p);
static RuleListNode *addNodeToOrderedList(RuleListNode *ordered_list, 
        RuleListNode *node, int evalIndex);

#ifdef PERF_PROFILING
PreprocStats eventqPerfStats;
#endif

int Preprocess(Packet * p)
{
    PreprocessFuncNode *idx;
    int retval = 0;
    PROFILE_VARS;

    /*
     *  If the packet has an invalid checksum marked, throw that
     *  traffic away as no end host should accept it.
     *
     *  This can be disabled by config checksum_mode: none
     */
    if(!p->csum_flags)
    {
        do_detect = do_detect_content = 1;
        idx = PreprocessList;

        /*
        **  Reset the appropriate application-layer protocol fields
        */
        p->uri_count = 0;
        UriBufs[0].decode_flags = 0;

        /*
        **  Turn on all preprocessors
        */
        boSetAllBits(p->preprocessor_bits);

        while ((idx != NULL) && (!(p->packet_flags & PKT_PASS_RULE)))
        {
            assert(idx->func != NULL);
            if (IsPreprocBitSet(p, idx->preproc_bit))
            {
                idx->func(p, idx->context);
            }
            idx = idx->next;
        }

        check_tags_flag = 1;
    
        if ((do_detect) && (p->bytes_to_inspect != -1))
        {
            /* Check if we are only inspecting a portion of this packet... */
            if (p->bytes_to_inspect > 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "Ignoring part of server "
                    "traffic -- only looking at %d of %d bytes!!!\n",
                    p->bytes_to_inspect, p->dsize););
                p->dsize = (u_int16_t)p->bytes_to_inspect;
            }
            Detect(p);
        }
        else if (p->bytes_to_inspect == -1)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "Ignoring server traffic!!!\n"););
        }
    }

    /*
    ** By checking tagging here, we make sure that we log the
    ** tagged packet whether it generates an alert or not.
    */
    PREPROC_PROFILE_START(eventqPerfStats);
    CheckTagging(p);

    retval = SnortEventqLog(p);
    SnortEventqReset();
    PREPROC_PROFILE_END(eventqPerfStats);

    otn_tmp = NULL;

    /*
    **  If we found events in this packet, let's flush
    **  the stream to make sure that we didn't miss any
    **  attacks before this packet.
    */
    if(retval && stream_api)
        stream_api->alert_flush_stream(p);

    /**
     * See if we should go ahead and remove this flow from the
     * flow_preprocessor -- cmg
     */
    CheckFlowShutdown(p);
    
    return retval;
}

/*
**  NAME
**    CheckTagging::
*/
/**
**  This is where we check to see if we tag the packet.  We only do
**  this if we've alerted on a non-pass rule and the packet is not
**  rebuilt.
**
**  We don't log rebuilt packets because the output plugins log the
**  individual packets of a rebuilt stream, so we don't want to dup
**  tagged packets for rebuilt streams.
**
**  @return integer
*/
static int CheckTagging(Packet *p)
{
    Event event;

    if(check_tags_flag == 1 && !(p->packet_flags & PKT_REBUILT_STREAM)) 
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FLOW, "calling CheckTagList\n"););

        if(CheckTagList(p, &event))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FLOW, "Matching tag node found, "
                        "calling log functions\n"););

            /* if we find a match, we want to send the packet to the
             * logging mechanism
             */
            CallLogFuncs(p, "Tagged Packet", NULL, &event);
        } 
    }

    return 0;
}

void CallLogFuncs(Packet *p, char *message, ListHead *head, Event *event)
{
    OutputFuncNode *idx = NULL;

    /*
    **  Don't do thresholding on tagged packets.  The tv_sec check
    **  makes sure that we don't.
    */
    if(p && event->ref_time.tv_sec == 0)
    {
        /*
         *  Perform Thresholding Tests 
         */
        if(p->iph)
        {
            if( !sfthreshold_test( event->sig_generator,
                                   event->sig_id,
                                   p->iph->ip_src.s_addr,
                                   p->iph->ip_dst.s_addr,
                                   p->pkth->ts.tv_sec ) )
            {
                return; /* Don't log it ! */
            }
        }
        else
        {
            if( !sfthreshold_test( event->sig_generator,
                                   event->sig_id,
                                   0,
                                   0,
                                   p->pkth->ts.tv_sec ) )
            {
                return; /* Don't log it ! */
            }
        }

        /*
        **  Set the ref time after we check thresholding.
        */
        event->ref_time.tv_sec = p->pkth->ts.tv_sec;
        event->ref_time.tv_usec = p->pkth->ts.tv_usec;
    }

    /* set the event number */
    event->event_id = event_id | pv.event_log_id;

    if(head == NULL)
    {
        CallLogPlugins(p, message, NULL, event);
        return;
    }

    if(p != NULL)
    {
        if(pv.obfuscation_flag)
            ObfuscatePacket(p);
    }

    pc.log_pkts++;
     
    idx = head->LogList;
    if(idx == NULL)
        idx = LogList;

    while(idx != NULL)
    {
        idx->func(p, message, idx->arg, event);
        idx = idx->next;
    }

    return;
}

void CallLogPlugins(Packet * p, char *message, void *args, Event *event)
{
    OutputFuncNode *idx;

    idx = LogList;

    if(p != NULL)
    {
        if(pv.obfuscation_flag)
            ObfuscatePacket(p);
    }

    pc.log_pkts++;

    while(idx != NULL)
    {
        idx->func(p, message, idx->arg, event);
        idx = idx->next;
    }

    return;
}

/* Call the output functions that are directly attached to the signature */
void CallSigOutputFuncs(Packet *p, OptTreeNode *otn, Event *event)
{
    OutputFuncNode *idx = NULL;

    idx = otn->outputFuncs;

    if(p && pv.obfuscation_flag)
        ObfuscatePacket(p);

    while(idx)
    {
        idx->func(p, otn->sigInfo.message, idx->arg, event);
        idx = idx->next;
    }
}


void CallAlertFuncs(Packet * p, char *message, ListHead * head, Event *event)
{
    OutputFuncNode *idx = NULL;

    /*
    **  Don't do thresholding on tagged packets.  The tv_sec check
    **  makes sure that we don't.
    */
    if(p && event->ref_time.tv_sec == 0)
    {
        /*
         *  Perform Thresholding Tests 
         */
        if(p->iph)
        {
            if( !sfthreshold_test( event->sig_generator,
                                   event->sig_id,
                                   p->iph->ip_src.s_addr,
                                   p->iph->ip_dst.s_addr,
                                   p->pkth->ts.tv_sec ) )
            {
                return; /* Don't log it ! */
            }
        }
        else
        {
            if( !sfthreshold_test( event->sig_generator,
                                   event->sig_id,
                                   0,
                                   0,
                                   p->pkth->ts.tv_sec ) )
            {
                return; /* Don't log it ! */
            }
        }

        /*
        **  Set the ref time after we check thresholding.
        */
        event->ref_time.tv_sec = p->pkth->ts.tv_sec;
        event->ref_time.tv_usec = p->pkth->ts.tv_usec;
    }

    /* set the event number */
    event->event_id = event_id | pv.event_log_id;
    /* set the event reference info */
    event->event_reference = event->event_id;

    if(head == NULL)
    {
        CallAlertPlugins(p, message, NULL, event);
        return;
    }

    if(p && pv.obfuscation_flag)
        ObfuscatePacket(p);


    pc.alert_pkts++;
    idx = head->AlertList;
    if(idx == NULL)
        idx = AlertList;

    while(idx != NULL)
    {
        idx->func(p, message, idx->arg, event);
        idx = idx->next;
    }

    return;
}


void CallAlertPlugins(Packet * p, char *message, void *args, Event *event)
{
    OutputFuncNode *idx;

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "Call Alert Plugins\n"););
    idx = AlertList;

    if(p && pv.obfuscation_flag)
        ObfuscatePacket(p);

    pc.alert_pkts++;
    while(idx != NULL)
    {
        idx->func(p, message, idx->arg, event);
        idx = idx->next;
    }

    return;
}



/****************************************************************************
 *
 * Function: Detect(Packet *)
 *
 * Purpose: Apply the rules lists to the current packet
 *
 * Arguments: p => ptr to the decoded packet struct
 *
 * Returns: 1 == detection event
 *          0 == no detection
 *
 ***************************************************************************/
int Detect(Packet * p)
{
    int detected = 0;
    PROFILE_VARS;

    if(p == NULL || p->iph == NULL)
    {
        return 0;
    }

    if (p->packet_flags & PKT_PASS_RULE)
    {
        /* If we've already seen a pass rule on this,
         * no need to continue do inspection.
         */
        return 0;
    }

    /*
    **  This is where we short circuit so 
    **  that we can do IP checks.
    */
    PREPROC_PROFILE_START(detectPerfStats);
    detected = fpEvalPacket(p);
    PREPROC_PROFILE_END(detectPerfStats);

#ifdef CONFIG_PROP_STATSD_STATSD
	if (detected) {
		InlineMode() ?	system("statsd -a incr ips blocked"):
						system("statsd -a incr snort detected");
	}
#endif

    return detected;
}

void TriggerResponses(Packet * p, OptTreeNode * otn)
{

    RspFpList *idx;

    idx = otn->rsp_func;

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,"Triggering responses %p\n", idx););

    while(idx != NULL)
    {
        idx->ResponseFunc(p, idx);
        idx = idx->next;
    }

}

int CheckAddrPort(IpAddrSet *rule_addr, u_int16_t hi_port, u_int16_t lo_port, 
        Packet *p, u_int32_t flags, int mode)
{
    u_long pkt_addr;         /* packet IP address */
    u_short pkt_port;        /* packet port */
    int global_except_addr_flag = 0; /* global exception flag is set */
    int any_port_flag = 0;           /* any port flag set */
    int except_addr_flag = 0;        /* any addr flag set */
    int except_port_flag = 0;        /* port exception flag set */
    int ip_match = 0;                /* flag to indicate addr match made */
    IpAddrSet *idx;  /* ip addr struct indexer */

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "CheckAddrPort: "););
    /* set up the packet particulars */
    if(mode & CHECK_SRC)
    {
        pkt_addr = p->iph->ip_src.s_addr;
        pkt_port = p->sp;

        DEBUG_WRAP(DebugMessage(DEBUG_DETECT,"SRC "););

        if(mode & INVERSE)
        {
            global_except_addr_flag = flags & EXCEPT_DST_IP;
            any_port_flag = flags & ANY_DST_PORT;
            except_port_flag = flags & EXCEPT_DST_PORT;
        }
        else
        {
            global_except_addr_flag = flags & EXCEPT_SRC_IP;
            any_port_flag = flags & ANY_SRC_PORT;
            except_port_flag = flags & EXCEPT_SRC_PORT;
        }
    }
    else
    {
        pkt_addr = p->iph->ip_dst.s_addr;
        pkt_port = p->dp;

        DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "DST "););

        if(mode & INVERSE)
        {
            global_except_addr_flag = flags & EXCEPT_SRC_IP;
            any_port_flag = flags & ANY_SRC_PORT;
            except_port_flag = flags & EXCEPT_SRC_PORT;
        }
        else
        {
            global_except_addr_flag = flags & EXCEPT_DST_IP;
            any_port_flag = flags & ANY_DST_PORT;
            except_port_flag = flags & EXCEPT_DST_PORT;
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "addr %lx, port %d ", pkt_addr, 
                pkt_port););

    idx = rule_addr;
    if(!(global_except_addr_flag)) /*modeled after Check{Src,Dst}IP function*/
    {
        while(idx != NULL)
        {
            except_addr_flag = idx->addr_flags & EXCEPT_IP;

            /* test the rule address vs. the packet address */
            if(!((idx->ip_addr==(pkt_addr & idx->netmask)) ^ except_addr_flag))
            {
                idx = idx->next;
            }
            else
            {
                ip_match = 1;
                goto bail;
            }
        }
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT, ", global exception flag set"););
        /* global exception flag is up, we can't match on *any* 
         * of the source addresses 
         */
        while(idx != NULL)
        {
            except_addr_flag = idx->addr_flags & EXCEPT_IP;

            /* test the rule address vs. the packet address */
            if(((idx->ip_addr == (pkt_addr & idx->netmask)) ^ 
                        except_addr_flag))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DETECT, 
                            ", address matched, packet rejected\n"));

                /* got address match on globally negated rule, fail */
                return 0;
            }
            idx = idx->next;
        }
        ip_match = 1;
    }

    bail:
    if(!ip_match)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT, ", no address match,  "
                    "packet rejected\n"););
        return 0;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, ", addresses accepted"););
    
    /* if the any port flag is up, we're all done (success) */
    if(any_port_flag)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT, ", any port match, "
                    "packet accepted\n"););
        return 1;
    }

    /* check the packet port against the rule port */
    if((pkt_port > hi_port) || (pkt_port < lo_port))
    {
        /* if the exception flag isn't up, fail */
        if(!except_port_flag)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DETECT, ", port mismatch,  "
                        "packet rejected\n"););
            return 0;
        }
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT, ", port mismatch exception"););
    }
    else
    {
        /* if the exception flag is up, fail */
        if(except_port_flag)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
                                    ", port match exception,  packet rejected\n"););
            return 0;
        }
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT, ", ports match"););
    }

    /* ports and address match */
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, ", packet accepted!\n"););
    return 1;

}

/****************************************************************************
 *
 * Function: DumpChain(RuleTreeNode *, char *, char *)
 *
 * Purpose: print out the chain lists by header block node group
 *
 * Arguments: rtn_idx => the RTN index pointer
 *                       rulename => the name of the rule the list belongs to
 *            listname => the name of the list being printed out
 *
 * Returns: void function
 *
 ***************************************************************************/
void DumpChain(RuleTreeNode * rtn_head, char *rulename, char *listname)
{
    RuleTreeNode *rtn_idx;
    IpAddrSet *idx;  /* indexing pointer */
    int i;
#ifdef DEBUG
    OptTreeNode *otn_idx;
#endif


    
    DEBUG_WRAP(DebugMessage(DEBUG_RULES, "%s %s\n", rulename, listname););

    rtn_idx = rtn_head;

    if(rtn_idx == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_RULES, "    Empty!\n\n"););
    }

    /* walk thru the RTN list */
    while(rtn_idx != NULL)
    {
        DEBUG_WRAP(
                DebugMessage(DEBUG_RULES, "Rule type: %d\n", rtn_idx->type);
                DebugMessage(DEBUG_RULES, "SRC IP List:\n");
                );
        idx = rtn_idx->sip;
        i = 0;
        while(idx != NULL)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_RULES,
                        "[%d]    0x%.8lX / 0x%.8lX",
                        i++, (u_long) idx->ip_addr,
                        (u_long) idx->netmask););

            if(idx->addr_flags & EXCEPT_IP)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_RULES, 
                            "    (EXCEPTION_FLAG Active)\n"););
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_RULES, "\n"););
            }
            idx = idx->next;
        }

        DEBUG_WRAP(DebugMessage(DEBUG_RULES, "DST IP List:\n"););
        idx = rtn_idx->dip;
        i = 0;

        while(idx != NULL)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_RULES,
                        "[%d]    0x%.8lX / 0x%.8lX",
                        i++,(u_long)  idx->ip_addr,
                        (u_long)  idx->netmask););    
            if(idx->addr_flags & EXCEPT_IP)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_RULES, 
                            "    (EXCEPTION_FLAG Active)\n"););
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_RULES, "\n"););
            }

            idx = idx->next;
        }
#ifdef DEBUG
        DebugMessage(DEBUG_RULES, "SRC PORT: %d - %d \n", rtn_idx->lsp, 
                rtn_idx->hsp);
        DebugMessage(DEBUG_RULES, "DST PORT: %d - %d \n", rtn_idx->ldp, 
                rtn_idx->hdp);
        DebugMessage(DEBUG_RULES, "Flags: ");

        if(rtn_idx->flags & EXCEPT_SRC_IP)
            DebugMessage(DEBUG_RULES, "EXCEPT_SRC_IP ");
        if(rtn_idx->flags & EXCEPT_DST_IP)
            DebugMessage(DEBUG_RULES, "EXCEPT_DST_IP ");
        if(rtn_idx->flags & ANY_SRC_PORT)
            DebugMessage(DEBUG_RULES, "ANY_SRC_PORT ");
        if(rtn_idx->flags & ANY_DST_PORT)
            DebugMessage(DEBUG_RULES, "ANY_DST_PORT ");
        if(rtn_idx->flags & EXCEPT_SRC_PORT)
            DebugMessage(DEBUG_RULES, "EXCEPT_SRC_PORT ");
        if(rtn_idx->flags & EXCEPT_DST_PORT)
            DebugMessage(DEBUG_RULES, "EXCEPT_DST_PORT ");
        DebugMessage(DEBUG_RULES, "\n");

        otn_idx = rtn_idx->down;

        DEBUG_WRAP(
            /* print the RTN header number */
            DebugMessage(DEBUG_RULES,
                "Head: %d (type: %d)\n",
                rtn_idx->head_node_number, otn_idx->type);
            DebugMessage(DEBUG_RULES, "      |\n");
            DebugMessage(DEBUG_RULES, "       ->");
            );

        /* walk thru the OTN chain */
        while(otn_idx != NULL)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_RULES,
                        " %d", otn_idx->chain_node_number););
            otn_idx = otn_idx->next;
        }

        DEBUG_WRAP(DebugMessage(DEBUG_RULES, "|=-\n"););
#endif
        rtn_idx = rtn_idx->right;
    }
}



void IntegrityCheck(RuleTreeNode * rtn_head, char *rulename, char *listname)
{
    RuleTreeNode *rtn_idx = NULL;
    OptTreeNode *otn_idx;
    OptFpList *ofl_idx;
    int opt_func_count;

#ifdef DEBUG
    char chainname[STD_BUF];

    SnortSnprintf(chainname, STD_BUF, "%s %s", rulename, listname);

    if(!pv.quiet_flag)
        DebugMessage(DEBUG_DETECT, "%-20s: ", chainname);
#endif

    if(rtn_head == NULL)
    {
#ifdef DEBUG
        if(!pv.quiet_flag)
            DebugMessage(DEBUG_DETECT,"Empty list...\n");
#endif
        return;
    }

    rtn_idx = rtn_head;

    while(rtn_idx != NULL)
    {
        otn_idx = rtn_idx->down;

        while(otn_idx != NULL)
        {
            ofl_idx = otn_idx->opt_func;
            opt_func_count = 0;

            while(ofl_idx != NULL)
            {
                opt_func_count++;
                DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "%p->",ofl_idx->OptTestFunc););
                ofl_idx = ofl_idx->next;
            }

            if(opt_func_count == 0)
            {
                FatalError("Zero Length OTN List\n");
            }
            DEBUG_WRAP(DebugMessage(DEBUG_DETECT,"\n"););
            otn_idx = otn_idx->next;
        }

        rtn_idx = rtn_idx->right;
    }

#ifdef DEBUG
    if(!pv.quiet_flag)
        DebugMessage(DEBUG_DETECT, "OK\n");
#endif

}



int CheckBidirectional(Packet *p, struct _RuleTreeNode *rtn_idx, 
        RuleFpList *fp_list)
{
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "Checking bidirectional rule...\n"););
    
    if(CheckAddrPort(rtn_idx->sip, rtn_idx->hsp, rtn_idx->lsp, p,
                     rtn_idx->flags, CHECK_SRC))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "   Src->Src check passed\n"););
        if(! CheckAddrPort(rtn_idx->dip, rtn_idx->hdp, rtn_idx->ldp, p,
                           rtn_idx->flags, CHECK_DST))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
                                    "   Dst->Dst check failed,"
                                    " checking inverse combination\n"););
            if(CheckAddrPort(rtn_idx->dip, rtn_idx->hdp, rtn_idx->ldp, p,
                             rtn_idx->flags, (CHECK_SRC | INVERSE)))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
                                    "   Inverse Dst->Src check passed\n"););
                if(!CheckAddrPort(rtn_idx->sip, rtn_idx->hsp, rtn_idx->lsp, p,
                                  rtn_idx->flags, (CHECK_DST | INVERSE)))
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
                                    "   Inverse Src->Dst check failed\n"););
                    return 0;
                }
                else
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "Inverse addr/port match\n"););
                }
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "   Inverse Dst->Src check failed,"
                                        " trying next rule\n"););
                return 0;
            }
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "dest IP/port match\n"););
        }
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
                                "   Src->Src check failed, trying inverse test\n"););
        if(CheckAddrPort(rtn_idx->dip, rtn_idx->hdp, rtn_idx->ldp, p,
                         rtn_idx->flags, CHECK_SRC | INVERSE))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
                        "   Dst->Src check passed\n"););

            if(! CheckAddrPort(rtn_idx->sip, rtn_idx->hsp, rtn_idx->lsp, p, 
                        rtn_idx->flags, CHECK_DST | INVERSE))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
                            "   Src->Dst check failed\n"););
                return 0;
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
                            "Inverse addr/port match\n"););
            }
        }
        else
        { 
            DEBUG_WRAP(DebugMessage(DEBUG_DETECT,"   Inverse test failed, "
                        "testing next rule...\n"););
            return 0;
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,"   Bidirectional success!\n"););
    return 1;
}



/****************************************************************************
 *
 * Function: CheckSrcIpEqual(Packet *, struct _RuleTreeNode *, RuleFpList *)
 *
 * Purpose: Test the source IP and see if it equals the SIP of the packet
 *
 * Arguments: p => ptr to the decoded packet data structure
 *            rtn_idx => ptr to the current rule data struct
 *            fp_list => ptr to the current function pointer node
 *
 * Returns: 0 on failure (no match), 1 on success (match)
 *
 ***************************************************************************/
int CheckSrcIP(Packet * p, struct _RuleTreeNode * rtn_idx, RuleFpList * fp_list)
{
    IpAddrSet *idx; /* ip address indexer */

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,"CheckSrcIPEqual: "););

    /* check for global exception flag */
    if(!(rtn_idx->flags & EXCEPT_SRC_IP))
    {
        /* do the check */
        for(idx=rtn_idx->sip; idx != NULL; idx=idx->next)
        {
            if( ((idx->ip_addr == (p->iph->ip_src.s_addr & idx->netmask)) 
                        ^ (idx->addr_flags & EXCEPT_IP)) )
            {
#ifdef DEBUG
                if(idx->addr_flags & EXCEPT_IP) {
                    DebugMessage(DEBUG_DETECT, "  SIP exception match\n");
                } 
                else
                {
                    DebugMessage(DEBUG_DETECT, "  SIP match\n");
                }

                DebugMessage(DEBUG_DETECT, "Rule: 0x%X     Packet: 0x%X\n", 
                        idx->ip_addr, (p->iph->ip_src.s_addr & idx->netmask));
#endif /* DEBUG */

                /* the packet matches this test, proceed to the next test */
                return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next);
            }
        }
    }
    else
    {
        /* global exception flag is up, we can't match on *any* 
         * of the source addresses 
         */
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT,"  global exception flag, \n"););

        /* do the check */
        for(idx=rtn_idx->sip; idx != NULL; idx=idx->next)
        {
            if( ((idx->ip_addr == (p->iph->ip_src.s_addr & idx->netmask)) 
                        ^ (idx->addr_flags & EXCEPT_IP)) )
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DETECT,"address matched, failing on SIP\n"););
                /* got address match on globally negated rule, fail */
                return 0;
            }
        }
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT,"no matches on SIP, passed\n"););

        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next);
    }
    
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,"  Mismatch on SIP\n"););

    /* return 0 on a failed test */
    return 0;
}



/****************************************************************************
 *
 * Function: CheckSrcIpNotEq(Packet *, struct _RuleTreeNode *, RuleFpList *)
 *
 * Purpose: Test the source IP and see if it's unequal to the SIP of the
 *          packet
 *
 * Arguments: p => ptr to the decoded packet data structure
 *            rtn_idx => ptr to the current rule data struct
 *            fp_list => ptr to the current function pointer node
 *
 * Returns: 0 on failure (no match), 1 on success (match)
 *
 ***************************************************************************/
int CheckSrcIPNotEq(Packet *p, struct _RuleTreeNode *rtn_idx, 
        RuleFpList *fp_list)
{
    IpAddrSet *idx;  /* IP address indexer */
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "CheckSrcIPNotEq: "););

    /* do the check */
    for(idx=rtn_idx->sip; idx != NULL; idx=idx->next)
    {
        if( idx->ip_addr != (p->iph->ip_src.s_addr & idx->netmask) )
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "  SIP exception match\n"););
            /* the packet matches this test, proceed to the next test */
            return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next);
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "  Mismatch on SIP\n"););
    
    /* return 0 on a failed test */
    return 0;
}



/****************************************************************************
 *
 * Function: CheckDstIpEqual(Packet *, struct _RuleTreeNode *, RuleFpList *)
 *
 * Purpose: Test the dest IP and see if it equals the DIP of the packet
 *
 * Arguments: p => ptr to the decoded packet data structure
 *            rtn_idx => ptr to the current rule data struct
 *            fp_list => ptr to the current function pointer node
 *
 * Returns: 0 on failure (no match), 1 on success (match)
 *
 ***************************************************************************/
int CheckDstIP(Packet *p, struct _RuleTreeNode *rtn_idx, RuleFpList *fp_list)
{
    IpAddrSet *idx;  /* ip address indexer */

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "CheckDstIPEqual: ");)

    /* check for global exception flag */
    if(!(rtn_idx->flags & EXCEPT_DST_IP))
    {
        /* do the check */
        for(idx=rtn_idx->dip; idx != NULL; idx=idx->next)
        {
            if( ((idx->ip_addr == (p->iph->ip_dst.s_addr & idx->netmask)) 
                        ^ (idx->addr_flags & EXCEPT_IP)) )
            {
#ifdef DEBUG
                if(idx->addr_flags & EXCEPT_IP)
                {
                    DebugMessage(DEBUG_DETECT, "  DIP exception match\n");
                }
                else
                {
                    DebugMessage(DEBUG_DETECT, "  DIP match\n");
                }
                
                DebugMessage(DEBUG_DETECT, "Rule: 0x%X     Packet: 0x%X\n", 
                        idx->ip_addr, (p->iph->ip_src.s_addr & idx->netmask));
#endif /* DEBUG */
                /* the packet matches this test, proceed to the next test */
                return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next);
            }
        }
    }
    else
    {
        /* global exception flag is up, we can't match on *any* 
         * of the source addresses 
         */
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "  global exception flag, \n"););

        /* do the check */
        for(idx=rtn_idx->dip; idx != NULL; idx=idx->next)
        {
            if( ((idx->ip_addr == (p->iph->ip_dst.s_addr & idx->netmask)) 
                        ^ (idx->addr_flags & EXCEPT_IP)) )
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
                                        "address matched, failing on DIP\n"););
                /* got address match on globally negated rule, fail */
                return 0;
            }
        }
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "no matches on DIP, passed\n"););

        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "  Mismatch on DIP\n"););
    /* return 0 on a failed test */
    return 0;
}


/****************************************************************************
 *
 * Function: CheckDstIpNotEq(Packet *, struct _RuleTreeNode *, RuleFpList *)
 *
 * Purpose: Test the dest IP and see if it equals the DIP of the packet
 *
 * Arguments: p => ptr to the decoded packet data structure
 *            rtn_idx => ptr to the current rule data struct
 *            fp_list => ptr to the current function pointer node
 *
 * Returns: 0 on failure (no match), 1 on success (match)
 *
 ***************************************************************************/
int CheckDstIPNotEq(Packet *p, struct _RuleTreeNode *rtn_idx, 
        RuleFpList *fp_list)
{
    IpAddrSet *idx; /* ip address indexer */

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,"CheckDstIPNotEq: "););

    /* same as above */
    for(idx=rtn_idx->dip;idx != NULL; idx=idx->next)
    {
        if( idx->ip_addr != (p->iph->ip_dst.s_addr & idx->netmask) )
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DETECT,"  DIP exception match\n"););
            return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next);
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,"  Mismatch on DIP\n"););

    return 0;
}



int CheckSrcPortEqual(Packet *p, struct _RuleTreeNode *rtn_idx, 
        RuleFpList *fp_list)
{
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,"CheckSrcPortEqual: "););

    if( (p->sp <= rtn_idx->hsp) && (p->sp >= rtn_idx->lsp) )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "  SP match!\n"););
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next);
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "   SP mismatch!\n"););
    }

    return 0;
}





int CheckSrcPortNotEq(Packet *p, struct _RuleTreeNode *rtn_idx, 
        RuleFpList *fp_list)
{
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "CheckSrcPortNotEq: "););

    if( (p->sp > rtn_idx->hsp) || (p->sp < rtn_idx->lsp) )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "  SP exception match!\n"););
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next);
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT,"   SP mismatch!\n"););
    }

    return 0;
}





int CheckDstPortEqual(Packet *p, struct _RuleTreeNode *rtn_idx, 
        RuleFpList *fp_list)
{
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,"CheckDstPortEqual: "););

    if( (p->dp <= rtn_idx->hdp) && (p->dp >= rtn_idx->ldp) )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT, " DP match!\n"););
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next);
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT," DP mismatch!\n"););
    }
    return 0;
}




int CheckDstPortNotEq(Packet *p, struct _RuleTreeNode *rtn_idx, 
        RuleFpList *fp_list)
{
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "CheckDstPortNotEq: "););

    if( (p->dp > rtn_idx->hdp) || (p->dp < rtn_idx->ldp) )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT," DP exception match!\n"););
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next);
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT," DP mismatch!\n"););
    }

    return 0;
}



int RuleListEnd(Packet *p, struct _RuleTreeNode *rtn_idx, RuleFpList *fp_list)
{
    return 1;
}


int OptListEnd(Packet *p, struct _OptTreeNode *otn_idx, OptFpList *fp_list)
{
    return 1;
}


void CreateDefaultRules()
{
    CreateRuleType("activation", RULE_ACTIVATE, 1, &Activation);
    CreateRuleType("dynamic", RULE_DYNAMIC, 1, &Dynamic);
    CreateRuleType("pass", RULE_PASS, 0, &Pass); /* changed on Jan 06 */
    CreateRuleType("drop", RULE_DROP, 1, &Drop);
#ifdef GIDS
    CreateRuleType("sdrop", RULE_SDROP, 0, &SDrop);
    CreateRuleType("reject", RULE_REJECT, 1, &Reject);
#endif /* GIDS */
    CreateRuleType("alert", RULE_ALERT, 1, &Alert);
    CreateRuleType("log", RULE_LOG, 1, &Log);
}

void printRuleOrder()
{
    printRuleListOrder(RuleLists);
}

/****************************************************************************
 *
 * Function: CreateRuleType
 *
 * Purpose: Creates a new type of rule and adds it to the end of the rule list
 *
 * Arguments: name = name of this rule type
 *                       mode = the mode for this rule type
 *                   rval = return value for this rule type (for detect events)
 *                       head = list head to use (or NULL to create a new one)
 *
 * Returns: the ListHead for the rule type
 *
 ***************************************************************************/
ListHead *CreateRuleType(char *name, int mode, int rval, ListHead *head)
{
    RuleListNode *node;
    int evalIndex = 0;

    /* Using calloc() instead of malloc() because code isn't initializing
     * all of the structure fields before returning.  This is a non-
     * time-critical function, and is only called a half dozen times
     * on startup.
     */

    /*
     * if this is the first rule list node, then we need to create a new
     * list. we do not allow multiple rules with the same name.
     */
    if(!RuleLists)
    {
        RuleLists = (RuleListNode *)SnortAlloc(sizeof(RuleListNode));
        node = RuleLists;
    }
    else
    {
        node = RuleLists;

        while(1)
        {
            evalIndex++;
            if(!strcmp(node->name, name))
                return NULL;
            if(!node->next)
                break;
            node = node->next;
        }

        node->next = (RuleListNode *)SnortAlloc(sizeof(RuleListNode));
        node = node->next;
    }

    if(!head)
    {
        node->RuleList = (ListHead *)SnortAlloc(sizeof(ListHead));
        node->RuleList->IpList = NULL;
        node->RuleList->TcpList = NULL;
        node->RuleList->UdpList = NULL;
        node->RuleList->IcmpList = NULL;
        node->RuleList->LogList = NULL;
        node->RuleList->AlertList = NULL;
    }
    else
    {
        node->RuleList = head;
    }

    node->RuleList->ruleListNode = node;
    node->mode = mode;
    node->rval = rval;
    node->name = strdup(name);
    node->evalIndex = evalIndex;
    node->next = NULL;
    
    pv.num_rule_types++;
    
    return node->RuleList;
}



/****************************************************************************
 *
 * Function: OrderRuleLists
 *
 * Purpose: Orders the rule lists into the specefied order.
 *
 * Returns: void function
 *
 ***************************************************************************/
void OrderRuleLists(char *order)
{
    int i;
    int evalIndex = 0;
    RuleListNode *ordered_list = NULL;
    RuleListNode *prev;
    RuleListNode *node;
    static int called = 0;
    char **toks;
    int num_toks;

    if( called > 0 )
        LogMessage("Warning: multiple rule order directives.\n");

    toks = mSplit(order, " ", 10, &num_toks, 0);

    for( i = 0; i < num_toks; i++ )
    {
        prev = NULL;
        node = RuleLists;

        while( 1 )
        {
            if( node == NULL )
            {
                FatalError("ruletype %s does not exist or "
                           "has already been ordered.\n", toks[i]);
                break;
            }
            if( !strcmp(toks[i], node->name) )
            {
                if( prev == NULL )
                    RuleLists = node->next;
                else
                    prev->next = node->next;
                /* Add node to ordered list */
                ordered_list = addNodeToOrderedList(ordered_list, node, 
                        evalIndex++);
                break;
            }
            else
            {
                prev = node;
                node = node->next;
            }
        }
    }
    mSplitFree(&toks, num_toks);

    /* anything left in the rule lists needs to be moved to the ordered lists */
    while( RuleLists != NULL )
    {
        node = RuleLists;
        RuleLists = node->next;
        /* Add node to ordered list */
        ordered_list = addNodeToOrderedList(ordered_list, node, evalIndex++);
    }

    /* set the rulelists to the ordered list */
    RuleLists = ordered_list;
    called = 1;
}

static RuleListNode *addNodeToOrderedList(RuleListNode *ordered_list, 
        RuleListNode *node, int evalIndex)
{
    RuleListNode *prev;

    prev = ordered_list;
    
    /* set the eval order for this rule set */
    node->evalIndex = evalIndex;
    
    if(!prev)
    {
        ordered_list = node;
    }
    else
    {
        while(prev->next)
            prev = prev->next;
        prev->next = node;
    }

    node->next = NULL;

    return ordered_list;
}


void printRuleListOrder(RuleListNode * node)
{
    char buf[STD_BUF+1];

    SnortSnprintf(buf, STD_BUF, "%s", "Rule application order: ");

    while( node != NULL )
    {
        SnortSnprintfAppend(buf, STD_BUF, "->%s", node->name);
        node = node->next;
    }

    LogMessage("%s\n", buf);
}

/* Rule Match Action Functions */
int PassAction()
{
    pc.pass_pkts++;

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,"   => Pass rule, returning...\n"););
    return 1;
}



int ActivateAction(Packet * p, OptTreeNode * otn, Event *event)
{
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
                   "        <!!> Activating and generating alert! \"%s\"\n",
                   otn->sigInfo.message););
    CallAlertFuncs(p, otn->sigInfo.message, otn->rtn->listhead, event);

    if (otn->OTN_activation_ptr == NULL)
    {
        LogMessage("WARNING: an activation rule with no "
                "dynamic rules matched!\n");
        return 0;
    }

    otn->OTN_activation_ptr->active_flag = 1;
    otn->OTN_activation_ptr->countdown = 
        otn->OTN_activation_ptr->activation_counter;

    otn->RTN_activation_ptr->active_flag = 1;
    otn->RTN_activation_ptr->countdown += 
        otn->OTN_activation_ptr->activation_counter;

    active_dynamic_nodes++;
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,"   => Finishing activation packet!\n"););
    
    CallLogFuncs(p, otn->sigInfo.message, otn->rtn->listhead, event);
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, 
                "   => Activation packet finished, returning!\n"););

    return 1;
}

int AlertAction(Packet * p, OptTreeNode * otn, Event *event)
{
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
                "        <!!> Generating alert! \"%s\"\n", otn->sigInfo.message););

    /* Call OptTreeNode specific output functions */
    if(otn->outputFuncs)
        CallSigOutputFuncs(p, otn, event);
    
    CallAlertFuncs(p, otn->sigInfo.message, otn->rtn->listhead, event);

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "   => Finishing alert packet!\n"););

    CallLogFuncs(p, otn->sigInfo.message, otn->rtn->listhead, event);

    /*
    if(p->ssnptr != NULL && stream_api)
    {
        if(stream_api->alert_flush_stream(p) == 0)
        {
            CallLogFuncs(p, otn->sigInfo.message, otn->rtn->listhead, event);
        }
    }
    else
    {
        CallLogFuncs(p, otn->sigInfo.message, otn->rtn->listhead, event);
    }
    */

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,"   => Alert packet finished, returning!\n"););

    return 1;
}

int DropAction(Packet * p, OptTreeNode * otn, Event *event)
{
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
               "        <!!> Generating Alert and dropping! \"%s\"\n",
               otn->sigInfo.message););
    
    if(stream_api && !stream_api->alert_inline_midstream_drops())
    {
        if(stream_api->get_session_flags(p->ssnptr) & SSNFLAG_MIDSTREAM) 
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
                " <!!> Alert Came From Midstream Session Silently Drop! "
                "\"%s\"\n", otn->sigInfo.message);); 

            InlineDrop(p);
            return 1;
        }
    }

    /*
    **  Set packet flag so output plugins will know we dropped the
    **  packet we just logged.
    */
    InlineDrop(p);

    CallAlertFuncs(p, otn->sigInfo.message, otn->rtn->listhead, event);

    CallLogFuncs(p, otn->sigInfo.message, otn->rtn->listhead, event);

    return 1;
}

#ifdef GIDS
int SDropAction(Packet * p, OptTreeNode * otn, Event *event)
{
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
               "        <!!> Dropping without Alerting! \"%s\"\n",
               otn->sigInfo.message););

    // Let's silently drop the packet
    InlineDrop(p);
    return 1;
}

int RejectAction(Packet * p, OptTreeNode * otn, Event *event)
{
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
               "        <!!>Ignoring! \"%s\"\n",
               otn->sigInfo.message););

    // Let's log/alert, drop the packet, and mark it for reset.
    CallAlertFuncs(p, otn->sigInfo.message, otn->rtn->listhead, event);

    CallLogFuncs(p, otn->sigInfo.message, otn->rtn->listhead, event);

    /*
    if(p->ssnptr != NULL)
    {
        if(stream_api && stream_api->alert_flush_stream(p) == 0)
        {
            CallLogFuncs(p, otn->sigInfo.message, otn->rtn->listhead, event);
        }
    }
    else
    {
        CallLogFuncs(p, otn->sigInfo.message, otn->rtn->listhead, event);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
               "   => Alert packet finished, returning!\n"););
    */

    InlineReject(p);

    return 1;
}
#endif /* GIDS */


int DynamicAction(Packet * p, OptTreeNode * otn, Event *event)
{
    RuleTreeNode *rtn = otn->rtn;

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "   => Logging packet data and"
                            " adjusting dynamic counts (%d/%d)...\n",
                            rtn->countdown, otn->countdown););

    CallLogFuncs(p, otn->sigInfo.message, otn->rtn->listhead, event);

    otn->countdown--;

    if( otn->countdown <= 0 )
    {
        otn->active_flag = 0;
        active_dynamic_nodes--;
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "   <!!> Shutting down dynamic OTN node\n"););
    }
    
    rtn->countdown--;

    if( rtn->countdown <= 0 )
    {
        rtn->active_flag = 0;
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "   <!!> Shutting down dynamic RTN node\n"););
    }

    return 1;
}

int LogAction(Packet * p, OptTreeNode * otn, Event *event)
{

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,"   => Logging packet data and returning...\n"););

    CallLogFuncs(p, otn->sigInfo.message, otn->rtn->listhead, event);

#ifdef BENCHMARK
    printf("        <!!> Check count = %d\n", check_count);
    check_count = 0;
    printf(" **** cmpcount: %d **** \n", cmpcount);
#endif

    return 1;
}

void ObfuscatePacket(Packet *p)
{
    /* only obfuscate once */
    if(p->packet_flags & PKT_OBFUSCATED)
        return;
    
    /* we only obfuscate IP packets */
    if(!p->iph)
        return;
    
    if(pv.obfuscation_net == 0)
    {
        p->iph->ip_src.s_addr = 0x00000000;
        p->iph->ip_dst.s_addr = 0x00000000;
    }
    else
    {
        if(pv.homenet != 0)
        {
            if((p->iph->ip_src.s_addr & pv.netmask) == pv.homenet)
            {
                p->iph->ip_src.s_addr = pv.obfuscation_net |
                    (p->iph->ip_src.s_addr & pv.obfuscation_mask);
            }
            if((p->iph->ip_dst.s_addr & pv.netmask) == pv.homenet)
            {
                p->iph->ip_dst.s_addr = pv.obfuscation_net |
                    (p->iph->ip_dst.s_addr & pv.obfuscation_mask);
            }
        }
        else
        {
            p->iph->ip_src.s_addr = pv.obfuscation_net |
                (p->iph->ip_src.s_addr & pv.obfuscation_mask);
            p->iph->ip_dst.s_addr = pv.obfuscation_net |
                (p->iph->ip_dst.s_addr & pv.obfuscation_mask);
        }
    }
    p->packet_flags |= PKT_OBFUSCATED;
}

/* end of rule action functions */

