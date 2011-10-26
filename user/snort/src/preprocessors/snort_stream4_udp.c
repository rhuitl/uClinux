/* $Id$ */

/*
** Copyright (C) 2005 Sourcefire, Inc.
** AUTHOR: Steven Sturges <ssturges@sourcefire.com>
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

/* snort_stream4_udp.c
 * 
 * Purpose: UDP Support for Stream4.  Used only to establish packet direction
 *          and provide session data.
 *
 * Arguments:
 *   
 * Effect:
 *
 * Comments:
 *
 * Any comments?
 *
 */

#ifdef STREAM4_UDP

#define _STREAM4_INTERNAL_USAGE_ONLY_

#include "decode.h"
#include "debug.h"
#include "util.h"
#include "checksum.h"
#include "detect.h"
#include "plugbase.h"
#include "plugin_enum.h"
#include "rules.h"
#include "snort.h"

#include "sp_dynamic.h"

#include "perf.h"

extern OptTreeNode *otn_tmp;

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

#include "stream.h"
#include "snort_stream4_session.h"
#include "stream_api.h"
#include "stream_ignore.h"

extern Stream4Data s4data;

#ifdef PERF_PROFILING
extern PreprocStats stream4PerfStats;
PreprocStats stream4UdpPerfStats;
PreprocStats stream4UdpPrunePerfStats;
#endif


/** 
 * See if we can get ignore this as a UDP packet
 *
 * The Emergency Status stuff is taken care of here.
 * 
 * @param p Packet
 * 
 * @return 1 if this packet isn't destined to be processeed, 0 otherwise
 */
static INLINE int NotForStream4Udp(Packet *p)
{
    if(!p)
    {
        return 1;
    }

    if (!s4data.enable_udp_sessions)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Not tracking UDP Sessions\n"););
        return 1;
    }

    if(p->udph == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "p->udph is null, returning\n"););
        return 1;
    }
    
    /* don't accept packets w/ bad checksums */
    if(p->csum_flags & CSE_IP || p->csum_flags & CSE_UDP)
    {
        DEBUG_WRAP(
                   u_int8_t c1 = (p->csum_flags & CSE_IP);
                   u_int8_t c2 = (p->csum_flags & CSE_UDP);
                   DebugMessage(DEBUG_STREAM, "IP CHKSUM: %d, CSE_UDP: %d",
                                c1,c2);
                   DebugMessage(DEBUG_STREAM, "Bad checksum returning\n");
                   );
        
        p->packet_flags |= PKT_STREAM_UNEST_UNI;
        return 1;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Packet is for stream4...\n"););
    return 0;
}

static INLINE int GetDirectionUdp(Session *ssn, Packet *p)
{
    if(p->iph->ip_src.s_addr == ssn->client.ip)
    {
        return FROM_CLIENT;
    }
        
    return FROM_SERVER;
}

static INLINE u_int8_t GetUdpAction(Packet *p)
{
    u_int8_t ret = s4data.udp_ports[p->sp] | s4data.udp_ports[p->dp];

    return ret;
}

/**
 * Prune The state machine if we need to
 *
 * Also updates all variables related to pruning that only have to
 * happen at initialization
 *
 * For want of packet time at plugin initialization. (It only happens once.)
 * It wood be nice to get the first packet and do a little extra before
 * getting into the main snort processing loop.
 *   -- cpw
 * 
 * @param p Packet ptr
 */
static INLINE void UDPPruneCheck(Packet *p)
{
    PROFILE_VARS;

    if (!s4data.last_udp_prune_time)
    {
        s4data.last_udp_prune_time = p->pkth->ts.tv_sec;
        return;
    }

    if( (u_int)(p->pkth->ts.tv_sec) > s4data.last_udp_prune_time + s4data.timeout)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Prune time quanta exceeded, pruning "
                    "udp cache\n"););

        PREPROC_PROFILE_START(stream4UdpPrunePerfStats);
        PruneSessionCache(IPPROTO_UDP, p->pkth->ts.tv_sec, 0, NULL);
        PREPROC_PROFILE_END(stream4UdpPrunePerfStats);
        s4data.last_udp_prune_time = p->pkth->ts.tv_sec;

        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Pruned for timeouts, %lu udp sessions "
                    "active\n", 
                    (unsigned long int) GetSessionCount(p)););
    }
}

void Stream4ProcessUdp(Packet *p)
{
    Session *ssn = NULL;
    int direction;
    char ignore;
    u_int8_t action;

    if (NotForStream4Udp(p))
    {
        return;
    }

    DEBUG_WRAP(
            DebugMessage((DEBUG_STREAM|DEBUG_STREAM_STATE), 
                "Got UDP Packet 0x%X:%d ->  0x%X:%d\n", 
                p->iph->ip_src.s_addr,
                p->sp,
                p->iph->ip_dst.s_addr,
                p->dp);
            );

    action = GetUdpAction(p);

    if (!action)
    {
        if (s4data.udp_ignore_any)
        {
            /* Ignore this UDP packet entirely */
            DisableDetect(p);
            SetPreprocBit(p, PP_SFPORTSCAN);
            SetPreprocBit(p, PP_PERFMONITOR);
            otn_tmp = NULL;
            DEBUG_WRAP(
                DebugMessage((DEBUG_STREAM|DEBUG_STREAM_STATE),
                    "Not inspecting UDP Packet because of ignore any\n"););
        }
        return;
    }

    if (action & UDP_SESSION)
    {
        ssn = GetSession(p);

        if (!ssn)
        {
            ssn = GetNewSession(p);

            if (ssn)
            {
                AddUDPSession(&sfPerf.sfBase);
                ssn->flush_point = 0;
                ssn->client.ip = p->iph->ip_src.s_addr;
                ssn->server.ip = p->iph->ip_dst.s_addr;
                ssn->client.port = p->sp;
                ssn->server.port = p->dp;

                /* New session, Sender is the first one we see. */

                /* UDP Sessions are AWLAYS considered 'midstream'
                 * since there is no real way to know if this is
                 * the first packet or the 100th.
                 */
                ssn->session_flags = SSNFLAG_SEEN_SENDER | SSNFLAG_MIDSTREAM;
                ssn->start_time = p->pkth->ts.tv_sec;
            }
            else
            {
                DEBUG_WRAP(DebugMessage((DEBUG_STREAM|DEBUG_STREAM_STATE),
                                        "Couldn't get a new udp session\n"););
                return;
            }
        }
        else
        {
            if (ssn->client.ip == p->iph->ip_src.s_addr)
            {
                ssn->client.pkts_sent++;
                ssn->client.bytes_sent += p->dsize;
            }
            else
            {
                ssn->session_flags |= SSNFLAG_SEEN_RESPONDER;
                ssn->server.pkts_sent++;
                ssn->server.bytes_sent += p->dsize;
            }
        }

        p->ssnptr = ssn;

        /* update the time for this session */
        ssn->last_session_time = p->pkth->ts.tv_sec;

        /* Check if stream is to be ignored per session flags */
        if ( ssn->ignore_flag )
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                    "Nothing to do -- stream is set to be ignored.\n"););

            stream_api->stop_inspection(NULL, p, SSN_DIR_BOTH, -1, 0);

#ifdef DEBUG
            {
                /* Have to allocate & copy one of these since inet_ntoa
                 * clobbers the info from the previous call. */
                struct in_addr tmpAddr;
                char srcAddr[17];
                tmpAddr.s_addr = p->iph->ip_src.s_addr;
                SnortStrncpy(srcAddr, (char *)inet_ntoa(tmpAddr), sizeof(srcAddr));
                tmpAddr.s_addr = p->iph->ip_dst.s_addr;

                DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                       "Ignoring channel %s:%d --> %s:%d\n",
                       srcAddr, p->sp,
                       inet_ntoa(tmpAddr), p->dp););
            }
#endif
            return;
        }

        /* Check if this packet is one of the "to be ignored" channels.
         * If so, set flag, flush any data that may be buffered up on
         * the connection, and bail. */
        ignore = CheckIgnoreChannel(p);
        if (ignore)
        {
            stream_api->stop_inspection(ssn, p, ignore, -1, 0);

            return;
        }

        /* update the packet flags */
        if((direction = GetDirectionUdp(ssn, p)) == FROM_SERVER)
        {
            p->packet_flags |= PKT_FROM_SERVER;
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  "UDP Listener packet\n"););

        }
        else
        {
            p->packet_flags |= PKT_FROM_CLIENT;
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  "UDP Sender packet\n"););
        }

        /* Mark session as established if packet from server
         * (and not already established)
         */
        if (!(ssn->session_flags & SSNFLAG_ESTABLISHED) &&
            (p->packet_flags & PKT_FROM_SERVER))
        {
            ssn->session_flags |= SSNFLAG_SEEN_RESPONDER;
            ssn->session_flags |= SSNFLAG_ESTABLISHED;
        }

        /* Update packet flags for session 'UDP state' info */
        if (ssn->session_flags & SSNFLAG_ESTABLISHED)
        {
            p->packet_flags |= PKT_STREAM_EST;
        }
        else
        {
            p->packet_flags |= PKT_STREAM_UNEST_BI;
        }
    }

    /* see if we need to prune the session cache */
    UDPPruneCheck(p);

    return;
}

void Stream4UdpConfigure()
{
    int16_t sport, dport;
    RuleListNode *rule;
    RuleTreeNode *rtn;
    OptTreeNode *otn;
    extern RuleListNode *RuleLists;
    char buf[STD_BUF+1];
    int i, j=0;
    char inspectSrc, inspectDst;

#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("s4UDP", &stream4UdpPerfStats, 1, &stream4PerfStats);
    RegisterPreprocessorProfile("s4UDPPrune", &stream4UdpPrunePerfStats, 1, &stream4PerfStats);
#endif

    /* Post-process UDP rules to establish UDP ports to inspect. */
    for (rule=RuleLists; rule; rule=rule->next)
    {
        if(!rule->RuleList)
            continue;

        /*
        **  Get UDP rules
        */
        if(rule->RuleList->UdpList)
        {
            for(rtn = rule->RuleList->UdpList; rtn != NULL; rtn = rtn->right)
            {
                inspectSrc = inspectDst = 0;

                sport = (rtn->hsp == rtn->lsp) ? rtn->hsp : -1;

                if (rtn->flags & ANY_SRC_PORT)
                {
                    sport = -1;
                }

                if (sport > 0 &&  rtn->not_sp_flag > 0 )
                {
                    sport = -1;
                }

                /* Set the source port to inspect */
                if (sport != -1)
                {
                    inspectSrc = 1;
                    s4data.udp_ports[sport] |= UDP_INSPECT;
                }

                dport = (rtn->hdp == rtn->ldp) ? rtn->hdp : -1;

                if (rtn->flags & ANY_DST_PORT)
                {
                    dport = -1;
                }

                if (dport > 0 && rtn->not_dp_flag > 0 )
                {
                    dport = -1;
                }

                /* Set the dest port to inspect */
                if (dport != -1)
                {
                    inspectDst = 1;
                    s4data.udp_ports[dport] |= UDP_INSPECT;
                }

                if (inspectSrc || inspectDst)
                {
                    /* Look for an OTN with flow keyword */
                    for (otn = rtn->down; otn; otn = otn->next)
                    {
                        if (otn->ds_list[PLUGIN_CLIENTSERVER] ||
                            otn->ds_list[PLUGIN_FLOWBIT])
                        {
                            if (inspectSrc)
                            {
                                s4data.udp_ports[sport] |= UDP_SESSION;
                            }
                            if (inspectDst)
                            {
                                s4data.udp_ports[dport] |= UDP_SESSION;
                            }
                        }
#ifdef DYNAMIC_PLUGIN
                        else if (DynamicHasFlow(otn) ||
                                 DynamicHasFlowbit(otn))
                        {
                            if (inspectSrc)
                            {
                                s4data.udp_ports[sport] |= UDP_SESSION;
                            }
                            if (inspectDst)
                            {
                                s4data.udp_ports[dport] |= UDP_SESSION;
                            }
                        }
#endif
                    }
                }
            }
        }
    }

    memset(buf, 0, STD_BUF+1);
    snprintf(buf, STD_BUF, "    Stream4 UDP Ports: ");       

    for(i=0;i<65536;i++)
    {
        if(s4data.udp_ports[i])
        {
            switch (s4data.udp_ports[i])
            {
            case UDP_INSPECT:
                sfsnprintfappend(buf, STD_BUF, "%d(%s) ", i, "I");
                break;
            case UDP_SESSION:
                /* Shouldn't have only a "session" */
                s4data.udp_ports[i] |= UDP_INSPECT;
                /* Fall through */
            case UDP_INSPECT|UDP_SESSION:
                sfsnprintfappend(buf, STD_BUF, "%d(%s) ", i, "SI");
                break;
            }
            j++;
        }

        if(j > 20)
        { 
            LogMessage("%s...\n", buf);
            return;
        }
    }
    LogMessage("%s\n", buf);
}
#endif /* STREAM4_UDP */

