/**
 * Copyright (C) 2003 Sourcefire, Inc.
 *
 * @file   spp_flow.c
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Thu May 29 11:27:17 2003
 * 
 * @brief  flow integration with snort
 *
 * The purpose of this module is to have an abstract way of detecting
 * significant events to various modules so that everything higher
 * layers see as a session can be tracked in a single spot.
 *
 * This module completely replaces spp_conversation.
 */
 
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <time.h>

#include "snort.h"
#include "decode.h" /* Packet */
#include "debug.h" /* DEBUG_WRAP */
#include "plugbase.h" /* RegisterPreprocesor */
#include "util.h" /* FatalError */
#include "parser.h" /* file_name, file_line */

#include "spp_flow.h"
#include "flow/flow.h"
#include "flow/flow_cache.h"
#include "flow/flow_callback.h"
#include "flow/flow_class.h"
#include "flow/flow_print.h"
#include "flow/portscan/flowps_snort.h"

#include "profiler.h"

#define DEFAULT_MEMCAP (1024 * 1024 * 10)
#define DEFAULT_ROWS   (1024 * 4)
#define DEFAULT_STAT_INTERVAL 0

typedef struct _SPPFLOW_CONFIG
{
    int stats_interval;
    int memcap;
    int rows;
    FLOWHASHID hashid;
} SPPFLOW_CONFIG;

static int s_flow_running = 0;  /**< is flow turned on? */
static FLOWCACHE s_fcache;
static SPPFLOW_CONFIG s_config;

static int FlowParseArgs(SPPFLOW_CONFIG *config, char *args);
static INLINE int FlowPacket(Packet *p);
static void FlowPreprocessor(Packet *p, void *);
static void FlowInit(u_char *args);
static void FlowCleanExit(int signal, void *data);
static void FlowRestart(int signal, void *data);
static void FlowParseOption(SPPFLOW_CONFIG *config,
                            char *fname, int lineno,
                            char *key, char *value);
static void DisplayFlowConfig(void);

static int s_debug = 0;
unsigned int giFlowbitSize = 64;

#ifdef PERF_PROFILING
PreprocStats flowPerfStats;
#endif

/** 
 * Add the Flow Preprocessor to the list of things that snort can
 * configure.
 * 
 */
void SetupFlow(void)
{
    /* we should really create some set of structure's that we can go
     * register as config editors */
    
    RegisterPreprocessor("flow", FlowInit);

    /* setup the portscan preprocessor */
    SetupFlowPS();    
}
/** 
 * Condense all the checks into one places
 *
 * Must be IP
 * Must not be a fragment
 * Must not be a rebuild stream
 * 
 * @param p packet to inspect
 * 
 * @return 1 if this packet is for flow module, 0 otherwise
 */
static INLINE int FlowPacket(Packet *p)
{
    if(!p->iph)
        return 0;

    if(p->frag_flag)
        return 0;

    /*
    if(p->packet_flags & PKT_REBUILT_STREAM)
        return 0;
    */

    return 1;
}

/** 
 * Initialize the configuration of the flow preprocessor
 * 
 * @param args command line arguments from snort.conf
 */
static void FlowInit(u_char *args)
{
    static int init_once = 0;
    int ret;
    static SPPFLOW_CONFIG *config = &s_config;
    
    if(init_once)
        FatalError("%s(%d) Unable to reinitialize flow!\n", file_name, file_line);
    else
        init_once = 1;

    /* setup the defaults */
    config->stats_interval = DEFAULT_STAT_INTERVAL;
    config->memcap = DEFAULT_MEMCAP;
    config->rows   = DEFAULT_ROWS;
    config->hashid = HASH2; /* use the quickest hash by default */
    FlowParseArgs(config, args);

    if((ret = flowcache_init(&s_fcache, config->rows, config->memcap, 
                             giFlowbitSize, config->hashid)) != FLOW_SUCCESS)
    {
        FatalError("Unable to initialize the flow cache!"
                   "-- try more memory (current memcap is %d)\n", config->memcap);
    }

    DisplayFlowConfig();

    s_flow_running = 1;
    
    AddFuncToPreprocList(FlowPreprocessor, PRIORITY_NETWORK, PP_FLOW);
    AddFuncToPreprocCleanExitList(FlowCleanExit, NULL, PRIORITY_LAST, PP_FLOW);
    AddFuncToPreprocRestartList(FlowRestart, NULL, PRIORITY_LAST, PP_FLOW);

#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("flow", &flowPerfStats, 0, &totalPerfStats);
#endif
}

static void FlowRestart(int signal, void *data)
{
    return;
}

static void FlowCleanExit(int signal, void *data)
{
    fflush(stdout);
    LogMessage("Final Flow Statistics\n");
    if(!pv.quiet_flag)
        flowcache_stats(stdout, &s_fcache);
    fflush(stdout);
    flowcache_destroy(&s_fcache);
    return;
}

/** 
 * The runtime entry point for the flow module from snort
 *
 * 1) Assign each packet a flow
 * 2) Perform various callbacks based on the parameters for the flow
 * 
 * @param p packet to process
 */
static void FlowPreprocessor(Packet *p, void *context)
{
    int flow_class; /**< addressing scheme to use */
    int direction; /**< which way does the flow go */
    static time_t last_output = 0;
    FLOWKEY search_key;
    FLOW *fp;
    FLOWCACHE *fcache = &s_fcache;
    FLOWPACKET *pkt = (FLOWPACKET *) p;
    PROFILE_VARS;
        
    if(!FlowPacket(p))
    {
        return;
    }

    PREPROC_PROFILE_START(flowPerfStats);
    
    /* first find the addressing schema */
    if(flow_classifier(pkt, &flow_class) != FLOW_SUCCESS)
    {
        //LogMessage("Error classifying packet\n");
        return;
    }

    switch(flow_class)
    {
    case FLOW_IPV4:
        if(flowkey_make(&search_key, pkt) != FLOW_SUCCESS)
        {
            ErrorMessage("Unable to make a search key\n");
            PREPROC_PROFILE_END(flowPerfStats);
            return;
        }
        break;
    default:
        ErrorMessage("Unknown Flow Type: %d\n", flow_class);
        PREPROC_PROFILE_END(flowPerfStats);
        return;
    }

    /** this should return a direction too for the key */
    //printf("flowkey: "); flowkey_fprint(stdout, &search_key); printf("\n");
    
    if(flowcache_find(fcache, &search_key, &fp, &direction) == FLOW_SUCCESS)
    {
        /*
        **  We set flows for rebuilt pkts if there is one, otherwise
        **  we just bail.
        */
        if(p->packet_flags & PKT_REBUILT_STREAM)
        {
            p->flow = fp;
            PREPROC_PROFILE_END(flowPerfStats);
            return;
        }

        if(direction == FROM_RESPONDER && fp->stats.packets_recv == 0)
        {
            /* this is the first packet back from the guy */           
            flow_callbacks(FLOW_FIRST_BIDIRECTIONAL, fp, direction, p);
        }

        flow_callbacks(FLOW_ADDITIONAL, fp, direction, pkt);
    }
    else
    {
        /*
        **  If there's no flow for a rebuilt stream, then we don't
        **  care because something is screwed up.
        */
        if(p->packet_flags & PKT_REBUILT_STREAM)
        {
            PREPROC_PROFILE_END(flowPerfStats);
            return;
        }

        if(flowcache_newflow(fcache, &search_key, &fp) != FLOW_SUCCESS)
        {
            flow_printf("***ERROR: "); flowkey_print(&search_key); flow_printf("\n");
        }

        direction = FROM_INITIATOR;

        flow_callbacks(FLOW_NEW, fp, FROM_INITIATOR, pkt);
    }

    fp->stats.direction = direction;

    /* printout some verbose statistics */
    if(s_config.stats_interval  &&
       ((last_output + s_config.stats_interval) <= p->pkth->ts.tv_sec))
    {
        last_output =  p->pkth->ts.tv_sec;

        if(!pv.quiet_flag)
            flowcache_stats(stdout, fcache);
    }

    p->flow = fp;

    PREPROC_PROFILE_END(flowPerfStats);
}

/** 
 * See if the flow needs to be shutdown and remove it from the
 * cache. This function should be placed AFTER all detection type
 * components.
 * 
 * @param p packet
 * 
 * @return 0 on success
 */
int CheckFlowShutdown(Packet *p)
{
    FLOWCACHE *fcache = &s_fcache;
    FLOW *flowp = (FLOW *) p->flow;
    PROFILE_VARS;
   
    /* Use REENTER_START to not add to 'checks' */
    PREPROC_PROFILE_REENTER_START(flowPerfStats);
    if(flowp != NULL)
    {
        if(flow_checkflag(flowp, FLOW_CLOSEME))
        {
            /* allow all the submodules to trigger their final stand */            
            flow_callbacks(FLOW_SHUTDOWN, flowp, FROM_INITIATOR, p);
            
            if(flowcache_releaseflow(fcache, &flowp) != FLOW_SUCCESS)
            {
                flow_printf("Can't release flow %p\n", p->flow);
                PREPROC_PROFILE_REENTER_END(flowPerfStats);
                return FLOW_BADJUJU;
            }
        }
    }

    p->flow = NULL;

    PREPROC_PROFILE_REENTER_END(flowPerfStats);
    return FLOW_SUCCESS;
}


static int FlowParseArgs(SPPFLOW_CONFIG *config, char *args)
{
    char *key, *value;
    char *myargs = NULL;
    const char *delim = " \t";
    
    if(args)
    {
        if(s_debug > 5)
            flow_printf("I'm parsing %s!\n", args);
        
        myargs = strdup(args);

        if(myargs == NULL)
            FatalError("Out of memory parsing flow arguments\n");
    }
    else
    {
        if(s_debug > 5)
            flow_printf("nothing to parse for this flow!\n");
        
        return 0;
    }

    key = strtok(myargs, delim);

    while(key != NULL)
    {
        value = strtok(NULL, delim);

        if(!value)
        {
            FatalError("%s(%d) key %s has no value\n", file_name, file_line, key); 
        }

        FlowParseOption(config, file_name, file_line, key, value);                
        key = strtok(NULL, delim);
    }

    if(myargs)
        free(myargs);
    
    return 0;
}

static void FlowParseOption(SPPFLOW_CONFIG *config,
                            char *fname, int lineno,
                            char *key, char *value)
{
    if(!strcasecmp(key, "memcap"))
    {
        config->memcap = atoi(value);        
    }
    else if(!strcasecmp(key, "rows"))
    {
        config->rows = atoi(value);        
    }   
    else if(!strcasecmp(key, "stats_interval"))
    {
        config->stats_interval = atoi(value);
    }
    else if(!strcasecmp(key, "hash"))
    {
        switch(atoi(value))
        {
        case 1:
            config->hashid = HASH1;
            break;
        case 2:
            config->hashid = HASH2;
            break;
        default:
            FatalError("%s(%d)  Unknown Hash Type: key(%s) value(%s)\n",
                       fname, lineno, key, value);
        }
    }

    else
    {
        FatalError("%s(%d)  Unknown Arguments: key(%s) value(%s)\n",
                   fname, lineno, key, value);
    }
    
}

/** 
 * Print out some of the common information about the Flow Processor
 * configuration
 * 
 */
static void DisplayFlowConfig(void)
{
    SPPFLOW_CONFIG *cp = &s_config;
    FLOWCACHE *fcp = &s_fcache;
    
    LogMessage(",-----------[Flow Config]----------------------\n");
    LogMessage("| Stats Interval:  %d\n", cp->stats_interval);
    LogMessage("| Hash Method:     %d\n", cp->hashid);
    LogMessage("| Memcap:          %d\n", cp->memcap);
    LogMessage("| Rows  :          %d\n", flowcache_row_count(fcp));
    LogMessage("| Overhead Bytes:  %d(%%%.2lf)\n",
               flowcache_overhead_bytes(fcp),
               calc_percent(flowcache_overhead_bytes(fcp),cp->memcap));
    LogMessage("`----------------------------------------------\n");

}

/** 
 * Return 1 if spp_flow has been configured
 * 
 * 
 * @return 1 if spp_flow is enabled
 */
int SppFlowIsRunning(void)
{
    return s_flow_running;
}
