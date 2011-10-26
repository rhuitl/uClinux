/**
 * @file   flowps_snort.c
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Fri Jun  6 14:49:30 2003
 * 
 * @brief  interface between snort & portscan
 * 
 * Implements the basic functionality required for snort+flow to
 * interact with a portscan procesor that accepts flow events from the
 * flow preprocessor.
 */


#include "debug.h"    /* DEBUG_WRAP */
#include "plugbase.h" /* RegisterPreprocesor */
#include "parser.h"   /* file_name, file_line */
#include "snort.h"

#include "scoreboard.h"
#include "server_stats.h"

#include "spp_flow.h" /* make sure that spp_flow is enabled */
#include "flowps.h"
#include "flowps_snort.h"

#include "packet_time.h"
#include "event_wrapper.h"
#include "generators.h"
#include "common_defs.h"
#include "util_str.h"
#include "util_net.h"
#include "snort_packet_header.h"

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* WIN32 */

#include <stdlib.h>
#include <ctype.h>

#define PSDEFAULT_SB_ROWS_ACTIVE        1000000
#define PSDEFAULT_SB_MEMCAP_ACTIVE      (ONE_MBYTE * 24)
#define PSDEFAULT_SB_ROWS_SCANNER       (PSDEFAULT_SB_ROWS_ACTIVE/4)
#define PSDEFAULT_SB_MEMCAP_SCANNER     (PSDEFAULT_SB_MEMCAP_ACTIVE/4)
#define PSDEFAULT_UT_ROWS               1000000
#define PSDEFAULT_UT_MEMCAP             (ONE_MBYTE * 24)
#define PSDEFAULT_SERVER_ROWS           (1 << 16) /* 65536 */
#define PSDEFAULT_SERVER_MEMCAP         (ONE_MBYTE * 2)
#define PSDEFAULT_SERVER_LEARNING_TIME  (ONE_HOUR * 8)
#define PSDEFAULT_SERVER_IGNORE_LIMIT   500
#define PSDEFAULT_SERVER_SCANNER_LIMIT  500
#define PSDEFAULT_BASE_SCORE            1
#define PSDEFAULT_ALERT_ONCE            1
#define PSDEFAULT_OUTPUT_MODE           VARIABLEMSG

/** 25% of the memory will be the scanner table */

#define PSDEFAULT_TCP_PENALTIES  1     /**< enable TCP penalities by default */

/* default limits for thresholds */
#define PSTALKER_FIXED_SIZE     30
#define PSTALKER_SLIDING_SIZE   30    /**< window frame */
#define PSTALKER_SLIDING_SCORE  30    /**< pt tally */
#define PSTALKER_FIXED_SCORE    15    /**< pt tally */
#define PSTALKER_WINDOW_SCALE   (0.5) /**< multiplier for wsize*/

#define PSSCANNER_FIXED_SIZE     15
#define PSSCANNER_SLIDING_SIZE   20    /**< window frame */
#define PSSCANNER_SLIDING_SCORE  40    /**< pt tally */
#define PSSCANNER_FIXED_SCORE    15    /**< pt tally */
#define PSSCANNER_WINDOW_SCALE   (0.5) /**< multiplier for wsize*/

#define FLOWPSMAXPKTSIZE        (IP_MAXPACKET - (IP_HEADER_LEN + ETHERNET_HEADER_LEN))

static PS_TRACKER s_tracker; /* snort's portscan stracker */
static int s_debug = 0;
static Packet *s_pkt = NULL;  /* pktkludge output mechanism */
     
void FlowPSRestart(int signal, void *data);
void FlowPSCleanExit(int signal, void *data);
static void FlowPSInit(u_char *args);
static void FlowPSParseArgs(PS_CONFIG *config , char *args);
static int flowps_generate_flow_event(SCORE_ENTRY *sep, FLOWPACKET *p, u_int32_t *address, FLOWPS_OUTPUT output_type, time_t cur);
static int flowps_init_pkt(void);
 /* pktkludge output system! */
static Packet *flowps_mkpacket(SCORE_ENTRY *sep, FLOWPACKET *orig_packet, u_int32_t *address, time_t cur);


void FlowPSSetDefaults(PS_CONFIG *config)
{
    flowps_mkconfig(config,
                    PSDEFAULT_SB_MEMCAP_ACTIVE,
                    PSDEFAULT_SB_ROWS_ACTIVE,
                    PSDEFAULT_SB_MEMCAP_SCANNER,
                    PSDEFAULT_SB_ROWS_SCANNER,
                    PSDEFAULT_UT_MEMCAP,
                    PSDEFAULT_UT_ROWS,
                    PSDEFAULT_SERVER_MEMCAP,
                    PSDEFAULT_SERVER_ROWS,
                    PSDEFAULT_SERVER_LEARNING_TIME,
                    PSDEFAULT_TCP_PENALTIES,
                    PSDEFAULT_SERVER_IGNORE_LIMIT,
                    PSDEFAULT_SERVER_SCANNER_LIMIT,
                    PSDEFAULT_BASE_SCORE,
                    PSDEFAULT_ALERT_ONCE,
                    PSDEFAULT_OUTPUT_MODE);

    
    flowps_mkthreshold(&config->limit_talker, /* threshold obj */
                       PSTALKER_FIXED_SIZE,  /* default fixed window */
                       PSTALKER_FIXED_SCORE, /* default fixed limit */
                       PSTALKER_SLIDING_SIZE, /* default sliding size */
                       PSTALKER_SLIDING_SCORE,
                       PSTALKER_WINDOW_SCALE); 

    flowps_mkthreshold(&config->limit_scanner, /* threshold obj */
                       PSSCANNER_FIXED_SIZE,  /* default fixed window */
                       PSSCANNER_FIXED_SCORE, /* default fixed limit */
                       PSSCANNER_SLIDING_SIZE, /* default sliding size */
                       PSSCANNER_SLIDING_SCORE,
                       PSSCANNER_WINDOW_SCALE);
}

void SetupFlowPS(void)
{
    RegisterPreprocessor("flow-portscan", FlowPSInit);
}

/** 
 * Display what the underlying tidbits think the config is
 * 
 * @param trackerp grab the configuration info from the portscan tracker
 */
static void FlowPSOutputConfig(PS_TRACKER *trackerp)
{
    if(pv.quiet_flag)
        return;

    flow_printf(",-----------[flow-portscan config]-------------\n");
    flow_printf("| TCP Penalties:  %s\n", trackerp->config.tcp_penalties ? "On": "Off");
    flow_printf("|    Ouput Mode:  %s\n",
                (trackerp->config.output_mode == VARIABLEMSG) ? "msg" : "pktkludge");
    flow_printf("|    Base Score:  %d\n", trackerp->config.base_score);
    
    flow_printf("+----------------------------------------------\n");
    flow_printf("| Scoreboard:  ACTIVE         PORTSCANNER\n");
    flow_printf("|     memcap:  %-8d         %-8d\n",
                scoreboard_memcap(&trackerp->table_active),
                scoreboard_memcap(&trackerp->table_scanner));
    flow_printf("|       rows:  %-8d         %-8d\n",
                scoreboard_row_count(&trackerp->table_active),
                scoreboard_row_count(&trackerp->table_scanner));
    flow_printf("|   overhead:  %-8d(%%%.02lf) %-8d(%%%.02lf)\n",
                scoreboard_overhead_bytes(&trackerp->table_active),
                calc_percent(scoreboard_overhead_bytes(&trackerp->table_active),
                             scoreboard_memcap(&trackerp->table_active)),
                scoreboard_overhead_bytes(&trackerp->table_scanner),
                calc_percent(scoreboard_overhead_bytes(&trackerp->table_scanner),
                             scoreboard_memcap(&trackerp->table_scanner)));

    flow_printf("|      fixed-size:    %-4ds        %-4ds\n",
                trackerp->config.limit_talker.fixed_size,
                trackerp->config.limit_scanner.fixed_size);
    flow_printf("|    sliding-size:    %-4ds        %-4ds\n",
                trackerp->config.limit_talker.sliding_size,
                trackerp->config.limit_scanner.sliding_size);
    flow_printf("| threshold-fixed:    %-4u         %-4u\n",
                trackerp->config.limit_talker.fixed,
                trackerp->config.limit_scanner.fixed);
    flow_printf("| threshold-sliding:  %-4u         %-4u\n",
                trackerp->config.limit_talker.sliding,
                trackerp->config.limit_scanner.sliding);
    flow_printf("|      window scale:  %-.2lf         %-.2lf\n",
                trackerp->config.limit_talker.window_scale,
                trackerp->config.limit_scanner.window_scale);
    
    
    flow_printf("+----------------------------------------------\n");
    flow_printf("|   Uniqueness:  memcap: %8d rows: %8d\n",
               ut_memcap(&trackerp->unique_tracker),
               ut_row_count(&trackerp->unique_tracker));
    flow_printf("|      overhead: %d (%%%.02lf)\n",               
                ut_overhead_bytes(&trackerp->unique_tracker),
                calc_percent(ut_overhead_bytes(&trackerp->unique_tracker),
                             ut_memcap(&trackerp->unique_tracker)));
    
    if(flowps_server_stats_enabled(trackerp) == FLOW_SUCCESS)
    {
        flow_printf("+----------------------------------------------\n");        
        flow_printf("| Server Stats:  memcap: %8d rows: %8d\n",
                    server_stats_memcap(&trackerp->server_stats),
                    server_stats_row_count(&trackerp->server_stats));
        flow_printf("|      overhead: %d (%%%.02lf)\n",               
                    server_stats_overhead_bytes(&trackerp->server_stats),
                    calc_percent(server_stats_overhead_bytes(&trackerp->server_stats),
                                 server_stats_memcap(&trackerp->server_stats)));
        flow_printf("|   learning time: %d\n",
                    trackerp->config.server_learning_time);
        flow_printf("|    ignore limit: %u\n",
                    trackerp->config.server_ignore_limit);
        flow_printf("|   scanner limit: %u\n",
                    trackerp->config.server_scanner_limit);
        
        
    }
    else
    {
        flow_printf("| Server Stats: Disabled\n");
    }

    flow_printf("`----------------------------------------------\n");
}
     


/** 
 * Initialize the configuration of the flow preprocessor
 * 
 * @param args command line arguments from snort.conf
 */
static void FlowPSInit(u_char *args)
{
    static int init_once = 0;    
    int ret;

    PS_TRACKER *pstp = &s_tracker;
    PS_CONFIG  tconfig;

    if(flowps_init_pkt())
    {
        flow_fatalerror("Error initializing flowps packet!\n");
    }
    
    if(!SppFlowIsRunning())
    {
        flow_fatalerror("%s(%d) flow-portscan requires spp_flow to be enabled!\n",
                        file_name, file_line);
    }
    
    if(init_once)
    {
        flow_fatalerror("%s(%d) Unable to reinitialize flow-portscan!\n",
                        file_name, file_line);
    }
    else
    {
        init_once = 1;
    }

    FlowPSSetDefaults(&tconfig);

    FlowPSParseArgs(&tconfig, args);

    
    if((ret = flowps_init(pstp, &tconfig)) != FLOW_SUCCESS)
    {
        flow_fatalerror("Unable to initialize the flow cache!"
                        "-- try more memory (current memcap is %d)\n",
                        tconfig.sb_memcap_total);
    }

    FlowPSOutputConfig(pstp);
    
    AddFuncToPreprocCleanExitList(FlowPSCleanExit, NULL, PRIORITY_LAST, PP_FLOW);
    AddFuncToPreprocRestartList(FlowPSRestart, NULL, PRIORITY_LAST, PP_FLOW);
}


static void FlowPSParseOption(PS_CONFIG *config,
                              char *fname, int lineno,
                              char *key, char *value)
{
    int ivalue;

    if(!key || !value)
    {
        flow_fatalerror("%s:(%d) Invalid command line arguments!\n");
    }

    if(s_debug > 1)
        flow_printf("key: %s value: %s\n", key, value);
    
    if(!strcasecmp(key, "scoreboard-memcap-talker"))
    {
        ivalue = atoi(value);
        config->sb_memcap_talker = ivalue;
    }
    else if(!strcasecmp(key, "scoreboard-memcap-scanner"))
    {
        ivalue = atoi(value);
        config->sb_memcap_scanner = ivalue;
    }
    else if(!strcasecmp(key,"unique-memcap"))
    {
        ivalue = atoi(value);
        config->ut_memcap = ivalue;
    }
    else if(!strcasecmp(key,"server-memcap"))
    {
        ivalue = atoi(value);
        config->server_memcap = ivalue;
    }
    else if(!strcasecmp(key, "scoreboard-rows-talker"))
    {
        ivalue = atoi(value);
        config->sb_rows_talker = ivalue;
    }
    else if(!strcasecmp(key, "scoreboard-rows-scanner"))
    {
        ivalue = atoi(value);
        config->sb_rows_scanner = ivalue;
    }
    else if(!strcasecmp(key,"unique-rows"))
    {
        ivalue = atoi(value);
        config->ut_rows = ivalue;
    }
    else if(!strcasecmp(key,"server-rows"))
    {
        ivalue = atoi(value);
        config->server_rows = ivalue;
    }
    else if(!strcasecmp(key, "server-watchnet"))
    {
        IPSET *ipset = ipset_new(IPV4_FAMILY);

        if(!ipset || ip4_setparse(ipset, value) !=0)
        {
            flow_fatalerror("%s(%d) Unable to create an IPSet from %s\n",
                            file_name,file_line,value);
        }

        config->server_watchnet_ipv4 = ipset;        
    }
    else if(!strcasecmp(key, "src-ignore-net"))
    {
        IPSET *ipset = ipset_new(IPV4_FAMILY);

        if(!ipset || ip4_setparse(ipset, value) !=0)
        {
            flow_fatalerror("%s(%d) Unable to create an IPSet from %s\n",
                            file_name,file_line,value);
        }

        config->src_ignore_ipv4 = ipset;        
    }
    else if(!strcasecmp(key, "dst-ignore-net"))
    {
        IPSET *ipset = ipset_new(IPV4_FAMILY);

        if(!ipset || ip4_setparse(ipset, value) !=0)
        {
            flow_fatalerror("%s(%d) Unable to create an IPSet from %s\n",
                       file_name,file_line,value);
        }

        config->dst_ignore_ipv4 = ipset;        
    }
    else if(!strcasecmp(key, "tcp-penalties"))
    {
        if(toggle_option(key, value, &config->tcp_penalties))
        {
            flow_fatalerror("%s(%d) Error processing %s directive (value = %s)\n",
                       file_name,file_line,key,value);
        }
    }
    else if(!strcasecmp(key, "server-learning-time"))
    {
        ivalue = atoi(value);
        config->server_learning_time = ivalue;
    }   
    else if(!strcasecmp(key, "server-ignore-limit"))
    {
        ivalue = atoi(value);
        config->server_ignore_limit = ivalue;
    }
    else if(!strcasecmp(key, "server-scanner-limit"))
    {
        ivalue = atoi(value);
        config->server_scanner_limit = ivalue;
    }
    else if(!strcasecmp(key, "talker-fixed-threshold"))
    {
        ivalue = atoi(value);
        config->limit_talker.fixed = ivalue;
    }
    else if(!strcasecmp(key, "talker-sliding-threshold"))
    {
        ivalue = atoi(value);
        config->limit_talker.sliding = ivalue;
    }
    else if(!strcasecmp(key, "talker-fixed-window"))
    {
        ivalue = atoi(value);
        config->limit_talker.fixed_size = ivalue;
    }
    else if(!strcasecmp(key, "talker-sliding-window"))
    {
        ivalue = atoi(value);
        config->limit_talker.sliding_size = ivalue;
    }
    else if(!strcasecmp(key, "talker-sliding-scale-factor"))
    {
        config->limit_talker.window_scale = (float)strtod(value, NULL);
    }
    else if(!strcasecmp(key, "scanner-fixed-threshold"))
    {
        ivalue = atoi(value);
        config->limit_scanner.fixed = ivalue;
    }
    else if(!strcasecmp(key, "scanner-sliding-threshold"))
    {
        ivalue = atoi(value);
        config->limit_scanner.sliding = ivalue;
    }
    else if(!strcasecmp(key, "scanner-fixed-window"))
    {
        ivalue = atoi(value);
        config->limit_scanner.fixed_size = ivalue;
    }
    else if(!strcasecmp(key, "scanner-sliding-window"))
    {
        ivalue = atoi(value);
        config->limit_scanner.sliding_size = ivalue;
    }
    else if(!strcasecmp(key, "scanner-sliding-scale-factor"))
    {
        config->limit_scanner.window_scale = (float)strtod(value, NULL);
    }
    else if(!strcasecmp(key, "base-score"))
    {
        config->base_score = atoi(value);
    }
    else if(!strcasecmp(key, "dumpall"))
    {
        config->dumpall = atoi(value);
    }
    else if(!strcasecmp(key, "alert-mode"))
    {
        if(!strcasecmp(value, "once"))
        {
            config->alert_once = 1;
        }
        else if(!strcasecmp(value, "all"))
        {
            config->alert_once = 0;
        }
        else
        {
            flow_fatalerror("%s(%d) Bad option to %s => %s\n",
                       file_name, file_line, key, value);
        }
    }
    else if(!strcasecmp(key, "output-mode"))
    {
        if(!strcasecmp(value, "msg"))
        {
            config->output_mode = VARIABLEMSG;
        }
        else if(!strcasecmp(value, "pktkludge"))
        {
            config->output_mode = PKTKLUDGE;
        }
        else
        {
            flow_fatalerror("%s(%d) Bad option to %s => %s\n",
                       file_name, file_line, key, value);
        }
    }
    else        
    {
        flow_fatalerror("%s(%d) Unknown Arguments: key(%s) value(%s)\n",
                   fname, lineno, key, value);
    }
    
}


/** 
 * Parse out the snort.conf line
 *
 * output type - (variable alert string, custom file, pktkludge)
 * watch-net - optional 
 * ignore-net - optional
 *
 * @param config config to set
 * @param args string to parse
 */
static void FlowPSParseArgs(PS_CONFIG *config , char *args)
{
    const char *delim = " \t";
    char *key, *value;
    char *myargs;
    
    if(!config)
    {
        flow_fatalerror("FlowPSParseArgs: NULL config passed\n!");
    }

    if(!args)
    {
        return;
    }
    
    while(isspace((int)*args))
        args++;

    if(*args == '\0')
    {
        return;
    }

    myargs = strdup(args);

    if(myargs == NULL)
        flow_fatalerror("%s(%d) Unable to allocate memory!\n", file_name, file_line);

    key = strtok(myargs, delim);

    while(key != NULL)
    {
        value = strtok(NULL, delim);

        if(!value)
        {
            flow_fatalerror("%s(%d) key %s has no value", file_name, file_line); 
        }

        FlowPSParseOption(config, file_name, file_line, key, value);                
        key = strtok(NULL, delim);
    }

    if(myargs)
        free(myargs);

    /* is server statistics table enabled? */
    if(config->server_watchnet_ipv4 != NULL)
    {
        if((config->server_scanner_limit == 0) &&
           (config->server_ignore_limit == 0))
        {
            flow_fatalerror("A Server watchnet is set"
                            " with no scanner or ignore limit\n"
                            "Perhaps you should just remove"
                            " the server-watchnet option\n");

        }
            
    }
}

void FlowPSRestart(int signal, void *data)
{
    return;
}

void FlowPSCleanExit(int signal, void *data)
{
    if(s_pkt)
    {
        free(s_pkt);
        s_pkt = NULL;
    }

    if(!pv.quiet_flag)
        flowps_stats(&s_tracker);

    flowps_destroy(&s_tracker);
    return;
}

/**
 * The callback for the flow-portscan module
 *
 * This function's purpose is to do about the same thing as a
 * traditional snort preprocessor.  The only difference is that this
 * occurs only on a specific FLOW position.
 *
 * This individual callback position is only valid in the "NEW" flow
 * position.
 *
 * The operations are pretty much the same as laid out by
 *
 * Chris Green, Marc Norton, Dan Roelker
 *
 * Basic code flow:
 *
 * 1) Get the score and flag type
 * 2) return if the score is 0
 * 3) Get the score entry node
 * 4) Perform time window maintence 
 *    - includes flushing the "scan data" out of the subsys
 * 5) Process the score data
 * 6) Generate alerts if necessary
 *
 * @param position where in the flow module this is being called from
 * @param flow the flow that the stats are kept for
 * @param direction the direction of the flow
 * @param cur the current time
 * @param p the current packet (may be NULL)
 *
 * @return TBD
 */
int flowps_newflow_callback(FLOW_POSITION position, FLOW *flowp,
                            int direction, time_t cur, FLOWPACKET *p)
{
    TRACKER_POSITION tr_pos = TRACKER_ACTIVE; /* where new nodes get inserted */
    PS_TRACKER *pstp = &s_tracker;
    SCORE_ENTRY *current_entry = NULL;
    int ret, alert_flags, score;    
    u_int8_t cflags;
    u_int32_t *address = &flowp->key.init_address;

    if(!flowps_enabled())
        return 0;

    if(s_debug > 5)
    {
        printf("DEBUG: callback %s:%d -> %s:%d\n",
               inet_ntoax(p->iph->ip_src.s_addr), p->sp,
               inet_ntoax(p->iph->ip_dst.s_addr), p->dp);
    }

    if(position != FLOW_NEW)        
    {
#ifndef WIN32
        flow_printf("Wrong callback position for %s\n", __func__);
#else
        flow_printf("Wrong callback position for %s(%d)\n", __FILE__, __LINE__);
#endif
        return 0;
    }

    if(flowps_is_ignored_ipv4(pstp,
                              &flowp->key.init_address,
                              &flowp->key.resp_address) == FLOW_SUCCESS)
    {
        return 0;
    }

    if(IsTcpPacket(p))
    {
        /* allow radically different flags from SYN help score
         * differently */
        cflags = GetTcpFlags(p);
    }
    else
    {
        cflags = 0;
    }

    /*
     * if we can't find the score for whatever reason, or the
     * resultant score is 0 (indicating that this a "normal" event),
     * just go ahead and return 
     */
    if(flowps_get_score(pstp, flowp, cur,
                        cflags, &score, &tr_pos) != FLOW_SUCCESS)
    {
        return -1;
    }

    if(score == 0)
    {
        return 0;
    }
    else if(s_debug > 5)
    {
        flow_printf("new unique flow!\n");
        flowkey_print(&flowp->key);
        flow_printf("\n");
    }
    
    /* run the "score entry finder" or create a new node */    
    ret = flowps_find_entry(pstp, address, &current_entry);

    if(ret == FLOW_NOTFOUND)
    {
        ret = flowps_add_entry(pstp,  tr_pos, address, &current_entry);

        if(ret != FLOW_SUCCESS)            
        {
            /* tracker failed horribly */
#ifndef WIN32
            flow_printf("flowps_add_entry check failed in %s\n", __func__);
#else
            flow_printf("flowps_add_entry check failed in %s(%d)\n", __FILE__, __LINE__);
#endif
            return 0;
        }
    }
    else if(ret != FLOW_SUCCESS)
    {
#ifndef WIN32
        flow_printf("bad return for finding the entry %s\n", __func__);
#else
        flow_printf("bad return for finding the entry %s(%d)\n", __FILE__, __LINE__);
#endif
        return 0;
    }

    flowps_sliding_winadj(&current_entry->sliding_talker,
                          cur,
                          &pstp->config.limit_talker);

    flowps_fixed_winadj(&current_entry->fixed_talker,
                        cur,
                        &pstp->config.limit_talker);

    flowps_sliding_winadj(&current_entry->sliding_scanner,
                          cur,
                          &pstp->config.limit_scanner);

    flowps_fixed_winadj(&current_entry->fixed_scanner,
                        cur,
                        &pstp->config.limit_scanner);

    /* maintain the list of recent connections */
    flowps_set_last_address(current_entry, flowp, cflags);

    /* windows adjusted, lets get us some alerts */
    if(s_debug > 5 && score > 1)
    {
        flow_printf("XXXX **** got a big old score(%d) because of [%s] -> %s\n",
               score,  mktcpflag_str(cflags),
               inet_ntoa(*(struct in_addr *) (&flowp->key.resp_address)));
        flowps_entry_print(current_entry, address);
        flow_printf("\nXXXX ****\n");
    }

    if(flowps_score_entry(pstp, current_entry, score, tr_pos, 
                          pstp->config.alert_once,
                          &alert_flags) != FLOW_SUCCESS)
    {
#ifndef WIN32
        flow_printf("bad return for finding the entry %s\n", __func__);
#else
        flow_printf("bad return for finding the entry %s(%d)\n", __FILE__, __LINE__);
#endif
        return 0;
    }

    /* If someone generates an event 
     * 
     *
     */
    if(current_entry->position == TRACKER_ACTIVE && tr_pos == TRACKER_SCANNER)
    {
        int ret;

        
        //flow_printf("moving this one! (cur %d) -> (new %d) %s\n",
        //current_entry->position, tr_pos, inet_ntoa(*(struct in_addr *) address));

        /* move address TO scanner FROM active */
        ret = scoreboard_move(&pstp->table_scanner, &pstp->table_active, address);
        
        if(ret != FLOW_SUCCESS)
        {
            flow_printf("Unable to move %s\n",inet_ntoa(*(struct in_addr *) address));
            return -1;
        }
        else
        {
            /* @todo - move this into the scoreboard mv call */
            current_entry->position = TRACKER_SCANNER;
        }
       
    }

    if(s_debug > 5)
    {
        if(tr_pos == TRACKER_SCANNER)
        {
            flow_printf("Found a tracker scanner!\n");
            flowps_entry_print(current_entry, address);
        }
    }
    
    if(s_debug > 10)
    {
        flowps_entry_print(current_entry, address);
    }
    
    if(alert_flags)        
    {
        /*
        **  We OR the alert_flags here because we only want to add
        **  new alerts and reset alerts that might not be set in
        **  alert_flags.  This is for the case of alert_once being
        **  set.
        */
        current_entry->flags |= alert_flags;
            
        /* push things through the output system */
        
        flowps_generate_flow_event(current_entry, p, address,
                                   pstp->config.output_mode, cur);
    }

    return 0;
}

static int flowps_generate_flow_event(SCORE_ENTRY *sep, FLOWPACKET *orig_packet,
                                      u_int32_t *address,
                                      FLOWPS_OUTPUT output_type,
                                      time_t cur)
{
    Packet *p = NULL;
    char buf[1024 + 1];    
    u_int32_t event_id; 
    u_int32_t event_type; /* the sid for the gid */
    /*  Assign an event type to the display
     */
    if(sep->flags & ALERT_FIXED_SCANNER)
    {
        event_type = FLOW_SCANNER_FIXED_ALERT;
    }
    else if(sep->flags & ALERT_SLIDING_SCANNER)
    {
        event_type = FLOW_SCANNER_SLIDING_ALERT;
    }
    else if(sep->flags & ALERT_SLIDING_TALKER)
    {
        event_type = FLOW_TALKER_SLIDING_ALERT;
    }
    else if(sep->flags & ALERT_FIXED_TALKER)
    {
        event_type = FLOW_TALKER_FIXED_ALERT;
    }
    else
    {
        return FLOW_EINVALID;
    }
    
    switch(output_type)
    {
    case PKTKLUDGE:
        /* log a packet to the output system */
        p = flowps_mkpacket(sep, orig_packet, address, cur);      
    case VARIABLEMSG:
        snprintf(buf, 1024,
                 "Portscan detected from %s Talker(fixed: %u sliding: %u) Scanner(fixed: %u sliding: %u)",
                 inet_ntoa(*(struct in_addr *) address),
                 sep->fixed_talker.score, sep->sliding_talker.score,
                 sep->fixed_scanner.score, sep->sliding_scanner.score);
        buf[1024] = '\0';
        
        /* p is NULL w/ the VARIABLEMSG fmt */
        event_id = GenerateSnortEvent(p,
                                      GENERATOR_FLOW_PORTSCAN,
                                      event_type,
                                      1, /* revision */
                                      1, /* classification */
                                      2, /* medium priority */
                                      buf);
        /*
         *  If this is the first time we have called an alert on this
         *  function, save it off so we have an event reference.
         *
         *  DEPRECATED:
         *    The event_id was to tag additional events to a previous
         *    one, but that logic was ifdef'ed out, so we'll keep it
         *    around anyway.
         */
        sep->event_id = event_id;

        /*
         * this is the last tv_sec from the packet
         */
        sep->event_sec = packet_timeofday(); 
    }
    
    return FLOW_SUCCESS;
}

/** 
 * Print the score entry to a buffer
 *
 * snprintf doesn't protect us any since we are calculating so much
 * but it does make me be explicit on how much data I am putting in.
 * 
 * @param buf buf to print into
 * @param buflen size of buffer
 * @param sep score entry to print
 * @param address address of attacker
 * 
 * @return 0 on sucess
 */
static int score_entry_sprint(unsigned char *buf, int buflen, SCORE_ENTRY *sep, u_int32_t *address)
{
    int printed = 0; /* tmp */
    int total_printed = 0;
    int remaining = buflen;
    u_int32_t i;
    
    if(buf && buflen > 0 && sep && address)
    {
        printed = snprintf(buf + total_printed,
                           remaining,
                           "Address: %s\n"
                           "AT_SCORE: %u\n"
                           "ST_SCORE: %u\n"
                           "AS_SCORE: %u\n"
                           "SS_SCORE: %u\n"
                           "Total Connections: %u\n"
                           "ScanFlags: 0x%x\n"
                           "AT_STARTEND: %u %u\n"
                           "ST_STARTEND: %u %u\n"
                           "AS_STARTEND: %u %u\n"
                           "SS_STARTEND: %u %u\n"
                           "REF_SEC:   %u\n"
                           "REF_EVENT: %u\n",
                           inet_ntoa(*(struct in_addr *)address),
                           sep->fixed_talker.score,
                           sep->sliding_talker.score,
                           sep->fixed_scanner.score,
                           sep->sliding_scanner.score,
                           sep->connections_seen,
                           sep->flags,
                           (unsigned) sep->fixed_talker.start,
                           (unsigned) sep->fixed_talker.ends,
                           (unsigned) sep->sliding_talker.start,
                           (unsigned) sep->sliding_talker.ends,
                           (unsigned) sep->fixed_scanner.start,
                           (unsigned) sep->fixed_scanner.ends,
                           (unsigned) sep->sliding_scanner.start,
                           (unsigned) sep->sliding_scanner.ends,
                           (unsigned) sep->event_sec,
                           sep->event_id);

        if(printed <= 0)
            return -1;

        remaining     -= printed;
        total_printed += printed;
        
        if(remaining <= 0)            
            return -1;

        /* as long as we have a postive # of connections, pump out the info */
        for(i=0; i < sep->connections_seen && i < FLOWPS_HOSTS_SIZE; i++)
        {
            CONN_ENTRY *cp = &sep->last_hosts[i];

            
            printed = snprintf(buf + total_printed,
                               remaining,
                               "ConnInfo: (%d:%s:%d Flags: %x)\n",
                               cp->protocol,
                               inet_ntoa(*(struct in_addr*) &cp->ip),
                               cp->port,
                               cp->cflags);

            if(printed <= 0)
                return -1;
            remaining     -= printed;
            total_printed += printed;
            if(remaining <= 0)            
                return -1;
        }

        /* successful exit! */
        return total_printed;        
    }
    
    return -1;
}

/** 
 * Make a packet with the flowps data in it.
 *
 * This is used to generate a fake IP datagram to carry portscan data
 * from snort so that it can be processed by custom utilities.
 *
 * SRC + DST mac addresses = "MACDAD"
 * sip+dip == attacker 
 * ip proto 255
 * ttl = 0
 * chksum = 0
 *
 * @param sep score entry to generate a packet from
 * @param address ptr to the address of the attacker
 * 
 * @return a pointer to a fully formed packet on success
 */
static Packet *flowps_mkpacket(SCORE_ENTRY *sep, FLOWPACKET *orig_packet, u_int32_t *address, time_t cur)
{
    Packet *p = s_pkt;
    int len;
    u_int32_t dst_ip;
    unsigned short plen;

    p->pkth->ts.tv_sec = cur;


    dst_ip = GetIPv4DstIp(orig_packet);

    memcpy(&p->iph->ip_src.s_addr, address, 4);
    memcpy(&p->iph->ip_dst.s_addr, &dst_ip, 4);

    len = score_entry_sprint(p->data, FLOWPSMAXPKTSIZE, sep, address);
    
    if(len <= 0)
    {
        /* this can never return more than FLOWPSMAXPKTSIZE */
        return NULL;
    }

    p->data[len] = '\0';
    
    /* explicitly cast it down */
    plen = (len & 0xFFFF);

    if((plen + IP_HEADER_LEN) < plen)
    {
        /* wrap around */
        return NULL;
    }
        
    p->dsize = plen;
    
    plen += IP_HEADER_LEN;
    p->iph->ip_len = htons(plen);

    p->pkth->caplen = ETHERNET_HEADER_LEN + plen;
    p->pkth->len    = ETHERNET_HEADER_LEN + plen;
        
    return p;
}

/** 
 * Initialize the static packet used for the portscan flow plugin.
 *
 * This allocates 2 bytes over what it needs to so that the IP header
 * will be 32bit aligned. 
 * 
 * @return FLOW_SUCCESS on sucess
 */
static int flowps_init_pkt(void)     
{
    Packet *p = NULL;
    const char *flow_portscan_mac_addr = "MACDADDY";
    const char twiddlebytes = 2;

    p = calloc(1,sizeof(Packet));

    if(!p)
    {
        flow_fatalerror("Unable to alloc memory for the flow-portscan packet!\n");
    }

    p->pkth = calloc(1,
                     sizeof(struct pcap_pkthdr) + ETHERNET_HEADER_LEN
                     + twiddlebytes + IP_MAXPACKET);

    if(!p->pkth)
    {
        flow_fatalerror("Unable to alloc memory for the flow-portscan packet!\n");
    }
    else
    {
        p->pkth = (struct pcap_pkthdr *) (((u_int8_t *) p->pkth) + twiddlebytes);
    }

    p->pkt  =  ((u_int8_t *)p->pkth) + sizeof(SnortPktHeader);
    p->eh   =   (EtherHdr *)((u_int8_t *)p->pkt);
    p->iph  =  (IPHdr *)((u_int8_t *)p->eh + ETHERNET_HEADER_LEN);
    p->data =  ((u_int8_t *)p->iph) + sizeof(IPHdr);
    
    /* p->data is now pkt +
     *  IPMAX_PACKET - (IP_HEADER_LEN + ETHERNET_HEADER_LEN)
     *
     * This is MAXFLOWPSPKTSIZE
     *
     */

    p->eh->ether_type = htons(0x0800);
    memcpy(p->eh->ether_dst, flow_portscan_mac_addr, 6);
    memcpy(p->eh->ether_src, flow_portscan_mac_addr, 6);
    
    SET_IP_VER(p->iph,  0x4);
    SET_IP_HLEN(p->iph, 0x5);
    
    p->iph->ip_proto = 0xFF;  /* set a reserved protocol */
    p->iph->ip_ttl   = 0x00;  /* set a TTL we'd never see */
    p->iph->ip_len = 0x5;
    p->iph->ip_tos = 0x10;

    /* save off s_pkt for flowps_mkpkt */
    s_pkt = p;

    return FLOW_SUCCESS;
}
