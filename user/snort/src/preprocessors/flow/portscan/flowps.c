/* $Id: */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include "flowps.h"
#include "scoreboard.h"
#include "unique_tracker.h"
#include "server_stats.h"
#include "packet_time.h"
#include "util_net.h"

/* local copy of these tcp flags */
#ifndef TH_FIN

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_RES2 0x40
#define TH_RES1 0x80


#endif /* TH_FIN */

#define FLOWPS_NC 1000000 /* number of rows to use for each scan table */

static int s_debug = 0;
static int s_enabled = 0;

/** 
 * Setup a SCORE_THRESHOLD object.
 *
 * This contains the limits and window sizes that will be used each
 * time we evaluate a SCORE_ENTRY from one of the scoreboards.
 * 
 * @param thr pointer to the threshold to initialize
 * @param fixed_size the time window for fixed scale
 * @param fixed_limit the score limit to alert on
 * @param sliding_size the sliding time window initial size
 * @param sliding_limit score limit to alert on
 * @param window_scale what to multiple the sliding size on each "hit"
 * 
 * @return FLOW_SUCCESS on success
 */
int flowps_mkthreshold(SCORE_THRESHOLD *thr,
                       int fixed_size, u_int32_t fixed_limit,
                       int sliding_size, u_int32_t sliding_limit,
                       float window_scale)
{
    if(!thr)
        return FLOW_ENULL;
    
    if(fixed_size < 0)
        fixed_size = 0;

    if(sliding_size < 0)
        sliding_size = 0;
    
    thr->fixed_size   = fixed_size;
    thr->sliding_size = sliding_size;
    thr->window_scale = window_scale;
    thr->fixed        = fixed_limit;
    thr->sliding      = sliding_limit;

    return FLOW_SUCCESS;
}

/** 
 * Initialize the configuration structure and set everything to 0
 * 
 * @param configp config to set
 * 
 * @return FLOW_SUCCESS on success
 */
int flowps_mkconfig(PS_CONFIG *configp,
                    int sb_memcap_talker,
                    int sb_rows_talker,
                    int sb_memcap_scanner,
                    int sb_rows_scanner,
                    int ut_memcap,
                    int ut_rows,
                    int server_memcap,
                    int server_rows,
                    int server_learning_time,
                    int tcp_penalties,
                    u_int32_t server_ignore_limit,
                    u_int32_t server_scanner_limit,
                    int base_score,
                    int alert_once,
                    FLOWPS_OUTPUT output_mode)
{
    if(!configp)
        return FLOW_ENULL;

    memset(configp, 0, sizeof(PS_CONFIG));
           
    configp->sb_memcap_total   = sb_memcap_scanner + sb_memcap_talker;
    configp->sb_memcap_scanner = sb_memcap_scanner;
    configp->sb_memcap_talker  = sb_memcap_talker;

    configp->sb_rows_talker    = sb_rows_talker;
    configp->sb_rows_scanner   = sb_rows_scanner;
        
    configp->tcp_penalties = tcp_penalties;

    configp->ut_memcap            = ut_memcap;
    configp->ut_rows              = ut_rows;

    
    configp->server_memcap        = server_memcap;
    configp->server_rows          = server_rows;
    configp->server_learning_time = server_learning_time;
    configp->server_ignore_limit  = server_ignore_limit;
    configp->server_scanner_limit = server_scanner_limit;
    configp->base_score           = base_score;
    configp->alert_once           = alert_once;
    configp->output_mode          = output_mode;
    configp->dumpall              = 0;
    return FLOW_SUCCESS;
}

/** 
 * Determine if the server stats feature is enabled
 * 
 * @param trackerp portscan tracker
 * 
 * @return FLOW_SUCCESS if server_stats is enabled
 */
int flowps_server_stats_enabled(PS_TRACKER *trackerp)
{
    if(trackerp->config.server_watchnet_ipv4)
        return FLOW_SUCCESS;
    
    return FLOW_DISABLED;

}
/** 
 * Determine if server stats is enabled for this particular IP
 * address.
 * 
 * @param trackerp portscan tracker to inquire
 * 
 * @return FLOW_SUCCESS if the server watchnet stuff is enabled
 */
int flowps_server_watch(PS_TRACKER *trackerp, u_int32_t address)
{
    FLOWASSERT(trackerp != NULL);

    if (trackerp == NULL)
        return FLOW_DISABLED;
        
    if(trackerp->config.server_watchnet_ipv4 == NULL)
        return FLOW_DISABLED;

    if(server_stats_contains(&trackerp->server_stats,address) == FLOW_SUCCESS)
        return FLOW_SUCCESS;

    /* finally fail */
    return FLOW_DISABLED;
}

/** 
 * initialize the Portscan Tracker.
 *
 * This takes several arguments, all, on the PS_CONFIG structure.
 * 
 * @param trackerp tracker object to initialize
 * @param configp well-formed configuration to initialize this object
 * 
 * @return FLOW_SUCCESS on success
 */
int flowps_init(PS_TRACKER *trackerp, PS_CONFIG *configp)
{
    int ret;
    
    if(!trackerp || !configp)
        return FLOW_ENULL;

    /* we should validate this threshold object somewhat */
    memcpy(&trackerp->config, configp, sizeof(PS_CONFIG));    

    ret = scoreboard_init(&trackerp->table_active,            /* table */
                          "Active Talkers",                   /* description */
                          TRACKER_ACTIVE,                     /* position */
                          trackerp->config.sb_rows_talker,    /* node count */
                          trackerp->config.sb_memcap_talker); /* memcap */

    if(ret != FLOW_SUCCESS)
    {
        return ret;
    }
    
    ret = scoreboard_init(&trackerp->table_scanner,            /* table */
                          "Portscanners",                      /* description */
                          TRACKER_SCANNER,                     /* position */
                          trackerp->config.sb_rows_scanner,    /* node count */
                          trackerp->config.sb_memcap_scanner); /* memcap */

    if(ret != FLOW_SUCCESS)
    {
        scoreboard_destroy(&trackerp->table_active);
        return ret;
    }

    /* setup the unique talkers table */
    ret = ut_init(&trackerp->unique_tracker,trackerp->config.ut_rows, trackerp->config.ut_memcap);

    if(ret != FLOW_SUCCESS)
    {
        scoreboard_destroy(&trackerp->table_active);
        scoreboard_destroy(&trackerp->table_scanner);
        return ret;
    }

    /* the watchnet stuff is optional */
    if(flowps_server_stats_enabled(trackerp) == FLOW_SUCCESS)
    {
        ret = server_stats_init(&trackerp->server_stats,
                                trackerp->config.server_watchnet_ipv4,
                                trackerp->config.server_rows,
                                trackerp->config.server_memcap);

        if(ret != FLOW_SUCCESS)
        {
            scoreboard_destroy(&trackerp->table_active);
            scoreboard_destroy(&trackerp->table_scanner);
            ut_destroy(&trackerp->unique_tracker);
            return ret;
        }
    }    

    s_enabled = 1;
    
    return FLOW_SUCCESS;
}

int flowps_destroy(PS_TRACKER *trackerp)
{
    if(!trackerp)
        return FLOW_ENULL;

    scoreboard_destroy(&trackerp->table_scanner);
    scoreboard_destroy(&trackerp->table_active);
    ut_destroy(&trackerp->unique_tracker);
    
    return FLOW_SUCCESS;
}

/** 
 * Reset a single flag in the alert_flags entry if the score is 0
 * 
 * @param type flag to reset
 * @param alert_flags flag entry
 * @param score score to reset
 */
static INLINE void flowps_reset_alert_flags(u_int32_t type,
                                            u_int32_t *alert_flags,
                                            u_int32_t *score)
{
    if(((*alert_flags) & type))
    {
        *alert_flags &= ~type;
        *score = 0;
    }
}

/** 
 * Evaluate the score on an entry, generating alerts if needed.
 * 
 * @param pstp portscan tracker
 * @param sep score entry 
 * @param score score determined for this flow
 * @param tr_pos what type of connection the current one is
 * @param alert_once alert only on the first one we find
 * @param alert_flags what type of alerts should we generate
 * 
 * @return FLOW_SUCCESS on success
 */
int flowps_score_entry(PS_TRACKER *pstp, SCORE_ENTRY *sep, int score,
                       TRACKER_POSITION tr_pos,
                       int alert_once,
                       u_int32_t *alert_flags)
{
    /* @todo - evaluate the score for the node before we evaluate the
       expiration on a sliding time window */
    if(!pstp || !sep || !alert_flags)
    {
        return FLOW_ENULL;
    }

    *alert_flags = 0;

    if(alert_once == 0)
    {
        /* if our score entry flags ever get set to 0, reset the alert
         * flags */
        flowps_reset_alert_flags(ALERT_FIXED_TALKER,
                                 &sep->flags,
                                 &sep->fixed_talker.score);

        flowps_reset_alert_flags(ALERT_SLIDING_TALKER,
                                 &sep->flags,
                                 &sep->sliding_talker.score);

        flowps_reset_alert_flags(ALERT_FIXED_SCANNER,
                                 &sep->flags,
                                 &sep->fixed_scanner.score);
        
        flowps_reset_alert_flags(ALERT_SLIDING_SCANNER,
                                 &sep->flags,
                                 &sep->sliding_scanner.score);
    }

    FLOWASSERT((tr_pos == TRACKER_SCANNER) || (tr_pos == TRACKER_ACTIVE));
    
    switch(tr_pos)
    {
    case TRACKER_SCANNER:
        sep->fixed_scanner.score   += score;
        sep->sliding_scanner.score += score;
        /* talking thresholds increment even if this is a "scanner"
         * connection */
        break;
    case TRACKER_ACTIVE:
        sep->fixed_talker.score    += score;
        sep->sliding_talker.score  += score;
        break;
    }

    /* done resetting the scores, now check the thresholds */   
    if(pstp->config.limit_talker.fixed &&
       pstp->config.limit_talker.fixed <= sep->fixed_talker.score)
    {
            *alert_flags |= ALERT_FIXED_TALKER;
    }

    if(pstp->config.limit_talker.sliding &&
       pstp->config.limit_talker.sliding <= sep->sliding_talker.score)
    {
            *alert_flags |= ALERT_SLIDING_TALKER;
    }
    
    if(pstp->config.limit_scanner.fixed &&
       pstp->config.limit_scanner.fixed <= sep->fixed_scanner.score)
    {
            *alert_flags |= ALERT_FIXED_SCANNER;
    }

    if(pstp->config.limit_scanner.sliding &&
       pstp->config.limit_scanner.sliding <= sep->sliding_scanner.score)
    {
            *alert_flags |= ALERT_SLIDING_SCANNER;
    }

    /*
    **  This logic will only give us alerts for the ones that have not
    **  already gone off for this score entry.
    */
    if(alert_once)
    {
        *alert_flags &= ~sep->flags;
    }

    return FLOW_SUCCESS;    
}


/** 
 * find the trackers in the table
 *
 * Currently, it first looks it up in the active table and then the
 * scanner table
 * 
 * @param trackerp tracker to search
 * @param address key to search for
 * @param sepp where to place the results
 * 
 * @return FLOW_SUCCESS on sucess and sets sepp
 */
int flowps_find_entry(PS_TRACKER *trackerp, u_int32_t *address, SCORE_ENTRY **sepp)
{
    int ret;
    
    if(!trackerp || !sepp || !address)
    {
        return FLOW_ENULL;
    }

    ret = scoreboard_find(&trackerp->table_active, address, sepp);
    
    if(ret == FLOW_NOTFOUND)
    {
        // flow_printf(stdout, "address was not found :(");
        /* the find failed -- look it up in the
         * scanner table */
        ret = scoreboard_find(&trackerp->table_scanner, address, sepp);
    }

    return ret;
}


/** 
 * Register a new node in the portscan tracker.
 *
 * This does not enforce that a node can only be in one table at a
 * time to avoid the 2 extra searching operations.  All uses of this
 * should be done after performing a find to make sure the trackers
 * do not already exist.
 * 
 * @param trackerp portscan tracker 
 * @param position where to place this node
 * @param address the address for the key
 * @param sepp score entry return information
 * 
 * @return FLOW_SUCCESS on success
 *
 * @retval FLOW_ENULL null arguments passed
 * @retval FLOW_SUCESS sucessfull added
 * @retval FLOW_EINVALID already in table
 * @retval FLOW_ENOMEM out of memory
 */

int flowps_add_entry(PS_TRACKER *trackerp,
                      TRACKER_POSITION position,
                      u_int32_t *address,
                      SCORE_ENTRY **sepp)
{
    int ret;
    
    if(position == TRACKER_ACTIVE)
    {
        ret = scoreboard_add(&trackerp->table_active, address, sepp);
    }
    else
    {
        ret = scoreboard_add(&trackerp->table_scanner, address, sepp);
    }

    if(ret == FLOW_SUCCESS)
    {
        (*sepp)->position = position;
    }
        
    return ret;
}


/** 
 * Printout a score entry
 * 
 * @param ps_score score entry to printf
 * 
 * @return FLOW_SUCCESS on success
 */
int flowps_score_print(PS_SCORE *ps_score)
{
    flow_printf(" score: %u start: %u end: %u",
                ps_score->score,
                (unsigned int) ps_score->start,
                (unsigned int) ps_score->ends);
    
    return FLOW_SUCCESS;
}


int flowps_entry_print(SCORE_ENTRY *entry, u_int32_t *address)
{
    char *c_position = "TRACKER_ACTIVE";
    u_int32_t i;
    if(entry->position == TRACKER_SCANNER)
        c_position = "TRACKER_SCANNER";

    flow_printf(",-----------------------------------------------------\n");
    flow_printf("| Score entry for %s@%p Flags: %x\n",
            inet_ntoa(*(struct in_addr *) address), entry, entry->flags);


    flow_printf("|   Alerts: FT: %u ST: %u FS: %u SS: %u",
            (entry->flags & ALERT_FIXED_TALKER),
            (entry->flags & ALERT_SLIDING_TALKER),
            (entry->flags & ALERT_FIXED_SCANNER),
            (entry->flags & ALERT_SLIDING_SCANNER));
    
    flowps_score_print(&entry->fixed_talker);
    
    flow_printf("\n| Position: %s\n", c_position);
    flow_printf("|   Fixed Talker:");
    flowps_score_print(&entry->fixed_talker);
    
    flow_printf("\n| Sliding Talker:");
    flowps_score_print(&entry->sliding_talker);
    
    flow_printf("\n|   Fixed Scanner:");
    flowps_score_print(&entry->fixed_scanner);

    flow_printf("\n| Sliding Scanner:");
    flowps_score_print(&entry->sliding_scanner);

    flow_printf("\n| Connections Seen: %u", entry->connections_seen);

    /* as long as we have a postive # of connections, pump out the info */
    for(i=0; i < entry->connections_seen && i < FLOWPS_HOSTS_SIZE; i++)
    {
        CONN_ENTRY *cp = &entry->last_hosts[i];
        if(cp->protocol == 6)
        {
            flow_printf("\n|        proto: %d %s:%d th_flags: %s",
                        cp->protocol,
                        inet_ntoa(*(struct in_addr*) &cp->ip),
                        cp->port,
                        mktcpflag_str(cp->cflags));
        }
        else
        {
            flow_printf("\n|        proto: %d %s:%d cflags: %d",
                        cp->protocol,
                        inet_ntoa(*(struct in_addr*) &cp->ip),
                        cp->port,
                        cp->cflags);

        }
    }
    flow_printf("\n`----------------------------------------------------\n");

    return 0;
}

void flowps_stats(PS_TRACKER *pstp)
{
    int dumpall = pstp->config.dumpall;
        
    flow_printf("+---[ Flow-portscan Stats ]----------------+\n");
    scoreboard_stats(&pstp->table_active, dumpall);
    scoreboard_stats(&pstp->table_scanner, dumpall);
    ut_stats(&pstp->unique_tracker, dumpall);
    server_stats(&pstp->server_stats, dumpall);
}


/** 
 * Assign TCP penalty points
 *
 * have an optional penalty for odd flags combinations on TCP --
 * this should probably promote people to the TRACKER_SCANNER
 * table as well.
 *
 * Perhaps we should extend this to non-common ICMP errors as
 * well.
 *
 * S,12 & SYN are the 1 ptrs.
 *
 * XMAS w/ ACK is a 5 ptr
 *
 * SF+ is a 3 ptr.
 *
 * @param flags th_flags
 * @param base_score base score value for normal initiations
 * @param score ptr for return value 
 */
static INLINE void flowps_tcp_penalty(u_int32_t flags, int base_score, int *score)
{
    if((flags == TH_SYN) || (flags == (TH_SYN|TH_RES1|TH_RES2)))
    {
        /* this is the common case for a session initiator */
        *score = base_score;
    }
    else if((flags & (TH_SYN|TH_FIN|TH_ACK)) == (TH_SYN|TH_FIN|TH_ACK))
    {
        *score = 5;
    }
    else if((flags & (TH_SYN|TH_FIN)) == (TH_SYN|TH_FIN))
    {
        *score = 3;
    }
    else
    {
        *score = 2;
    }
}
     

/** 
 * Get the score and the type of connection this is
 *
 * If the score is 0, this is an already existing connection and can
 * be successfully ignored.
 *
 * @param pstp portscan tracker
 * @param flowp flow to aquire a score for *
 * @param cur current time
 * @flags packet related flags that can be used to modify the score
 * @param score return value for the score
 * @param type return value for the type of connection
 * 
 * @return FLOW_SUCCESS on success and sets the score and type
 */
int flowps_get_score(PS_TRACKER *pstp, FLOW *flowp,
                     time_t cur, u_int32_t flags,
                     int *score, TRACKER_POSITION *type)
{
    UT_TYPE unique;
    u_int32_t hitcount = 1;
    int base_score;
    
    
    if(!flowp || !score || !type)
    {
        return FLOW_ENULL;
    }

    /* save off a default base score */
    base_score = pstp->config.base_score;
    *score     = pstp->config.base_score;

    /* run the uniqueness check
     *
     * This should be ABOVE the finding code since the unquieness
     * check is the key to determining if this should accrue more
     * points. If it's not unique, we can bail out instantly.
     *
     */

    if(ut_check(&pstp->unique_tracker, &flowp->key, &unique) != FLOW_SUCCESS)
    {
#ifndef WIN32
        flow_printf("ut check failed in %s\n", __func__);
#else
        flow_printf("ut check failed in %s(%d)\n", __FILE__, __LINE__);
#endif
        return 0;
    }

    
    if(unique == UT_OLD)
    {
        /* bail out if we do not have a reason to further evaluate the
         * score. The score can only be changed if this flow is truely
         * a unique (dport+proto+address)
         */
        *score = 0;
        return FLOW_SUCCESS;
    }
    else /* UT_NEW */
    {
        if(flowps_server_watch(pstp,flowp->key.resp_address) == FLOW_SUCCESS)
        {
            /* perform the hitcount management */            
            if(cur < (packet_first_time() + pstp->config.server_learning_time))
            {
                if(server_stats_add_ipv4(&pstp->server_stats,
                                         flowp->key.protocol,
                                         flowp->key.resp_address,
                                         flowp->key.resp_port,
                                         &hitcount) != FLOW_SUCCESS)
                {
#ifdef DEBUG
                    flow_printf("Unable to add ipv4 to server stats!\n");
#endif /* DEBUG */
                }
                
            }
            else
            {
                hitcount = server_stats_hitcount_ipv4(&pstp->server_stats,
                                                      flowp->key.protocol,
                                                      flowp->key.resp_address,
                                                      flowp->key.resp_port);

                if(pstp->config.server_scanner_limit &&
                   hitcount < pstp->config.server_scanner_limit)
                {
                    *type = TRACKER_SCANNER;
                }
            }

            if(pstp->config.server_ignore_limit > 0 &&
               hitcount > pstp->config.server_ignore_limit)
            {
                /* this must be a semi-active service -- it's not worth
                 * anything */
                
                if(s_debug > 5)
                {
                    flow_printf("Happy Server hitcount: %d proto: %d %s:%d\n",
                                hitcount,
                                flowp->key.protocol,
                                inet_ntoa(*(struct in_addr *) &flowp->key.resp_address),
                                flowp->key.resp_port);
                }
                
                base_score = 0;
            }
            
        } /* this IP is not being watched or something like it */
        else
        {
            hitcount = 1;
        }
    }

    /*
     * possibly assign penalty points for "bad session initiators
     */
    if(pstp->config.tcp_penalties && flowp->key.protocol == 6)
    {        
        flowps_tcp_penalty(flags, base_score, score);
    }
    else
    {
        *score = base_score;
    }

    /* @todo switch tables */
    return FLOW_SUCCESS;
}

/** 
 * Expire a fixed scale PS_SCORE
 * 
 * @param pscp score entry to expire
 * @param current_time now
 * @param threshold threshold to slide againt
 * 
 * @return FLOW_SUCCESS
 */
int flowps_fixed_winadj(PS_SCORE *pscp, time_t current_time,
                        SCORE_THRESHOLD *threshold)
{
    int window_size = threshold->fixed_size;

    if(pscp->ends <= current_time)
    {
        pscp->start = current_time;
        pscp->score = 0;
        pscp->ends  = current_time + window_size;
    }
    
    return FLOW_SUCCESS;
}

/** 
 * Expire a sliding scale PS_SCORE
 *
 * considerably more complicated than the fixed time window
 * stuff. This really should be simplified.  
 * 
 * @param pscp score entry to expire
 * @param current_time current_time
 * @param threshold threshold to slide againt
 * 
 * @return FLOW_SUCCESS
 */
int flowps_sliding_winadj(PS_SCORE *pscp, time_t current_time,
                          SCORE_THRESHOLD *threshold)
{
    int diff_SE;     /* time from start to end */
    int diff_EN;     /* time from end to current_time */
    int window_size = threshold->sliding_size;
    int adjustment;        
    float scale     = threshold->window_scale;
    
    if(pscp->ends > current_time)
    {
        /* we're still in the right time frame -- should this
         *  increment the time frame? Seems to make sense but how
         *  often should the window "slide"?
         */
        return FLOW_SUCCESS;
    }

    /* we atleast kcurrent_time to expire the score */
    pscp->score = 0;

    if(pscp->ends == 0)
    {
        /* new time window, let's just initialize it */
        pscp->start = current_time;
        pscp->ends  = current_time + window_size;        
    }
    else
    {
        diff_SE = pscp->ends - pscp->start;

        /* since we never allow end > current_time, this will always be >=0  */    
        diff_EN = current_time - pscp->ends;

        if(diff_EN > (diff_SE * 2))
        {
            /* I've guessed at this one.  If the difference between end ->
             * current_time is much bigger than the previous time window, this is
             * good enough to start the sliding time frame over
             *
             * This could present a weakness in that 1 unique flow every N
             * scale could still slip past us.  It will always be possible
             * to slow the scan down though.  This should really decrease
             * the amount of benign active talkers.
             */
            pscp->start = current_time;
            pscp->ends  = current_time + window_size;        
        }
        else
        {
            pscp->start = current_time;
            adjustment = diff_SE + (diff_SE * ((int) scale));
            
            if((adjustment + pscp->ends) > pscp->ends)
            {
                pscp->ends += adjustment;
            }
            else
            {
                /* watching for integer wrap around incase an attacker
                 * causes our scales to wrapidly increase somehow
                 *
                 * We don't watch to make sure that the user doesn't
                 * screw us.
                 */
                pscp->ends += window_size;
                
            }
        }
    }
    
    return FLOW_SUCCESS;
}

/** 
 * Maintain the ring buffer of most recent connections
 * 
 * @param sep score entry pointer
 * @param flowp flow pointer
 * @param cflags connection flags ( often just the th_flags )
 * 
 * @return FLOW_SUCCESS on sucess
 */
int flowps_set_last_address(SCORE_ENTRY *sep, FLOW *flowp, u_int8_t cflags)
{
    CONN_ENTRY *conn_entry;
    
    if(sep && flowp)
    {
        if(sep->last_idx >= FLOWPS_HOSTS_SIZE)
        {
            sep->last_idx = 0;            
        }

        /* find the entry and increment the ring */
        conn_entry = &sep->last_hosts[sep->last_idx++];

        /* fill out the entry */
        conn_entry->port     = flowp->key.resp_port;
        conn_entry->ip       = flowp->key.resp_address;
        conn_entry->protocol = flowp->key.protocol;
        conn_entry->cflags   = cflags;
        /* increment how many connections this tracker has seen */
        sep->connections_seen++;
    }
    
    return FLOW_SUCCESS;
}

/** 
 * see if flowps is turned on
 * 
 * 
 * @return 1 if portscan is on
 */
int flowps_enabled(void)
{
    return s_enabled;
}


/** 
 * Check to see if this IPv4 Address should be ignored by the portscan
 * tracker.
 *
 * This checks both the src and dst lists.
 * 
 * @param pstp portscan tracker
 * @param sip pointer to the sip in NETWORK byte order
 * @param dip pointer to the dip in NETWORK byte order
 * 
 * @return FLOW_SUCCESS if this ip should be ignored, else it should be used
 */
int flowps_is_ignored_ipv4(PS_TRACKER *pstp, u_int32_t *sip, u_int32_t *dip)
{
    u_int32_t host_sip, host_dip; /**< host ordered addresses */

    if(pstp && sip && dip)
    {
        if(pstp->config.src_ignore_ipv4)
        {
            host_sip = ntohl(*sip);

            if(ipset_contains(pstp->config.src_ignore_ipv4,
                              &host_sip, NULL, IPV4_FAMILY))
            {
                return FLOW_SUCCESS;
            }
        }

        if(pstp->config.dst_ignore_ipv4)
        {
            host_dip = ntohl(*dip);

            if(ipset_contains(pstp->config.dst_ignore_ipv4,
                              &host_dip, NULL, IPV4_FAMILY))
            {
                return FLOW_SUCCESS;
            }
        }

        return FLOW_DISABLED;
    }

    return FLOW_ENULL;
}
