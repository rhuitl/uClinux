#include "debug.h"
#include "detect.h"
#include "plugbase.h"
#include "mstring.h"
#include "sfxhash.h"
#include "util.h"
#include "decode.h"

#include "stream5_common.h"
#include "stream_api.h"
#include "snort_stream5_session.h"
#include "stream_ignore.h"

#include "plugin_enum.h"
#include "rules.h"
#include "snort.h"

#include "dynamic-plugins/sp_dynamic.h"

#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats s5UdpPerfStats;
#endif

/*  M A C R O S  **************************************************/
/* actions */
#define ACTION_NOTHING                  0x00000000

/*  D A T A  S T R U C T U R E S  ***********************************/
typedef struct _UdpSession
{
    Stream5LWSession *lwSsn;

    u_int32_t   sender_ip;
    u_int16_t   sender_port;
    u_int32_t   responder_ip;
    u_int16_t   responder_port;

    struct timeval ssn_time;

    //u_int8_t    c_ttl;
    //u_int8_t    s_ttl;

    u_int32_t   expire_time;
} UdpSession;

typedef struct _Stream5UdpPolicy
{
    u_int32_t   session_timeout;
    u_int16_t   flags;
    IpAddrSet   *bound_addrs;
} Stream5UdpPolicy;

/* Mark specific ports as "to inspect" */
#define UDP_INSPECT 0x01
#define UDP_SESSION 0x02
static u_int16_t udp_ports[65536];

/*  G L O B A L S  **************************************************/
static Stream5SessionCache *udp_lws_cache;
static Stream5UdpPolicy **udpPolicyList = NULL; /* List of Policies configured */
static u_int8_t numUdpPolicies = 0;
static MemPool udp_session_mempool;

/*  P R O T O T Y P E S  ********************************************/
static void Stream5ParseUdpArgs(u_char *, Stream5UdpPolicy *);
static void Stream5PrintUdpConfig(Stream5UdpPolicy *);
void UdpSessionCleanup(Stream5LWSession *ssn);
static int ProcessUdp(Stream5LWSession *, Packet *, Stream5UdpPolicy *);

void Stream5InitUdp()
{
    /* Now UDP */ 
    if((udp_lws_cache == NULL) && s5_global_config.track_udp_sessions)
    {
        udp_lws_cache = InitLWSessionCache(s5_global_config.max_udp_sessions,
                30, 5, 0, &UdpSessionCleanup);

        if(!udp_lws_cache)
        {
            LogMessage("Unable to init stream5 UDP session cache, no UDP "
                       "stream inspection!\n");
            s5_global_config.track_udp_sessions = 0;
            s5_global_config.max_udp_sessions = 0;
            return;
        }
        mempool_init(&udp_session_mempool, s5_global_config.max_udp_sessions, sizeof(UdpSession));
    }
}

void Stream5UdpPolicyInit(u_char *args)
{
    Stream5UdpPolicy *s5UdpPolicy;
    s5UdpPolicy = (Stream5UdpPolicy *) SnortAlloc(sizeof(Stream5UdpPolicy));
    s5UdpPolicy->bound_addrs = (IpAddrSet *) SnortAlloc(sizeof(IpAddrSet));

    Stream5ParseUdpArgs(args, s5UdpPolicy);

    /* Now add this context to the internal list */
    if (udpPolicyList == NULL)
    {
        numUdpPolicies = 1;
        udpPolicyList = (Stream5UdpPolicy **)SnortAlloc(sizeof (Stream5UdpPolicy *)
            * numUdpPolicies);
    }
    else
    {
        Stream5UdpPolicy **tmpPolicyList =
            (Stream5UdpPolicy **)SnortAlloc(sizeof (Stream5UdpPolicy *)
            * (++numUdpPolicies));
        memcpy(tmpPolicyList, udpPolicyList,
            sizeof(Stream5UdpPolicy *) * (numUdpPolicies-1));
        free(udpPolicyList);
        
        udpPolicyList = tmpPolicyList;
    }
    udpPolicyList[numUdpPolicies-1] = s5UdpPolicy;

    Stream5PrintUdpConfig(s5UdpPolicy);

    return;
}

static void Stream5ParseUdpArgs(u_char *args, Stream5UdpPolicy *s5UdpPolicy)
{
    char **toks;
    int num_toks;
    int i;
    char *index;
    char **stoks = NULL;
    int s_toks;
    char *endPtr = NULL;

    s5UdpPolicy->session_timeout = S5_DEFAULT_SSN_TIMEOUT;
    s5UdpPolicy->flags = 0;

    if(args != NULL && strlen(args) != 0)
    {
        toks = mSplit(args, ",", 6, &num_toks, 0);

        i=0;

        while(i < num_toks)
        {
            index = toks[i];

            while(isspace((int)*index)) index++;

            stoks = mSplit(index, " ", 2, &s_toks, 0);

            if(!strcasecmp(stoks[0], "timeout"))
            {
                if(stoks[1])
                {
                    s5UdpPolicy->session_timeout = strtoul(stoks[1], &endPtr, 10);
                }
                
                if (!stoks[1] || (endPtr == &stoks[1][0]))
                {
                    FatalError("%s(%d) => Invalid timeout in config file.  Integer parameter required.\n",
                            file_name, file_line);
                }
            }
            else if (!strcasecmp(stoks[0], "ignore_any_rules"))
            {
                s5UdpPolicy->flags |= STREAM5_CONFIG_IGNORE_ANY;
            }
            else
            {
                FatalError("%s(%d) => Invalid Stream5 UDP Policy option\n", 
                            file_name, file_line);
            }

            mSplitFree(&stoks, s_toks);
            i++;
        }

        mSplitFree(&toks, num_toks);

        if(s5UdpPolicy->bound_addrs == NULL)
        {
            /* allocate and initializes the
             * IpAddrSet at the same time
             * set to "any"
             */
            s5UdpPolicy->bound_addrs = (IpAddrSet *) SnortAlloc(sizeof(IpAddrSet));
        }
    }
    return;
}

static void Stream5PrintUdpConfig(Stream5UdpPolicy *s5UdpPolicy)
{
    LogMessage("Stream5 UDP Policy config:\n");
    LogMessage("    Timeout: %d seconds\n", s5UdpPolicy->session_timeout);
    LogMessage("    Flags: 0x%X\n", s5UdpPolicy->flags);
    //IpAddrSetPrint("    Bound Addresses:", s5UdpPolicy->bound_addrs);
}

int Stream5VerifyUdpConfig()
{
    int16_t sport, dport;
    RuleListNode *rule;
    RuleTreeNode *rtn;
    OptTreeNode *otn;
    extern RuleListNode *RuleLists;
    char inspectSrc, inspectDst;

    if (!udp_lws_cache)
        return -1;

    if (numUdpPolicies < 1)
        return -1;

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
                    udp_ports[sport] |= UDP_INSPECT;
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
                    udp_ports[dport] |= UDP_INSPECT;
                }

                if (inspectSrc || inspectDst)
                {
                    /* Look for an OTN with flow or flowbits keyword */
                    for (otn = rtn->down; otn; otn = otn->next)
                    {
                        if (otn->ds_list[PLUGIN_CLIENTSERVER] ||
                            otn->ds_list[PLUGIN_FLOWBIT])
                        {
                            if (inspectSrc)
                            {
                                udp_ports[sport] |= UDP_SESSION;
                            }
                            if (inspectDst)
                            {
                                udp_ports[dport] |= UDP_SESSION;
                            }
                        }
#ifdef DYNAMIC_PLUGIN
                        else if (DynamicHasFlow(otn) ||
                                 DynamicHasFlowbit(otn))
                        {
                            if (inspectSrc)
                            {
                                udp_ports[sport] |= UDP_SESSION;
                            }
                            if (inspectDst)
                            {
                                udp_ports[dport] |= UDP_SESSION;
                            }
                        }
#endif
                    }
                }
            }
        }
    }

    return 0;
}

#ifdef DEBUG
static void PrintUdpSession(UdpSession *us)
{
    LogMessage("UdpSession:\n");
    LogMessage("    ssn_time:           %lu\n", us->ssn_time.tv_sec);
    LogMessage("    sender IP:          0x%08X\n", us->sender_ip);
    LogMessage("    responder IP:          0x%08X\n", us->responder_ip);
    LogMessage("    sender port:        %d\n", us->sender_port);
    LogMessage("    responder port:        %d\n", us->responder_port);

    LogMessage("    flags:              0x%X\n", us->lwSsn->session_flags);
}
#endif

Stream5LWSession *GetLWUdpSession(SessionKey *key)
{
    return GetLWSessionFromKey(udp_lws_cache, key);
}

void UdpSessionCleanup(Stream5LWSession *ssn)
{
    UdpSession *udpssn = NULL;

    if (ssn->proto_specific_data)
        udpssn = (UdpSession *)ssn->proto_specific_data->data;

    if (!udpssn)
    {
        /* Huh? */
        return;
    }

    /* Cleanup the proto specific data */
    mempool_free(&udp_session_mempool, ssn->proto_specific_data);
    ssn->proto_specific_data = NULL;

    s5stats.udp_sessions_released++;

    RemoveUDPSession(&sfPerf.sfBase);
}

void Stream5CleanUdp()
{
    /* Clean up hash table -- delete all sessions */
    PurgeLWSessionCache(udp_lws_cache);

    mempool_destroy(&udp_session_mempool);
}

static int NewUdpSession(Packet *p,
                         Stream5LWSession *ssn,
                         Stream5UdpPolicy *s5UdpPolicy)
{
    UdpSession *tmp;
    MemBucket *tmpBucket;
    /******************************************************************
     * create new sessions
     *****************************************************************/
    tmpBucket = mempool_alloc(&udp_session_mempool);
    tmp = tmpBucket->data;
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                "Creating new session tracker!\n"););

    tmp->ssn_time.tv_sec = p->pkth->ts.tv_sec;
    tmp->ssn_time.tv_usec = p->pkth->ts.tv_usec;
    ssn->session_flags |= SSNFLAG_SEEN_SENDER;

    tmp->sender_ip = ssn->client_ip;
    tmp->sender_port = ssn->client_port;
    tmp->responder_ip = ssn->server_ip;
    tmp->responder_port = ssn->server_port;

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                "adding UdpSession to lightweight session\n"););
    ssn->proto_specific_data = tmpBucket;
    ssn->protocol = p->iph->ip_proto;
    ssn->direction = FROM_SENDER;
    tmp->lwSsn = ssn;

#ifdef DEBUG_STREAM5
    PrintUdpSession(tmp);
#endif
    Stream5SetExpire(p, ssn, UDP_TIMEOUT);

    s5stats.udp_sessions_created++;

    AddUDPSession(&sfPerf.sfBase);
    return 1;
}


/*
 * Main entry point for UDP
 */
int Stream5ProcessUdp(Packet *p)
{
    Stream5UdpPolicy *s5UdpPolicy = NULL;
    SessionKey skey;
    Stream5LWSession *ssn = NULL;
    int policyIndex;
    char action;

    DEBUG_WRAP(
            DebugMessage((DEBUG_STREAM|DEBUG_STREAM_STATE),
                "Got UDP Packet 0x%X:%d ->  0x%X:%d\n  "
                "dsize: %lu\n"
                "active sessions: %lu\n",
                p->iph->ip_src.s_addr,
                p->sp,
                p->iph->ip_dst.s_addr,
                p->dp,
                p->dsize,
                sfxhash_count(udp_lws_cache->hashTable));
            );

    /* Find an Udp policy for this packet */
    for (policyIndex = 0; policyIndex < numUdpPolicies; policyIndex++)
    {
        s5UdpPolicy = udpPolicyList[policyIndex];
        
        /*
         * Does this policy handle packets to this IP address?
         */
        if(IpAddrSetContains(s5UdpPolicy->bound_addrs, p->iph->ip_dst))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                        "[Stream5] Found udp policy in IpAddrSet\n"););
            break;
        }
        else
        {
            s5UdpPolicy = NULL;
        }
    }

    if (!s5UdpPolicy)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                    "[Stream5] Could not find Udp Policy context "
                    "for IP %s\n", inet_ntoa(p->iph->ip_dst)););
        return 0;
    }

    action = udp_ports[p->sp] | udp_ports[p->dp];

    if (!(action & UDP_SESSION))
    {
        if (!(action & UDP_INSPECT) && (s5UdpPolicy->flags & STREAM5_CONFIG_IGNORE_ANY))
        {
            /* Ignore this UDP packet entirely */
            DisableDetect(p);
            SetPreprocBit(p, PP_SFPORTSCAN);
            SetPreprocBit(p, PP_PERFMONITOR);
            //otn_tmp = NULL;
        }
        return 0;
    }

    /* UDP Sessions required */

    if ((ssn = GetLWSession(udp_lws_cache, p, &skey)) == NULL)
    {
        /* Create a new session, mark SENDER seen */
        ssn = NewLWSession(udp_lws_cache, p, &skey);
        s5stats.total_udp_sessions++;
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Stream5: Retrieved existing session object.\n"););
    }

    if (!ssn)
    {
        LogMessage("Stream5: Failed to retrieve session object.  Out of memory?\n");
        return -1;
    }

    p->ssnptr = ssn;

    /*
     * Check if the session is expired.
     * Should be done before we do something with the packet...
     * ie, Insert a packet, or handle state change SYN, FIN, RST, etc.
     */
    if ((ssn->session_flags & STREAM5_STATE_TIMEDOUT) ||
        Stream5Expire(p, ssn))
    {
        /* Session is timed out */
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Stream5 UDP session timedout!\n"););
    }
    else
    {
        ProcessUdp(ssn, p, s5UdpPolicy);
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Finished Stream5 UDP cleanly!\n"
                    "---------------------------------------------------\n"););
    }
    MarkupPacketFlags(p, ssn);

    return 0;
}

static int ProcessUdp(Stream5LWSession *lwssn, Packet *p,
        Stream5UdpPolicy *s5UdpPolicy)
{
    char ignore = 0;
    UdpSession *udpssn = (UdpSession *)lwssn->proto_specific_data;
    DEBUG_WRAP(
            char *t = NULL;
            char *l = NULL;
            );

    if (lwssn->protocol != IPPROTO_UDP)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Lightweight session not UDP on UDP packet\n"););
        return ACTION_NOTHING;
    }

    if (lwssn->session_flags & (STREAM5_STATE_DROP_CLIENT|STREAM5_STATE_DROP_SERVER))
    {
        /* Got a packet on a session that was dropped (by a rule). */

        /* TODO: Send reset to other side if not already done for inline mode */
        //if (!(ssn->session_flags & STREAM5_STATE_SERVER_RESET)
        //{
        //    Send Server Reset
        //    ssn->session_flags |= STREAM5_STATE_SERVER_RESET;
        //}
        //if (!(ssn->session_flags & STREAM5_STATE_CLIENT_RESET)
        //{
        //    Send Client Reset
        //    ssn->session_flags |= STREAM5_STATE_CLIENT_RESET;
        //}
        /* TODO: Drop this packet */
    }

    if (udpssn == NULL)
    {
        lwssn->direction = FROM_SENDER;
        lwssn->client_ip = p->iph->ip_src.s_addr;
        lwssn->client_port = p->udph->uh_sport;
        lwssn->server_ip = p->iph->ip_dst.s_addr;
        lwssn->server_port = p->udph->uh_dport;
        lwssn->session_state |= STREAM5_STATE_SENDER_SEEN;
        NewUdpSession(p, lwssn, s5UdpPolicy);
        udpssn = (UdpSession *)lwssn->proto_specific_data;
    }

    /* figure out direction of this packet */
    GetPacketDirection(p, lwssn);

    if (((p->packet_flags & PKT_FROM_SERVER) && lwssn->ignoreSessionServer) ||
        ((p->packet_flags & PKT_FROM_CLIENT) && lwssn->ignoreSessionClient))
    {
        Stream5DisableInspection(lwssn, p);
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Stream5 Ignoring packet from %d. "
                    "Session marked as ignore\n",
                    p->packet_flags & PKT_FROM_CLIENT? "sender" : "responder"););
        return ACTION_NOTHING;
    }

    /* Check if the session is to be ignored */
    ignore = CheckIgnoreChannel(p);
    if (ignore)
    {
        /* Check if we should ignore each directions... */
        if (ignore & SSN_DIR_CLIENT)
        {
            lwssn->ignoreSessionServer = 1;
        }
        if (ignore & SSN_DIR_SERVER)
        {
            lwssn->ignoreSessionClient = 1;
        }
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Stream5: Ignoring packet from %d. "
                    "Marking session marked as ignore.\n",
                    p->packet_flags & PKT_FROM_CLIENT? "sender" : "responder"););
        Stream5DisableInspection(lwssn, p);
        return ACTION_NOTHING;
    }

    /* if both seen, mark established */
    if(p->packet_flags & PKT_FROM_SERVER)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Stream5: Updating on packet from responder\n"););
        lwssn->session_flags |= SSNFLAG_SEEN_RESPONDER;

        DEBUG_WRAP(
                t = "Responder";
                l = "Sender");
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Stream5: Updating on packet from client\n"););
        /* if we got here we had to see the SYN already... */
        lwssn->session_flags |= SSNFLAG_SEEN_SENDER;

        DEBUG_WRAP(
                t = "Sender";
                l = "Responder");
    }

    if (!(lwssn->session_flags & SSNFLAG_ESTABLISHED))
    {
        if ((lwssn->session_flags & SSNFLAG_SEEN_SENDER) &&
            (lwssn->session_flags & SSNFLAG_SEEN_RESPONDER))
        {
            lwssn->session_flags |= SSNFLAG_ESTABLISHED;
        }
    }

    return ACTION_NOTHING;
}

void UdpUpdateDirection(Stream5LWSession *ssn, char dir,
                        u_int32_t ip, u_int16_t port)
{
    UdpSession *udpssn = (UdpSession *)ssn->proto_specific_data;
    u_int32_t tmpIp;
    u_int16_t tmpPort;

    if ((udpssn->sender_ip == ip) && (udpssn->sender_port == port))
    {
        if ((dir == SSN_DIR_SENDER) && (ssn->direction == SSN_DIR_SENDER))
        {
            /* Direction already set as SENDER */
            return;
        }
    }
    else if ((udpssn->responder_ip == ip) && (udpssn->responder_port == port))
    {
        if ((dir == SSN_DIR_RESPONDER) && (ssn->direction == SSN_DIR_RESPONDER))
        {
            /* Direction already set as RESPONDER */
            return;
        }
    }

    /* Swap them -- leave ssn->direction the same */

    /* XXX: Gotta be a more efficient way to do this without the memcpy */
    tmpIp = udpssn->sender_ip;
    tmpPort = udpssn->sender_port;
    udpssn->sender_ip = udpssn->responder_ip;
    udpssn->sender_port = udpssn->responder_port;
    udpssn->responder_ip = tmpIp;
    udpssn->responder_port = tmpPort;
}
