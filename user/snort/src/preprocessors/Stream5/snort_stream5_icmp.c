#include "debug.h"
#include "decode.h"
#include "sfxhash.h"
#include "util.h"
#include "stream5_common.h"
#include "snort_stream5_session.h"

#include "snort_stream5_tcp.h"
#include "snort_stream5_udp.h"

#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats s5IcmpPerfStats;
#endif

/*  D A T A  S T R U C T U R E S  ***********************************/
typedef struct _IcmpSession
{
    Stream5LWSession *lwSsn;

    u_int32_t   sender_ip;
    u_int32_t   responder_ip;
    u_int32_t   echo_count;

    struct timeval ssn_time;

    u_int32_t   expire_time;
} IcmpSession;

/*  G L O B A L S  **************************************************/
static Stream5SessionCache *icmp_lws_cache;
static MemPool icmp_session_mempool;

/*  P R O T O T Y P E S  ********************************************/
static int ProcessIcmpUnreach(Packet *p);
static int ProcessIcmpEcho(Packet *p);

void Stream5InitIcmp()
{
    /* Finally ICMP */ 
    if((icmp_lws_cache == NULL) && s5_global_config.track_icmp_sessions)
    {
        icmp_lws_cache = InitLWSessionCache(s5_global_config.max_icmp_sessions,
                30, 5, 0, NULL);

        if(!icmp_lws_cache)
        {
            LogMessage("Unable to init stream5 ICMP session cache, no ICMP "
                       "stream inspection!\n");
            s5_global_config.track_icmp_sessions = 0;
            s5_global_config.max_icmp_sessions = 0;
            return;
        }

        mempool_init(&icmp_session_mempool, s5_global_config.max_icmp_sessions, sizeof(IcmpSession));
    }
}

void IcmpSessionCleanup(Stream5LWSession *ssn)
{
    IcmpSession *icmpssn = NULL;
    
    if (ssn->proto_specific_data)
        icmpssn = ssn->proto_specific_data->data;

    if (!icmpssn)
    {
        /* Huh? */
        return;
    }

    /* Cleanup the proto specific data */
    mempool_free(&icmp_session_mempool, ssn->proto_specific_data);
    ssn->proto_specific_data = NULL;

    s5stats.icmp_sessions_released++;
}

void Stream5CleanIcmp()
{
    /* Clean up hash table -- delete all sessions */
    PurgeLWSessionCache(icmp_lws_cache);
}

int Stream5VerifyIcmpConfig()
{
    if (!icmp_lws_cache)
        return -1;

    mempool_destroy(&icmp_session_mempool);

    return 0;
}

int Stream5ProcessIcmp(Packet *p)
{
    switch (p->icmph->type)
    {
    case ICMP_DEST_UNREACH:
        return ProcessIcmpUnreach(p);
        break;
    case ICMP_ECHO:
    case ICMP_ECHOREPLY:
        return ProcessIcmpEcho(p);
        break;
    default:
        /* We only handle the above ICMP messages with stream5 */
        break;
    }
    
    return 0;
}

static int ProcessIcmpUnreach(Packet *p)
{
    /* Handle ICMP unreachable */
    SessionKey skey;
    Stream5LWSession *ssn = NULL;
    u_int16_t sport;
    u_int16_t dport;

    /* No "orig" IP Header */
    if (!p->orig_iph)
        return 0;

    /* Get TCP/UDP/ICMP session from original protocol/port info
     * embedded in the ICMP Unreach message.  This is already decoded
     * in p->orig_foo.  TCP/UDP ports are decoded as p->orig_sp/dp.
     */
    skey.protocol = p->orig_iph->ip_proto;
    sport = p->orig_sp;
    dport = p->orig_dp;

    if (p->orig_iph->ip_src.s_addr < p->orig_iph->ip_dst.s_addr)
    {
        skey.ip_l = p->orig_iph->ip_src.s_addr;
        skey.port_l = sport;
        skey.ip_h = p->orig_iph->ip_dst.s_addr;
        skey.port_h = dport;
    }
    else if (p->orig_iph->ip_dst.s_addr == p->orig_iph->ip_src.s_addr)
    {
        skey.ip_l = p->orig_iph->ip_src.s_addr;
        skey.ip_h = p->orig_iph->ip_src.s_addr;
        if (sport < dport)
        {
            skey.port_l = sport;
            skey.port_h = dport;
        }
        else
        {
            skey.port_l = dport;
            skey.port_h = sport;
        }
    }
    else
    {
        skey.ip_l = p->orig_iph->ip_dst.s_addr;
        skey.port_l = dport;
        skey.ip_h = p->orig_iph->ip_src.s_addr;
        skey.port_h = sport;
    }

    if (p->vh)
        skey.vlan_tag = VTH_VLAN(p->vh);
    else
        skey.vlan_tag = 0;

    switch (skey.protocol)
    {
    case IPPROTO_TCP:
        /* Lookup a TCP session */
        ssn = GetLWTcpSession(&skey);
        break;
    case IPPROTO_UDP:
        /* Lookup a UDP session */
        ssn = GetLWUdpSession(&skey);
        break;
    case IPPROTO_ICMP:
        /* Lookup a ICMP session */
        ssn = GetLWSessionFromKey(icmp_lws_cache, &skey);
        break;
    }

    if (ssn)
    {
        /* Mark this session as dead. */
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Marking session as dead, per ICMP Unreachable!\n"););
        ssn->session_flags |= STREAM5_STATE_DROP_CLIENT;
        ssn->session_flags |= STREAM5_STATE_DROP_SERVER;
        ssn->session_flags |= STREAM5_STATE_UNREACH;
    }

    return 0;
}

static int ProcessIcmpEcho(Packet *p)
{
    //SessionKey skey;
    Stream5LWSession *ssn = NULL;

    return 0;
}

void IcmpUpdateDirection(Stream5LWSession *ssn, char dir,
                        u_int32_t ip, u_int16_t port)
{
    IcmpSession *icmpssn = ssn->proto_specific_data->data;
    u_int32_t tmpIp;

    if (!icmpssn)
    {
        /* Huh? */
        return;
    }

    if (icmpssn->sender_ip == ip)
    {
        if ((dir == SSN_DIR_SENDER) && (ssn->direction == SSN_DIR_SENDER))
        {
            /* Direction already set as SENDER */
            return;
        }
    }
    else if (icmpssn->responder_ip == ip)
    {
        if ((dir == SSN_DIR_RESPONDER) && (ssn->direction == SSN_DIR_RESPONDER))
        {
            /* Direction already set as RESPONDER */
            return;
        }
    }

    /* Swap them -- leave ssn->direction the same */

    /* XXX: Gotta be a more efficient way to do this without the memcpy */
    tmpIp = icmpssn->sender_ip;
    icmpssn->sender_ip = icmpssn->responder_ip;
    icmpssn->responder_ip = tmpIp;
}

