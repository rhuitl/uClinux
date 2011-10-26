#include "debug.h"
#include "decode.h"
#include "generators.h"
#include "event_queue.h"
#include "snort.h"

#include "stream5_common.h"

/*  M A C R O S  **************************************************/
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

INLINE u_int32_t CalcJiffies(Packet *p)
{
    return (p->pkth->ts.tv_sec * TCP_HZ) + 
           (p->pkth->ts.tv_usec / (1000000UL/TCP_HZ));
}

int Stream5Expire(Packet *p, Stream5LWSession *ssn)
{
    u_int32_t pkttime = CalcJiffies(p);

    if (ssn->expire_time == 0)
    {
        /* Not yet set, not expired */
        return 0;
    }
    
    if((int)(pkttime - ssn->expire_time) > 0)
    {
        sfPerf.sfBase.iStreamTimeouts++;
        ssn->session_flags |= STREAM5_STATE_TIMEDOUT;

        switch (ssn->protocol)
        {
            case IPPROTO_TCP:
                s5stats.tcp_timeouts++;
                //DeleteLWSession(tcp_lws_cache, ssn);
                break;
            case IPPROTO_UDP:
                s5stats.udp_timeouts++;
                //DeleteLWSession(udp_lws_cache, ssn);
                break;
            case IPPROTO_ICMP:
                s5stats.icmp_timeouts++;
                //DeleteLWSession(icmp_lws_cache, ssn);
                break;
        }
        return 1;
    }

    return 0;
}

void Stream5SetExpire(Packet *p, 
        Stream5LWSession *ssn, u_int32_t timeout)
{
    ssn->expire_time = CalcJiffies(p) + timeout;
    return;
}

void MarkupPacketFlags(Packet *p, Stream5LWSession *ssn)
{
    if(!ssn)
        return;

    if((ssn->session_flags & SSNFLAG_ESTABLISHED) != SSNFLAG_ESTABLISHED)
    {
        if((ssn->session_flags & (SSNFLAG_SEEN_SERVER|SSNFLAG_SEEN_CLIENT)) ==
            (SSNFLAG_SEEN_SERVER|SSNFLAG_SEEN_CLIENT))
        {
            p->packet_flags |= PKT_STREAM_UNEST_BI;
        }
        else
        {
            p->packet_flags |= PKT_STREAM_UNEST_UNI;
        }
    }
    else
    {
        p->packet_flags |= PKT_STREAM_EST;
        if(p->packet_flags & PKT_STREAM_UNEST_UNI)
        {
            p->packet_flags ^= PKT_STREAM_UNEST_UNI;
        }
    }
}

