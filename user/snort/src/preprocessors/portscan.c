/*
**  @file       portscan.c
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      Detect portscans
**
**  NOTES
**    - Marc Norton and Jeremy Hewlett were involved in the requirements and
**      design of this portscan detection engine.
**    - Thanks to Judy Novak for her suggestion to log open ports
**      on hosts that are portscanned.  This idea makes portscan a lot more
**      useful for analysts.
**
**  The philosophy of portscan detection that we use is based on a generic
**  network attack methodology: reconnaissance, network service enumeration,
**  and service exploitation.
**
**  The reconnaissance phase determines what types of network protocols and
**  services that a host supports.  This is the traditional phase where a
**  portscan occurs.  An important requirement of this phase is that an
**  attacker does not already know what protocols and services are supported
**  by the destination host.  If an attacker does know what services are
**  open on the destination host then there is no need for this phase.
**  Because of this requirement, we assume that if an attacker engages in this
**  phase that they do not have prior knowledege to what services are open.
**  So, the attacker will need to query the ports or protocols they are
**  interested in.  Most or at least some of these queries will be negative
**  and take the form of either an invalid response (TCP RSTs, ICMP
**  unreachables) or no response (in which case the host is firewalled or
**  filtered).  We detect portscans from these negative queries.
**  
**  The primary goal of this portscan detection engine is to catch nmap and
**  variant scanners.  The engine tracks connection attempts on TCP, UDP,
**  ICMP, and IP Protocols.  If there is a valid response, the connection
**  is marked as valid.  If there is no response or a invalid response
**  (TCP RST), then we track these attempts separately, so we know the
**  number of invalid responses and the number of connection attempts that
**  generated no response.  These two values differentiate between a
**  normal scan and a filtered scan.
**
**  We detect four different scan types, and each scan type has its own
**  negative query characteristics.  This is how we determine what type
**  of scan we are seeing.  The different scans are:
**
**    - Portscan
**    - Decoy Portscan
**    - Distributed Portscan
**    - Portsweep
**
**  Portscan:  A portscan is a basic one host to one host scan where
**  multiple ports are scanned on the destination host.  We detect these
**  scans by looking for a low number of hosts that contacted the
**  destination host and a high number of unique ports and a high number
**  of invalid responses or connections.
**
**  Distributed Portscan:  A distributed portscan occurs when many hosts
**  connect to a single destination host and multiple ports are scanned
**  on the destination host.  We detect these scans by looking for a high
**  number of hosts that contacted the destination host and a high number
**  of unique ports with a high number of invalid responses or connections.
**
**  Decoy Portscan:  A decoy portscan is a variation on a distributed
**  portscan, the difference being that a decoy portscan connects to a
**  single port multiple times.  This shows up in the unqiue port count that
**  is tracked.  There's still many hosts connecting to the destination host.
**
**  Portsweep:  A portsweep is a basic one host to many host scan where
**  one to a few ports are scanned on each host.  We detect these scans by
**  looking at src hosts for a high number of contacted hosts and a low
**  number of unique ports with a high number of invalid responses or
**  connections.
**
**  Each of these scans can also be detected as a filtered portscan, or a
**  portscan where there wasn't invalid responses and the responses have
**  been firewalled in some way.
** 
*/
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifndef WIN32
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
#endif /* !WIN32 */

#include "portscan.h"
#include "decode.h"
#include "packet_time.h"
#include "sfxhash.h"
#include "ipobj.h"
#include "flow.h"
#include "stream_api.h"

typedef struct s_PS_INIT
{
    int detect_scans;
    int detect_scan_type;
    int sense_level;
    int proto_cnt;
    IPSET *ignore_scanners;
    IPSET *ignore_scanned;
    IPSET *watch_ip;

} PS_INIT;

typedef struct s_PS_HASH_KEY
{
    unsigned long scanner;
    unsigned long scanned;

} PS_HASH_KEY;

typedef struct s_PS_ALERT_CONF
{
    short connection_count;
    short priority_count;
    short u_ip_count;
    short u_port_count;

} PS_ALERT_CONF;

static int      g_ps_tracker_size;
static PS_INIT  g_ps_init;
static SFXHASH *g_hash;

extern int g_include_midstream;

/*
**  Scanning configurations.  This is where we configure what the thresholds
**  are for the different types of scans, protocols, and sense levels.  If
**  you want to tweak the sense levels, change the values here.
*/
/*
**  TCP alert configurations
*/
static PS_ALERT_CONF g_tcp_low_ps =       {0,5,25,5};
static PS_ALERT_CONF g_tcp_low_decoy_ps = {0,15,50,30};
static PS_ALERT_CONF g_tcp_low_sweep =    {0,5,5,15};
static PS_ALERT_CONF g_tcp_low_dist_ps =  {0,15,50,15};

static PS_ALERT_CONF g_tcp_med_ps =       {200,10,60,15};
static PS_ALERT_CONF g_tcp_med_decoy_ps = {200,30,120,60};
static PS_ALERT_CONF g_tcp_med_sweep =    {30,7,7,10};
static PS_ALERT_CONF g_tcp_med_dist_ps =  {200,30,120,30};

static PS_ALERT_CONF g_tcp_hi_ps =        {200,5,100,10};
static PS_ALERT_CONF g_tcp_hi_decoy_ps =  {200,7,200,60};
static PS_ALERT_CONF g_tcp_hi_sweep =     {30,3,3,10};
static PS_ALERT_CONF g_tcp_hi_dist_ps =   {200,5,200,10};

/*
**  UDP alert configurations
*/
static PS_ALERT_CONF g_udp_low_ps =       {0,5,25,5};
static PS_ALERT_CONF g_udp_low_decoy_ps = {0,15,50,30};
static PS_ALERT_CONF g_udp_low_sweep =    {0,5,5,15};
static PS_ALERT_CONF g_udp_low_dist_ps =  {0,15,50,15};

static PS_ALERT_CONF g_udp_med_ps =       {200,10,60,15};
static PS_ALERT_CONF g_udp_med_decoy_ps = {200,30,120,60};
static PS_ALERT_CONF g_udp_med_sweep =    {30,5,5,20};
static PS_ALERT_CONF g_udp_med_dist_ps =  {200,30,120,30};

static PS_ALERT_CONF g_udp_hi_ps =        {200,3,100,10};
static PS_ALERT_CONF g_udp_hi_decoy_ps =  {200,7,200,60};
static PS_ALERT_CONF g_udp_hi_sweep =     {30,3,3,10};
static PS_ALERT_CONF g_udp_hi_dist_ps =   {200,3,200,10};

/*
**  IP Protocol alert configurations
*/
static PS_ALERT_CONF g_ip_low_ps =        {0,10,10,50};
static PS_ALERT_CONF g_ip_low_decoy_ps =  {0,40,50,25};
static PS_ALERT_CONF g_ip_low_sweep =     {0,10,10,10};
static PS_ALERT_CONF g_ip_low_dist_ps =   {0,15,25,50};

static PS_ALERT_CONF g_ip_med_ps =        {200,10,10,50};
static PS_ALERT_CONF g_ip_med_decoy_ps =  {200,40,50,25};
static PS_ALERT_CONF g_ip_med_sweep =     {30,10,10,10};
static PS_ALERT_CONF g_ip_med_dist_ps =   {200,15,25,50};

static PS_ALERT_CONF g_ip_hi_ps =         {200,3,3,10};
static PS_ALERT_CONF g_ip_hi_decoy_ps =   {200,7,15,5};
static PS_ALERT_CONF g_ip_hi_sweep =      {30,3,3,7};
static PS_ALERT_CONF g_ip_hi_dist_ps =    {200,3,11,10};

/*
**  ICMP alert configurations
*/
static PS_ALERT_CONF g_icmp_low_sweep =   {0,5,5,5};
static PS_ALERT_CONF g_icmp_med_sweep =   {20,5,5,5};
static PS_ALERT_CONF g_icmp_hi_sweep =    {10,3,3,5};

/*
**  NAME
**    ps_tracker_free::
*/
/**
**  This function is passed into the hash algorithm, so that
**  we only reuse nodes that aren't priority nodes.  We have to make
**  sure that we only track so many priority nodes, otherwise we could
**  have all priority nodes and not be able to allocate more.
*/
static int ps_tracker_free(void *key, void *data)
{
    PS_TRACKER *tracker;
    int         iCtr;
    time_t      pkt_time;

    if(!key || !data)
        return 0;

    tracker = (PS_TRACKER *)data;
    if(!tracker->priority_node)
        return 0;

    /*
    **  Cycle through the protos to see if it's past the time.
    **  We only get here if we ARE a priority node.
    */
    pkt_time = packet_timeofday();
    for(iCtr = 0; iCtr < g_ps_init.proto_cnt; iCtr++)
    {
        if(tracker->proto[iCtr].window >= pkt_time)
            return 1;
    }

    return 0;
}

/*
**  NAME
**    ps_init::
*/
/*
**  Initialize the portscan infrastructure.  We check to make sure that
**  we have enough memory to support at least 100 nodes.
** 
**  @return int
**  
**  @retval -2 memcap is too low
*/
int ps_init(int detect_scans, int detect_scan_type, int sense_level,
        IPSET *scanner, IPSET *scanned, IPSET *watch, int memcap)
{
    int proto_cnt = 0;
    int datasize;

    proto_cnt += ((detect_scans & PS_PROTO_TCP)  ? 1 : 0);
    proto_cnt += ((detect_scans & PS_PROTO_UDP)  ? 1 : 0);
    proto_cnt += ((detect_scans & PS_PROTO_ICMP) ? 1 : 0);
    proto_cnt += ((detect_scans & PS_PROTO_IP)   ? 1 : 0);

    if(!proto_cnt)
        return -1;

   if(!(detect_scan_type & PS_TYPE_ALL)) 
       return -1;

   if(sense_level < 1 || sense_level > 3)
       return -1;

   /*
   **  Set the datasize that the hash will be keeping track of.  This
   **  changes dynamically based on the number of protocols that we are
   **  tracking.
   */
   datasize = sizeof(PS_TRACKER) + (sizeof(PS_PROTO)*(proto_cnt - 1));

   if(memcap <= 0 || memcap < (datasize * 100))
       return -2;

   g_hash = sfxhash_new(50000, sizeof(PS_HASH_KEY), datasize, 
           memcap, 1, ps_tracker_free, NULL, 1);

   if(!g_hash)
       return -1;

   g_ps_init.detect_scans     = detect_scans;
   g_ps_init.detect_scan_type = detect_scan_type;
   g_ps_init.sense_level      = sense_level;
   g_ps_init.ignore_scanners  = scanner;
   g_ps_init.ignore_scanned   = scanned;
   g_ps_init.watch_ip         = watch;

   g_ps_tracker_size = datasize;

   return 0;
}

/*
**  NAME
**    ps_ignore_ip::
*/
/**
**  Check scanner and scanned ips to see if we can filter them out.
*/
static int ps_ignore_ip(unsigned long scanner, unsigned short scanner_port,
                        unsigned long scanned, unsigned short scanned_port)
{
    if(g_ps_init.ignore_scanners)
    {
        if(ipset_contains(g_ps_init.ignore_scanners, &scanner, &scanner_port, IPV4_FAMILY))
            return 1;
    }

    if(g_ps_init.ignore_scanned)
    {
        if(ipset_contains(g_ps_init.ignore_scanned, &scanned, &scanned_port, IPV4_FAMILY))
            return 1;
    }

    return 0;
}

/*
**  NAME
**    ps_filter_ignore::
*/
/**
**  Check the incoming packet to decide whether portscan detection cares
**  about this packet.  We try to ignore as many packets as possible.
*/
static int ps_filter_ignore(PS_PKT *ps_pkt)
{
    Packet  *p;
    FLOW    *flow;
    int      reverse_pkt = 0;
    unsigned long scanner;
    unsigned long scanned;

    p = (Packet *)ps_pkt->pkt;

    if(!p->iph)
        return 1;

    if(p->tcph)
    {
        if(!(g_ps_init.detect_scans & PS_PROTO_TCP))
            return 1;
   
        /*
        **  This is where we check all of snort's flags for different
        **  TCP session scenarios.  The checks cover:
        **
        **    - dropping packets in established sessions, but not the
        **      TWH packet.
        **    - dropping the SYN/ACK packet from the server on a valid
        **      connection (we'll catch the TWH later if it happens).
        */
        /*
        **  Ignore packets that are already part of an established TCP
        **  stream. 
        */
        if(((p->packet_flags & (PKT_STREAM_EST | PKT_STREAM_TWH)) 
                == PKT_STREAM_EST) && !(p->tcph->th_flags & TH_RST))
        {
            return 1;
        }

        /*
        **  Ignore the server's initial response, unless it's to RST
        **  the connection.
        */
        /*
        if(!(p->tcph->th_flags & TH_RST) &&
           !(p->packet_flags & (PKT_STREAM_EST)) &&
            (p->packet_flags & PKT_FROM_SERVER))
        {
            return 1;
        }
        */
    }
    else if(p->udph)
    {
        if(!(g_ps_init.detect_scans & PS_PROTO_UDP))
            return 1;
    }
    else if(p->icmph)
    {
        if(p->icmph->type != ICMP_DEST_UNREACH &&
           !(g_ps_init.detect_scans & PS_PROTO_ICMP))
        {
            return 1;
        }
    }
    else
    {
        if(!(g_ps_init.detect_scans & PS_PROTO_IP))
            return 1;
    }

    /*
    **  Check if the packet is reversed
    */
    if((p->packet_flags & PKT_FROM_SERVER))
    {
        reverse_pkt = 1;
    }
    else if(p->icmph && p->icmph->type == ICMP_DEST_UNREACH)
    {
        reverse_pkt = 1;
    }
    else if((p->udph || p->iph) && p->flow)
    {
        flow = (FLOW *)p->flow;
        if(flow->stats.direction == FROM_RESPONDER)
            reverse_pkt = 1;
    }

    scanner = ntohl(p->iph->ip_src.s_addr);
    scanned = ntohl(p->iph->ip_dst.s_addr);
    
    if(reverse_pkt)
    {
        if(ps_ignore_ip(scanned, p->dp, scanner, p->sp))
            return 1;
    }
    else
    {
        if(ps_ignore_ip(scanner, p->sp, scanned, p->dp))
            return 1;
    }
    
    ps_pkt->reverse_pkt = reverse_pkt;

    if(g_ps_init.watch_ip)
    {
        if(ipset_contains(g_ps_init.watch_ip, &scanner, &(p->sp), IPV4_FAMILY))
            return 0;

        if(ipset_contains(g_ps_init.watch_ip, &scanned, &(p->dp), IPV4_FAMILY))
            return 0;

        return 1;
    }

    return 0;
}

/*
**  NAME
**    ps_tracker_init::
*/
/**
**  Right now all we do is memset, but just in case we want to do more
**  initialization has been extracted.
*/
static int ps_tracker_init(PS_TRACKER *tracker)
{
    memset(tracker, 0x00, g_ps_tracker_size);

    return 0;
}

/*
**  NAME
**    ps_tracker_get::
*/
/**
**  Get a tracker node by either finding one or starting a new one.  We may
**  return NULL, in which case we wait till the next packet.
*/
static int ps_tracker_get(PS_TRACKER **ht, PS_HASH_KEY *key)
{
    int iRet;

    *ht = (PS_TRACKER *)sfxhash_find(g_hash, (void *)key);
    if(!(*ht))
    {
        iRet = sfxhash_add(g_hash, (void *)key, NULL);
        if(iRet == SFXHASH_OK)
        {
            *ht = (PS_TRACKER *)sfxhash_mru(g_hash);
            if(!(*ht))
                return -1;

            ps_tracker_init(*ht);
        }
        else
        {
            return -1;
        }
    }

    return 0;
}

static int ps_tracker_lookup(PS_PKT *ps_pkt, PS_TRACKER **scanner,
                             PS_TRACKER **scanned)
{
    PS_HASH_KEY key;
    Packet     *p;

    if(!ps_pkt->pkt)
        return -1;

    p = (Packet *)ps_pkt->pkt;

    /*
    **  Let's lookup the host that is being scanned, taking into account
    **  the pkt may be reversed.
    */
    if(g_ps_init.detect_scan_type & 
            (PS_TYPE_PORTSCAN | PS_TYPE_DECOYSCAN | PS_TYPE_DISTPORTSCAN))
    {
        key.scanner = 0;
        
        if(ps_pkt->reverse_pkt)
            key.scanned = p->iph->ip_src.s_addr;
        else
            key.scanned = p->iph->ip_dst.s_addr;

        /*
        **  Get the scanned tracker.
        */
        if(ps_tracker_get(scanned, &key))
            return -1;
    }

    /*
    **  Let's lookup the host that is scanning.
    */
    if(g_ps_init.detect_scan_type & PS_TYPE_PORTSWEEP)
    {
        key.scanned = 0;
        
        if(ps_pkt->reverse_pkt)
            key.scanner = p->iph->ip_dst.s_addr;
        else
            key.scanner = p->iph->ip_src.s_addr;

        /*
        **  Get the scanner tracker
        */
        if(ps_tracker_get(scanner, &key))
            return -1;
    }

    return 0;
}

/*
**  NAME
**    ps_get_proto_index::
*/
/**
**  This logic finds the index to the proto array based on the
**  portscan configuration.  We need special logic because the 
**  index of the protocol changes based on the configuration.
*/
static int ps_get_proto_index(PS_PKT *ps_pkt, int *proto_index, int *proto)
{
    Packet *p;
    int     found = 0;

    if(!ps_pkt || !ps_pkt->pkt || !proto_index || !proto)
        return -1;

    p = (Packet *)ps_pkt->pkt;
    *proto_index = 0;
    *proto = 0;

    if(!found && g_ps_init.detect_scans & PS_PROTO_TCP)
    {
        if(p->tcph) 
        {
            found = 1;
            *proto = PS_PROTO_TCP;
        }
        else if(p->icmph && p->icmph->type == ICMP_DEST_UNREACH &&
                p->icmph->code == ICMP_PORT_UNREACH && p->orig_tcph)
        {
            found = 1;
            *proto = PS_PROTO_TCP;
        }
        else 
        {
            (*proto_index)++;
        }
    }

    if(!found && g_ps_init.detect_scans & PS_PROTO_UDP)
    {
        if(p->udph)
        { 
            found = 1;
            *proto = PS_PROTO_UDP;
        }
        else if(p->icmph && p->icmph->type == ICMP_DEST_UNREACH &&
                p->icmph->code == ICMP_PORT_UNREACH && p->orig_udph)
        {
            found = 1;
            *proto = PS_PROTO_UDP;
        }
        else 
        {
            (*proto_index)++;
        }
    }

    if(!found && g_ps_init.detect_scans & PS_PROTO_IP)
    {
        if(p->iph && !p->icmph)
        {
            found = 1;
            *proto = PS_PROTO_IP;
        }
        else if(p->icmph && p->icmph->type == ICMP_DEST_UNREACH &&
                p->icmph->code == ICMP_PROT_UNREACH)
        {
            found = 1;
            *proto = PS_PROTO_IP;
        }
        else
        {
            (*proto_index)++;
        }
    }

    if(!found && g_ps_init.detect_scans & PS_PROTO_ICMP)
    {
        if(p->icmph) 
        {
            found = 1;
            *proto = PS_PROTO_ICMP;
        }
        else 
        {
            (*proto_index)++;
        }
    }

    if(!found)
    {
        *proto = 0;
        *proto_index = 0;
        return -1;
    }

    return 0;
}

/*
**  NAME
**    ps_proto_update_window::
*/
/**
**  Update the proto time windows based on the portscan sensitivity
**  level.
*/
static int ps_proto_update_window(PS_PROTO *proto, time_t pkt_time)
{
    time_t interval;

    switch(g_ps_init.sense_level)
    {
        case PS_SENSE_LOW:
            //interval = 15;
            interval = 60;
            break;

        case PS_SENSE_MEDIUM:
            //interval = 15;
            interval = 90;
            break;

        case PS_SENSE_HIGH:
            interval = 600;
            break;

        default:
            return -1;
    }

    /*
    **  If we are outside of the window, reset our ps counters.
    */
    if(pkt_time > proto->window)
    {
        memset(proto, 0x00, sizeof(PS_PROTO));

        proto->window = pkt_time + interval;

        return 0;
    }

    return 0;
}

/*
**  NAME
**    ps_proto_update::
*/
/**
**  This function updates the PS_PROTO structure.
**
**  @param PS_PROTO pointer to structure to update
**  @param int      number to increment portscan counter
**  @param u_long   IP address of other host
**  @param u_short  port/ip_proto to track
**  @param time_t   time the packet was received. update windows.
*/
static int ps_proto_update(PS_PROTO *proto, int ps_cnt, int pri_cnt, u_long ip,
        u_short port, time_t pkt_time)
{
    if(!proto)
        return 0;

    /*
    **  If the ps_cnt is negative, that means we are just taking off
    **  for valid connection, and we don't want to do anything else,
    **  like update ip/port, etc.
    */
    if(ps_cnt < 0)
    {
        proto->connection_count += ps_cnt;
        if(proto->connection_count < 0)
            proto->connection_count = 0;

        return 0;
    }

    /*
    **  If we are updating a priority cnt, it means we already did the
    **  unique port and IP on the connection packet.
    **
    **  Priority points are only added for invalid response packets.
    */
    if(pri_cnt)
    {
        proto->priority_count += pri_cnt;
        if(proto->priority_count < 0)
            proto->priority_count = 0;

        return 0;
    }

    /*
    **  Do time check first before we update the counters, so if
    **  we need to reset them we do it before we update them.
    */
    if(ps_proto_update_window(proto, pkt_time))
        return -1;

    /*
    **  Update ps counter
    */
    proto->connection_count += ps_cnt;
    if(proto->connection_count < 0)
        proto->connection_count = 0;

    if(proto->u_ips != ip)
    {
        proto->u_ip_count++;
        proto->u_ips = ip;
    }

    if(proto->low_ip)
    {
        if(proto->low_ip > ip)
            proto->low_ip = ip;
    }
    else
    {
        proto->low_ip = ip;
    }

    if(proto->high_ip)
    {
        if(proto->high_ip < ip)
            proto->high_ip = ip;
    }
    else
    {
        proto->high_ip = ip;
    }

    if(proto->u_ports != port)
    {
        proto->u_port_count++;
        proto->u_ports = port;
    }
    
    if(proto->low_p)
    {
        if(proto->low_p > port)
            proto->low_p = port;
    }
    else
    {
        proto->low_p = port;
    }

    if(proto->high_p)
    {
        if(proto->high_p < port)
            proto->high_p = port;
    }
    else
    {
        proto->high_p = port;
    }

    return 0;
}

static int ps_update_open_ports(PS_PROTO *proto, unsigned short port)
{
    int iCtr;
    
    for(iCtr = 0; iCtr < proto->open_ports_cnt; iCtr++)
    {
        if(port == proto->open_ports[iCtr])
            return 0;
    }
    
    if(iCtr < (PS_OPEN_PORTS - 1))
    {
        proto->open_ports[iCtr] = port;
        proto->open_ports_cnt++;

        if(proto->alerts == PS_ALERT_GENERATED)
        {
            proto->alerts = PS_ALERT_OPEN_PORT;
        }
    }

    return 0;
}
    
/*
**  NAME
**    ps_tracker_update_tcp::
*/
/**
**  Determine how to update the portscan counter depending on the type
**  of TCP packet we have.
**
**  We are concerned with three types of TCP packets:
**  
**    - initiating TCP packets (we don't care about flags)
**    - TCP 3-way handshake packets (we decrement the counter)
**    - TCP reset packets on unestablished streams.
*/
static int ps_tracker_update_tcp(PS_PKT *ps_pkt, PS_TRACKER *scanner,
        PS_TRACKER *scanned, int proto_idx)
{
    Packet  *p;
    time_t  pkt_time;
    FLOW    *flow;
    u_int32_t session_flags;
    
    p = (Packet *)ps_pkt->pkt;
    pkt_time = packet_timeofday();

    flow = (FLOW *)p->flow;

    /*
    **  Handle the initiating packet.
    **
    **  If this what stream4 considers to be a valid initiator, then
    **  we will use the available stream4 information.  Otherwise, we
    **  can just revert to flow and look for initiators and responders.
    **
    **  The "midstream" logic below says that, if we include sessions
    **  picked up midstream, then we don't care about the MIDSTREAM flag.
    **  Otherwise, only consider streams not picked up midstream.
    */
    if(p->ssnptr && stream_api)
    {
        session_flags = stream_api->get_session_flags(p->ssnptr);

        if((session_flags & SSNFLAG_SEEN_CLIENT) && 
           !(session_flags & SSNFLAG_SEEN_SERVER) &&
           (g_include_midstream || !(session_flags & SSNFLAG_MIDSTREAM)))
        {
            if(scanned)
            {
                ps_proto_update(&scanned->proto[proto_idx],1,0,
                                 p->iph->ip_src.s_addr,p->dp, pkt_time);
            }

            if(scanner)
            {
                ps_proto_update(&scanner->proto[proto_idx],1,0,
                                 p->iph->ip_dst.s_addr,p->dp, pkt_time);
            }
        }
        /*
        **  Handle the final packet of the three-way handshake.
        */
        else if(p->packet_flags & PKT_STREAM_TWH)
        {
            if(scanned)
                ps_proto_update(&scanned->proto[proto_idx],-1,0,0,0,0);

            if(scanner)
                ps_proto_update(&scanner->proto[proto_idx],-1,0,0,0,0);
        }
        /*
        **  RST packet on unestablished streams
        */
        else if((p->packet_flags & PKT_FROM_SERVER) &&
                (p->tcph->th_flags & TH_RST) &&
                (!(p->packet_flags & PKT_STREAM_EST) ||
                (session_flags & SSNFLAG_MIDSTREAM)))
        {
            if(scanned)
            {
                ps_proto_update(&scanned->proto[proto_idx],0,1,0,0,0);
                scanned->priority_node = 1;
            }

            if(scanner)
            {
                ps_proto_update(&scanner->proto[proto_idx],0,1,0,0,0);
                scanner->priority_node = 1;
            }
        }
        /*
        **  We only get here on the server's response to the intial
        **  client connection.
        **
        **  That's why we use the sp, because that's the port that is
        **  open.
        */
        else if((p->packet_flags & PKT_FROM_SERVER) &&
                !(p->packet_flags & PKT_STREAM_EST))
        {
            if(scanned)
                ps_update_open_ports(&scanned->proto[proto_idx], p->sp);
        
            if(scanner)
            {
                if(scanner->proto[proto_idx].alerts == PS_ALERT_GENERATED)
                    scanner->proto[proto_idx].alerts = PS_ALERT_OPEN_PORT;
            }
        }
    }
    /*
    **  If we are an icmp unreachable, deal with it here.
    */
    else if(p->icmph && p->orig_tcph)
    {
        if(scanned)
        {
            ps_proto_update(&scanned->proto[proto_idx],0,1,0,0,0);
            scanned->priority_node = 1;
        }

        if(scanner)
        {
            ps_proto_update(&scanner->proto[proto_idx],0,1,0,0,0);
            scanner->priority_node = 1;
        }
    }
    /*
    **  If we're none of the above, revert to flow to do some basic
    **  processing.  This means that the TCP packet we got is not
    **  considered a valid initiator, so we didn't start a stream
    **  tracker.
    */
    else if(flow)
    {
        if(flow->stats.direction == FROM_INITIATOR)
        {
            if(scanned)
            {
                ps_proto_update(&scanned->proto[proto_idx],1,0,
                                 p->iph->ip_src.s_addr,p->dp, pkt_time);
            }

            if(scanner)
            {
                ps_proto_update(&scanner->proto[proto_idx],1,0,
                                 p->iph->ip_dst.s_addr,p->dp, pkt_time);
            }
        }
        else if(flow->stats.direction == FROM_RESPONDER &&
                (p->tcph->th_flags & TH_RST))
        {
            if(scanned)
            {
                ps_proto_update(&scanned->proto[proto_idx],0,1,0,0,0);
                scanned->priority_node = 1;
            }

            if(scanner)
            {
                ps_proto_update(&scanner->proto[proto_idx],0,1,0,0,0);
                scanner->priority_node = 1;
            }
        }
    }

    return 0;
}

static int ps_tracker_update_ip(PS_PKT *ps_pkt, PS_TRACKER *scanner,
        PS_TRACKER *scanned, int proto_idx)
{
    Packet *p;
    time_t  pkt_time;
    FLOW   *flow;
    
    p = (Packet *)ps_pkt->pkt;
    pkt_time = packet_timeofday();

    if(p->iph)
    {
        if(p->icmph)
        {
            if(p->icmph->type == ICMP_DEST_UNREACH &&
               p->icmph->code == ICMP_PROT_UNREACH)
            {
                if(scanned)
                {
                    ps_proto_update(&scanned->proto[proto_idx],0,1,0,0,0);
                    scanned->priority_node = 1;
                }

                if(scanner)
                {
                    ps_proto_update(&scanner->proto[proto_idx],0,1,0,0,0);
                    scanner->priority_node = 1;
                }
            }

            return 0;
        }

        if(p->flow)
        {
            flow = (FLOW *)p->flow;
            if(flow->stats.direction == FROM_INITIATOR)
            {
                if(scanned)
                {
                    ps_proto_update(&scanned->proto[proto_idx],1,0,
                        p->iph->ip_src.s_addr,(u_short)p->iph->ip_proto, pkt_time);
                }

                if(scanner)
                {
                    ps_proto_update(&scanner->proto[proto_idx],1,0,
                        p->iph->ip_dst.s_addr,(u_short)p->iph->ip_proto, pkt_time);
                }
            }
            else if(flow->stats.direction == FROM_RESPONDER)
            {
                if(scanned)
                    ps_proto_update(&scanned->proto[proto_idx],-1,0,0,0,0);

                if(scanner)
                    ps_proto_update(&scanner->proto[proto_idx],-1,0,0,0,0);
            }
        }
    }

    return 0;
}

static int ps_tracker_update_udp(PS_PKT *ps_pkt, PS_TRACKER *scanner,
        PS_TRACKER *scanned, int proto_idx)
{
    Packet  *p;
    time_t  pkt_time;
    FLOW    *flow;
    
    p = (Packet *)ps_pkt->pkt;
    pkt_time = packet_timeofday();

    if(p->icmph)
    { 
        if(p->icmph->type == ICMP_DEST_UNREACH &&
           p->icmph->code == ICMP_PORT_UNREACH)
        {
            if(scanned)
            {
                ps_proto_update(&scanned->proto[proto_idx],0,1,0,0,0);
                scanned->priority_node = 1;
            }

            if(scanner)
            {
                ps_proto_update(&scanner->proto[proto_idx],0,1,0,0,0);
                scanner->priority_node = 1;
            }
        }
    }
    else if(p->udph)
    {
        if(p->flow)
        {
            flow = (FLOW *)p->flow;
            if(flow->stats.direction == FROM_INITIATOR)
            {
                if(scanned)
                {
                    ps_proto_update(&scanned->proto[proto_idx],1,0,
                                     p->iph->ip_src.s_addr,p->dp, pkt_time);
                }

                if(scanner)
                {
                    ps_proto_update(&scanner->proto[proto_idx],1,0,
                                     p->iph->ip_dst.s_addr,p->dp, pkt_time);
                }
            }
            else if(flow->stats.direction == FROM_RESPONDER)
            {
                if(scanned)
                    ps_proto_update(&scanned->proto[proto_idx],-1,0,0,0,0);

                if(scanner)
                    ps_proto_update(&scanner->proto[proto_idx],-1,0,0,0,0);
            }
        }
    }

    return 0;
}

static int ps_tracker_update_icmp(PS_PKT *ps_pkt, PS_TRACKER *scanner,
        PS_TRACKER *scanned, int proto_idx)
{
    Packet  *p;
    time_t  pkt_time;
    
    p = (Packet *)ps_pkt->pkt;
    pkt_time = packet_timeofday();

    if(p->icmph)
    {
        switch(p->icmph->type)
        {
            case ICMP_ECHO:
            case ICMP_TIMESTAMP:
            case ICMP_ADDRESS:
            case ICMP_INFO_REQUEST:

                if(scanner)
                {
                    ps_proto_update(&scanner->proto[proto_idx],1,0,
                                     p->iph->ip_dst.s_addr, 0, pkt_time);
                }
                
                break;

            case ICMP_DEST_UNREACH:

                if(scanner)
                {
                    ps_proto_update(&scanner->proto[proto_idx],0,1,0,0,0);
                    scanner->priority_node = 1;
                }

                break;

            default:
                break;
        }
    }

    return 0;
}

/*
**  NAME
**    ps_tracker_update::
*/
/**
**  At this point, we should only be looking at tranport protocols
**  that we want to.  For instance, if we aren't doing UDP portscans
**  then we won't see UDP packets here because they were ignored.
**
**  This is where we evaluate the packet to add/subtract portscan
**  tracker values and prioritize a tracker.  We also update the
**  time windows.
*/
static int ps_tracker_update(PS_PKT *ps_pkt, PS_TRACKER *scanner,
        PS_TRACKER *scanned)
{
    Packet *p;
    int     proto_idx;
    int     proto;

    p = (Packet *)ps_pkt->pkt;

    if(ps_get_proto_index(ps_pkt, &proto_idx, &proto))
        return -1;

    if(scanner && scanner->proto[proto_idx].alerts)
        scanner->proto[proto_idx].alerts = PS_ALERT_GENERATED;
    if(scanned && scanned->proto[proto_idx].alerts)
        scanned->proto[proto_idx].alerts = PS_ALERT_GENERATED;
    
    switch(proto)
    {
        case PS_PROTO_TCP:
            if(ps_tracker_update_tcp(ps_pkt, scanner, scanned, proto_idx))
                return -1;

            break;

        case PS_PROTO_UDP:
            if(ps_tracker_update_udp(ps_pkt, scanner, scanned, proto_idx))
                return -1;

            break;

        case PS_PROTO_ICMP:
            if(ps_tracker_update_icmp(ps_pkt, scanner, scanned, proto_idx))
                return -1;

            break;

        case PS_PROTO_IP:
            if(ps_tracker_update_ip(ps_pkt, scanner, scanned, proto_idx))
                return -1;

            break;

        default:
            return -1;
    }

    ps_pkt->proto     = proto;
    ps_pkt->proto_idx = proto_idx;

    return 0;
}

static int ps_alert_one_to_one(PS_PROTO *scanner, PS_PROTO *scanned,
        PS_ALERT_CONF *conf)
{
    if(!conf)
        return -1;

    /*
    **  Let's evaluate the scanned host.
    */
    if(scanned && !scanned->alerts)
    {
        if(scanned->priority_count >= conf->priority_count)
        {
            if(scanned->u_ip_count < conf->u_ip_count &&
               scanned->u_port_count >= conf->u_port_count)
            {
                if(scanner)
                {
                    if(scanner->priority_count >= conf->priority_count)
                    {
                        /*
                        **  Now let's check to make sure this is one
                        **  to one
                        */
                        scanned->alerts = PS_ALERT_ONE_TO_ONE;
                        return 0;
                    }
                }
                else
                {
                    /*
                    **  If there is no scanner, then we do the best we can.
                    */
                    scanned->alerts = PS_ALERT_ONE_TO_ONE;
                    return 0;
                }
            }
        }
        if(scanned->connection_count >= conf->connection_count)
        {
            if(conf->connection_count == 0)
                return 0;

            if(scanned->u_ip_count < conf->u_ip_count &&
               scanned->u_port_count >= conf->u_port_count)
            {
                scanned->alerts = PS_ALERT_ONE_TO_ONE_FILTERED;
                return 0;
            }
        }
    }

    return 0;

}

static int ps_alert_one_to_one_decoy(PS_PROTO *scanner, PS_PROTO *scanned,
        PS_ALERT_CONF *conf)
{
    if(!conf)
        return -1;

    if(scanned && !scanned->alerts)
    {
        if(scanned->priority_count >= conf->priority_count)
        {
            if(scanned->u_ip_count >= conf->u_ip_count &&
               scanned->u_port_count >= conf->u_port_count)
            {
                scanned->alerts = PS_ALERT_ONE_TO_ONE_DECOY;
                return 0;
            }
        }
        if(scanned->connection_count >= conf->connection_count)
        {
            if(conf->connection_count == 0)
                return 0;

            if(scanned->u_ip_count >= conf->u_ip_count &&
               scanned->u_port_count >= conf->u_port_count)
            {
                scanned->alerts = PS_ALERT_ONE_TO_ONE_DECOY_FILTERED;
                return 0;
            }
        }
    }

    return 0;
}

static int ps_alert_many_to_one(PS_PROTO *scanner, PS_PROTO *scanned,
        PS_ALERT_CONF *conf)
{
    if(!conf)
        return -1;

    if(scanned && !scanned->alerts)
    {
        if(scanned->priority_count >= conf->priority_count)
        {
            if(scanned->u_ip_count <= conf->u_ip_count &&
               scanned->u_port_count >= conf->u_port_count)
            {
                scanned->alerts = PS_ALERT_DISTRIBUTED;
                return 0;
            }
        }
        if(scanned->connection_count >= conf->connection_count)
        {
            if(conf->connection_count == 0)
                return 0;

            if(scanned->u_ip_count <= conf->u_ip_count &&
               scanned->u_port_count >= conf->u_port_count)
            {
                scanned->alerts = PS_ALERT_DISTRIBUTED_FILTERED;
                return 0;
            }
        }
    }
            
    return 0;
}

static int ps_alert_one_to_many(PS_PROTO *scanner, PS_PROTO *scanned,
        PS_ALERT_CONF *conf)
{
    if(!conf)
        return -1;
     
    if(scanner && !scanner->alerts)
    {
        if(scanner->priority_count >= conf->priority_count)
        {
            if(scanner->u_ip_count >= conf->u_ip_count &&
               scanner->u_port_count <= conf->u_port_count)
            {
                scanner->alerts = PS_ALERT_PORTSWEEP;
                return 1;
            }
        }
        if(scanner->connection_count >= conf->connection_count)
        {
            if(conf->connection_count == 0)
                return 0;

            if(scanner->u_ip_count >= conf->u_ip_count &&
               scanner->u_port_count <= conf->u_ip_count)
            {
                scanner->alerts = PS_ALERT_PORTSWEEP_FILTERED;
                return 1;
            }
        }
    }
            
    return 0;
}

static int ps_alert_tcp(PS_PROTO *scanner, PS_PROTO *scanned)
{
    static PS_ALERT_CONF *one_to_one;
    static PS_ALERT_CONF *one_to_one_decoy;
    static PS_ALERT_CONF *one_to_many;
    static PS_ALERT_CONF *many_to_one;

    /*
    ** Set the configurations depending on the sensitivity
    ** level.
    */
    switch(g_ps_init.sense_level)
    {
        case PS_SENSE_HIGH:
            one_to_one       = &g_tcp_hi_ps;
            one_to_one_decoy = &g_tcp_hi_decoy_ps;
            one_to_many      = &g_tcp_hi_sweep;
            many_to_one      = &g_tcp_hi_dist_ps;

            break;

        case PS_SENSE_MEDIUM:
            one_to_one       = &g_tcp_med_ps;
            one_to_one_decoy = &g_tcp_med_decoy_ps;
            one_to_many      = &g_tcp_med_sweep;
            many_to_one      = &g_tcp_med_dist_ps;

            break;

        case PS_SENSE_LOW:
            one_to_one       = &g_tcp_low_ps;
            one_to_one_decoy = &g_tcp_low_decoy_ps;
            one_to_many      = &g_tcp_low_sweep;
            many_to_one      = &g_tcp_low_dist_ps;

            break;

        default:
            return -1;
    }

    /*
    **  Do detection on the different portscan types.
    */
    if((g_ps_init.detect_scan_type & PS_TYPE_PORTSCAN) &&
        ps_alert_one_to_one(scanner, scanned, one_to_one))
    {
        return 0;
    }

    if((g_ps_init.detect_scan_type & PS_TYPE_DECOYSCAN) &&
        ps_alert_one_to_one_decoy(scanner, scanned, one_to_one_decoy))
    {
        return 0;
    }
    
    if((g_ps_init.detect_scan_type & PS_TYPE_PORTSWEEP) && 
        ps_alert_one_to_many(scanner, scanned, one_to_many))
    {
        return 0;
    }

    if((g_ps_init.detect_scan_type & PS_TYPE_DISTPORTSCAN) &&
        ps_alert_many_to_one(scanner, scanned, many_to_one))
    {
        return 0;
    }
    
    return 0;
}

static int ps_alert_ip(PS_PROTO *scanner, PS_PROTO *scanned)
{
    static PS_ALERT_CONF *one_to_one;
    static PS_ALERT_CONF *one_to_one_decoy;
    static PS_ALERT_CONF *one_to_many;
    static PS_ALERT_CONF *many_to_one;

    /*
    ** Set the configurations depending on the sensitivity
    ** level.
    */
    switch(g_ps_init.sense_level)
    {
        case PS_SENSE_HIGH:
            one_to_one       = &g_ip_hi_ps;
            one_to_one_decoy = &g_ip_hi_decoy_ps;
            one_to_many      = &g_ip_hi_sweep;
            many_to_one      = &g_ip_hi_dist_ps;

            break;

        case PS_SENSE_MEDIUM:
            one_to_one       = &g_ip_med_ps;
            one_to_one_decoy = &g_ip_med_decoy_ps;
            one_to_many      = &g_ip_med_sweep;
            many_to_one      = &g_ip_med_dist_ps;

            break;

        case PS_SENSE_LOW:
            one_to_one       = &g_ip_low_ps;
            one_to_one_decoy = &g_ip_low_decoy_ps;
            one_to_many      = &g_ip_low_sweep;
            many_to_one      = &g_ip_low_dist_ps;

            break;

        default:
            return -1;
    }

    /*
    **  Do detection on the different portscan types.
    */
    if((g_ps_init.detect_scan_type & PS_TYPE_PORTSCAN) &&
        ps_alert_one_to_one(scanner, scanned, one_to_one))
    {
        return 0;
    }

    if((g_ps_init.detect_scan_type & PS_TYPE_DECOYSCAN) &&
        ps_alert_one_to_one_decoy(scanner, scanned, one_to_one_decoy))
    {
        return 0;
    }
    
    if((g_ps_init.detect_scan_type & PS_TYPE_PORTSWEEP) && 
        ps_alert_one_to_many(scanner, scanned, one_to_many))
    {
        return 0;
    }

    if((g_ps_init.detect_scan_type & PS_TYPE_DISTPORTSCAN) &&
        ps_alert_many_to_one(scanner, scanned, many_to_one))
    {
        return 0;
    }
    
    return 0;
}

static int ps_alert_udp(PS_PROTO *scanner, PS_PROTO *scanned)
{
    static PS_ALERT_CONF *one_to_one;
    static PS_ALERT_CONF *one_to_one_decoy;
    static PS_ALERT_CONF *one_to_many;
    static PS_ALERT_CONF *many_to_one;

    /*
    ** Set the configurations depending on the sensitivity
    ** level.
    */
    switch(g_ps_init.sense_level)
    {
        case PS_SENSE_HIGH:
            one_to_one       = &g_udp_hi_ps;
            one_to_one_decoy = &g_udp_hi_decoy_ps;
            one_to_many      = &g_udp_hi_sweep;
            many_to_one      = &g_udp_hi_dist_ps;

            break;

        case PS_SENSE_MEDIUM:
            one_to_one       = &g_udp_med_ps;
            one_to_one_decoy = &g_udp_med_decoy_ps;
            one_to_many      = &g_udp_med_sweep;
            many_to_one      = &g_udp_med_dist_ps;

            break;

        case PS_SENSE_LOW:
            one_to_one       = &g_udp_low_ps;
            one_to_one_decoy = &g_udp_low_decoy_ps;
            one_to_many      = &g_udp_low_sweep;
            many_to_one      = &g_udp_low_dist_ps;

            break;

        default:
            return -1;
    }

    /*
    **  Do detection on the different portscan types.
    */
    if((g_ps_init.detect_scan_type & PS_TYPE_PORTSCAN) &&
        ps_alert_one_to_one(scanner, scanned, one_to_one))
    {
        return 0;
    }

    if((g_ps_init.detect_scan_type & PS_TYPE_DECOYSCAN) &&
        ps_alert_one_to_one_decoy(scanner, scanned, one_to_one_decoy))
    {
        return 0;
    }
    
    if((g_ps_init.detect_scan_type & PS_TYPE_PORTSWEEP) && 
        ps_alert_one_to_many(scanner, scanned, one_to_many))
    {
        return 0;
    }

    if((g_ps_init.detect_scan_type & PS_TYPE_DISTPORTSCAN) &&
        ps_alert_many_to_one(scanner, scanned, many_to_one))
    {
        return 0;
    }
    
    return 0;
}

static int ps_alert_icmp(PS_PROTO *scanner, PS_PROTO *scanned)
{
    static PS_ALERT_CONF *one_to_many;

    /*
    ** Set the configurations depending on the sensitivity
    ** level.
    */
    switch(g_ps_init.sense_level)
    {
        case PS_SENSE_HIGH:
            one_to_many = &g_icmp_hi_sweep;
     
            break;

        case PS_SENSE_MEDIUM:
            one_to_many = &g_icmp_med_sweep;

            break;

        case PS_SENSE_LOW:
            one_to_many = &g_icmp_low_sweep;

            break;

        default:
            return -1;
    }

    /*
    **  Do detection on the different portscan types.
    */
    if((g_ps_init.detect_scan_type & PS_TYPE_PORTSWEEP) && 
        ps_alert_one_to_many(scanner, scanned, one_to_many))
    {
        return 0;
    }
    
    return 0;
}
/*
**  NAME
**    ps_tracker_alert::
*/
/**
**  This function evaluates the scanner and scanned trackers and if
**  applicable, generate an alert or alerts for either of the trackers.
**
**  The following alerts can be generated:
**    - One to One Portscan
**    - One to One Decoy Portscan
**    - One to Many Portsweep
**    - Distributed Portscan (Many to One)
**    - Filtered Portscan?
*/
static int ps_tracker_alert(PS_PKT *ps_pkt, PS_TRACKER *scanner,
        PS_TRACKER *scanned)
{
    if(!ps_pkt)
        return -1;

    switch(ps_pkt->proto)
    {
        case PS_PROTO_TCP:
            ps_alert_tcp((scanner ? &scanner->proto[ps_pkt->proto_idx] : NULL),
                    (scanned ? &scanned->proto[ps_pkt->proto_idx] : NULL));

            break;

        case PS_PROTO_UDP:
            ps_alert_udp((scanner ? &scanner->proto[ps_pkt->proto_idx] : NULL),
                    (scanned ? &scanned->proto[ps_pkt->proto_idx] : NULL));

            break;

        case PS_PROTO_ICMP:
            ps_alert_icmp((scanner ? &scanner->proto[ps_pkt->proto_idx] : NULL),
                    (scanned ? &scanned->proto[ps_pkt->proto_idx] : NULL));

            break;

        case PS_PROTO_IP:
            ps_alert_ip((scanner ? &scanner->proto[ps_pkt->proto_idx] : NULL),
                    (scanned ? &scanned->proto[ps_pkt->proto_idx] : NULL));
            break;

        default:
            return -1;
    }

    return 0;
}

/*
**  NAME
**    ps_detect::
*/
/**
**  The design of portscan is as follows:
**
**    - Filter Packet.  Is the packet part of the ignore or watch list?  Is
**      the packet part of an established TCP session (we ignore it)?
**
**    - Tracker Lookup.  We lookup trackers for src and dst if either is in
**      the watch list, or not in the ignore list if there is no watch list.
**      If there is not tracker, we create a new one and keep track, both of
**      the scanned host and the scanning host.
**
**    - Tracker Update.  We update the tracker using the incoming packet.  If
**      the update causes a portscan alert, then we move into the log alert
**      phase.
**
**    - Tracker Evaluate.  Generate an alert from the updated tracker.  We
**      decide whether we are logging a portscan or sweep (based on the
**      scanning or scanned host, we decide which is more relevant).
*/
int ps_detect(PS_PKT *p)
{
    PS_TRACKER *scanner = NULL;
    PS_TRACKER *scanned = NULL;

    if(!p || !p->pkt)
        return -1;

    if(ps_filter_ignore(p))
        return 0;

    //printf("** ignore\n");

    if(ps_tracker_lookup(p, &scanner, &scanned))
        return 0;

    //printf("** lookup\n");
    if(ps_tracker_update(p, scanner, scanned))
        return 0;

    //printf("** update\n");
    if(ps_tracker_alert(p, scanner, scanned))
        return 0;

    //printf("** alert\n");
    p->scanner = scanner;
    p->scanned = scanned;
    
    return 1;
}

static void ps_proto_print(PS_PROTO *proto)
{
    int            iCtr;
    struct in_addr ip;

    if(!proto)
        return;

    printf("    priority count    = %d\n", proto->priority_count);
    printf("    connection count  = %d\n", proto->connection_count);
    printf("    unique IP count   = %d\n", proto->u_ip_count);
    
    ip.s_addr = proto->low_ip;
    printf("    IP range          = %s:", inet_ntoa(ip));
    ip.s_addr = proto->high_ip;
    printf("%s\n", inet_ntoa(ip));
            
    printf("    unique port count = %d\n", proto->u_port_count);
    printf("    port range        = %d:%d\n", proto->low_p, proto->high_p);

    printf("    open ports        = ");

    for(iCtr = 0; iCtr < proto->open_ports_cnt; iCtr++)
    {
        printf("%d ", proto->open_ports[iCtr]);
    }
    printf("\n");

    printf("    alerts            = %.2x\n", proto->alerts);

    ip.s_addr = proto->u_ips;
    printf("    Last IP:   %s\n", inet_ntoa(ip));
    printf("    Last Port: %d\n", proto->u_ports);

    printf("    Time:      %s\n", ctime(&proto->window));

    return;
}

void ps_tracker_print(PS_TRACKER* ps_tracker)
{
    int proto_index = 0;

    if(!ps_tracker)
        return;

    printf("    -- PS_TRACKER --\n");
    printf("    priority_node = %d\n", ps_tracker->priority_node);

    if(g_ps_init.detect_scans & PS_PROTO_TCP)
    {
        printf("    ** TCP **\n");
        ps_proto_print(&ps_tracker->proto[proto_index]);
        proto_index++;
    }
    if(g_ps_init.detect_scans & PS_PROTO_UDP)
    {
        printf("    ** UDP **\n");
        ps_proto_print(&ps_tracker->proto[proto_index]);
        proto_index++;
    }
    if(g_ps_init.detect_scans & PS_PROTO_IP)
    {
        printf("    ** IP **\n");
        ps_proto_print(&ps_tracker->proto[proto_index]);
        proto_index++;
    }
    if(g_ps_init.detect_scans & PS_PROTO_ICMP)
    {
        printf("    ** ICMP **\n");
        ps_proto_print(&ps_tracker->proto[proto_index]);
        proto_index++;
    }

    printf("    -- END --\n\n");

    return;
}
