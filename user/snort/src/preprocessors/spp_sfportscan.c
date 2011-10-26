/*
**  @file       spp_sfportscan.c
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      Portscan detection
**
**  NOTES
**    - User Configuration:  The following is a list of parameters that can
**      be configured through the user interface:
**
**      proto  { tcp udp icmp ip all }
**      scan_type { portscan portsweep decoy_portscan distributed_portscan all }
**      sense_level { high }    # high, medium, low
**      watch_ip { }            # list of IPs, CIDR blocks
**      ignore_scanners { }     # list of IPs, CIDR blocks
**      ignore_scanned { }      # list of IPs, CIDR blocks
**      memcap { 10000000 }     # number of max bytes to allocate
**      logfile { /tmp/ps.log } # file to log detailed portscan info
*/
#include <sys/types.h>
#ifndef WIN32
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
#endif /* !WIN32 */

#include "decode.h"
#include "plugbase.h"
#include "generators.h"
#include "event_wrapper.h"
#include "util.h"
#include "ipobj.h"
#include "checksum.h"
#include "packet_time.h"
#include "snort.h"
#include "sfthreshold.h"
#include "snort_packet_header.h"

#include "portscan.h"

#include "profiler.h"

#define DELIMITERS " \t\n"
#define TOKEN_ARG_BEGIN "{"
#define TOKEN_ARG_END   "}"

#define PROTO_BUFFER_SIZE 256

extern PV    pv;
extern char *file_name;
extern int   file_line;

static int     g_print_tracker = 0;
static u_char  g_logpath[256];
static FILE   *g_logfile = NULL;
static Packet *g_tmp_pkt;

int g_include_midstream = 0;

#ifdef PERF_PROFILING
PreprocStats sfpsPerfStats;
#endif

/*
**  NAME
**    PortscanPacketInit::
*/
/**
**  Initialize the Packet structure buffer so we can generate our
**  alert packets for portscan.  We initialize the various fields in
**  the Packet structure and set the hardware layer for easy identification
**  by user interfaces.
**
**  @return int
**
**  @retval !0 initialization failed
**  @retval  0 success
*/
static int PortscanPacketInit(void)
{
    const char mac_addr[] = "MACDAD";
    Packet *p;

    p = (Packet *)SnortAlloc(sizeof(Packet));
    p->pkth = (struct pcap_pkthdr *)SnortAlloc(sizeof(struct pcap_pkthdr) +
                    ETHERNET_HEADER_LEN + SPARC_TWIDDLE + IP_MAXPACKET);
    
    /* Add 2 to align iph struct members on 4 byte boundaries - for sparc, etc */
    p->pkt  = ((u_char *)p->pkth + sizeof(SnortPktHeader) + SPARC_TWIDDLE);
    p->eh   = (EtherHdr *)p->pkt;
    p->iph  = (IPHdr *)(((u_char *)p->eh) + ETHERNET_HEADER_LEN);
    p->data = ((u_char *)p->iph) + sizeof(IPHdr);

    /*
    **  Set the ethernet header with our cooked values.
    */
    p->eh->ether_type = htons(0x0800);
    memcpy(p->eh->ether_dst, mac_addr, 6);
    memcpy(p->eh->ether_src, mac_addr, 6);

    g_tmp_pkt = p;

    return 0;
}

void PortscanCleanExitFunction(int signal, void *foo)
{
    free(g_tmp_pkt->pkth);
    free(g_tmp_pkt);
    g_tmp_pkt = NULL;
}


void PortscanRestartFunction(int signal, void *foo)
{
    free(g_tmp_pkt->pkth);
    free(g_tmp_pkt);
    g_tmp_pkt = NULL;
}

/*
**  NAME
**    MakeProtoInfo::
*/
/**
**  This routine makes the portscan payload for the events.  The listed
**  info is:
**    - priority count (number of error transmissions RST/ICMP UNREACH)
**    - connection count (number of protocol connections SYN)
**    - ip count (number of IPs that communicated with host)
**    - ip range (low to high range of IPs)
**    - port count (number of port changes that occurred on host)
**    - port range (low to high range of ports connected too)
**
**  @return integer
**
**  @retval -1 buffer not large enough
**  @retval  0 successful
*/
static int MakeProtoInfo(PS_PROTO *proto, u_char *buffer, u_int *total_size)
{
    unsigned char *ip1;
    unsigned char *ip2;
    int            dsize;

    if(!total_size || !buffer)
        return -1;

    dsize = (IP_MAXPACKET - *total_size);

    if(dsize < PROTO_BUFFER_SIZE)
       return -1; 

    ip1 = (char *)&proto->low_ip;
    ip2 = (char *)&proto->high_ip;

    if(proto->alerts == PS_ALERT_PORTSWEEP ||
       proto->alerts == PS_ALERT_PORTSWEEP_FILTERED)
    {
        SnortSnprintf((char *)buffer, PROTO_BUFFER_SIZE,
                      "Priority Count: %d\n"
                      "Connection Count: %d\n"
                      "IP Count: %d\n"
                      "Scanned IP Range: %d.%d.%d.%d:%d.%d.%d.%d\n"
                      "Port/Proto Count: %d\n"
                      "Port/Proto Range: %d:%d\n",
                      proto->priority_count,
                      proto->connection_count,
                      proto->u_ip_count,
                      ip1[0],ip1[1],ip1[2],ip1[3],
                      ip2[0],ip2[1],ip2[2],ip2[3],
                      proto->u_port_count,
                      proto->low_p,
                      proto->high_p);
    }
    else
    {
        SnortSnprintf((char *)buffer, PROTO_BUFFER_SIZE,
                      "Priority Count: %d\n"
                      "Connection Count: %d\n"
                      "IP Count: %d\n"
                      "Scanner IP Range: %d.%d.%d.%d:%d.%d.%d.%d\n"
                      "Port/Proto Count: %d\n"
                      "Port/Proto Range: %d:%d\n",
                      proto->priority_count,
                      proto->connection_count,
                      proto->u_ip_count,
                      ip1[0],ip1[1],ip1[2],ip1[3],
                      ip2[0],ip2[1],ip2[2],ip2[3],
                      proto->u_port_count,
                      proto->low_p,
                      proto->high_p);
    }

    /* guaranteed to be null terminated */
    dsize = SnortStrnlen(buffer, PROTO_BUFFER_SIZE);
    *total_size += dsize;

    /*
    **  Set the payload size.  This is protocol independent.
    */
    g_tmp_pkt->dsize = dsize;

    return 0;
}

static int LogPortscanAlert(Packet *p, char *msg, u_int32_t event_id,
        u_int32_t event_ref, u_int32_t gen_id, u_int32_t sig_id)
{
    char timebuf[TIMEBUF_SIZE];
    u_long src_addr = 0;
    u_long dst_addr = 0;

    if(!p->iph)
        return -1;

    /* Do not log if being suppressed */
    if ( p->iph )
    {
        src_addr = p->iph->ip_src.s_addr;
        dst_addr = p->iph->ip_dst.s_addr;
    }

    if( !sfthreshold_test(gen_id, sig_id, src_addr, dst_addr, p->pkth->ts.tv_sec) )
    {
        return 0;
    }

    ts_print((struct timeval *)&p->pkth->ts, timebuf);

    fprintf(g_logfile, "Time: %s\n", timebuf);

    if(event_id)
        fprintf(g_logfile, "event_id: %u\n", event_id);
    else
        fprintf(g_logfile, "event_ref: %u\n", event_ref);

    fprintf(g_logfile, "%s ", inet_ntoa(p->iph->ip_src));
    fprintf(g_logfile, "-> %s %s\n", inet_ntoa(p->iph->ip_dst), msg);
    fprintf(g_logfile, "%.*s\n", p->dsize, p->data);

    fflush(g_logfile);

    return 0;
}

static int GeneratePSSnortEvent(Packet *p,u_int32_t gen_id,u_int32_t sig_id, 
        u_int32_t sig_rev, u_int32_t class, u_int32_t priority, char *msg)
{
    unsigned int event_id;
    
    event_id = GenerateSnortEvent(p,gen_id,sig_id,sig_rev,class,priority,msg);

    if(g_logfile)
        LogPortscanAlert(p, msg, event_id, 0, gen_id, sig_id);

    return event_id;
}

/*
**  NAME
**    GenerateOpenPortEvent::
*/
/**
**  We have to generate open port events differently because we tag these
**  to the original portscan event.
**
**  @return int
**
**  @retval 0 success
*/
static int GenerateOpenPortEvent(Packet *p, u_int32_t gen_id, u_int32_t sig_id,
        u_int32_t sig_rev, u_int32_t class, u_int32_t pri, 
        u_int32_t event_ref, struct timeval *event_time, char *msg)
{
    Event event;

    /*
    **  This means that we logged an open port, but we don't have a event
    **  reference for it, so we don't log a snort event.  We still keep
    **  track of it though.
    */
    if(!event_ref)
        return 0;

    /* reset the thresholding subsystem checks for this packet */
    sfthreshold_reset();
            
    SetEvent(&event, gen_id, sig_id, sig_rev, class, pri, event_ref);
    //CallAlertFuncs(p,msg,NULL,&event);

    event.ref_time.tv_sec  = event_time->tv_sec;
    event.ref_time.tv_usec = event_time->tv_usec;

    if(p)
    {
        /*
         * Do threshold test for suppression and thresholding.  We have to do it
         * here since these are tagged packets, which aren't subject to thresholding,
         * but we want to do it for open port events.
         */
        if( !sfthreshold_test(gen_id, sig_id, p->iph->ip_src.s_addr,
                            p->iph->ip_dst.s_addr, p->pkth->ts.tv_sec) )
        {
            return 0;
        }

        CallLogFuncs(p,msg,NULL,&event);
    } 
    else 
    {
        return -1;
    }

    if(g_logfile)
        LogPortscanAlert(p, msg, 0, event_ref, gen_id, sig_id);

    return event.event_id;
}

/*
**  NAME
**    MakeOpenPortInfo::
*/
/** 
**  Write out the open ports info for open port alerts.
**
**  @return integer
*/
static int MakeOpenPortInfo(PS_PROTO *proto, u_char *buffer, u_int *total_size,
         void *user)
{
    int dsize;

    if(!total_size || !buffer)
        return -1;

    dsize = (IP_MAXPACKET - *total_size);

    if(dsize < PROTO_BUFFER_SIZE)
       return -1; 

    SnortSnprintf((char *)buffer, PROTO_BUFFER_SIZE,
                  "Open Port: %u\n", *((unsigned short *)user));

    /* guaranteed to be null terminated */
    dsize = SnortStrnlen(buffer, PROTO_BUFFER_SIZE);
    *total_size += dsize;

    /*
    **  Set the payload size.  This is protocol independent.
    */
    g_tmp_pkt->dsize = dsize;

    return 0;
}

/*
**  NAME
**    MakePortscanPkt::
*/
/*
**  We have to create this fake packet so portscan data can be passed
**  through the unified output.
**
**  We want to copy the network and transport layer headers into our
**  fake packet.
**  
*/
static int MakePortscanPkt(PS_PKT *ps_pkt, PS_PROTO *proto, int proto_type,
        void *user)
{
    Packet *p;
    unsigned long  tmp_addr;
    unsigned int   hlen;
    unsigned int   ip_size = 0; 
  
    if(!ps_pkt && proto_type != PS_PROTO_OPEN_PORT)
       return -1;

    if(ps_pkt)
    { 
        p = (Packet *)ps_pkt->pkt;

        if(!p->iph)
            return -1;

        hlen = IP_HLEN(p->iph)<<2;

        if ( p->iph != g_tmp_pkt->iph )
            /*
             * it happen that ps_pkt->pkt can be the same
             * as g_tmp_pkt. Avoid overlapping copy then.
             */
             memcpy(g_tmp_pkt->iph, p->iph, hlen);

        if(ps_pkt->reverse_pkt)
        {
            tmp_addr = p->iph->ip_src.s_addr;
            g_tmp_pkt->iph->ip_src.s_addr = p->iph->ip_dst.s_addr;
            g_tmp_pkt->iph->ip_dst.s_addr = tmp_addr;
        }

        ip_size += hlen;

        g_tmp_pkt->iph->ip_proto = 0xff;
        g_tmp_pkt->iph->ip_ttl = 0x00;
        g_tmp_pkt->data = (u_char *)((u_char *)g_tmp_pkt->iph + hlen);

        g_tmp_pkt->pkth->ts.tv_sec = p->pkth->ts.tv_sec;
        g_tmp_pkt->pkth->ts.tv_usec = p->pkth->ts.tv_usec;
    }

    switch(proto_type)
    {
        case PS_PROTO_TCP:
        case PS_PROTO_UDP:
        case PS_PROTO_ICMP:
        case PS_PROTO_IP:
            if(MakeProtoInfo(proto, g_tmp_pkt->data, &ip_size))
                return -1;

            break;

        case PS_PROTO_OPEN_PORT:
            if(MakeOpenPortInfo(proto, g_tmp_pkt->data, &ip_size, user))
                return -1;

            break;

        default:
            return -1;
    }

    /*
    **  Let's finish up the IP header and checksum.
    */
    g_tmp_pkt->iph->ip_len = htons((short)ip_size);
    g_tmp_pkt->iph->ip_csum = 0;
    g_tmp_pkt->iph->ip_csum = 
        in_chksum_ip((u_short *)g_tmp_pkt->iph, (IP_HLEN(g_tmp_pkt->iph)<<2));


    /*
    **  And we set the pcap headers correctly so they decode.
    */
    g_tmp_pkt->pkth->caplen = ip_size + ETHERNET_HEADER_LEN;
    g_tmp_pkt->pkth->len    = ip_size + ETHERNET_HEADER_LEN;

    return 0;
}

static int PortscanAlertTcp(Packet *p, PS_PROTO *proto, int proto_type)
{
    int iCtr;
    unsigned int event_ref;
    int portsweep = 0;
    
    if(!proto)
        return -1;

    switch(proto->alerts)
    {
        case PS_ALERT_ONE_TO_ONE:
            event_ref = GeneratePSSnortEvent(p, GENERATOR_PSNG, 
                    PSNG_TCP_PORTSCAN, 0, 0, 3, PSNG_TCP_PORTSCAN_STR);
            break;

        case PS_ALERT_ONE_TO_ONE_DECOY:
            event_ref = GeneratePSSnortEvent(p,GENERATOR_PSNG,
                    PSNG_TCP_DECOY_PORTSCAN,0,0,3,PSNG_TCP_DECOY_PORTSCAN_STR);
            break;

        case PS_ALERT_PORTSWEEP:
           event_ref = GeneratePSSnortEvent(p,GENERATOR_PSNG,
                   PSNG_TCP_PORTSWEEP, 0, 0, 3, PSNG_TCP_PORTSWEEP_STR);
           portsweep = 1;
           
           break;

        case PS_ALERT_DISTRIBUTED:
            event_ref = GeneratePSSnortEvent(p,GENERATOR_PSNG,
                    PSNG_TCP_DISTRIBUTED_PORTSCAN, 0, 0, 3, 
                    PSNG_TCP_DISTRIBUTED_PORTSCAN_STR);
            break;

        case PS_ALERT_ONE_TO_ONE_FILTERED:
            event_ref = GeneratePSSnortEvent(p,GENERATOR_PSNG,
                    PSNG_TCP_FILTERED_PORTSCAN,0,0,3, 
                    PSNG_TCP_FILTERED_PORTSCAN_STR);
            break;

        case PS_ALERT_ONE_TO_ONE_DECOY_FILTERED:
            event_ref = GeneratePSSnortEvent(p,GENERATOR_PSNG,
                    PSNG_TCP_FILTERED_DECOY_PORTSCAN, 0,0,3, 
                    PSNG_TCP_FILTERED_DECOY_PORTSCAN_STR);
            break;

        case PS_ALERT_PORTSWEEP_FILTERED:
           event_ref = GeneratePSSnortEvent(p,GENERATOR_PSNG,
                   PSNG_TCP_PORTSWEEP_FILTERED,0,0,3,
                   PSNG_TCP_PORTSWEEP_FILTERED_STR);
           portsweep = 1;

           return 0;

        case PS_ALERT_DISTRIBUTED_FILTERED:
            event_ref = GeneratePSSnortEvent(p,GENERATOR_PSNG,
                    PSNG_TCP_FILTERED_DISTRIBUTED_PORTSCAN, 0, 0, 3, 
                    PSNG_TCP_FILTERED_DISTRIBUTED_PORTSCAN_STR);
            break;

        default:
            return 0;
    }

    /*
    **  Set the current event reference information for any open ports.
    */
    proto->event_ref  = event_ref;
    proto->event_time.tv_sec  = p->pkth->ts.tv_sec;
    proto->event_time.tv_usec = p->pkth->ts.tv_usec;

    /*
    **  Only log open ports for portsweeps after the alert has been
    **  generated.
    */
    if(proto->open_ports_cnt && !portsweep)
    {
        for(iCtr = 0; iCtr < proto->open_ports_cnt; iCtr++)
        {
            PS_PKT ps_pkt;            
            
            memset(&ps_pkt, 0x00, sizeof(PS_PKT));
            ps_pkt.pkt = (void *)p;

            if(MakePortscanPkt(&ps_pkt, proto, PS_PROTO_OPEN_PORT, 
                        (void *)&proto->open_ports[iCtr]))
                return -1;

            g_tmp_pkt->pkth->ts.tv_usec += 1;
            GenerateOpenPortEvent(g_tmp_pkt,GENERATOR_PSNG,PSNG_OPEN_PORT,
                    0,0,3, proto->event_ref, &proto->event_time, 
                    PSNG_OPEN_PORT_STR);
        }
    }

    return 0;
}

static int PortscanAlertUdp(Packet *p, PS_PROTO *proto, int proto_type)
{
    if(!proto)
        return -1;

    switch(proto->alerts)
    {
        case PS_ALERT_ONE_TO_ONE:
            GeneratePSSnortEvent(p, GENERATOR_PSNG, PSNG_UDP_PORTSCAN, 0, 0, 3,
                    PSNG_UDP_PORTSCAN_STR);
            break;

        case PS_ALERT_ONE_TO_ONE_DECOY:
            GeneratePSSnortEvent(p,GENERATOR_PSNG,PSNG_UDP_DECOY_PORTSCAN, 0, 0, 3,
                    PSNG_UDP_DECOY_PORTSCAN_STR);
            break;

        case PS_ALERT_PORTSWEEP:
           GeneratePSSnortEvent(p,GENERATOR_PSNG,PSNG_UDP_PORTSWEEP, 0, 0, 3,
                    PSNG_UDP_PORTSWEEP_STR);
            break;

        case PS_ALERT_DISTRIBUTED:
            GeneratePSSnortEvent(p,GENERATOR_PSNG,PSNG_UDP_DISTRIBUTED_PORTSCAN, 
                    0, 0, 3, PSNG_UDP_DISTRIBUTED_PORTSCAN_STR);
            break;

        case PS_ALERT_ONE_TO_ONE_FILTERED:
            GeneratePSSnortEvent(p,GENERATOR_PSNG,PSNG_UDP_FILTERED_PORTSCAN,0,0,3,
                    PSNG_UDP_FILTERED_PORTSCAN_STR);
            break;

        case PS_ALERT_ONE_TO_ONE_DECOY_FILTERED:
            GeneratePSSnortEvent(p,GENERATOR_PSNG,PSNG_UDP_FILTERED_DECOY_PORTSCAN,
                    0,0,3, PSNG_UDP_FILTERED_DECOY_PORTSCAN_STR);
            break;

        case PS_ALERT_PORTSWEEP_FILTERED:
           GeneratePSSnortEvent(p,GENERATOR_PSNG,PSNG_UDP_PORTSWEEP_FILTERED,0,0,3,
                    PSNG_UDP_PORTSWEEP_FILTERED_STR);
            break;

        case PS_ALERT_DISTRIBUTED_FILTERED:
            GeneratePSSnortEvent(p,GENERATOR_PSNG,
                    PSNG_UDP_FILTERED_DISTRIBUTED_PORTSCAN, 0, 0, 3, 
                    PSNG_UDP_FILTERED_DISTRIBUTED_PORTSCAN_STR);
            break;

        default:
            break;
    }

    return 0;
}

static int PortscanAlertIp(Packet *p, PS_PROTO *proto, int proto_type)
{
    if(!proto)
        return -1;

    switch(proto->alerts)
    {
        case PS_ALERT_ONE_TO_ONE:
            GeneratePSSnortEvent(p, GENERATOR_PSNG, PSNG_IP_PORTSCAN, 0, 0, 3,
                    PSNG_IP_PORTSCAN_STR);
            break;

        case PS_ALERT_ONE_TO_ONE_DECOY:
            GeneratePSSnortEvent(p,GENERATOR_PSNG,PSNG_IP_DECOY_PORTSCAN, 0, 0, 3,
                    PSNG_IP_DECOY_PORTSCAN_STR);
            break;

        case PS_ALERT_PORTSWEEP:
           GeneratePSSnortEvent(p,GENERATOR_PSNG,PSNG_IP_PORTSWEEP, 0, 0, 3,
                    PSNG_IP_PORTSWEEP_STR);
            break;

        case PS_ALERT_DISTRIBUTED:
            GeneratePSSnortEvent(p,GENERATOR_PSNG,PSNG_IP_DISTRIBUTED_PORTSCAN, 
                    0, 0, 3, PSNG_IP_DISTRIBUTED_PORTSCAN_STR);
            break;

        case PS_ALERT_ONE_TO_ONE_FILTERED:
            GeneratePSSnortEvent(p,GENERATOR_PSNG,PSNG_IP_FILTERED_PORTSCAN,0,0,3,
                    PSNG_IP_FILTERED_PORTSCAN_STR);
            break;

        case PS_ALERT_ONE_TO_ONE_DECOY_FILTERED:
            GeneratePSSnortEvent(p,GENERATOR_PSNG,PSNG_IP_FILTERED_DECOY_PORTSCAN,
                    0,0,3, PSNG_IP_FILTERED_DECOY_PORTSCAN_STR);
            break;

        case PS_ALERT_PORTSWEEP_FILTERED:
           GeneratePSSnortEvent(p,GENERATOR_PSNG,PSNG_IP_PORTSWEEP_FILTERED,0,0,3,
                    PSNG_IP_PORTSWEEP_FILTERED_STR);
            break;

        case PS_ALERT_DISTRIBUTED_FILTERED:
            GeneratePSSnortEvent(p,GENERATOR_PSNG,
                    PSNG_IP_FILTERED_DISTRIBUTED_PORTSCAN, 0, 0, 3, 
                    PSNG_IP_FILTERED_DISTRIBUTED_PORTSCAN_STR);
            break;

        default:
            break;
    }

    return 0;
}

static int PortscanAlertIcmp(Packet *p, PS_PROTO *proto, int proto_type)
{
    if(!proto)
        return -1;

    switch(proto->alerts)
    {
        case PS_ALERT_PORTSWEEP:
           GeneratePSSnortEvent(p,GENERATOR_PSNG,PSNG_ICMP_PORTSWEEP, 0, 0, 3,
                    PSNG_ICMP_PORTSWEEP_STR);
            break;

        case PS_ALERT_PORTSWEEP_FILTERED:
           GeneratePSSnortEvent(p,GENERATOR_PSNG,PSNG_ICMP_PORTSWEEP_FILTERED,0,0,3,
                    PSNG_ICMP_PORTSWEEP_FILTERED_STR);
            break;

        default:
            break;
    }

    return 0;
}

static int PortscanAlert(PS_PKT *ps_pkt, PS_PROTO *proto, int proto_type)
{
    Packet *p;

    if(!ps_pkt || !ps_pkt->pkt)
        return -1;

    p = (Packet *)ps_pkt->pkt;
    
    if(proto->alerts == PS_ALERT_OPEN_PORT)
    {
        if(MakePortscanPkt(ps_pkt, proto, PS_PROTO_OPEN_PORT, (void *)&p->sp))
            return -1;

        GenerateOpenPortEvent(g_tmp_pkt,GENERATOR_PSNG,PSNG_OPEN_PORT,0,0,3,
                proto->event_ref, &proto->event_time, PSNG_OPEN_PORT_STR);
    }
    else
    {
        if(MakePortscanPkt(ps_pkt, proto, proto_type, NULL))
            return -1;

        switch(proto_type)
        {
            case PS_PROTO_TCP:
                PortscanAlertTcp(g_tmp_pkt, proto, proto_type);
                break;

            case PS_PROTO_UDP:
                PortscanAlertUdp(g_tmp_pkt, proto, proto_type);
                break;

            case PS_PROTO_ICMP:
                PortscanAlertIcmp(g_tmp_pkt, proto, proto_type);
                break;

            case PS_PROTO_IP:
                PortscanAlertIp(g_tmp_pkt, proto, proto_type);
                break;
        }
    }

    return 0;
}

static void PortscanDetect(Packet *p, void *context)
{
    PS_PKT ps_pkt;
    PROFILE_VARS;

    if(!p || !p->iph || (p->packet_flags & PKT_REBUILT_STREAM))
        return;

    PREPROC_PROFILE_START(sfpsPerfStats);

    memset(&ps_pkt, 0x00, sizeof(PS_PKT));
    ps_pkt.pkt = (void *)p;

    ps_detect(&ps_pkt);

    if(ps_pkt.scanner && ps_pkt.scanner->proto[ps_pkt.proto_idx].alerts &&
            (ps_pkt.scanner->proto[ps_pkt.proto_idx].alerts != PS_ALERT_GENERATED))
    {
        PortscanAlert(&ps_pkt, &ps_pkt.scanner->proto[ps_pkt.proto_idx], 
                ps_pkt.proto);
    }

    if(ps_pkt.scanned && ps_pkt.scanned->proto[ps_pkt.proto_idx].alerts &&
            (ps_pkt.scanned->proto[ps_pkt.proto_idx].alerts != PS_ALERT_GENERATED))
    {
        PortscanAlert(&ps_pkt, &ps_pkt.scanned->proto[ps_pkt.proto_idx], 
                ps_pkt.proto);
    }

    PREPROC_PROFILE_END(sfpsPerfStats);
    return;
}

NORETURN static void FatalErrorNoOption(u_char *option)
{
    FatalError("%s(%d) => No argument to '%s' config option.\n", 
            file_name, file_line, option);

    return;
}

NORETURN static void FatalErrorNoEnd(char *option)
{
    FatalError("%s(%d) => No ending brace to '%s' config option.\n", 
            file_name, file_line, option);
}

NORETURN static void FatalErrorInvalidArg(char *option)
{
    FatalError("%s(%d) => Invalid argument to '%s' config option.\n", 
            file_name, file_line, option);
}

NORETURN static void FatalErrorInvalidOption(char *option)
{
    FatalError("%s(%d) => Invalid option '%s' to portscan preprocessor.\n", 
            file_name, file_line, option);
}

static void ParseProtos(int *protos)
{
    char *pcTok;

    if(!protos)
        return;

    *protos = 0;

    pcTok = strtok(NULL, DELIMITERS);
    while(pcTok)
    {
        if(!strcasecmp(pcTok, "tcp"))
            *protos |= PS_PROTO_TCP;
        else if(!strcasecmp(pcTok, "udp"))
            *protos |= PS_PROTO_UDP;
        else if(!strcasecmp(pcTok, "icmp"))
            *protos |= PS_PROTO_ICMP;
        else if(!strcasecmp(pcTok, "ip"))
            *protos |= PS_PROTO_IP;
        else if(!strcasecmp(pcTok, "all"))
            *protos = PS_PROTO_ALL;
        else if(!strcasecmp(pcTok, TOKEN_ARG_END))
            return;
        else
            FatalErrorInvalidArg("proto");

        pcTok = strtok(NULL, DELIMITERS);
    }

    if(!pcTok)
        FatalErrorNoEnd("proto");

    return;
}

static void ParseScanType(int *scan_types)
{
    char *pcTok;
    
    if(!scan_types)
        return;

    *scan_types = 0;

    pcTok = strtok(NULL, DELIMITERS);
    while(pcTok)
    {
        if(!strcasecmp(pcTok, "portscan"))
            *scan_types |= PS_TYPE_PORTSCAN;
        else if(!strcasecmp(pcTok, "portsweep"))
            *scan_types |= PS_TYPE_PORTSWEEP;
        else if(!strcasecmp(pcTok, "decoy_portscan"))
            *scan_types |= PS_TYPE_DECOYSCAN;
        else if(!strcasecmp(pcTok, "distributed_portscan"))
            *scan_types |= PS_TYPE_DISTPORTSCAN;
        else if(!strcasecmp(pcTok, "all"))
            *scan_types = PS_TYPE_ALL;
        else if(!strcasecmp(pcTok, TOKEN_ARG_END))
            return;
        else
            FatalErrorInvalidArg("scan_type");

        pcTok = strtok(NULL, DELIMITERS);
    }

    if(!pcTok)
        FatalErrorNoEnd("scan_type");

    return;
}

static void ParseSenseLevel(int *sense_level)
{
    char *pcTok;
    
    if(!sense_level)
        return;

    *sense_level = 0;

    pcTok = strtok(NULL, DELIMITERS);
    while(pcTok)
    {
        if(!strcasecmp(pcTok, "low"))
            *sense_level = PS_SENSE_LOW;
        else if(!strcasecmp(pcTok, "medium"))
            *sense_level = PS_SENSE_MEDIUM;
        else if(!strcasecmp(pcTok, "high"))
            *sense_level = PS_SENSE_HIGH;
        else if(!strcmp(pcTok, TOKEN_ARG_END))
            return;
        else
            FatalErrorInvalidArg("sense_level");

        pcTok = strtok(NULL, DELIMITERS);
    }

    if(!pcTok)
        FatalErrorNoEnd("sense_level");

    return;
}

static void ParseIpList(IPSET **ip_list, char *option)
{
    char *pcTok;

    if(!ip_list)
        return;

    pcTok = strtok(NULL, TOKEN_ARG_END);
    if(!pcTok)
        FatalErrorInvalidArg(option);

    *ip_list = ipset_new(IPV4_FAMILY);
    if(!*ip_list)
        FatalError("Failed to initialize ip_list in portscan preprocessor.\n");

    if(ip4_setparse(*ip_list, pcTok))
        FatalError("%s(%d) => Invalid ip_list to '%s' option.\n",
                file_name, file_line, option);

    return;
}

static void ParseMemcap(int *memcap)
{
    char *pcTok;

    if(!memcap)
        return;
    
    *memcap = 0;
    
    pcTok = strtok(NULL, DELIMITERS);
    if(!pcTok)
        FatalErrorNoEnd("memcap");

    *memcap = atoi(pcTok);

    if(*memcap <= 0)
        FatalErrorInvalidArg("memcap");

    pcTok = strtok(NULL, DELIMITERS);
    if(!pcTok)
        FatalErrorNoEnd("memcap");

    if(strcmp(pcTok, TOKEN_ARG_END))
        FatalErrorInvalidArg("memcap");
    
    return;
}

static void PrintCIDRBLOCK(CIDRBLOCK *p)
{
    char ip_str[80], mask_str[80];
    PORTRANGE *pr;

    ip4_sprintx(ip_str, sizeof(ip_str), &p->ip);
    ip4_sprintx(mask_str, sizeof(mask_str), &p->mask);

    if(p->notflag)
        LogMessage("        !%s / %s", ip_str, mask_str);
    else
        LogMessage("        %s / %s", ip_str, mask_str);

    pr=(PORTRANGE*)sflist_first(&p->portset.port_list);
    if ( pr && pr->port_lo != 0 )
        LogMessage(":");
    for( ; pr != 0;
        pr=(PORTRANGE*)sflist_next(&p->portset.port_list) )
    {
        if ( pr->port_lo != 0 )
        {
            LogMessage("%d", pr->port_lo);
            if ( pr->port_hi != pr->port_lo )
            {
                LogMessage("-%d", pr->port_hi);
            }   
            LogMessage(" ");
        }
    }
    LogMessage("\n");

}

static void PrintPortscanConf(int detect_scans, int detect_scan_type,
        int sense_level, IPSET *scanner, IPSET *scanned, IPSET *watch,
        int memcap)
{
    char buf[STD_BUF+1];
    int proto_cnt = 0;
    CIDRBLOCK *p;

    LogMessage("Portscan Detection Config:\n");
    
    memset(buf, 0, STD_BUF+1);
    snprintf(buf, STD_BUF, "    Detect Protocols:  ");
    if(detect_scans & PS_PROTO_TCP)  { sfsnprintfappend(buf, STD_BUF, "TCP ");  proto_cnt++; }
    if(detect_scans & PS_PROTO_UDP)  { sfsnprintfappend(buf, STD_BUF, "UDP ");  proto_cnt++; }
    if(detect_scans & PS_PROTO_ICMP) { sfsnprintfappend(buf, STD_BUF, "ICMP "); proto_cnt++; }
    if(detect_scans & PS_PROTO_IP)   { sfsnprintfappend(buf, STD_BUF, "IP");    proto_cnt++; }
    LogMessage("%s\n", buf);

    memset(buf, 0, STD_BUF+1);
    snprintf(buf, STD_BUF, "    Detect Scan Type:  ");
    if(detect_scan_type & PS_TYPE_PORTSCAN)
        sfsnprintfappend(buf, STD_BUF, "portscan ");
    if(detect_scan_type & PS_TYPE_PORTSWEEP)
        sfsnprintfappend(buf, STD_BUF, "portsweep ");
    if(detect_scan_type & PS_TYPE_DECOYSCAN)
        sfsnprintfappend(buf, STD_BUF, "decoy_portscan ");
    if(detect_scan_type & PS_TYPE_DISTPORTSCAN)
        sfsnprintfappend(buf, STD_BUF, "distributed_portscan");
    LogMessage("%s\n", buf);

    memset(buf, 0, STD_BUF+1);
    snprintf(buf, STD_BUF, "    Sensitivity Level: ");
    if(sense_level == PS_SENSE_HIGH)
        sfsnprintfappend(buf, STD_BUF, "High/Experimental");
    if(sense_level == PS_SENSE_MEDIUM)
        sfsnprintfappend(buf, STD_BUF, "Medium");
    if(sense_level == PS_SENSE_LOW)
        sfsnprintfappend(buf, STD_BUF, "Low");
    LogMessage("%s\n", buf);

    LogMessage("    Memcap (in bytes): %d\n", memcap);
    LogMessage("    Number of Nodes:   %d\n",
            memcap / (sizeof(PS_PROTO)*proto_cnt-1));

    if(g_logpath[0])
        LogMessage("    Logfile:           %s\n", g_logpath); 

    if(scanner)
    {
        LogMessage("    Ignore Scanner IP List:\n");
        for(p = (CIDRBLOCK*)sflist_first(&scanner->cidr_list);
            p;
            p = (CIDRBLOCK*)sflist_next(&scanner->cidr_list))
        {
            PrintCIDRBLOCK(p);
        }
    }

    if(scanned)
    {
        LogMessage("    Ignore Scanned IP List:\n");
        for(p = (CIDRBLOCK*)sflist_first(&scanned->cidr_list);
            p;
            p = (CIDRBLOCK*)sflist_next(&scanned->cidr_list))
        {
            PrintCIDRBLOCK(p);
        }
    }

    if(watch)
    {
        LogMessage("    Ignore Watch IP List:\n");
        for(p = (CIDRBLOCK*)sflist_first(&watch->cidr_list);
            p;
            p = (CIDRBLOCK*)sflist_next(&watch->cidr_list))
        {
            PrintCIDRBLOCK(p);
        }
    }

    LogMessage("\n");

    return;
}

static void ParseLogFile(FILE **flog, u_char *logfile, int logfile_size)
{
    char *pcTok;

    pcTok = strtok(NULL, DELIMITERS);
    if(!pcTok)
        FatalErrorNoEnd("logfile");

    if(pcTok[0] == '/')
        SnortSnprintf(logfile, logfile_size, "%s", pcTok);
    else
        SnortSnprintf(logfile, logfile_size, "%s/%s", pv.log_dir,pcTok);

    pcTok = strtok(NULL, DELIMITERS);
    if(!pcTok)
        FatalErrorNoEnd("logfile");

    if(strcmp(pcTok, TOKEN_ARG_END))
        FatalErrorInvalidArg("logfile");

    *flog = fopen(logfile, "a+");
    if(!(*flog))
        FatalError("%s(%d) => '%s' could not be opened.\n", 
                file_name, file_line, logfile);
    
    return;
}
    
static void PortscanInit(u_char *args)
{
    int    sense_level = PS_SENSE_LOW;
    int    protos      = (PS_PROTO_TCP | PS_PROTO_UDP);
    int    scan_types  = PS_TYPE_ALL;
    int    memcap      = 1048576;
    IPSET *ignore_scanners = NULL;
    IPSET *ignore_scanned = NULL;
    IPSET *watch_ip = NULL;
    char  *pcTok;
    int    iRet;

    g_logpath[0] = 0x00;

    if(args)
    {
        pcTok = strtok(args, DELIMITERS);
        while(pcTok)
        {
            if(!strcasecmp(pcTok, "proto"))
            {
                pcTok = strtok(NULL, DELIMITERS);
                if(!pcTok || strcmp(pcTok, TOKEN_ARG_BEGIN))
                    FatalErrorNoOption("proto");

                ParseProtos(&protos);
            }
            else if(!strcasecmp(pcTok, "scan_type"))
            {
                pcTok = strtok(NULL, DELIMITERS);
                if(!pcTok || strcmp(pcTok, TOKEN_ARG_BEGIN))
                    FatalErrorNoOption("scan_type");

                ParseScanType(&scan_types);
            }
            else if(!strcasecmp(pcTok, "sense_level"))
            {
                pcTok = strtok(NULL, DELIMITERS);
                if(!pcTok || strcmp(pcTok, TOKEN_ARG_BEGIN))
                    FatalErrorNoOption("sense_level");

                ParseSenseLevel(&sense_level);
            }
            else if(!strcasecmp(pcTok, "ignore_scanners"))
            {
                pcTok = strtok(NULL, DELIMITERS);
                if(!pcTok || strcmp(pcTok, TOKEN_ARG_BEGIN))
                    FatalErrorNoOption("ignore_scanners");

                ParseIpList(&ignore_scanners, "ignore_scanners");
            }
            else if(!strcasecmp(pcTok, "ignore_scanned"))
            {
                pcTok = strtok(NULL, DELIMITERS);
                if(!pcTok || strcmp(pcTok, TOKEN_ARG_BEGIN))
                    FatalErrorNoOption("ignore_scanned");

                ParseIpList(&ignore_scanned, "ignore_scanned");
            }
            else if(!strcasecmp(pcTok, "watch_ip"))
            {
                pcTok = strtok(NULL, DELIMITERS);
                if(!pcTok || strcmp(pcTok, TOKEN_ARG_BEGIN))
                    FatalErrorNoOption("watch_ip");

                ParseIpList(&watch_ip, "watch_ip");
            }
            else if(!strcasecmp(pcTok, "print_tracker"))
            {
                g_print_tracker = 1;
            }
            else if(!strcasecmp(pcTok, "memcap"))
            {
                pcTok = strtok(NULL, DELIMITERS);
                if(!pcTok || strcmp(pcTok, TOKEN_ARG_BEGIN))
                    FatalErrorNoOption("memcap");

                ParseMemcap(&memcap);
            }
            else if(!strcasecmp(pcTok, "logfile"))
            {
                pcTok = strtok(NULL, DELIMITERS);
                if(!pcTok || strcmp(pcTok, TOKEN_ARG_BEGIN))
                    FatalErrorNoOption("logfile");

                ParseLogFile(&g_logfile, g_logpath, sizeof(g_logpath));
            }
            else if(!strcasecmp(pcTok, "include_midstream"))
            {
                /* Do not ignore packets in sessions picked up mid-stream */
                g_include_midstream = 1;
            }
            else if(!strcasecmp(pcTok, "detect_ack_scans"))
            {
                /* 
                 *  We will only see ack scan packets if we are looking at sessions that the
                 *    have been flagged as being picked up mid-stream
                 */
                g_include_midstream = 1;
            }
            else
            {
                FatalErrorInvalidOption(pcTok);
            }

            pcTok = strtok(NULL, DELIMITERS);
        }
    }

    if((iRet = ps_init(protos, scan_types, sense_level, ignore_scanners,
                ignore_scanned, watch_ip, memcap)))
    {
        if(iRet == -2)
        {
            FatalError("%s(%d) => 'memcap' limit not sufficient to run "
                       "sfportscan preprocessor.  Please increase this "
                       "value or keep the default memory usage.\n", 
                       file_name, file_line);
        }

        FatalError("Failed to initialize the sfportscan detection module.  "
                   "Please check your configuration before submitting a "
                   "bug.\n");
    }

    AddFuncToPreprocList(PortscanDetect, PRIORITY_SCANNER, PP_SFPORTSCAN);
    AddFuncToPreprocCleanExitList(PortscanCleanExitFunction, NULL, PRIORITY_SCANNER, PP_SFPORTSCAN);
    AddFuncToPreprocRestartList(PortscanRestartFunction, NULL, PRIORITY_SCANNER, PP_SFPORTSCAN);    

    PrintPortscanConf(protos, scan_types, sense_level, ignore_scanners,
            ignore_scanned, watch_ip, memcap);

    PortscanPacketInit();

#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("sfportscan", &sfpsPerfStats, 0, &totalPerfStats);
#endif

    return;
}

void SetupPsng(void)
{
    RegisterPreprocessor("sfportscan", PortscanInit);

    return;
}
