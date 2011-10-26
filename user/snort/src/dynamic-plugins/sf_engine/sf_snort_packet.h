/*
 * sf_snort_packet.h
 *
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
 *
 * Copyright (C) 2005 Sourcefire Inc.
 *
 * Author: Steve Sturges
 *         Andy Mullican
 *
 * Date: 5/2005
 *
 * Sourcefire Black-box Plugin API for rules
 *
 */
#ifndef _SF_SNORT_PACKET_H_
#define _SF_SNORT_PACKET_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef WIN32
#include <sys/types.h>
#include <netinet/in.h>
#else
typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned long u_int32_t;
typedef char int8_t;
typedef short int16_t;
typedef long int32_t;
#include <winsock2.h>
#include <windows.h>
#endif

#define IP_RESBIT       0x8000
#ifdef IP_DONTFRAG
#undef IP_DONTFRAG
#endif
#define IP_DONTFRAG     0x4000
#define IP_MOREFRAGS    0x2000

typedef struct _IPV4Header
{
    u_int8_t version_headerlength;
    u_int8_t type_service;
    u_int16_t data_length;
    u_int16_t identifier;
    u_int16_t offset;
    u_int8_t time_to_live;
    u_int8_t proto;
    u_int16_t checksum;
    struct in_addr source;
    struct in_addr destination;
} IPV4Header;

#define MAX_IP_OPTIONS 40
/* ip option codes */
#define IPOPTION_EOL            0x00
#define IPOPTION_NOP            0x01
#define IPOPTION_RR             0x07
#define IPOPTION_RTRALT         0x14
#define IPOPTION_TS             0x44
#define IPOPTION_SECURITY       0x82
#define IPOPTION_LSRR           0x83
#define IPOPTION_LSRR_E         0x84
#define IPOPTION_SATID          0x88
#define IPOPTION_SSRR           0x89

typedef struct _IPOptions
{
    u_int8_t option_code;
    u_int8_t length;
    u_int8_t *option_data;
} IPOptions;

typedef struct _TCPHeader
{
    u_int16_t source_port;
    u_int16_t destination_port;
    u_int32_t sequence;
    u_int32_t acknowledgement;
    u_int8_t offset_reserved;
    u_int8_t flags;
    u_int16_t window;
    u_int16_t checksum;
    u_int16_t urgent_pointer;
} TCPHeader;

#define TCPHEADER_FIN  0x01
#define TCPHEADER_SYN  0x02
#define TCPHEADER_RST  0x04
#define TCPHEADER_PUSH 0x08
#define TCPHEADER_ACK  0x10
#define TCPHEADER_URG  0x20
#define TCPHEADER_RES2 0x40
#define TCPHEADER_RES1 0x80
#define TCPHEADER_NORESERVED (TCPHEADER_FIN|TCPHEADER_SYN|TCPHEADER_RST \
                            |TCPHEADER_PUSH|TCPHEADER_ACK|TCPHEADER_URG)

#define MAX_TCP_OPTIONS 40
/* tcp option codes */
#define TCPOPT_EOL              0x00
#define TCPOPT_NOP              0x01
#define TCPOPT_MSS              0x02
#define TCPOPT_WSCALE           0x03     /* window scale factor (rfc1072) */
#define TCPOPT_SACKOK           0x04     /* selective ack ok (rfc1072) */
#define TCPOPT_SACK             0x05     /* selective ack (rfc1072) */
#define TCPOPT_ECHO             0x06     /* echo (rfc1072) */
#define TCPOPT_ECHOREPLY        0x07     /* echo (rfc1072) */
#define TCPOPT_TIMESTAMP        0x08     /* timestamps (rfc1323) */
#define TCPOPT_CC               0x11     /* T/TCP CC options (rfc1644) */
#define TCPOPT_CCNEW            0x12     /* T/TCP CC options (rfc1644) */
#define TCPOPT_CCECHO           0x13     /* T/TCP CC options (rfc1644) */

typedef IPOptions TCPOptions;

typedef struct _UDPHeader
{
    u_int16_t source_port;
    u_int16_t destination_port;
    u_int16_t data_length;
    u_int16_t checksum;
} UDPHeader;

typedef struct _ICMPSequenceID
{
    u_int16_t id;
    u_int16_t seq;
} ICMPSequenceID;

typedef struct _ICMPHeader
{
    u_int8_t type;
    u_int8_t code;
    u_int16_t checksum;

    union
    {
        /* type 12 */
        u_int8_t parameter_problem_ptr; 

        /* type 5 */
        struct in_addr gateway_addr;

        /* type 8, 0 */
        ICMPSequenceID echo;

        /* type 13, 14 */
        ICMPSequenceID timestamp;
        
        /* type 15, 16 */
        ICMPSequenceID info;
        
        int voidInfo;

        /* type 3/code=4 (Path MTU, RFC 1191) */
        struct path_mtu
        {
            u_int16_t voidInfo;
            u_int16_t next_mtu;
        } path_mtu;

        /* type 9 */
        struct router_advertisement 
        {
            u_int8_t number_addrs;
            u_int8_t entry_size;
            u_int16_t lifetime;
        } router_advertisement;
    } icmp_header_union;

#define icmp_parameter_ptr  icmp_header_union.parameter_problem_ptr
#define icmp_gateway_addr   icmp_header_union.gateway_waddr
#define icmp_echo_id        icmp_header_union.echo.id
#define icmp_echo_seq       icmp_header_union.echo.seq
#define icmp_timestamp_id   icmp_header_union.timestamp.id
#define icmp_timestamp_seq  icmp_header_union.timestamp.seq
#define icmp_info_id        icmp_header_union.info.id
#define icmp_info_seq       icmp_header_union.info.seq
#define icmp_void           icmp_header_union.void
#define icmp_nextmtu        icmp_header_union.path_mtu.nextmtu
#define icmp_ra_num_addrs   icmp_header_union.router_advertisement.number_addrs
#define icmp_ra_entry_size  icmp_header_union.router_advertisement.entry_size
#define icmp_ra_lifetime    icmp_header_union.router_advertisement.lifetime

    union 
    {
        /* timestamp */
        struct timestamp 
        {
            u_int32_t orig;
            u_int32_t receive;
            u_int32_t transmit;
        } timestamp;
        
        /* IP header for unreach */
        struct ipv4_header  
        {
            IPV4Header *ip;
            /* options and then 64 bits of data */
        } ipv4_header;
       
        /* Router Advertisement */ 
        struct router_address 
        {
            u_int32_t addr;
            u_int32_t preference;
        } router_address;

        /* type 17, 18 */
        u_int32_t mask;

        char    data[1];

    } icmp_data_union;
#define icmp_orig_timestamp     icmp_data_union.timestamp.orig
#define icmp_recv_timestamp     icmp_data_union.timestamp.receive
#define icmp_xmit_timestamp     icmp_data_union.timestamp.transmit
#define icmp_ipheader           icmp_data_union.ip_header
#define icmp_ra_addr0           icmp_data_union.router_address
#define icmp_mask               icmp_data_union.mask
#define icmp_data               icmp_data_union.data
} ICMPHeader;

#define ICMP_ECHO_REPLY             0    /* Echo Reply                   */
#define ICMP_DEST_UNREACHABLE       3    /* Destination Unreachable      */
#define ICMP_SOURCE_QUENCH          4    /* Source Quench                */
#define ICMP_REDIRECT               5    /* Redirect (change route)      */
#define ICMP_ECHO_REQUEST           8    /* Echo Request                 */
#define ICMP_ROUTER_ADVERTISEMENT   9    /* Router Advertisement         */
#define ICMP_ROUTER_SOLICITATION    10    /* Router Solicitation          */
#define ICMP_TIME_EXCEEDED          11    /* Time Exceeded                */
#define ICMP_PARAMETER_PROBLEM      12    /* Parameter Problem            */
#define ICMP_TIMESTAMP_REQUEST      13    /* Timestamp Request            */
#define ICMP_TIMESTAMP_REPLY        14    /* Timestamp Reply              */
#define ICMP_INFO_REQUEST           15    /* Information Request          */
#define ICMP_INFO_REPLY             16    /* Information Reply            */
#define ICMP_ADDRESS_REQUEST        17    /* Address Mask Request         */
#define ICMP_ADDRESS_REPLY          18    /* Address Mask Reply           */

#define CHECKSUM_INVALID_IP 0x01
#define CHECKSUM_INVALID_TCP 0x02
#define CHECKSUM_INVALID_UDP 0x04
#define CHECKSUM_INVALID_ICMP 0x08
#define CHECKSUM_INVALID_IGMP 0x10

typedef struct _SFSnortPacket
{
    struct pcap_pkthdr *pcap_header; /* Is this GPF'd? */
    u_int8_t *pkt_data;

    void *fddi_header;
    void *fddi_saps;
    void *fddi_sna;
    void *fddi_iparp;
    void *fddi_other;

    void *tokenring_header;
    void *tokenring_header_llc;
    void *tokenring_header_mr;

    void *sll_header;

    void *pflog_header;
    void *old_pflog_header;

    void *ether_header;
    void *vlan_tag_header;

    void *ether_header_llc;
    void *ether_header_other;

    void *wifi_header;

    void *ether_arp_header;

    void *ether_eapol_header; /* 802.1x */
    void *eapol_headear;
    u_int8_t *eapol_type;
    void *eapol_key;

    void *ppp_over_ether_header;

    IPV4Header *ip4_header, *orig_ip4_header;
    u_int32_t ip4_options_length;
    void *ip4_options_data;

    TCPHeader *tcp_header, *orig_tcp_header;
    u_int32_t tcp_options_length;
    void *tcp_options_data;

    UDPHeader *udp_header, *orig_udp_header;
    ICMPHeader *icmp_header, *orig_icmp_header;

#ifdef GRE
    void *gre_header;
#endif

    u_int8_t *payload;
    u_int16_t payload_size;
    u_int16_t normalized_payload_size;

    u_int16_t actual_ip_length;

    u_int8_t ip_fragmented;
    u_int16_t ip_fragment_offset;
    u_int8_t ip_more_fragments;
    u_int8_t ip_dont_fragment;
    u_int8_t ip_reserved;

    u_int16_t src_port;
    u_int16_t dst_port;
    u_int16_t orig_src_port;
    u_int16_t orig_dst_port;
    u_int32_t pcap_cap_len;

    u_int8_t num_uris;

    void *stream_session_ptr;
    void *fragmentation_tracking_ptr;
    void *flow_ptr;
    void *stream_ptr;

    IPOptions ip_options[MAX_IP_OPTIONS];
    u_int32_t num_ip_options;
    u_int8_t ip_last_option_invalid_flag;
    
    TCPOptions tcp_options[MAX_TCP_OPTIONS];
    u_int32_t num_tcp_options;
    u_int8_t tcp_last_option_invalid_flag;

    u_int8_t checksums_invalid;
    u_int32_t flags;
    u_int32_t number_bytes_to_check;

    void *preprocessor_bit_mask;

} SFSnortPacket;

#define IsIP(p) (p->ip4_header != NULL)
#define IsTCP(p) ((p->ip4_header != NULL) && (p->tcp_header != NULL))
#define IsUDP(p) ((p->ip4_header != NULL) && (p->udp_header != NULL))
#define IsICMP(p) ((p->ip4_header != NULL) && (p->icmp_header != NULL))


#define FLAG_REBUILT_FRAG     0x00000001
#define FLAG_REBUILT_STREAM   0x00000002
#define FLAG_STREAM_UNEST_UNI 0x00000004
#define FLAG_STREAM_UNEST_BI  0x00000008
#define FLAG_STREAM_EST       0x00000010
#define FLAG_FROM_SERVER      0x00000040	
#define FLAG_FROM_CLIENT      0x00000080
#define FLAG_HTTP_DECODE      0x00000100
#define FLAG_STREAM_INSERT    0x00000400
#define FLAG_ALT_DECODE       0x00000800

#endif /* _SF_SNORT_PACKET_H_ */

