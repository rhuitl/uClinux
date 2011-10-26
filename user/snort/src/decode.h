/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

/* $Id$ */


#ifndef __DECODE_H__
#define __DECODE_H__


/*  I N C L U D E S  **********************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <pcap.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#else /* !WIN32 */
#include <netinet/in_systm.h>
#include "libnet/IPExport.h"
#ifndef IFNAMSIZ
#define IFNAMESIZ MAX_ADAPTER_NAME
#endif /* !IFNAMSIZ */
#endif /* !WIN32 */
//#include "ubi_SplayTree.h"
#include "bitop.h"


/*  D E F I N E S  ************************************************************/
#define ETHERNET_MTU                  1500
#define ETHERNET_TYPE_IP              0x0800
#define ETHERNET_TYPE_ARP             0x0806
#define ETHERNET_TYPE_REVARP          0x8035
#define ETHERNET_TYPE_EAPOL           0x888e
#define ETHERNET_TYPE_IPV6            0x86dd
#define ETHERNET_TYPE_IPX             0x8137
#define ETHERNET_TYPE_PPPoE_DISC      0x8863 /* discovery stage */
#define ETHERNET_TYPE_PPPoE_SESS      0x8864 /* session stage */
#define ETHERNET_TYPE_8021Q           0x8100
#define ETHERNET_TYPE_LOOP            0x9000

#define ETH_DSAP_SNA                  0x08    /* SNA */
#define ETH_SSAP_SNA                  0x00    /* SNA */
#define ETH_DSAP_STP                  0x42    /* Spanning Tree Protocol */
#define ETH_SSAP_STP                  0x42    /* Spanning Tree Protocol */
#define ETH_DSAP_IP                   0xaa    /* IP */
#define ETH_SSAP_IP                   0xaa    /* IP */

#define ETH_ORG_CODE_ETHR              0x000000    /* Encapsulated Ethernet */
#define ETH_ORG_CODE_CDP               0x00000c    /* Cisco Discovery Proto */

#define ETHERNET_HEADER_LEN             14
#define ETHERNET_MAX_LEN_ENCAP          1518    /* 802.3 (+LLC) or ether II ? */
#define PPPOE_HEADER_LEN                20    /* ETHERNET_HEADER_LEN + 6 */
#define MINIMAL_TOKENRING_HEADER_LEN    22
#define MINIMAL_IEEE80211_HEADER_LEN    10    /* Ack frames and others */
#define IEEE802_11_DATA_HDR_LEN         24    /* Header for data packets */
#define TR_HLEN                         MINIMAL_TOKENRING_HEADER_LEN
#define TOKENRING_LLC_LEN                8
#define SLIP_HEADER_LEN                 16

/* Frame type/subype combinations with version = 0 */
        /*** FRAME TYPE *****  HEX ****  SUBTYPE TYPE  DESCRIPT ********/
#define WLAN_TYPE_MGMT_ASREQ   0x0      /* 0000    00  Association Req */
#define WLAN_TYPE_MGMT_ASRES   0x10     /* 0001    00  Assocaition Res */
#define WLAN_TYPE_MGMT_REREQ   0x20     /* 0010    00  Reassoc. Req.   */
#define WLAN_TYPE_MGMT_RERES   0x30     /* 0011    00  Reassoc. Resp.  */
#define WLAN_TYPE_MGMT_PRREQ   0x40     /* 0100    00  Probe Request   */
#define WLAN_TYPE_MGMT_PRRES   0x50     /* 0101    00  Probe Response  */ 
#define WLAN_TYPE_MGMT_BEACON  0x80     /* 1000    00  Beacon          */
#define WLAN_TYPE_MGMT_ATIM    0x90     /* 1001    00  ATIM message    */
#define WLAN_TYPE_MGMT_DIS     0xa0     /* 1010    00  Disassociation  */
#define WLAN_TYPE_MGMT_AUTH    0xb0     /* 1011    00  Authentication  */
#define WLAN_TYPE_MGMT_DEAUTH  0xc0     /* 1100    00  Deauthentication*/

#define WLAN_TYPE_CONT_PS      0xa4     /* 1010    01  Power Save      */
#define WLAN_TYPE_CONT_RTS     0xb4     /* 1011    01  Request to send */
#define WLAN_TYPE_CONT_CTS     0xc4     /* 1100    01  Clear to sene   */
#define WLAN_TYPE_CONT_ACK     0xd4     /* 1101    01  Acknowledgement */
#define WLAN_TYPE_CONT_CFE     0xe4     /* 1110    01  Cont. Free end  */
#define WLAN_TYPE_CONT_CFACK   0xf4     /* 1111    01  CF-End + CF-Ack */

#define WLAN_TYPE_DATA_DATA    0x08     /* 0000    10  Data            */
#define WLAN_TYPE_DATA_DTCFACK 0x18     /* 0001    10  Data + CF-Ack   */
#define WLAN_TYPE_DATA_DTCFPL  0x28     /* 0010    10  Data + CF-Poll  */
#define WLAN_TYPE_DATA_DTACKPL 0x38     /* 0011    10  Data+CF-Ack+CF-Pl */
#define WLAN_TYPE_DATA_NULL    0x48     /* 0100    10  Null (no data)  */
#define WLAN_TYPE_DATA_CFACK   0x58     /* 0101    10  CF-Ack (no data)*/
#define WLAN_TYPE_DATA_CFPL    0x68     /* 0110    10  CF-Poll (no data)*/
#define WLAN_TYPE_DATA_ACKPL   0x78     /* 0111    10  CF-Ack+CF-Poll  */

/*** Flags for IEEE 802.11 Frame Control ***/
/* The following are designed to be bitwise-AND-d in an 8-bit u_char */
#define WLAN_FLAG_TODS      0x0100    /* To DS Flag   10000000 */
#define WLAN_FLAG_FROMDS    0x0200    /* From DS Flag 01000000 */
#define WLAN_FLAG_FRAG      0x0400    /* More Frag    00100000 */
#define WLAN_FLAG_RETRY     0x0800    /* Retry Flag   00010000 */
#define WLAN_FLAG_PWRMGMT   0x1000    /* Power Mgmt.  00001000 */
#define WLAN_FLAG_MOREDAT   0x2000    /* More Data    00000100 */
#define WLAN_FLAG_WEP       0x4000    /* Wep Enabled  00000010 */
#define WLAN_FLAG_ORDER     0x8000    /* Strict Order 00000001 */

/* IEEE 802.1x eapol types */
#define EAPOL_TYPE_EAP      0x00      /* EAP packet */
#define EAPOL_TYPE_START    0x01      /* EAPOL start */
#define EAPOL_TYPE_LOGOFF   0x02      /* EAPOL Logoff */
#define EAPOL_TYPE_KEY      0x03      /* EAPOL Key */
#define EAPOL_TYPE_ASF      0x04      /* EAPOL Encapsulated ASF-Alert */

/* Extensible Authentication Protocol Codes RFC 2284*/
#define EAP_CODE_REQUEST    0x01   
#define EAP_CODE_RESPONSE   0x02
#define EAP_CODE_SUCCESS    0x03
#define EAP_CODE_FAILURE    0x04
/* EAP Types */
#define EAP_TYPE_IDENTITY   0x01
#define EAP_TYPE_NOTIFY     0x02
#define EAP_TYPE_NAK        0x03
#define EAP_TYPE_MD5        0x04
#define EAP_TYPE_OTP        0x05
#define EAP_TYPE_GTC        0x06
#define EAP_TYPE_TLS        0x0d

/* Cisco HDLC header values */
#define CHDLC_HEADER_LEN        4
#define CHDLC_ADDR_UNICAST      0x0f
#define CHDLC_ADDR_MULTICAST    0x8f
#define CHDLC_ADDR_BROADCAST    0xff
#define CHDLC_CTRL_UNNUMBERED   0x03

/* ppp header structure
 *
 * Actually, this is the header for RFC1332 Section 3
 * IPCP Configuration Options for sending IP datagrams over a PPP link
 *
 */
struct ppp_header {
    unsigned char  address;
    unsigned char  control;
    unsigned short protocol;
};

#ifndef PPP_HDRLEN
    #define PPP_HDRLEN          sizeof(struct ppp_header)
#endif

#define PPP_IP         0x0021        /* Internet Protocol */
#define PPP_VJ_COMP    0x002d        /* VJ compressed TCP/IP */
#define PPP_VJ_UCOMP   0x002f        /* VJ uncompressed TCP/IP */
#define PPP_IPX        0x002b        /* Novell IPX Protocol */

/* otherwise defined in /usr/include/ppp_defs.h */
#ifndef PPP_MTU
    #define PPP_MTU                 1500
#endif

/* NULL aka LoopBack interfaces */
#define NULL_HDRLEN             4

/* enc interface */
struct enc_header {
    u_int32_t af;
    u_int32_t spi;
    u_int32_t flags;
};
#define ENC_HEADER_LEN          12

/* otherwise defined in /usr/include/ppp_defs.h */
#define IP_HEADER_LEN           20
#define TCP_HEADER_LEN          20
#define UDP_HEADER_LEN          8
#define ICMP_HEADER_LEN         4

#define IP_OPTMAX               40
#define TCP_OPTLENMAX           40 /* (((2^4) - 1) * 4  - TCP_HEADER_LEN) */

#ifndef IP_MAXPACKET
#define IP_MAXPACKET    65535        /* maximum packet size */
#endif /* IP_MAXPACKET */

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_RES2 0x40
#define TH_RES1 0x80
#define TH_NORESERVED (TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG)

/* http://www.iana.org/assignments/tcp-parameters
 *
 * tcp options stuff. used to be in <netinet/tcp.h> but it breaks
 * things on AIX
 */
#define TCPOPT_EOL              0   /* End of Option List [RFC793] */
#define TCPOLEN_EOL             1   /* Always one byte */

#define TCPOPT_NOP              1   /* No-Option [RFC793] */
#define TCPOLEN_NOP             1   /* Always one byte */

#define TCPOPT_MAXSEG           2   /* Maximum Segment Size [RFC793] */
#define TCPOLEN_MAXSEG          4   /* Always 4 bytes */

#define TCPOPT_WSCALE           3   /* Window scaling option [RFC1323] */
#define TCPOLEN_WSCALE          3   /* 1 byte with logarithmic values */

#define TCPOPT_SACKOK           4    /* Experimental [RFC2018]*/
#define TCPOLEN_SACKOK          2

#define TCPOPT_SACK             5    /* Experimental [RFC2018] variable length */

#define TCPOPT_ECHO             6    /* Echo (obsoleted by option 8)      [RFC1072] */
#define TCPOLEN_ECHO            6    /* 6 bytes  */

#define TCPOPT_ECHOREPLY        7    /* Echo Reply (obsoleted by option 8)[RFC1072] */
#define TCPOLEN_ECHOREPLY       6    /* 6 bytes  */

#define TCPOPT_TIMESTAMP        8   /* Timestamp [RFC1323], 10 bytes */
#define TCPOLEN_TIMESTAMP       10

#define TCPOPT_PARTIAL_PERM     9   /* Partial Order Permitted/ Experimental [RFC1693] */
#define TCPOLEN_PARTIAL_PERM    2   /* Partial Order Permitted/ Experimental [RFC1693] */

#define TCPOPT_PARTIAL_SVC      10  /*  Partial Order Profile [RFC1693] */
#define TCPOLEN_PARTIAL_SVC     3   /*  3 bytes long -- Experimental */

/* atleast decode T/TCP options... */
#define TCPOPT_CC               11  /*  T/TCP Connection count  [RFC1644] */
#define TCPOPT_CC_NEW           12  /*  CC.NEW [RFC1644] */
#define TCPOPT_CC_ECHO          13  /*  CC.ECHO [RFC1644] */
#define TCPOLEN_CC             6  /* page 17 of rfc1644 */
#define TCPOLEN_CC_NEW         6  /* page 17 of rfc1644 */
#define TCPOLEN_CC_ECHO        6  /* page 17 of rfc1644 */

#define TCPOPT_ALTCSUM          15  /* TCP Alternate Checksum Data [RFC1146], variable length */
#define TCPOPT_SKEETER          16  /* Skeeter [Knowles] */
#define TCPOPT_BUBBA            17  /* Bubba   [Knowles] */

#define TCPOPT_TRAILER_CSUM     18  /* Trailer Checksum Option [Subbu & Monroe] */
#define TCPOLEN_TRAILER_CSUM  3  

#define TCPOPT_MD5SIG           19  /* MD5 Signature Option [RFC2385] */
#define TCPOLEN_MD5SIG        18

/* Space Communications Protocol Standardization */
#define TCPOPT_SCPS             20  /* Capabilities [Scott] */
#define TCPOPT_SELNEGACK        21  /* Selective Negative Acknowledgements [Scott] */
#define TCPOPT_RECORDBOUND         22  /* Record Boundaries [Scott] */
#define TCPOPT_CORRUPTION          23  /* Corruption experienced [Scott] */

#define TCPOPT_SNAP                24  /* SNAP [Sukonnik] -- anyone have info?*/
#define TCPOPT_UNASSIGNED          25  /* Unassigned (released 12/18/00) */
#define TCPOPT_COMPRESSION         26  /* TCP Compression Filter [Bellovin] */
/* http://www.research.att.com/~smb/papers/draft-bellovin-tcpcomp-00.txt*/

#define TCP_OPT_TRUNC -1
#define TCP_OPT_BADLEN -2

/* Why are these lil buggers here? Never Used. -- cmg */
#define TCPOLEN_TSTAMP_APPA     (TCPOLEN_TIMESTAMP+2)    /* appendix A / rfc 1323 */
#define TCPOPT_TSTAMP_HDR    \
    (TCPOPT_NOP<<24|TCPOPT_NOP<<16|TCPOPT_TIMESTAMP<<8|TCPOLEN_TIMESTAMP)

/*
 * Default maximum segment size for TCP.
 * With an IP MSS of 576, this is 536,
 * but 512 is probably more convenient.
 * This should be defined as MIN(512, IP_MSS - sizeof (struct tcpiphdr)).
 */

#ifndef TCP_MSS
    #define    TCP_MSS      512
#endif

#ifndef TCP_MAXWIN
    #define    TCP_MAXWIN   65535    /* largest value for (unscaled) window */
#endif

#ifndef TCP_MAX_WINSHIFT 
    #define TCP_MAX_WINSHIFT    14    /* maximum window shift */
#endif

/*
 * User-settable options (used with setsockopt).
 */
#ifndef TCP_NODELAY
    #define    TCP_NODELAY   0x01    /* don't delay send to coalesce packets */
#endif

#ifndef TCP_MAXSEG
    #define    TCP_MAXSEG    0x02    /* set maximum segment size */
#endif

#define SOL_TCP        6    /* TCP level */



#define L2TP_PORT           1701
#define DHCP_CLIENT_PORT    68
#define DHCP_SERVER_PORT    67

/* IRIX 6.2 hack! */
#ifndef IRIX
    #define SNAPLEN         1514
#else
    #define SNAPLEN         1500
#endif

#define MIN_SNAPLEN         68
#define PROMISC             1
#define READ_TIMEOUT        500

/* Start Token Ring */
#define TR_ALEN             6        /* octets in an Ethernet header */
#define IPARP_SAP           0xaa

#define AC                  0x10
#define LLC_FRAME           0x40

#define TRMTU                      2000    /* 2000 bytes            */
#define TR_RII                     0x80
#define TR_RCF_DIR_BIT             0x80
#define TR_RCF_LEN_MASK            0x1f00
#define TR_RCF_BROADCAST           0x8000    /* all-routes broadcast   */
#define TR_RCF_LIMITED_BROADCAST   0xC000    /* single-route broadcast */
#define TR_RCF_FRAME2K             0x20
#define TR_RCF_BROADCAST_MASK      0xC000
/* End Token Ring */

/* Start FDDI */
#define FDDI_ALLC_LEN                   13
#define FDDI_ALEN                       6
#define FDDI_MIN_HLEN                   (FDDI_ALLC_LEN + 3)

#define FDDI_DSAP_SNA                   0x08    /* SNA */
#define FDDI_SSAP_SNA                   0x00    /* SNA */
#define FDDI_DSAP_STP                   0x42    /* Spanning Tree Protocol */
#define FDDI_SSAP_STP                   0x42    /* Spanning Tree Protocol */
#define FDDI_DSAP_IP                    0xaa    /* IP */
#define FDDI_SSAP_IP                    0xaa    /* IP */

#define FDDI_ORG_CODE_ETHR              0x000000    /* Encapsulated Ethernet */
#define FDDI_ORG_CODE_CDP               0x00000c    /* Cisco Discovery
                             * Proto(?) */

#define ETHERNET_TYPE_CDP               0x2000    /* Cisco Discovery Protocol */
/* End FDDI */

#define ARPOP_REQUEST   1    /* ARP request                  */
#define ARPOP_REPLY     2    /* ARP reply                    */
#define ARPOP_RREQUEST  3    /* RARP request                 */
#define ARPOP_RREPLY    4    /* RARP reply                   */

/* PPPoE types */
#define PPPoE_CODE_SESS 0x00 /* PPPoE session */
#define PPPoE_CODE_PADI 0x09 /* PPPoE Active Discovery Initiation */
#define PPPoE_CODE_PADO 0x07 /* PPPoE Active Discovery Offer */
#define PPPoE_CODE_PADR 0x19 /* PPPoE Active Discovery Request */
#define PPPoE_CODE_PADS 0x65 /* PPPoE Active Discovery Session-confirmation */
#define PPPoE_CODE_PADT 0xa7 /* PPPoE Active Discovery Terminate */

/* PPPoE tag types */
#define PPPoE_TAG_END_OF_LIST        0x0000
#define PPPoE_TAG_SERVICE_NAME       0x0101
#define PPPoE_TAG_AC_NAME            0x0102
#define PPPoE_TAG_HOST_UNIQ          0x0103
#define PPPoE_TAG_AC_COOKIE          0x0104
#define PPPoE_TAG_VENDOR_SPECIFIC    0x0105
#define PPPoE_TAG_RELAY_SESSION_ID   0x0110
#define PPPoE_TAG_SERVICE_NAME_ERROR 0x0201
#define PPPoE_TAG_AC_SYSTEM_ERROR    0x0202
#define PPPoE_TAG_GENERIC_ERROR      0x0203


#define ICMP_ECHOREPLY          0    /* Echo Reply                   */
#define ICMP_DEST_UNREACH       3    /* Destination Unreachable      */
#define ICMP_SOURCE_QUENCH      4    /* Source Quench                */
#define ICMP_REDIRECT           5    /* Redirect (change route)      */
#define ICMP_ECHO               8    /* Echo Request                 */
#define ICMP_ROUTER_ADVERTISE   9    /* Router Advertisement         */
#define ICMP_ROUTER_SOLICIT     10    /* Router Solicitation          */
#define ICMP_TIME_EXCEEDED      11    /* Time Exceeded                */
#define ICMP_PARAMETERPROB      12    /* Parameter Problem            */
#define ICMP_TIMESTAMP          13    /* Timestamp Request            */
#define ICMP_TIMESTAMPREPLY     14    /* Timestamp Reply              */
#define ICMP_INFO_REQUEST       15    /* Information Request          */
#define ICMP_INFO_REPLY         16    /* Information Reply            */
#define ICMP_ADDRESS            17    /* Address Mask Request         */
#define ICMP_ADDRESSREPLY       18    /* Address Mask Reply           */
#define NR_ICMP_TYPES           18

/* Codes for ICMP UNREACHABLES */
#define ICMP_NET_UNREACH        0    /* Network Unreachable          */
#define ICMP_HOST_UNREACH       1    /* Host Unreachable             */
#define ICMP_PROT_UNREACH       2    /* Protocol Unreachable         */
#define ICMP_PORT_UNREACH       3    /* Port Unreachable             */
#define ICMP_FRAG_NEEDED        4    /* Fragmentation Needed/DF set  */
#define ICMP_SR_FAILED          5    /* Source Route failed          */
#define ICMP_NET_UNKNOWN        6
#define ICMP_HOST_UNKNOWN       7
#define ICMP_HOST_ISOLATED      8
#define ICMP_PKT_FILTERED_NET   9
#define ICMP_PKT_FILTERED_HOST  10
#define ICMP_NET_UNR_TOS        11
#define ICMP_HOST_UNR_TOS       12
#define ICMP_PKT_FILTERED       13    /* Packet filtered */
#define ICMP_PREC_VIOLATION     14    /* Precedence violation */
#define ICMP_PREC_CUTOFF        15    /* Precedence cut off */
#define NR_ICMP_UNREACH         15    /* instead of hardcoding immediate
                                       * value */

#define ICMP_REDIR_NET          0
#define ICMP_REDIR_HOST         1
#define ICMP_REDIR_TOS_NET      2
#define ICMP_REDIR_TOS_HOST     3

#define ICMP_TIMEOUT_TRANSIT    0
#define ICMP_TIMEOUT_REASSY     1

#define ICMP_PARAM_BADIPHDR     0
#define ICMP_PARAM_OPTMISSING   1
#define ICMP_PARAM_BAD_LENGTH   2

/* ip option type codes */
#ifndef IPOPT_EOL
    #define IPOPT_EOL            0x00
#endif

#ifndef IPOPT_NOP
    #define IPOPT_NOP            0x01
#endif

#ifndef IPOPT_RR
    #define IPOPT_RR             0x07
#endif

#ifndef IPOPT_RTRALT
    #define IPOPT_RTRALT         0x14
#endif

#ifndef IPOPT_TS
    #define IPOPT_TS             0x44
#endif

#ifndef IPOPT_SECURITY
    #define IPOPT_SECURITY       0x82
#endif

#ifndef IPOPT_LSRR
    #define IPOPT_LSRR           0x83
#endif

#ifndef IPOPT_LSRR_E
    #define IPOPT_LSRR_E         0x84
#endif

#ifndef IPOPT_SATID
    #define IPOPT_SATID          0x88
#endif

#ifndef IPOPT_SSRR
    #define IPOPT_SSRR           0x89
#endif



/* tcp option codes */
#define TOPT_EOL                0x00
#define TOPT_NOP                0x01
#define TOPT_MSS                0x02
#define TOPT_WS                 0x03
#define TOPT_TS                 0x08
#ifndef TCPOPT_WSCALE
    #define TCPOPT_WSCALE           3     /* window scale factor (rfc1072) */
#endif
#ifndef TCPOPT_SACKOK
    #define    TCPOPT_SACKOK        4     /* selective ack ok (rfc1072) */
#endif
#ifndef TCPOPT_SACK
    #define    TCPOPT_SACK          5     /* selective ack (rfc1072) */
#endif
#ifndef TCPOPT_ECHO
    #define TCPOPT_ECHO             6     /* echo (rfc1072) */
#endif
#ifndef TCPOPT_ECHOREPLY
    #define TCPOPT_ECHOREPLY        7     /* echo (rfc1072) */
#endif
#ifndef TCPOPT_TIMESTAMP
    #define TCPOPT_TIMESTAMP        8     /* timestamps (rfc1323) */
#endif
#ifndef TCPOPT_CC
    #define TCPOPT_CC               11    /* T/TCP CC options (rfc1644) */
#endif
#ifndef TCPOPT_CCNEW
    #define TCPOPT_CCNEW            12    /* T/TCP CC options (rfc1644) */
#endif
#ifndef TCPOPT_CCECHO
    #define TCPOPT_CCECHO           13    /* T/TCP CC options (rfc1644) */
#endif

#define EXTRACT_16BITS(p) ((u_short) ntohs (*(u_short *)(p)))

#ifdef WORDS_MUSTALIGN

#if defined(__GNUC__)
/* force word-aligned ntohl parameter */
    #define EXTRACT_32BITS(p)  ({ u_int32_t __tmp; memmove(&__tmp, (p), sizeof(u_int32_t)); (u_int32_t) ntohl(__tmp);})
#endif /* __GNUC__ */

#else

/* allows unaligned ntohl parameter - dies w/SIGBUS on SPARCs */
    #define EXTRACT_32BITS(p) ((u_int32_t) ntohl (*(u_int32_t *)(p)))

#endif                /* WORDS_MUSTALIGN */

/* packet status flags */
#define PKT_REBUILT_FRAG     0x00000001  /* is a rebuilt fragment */
#define PKT_REBUILT_STREAM   0x00000002  /* is a rebuilt stream */
#define PKT_STREAM_UNEST_UNI 0x00000004  /* is from an unestablished stream and
                                          * we've only seen traffic in one
                                          * direction
                                          */
#define PKT_STREAM_UNEST_BI  0x00000008  /* is from an unestablished stream and
                                          * we've seen traffic in both 
                                          * directions
                                          */
#define PKT_STREAM_EST       0x00000010  /* is from an established stream */
#define PKT_ECN              0x00000020  /* this is ECN traffic */
#define PKT_FROM_SERVER      0x00000040  /* this packet came from the server
                                            side of a connection (TCP) */
#define PKT_FROM_CLIENT      0x00000080  /* this packet came from the client
                                            side of a connection (TCP) */
#define PKT_HTTP_DECODE      0x00000100  /* this packet has normalized http */
#define PKT_FRAG_ALERTED     0x00000200  /* this packet has been alerted by 
                                            defrag */
#define PKT_STREAM_INSERT    0x00000400  /* this packet has been inserted into stream4 */
#define PKT_ALT_DECODE       0x00000800  /* this packet has been normalized by telnet
                                             (only set when we must look at an alernative buffer)
                                         */
#define PKT_STREAM_TWH       0x00001000
#define PKT_IGNORE_PORT      0x00002000  /* this packet should be ignored, based on port */
#define PKT_PASS_RULE        0x00004000  /* this packet has matched a pass rule */
#define PKT_STATELESS        0x10000000  /* Packet has matched a stateless rule */
#define PKT_INLINE_DROP      0x20000000
#define PKT_OBFUSCATED       0x40000000  /* this packet has been obfuscated */
#define PKT_NO_DETECT        0x80000000  /* this packet should not be preprocessed */

#ifdef GRE
    #ifndef IPPROTO_GRE
        #define IPPROTO_GRE 47
    #endif
#endif


/*  D A T A  S T R U C T U R E S  *********************************************/

/* Start Token Ring Data Structures */


#ifdef _MSC_VER
    /* Visual C++ pragma to disable warning messages about nonstandard bit field type */
    #pragma warning( disable : 4214 )  
#endif

/* LLC structure */
typedef struct _Trh_llc
{
    u_int8_t dsap;
    u_int8_t ssap;
    u_int8_t protid[3];
    u_int16_t ethertype;
}        Trh_llc;

/* RIF structure
 * Linux/tcpdump patch defines tokenring header in dump way, since not
 * every tokenring header with have RIF data... we define it separately, and
 * a bit more split up
 */

#ifdef _MSC_VER
  /* Visual C++ pragma to disable warning messages about nonstandard bit field type */
  #pragma warning( disable : 4214 )  
#endif


/* These are macros to use the bitlevel accesses in the Trh_Mr header

   they haven't been tested and they aren't used much so here is a
   listing of what used to be there

   #if defined(WORDS_BIGENDIAN)
      u_int16_t bcast:3, len:5, dir:1, lf:3, res:4;
   #else
      u_int16_t len:5,         length of RIF field, including RC itself
      bcast:3,       broadcast indicator 
      res:4,         reserved 
      lf:3,      largest frame size 
      dir:1;         direction
*/

#define TRH_MR_BCAST(trhmr)  ((ntohs((trhmr)->bcast_len_dir_lf_res) & 0xe000) >> 13)
#define TRH_MR_LEN(trhmr)    ((ntohs((trhmr)->bcast_len_dir_lf_res) & 0x1F00) >> 8)
#define TRH_MR_DIR(trhmr)    ((ntohs((trhmr)->bcast_len_dir_lf_res) & 0x0080) >> 8)
#define TRH_MR_LF(trhmr)     ((ntohs((trhmr)->bcast_len_dir_lf_res) & 0x0070) >> 7)
#define TRH_MR_RES(trhmr)     ((ntohs((trhmr)->bcast_len_dir_lf_res) & 0x000F))

typedef struct _Trh_mr
{
    u_int16_t bcast_len_dir_lf_res; /* broadcast/res/framesize/direction */
    u_int16_t rseg[8];
}       Trh_mr;
#ifdef _MSC_VER
  /* Visual C++ pragma to enable warning messages about nonstandard bit field type */
  #pragma warning( default : 4214 )
#endif


typedef struct _Trh_hdr
{
    u_int8_t ac;        /* access control field */
    u_int8_t fc;        /* frame control field */
    u_int8_t daddr[TR_ALEN];    /* src address */
    u_int8_t saddr[TR_ALEN];    /* dst address */
}        Trh_hdr;

#ifdef WIN32
    /* Visual C++ pragma to enable warning messages about nonstandard bit field type */
    #pragma warning( default : 4214 )
#endif
/* End Token Ring Data Structures */


/* Start FDDI Data Structures */

/* FDDI header is always this: -worm5er */
typedef struct _Fddi_hdr
{
    u_int8_t fc;        /* frame control field */
    u_int8_t daddr[FDDI_ALEN];  /* src address */
    u_int8_t saddr[FDDI_ALEN];  /* dst address */
}         Fddi_hdr;

/* splitting the llc up because of variable lengths of the LLC -worm5er */
typedef struct _Fddi_llc_saps
{
    u_int8_t dsap;
    u_int8_t ssap;
}              Fddi_llc_saps;

/* I've found sna frames have two addition bytes after the llc saps -worm5er */
typedef struct _Fddi_llc_sna
{
    u_int8_t ctrl_fld[2];
}             Fddi_llc_sna;

/* I've also found other frames that seem to have only one byte...  We're only
really intersted in the IP data so, until we want other, I'm going to say
the data is one byte beyond this frame...  -worm5er */
typedef struct _Fddi_llc_other
{
    u_int8_t ctrl_fld[1];
}               Fddi_llc_other;

/* Just like TR the ip/arp data is setup as such: -worm5er */
typedef struct _Fddi_llc_iparp
{
    u_int8_t ctrl_fld;
    u_int8_t protid[3];
    u_int16_t ethertype;
}               Fddi_llc_iparp;

/* End FDDI Data Structures */


/* 'Linux cooked captures' data
 * (taken from tcpdump source).
 */

#define SLL_HDR_LEN     16              /* total header length */
#define SLL_ADDRLEN     8               /* length of address field */
typedef struct _SLLHdr {
        u_int16_t       sll_pkttype;    /* packet type */
        u_int16_t       sll_hatype;     /* link-layer address type */
        u_int16_t       sll_halen;      /* link-layer address length */
        u_int8_t        sll_addr[SLL_ADDRLEN];  /* link-layer address */
        u_int16_t       sll_protocol;   /* protocol */
} SLLHdr;


/* Old OpenBSD pf firewall pflog0 header
 * (information from pf source in kernel)
 * the rule, reason, and action codes tell why the firewall dropped it -fleck
 */

typedef struct _OldPflog_hdr
{
    u_int32_t af;
    char intf[IFNAMSIZ];
    short rule;
    u_short reason;
    u_short action;
    u_short dir;
} OldPflogHdr;

#define OLDPFLOG_HDRLEN    sizeof(struct _OldPflog_hdr)

/* OpenBSD pf firewall pflog0 header
 * (information from pf source in kernel)
 * the rule, reason, and action codes tell why the firewall dropped it -fleck
 */

typedef struct _Pflog_hdr
{
        int8_t          length;
        sa_family_t     af;
        u_int8_t        action;
        u_int8_t        reason;
        char            ifname[IFNAMSIZ];
        char            ruleset[16];
        u_int32_t       rulenr;
        u_int32_t       subrulenr;
        u_int8_t        dir;
        u_int8_t        pad[3];
} PflogHdr;

#define PFLOG_HDRLEN    sizeof(struct _Pflog_hdr)

/*
 * ssl_pkttype values.
 */

#define LINUX_SLL_HOST          0
#define LINUX_SLL_BROADCAST     1
#define LINUX_SLL_MULTICAST     2
#define LINUX_SLL_OTHERHOST     3
#define LINUX_SLL_OUTGOING      4

/* ssl protocol values */

#define LINUX_SLL_P_802_3       0x0001  /* Novell 802.3 frames without 802.2 LLC header */
#define LINUX_SLL_P_802_2       0x0004  /* 802.2 frames (not D/I/X Ethernet) */


#ifdef _MSC_VER
  /* Visual C++ pragma to disable warning messages 
   * about nonstandard bit field type 
   */
  #pragma warning( disable : 4214 )  
#endif

#define VTH_PRIORITY(vh)  ((ntohs((vh)->vth_pri_cfi_vlan) & 0xe000) >> 13)
#define VTH_CFI(vh)       ((ntohs((vh)->vth_pri_cfi_vlan) & 0x0100) >> 12)
#define VTH_VLAN(vh)      ((ntohs((vh)->vth_pri_cfi_vlan) & 0x0FFF))

typedef struct _VlanTagHdr
{
    u_int16_t vth_pri_cfi_vlan;
    u_int16_t vth_proto;  /* protocol field... */
} VlanTagHdr;
#ifdef _MSC_VER
  /* Visual C++ pragma to enable warning messages about nonstandard bit field type */
  #pragma warning( default : 4214 )
#endif


typedef struct _EthLlc
{
    u_int8_t dsap;
    u_int8_t ssap;
} EthLlc;

typedef struct _EthLlcOther
{
    u_int8_t ctrl;
    u_int8_t org_code[3];
    u_int16_t proto_id;
} EthLlcOther;

/* We must twiddle to align the offset the ethernet header and align
 * the IP header on solaris -- maybe this will work on HPUX too.
 */
#if defined (SOLARIS) || defined (SUNOS) || defined (__sparc__) || defined(__sparc64__) || defined (HPUX)
#define SPARC_TWIDDLE       2
#else
#define SPARC_TWIDDLE       0
#endif

/* 
 * Ethernet header
 */

typedef struct _EtherHdr
{
    u_int8_t ether_dst[6];
    u_int8_t ether_src[6];
    u_int16_t ether_type;

}         EtherHdr;


/*
 *  Wireless Header (IEEE 802.11)
 */
typedef struct _WifiHdr
{
  u_int16_t frame_control;
  u_int16_t duration_id;
  u_int8_t  addr1[6];
  u_int8_t  addr2[6];
  u_int8_t  addr3[6];
  u_int16_t seq_control;
  u_int8_t  addr4[6];
} WifiHdr;


/* Can't add any fields not in the real header here 
   because of how the decoder uses structure overlaying */
#ifdef _MSC_VER
  /* Visual C++ pragma to disable warning messages 
   * about nonstandard bit field type 
   */
  #pragma warning( disable : 4214 )  
#endif

/* tcpdump shows us the way to cross platform compatibility */
#define IP_VER(iph)    (((iph)->ip_verhl & 0xf0) >> 4)
#define IP_HLEN(iph)   ((iph)->ip_verhl & 0x0f)

/* we need to change them as well as get them */
#define SET_IP_VER(iph, value)  ((iph)->ip_verhl = (unsigned char)(((iph)->ip_verhl & 0x0f) | (value << 4)))
#define SET_IP_HLEN(iph, value)  ((iph)->ip_verhl = (unsigned char)(((iph)->ip_verhl & 0xf0) | (value & 0x0f)))

typedef struct _IPHdr
{
    u_int8_t ip_verhl;      /* version & header length */
    u_int8_t ip_tos;        /* type of service */
    u_int16_t ip_len;       /* datagram length */
    u_int16_t ip_id;        /* identification  */
    u_int16_t ip_off;       /* fragment offset */
    u_int8_t ip_ttl;        /* time to live field */
    u_int8_t ip_proto;      /* datagram protocol */
    u_int16_t ip_csum;      /* checksum */
    struct in_addr ip_src;  /* source IP */
    struct in_addr ip_dst;  /* dest IP */
}      IPHdr;

#ifdef WIN32
/* IPv6 address */
#ifndef s6_addr
struct in6_addr
{
    union
    {
        uint8_t u6_addr8[16];
        uint16_t u6_addr16[8];
        uint32_t u6_addr32[4];
    } in6_u;
#define s6_addr         in6_u.u6_addr8
#define s6_addr16       in6_u.u6_addr16
#define s6_addr32       in6_u.u6_addr32
};
#endif
#endif

typedef struct _IP6Hdr
{
    union
    {
        struct ip6_hdrctl
        {
            uint32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC,
                                        20 bits flow-ID */
            uint16_t ip6_un1_plen;   /* payload length */
            uint8_t  ip6_un1_nxt;    /* next header */
            uint8_t  ip6_un1_hlim;   /* hop limit */
        } ip6_un1;
        uint8_t ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
    } ip6_ctlun;

    struct in6_addr ip6_src;      /* source address */
    struct in6_addr ip6_dst;      /* destination address */
} IP6Hdr;

#define ip6_vfc   ip6_ctlun.ip6_un2_vfc
#define ip6_flow  ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen  ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt   ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim  ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops  ip6_ctlun.ip6_un1.ip6_un1_hlim

/* Fragment header */
typedef struct _IP6Frag
{
    uint8_t   ip6f_nxt;     /* next header */
    uint8_t   ip6f_reserved;    /* reserved field */
    uint16_t  ip6f_offlg;   /* offset, reserved, and flag */
    uint32_t  ip6f_ident;   /* identification */
} IP6Frag;


typedef struct _ipv6_header_chain {
    u_int8_t        next_header;
    u_int8_t        length;
} ipv6_header_chain;

#ifdef _MSC_VER
  /* Visual C++ pragma to enable warning messages about nonstandard bit field type */
  #pragma warning( default : 4214 )
#endif


/* Can't add any fields not in the real header here 
   because of how the decoder uses structure overlaying */
#ifdef _MSC_VER
  /* Visual C++ pragma to disable warning 
   * messages about nonstandard bit field type 
   */
  #pragma warning( disable : 4214 )  
#endif


#ifdef GRE

#define GRE_TYPE_TRANS_BRIDGING 0x6558
#define GRE_HEADER_LEN 4
#define GRE_CHECKSUM_LEN 2
#define GRE_OFFSET_LEN 2
#define GRE_KEY_LEN 4
#define GRE_SEQNO_LEN 4
#define GRE_SRE_HEADER_LEN 4
#define GRE_CHECKSUM_FLAG 0x80
#define GRE_ROUTING_FLAG  0x40
#define GRE_KEY_FLAG      0x20
#define GRE_SEQNO_FLAG    0x10
#define GRE_SSR_FLAG      0x08   /* strict source route */

typedef struct _GREHdr
{
    u_int8_t flags;
    u_int8_t version;
    u_int16_t ether_type;

} GREHdr;

#endif


/* more macros for TCP offset */
#define TCP_OFFSET(tcph)        (((tcph)->th_offx2 & 0xf0) >> 4)
#define TCP_X2(tcph)            ((tcph)->th_offx2 & 0x0f)

#define TCP_ISFLAGSET(tcph, flags) (((tcph)->th_flags & (flags)) == (flags))

/* we need to change them as well as get them */
#define SET_TCP_OFFSET(tcph, value)  ((tcph)->th_offx2 = (unsigned char)(((tcph)->th_offx2 & 0x0f) | (value << 4)))
#define SET_TCP_X2(tcph, value)  ((tcph)->th_offx2 = (unsigned char)(((tcph)->th_offx2 & 0xf0) | (value & 0x0f)))

typedef struct _TCPHdr
{
    u_int16_t th_sport;     /* source port */
    u_int16_t th_dport;     /* destination port */
    u_int32_t th_seq;       /* sequence number */
    u_int32_t th_ack;       /* acknowledgement number */
    u_int8_t th_offx2;      /* offset and reserved */
    u_int8_t th_flags;
    u_int16_t th_win;       /* window */
    u_int16_t th_sum;       /* checksum */
    u_int16_t th_urp;       /* urgent pointer */

}       TCPHdr;
#ifdef _MSC_VER
  /* Visual C++ pragma to enable warning messages 
   * about nonstandard bit field type 
   */
  #pragma warning( default : 4214 )
#endif


typedef struct _UDPHdr
{
    u_int16_t uh_sport;
    u_int16_t uh_dport;
    u_int16_t uh_len;
    u_int16_t uh_chk;

}       UDPHdr;


typedef struct _ICMPHdr
{
    u_int8_t type;
    u_int8_t code;
    u_int16_t csum;
    union
    {
        u_int8_t pptr;

        struct in_addr gwaddr;

        struct idseq
        {
            u_int16_t id;
            u_int16_t seq;
        } idseq;

        int sih_void;

        struct pmtu 
        {
            u_int16_t ipm_void;
            u_int16_t nextmtu;
        } pmtu;

        struct rtradv 
        {
            u_int8_t num_addrs;
            u_int8_t wpa;
            u_int16_t lifetime;
        } rtradv;
    } icmp_hun;

#define s_icmp_pptr       icmp_hun.pptr
#define s_icmp_gwaddr     icmp_hun.gwaddr
#define s_icmp_id         icmp_hun.idseq.id
#define s_icmp_seq        icmp_hun.idseq.seq
#define s_icmp_void       icmp_hun.sih_void
#define s_icmp_pmvoid     icmp_hun.pmtu.ipm_void
#define s_icmp_nextmtu    icmp_hun.pmtu.nextmtu
#define s_icmp_num_addrs  icmp_hun.rtradv.num_addrs
#define s_icmp_wpa        icmp_hun.rtradv.wpa
#define s_icmp_lifetime   icmp_hun.rtradv.lifetime

    union 
    {
        /* timestamp */
        struct ts 
        {
            u_int32_t otime;
            u_int32_t rtime;
            u_int32_t ttime;
        } ts;
        
        /* IP header for unreach */
        struct ih_ip  
        {
            IPHdr *ip;
            /* options and then 64 bits of data */
        } ip;
        
        struct ra_addr 
        {
            u_int32_t addr;
            u_int32_t preference;
        } radv;

        u_int32_t mask;

        char    data[1];

    } icmp_dun;
#define s_icmp_otime      icmp_dun.ts.otime
#define s_icmp_rtime      icmp_dun.ts.rtime
#define s_icmp_ttime      icmp_dun.ts.ttime
#define s_icmp_ip         icmp_dun.ih_ip
#define s_icmp_radv       icmp_dun.radv
#define s_icmp_mask       icmp_dun.mask
#define s_icmp_data       icmp_dun.data

}        ICMPHdr;


typedef struct _ARPHdr
{
    u_int16_t ar_hrd;       /* format of hardware address   */
    u_int16_t ar_pro;       /* format of protocol address   */
    u_int8_t ar_hln;        /* length of hardware address   */
    u_int8_t ar_pln;        /* length of protocol address   */
    u_int16_t ar_op;        /* ARP opcode (command)         */
}       ARPHdr;



typedef struct _EtherARP
{
    ARPHdr ea_hdr;      /* fixed-size header */
    u_int8_t arp_sha[6];    /* sender hardware address */
    u_int8_t arp_spa[4];    /* sender protocol address */
    u_int8_t arp_tha[6];    /* target hardware address */
    u_int8_t arp_tpa[4];    /* target protocol address */
}         EtherARP;


typedef struct _EtherEapol
{
    u_int8_t  version;  /* EAPOL proto version */
    u_int8_t  eaptype;  /* EAPOL Packet type */
    u_int16_t len;  /* Packet body length */
}         EtherEapol;

typedef struct _EAPHdr
{
    u_int8_t code;
    u_int8_t id;
    u_int16_t len;
}         EAPHdr;

typedef struct _EapolKey
{
  u_int8_t type;
  u_int8_t length[2];
  u_int8_t counter[8];
  u_int8_t iv[16];
  u_int8_t index;
  u_int8_t sig[16];
}       EapolKey;

typedef struct _Options
{
    u_int8_t code;
    u_int8_t len; /* length of the data section */
    u_int8_t *data;
}        Options;

/* PPPoEHdr Header; EtherHdr plus the PPPoE Header */
typedef struct _PPPoEHdr
{
    EtherHdr ethhdr;            /* ethernet header */
    unsigned char ver_type;     /* pppoe version/type */
    unsigned char code;         /* pppoe code CODE_* */
    unsigned short session;     /* session id */
    unsigned short length;      /* payload length */
                                /* payload follows */
} PPPoEHdr;

/* PPPoE tag; the payload is a sequence of these */
typedef struct _PPPoE_Tag
{
    unsigned short type;    /* tag type TAG_* */
    unsigned short length;    /* tag length */
                            /* payload follows */
} PPPoE_Tag;

#define DECODE_BLEN 65535

/* Max Number of HTTP/1.1 requests in a single segment */
#define URI_COUNT        5

#define HTTPURI_PIPELINE_REQ 0x01

#define HTTP_BUFFER_URI 0
#define HTTP_BUFFER_CLIENT_BODY 1

typedef struct _HttpUri
{
    u_int8_t *uri;  /* static buffer for uri length */
    u_int16_t length;
    u_int32_t decode_flags; 
} HttpUri;

typedef struct _Packet
{
    struct pcap_pkthdr *pkth;   /* BPF data */
    u_int8_t *pkt;              /* base pointer to the raw packet data */

    Fddi_hdr *fddihdr;          /* FDDI support headers */
    Fddi_llc_saps *fddisaps;
    Fddi_llc_sna *fddisna;
    Fddi_llc_iparp *fddiiparp;    
    Fddi_llc_other *fddiother;

    Trh_hdr *trh;               /* Token Ring support headers */
    Trh_llc *trhllc;
    Trh_mr *trhmr;

    SLLHdr *sllh;               /* Linux cooked sockets header */

    PflogHdr *pfh;              /* OpenBSD pflog interface header */

    OldPflogHdr *opfh;          /* Old OpenBSD pflog interface header */

    EtherHdr *eh;               /* standard TCP/IP/Ethernet/ARP headers */
    VlanTagHdr *vh;
    EthLlc   *ehllc;
    EthLlcOther *ehllcother;
    
    WifiHdr *wifih;         /* wireless LAN header */

    EtherARP *ah;

    EtherEapol *eplh;       /* 802.1x EAPOL header */
    EAPHdr *eaph;
    u_int8_t *eaptype;
    EapolKey *eapolk;

    PPPoEHdr *pppoeh;        /* Encapsulated PPP of Ether header */

    IPHdr *iph, *orig_iph;   /* and orig. headers for ICMP_*_UNREACH family */
    u_int32_t ip_options_len;
    u_int8_t *ip_options_data;

    TCPHdr *tcph, *orig_tcph;
    u_int32_t tcp_options_len;
    u_int8_t *tcp_options_data;

    UDPHdr *udph, *orig_udph;
    ICMPHdr *icmph, *orig_icmph;

#ifdef GRE
    GREHdr *greh;
#endif

    u_int8_t *data;         /* packet payload pointer */
    u_int16_t dsize;        /* packet payload size */
    u_int16_t alt_dsize;    /* the dsize of a packet before munging (used for log)*/

    u_int16_t actual_ip_len;/* for logging truncated packets (usually by a small snaplen) */

    u_int8_t frag_flag;     /* flag to indicate a fragmented packet */
    u_int16_t frag_offset;  /* fragment offset number */
    u_int8_t mf;            /* more fragments flag */
    u_int8_t df;            /* don't fragment flag */
    u_int8_t rf;                  /* IP reserved bit */

    u_int16_t sp;           /* source port (TCP/UDP) */
    u_int16_t dp;           /* dest port (TCP/UDP) */
    u_int16_t orig_sp;      /* source port (TCP/UDP) of original datagram */
    u_int16_t orig_dp;      /* dest port (TCP/UDP) of original datagram */
    u_int32_t caplen;

    u_int8_t uri_count;     /* number of URIs in this packet */

    void *ssnptr;           /* for tcp session tracking info... */
    void *fragtracker;      /* for ip fragmentation tracking info... */
    void *flow;             /* for flow info */
    void *streamptr;        /* for tcp pkt dump */
    
    Options ip_options[IP_OPTMAX]; /* ip options decode structure */
    u_int32_t ip_option_count;  /* number of options in this packet */
    u_char ip_lastopt_bad;  /* flag to indicate that option decoding was
                               halted due to a bad option */
    Options tcp_options[TCP_OPTLENMAX];    /* tcp options decode struct */
    u_int32_t tcp_option_count;
    u_char tcp_lastopt_bad;  /* flag to indicate that option decoding was
                                halted due to a bad option */

    u_int8_t csum_flags;        /* checksum flags */
    u_int32_t packet_flags;     /* special flags for the packet */
    u_int32_t bytes_to_inspect; /* Number of bytes to check against rules */

    BITOP *preprocessor_bits;  /* flags for preprocessors to check */
} Packet;

typedef struct s_pseudoheader
{
    u_int32_t sip, dip; 
    u_int8_t  zero;     
    u_int8_t  protocol; 
    u_int16_t len; 

} PSEUDO_HDR;

/* Default classification for decoder alerts */
#define DECODE_CLASS 25 

typedef struct _DecoderFlags
{
    char decode_alerts;   /* if decode.c alerts are going to be enabled */
    char oversized_alert;   /* alert if garbage after tcp/udp payload */
    char oversized_drop;   /* alert if garbage after tcp/udp payload */
    char drop_alerts;     /* drop alerts from decoder */
    char tcpopt_experiment;  /* TcpOptions Decoder */
    char drop_tcpopt_experiment; /* Drop alerts from TcpOptions Decoder */
    char tcpopt_obsolete;    /* Alert on obsolete TCP options */
    char drop_tcpopt_obsolete; /* Drop on alerts from obsolete TCP options */
    char tcpopt_ttcp;        /* Alert on T/TCP options */
    char drop_tcpopt_ttcp;   /* Drop on alerts from T/TCP options */
    char tcpopt_decode;      /* alert on decoder inconsistencies */
    char drop_tcpopt_decode; /* Drop on alerts from decoder inconsistencies */
    char ipopt_decode;      /* alert on decoder inconsistencies */
    char drop_ipopt_decode; /* Drop on alerts from decoder inconsistencies */

    /* To be moved to the frag preprocessor once it supports IPv6 */
    char ipv6_bad_frag_pkt;
    char bsd_icmp_frag;
    char drop_bad_ipv6_frag;    

} DecoderFlags;

#define        ALERTMSG_LENGTH 256


/*  P R O T O T Y P E S  ******************************************************/
void InitDecoderFlags(void);
void DecodeTRPkt(Packet *, struct pcap_pkthdr *, u_int8_t *);
void DecodeFDDIPkt(Packet *, struct pcap_pkthdr *, u_int8_t *);
void DecodeLinuxSLLPkt(Packet *, struct pcap_pkthdr *, u_int8_t *);
void DecodeEthPkt(Packet *, struct pcap_pkthdr *, u_int8_t *);
void DecodeIEEE80211Pkt(Packet *, struct pcap_pkthdr *, u_int8_t *);
void DecodeVlan(u_int8_t *, const u_int32_t, Packet *);
void DecodePppPkt(Packet *, struct pcap_pkthdr *, u_int8_t *);
void DecodePppSerialPkt(Packet *, struct pcap_pkthdr *, u_int8_t *);
void DecodePppPktEncapsulated(Packet *, const u_int32_t, u_int8_t *);
void DecodeSlipPkt(Packet *, struct pcap_pkthdr *, u_int8_t *);
void DecodeNullPkt(Packet *, struct pcap_pkthdr *, u_int8_t *);
void DecodeRawPkt(Packet *, struct pcap_pkthdr *, u_int8_t *);
void DecodeI4LRawIPPkt(Packet *, struct pcap_pkthdr *, u_int8_t *);
void DecodeI4LCiscoIPPkt(Packet *, struct pcap_pkthdr *, u_int8_t *);
void DecodeChdlcPkt(Packet *, struct pcap_pkthdr *, u_int8_t *);
void DecodePflog(Packet *, struct pcap_pkthdr *, u_int8_t *);
void DecodeOldPflog(Packet *, struct pcap_pkthdr *, u_int8_t *);
void DecodeIP(u_int8_t *, const u_int32_t, Packet *);
void DecodeARP(u_int8_t *, u_int32_t, Packet *);
void DecodeEapol(u_int8_t *, u_int32_t, Packet *);
void DecodeEapolKey(u_int8_t *, u_int32_t, Packet *);
void DecodeIPV6(u_int8_t *, u_int32_t, Packet *);
void DecodeIPX(u_int8_t *, u_int32_t);
void DecodeEthLoopback(u_int8_t *, u_int32_t);
void DecodeTCP(u_int8_t *, const u_int32_t, Packet *);
void DecodeUDP(u_int8_t *, const u_int32_t, Packet *);
void DecodeEAP(u_int8_t *, const u_int32_t, Packet *);
void DecodeICMP(u_int8_t *, const u_int32_t, Packet *);
void DecodeICMPEmbeddedIP(u_int8_t *, const u_int32_t, Packet *);
void DecodeIPOptions(u_int8_t *, u_int32_t, Packet *);
void DecodeTCPOptions(u_int8_t *, u_int32_t, Packet *);
void DecodeIPOptions(u_int8_t *, u_int32_t, Packet *);
void DecodePPPoEPkt(Packet *, struct pcap_pkthdr *, u_int8_t *);
void DecodeEncPkt(Packet *, struct pcap_pkthdr *, u_int8_t *);
#ifdef GRE
void DecodeGRE(u_int8_t *, const u_int32_t, Packet *);
void DecodeTransBridging(u_int8_t *, const u_int32_t, Packet *);
#endif
#ifdef GIDS
#ifndef IPFW
void DecodeIptablesPkt(Packet *, struct pcap_pkthdr *, u_int8_t *);
#else
void DecodeIpfwPkt(Packet *, struct pcap_pkthdr *, u_int8_t *);
#endif /* IPFW */
#endif /* GIDS */

#if defined(WORDS_MUSTALIGN) && !defined(__GNUC__)
u_int32_t EXTRACT_32BITS (u_char *);
#endif /* WORDS_MUSTALIGN && !__GNUC__ */

/* XXX not sure where this guy needs to live at the moment */
typedef struct _PortList
{
    int ports[32];   /* 32 is kind of arbitrary */

    int num_entries;

} PortList;

#endif                /* __DECODE_H__ */
