/***********************************************************************
*
* pppoe.h
*
* Declaration of various PPPoE constants
*
* Copyright (C) 2000 Roaring Penguin Software Inc.
*
* This program may be distributed according to the terms of the GNU
* General Public License, version 2 or (at your option) any later version.
*
* $Id: pppoe.h,v 1.3 2009-04-03 03:34:31 davidm Exp $
*
***********************************************************************/

#ifdef __sun__
#define __EXTENSIONS__
#endif

#include "config.h"

#include <stdio.h>		/* For FILE */
#include <sys/types.h>		/* For pid_t */

/* How do we access raw Ethernet devices? */
#undef USE_LINUX_PACKET
#undef USE_BPF

#if defined(HAVE_NETPACKET_PACKET_H) || defined(HAVE_LINUX_IF_PACKET_H)
#define USE_LINUX_PACKET 1
#elif defined(HAVE_NET_BPF_H)
#define USE_BPF 1
#elif defined(HAVE_SYS_DLPI_H)
#define USE_DLPI
#endif

/* Sanity check */
#if !defined(USE_BPF) && !defined(USE_LINUX_PACKET) && !defined(USE_DLPI)
#error Unknown method for accessing raw Ethernet frames
#endif

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef HAVE_NET_IF_TYPES_H
#include <net/if_types.h>
#endif

#ifdef HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif

/* I'm not sure why this is needed... I do not have OpenBSD */
#if defined(__OpenBSD__)
#include <net/ppp_defs.h>
#include <net/if_ppp.h>
#endif

#ifdef USE_BPF
extern int bpfSize;
struct PPPoEPacket;
void sessionDiscoveryPacket(struct PPPoEPacket *packet);
#define BPF_BUFFER_IS_EMPTY (bpfSize <= 0)
#define BPF_BUFFER_HAS_DATA (bpfSize > 0)
#define ethhdr ether_header
#define h_dest ether_dhost
#define h_source ether_shost
#define h_proto ether_type
#define	ETH_DATA_LEN ETHERMTU
#define	ETH_ALEN ETHER_ADDR_LEN
#else
#undef USE_BPF
#define BPF_BUFFER_IS_EMPTY 1
#define BPF_BUFFER_HAS_DATA 0
#endif

#ifdef USE_DLPI
#include <sys/ethernet.h>
#define ethhdr ether_header
#define	ETH_DATA_LEN ETHERMTU
#define	ETH_ALEN ETHERADDRL
#define h_dest ether_dhost.ether_addr_octet
#define h_source ether_shost.ether_addr_octet
#define h_proto ether_type

/* cloned from dltest.h */
#define         MAXDLBUF        8192
#define         MAXDLADDR       1024
#define         MAXWAIT         15
#define         OFFADDR(s, n)   (u_char*)((char*)(s) + (int)(n))
#define         CASERET(s)      case s:  return ("s")

#endif

/* Define various integer types -- assumes a char is 8 bits */
#if SIZEOF_UNSIGNED_SHORT == 2
typedef unsigned short UINT16_t;
#elif SIZEOF_UNSIGNED_INT == 2
typedef unsigned int UINT16_t;
#else
#error Could not find a 16-bit integer type
#endif

#if SIZEOF_UNSIGNED_SHORT == 4
typedef unsigned short UINT32_t;
#elif SIZEOF_UNSIGNED_INT == 4
typedef unsigned int UINT32_t;
#elif SIZEOF_UNSIGNED_LONG == 4
typedef unsigned long UINT32_t;
#else
#error Could not find a 16-bit integer type
#endif

#ifdef HAVE_LINUX_IF_ETHER_H
#include <linux/if_ether.h>
#endif

#include <netinet/in.h>

#ifdef HAVE_NETINET_IF_ETHER_H
#include <sys/types.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifndef HAVE_SYS_DLPI_H
#include <netinet/if_ether.h>
#endif
#endif



/* Ethernet frame types according to RFC 2516 */
#define ETH_PPPOE_DISCOVERY 0x8863
#define ETH_PPPOE_SESSION   0x8864

/* But some brain-dead peers disobey the RFC, so frame types are variables */
extern UINT16_t Eth_PPPOE_Discovery;
extern UINT16_t Eth_PPPOE_Session;

/* PPPoE codes */
#define CODE_PADI           0x09
#define CODE_PADO           0x07
#define CODE_PADR           0x19
#define CODE_PADS           0x65
#define CODE_PADT           0xA7
#define CODE_SESS           0x00

/* PPPoE Tags */
#define TAG_END_OF_LIST        0x0000
#define TAG_SERVICE_NAME       0x0101
#define TAG_AC_NAME            0x0102
#define TAG_HOST_UNIQ          0x0103
#define TAG_AC_COOKIE          0x0104
#define TAG_VENDOR_SPECIFIC    0x0105
#define TAG_RELAY_SESSION_ID   0x0110
#define TAG_SERVICE_NAME_ERROR 0x0201
#define TAG_AC_SYSTEM_ERROR    0x0202
#define TAG_GENERIC_ERROR      0x0203

/* Discovery phase states */
#define STATE_SENT_PADI     0
#define STATE_RECEIVED_PADO 1
#define STATE_SENT_PADR     2
#define STATE_SESSION       3
#define STATE_TERMINATED    4

/* How many PADI/PADS attempts? */
#define MAX_PADI_ATTEMPTS 3

/* Initial timeout for PADO/PADS */
#define PADI_TIMEOUT 5

/* States for scanning PPP frames */
#define STATE_WAITFOR_FRAME_ADDR 0
#define STATE_DROP_PROTO         1
#define STATE_BUILDING_PACKET    2

/* Special PPP frame characters */
#define FRAME_ESC    0x7D
#define FRAME_FLAG   0x7E
#define FRAME_ADDR   0xFF
#define FRAME_CTRL   0x03
#define FRAME_ENC    0x20

#define IPV4ALEN     4
#define SMALLBUF   256

/* A PPPoE Packet, including Ethernet headers */
struct PPPoEPacket {
    struct ethhdr ethHdr;	/* Ethernet header */
    unsigned int ver:4;		/* PPPoE Version (must be 1) */
    unsigned int type:4;	/* PPPoE Type (must be 1) */
    unsigned int code:8;	/* PPPoE code */
    unsigned int session:16;	/* PPPoE session */
    unsigned int length:16;	/* Payload length */
    unsigned char payload[ETH_DATA_LEN]; /* A bit of room to spare */
};

/* Header size of a PPPoE packet */
#define PPPOE_OVERHEAD 6  /* type, code, session, length */
#define HDR_SIZE (sizeof(struct ethhdr) + PPPOE_OVERHEAD)
#define MAX_PPPOE_PAYLOAD (ETH_DATA_LEN - PPPOE_OVERHEAD)

/* PPPoE Tag */

struct PPPoETag {
    unsigned int type:16;	/* tag type */
    unsigned int length:16;	/* Length of payload */
    unsigned char payload[ETH_DATA_LEN]; /* A LOT of room to spare */
};
/* Header size of a PPPoE tag */
#define TAG_HDR_SIZE 4

/* Chunk to read from stdin */
#define READ_CHUNK 4096

/* Function passed to parsePacket */
typedef void ParseFunc(UINT16_t type,
		       UINT16_t len,
		       unsigned char *data,
		       void *extra);

/* Structure used to determine acceptable PADO or PADS packet */
struct PacketCriteria {
    int acNameOK;
    int serviceNameOK;
};

/* Structures used by PPPoE server */
struct ClientSession {
    pid_t pid;			/* PID of child handling session */
    unsigned char ip[IPV4ALEN];	/* IP address of peer */
    UINT16_t sess;		/* Session number */
    unsigned char eth[ETH_ALEN]; /* Peer's Ethernet address */
};

#define PPPINITFCS16    0xffff  /* Initial FCS value */

/* Function Prototypes */
UINT16_t etherType(struct PPPoEPacket *packet);
int openInterface(char const *ifname, UINT16_t type, unsigned char *hwaddr);
void sendPacket(int sock, struct PPPoEPacket *pkt, int size);
void receivePacket(int sock, struct PPPoEPacket *pkt, int *size);
void fatalSys(char const *str);
void fatal(char const *str);
void printErr(char const *str);
void dumpPacket(FILE *fp, struct PPPoEPacket *packet);
void dumpHex(FILE *fp, unsigned char const *buf, int len);
int parsePacket(struct PPPoEPacket *packet, ParseFunc *func, void *extra);
void syncReadFromPPP(struct PPPoEPacket *packet);
void asyncReadFromPPP(struct PPPoEPacket *packet);
void asyncReadFromEth(int sock, int clampMss);
void syncReadFromEth(int sock, int clampMss);
char *strDup(char const *str);
void sendPADT(void);
void sendSessionPacket(struct PPPoEPacket *packet, int len);
void initPPP(void);
void clampMSS(struct PPPoEPacket *packet, char const *dir, int clampMss);
UINT16_t computeTCPChecksum(unsigned char *ipHdr, unsigned char *tcpHdr);
UINT16_t pppFCS16(UINT16_t fcs, unsigned char *cp, int len);

#define SET_STRING(var, val) do { if (var) free(var); var = strDup(val); } while(0);

