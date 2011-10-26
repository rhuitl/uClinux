#ifndef _NETINET_IP_H
#define _NETINET_IP_H

#include <features.h>
#include <netinet/in.h>
#include <linux/ip.h>

#ifdef _BSD_SOURCE

/*
 *	BSD has the following structure
 */
 
struct ip
{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ip_hl:4,
		ip_v:4;
#else
	__u8	ip_v:4,
		ip_hl:4;
#endif
#define IPVERSION	4
	__u8	ip_tos;
	__u16	ip_len;
	__u16	ip_id;
	__u16	ip_off;
	__u8	ip_ttl;
	__u8	ip_p;
	__u16	ip_csum;
	struct	in_addr ip_src,ip_dst;
};

#define	IP_DF	0x4000		/* dont fragment flag */
#define	IP_MF	0x2000		/* more fragments flag */

#endif

#endif /* _NETINET_IP_H */
