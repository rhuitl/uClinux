/*
 * IPSEC Tunneling code. Heavily based on drivers/net/new_tunnel.c
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs.
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

char ipsec_tunnel_c_version[] = "RCSID $Id: ipsec_tunnel.c,v 1.187 2002/03/23 19:55:17 rgb Exp $";

#define __NO_VERSION__
#include <linux/module.h>
#include <linux/config.h>	/* for CONFIG_IP_FORWARD */
#include <linux/version.h>
#include <linux/kernel.h> /* printk() */

/* XXX-mcr remove this definition when the code has been properly rototiled */
#define IPSEC_KLIPS1_COMPAT 1
#include "ipsec_param.h"

#ifdef MALLOC_SLAB
# include <linux/slab.h> /* kmalloc() */
#else /* MALLOC_SLAB */
# include <linux/malloc.h> /* kmalloc() */
#endif /* MALLOC_SLAB */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */

#include <linux/netdevice.h>   /* struct device, struct net_device_stats, dev_queue_xmit() and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/ip.h>          /* struct iphdr */
#include <linux/tcp.h>         /* struct tcphdr */
#include <linux/udp.h>         /* struct udphdr */
#include <linux/skbuff.h>
#include <freeswan.h>
#ifdef NET_21
# define MSS_HACK_		/* experimental */
# include <asm/uaccess.h>
# include <linux/in6.h>
# define ip_chk_addr inet_addr_type
# define IS_MYADDR RTN_LOCAL
# include <net/dst.h>
# undef dev_kfree_skb
# define dev_kfree_skb(a,b) kfree_skb(a)
# define proto_priv cb
# define PHYSDEV_TYPE
#endif /* NET_21 */
#include <asm/checksum.h>
#include <net/icmp.h>		/* icmp_send() */
#include <net/ip.h>
#ifdef NETDEV_23
# include <linux/netfilter_ipv4.h>
#endif /* NETDEV_23 */
#ifdef CONFIG_LEDMAN
#include <linux/ledman.h>
#endif

#include "ipsec_alg.h"

#include <linux/if_arp.h>
#ifdef MSS_HACK
# include <net/tcp.h>		/* TCP options */
#endif	/* MSS_HACK */

#include "radij.h"
#include "ipsec_life.h"
#include "ipsec_xform.h"
#include "ipsec_eroute.h"
#include "ipsec_encap.h"
#include "ipsec_radij.h"
#include "ipsec_netlink.h"
#include "ipsec_sa.h"
#include "ipsec_tunnel.h"
#include "ipsec_ipe4.h"
#include "ipsec_ah.h"
#include "ipsec_esp.h"

#ifdef CONFIG_IPSEC_IPCOMP
# include "ipcomp.h"
#endif /* CONFIG_IPSEC_IPCOMP */

#include <pfkeyv2.h>
#include <pfkey.h>

#include "ipsec_proto.h"

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
#include <linux/udp.h>
#endif

static __u32 zeroes[64];

#ifdef CONFIG_IPSEC_DEBUG
int debug_tunnel = 0;
int sysctl_ipsec_debug_verbose = 0;
#endif /* CONFIG_IPSEC_DEBUG */

int sysctl_ipsec_icmp = 0;
int sysctl_ipsec_tos = 0;

#ifdef CONFIG_IPSEC_DEBUG_
DEBUG_NO_STATIC void
dmp(char *s, caddr_t bb, int len)
{
	int i;
	unsigned char *b = bb;
  
	if (debug_tunnel) {
		printk(KERN_INFO "klips_debug:ipsec_tunnel_:dmp: "
		       "at %s, len=%d:",
		       s,
		       len);
		for (i=0; i < len; i++) {
			if(!(i%16)){
				printk("\nklips_debug:  ");
			}
			printk(" %02x", *b++);
		}
		printk("\n");
	}
}
#else /* CONFIG_IPSEC_DEBUG */
#define dmp(_x, _y, _z) 
#endif /* CONFIG_IPSEC_DEBUG */

#ifndef SKB_COPY_EXPAND
/*
 *	This is mostly skbuff.c:skb_copy().
 */
struct sk_buff *
skb_copy_expand(struct sk_buff *skb, int headroom, int tailroom, int priority)
{
	struct sk_buff *n;
	unsigned long offset;

	/*
	 *	Do sanity checking
	 */
	if((headroom < 0) || (tailroom < 0) || ((headroom+tailroom) < 0)) {
		printk(KERN_WARNING
		       "klips_error:skb_copy_expand: "
		       "Illegal negative head,tailroom %d,%d\n",
		       headroom,
		       tailroom);
		return NULL;
	}
	/*
	 *	Allocate the copy buffer
	 */
	 
#ifndef NET_21
	IS_SKB(skb);
#endif /* !NET_21 */


	n=alloc_skb(skb->end - skb->head + headroom + tailroom, priority);

	KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
		    "klips_debug:skb_copy_expand: "
		    "head=%p data=%p tail=%p end=%p end-head=%d tail-data=%d\n",
		    skb->head,
		    skb->data,
		    skb->tail,
		    skb->end,
		    skb->end - skb->head,
		    skb->tail - skb->data);

	if(n==NULL)
		return NULL;

	/*
	 *	Shift between the two data areas in bytes
	 */
	 
	/* offset=n->head-skb->head; */ /* moved down a few lines */

	/* Set the data pointer */
	skb_reserve(n,skb->data-skb->head+headroom);
	/* Set the tail pointer and length */
	if(skb_tailroom(n) < skb->len) {
		printk(KERN_WARNING "klips_error:skb_copy_expand: "
		       "tried to skb_put %ld, %d available.  This should never happen, please report.\n",
		       (unsigned long int)skb->len,
		       skb_tailroom(n));
		dev_kfree_skb(n, FREE_WRITE);
		return NULL;
	}
	skb_put(n,skb->len);

	offset=n->head + headroom - skb->head;

	/* Copy the bytes */
	memcpy(n->head + headroom, skb->head,skb->end-skb->head);
#ifdef NET_21
	n->csum=skb->csum;
	n->priority=skb->priority;
	n->dst=dst_clone(skb->dst);
	if(skb->nh.raw)
		n->nh.raw=skb->nh.raw+offset;
#ifndef NETDEV_23
	n->is_clone=0;
#endif /* NETDEV_23 */
	atomic_set(&n->users, 1);
	n->destructor = NULL;
	n->security=skb->security;
#else /* NET_21 */
	n->link3=NULL;
	n->when=skb->when;
	if(skb->ip_hdr)
	        n->ip_hdr=(struct iphdr *)(((char *)skb->ip_hdr)+offset);
	n->saddr=skb->saddr;
	n->daddr=skb->daddr;
	n->raddr=skb->raddr;
	n->seq=skb->seq;
	n->end_seq=skb->end_seq;
	n->ack_seq=skb->ack_seq;
	n->acked=skb->acked;
	n->free=1;
	n->arp=skb->arp;
	n->tries=0;
	n->lock=0;
	n->users=0;
#endif /* NET_21 */
	n->protocol=skb->protocol;
	n->list=NULL;
	n->sk=NULL;
	n->dev=skb->dev;
	if(skb->h.raw)
		n->h.raw=skb->h.raw+offset;
	if(skb->mac.raw) 
		n->mac.raw=skb->mac.raw+offset;
	memcpy(n->proto_priv, skb->proto_priv, sizeof(skb->proto_priv));
#ifndef NETDEV_23
	n->used=skb->used;
#endif /* !NETDEV_23 */
	n->pkt_type=skb->pkt_type;
	n->stamp=skb->stamp;
	
#ifndef NET_21
	IS_SKB(n);
#endif /* !NET_21 */
	return n;
}
#endif /* !SKB_COPY_EXPAND */

#ifdef CONFIG_IPSEC_DEBUG
void
ipsec_print_ip(struct iphdr *ip)
{
	char buf[ADDRTOA_BUF];

	printk(KERN_INFO "klips_debug:   IP:");
	printk(" ihl:%d", ip->ihl*4);
	printk(" ver:%d", ip->version);
	printk(" tos:%d", ip->tos);
	printk(" tlen:%d", ntohs(ip->tot_len));
	printk(" id:%d", ntohs(ip->id));
	printk(" %s%s%sfrag_off:%d",
               ip->frag_off & __constant_htons(IP_CE) ? "CE " : "",
               ip->frag_off & __constant_htons(IP_DF) ? "DF " : "",
               ip->frag_off & __constant_htons(IP_MF) ? "MF " : "",
               (ntohs(ip->frag_off) & IP_OFFSET) << 3);
	printk(" ttl:%d", ip->ttl);
	printk(" proto:%d", ip->protocol);
	if(ip->protocol == IPPROTO_UDP)
		printk(" (UDP)");
	if(ip->protocol == IPPROTO_TCP)
		printk(" (TCP)");
	if(ip->protocol == IPPROTO_ICMP)
		printk(" (ICMP)");
	printk(" chk:%d", ntohs(ip->check));
	addrtoa(*((struct in_addr*)(&ip->saddr)), 0, buf, sizeof(buf));
	printk(" saddr:%s", buf);
	if(ip->protocol == IPPROTO_UDP)
		printk(":%d",
		       ntohs(((struct udphdr*)((caddr_t)ip + (ip->ihl << 2)))->source));
	if(ip->protocol == IPPROTO_TCP)
		printk(":%d",
		       ntohs(((struct tcphdr*)((caddr_t)ip + (ip->ihl << 2)))->source));
	addrtoa(*((struct in_addr*)(&ip->daddr)), 0, buf, sizeof(buf));
	printk(" daddr:%s", buf);
	if(ip->protocol == IPPROTO_UDP)
		printk(":%d",
		       ntohs(((struct udphdr*)((caddr_t)ip + (ip->ihl << 2)))->dest));
	if(ip->protocol == IPPROTO_TCP)
		printk(":%d",
		       ntohs(((struct tcphdr*)((caddr_t)ip + (ip->ihl << 2)))->dest));
	if(ip->protocol == IPPROTO_ICMP)
		printk(" type:code=%d:%d",
		       ((struct icmphdr*)((caddr_t)ip + (ip->ihl << 2)))->type,
		       ((struct icmphdr*)((caddr_t)ip + (ip->ihl << 2)))->code);
	printk("\n");

	if(sysctl_ipsec_debug_verbose) {
		__u8 *c;
		int i;
		
		c = ((__u8*)ip) + ip->ihl*4;
		for(i = 0; i < ntohs(ip->tot_len) - ip->ihl*4; i++ /*, c++*/) {
			if(!(i % 16)) {
				printk(KERN_INFO
				       "klips_debug:   @%03x:",
				       i);
			}
			printk(" %02x", /***/c[i]);
			if(!((i + 1) % 16)) {
				printk("\n");
			}
		}
		if(i % 16) {
			printk("\n");
		}
	}
}
#endif /* CONFIG_IPSEC_DEBUG */

#ifdef REAL_LOCKING_P
/*
 *	Locking
 */
 
#if 0
DEBUG_NO_STATIC int
ipsec_tunnel_lock(struct ipsecpriv *prv)
{
	unsigned long flags;
	save_flags(flags);
	cli();
	/*
	 *	Lock in an interrupt may fail
	 */
	if(prv->locked && in_interrupt()) {
		restore_flags(flags);
		return 0;
	}
	while(prv->locked)
		sleep_on(&prv->wait_queue);
	prv->locked=1;
	restore_flags(flags);
	return 1;
}
#endif

#if 0
DEBUG_NO_STATIC void
ipsec_tunnel_unlock(struct ipsecpriv *prv)
{
	prv->locked=0;
	wake_up(&prv->wait_queue);
}
#endif
#endif /* REAL_LOCKING_P */

DEBUG_NO_STATIC int
ipsec_tunnel_open(struct device *dev)
{
	struct ipsecpriv *prv = dev->priv;
	
	/*
	 * Can't open until attached.
	 */

	KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
		    "klips_debug:ipsec_tunnel_open: "
		    "dev = %s, prv->dev = %s\n",
		    dev->name, prv->dev?prv->dev->name:"NONE");

	if (prv->dev == NULL)
		return -ENODEV;
	
	MOD_INC_USE_COUNT;
	return 0;
}

DEBUG_NO_STATIC int
ipsec_tunnel_close(struct device *dev)
{
	MOD_DEC_USE_COUNT;
	return 0;
}

#ifdef MSS_HACK
/*
 * Issues:
 *  1) Fragments arriving in the tunnel should probably be rejected.
 *  2) How does this affect syncookies, mss_cache, dst cache ?
 *  3) Path MTU discovery handling needs to be reviewed.  For example,
 *     if we receive an ICMP 'packet too big' message from an intermediate 
 *     router specifying it's next hop MTU, our stack may process this and
 *     adjust the MSS without taking our AH/ESP overheads into account.
 */

 
/*
 * Recaclulate checksum using differences between changed datum, 
 * borrowed from netfilter.
 */
DEBUG_NO_STATIC u_int16_t 
ipsec_fast_csum(u_int32_t oldvalinv, u_int32_t newval, u_int16_t oldcheck)
{
	u_int32_t diffs[] = { oldvalinv, newval };
	return csum_fold(csum_partial((char *)diffs, sizeof(diffs),
	oldcheck^0xFFFF));
}

/*
 * Determine effective MSS.
 *
 * Note that we assume that there is always an MSS option for our own
 * SYN segments, which is mentioned in tcp_syn_build_options(), kernel 2.2.x.
 * This could change, and we should probably parse TCP options instead.
 *
 */
DEBUG_NO_STATIC u_int8_t
ipsec_adjust_mss(struct sk_buff *skb, struct tcphdr *tcph, u_int16_t mtu)
{
	u_int16_t oldmss, newmss;
	u_int32_t *mssp;
	struct sock *sk = skb->sk;
	
	newmss = tcp_sync_mss(sk, mtu);
	printk(KERN_INFO "klips: setting mss to %u\n", newmss);
	mssp = (u_int32_t *)tcph + sizeof(struct tcphdr) / sizeof(u_int32_t);
	oldmss = ntohl(*mssp) & 0x0000FFFF;
	*mssp = htonl((TCPOPT_MSS << 24) | (TCPOLEN_MSS << 16) | newmss);
	tcph->check = ipsec_fast_csum(htons(~oldmss), 
	                              htons(newmss), tcph->check);
	return 1;
}
#endif	/* MSS_HACK */
                                                        
#ifdef NETDEV_23
static inline int ipsec_tunnel_xmit2(struct sk_buff *skb)
{
	return ip_send(skb);
}
#endif /* NETDEV_23 */

/*
 *	This function assumes it is being called from dev_queue_xmit()
 *	and that skb is filled properly by that function.
 */

int
ipsec_tunnel_start_xmit(struct sk_buff *skb, struct device *dev)
{
	struct ipsecpriv *prv;		/* Our device' private space */
	struct sk_buff *oskb = NULL;	/* Original skb pointer */
	struct net_device_stats *stats;	/* This device's statistics */
	struct iphdr  *iph;		/* Our new IP header */
	__u32   newdst;			/* The other SG's IP address */
	__u32	orgdst;			/* Original IP destination address */
	__u32	orgedst;		/* 1st SG's IP address */
	__u32   newsrc;			/* The new source SG's IP address */
	__u32	orgsrc;			/* Original IP source address */
	__u32	innersrc;		/* Innermost IP source address */
	int	iphlen;			/* IP header length */
	int	pyldsz;			/* upper protocol payload size */
	int	headroom;
	int	tailroom;
	int     max_headroom = 0;	/* The extra header space needed */
	int	max_tailroom = 0;	/* The extra stuffing needed */
	int     ll_headroom;		/* The extra link layer hard_header space needed */
	int     tot_headroom = 0;	/* The total header space needed */
	int	tot_tailroom = 0;	/* The totalstuffing needed */
	__u8	*saved_header = NULL;	/* saved copy of the hard header */
	int i;
	unsigned short   sport,dport;

	struct sockaddr_encap matcher;	/* eroute search key */
	struct eroute *er;
	struct ipsec_sa *tdbp, *tdbq;	/* Tunnel Descriptor Block pointers */
	char sa[SATOA_BUF];
	size_t sa_len;
	int hard_header_stripped = 0;	/* has the hard header been removed yet? */
	int hard_header_len = 0;
	struct device *physdev;
/*	struct device *virtdev; */
	short physmtu;
	short mtudiff;
	int blocksize = 8;
#ifdef NET_21
	struct rtable *rt = NULL;
#endif /* NET_21 */
	struct sa_id outgoing_said;
#ifdef NET_21
	int pass = 0;
#endif /* NET_21 */
	int error = 0;
	uint32_t eroute_pid = 0;
	struct ipsec_sa tdb;
#ifdef CONFIG_IPSEC_ALG
	struct ipsec_alg_enc *ixt_e = NULL;
	struct ipsec_alg_auth *ixt_a = NULL;
#endif /* CONFIG_IPSEC_ALG */

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	uint8_t natt_type = 0, natt_head = 0;
	uint16_t natt_sport = 0, natt_dport = 0;
#endif

	dport=sport=0;

	memset((char*)&tdb, 0, sizeof(struct ipsec_sa));

	/*
	 *	Return if there is nothing to do.  (Does this ever happen?) XXX
	 */
	if (skb == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_error:ipsec_tunnel_start_xmit: "
			    "Nothing to do!\n" );
		goto cleanup;
	}
	if (dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_error:ipsec_tunnel_start_xmit: "
			    "No device associated with skb!\n" );
		goto cleanup;
	}

	prv = dev->priv;
	if (prv == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_error:ipsec_tunnel_start_xmit: "
			    "Device has no private structure!\n" );
		goto cleanup;
	}

	physdev = prv->dev;
	if (physdev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_error:ipsec_tunnel_start_xmit: "
			    "Device is not attached to physical device!\n" );
		goto cleanup;
	}

	physmtu = physdev->mtu;

	stats = (struct net_device_stats *) &(prv->mystats);

#ifdef NET_21
	/* if skb was cloned (most likely due to a packet sniffer such as
	   tcpdump being momentarily attached to the interface), make
	   a copy of our own to modify */
	if(skb_cloned(skb)) {
		if
#ifdef SKB_COW_NEW
	       (skb_cow(skb, skb_headroom(skb)) != 0)
#else /* SKB_COW_NEW */
	       ((skb = skb_cow(skb, skb_headroom(skb))) == NULL)
#endif /* SKB_COW_NEW */
		{
			KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
				    "klips_error:ipsec_tunnel_start_xmit: "
				    "skb_cow failed to allocate buffer, dropping.\n" );
			stats->tx_dropped++;
			goto cleanup;
		}
	}
#endif /* NET_21 */

#ifdef NET_21
	iph = skb->nh.iph;
#else /* NET_21 */
	iph = skb->ip_hdr;
#endif /* NET_21 */

	/* sanity check for IP version as we can't handle IPv6 right now */
	if (iph->version != 4) {
		KLIPS_PRINT(debug_tunnel,
			    "klips_debug:ipsec_tunnel_start_xmit: "
			    "found IP Version %d but cannot process other IP versions than v4.\n",
			    iph->version); /* XXX */
		stats->tx_dropped++;
		goto cleanup;
	}
	
	/* physdev->hard_header_len is unreliable and should not be used */
	hard_header_len = (unsigned char *)iph - skb->data;

	if(hard_header_len < 0) {
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_error:ipsec_tunnel_start_xmit: "
			    "Negative hard_header_len (%d)?!\n", hard_header_len);
		stats->tx_dropped++;
		goto cleanup;
	}

	if(hard_header_len == 0) { /* no hard header present */
		hard_header_stripped = 1;
	}

#ifdef CONFIG_IPSEC_DEBUG
	if (debug_tunnel & DB_TN_XMIT) {
		int i;
		char c;
		
		printk(KERN_INFO "klips_debug:ipsec_tunnel_start_xmit: "
		       ">>> skb->len=%ld hard_header_len:%d",
		       (unsigned long int)skb->len, hard_header_len);
		c = ' ';
		for (i=0; i < hard_header_len; i++) {
			printk("%c%02x", c, skb->data[i]);
			c = ':';
		}
		printk(" \n");
	}
#endif /* CONFIG_IPSEC_DEBUG */

	KLIPS_IP_PRINT(debug_tunnel & DB_TN_XMIT, iph);

	/*
	 * Sanity checks
	 */

	if ((iph->ihl << 2) != sizeof (struct iphdr)) {
		KLIPS_PRINT(debug_tunnel,
			    "klips_debug:ipsec_tunnel_start_xmit: "
			    "cannot process IP header options yet.  May be mal-formed packet.\n"); /* XXX */
		stats->tx_dropped++;
		goto cleanup;
	}
	
#ifndef NET_21
	/* TTL decrement code (on the way out!) borrowed from ip_forward.c */
	if(0) {
		unsigned long checksum = iph->check;
		iph->ttl--;
	/*
	 *	Re-compute the IP header checksum.
	 *	This is efficient. We know what has happened to the header
	 *	and can thus adjust the checksum as Phil Karn does in KA9Q
	 *	except we do this in "network byte order".
	 */
		checksum += htons(0x0100);
		/* carry overflow? */
		checksum += checksum >> 16;
		iph->check = checksum;
	}
	if (iph->ttl <= 0) {
		/* Tell the sender its packet died... */
		ICMP_SEND(skb, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0, physdev);

		KLIPS_PRINT(debug_tunnel, "klips_debug:ipsec_tunnel_start_xmit: "
			    "TTL=0, too many hops!\n");
		stats->tx_dropped++;
		goto cleanup;
	}
#endif /* !NET_21 */

	/*
	 * First things first -- look us up in the erouting tables.
	 */
	matcher.sen_len = sizeof (struct sockaddr_encap);
	matcher.sen_family = AF_ENCAP;
	matcher.sen_type = SENT_IP4;
	matcher.sen_ip_src.s_addr = iph->saddr;
	matcher.sen_ip_dst.s_addr = iph->daddr;

	/*
	 * The spinlock is to prevent any other process from accessing or deleting
	 * the eroute while we are using and updating it.
	 */
	spin_lock(&eroute_lock);
	
	er = ipsec_findroute(&matcher);

	if(iph->protocol == IPPROTO_UDP) {
#ifdef NET_21
		if(skb->sk) {
			sport=ntohs(skb->sk->sport);
			dport=ntohs(skb->sk->dport);
		} else
#endif
		if((ntohs(iph->frag_off) & IP_OFFSET) == 0 &&
			  iph->ihl << 2 > sizeof(struct iphdr) + sizeof(struct udphdr)) {
			sport=ntohs(((struct udphdr*)((caddr_t)iph+(iph->ihl<<2)))->source);
			dport=ntohs(((struct udphdr*)((caddr_t)iph + (iph->ihl<<2)))->dest);
		} else {
			sport=0; dport=0;
		}
	}

	/* default to a %drop eroute */
	outgoing_said.proto = IPPROTO_INT;
	outgoing_said.spi = htonl(SPI_DROP);
	outgoing_said.dst.s_addr = INADDR_ANY;
	KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
		    "klips_debug:ipsec_tunnel_start_xmit: "
		    "checking for local udp/500 IKE packet "
		    "saddr=%x, er=%p, daddr=%x, er_dst=%x, proto=%d sport=%d dport=%d\n",
		    ntohl((unsigned int)iph->saddr),
		    er,
		    ntohl((unsigned int)iph->daddr),
		    er ? ntohl((unsigned int)er->er_said.dst.s_addr) : 0,
		    iph->protocol,
		    sport,
		    dport); 

	/*
	 * Quick cheat for now...are we udp/500? If so, let it through
	 * without interference since it is most likely an IKE packet.
	 */

	if (ip_chk_addr((unsigned long)iph->saddr) == IS_MYADDR
	    && (!er
		|| iph->daddr == er->er_said.dst.s_addr
		|| INADDR_ANY == er->er_said.dst.s_addr)
#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	    && ((sport == 500) || (sport == 4500))
#else
	    && (sport == 500)
#endif
	    ) {
		/* Whatever the eroute, this is an IKE message
		 * from us (i.e. not being forwarded).
		 * Furthermore, if there is a tunnel eroute,
		 * the destination is the peer for this eroute.
		 * So %pass the packet: modify the default %drop.
		 */
		outgoing_said.spi = htonl(SPI_PASS);
		if(!(skb->sk) && ((ntohs(iph->frag_off) & IP_MF) != 0)) {
			KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
				    "klips_debug:ipsec_tunnel_start_xmit: "
				    "local UDP/500 (probably IKE) passthrough: base fragment, rest of fragments will probably get filtered.\n");
		}
	} else if (er) {
		er->er_count++;
		er->er_lasttime = jiffies/HZ;
		if(er->er_said.proto==IPPROTO_INT
		   && er->er_said.spi==htonl(SPI_HOLD)) {
			KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
				    "klips_debug:ipsec_tunnel_start_xmit: "
				    "shunt SA of HOLD: skb stored in HOLD.\n");
			if(er->er_last != NULL) {
				dev_kfree_skb(er->er_last, FREE_WRITE);
			}
			er->er_last = skb;
			skb = NULL;
			stats->tx_dropped++;
			spin_unlock(&eroute_lock);
			goto cleanup;
		}
		outgoing_said = er->er_said;
		eroute_pid = er->er_pid;
		/* Copy of the ident for the TRAP/TRAPSUBNET eroutes */
		if(outgoing_said.proto==IPPROTO_INT
		   && (outgoing_said.spi==htonl(SPI_TRAP)
		       || (outgoing_said.spi==htonl(SPI_TRAPSUBNET)))) {
			int len;
			
			tdb.tdb_ident_s.type = er->er_ident_s.type;
			tdb.tdb_ident_s.id = er->er_ident_s.id;
			tdb.tdb_ident_s.len = er->er_ident_s.len;
			if (tdb.tdb_ident_s.len) {
				len = tdb.tdb_ident_s.len * IPSEC_PFKEYv2_ALIGN - sizeof(struct sadb_ident);
				if ((tdb.tdb_ident_s.data = kmalloc(len, GFP_ATOMIC)) == NULL) {
					printk(KERN_WARNING "klips_debug:ipsec_tunnel_start_xmit: "
					       "Failed, tried to allocate %d bytes for source ident.\n", 
					       len);
					stats->tx_dropped++;
					spin_unlock(&eroute_lock);
					goto cleanup;
				}
				memcpy(tdb.tdb_ident_s.data, er->er_ident_s.data, len);
			}
			tdb.tdb_ident_d.type = er->er_ident_d.type;
			tdb.tdb_ident_d.id = er->er_ident_d.id;
			tdb.tdb_ident_d.len = er->er_ident_d.len;
			if (tdb.tdb_ident_d.len) {
				len = tdb.tdb_ident_d.len * IPSEC_PFKEYv2_ALIGN - sizeof(struct sadb_ident);
				if ((tdb.tdb_ident_d.data = kmalloc(len, GFP_ATOMIC)) == NULL) {
					printk(KERN_WARNING "klips_debug:ipsec_tunnel_start_xmit: "
					       "Failed, tried to allocate %d bytes for dest ident.\n", 
					       len);
					stats->tx_dropped++;
					spin_unlock(&eroute_lock);
					goto cleanup;
				}
				memcpy(tdb.tdb_ident_d.data, er->er_ident_d.data, len);
			}
		}
	}

	spin_unlock(&eroute_lock);

	KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
		    "klips_debug:ipsec_tunnel_start_xmit: "
		    "Original head,tailroom: %d,%d\n",
		    skb_headroom(skb), skb_tailroom(skb));

#ifdef CONFIG_LEDMAN
	ledman_cmd(LEDMAN_CMD_SET, LEDMAN_VPN_TX);
#endif

	innersrc = iph->saddr;
	/* start encapsulation loop here XXX */
	do {
		struct ipsec_sa *tdbprev = NULL;

		newdst = orgdst = iph->daddr;
		newsrc = orgsrc = iph->saddr;
		orgedst = outgoing_said.dst.s_addr;
		iphlen = iph->ihl << 2;
		pyldsz = ntohs(iph->tot_len) - iphlen;
		max_headroom = max_tailroom = 0;
		
		if (outgoing_said.proto == IPPROTO_INT) {
			switch (ntohl(outgoing_said.spi)) {
			case SPI_DROP:
				KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
					    "klips_debug:ipsec_tunnel_start_xmit: "
					    "shunt SA of DROP or no eroute: dropping.\n");
				stats->tx_dropped++;
				break;
				
			case SPI_REJECT:
				KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
					    "klips_debug:ipsec_tunnel_start_xmit: "
					    "shunt SA of REJECT: notifying and dropping.\n");
				ICMP_SEND(skb,
					  ICMP_DEST_UNREACH,
					  ICMP_PKT_FILTERED,
					  0,
					  physdev);
				stats->tx_dropped++;
				break;
				
			case SPI_PASS:
#ifdef NET_21
				pass = 1;
#endif /* NET_21 */
				KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
					    "klips_debug:ipsec_tunnel_start_xmit: "
					    "PASS: calling dev_queue_xmit\n");
				goto bypass;
				
#if 1 /* now moved up to finderoute so we don't need to lock it longer */
			case SPI_HOLD:
				KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
					    "klips_debug:ipsec_tunnel_start_xmit: "
					    "shunt SA of HOLD: this does not make sense here, dropping.\n");
			stats->tx_dropped++;
			break;
#endif		
			case SPI_TRAP:
			case SPI_TRAPSUBNET:
				stats->tx_dropped++;
			default:
				/* XXX what do we do with an unknown shunt spi? */
				break;
			} /* switch (ntohl(outgoing_said.spi)) */
			goto cleanup;
		} /* if (outgoing_said.proto == IPPROTO_INT) */
		
		/*
		  The spinlock is to prevent any other process from
		  accessing or deleting the TDB hash table or any of the
		  TDBs while we are using and updating them.
		  
		  This is not optimal, but was relatively straightforward
		  at the time.  A better way to do it has been planned for
		  more than a year, to lock the hash table and put reference
		  counts on each TDB instead.  This is not likely to happen
		  in KLIPS1 unless a volunteer contributes it, but will be
		  designed into KLIPS2.
		*/
		spin_lock(&tdb_lock);

		tdbp = ipsec_sa_getbyid(&outgoing_said);
		sa_len = satoa(outgoing_said, 0, sa, SATOA_BUF);

		if (tdbp == NULL) {
			spin_unlock(&tdb_lock);
			KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
				    "klips_debug:ipsec_tunnel_start_xmit: "
				    "no Tunnel Descriptor Block for SA%s: outgoing packet with no SA, dropped.\n",
				    sa_len ? sa : " (error)");
			stats->tx_dropped++;
			goto cleanup;
		}
		
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_debug:ipsec_tunnel_start_xmit: "
			    "found Tunnel Descriptor Block -- SA:<%s%s%s> %s\n",
			    IPS_XFORM_NAME(tdbp),
			    sa_len ? sa : " (error)");
		
		/*
		 * How much headroom do we need to be able to apply
		 * all the grouped transforms?
		 */
		tdbq = tdbp;	/* save the head of the tdb chain */
		while (tdbp)	{
			sa_len = satoa(tdbp->tdb_said, 0, sa, SATOA_BUF);
			if(sa_len == 0) {
				strcpy(sa, "(error)");
			}

			/* If it is in larval state, drop the packet, we cannot process yet. */
			if(tdbp->tdb_state == SADB_SASTATE_LARVAL) {
				KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
					    "klips_debug:ipsec_tunnel_start_xmit: "
					    "TDB in larval state for SA:<%s%s%s> %s, cannot be used yet, dropping packet.\n",
					    IPS_XFORM_NAME(tdbp),
					    sa_len ? sa : " (error)");
				spin_unlock(&tdb_lock);
				stats->tx_errors++;
				goto cleanup;
			}

			if(tdbp->tdb_state == SADB_SASTATE_DEAD) {
				KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
					    "klips_debug:ipsec_tunnel_start_xmit: "
					    "TDB in dead state for SA:<%s%s%s> %s, can no longer be used, dropping packet.\n",
					    IPS_XFORM_NAME(tdbp),
					    sa_len ? sa : " (error)");
				spin_unlock(&tdb_lock);
				stats->tx_errors++;
				goto cleanup;
			}

			/* If the replay window counter == -1, expire SA, it will roll */
			if(tdbp->tdb_replaywin && tdbp->tdb_replaywin_lastseq == -1) {
				pfkey_expire(tdbp, 1);
				KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
					    "klips_debug:ipsec_tunnel_start_xmit: "
					    "replay window counter rolled for SA:<%s%s%s> %s, packet dropped, expiring SA.\n",
					    IPS_XFORM_NAME(tdbp),
					    sa_len ? sa : " (error)");
				ipsec_sa_delchain(tdbp);
				spin_unlock(&tdb_lock);
				stats->tx_errors++;
				goto cleanup;
			}

			/*
			 * if this is the first time we are using this SA, mark start time,
			 * and offset hard/soft counters by "now" for later checking.
			 */
#if 0
			if(tdbp->ips_life.ipl_usetime.count == 0) {
				tdbp->ips_life.ipl_usetime.count = jiffies;
				tdbp->ips_life.ipl_usetime.hard += jiffies;
				tdbp->ips_life.ipl_usetime.soft += jiffies;
			}
#endif
			  

			if(ipsec_lifetime_check(&tdbp->ips_life.ipl_bytes, "bytes", sa, 
						ipsec_life_countbased, ipsec_outgoing, tdbp) == ipsec_life_harddied ||
			   ipsec_lifetime_check(&tdbp->ips_life.ipl_addtime, "addtime",sa,
						ipsec_life_timebased,  ipsec_outgoing, tdbp) == ipsec_life_harddied ||
			   ipsec_lifetime_check(&tdbp->ips_life.ipl_usetime, "usetime",sa,
						ipsec_life_timebased,  ipsec_outgoing, tdbp) == ipsec_life_harddied ||
			   ipsec_lifetime_check(&tdbp->ips_life.ipl_packets, "packets",sa,
						ipsec_life_countbased, ipsec_outgoing, tdbp) == ipsec_life_harddied) {
				
				ipsec_sa_delchain(tdbp);
				spin_unlock(&tdb_lock);
				stats->tx_errors++;
				goto cleanup;
			}
			

			headroom = tailroom = 0;
			KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
				    "klips_debug:ipsec_tunnel_start_xmit: "
				    "calling room for <%s%s%s>, SA:%s\n", 
				    IPS_XFORM_NAME(tdbp),
				    sa_len ? sa : " (error)");
			switch(tdbp->tdb_said.proto) {
#ifdef CONFIG_IPSEC_AH
			case IPPROTO_AH:
				headroom += sizeof(struct ah);
				break;
#endif /* CONFIG_IPSEC_AH */
#ifdef CONFIG_IPSEC_ESP
			case IPPROTO_ESP:
#ifdef CONFIG_IPSEC_ALG
				if ((ixt_e=IPSEC_ALG_SA_ESP_ENC(tdbp))) {
					blocksize = ixt_e->ixt_blocksize;
					headroom += ESP_HEADER_LEN+blocksize;
				} else
#endif /* CONFIG_IPSEC_ALG */
				switch(tdbp->tdb_encalg) {
#ifdef CONFIG_IPSEC_ENC_DES
				case ESP_DES:
					headroom += sizeof(struct esp);
					break;
#endif /* CONFIG_IPSEC_ENC_DES */
#ifdef CONFIG_IPSEC_ENC_3DES
				case ESP_3DES:
					headroom += sizeof(struct esp);
					break;
#endif /* CONFIG_IPSEC_ENC_3DES */
				default:
					spin_unlock(&tdb_lock);
					stats->tx_errors++;
					goto cleanup;
				}
#ifdef CONFIG_IPSEC_ALG
				if ((ixt_a=IPSEC_ALG_SA_ESP_AUTH(tdbp))) {
					tailroom += AHHMAC_HASHLEN;
				} else
#endif /* CONFIG_IPSEC_ALG */
				switch(tdbp->tdb_authalg) {
#ifdef CONFIG_IPSEC_AUTH_HMAC_MD5
				case AH_MD5:
					tailroom += AHHMAC_HASHLEN;
					break;
#endif /* CONFIG_IPSEC_AUTH_HMAC_MD5 */
#ifdef CONFIG_IPSEC_AUTH_HMAC_SHA1
				case AH_SHA:
					tailroom += AHHMAC_HASHLEN;
					break;
#endif /* CONFIG_IPSEC_AUTH_HMAC_SHA1 */
				case AH_NONE:
					break;
				default:
					spin_unlock(&tdb_lock);
					stats->tx_errors++;
					goto cleanup;
				}			
				tailroom += ((blocksize - ((pyldsz + 2 * sizeof(unsigned char)) % blocksize)) % blocksize) + 2;
#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
				if ((tdbp->ips_natt_type) && (!natt_type)) {
					natt_type = tdbp->ips_natt_type;
					natt_sport = tdbp->ips_natt_sport;
					natt_dport = tdbp->ips_natt_dport;
					switch (natt_type) {
						case ESPINUDP_WITH_NON_IKE:
							natt_head = sizeof(struct udphdr)+(2*sizeof(__u32));
							break;
						case ESPINUDP_WITH_NON_ESP:
							natt_head = sizeof(struct udphdr);
							break;
						default:
							natt_head = 0;
							break;
					}
					tailroom += natt_head;
				}
#endif
				break;
#endif /* !CONFIG_IPSEC_ESP */
#ifdef CONFIG_IPSEC_IPIP
			case IPPROTO_IPIP:
				headroom += sizeof(struct iphdr);
				break;
#endif /* !CONFIG_IPSEC_IPIP */
			case IPPROTO_COMP:
#ifdef CONFIG_IPSEC_IPCOMP
				/*
				  We can't predict how much the packet will
				  shrink without doing the actual compression.
				  We could do it here, if we were the first
				  encapsulation in the chain.  That might save
				  us a skb_copy_expand, since we might fit
				  into the existing skb then.  However, this
				  would be a bit unclean (and this hack has
				  bit us once), so we better not do it. After
				  all, the skb_copy_expand is cheap in
				  comparison to the actual compression.
				  At least we know the packet will not grow.
				*/
				break;
#endif /* CONFIG_IPSEC_IPCOMP */
			default:
				spin_unlock(&tdb_lock);
				stats->tx_errors++;
				goto cleanup;
			}
			tdbp = tdbp->tdb_onext;
#ifdef CONFIG_IPSEC_ALG
			ixt_e = NULL;	/* invalidate ipsec_alg */
			ixt_a = NULL;
#endif /* CONFIG_IPSEC_ALG */
			KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
				    "klips_debug:ipsec_tunnel_start_xmit: "
				    "Required head,tailroom: %d,%d\n", 
				    headroom, tailroom);
			max_headroom += headroom;
			max_tailroom += tailroom;
			pyldsz += (headroom + tailroom);
		}
		tdbp = tdbq;	/* restore the head of the tdb chain */
		
		KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
			    "klips_debug:ipsec_tunnel_start_xmit: "
			    "existing head,tailroom: %d,%d before applying xforms with head,tailroom: %d,%d .\n",
			    skb_headroom(skb), skb_tailroom(skb),
			    max_headroom, max_tailroom);
		
		tot_headroom += max_headroom;
		tot_tailroom += max_tailroom;
		
		mtudiff = prv->mtu + tot_headroom + tot_tailroom - physmtu;

		KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
			    "klips_debug:ipsec_tunnel_start_xmit: "
			    "mtu:%d physmtu:%d tothr:%d tottr:%d mtudiff:%d ippkttotlen:%d\n",
			    prv->mtu, physmtu,
			    tot_headroom, tot_tailroom, mtudiff, ntohs(iph->tot_len));
		if(mtudiff > 0) {
			int newmtu = physmtu - (tot_headroom + ((tot_tailroom + 2) & ~7) + 5);

			KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
				    "klips_info:ipsec_tunnel_start_xmit: "
				    "dev %s mtu of %d decreased by %d to %d\n",
				    dev->name,
				    prv->mtu,
				    prv->mtu - newmtu,
				    newmtu);
			prv->mtu = newmtu;
#ifdef NET_21
#if 0
			skb->dst->pmtu = prv->mtu; /* RGB */
#endif /* 0 */
#else /* NET_21 */
#if 0
			dev->mtu = prv->mtu; /* RGB */
#endif /* 0 */
#endif /* NET_21 */
		}

		/* 
		   If the sender is doing PMTU discovery, and the
		   packet doesn't fit within prv->mtu, notify him
		   (unless it was an ICMP packet, or it was not the
		   zero-offset packet) and send it anyways.

		   Note: buggy firewall configuration may prevent the
		   ICMP packet from getting back.
		*/
		if(sysctl_ipsec_icmp
		   && prv->mtu < ntohs(iph->tot_len)
		   && (iph->frag_off & __constant_htons(IP_DF)) ) {
			int notify = iph->protocol != IPPROTO_ICMP
				&& (iph->frag_off & __constant_htons(IP_OFFSET)) == 0;
			
#ifdef IPSEC_obey_DF
			spin_unlock(&tdb_lock);
			KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
				    "klips_debug:ipsec_tunnel_start_xmit: "
				    "fragmentation needed and DF set; %sdropping packet\n",
				    notify ? "sending ICMP and " : "");
			if (notify)
				ICMP_SEND(skb,
					  ICMP_DEST_UNREACH,
					  ICMP_FRAG_NEEDED,
					  prv->mtu,
					  physdev);
			stats->tx_errors++;
			goto cleanup;
#else /* IPSEC_obey_DF */
			KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
				    "klips_debug:ipsec_tunnel_start_xmit: "
				    "fragmentation needed and DF set; %spassing packet\n",
				    notify ? "sending ICMP and " : "");
			if (notify)
				ICMP_SEND(skb,
					  ICMP_DEST_UNREACH,
					  ICMP_FRAG_NEEDED,
					  prv->mtu,
					  physdev);
#endif /* IPSEC_obey_DF */
		}
		
#ifdef MSS_HACK
		/*
		 * If this is a transport mode TCP packet with
		 * SYN set, determine an effective MSS based on 
		 * AH/ESP overheads determined above.
		 */
		if (iph->protocol == IPPROTO_TCP 
		    && outgoing_said.proto != IPPROTO_IPIP) {
			struct tcphdr *tcph = skb->h.th;
			if (tcph->syn && !tcph->ack) {
				if(!ipsec_adjust_mss(skb, tcph, prv->mtu)) {
					spin_unlock(&tdb_lock);
					printk(KERN_WARNING
					       "klips_warning:ipsec_tunnel_start_xmit: "
					       "ipsec_adjust_mss() failed\n");
					stats->tx_errors++;
					goto cleanup;
				}
			}
		}
#endif /* MSS_HACK */

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	if ((natt_type) && (outgoing_said.proto != IPPROTO_IPIP)) {
		/**
		 * NAT-Traversal and Transport Mode:
		 *   we need to correct TCP/UDP checksum
		 *
		 * If we've got NAT-OA, we can fix checksum without recalculation.
		 * If we don't we can zero udp checksum.
		 */
		__u32 natt_oa = tdbp->ips_natt_oa ?
			((struct sockaddr_in*)(tdbp->ips_natt_oa))->sin_addr.s_addr : 0;
		__u16 pkt_len = skb->tail - (unsigned char *)iph;
		__u16 data_len = pkt_len - (iph->ihl << 2);
		switch (iph->protocol) {
			case IPPROTO_TCP:
				if (data_len >= sizeof(struct tcphdr)) {
					struct tcphdr *tcp = (struct tcphdr *)((__u32 *)iph+iph->ihl);
					if (natt_oa) {
						__u32 buff[2] = { ~iph->daddr, natt_oa };
						KLIPS_PRINT(debug_tunnel,
							"klips_debug:ipsec_tunnel_start_xmit: "
							"NAT-T & TRANSPORT: "
							"fix TCP checksum using NAT-OA\n");
						tcp->check = csum_fold(
							csum_partial((unsigned char *)buff, sizeof(buff),
							tcp->check^0xffff));
					}
					else {
						KLIPS_PRINT(debug_tunnel,
							"klips_debug:ipsec_tunnel_start_xmit: "
							"NAT-T & TRANSPORT: do not recalc TCP checksum\n");
					}
				}
				else {
					KLIPS_PRINT(debug_tunnel,
						"klips_debug:ipsec_tunnel_start_xmit: "
						"NAT-T & TRANSPORT: can't fix TCP checksum\n");
				}
				break;
			case IPPROTO_UDP:
				if (data_len >= sizeof(struct udphdr)) {
					struct udphdr *udp = (struct udphdr *)((__u32 *)iph+iph->ihl);
					if (udp->check == 0) {
						KLIPS_PRINT(debug_tunnel,
							"klips_debug:ipsec_tunnel_start_xmit: "
							"NAT-T & TRANSPORT: UDP checksum already 0\n");
					}
					else if (natt_oa) {
						__u32 buff[2] = { ~iph->daddr, natt_oa };
						KLIPS_PRINT(debug_tunnel,
							"klips_debug:ipsec_tunnel_start_xmit: "
							"NAT-T & TRANSPORT: "
							"fix UDP checksum using NAT-OA\n");
						udp->check = csum_fold(
							csum_partial((unsigned char *)buff, sizeof(buff),
							udp->check^0xffff));
					}
					else {
						KLIPS_PRINT(debug_tunnel,
							"klips_debug:ipsec_tunnel_start_xmit: "
							"NAT-T & TRANSPORT: zero UDP checksum\n");
						udp->check = 0;
					}
				}
				else {
					KLIPS_PRINT(debug_tunnel,
						"klips_debug:ipsec_tunnel_start_xmit: "
						"NAT-T & TRANSPORT: can't fix UDP checksum\n");
				}
				break;
			default:
				KLIPS_PRINT(debug_tunnel,
					"klips_debug:ipsec_tunnel_start_xmit: "
					"NAT-T & TRANSPORT: non TCP/UDP packet -- do nothing\n");
				break;
		}
	}
#endif /* CONFIG_IPSEC_NAT_TRAVERSAL */

		if(!hard_header_stripped) {
			if((saved_header = kmalloc(hard_header_len, GFP_ATOMIC)) == NULL) {
				spin_unlock(&tdb_lock);
				printk(KERN_WARNING "klips_debug:ipsec_tunnel_start_xmit: "
				       "Failed, tried to allocate %d bytes for temp hard_header.\n", 
				       hard_header_len);
				stats->tx_errors++;
				goto cleanup;
			}
			for (i = 0; i < hard_header_len; i++) {
				saved_header[i] = skb->data[i];
			}
			if(skb->len < hard_header_len) {
				spin_unlock(&tdb_lock);
				printk(KERN_WARNING "klips_error:ipsec_tunnel_start_xmit: "
				       "tried to skb_pull hhlen=%d, %d available.  This should never happen, please report.\n",
				       hard_header_len, (int)(skb->len));
				stats->tx_errors++;
				goto cleanup;
			}
			skb_pull(skb, hard_header_len);
			hard_header_stripped = 1;
			
/*			iph = (struct iphdr *) (skb->data); */
			KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
				    "klips_debug:ipsec_tunnel_start_xmit: "
				    "head,tailroom: %d,%d after hard_header stripped.\n",
				    skb_headroom(skb), skb_tailroom(skb));
			KLIPS_IP_PRINT(debug_tunnel & DB_TN_CROUT, iph);
		} else {
			KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
				    "klips_debug:ipsec_tunnel_start_xmit: "
				    "hard header already stripped.\n");
		}
		
		ll_headroom = (hard_header_len + 15) & ~15;

		if ((skb_headroom(skb) >= max_headroom + 2 * ll_headroom) && 
		    (skb_tailroom(skb) >= max_tailroom)
#ifndef NET_21
			&& skb->free
#endif /* !NET_21 */
			) {
			KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
				    "klips_debug:ipsec_tunnel_start_xmit: "
				    "data fits in existing skb\n");
		} else {
			struct sk_buff* tskb = skb;

			if(!oskb) {
				oskb = skb;
			}

			tskb = skb_copy_expand(skb,
			/* The reason for 2 * link layer length here still baffles me...RGB */
					       max_headroom + 2 * ll_headroom,
					       max_tailroom,
					       GFP_ATOMIC);
#ifdef NET_21
			if(tskb && skb->sk) {
				skb_set_owner_w(tskb, skb->sk);
			}
#endif /* NET_21 */
			if(!(skb == oskb) ) {
				dev_kfree_skb(skb, FREE_WRITE);
			}
			skb = tskb;
			if (!skb) {
				spin_unlock(&tdb_lock);
				printk(KERN_WARNING
				       "klips_debug:ipsec_tunnel_start_xmit: "
				       "Failed, tried to allocate %d head and %d tailroom\n", 
				       max_headroom, max_tailroom);
				stats->tx_errors++;
				goto cleanup;
			}
			KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
				    "klips_debug:ipsec_tunnel_start_xmit: "
				    "head,tailroom: %d,%d after allocation\n",
				    skb_headroom(skb), skb_tailroom(skb));
		}
		
		/*
		 * Apply grouped transforms to packet
		 */
		while (tdbp) {
#ifdef CONFIG_IPSEC_ESP
			struct esp *espp;
			__u32 iv[ESP_IV_MAXSZ_INT];
			unsigned char *idat, *pad;
			int authlen = 0, padlen = 0, i;
#endif /* !CONFIG_IPSEC_ESP */
#ifdef CONFIG_IPSEC_AH
			struct iphdr ipo;
			struct ah *ahp;
#endif /* CONFIG_IPSEC_AH */
#if defined(CONFIG_IPSEC_AUTH_HMAC_MD5) || defined(CONFIG_IPSEC_AUTH_HMAC_SHA1)
			union {
#ifdef CONFIG_IPSEC_AUTH_HMAC_MD5
				MD5_CTX md5;
#endif /* CONFIG_IPSEC_AUTH_HMAC_MD5 */
#ifdef CONFIG_IPSEC_AUTH_HMAC_SHA1
				SHA1_CTX sha1;
#endif /* CONFIG_IPSEC_AUTH_HMAC_SHA1 */
			} tctx;
			__u8 hash[AH_AMAX];
#endif /* defined(CONFIG_IPSEC_AUTH_HMAC_MD5) || defined(CONFIG_IPSEC_AUTH_HMAC_SHA1) */
			int headroom = 0, tailroom = 0, ilen = 0, len = 0;
			unsigned char *dat;
			
			iphlen = iph->ihl << 2;
			pyldsz = ntohs(iph->tot_len) - iphlen;
			sa_len = satoa(tdbp->tdb_said, 0, sa, SATOA_BUF);
			KLIPS_PRINT(debug_tunnel & DB_TN_OXFS,
				    "klips_debug:ipsec_tunnel_start_xmit: "
				    "calling output for <%s%s%s>, SA:%s\n", 
				    IPS_XFORM_NAME(tdbp),
				    sa_len ? sa : " (error)");
			
			switch(tdbp->tdb_said.proto) {
#ifdef CONFIG_IPSEC_AH
			case IPPROTO_AH:
				headroom += sizeof(struct ah);
				break;
#endif /* CONFIG_IPSEC_AH */
#ifdef CONFIG_IPSEC_ESP
			case IPPROTO_ESP:
#ifdef CONFIG_IPSEC_ALG
				if ((ixt_e=IPSEC_ALG_SA_ESP_ENC(tdbp))) {
					blocksize = ixt_e->ixt_blocksize;
					headroom += ESP_HEADER_LEN+blocksize;
				} else
#endif /* CONFIG_IPSEC_ALG */
				switch(tdbp->tdb_encalg) {
#ifdef CONFIG_IPSEC_ENC_DES 
				case ESP_DES:
					headroom += sizeof(struct esp);
					break;
#endif /* CONFIG_IPSEC_ENC_DES */
#ifdef CONFIG_IPSEC_ENC_3DES
				case ESP_3DES:
					headroom += sizeof(struct esp);
					break;
#endif /* CONFIG_IPSEC_ENC_3DES */
				default:
					spin_unlock(&tdb_lock);
					stats->tx_errors++;
					goto cleanup;
				}
#ifdef CONFIG_IPSEC_ALG
				if ((ixt_a=IPSEC_ALG_SA_ESP_AUTH(tdbp))) {
					authlen = AHHMAC_HASHLEN;
				} else
#endif /* CONFIG_IPSEC_ALG */
				switch(tdbp->tdb_authalg) {
#ifdef CONFIG_IPSEC_AUTH_HMAC_MD5
				case AH_MD5:
					authlen = AHHMAC_HASHLEN;
					break;
#endif /* CONFIG_IPSEC_AUTH_HMAC_MD5 */
#ifdef CONFIG_IPSEC_AUTH_HMAC_SHA1
				case AH_SHA:
					authlen = AHHMAC_HASHLEN;
					break;
#endif /* CONFIG_IPSEC_AUTH_HMAC_SHA1 */
				case AH_NONE:
					break;
				default:
					spin_unlock(&tdb_lock);
					stats->tx_errors++;
					goto cleanup;
				}		
				tailroom += ((blocksize - ((pyldsz + 2 * sizeof(unsigned char)) % blocksize)) % blocksize) + 2;
				tailroom += authlen;
				break;
#endif /* !CONFIG_IPSEC_ESP */
#ifdef CONFIG_IPSEC_IPIP
			case IPPROTO_IPIP:
				headroom += sizeof(struct iphdr);
				break;
#endif /* !CONFIG_IPSEC_IPIP */
#ifdef CONFIG_IPSEC_IPCOMP
			case IPPROTO_COMP:
				break;
#endif /* CONFIG_IPSEC_IPCOMP */
			default:
				spin_unlock(&tdb_lock);
				stats->tx_errors++;
				goto cleanup;
			}
			
			KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
				    "klips_debug:ipsec_tunnel_start_xmit: "
				    "pushing %d bytes, putting %d, proto %d.\n", 
				    headroom, tailroom, tdbp->tdb_said.proto);
			if(skb_headroom(skb) < headroom) {
				spin_unlock(&tdb_lock);
				printk(KERN_WARNING
				       "klips_error:ipsec_tunnel_start_xmit: "
				       "tried to skb_push headroom=%d, %d available.  This should never happen, please report.\n",
				       headroom, skb_headroom(skb));
				stats->tx_errors++;
				goto cleanup;
			}
			dat = skb_push(skb, headroom);
			ilen = skb->len - tailroom;
			if(skb_tailroom(skb) < tailroom) {
				spin_unlock(&tdb_lock);
				printk(KERN_WARNING
				       "klips_error:ipsec_tunnel_start_xmit: "
				       "tried to skb_put %d, %d available.  This should never happen, please report.\n",
				       tailroom, skb_tailroom(skb));
				stats->tx_errors++;
				goto cleanup;
			}
			skb_put(skb, tailroom);
			KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
				    "klips_debug:ipsec_tunnel_start_xmit: "
				    "head,tailroom: %d,%d before xform.\n",
				    skb_headroom(skb), skb_tailroom(skb));
			len = skb->len;
			if(len > 0xfff0) {
				spin_unlock(&tdb_lock);
				printk(KERN_WARNING "klips_error:ipsec_tunnel_start_xmit: "
				       "tot_len (%d) > 65520.  This should never happen, please report.\n",
				       len);
				stats->tx_errors++;
				goto cleanup;
			}
			memmove((void *)dat, (void *)(dat + headroom), iphlen);
			iph = (struct iphdr *)dat;
			iph->tot_len = htons(skb->len);
			
			switch(tdbp->tdb_said.proto) {
#ifdef CONFIG_IPSEC_ESP
			case IPPROTO_ESP:
				espp = (struct esp *)(dat + iphlen);
				espp->esp_spi = tdbp->tdb_said.spi;
				espp->esp_rpl = htonl(++(tdbp->tdb_replaywin_lastseq));
				
#ifdef CONFIG_IPSEC_ALG
				if (!ixt_e)
#endif /* CONFIG_IPSEC_ALG */
				switch(tdbp->tdb_encalg) {
#if defined(CONFIG_IPSEC_ENC_DES) || defined(CONFIG_IPSEC_ENC_3DES)
#ifdef CONFIG_IPSEC_ENC_DES
				case ESP_DES:
#endif /* CONFIG_IPSEC_ENC_DES */
#ifdef CONFIG_IPSEC_ENC_3DES
				case ESP_3DES:
#endif /* CONFIG_IPSEC_ENC_3DES */
					iv[0] = *((__u32*)&(espp->esp_iv)    ) =
						((__u32*)(tdbp->tdb_iv))[0];
					iv[1] = *((__u32*)&(espp->esp_iv) + 1) =
						((__u32*)(tdbp->tdb_iv))[1];
					break;
#endif /* defined(CONFIG_IPSEC_ENC_DES) || defined(CONFIG_IPSEC_ENC_3DES) */
#ifdef CONFIG_IPSEC_ENC_NULL
				case ESP_NULL:
					break;
#endif /* CONFIG_IPSEC_ENC_NULL */
				default:
					spin_unlock(&tdb_lock);
					stats->tx_errors++;
					goto cleanup;
				}
				
				idat = dat + iphlen + headroom;
				ilen = len - (iphlen + headroom + authlen);
				
				/* Self-describing padding */
				pad = &dat[len - tailroom];
				padlen = tailroom - 2 - authlen;
				for (i = 0; i < padlen; i++) {
					pad[i] = i + 1; 
				}
				dat[len - authlen - 2] = padlen;
				
				dat[len - authlen - 1] = iph->protocol;
				iph->protocol = IPPROTO_ESP;
				
#ifdef CONFIG_IPSEC_ALG
				/* Do all operations here:
				 * copy IV->ESP, encrypt, update ips IV
				 */
				if (ixt_e) {
					int ret;
					memcpy(espp->esp_iv, 
						tdbp->ips_iv, 
						ixt_e->ixt_blocksize);
					ret=ipsec_alg_esp_encrypt(tdbp, 
						idat, ilen, espp->esp_iv,
						IPSEC_ALG_ENCRYPT);
					memcpy(tdbp->ips_iv,
						idat + ilen - ixt_e->ixt_blocksize,
						ixt_e->ixt_blocksize);
				} else
#endif /* CONFIG_IPSEC_ALG */
				switch(tdbp->tdb_encalg) {
#ifdef CONFIG_IPSEC_ENC_DES
				case ESP_DES:
					des_cbc_encrypt(idat, idat, ilen,
							(caddr_t)tdbp->tdb_key_e,
							(caddr_t)iv, 1);
					break;
#endif /* CONFIG_IPSEC_ENC_DES */
#ifdef CONFIG_IPSEC_ENC_3DES
				case ESP_3DES:
					des_ede3_cbc_encrypt((des_cblock *)idat,
							     (des_cblock *)idat,
							     ilen,
							     ((struct des_eks *)(tdbp->tdb_key_e))[0].ks,
							     ((struct des_eks *)(tdbp->tdb_key_e))[1].ks,
							     ((struct des_eks *)(tdbp->tdb_key_e))[2].ks,
							     (des_cblock *)iv, 1);
					break;
#endif /* CONFIG_IPSEC_ENC_3DES */
				default:
					spin_unlock(&tdb_lock);
					stats->tx_errors++;
					goto cleanup;
				}
#ifdef CONFIG_IPSEC_ALG
				if (!ixt_e)
#endif /* CONFIG_IPSEC_ALG */
				
				switch(tdbp->tdb_encalg) {
#if defined(CONFIG_IPSEC_ENC_DES) || defined(CONFIG_IPSEC_ENC_3DES)
#ifdef CONFIG_IPSEC_ENC_DES
				case ESP_DES:
#endif /* CONFIG_IPSEC_ENC_DES */
#ifdef CONFIG_IPSEC_ENC_3DES
				case ESP_3DES:
#endif /* CONFIG_IPSEC_ENC_3DES */
					/* XXX update IV with the last 8 octets of the encryption */
					((__u32*)(tdbp->tdb_iv))[0] =
						((__u32 *)(idat))[(ilen >> 2) - 2];
					((__u32*)(tdbp->tdb_iv))[1] =
						((__u32 *)(idat))[(ilen >> 2) - 1];
					break;
#endif /* defined(CONFIG_IPSEC_ENC_DES) || defined(CONFIG_IPSEC_ENC_3DES) */
#ifdef CONFIG_IPSEC_ENC_NULL
				case ESP_NULL:
					break;
#endif /* CONFIG_IPSEC_ENC_NULL */
				default:
					spin_unlock(&tdb_lock);
					stats->tx_errors++;
					goto cleanup;
				}
#ifdef CONFIG_IPSEC_ALG
				if (ixt_a) {
					ipsec_alg_sa_esp_hash(tdbp,
					(caddr_t)espp, len - iphlen - authlen,
					&(dat[len - authlen]), authlen);

				} else
#endif /* CONFIG_IPSEC_ALG */
				
				switch(tdbp->tdb_authalg) {
#ifdef CONFIG_IPSEC_AUTH_HMAC_MD5
				case AH_MD5:
					dmp("espp", (char*)espp, len - iphlen - authlen);
					tctx.md5 = ((struct md5_ctx*)(tdbp->tdb_key_a))->ictx;
					dmp("ictx", (char*)&tctx.md5, sizeof(tctx.md5));
					MD5Update(&tctx.md5, (caddr_t)espp, len - iphlen - authlen);
					dmp("ictx+dat", (char*)&tctx.md5, sizeof(tctx.md5));
					MD5Final(hash, &tctx.md5);
					dmp("ictx hash", (char*)&hash, sizeof(hash));
					tctx.md5 = ((struct md5_ctx*)(tdbp->tdb_key_a))->octx;
					dmp("octx", (char*)&tctx.md5, sizeof(tctx.md5));
					MD5Update(&tctx.md5, hash, AHMD596_ALEN);
					dmp("octx+hash", (char*)&tctx.md5, sizeof(tctx.md5));
					MD5Final(hash, &tctx.md5);
					dmp("octx hash", (char*)&hash, sizeof(hash));
					memcpy(&(dat[len - authlen]), hash, authlen);

					/* paranoid */
					memset((caddr_t)&tctx.md5, 0, sizeof(tctx.md5));
					memset((caddr_t)hash, 0, sizeof(*hash));
					break;
#endif /* CONFIG_IPSEC_AUTH_HMAC_MD5 */
#ifdef CONFIG_IPSEC_AUTH_HMAC_SHA1
				case AH_SHA:
					tctx.sha1 = ((struct sha1_ctx*)(tdbp->tdb_key_a))->ictx;
					SHA1Update(&tctx.sha1, (caddr_t)espp, len - iphlen - authlen);
					SHA1Final(hash, &tctx.sha1);
					tctx.sha1 = ((struct sha1_ctx*)(tdbp->tdb_key_a))->octx;
					SHA1Update(&tctx.sha1, hash, AHSHA196_ALEN);
					SHA1Final(hash, &tctx.sha1);
					memcpy(&(dat[len - authlen]), hash, authlen);
					
					/* paranoid */
					memset((caddr_t)&tctx.sha1, 0, sizeof(tctx.sha1));
					memset((caddr_t)hash, 0, sizeof(*hash));
					break;
#endif /* CONFIG_IPSEC_AUTH_HMAC_SHA1 */
				case AH_NONE:
					break;
				default:
					spin_unlock(&tdb_lock);
					stats->tx_errors++;
					goto cleanup;
				}
#ifdef NET_21
				skb->h.raw = (unsigned char*)espp;
#endif /* NET_21 */
				break;
#endif /* !CONFIG_IPSEC_ESP */
#ifdef CONFIG_IPSEC_AH
			case IPPROTO_AH:
				ahp = (struct ah *)(dat + iphlen);
				ahp->ah_spi = tdbp->tdb_said.spi;
				ahp->ah_rpl = htonl(++(tdbp->tdb_replaywin_lastseq));
				ahp->ah_rv = 0;
				ahp->ah_nh = iph->protocol;
				ahp->ah_hl = (headroom >> 2) - sizeof(__u64)/sizeof(__u32);
				iph->protocol = IPPROTO_AH;
				dmp("ahp", (char*)ahp, sizeof(*ahp));
				
				ipo = *iph;
				ipo.tos = 0;
				ipo.frag_off = 0;
				ipo.ttl = 0;
				ipo.check = 0;
				dmp("ipo", (char*)&ipo, sizeof(ipo));
				
				switch(tdbp->tdb_authalg) {
#ifdef CONFIG_IPSEC_AUTH_HMAC_MD5
				case AH_MD5:
					tctx.md5 = ((struct md5_ctx*)(tdbp->tdb_key_a))->ictx;
					dmp("ictx", (char*)&tctx.md5, sizeof(tctx.md5));
					MD5Update(&tctx.md5, (unsigned char *)&ipo, sizeof (struct iphdr));
					dmp("ictx+ipo", (char*)&tctx.md5, sizeof(tctx.md5));
					MD5Update(&tctx.md5, (unsigned char *)ahp, headroom - sizeof(ahp->ah_data));
					dmp("ictx+ahp", (char*)&tctx.md5, sizeof(tctx.md5));
					MD5Update(&tctx.md5, (unsigned char *)zeroes, AHHMAC_HASHLEN);
					dmp("ictx+zeroes", (char*)&tctx.md5, sizeof(tctx.md5));
					MD5Update(&tctx.md5,  dat + iphlen + headroom, len - iphlen - headroom);
					dmp("ictx+dat", (char*)&tctx.md5, sizeof(tctx.md5));
					MD5Final(hash, &tctx.md5);
					dmp("ictx hash", (char*)&hash, sizeof(hash));
					tctx.md5 = ((struct md5_ctx*)(tdbp->tdb_key_a))->octx;
					dmp("octx", (char*)&tctx.md5, sizeof(tctx.md5));
					MD5Update(&tctx.md5, hash, AHMD596_ALEN);
					dmp("octx+hash", (char*)&tctx.md5, sizeof(tctx.md5));
					MD5Final(hash, &tctx.md5);
					dmp("octx hash", (char*)&hash, sizeof(hash));
					
					memcpy(ahp->ah_data, hash, AHHMAC_HASHLEN);
					
					/* paranoid */
					memset((caddr_t)&tctx.md5, 0, sizeof(tctx.md5));
					memset((caddr_t)hash, 0, sizeof(hash));
					break;
#endif /* CONFIG_IPSEC_AUTH_HMAC_MD5 */
#ifdef CONFIG_IPSEC_AUTH_HMAC_SHA1
				case AH_SHA:
					tctx.sha1 = ((struct sha1_ctx*)(tdbp->tdb_key_a))->ictx;
					SHA1Update(&tctx.sha1, (unsigned char *)&ipo, sizeof (struct iphdr));
					SHA1Update(&tctx.sha1, (unsigned char *)ahp, headroom - sizeof(ahp->ah_data));
					SHA1Update(&tctx.sha1, (unsigned char *)zeroes, AHHMAC_HASHLEN);
					SHA1Update(&tctx.sha1,  dat + iphlen + headroom, len - iphlen - headroom);
					SHA1Final(hash, &tctx.sha1);
					tctx.sha1 = ((struct sha1_ctx*)(tdbp->tdb_key_a))->octx;
					SHA1Update(&tctx.sha1, hash, AHSHA196_ALEN);
					SHA1Final(hash, &tctx.sha1);
					
					memcpy(ahp->ah_data, hash, AHHMAC_HASHLEN);
					
					/* paranoid */
					memset((caddr_t)&tctx.sha1, 0, sizeof(tctx.sha1));
					memset((caddr_t)hash, 0, sizeof(hash));
					break;
#endif /* CONFIG_IPSEC_AUTH_HMAC_SHA1 */
				default:
					spin_unlock(&tdb_lock);
					stats->tx_errors++;
					goto cleanup;
				}
#ifdef NET_21
				skb->h.raw = (unsigned char*)ahp;
#endif /* NET_21 */
				break;
#endif /* CONFIG_IPSEC_AH */
#ifdef CONFIG_IPSEC_IPIP
			case IPPROTO_IPIP:
				iph->version  = 4;
				switch(sysctl_ipsec_tos) {
				case 0:
#ifdef NET_21
					iph->tos = skb->nh.iph->tos;
#else /* NET_21 */
					iph->tos = skb->ip_hdr->tos;
#endif /* NET_21 */
					break;
				case 1:
					iph->tos = 0;
					break;
				default:
					break;
				}
#ifdef NET_21
#ifdef NETDEV_23
				iph->ttl      = sysctl_ip_default_ttl;
#else /* NETDEV_23 */
				iph->ttl      = ip_statistics.IpDefaultTTL;
#endif /* NETDEV_23 */
#else /* NET_21 */
				iph->ttl      = 64; /* ip_statistics.IpDefaultTTL; */
#endif /* NET_21 */
				iph->frag_off = 0;
				iph->saddr    = ((struct sockaddr_in*)(tdbp->tdb_addr_s))->sin_addr.s_addr;
				iph->daddr    = ((struct sockaddr_in*)(tdbp->tdb_addr_d))->sin_addr.s_addr;
				iph->protocol = IPPROTO_IPIP;
				iph->ihl      = sizeof(struct iphdr) >> 2 /* 5 */;
#ifdef IP_SELECT_IDENT
				/* XXX use of skb->dst below is a questionable
				   substitute for &rt->u.dst which is only
				   available later-on */
#ifdef IP_SELECT_IDENT_NEW
				ip_select_ident(iph, skb->dst, NULL);
#else /* IP_SELECT_IDENT_NEW */
                                ip_select_ident(iph, skb->dst);
#endif /* IP_SELECT_IDENT_NEW */
#else /* IP_SELECT_IDENT */
				iph->id       = htons(ip_id_count++);   /* Race condition here? */
#endif /* IP_SELECT_IDENT */

				newdst = (__u32)iph->daddr;
				newsrc = (__u32)iph->saddr;
		
#ifdef NET_21
				skb->h.ipiph = skb->nh.iph;
#endif /* NET_21 */
				break;
#endif /* !CONFIG_IPSEC_IPIP */
#ifdef CONFIG_IPSEC_IPCOMP
			case IPPROTO_COMP:
				{
					unsigned int flags = 0;
#ifdef CONFIG_IPSEC_DEBUG
					unsigned int old_tot_len = ntohs(iph->tot_len);
#endif /* CONFIG_IPSEC_DEBUG */
					tdbp->tdb_comp_ratio_dbytes += ntohs(iph->tot_len);

					skb = skb_compress(skb, tdbp, &flags);

#ifdef NET_21
					iph = skb->nh.iph;
#else /* NET_21 */
					iph = skb->ip_hdr;
#endif /* NET_21 */

					tdbp->tdb_comp_ratio_cbytes += ntohs(iph->tot_len);

#ifdef CONFIG_IPSEC_DEBUG
					if (debug_tunnel & DB_TN_CROUT)
					{
						if (old_tot_len > ntohs(iph->tot_len))
							KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
								    "klips_debug:ipsec_tunnel_start_xmit: "
								    "packet shrunk from %d to %d bytes after compression, cpi=%04x (should be from spi=%08x, spi&0xffff=%04x.\n",
								    old_tot_len, ntohs(iph->tot_len),
								    ntohs(((struct ipcomphdr*)(((char*)iph) + ((iph->ihl) << 2)))->ipcomp_cpi),
								    ntohl(tdbp->tdb_said.spi),
								    (__u16)(ntohl(tdbp->tdb_said.spi) & 0x0000ffff));
						else
							KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
								    "klips_debug:ipsec_tunnel_start_xmit: "
								    "packet did not compress (flags = %d).\n",
								    flags);
					}
#endif /* CONFIG_IPSEC_DEBUG */
				}
				break;
#endif /* CONFIG_IPSEC_IPCOMP */
			default:
				spin_unlock(&tdb_lock);
				stats->tx_errors++;
				goto cleanup;
			}
			
#ifdef NET_21
			skb->nh.raw = skb->data;
#else /* NET_21 */
			skb->ip_hdr = skb->h.iph = (struct iphdr *) skb->data;
#endif /* NET_21 */
			iph->check = 0;
			iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
			
			KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
				    "klips_debug:ipsec_tunnel_start_xmit: "
				    "after <%s%s%s>, SA:%s:\n",
				    IPS_XFORM_NAME(tdbp),
				    sa_len ? sa : " (error)");
			KLIPS_IP_PRINT(debug_tunnel & DB_TN_XMIT, iph);
 			
			tdbp->ips_life.ipl_bytes.ipl_count += len;
			tdbp->ips_life.ipl_bytes.ipl_last = len;

			if(!tdbp->ips_life.ipl_usetime.ipl_count) {
				tdbp->ips_life.ipl_usetime.ipl_count = jiffies / HZ;
			}
			tdbp->ips_life.ipl_usetime.ipl_last = jiffies / HZ;
			tdbp->ips_life.ipl_packets.ipl_count++; 

			tdbprev = tdbp;
			tdbp = tdbp->ips_onext;
#ifdef CONFIG_IPSEC_ALG
			ixt_e = NULL;	/* invalidate ipsec_alg */
			ixt_a = NULL;
#endif /* CONFIG_IPSEC_ALG */
			
		}
		/* end encapsulation loop here XXX */

		spin_unlock(&tdb_lock);

		matcher.sen_ip_src.s_addr = iph->saddr;
		matcher.sen_ip_dst.s_addr = iph->daddr;
		spin_lock(&eroute_lock);
		er = ipsec_findroute(&matcher);
		if(er) {
			outgoing_said = er->er_said;
			eroute_pid = er->er_pid;
			er->er_count++;
			er->er_lasttime = jiffies/HZ;
		}
		spin_unlock(&eroute_lock);
		KLIPS_PRINT((debug_tunnel & DB_TN_XMIT) &&
			    /* ((orgdst != newdst) || (orgsrc != newsrc)) */
			    (orgedst != outgoing_said.dst.s_addr) &&
			    outgoing_said.dst.s_addr &&
			    er,
			    "klips_debug:ipsec_tunnel_start_xmit: "
			    "We are recursing here.\n");
	} while(/*((orgdst != newdst) || (orgsrc != newsrc))*/
		(orgedst != outgoing_said.dst.s_addr) &&
		outgoing_said.dst.s_addr &&
		er);
	
	KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
		    "klips_debug:ipsec_tunnel_start_xmit: "
		    "After recursive xforms -- head,tailroom: %d,%d\n",
		    skb_headroom(skb), skb_tailroom(skb));

	if(saved_header) {
		if(skb_headroom(skb) < hard_header_len) {
			printk(KERN_WARNING
			       "klips_error:ipsec_tunnel_start_xmit: "
			       "tried to skb_push hhlen=%d, %d available.  This should never happen, please report.\n",
			       hard_header_len, skb_headroom(skb));
			stats->tx_errors++;
			goto cleanup;
		}
		skb_push(skb, hard_header_len);
		for (i = 0; i < hard_header_len; i++) {
			skb->data[i] = saved_header[i];
		}
	}
#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	if (natt_type && natt_head) {
		struct iphdr *ipp = skb->nh.iph;
		struct udphdr *udp;
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			"klips_debug:ipsec_tunnel_start_xmit: "
			"encapsuling packet into UDP (NAT-Traversal)\n");
		iphlen = ipp->ihl << 2;
		ipp->tot_len =
			htons(ntohs(ipp->tot_len) + natt_head);
		if(skb_tailroom(skb) < natt_head) {
			printk(KERN_WARNING "klips_error:ipsec_tunnel_start_xmit: "
				"tried to skb_put %d, %d available. "
				"This should never happen, please report.\n",
				natt_head,
				skb_tailroom(skb));
			stats->tx_errors++;
			goto cleanup;
		}
		skb_put(skb, natt_head);
		udp = (struct udphdr *)((char *)ipp + iphlen);
		/* move ESP hdr after UDP hdr */
		memmove((void *)((char *)udp + natt_head),
			(void *)(udp),
			ntohs(ipp->tot_len) - iphlen - natt_head);
		/* clear UDP & Non-IKE Markers (if any) */
		memset(udp, 0, natt_head);
		/* fill UDP with usefull informations ;-) */
		udp->source = htons(natt_sport);
		udp->dest = htons(natt_dport);
		udp->len = htons(ntohs(ipp->tot_len) - iphlen);
		/* set protocol */
		ipp->protocol = IPPROTO_UDP;
		/* fix IP checksum */
		ipp->check = 0;
		ipp->check = ip_fast_csum((unsigned char *)ipp, ipp->ihl);
	}
#endif
 bypass:
	KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
		    "klips_debug:ipsec_tunnel_start_xmit: "
		    "With hard_header, final head,tailroom: %d,%d\n",
		    skb_headroom(skb), skb_tailroom(skb));

#ifdef NET_21	/* 2.2 and 2.4 kernels */
	/* new route/dst cache code from James Morris */
	skb->dev = physdev;
	/*skb_orphan(skb);*/
	if((error = ip_route_output(&rt,
				    skb->nh.iph->daddr,
				    pass ? 0 : skb->nh.iph->saddr,
				    RT_TOS(skb->nh.iph->tos),
				    physdev->iflink /* rgb: should this be 0? */))) {
		stats->tx_errors++;
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_debug:ipsec_tunnel_start_xmit: "
			    "ip_route_output failed with error code %d, rt->u.dst.dev=%s, dropped\n",
			    error,
			    rt->u.dst.dev->name);
		goto cleanup;
	}
	if(dev == rt->u.dst.dev) {
		ip_rt_put(rt);
		/* This is recursion, drop it. */
		stats->tx_errors++;
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_debug:ipsec_tunnel_start_xmit: "
			    "suspect recursion, dev=rt->u.dst.dev=%s, dropped\n", dev->name);
		goto cleanup;
	}
	dst_release(skb->dst);
	skb->dst = &rt->u.dst;
	stats->tx_bytes += skb->len;
	if(skb->len < skb->nh.raw - skb->data) {
		stats->tx_errors++;
		printk(KERN_WARNING
		       "klips_error:ipsec_tunnel_start_xmit: "
		       "tried to __skb_pull nh-data=%d, %d available.  This should never happen, please report.\n",
		       skb->nh.raw - skb->data, skb->len);
		goto cleanup;
	}
	__skb_pull(skb, skb->nh.raw - skb->data);
#ifdef SKB_RESET_NFCT
	nf_conntrack_put(skb->nfct);
	skb->nfct = NULL;
#ifdef CONFIG_NETFILTER_DEBUG
	skb->nf_debug = 0;
#endif /* CONFIG_NETFILTER_DEBUG */
#if defined(CONFIG_BRIDGE) || defined(CONFIG_BRIDGE_MODULE)
	nf_bridge_put(skb->nf_bridge);
	skb->nf_bridge = NULL;
#endif
#endif /* SKB_RESET_NFCT */
	KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
		    "klips_debug:ipsec_tunnel_start_xmit: "
		    "...done, calling ip_send() on device:%s\n",
		    skb->dev ? skb->dev->name : "NULL");
	KLIPS_IP_PRINT(debug_tunnel & DB_TN_XMIT, skb->nh.iph);
#ifdef NETDEV_23	/* 2.4 kernels */
	{
		int err;

		err = NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skb, NULL, rt->u.dst.dev,
			      ipsec_tunnel_xmit2);
		if(err != NET_XMIT_SUCCESS && err != NET_XMIT_CN) {
			if(net_ratelimit())
				printk(KERN_ERR
				       "klips_error:ipsec_tunnel_start_xmit: "
				       "ip_send() failed, err=%d\n", 
				       -err);
			stats->tx_errors++;
			stats->tx_aborted_errors++;
			skb = NULL;
			goto cleanup;
		}
	}
#else /* NETDEV_23 */	/* 2.2 kernels */
	ip_send(skb);
#endif /* NETDEV_23 */
#else /* NET_21 */	/* 2.0 kernels */
	skb->arp = 1;
	/* ISDN/ASYNC PPP from Matjaz Godec. */
	/*	skb->protocol = htons(ETH_P_IP); */
	KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
		    "klips_debug:ipsec_tunnel_start_xmit: "
		    "...done, calling dev_queue_xmit() or ip_fragment().\n");
	IP_SEND(skb, physdev);
#endif /* NET_21 */
	stats->tx_packets++;

	skb = NULL;
 cleanup:
#if defined(HAS_NETIF_QUEUE) || defined (HAVE_NETIF_QUEUE)
	netif_wake_queue(dev);
#else /* defined(HAS_NETIF_QUEUE) || defined (HAVE_NETIF_QUEUE) */
	dev->tbusy = 0;
#endif /* defined(HAS_NETIF_QUEUE) || defined (HAVE_NETIF_QUEUE) */
	if(saved_header) {
		kfree(saved_header);
	}
	if(skb) {
		dev_kfree_skb(skb, FREE_WRITE);
	}
	if(oskb) {
		dev_kfree_skb(oskb, FREE_WRITE);
	}
	if (tdb.tdb_ident_s.data) {
		kfree(tdb.tdb_ident_s.data);
	}
	if (tdb.tdb_ident_d.data) {
		kfree(tdb.tdb_ident_d.data);
	}
	return 0;
}

DEBUG_NO_STATIC struct net_device_stats *
ipsec_tunnel_get_stats(struct device *dev)
{
	return &(((struct ipsecpriv *)(dev->priv))->mystats);
}

/*
 * Revectored calls.
 * For each of these calls, a field exists in our private structure.
 */

DEBUG_NO_STATIC int
ipsec_tunnel_hard_header(struct sk_buff *skb, struct device *dev,
	unsigned short type, void *daddr, void *saddr, unsigned len)
{
	struct ipsecpriv *prv = dev->priv;
	struct device *tmp;
	int ret;
	struct net_device_stats *stats;	/* This device's statistics */
	
	if(skb == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_hard_header: "
			    "no skb...\n");
		return -ENODATA;
	}

	if(dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_hard_header: "
			    "no device...\n");
		return -ENODEV;
	}

	KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
		    "klips_debug:ipsec_tunnel_hard_header: "
		    "skb->dev=%s dev=%s.\n",
		    skb->dev ? skb->dev->name : "NULL",
		    dev->name);
	
	if(prv == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_hard_header: "
			    "no private space associated with dev=%s\n",
			    dev->name ? dev->name : "NULL");
		return -ENODEV;
	}

	stats = (struct net_device_stats *) &(prv->mystats);

	if(prv->dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_hard_header: "
			    "no physical device associated with dev=%s\n",
			    dev->name ? dev->name : "NULL");
		stats->tx_dropped++;
		return -ENODEV;
	}

	/* check if we have to send a IPv6 packet. It might be a Router
	   Solicitation, where the building of the packet happens in
	   reverse order:
	   1. ll hdr,
	   2. IPv6 hdr,
	   3. ICMPv6 hdr
	   -> skb->nh.raw is still uninitialized when this function is
	   called!!  If this is no IPv6 packet, we can print debugging
	   messages, otherwise we skip all debugging messages and just
	   build the ll header */
	if(type != ETH_P_IPV6) {
		/* execute this only, if we don't have to build the
		   header for a IPv6 packet */
		if(!prv->hard_header) {
			KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
				    "klips_debug:ipsec_tunnel_hard_header: "
				    "physical device has been detached, packet dropped 0x%p->0x%p len=%d type=%d dev=%s->NULL ",
				    saddr,
				    daddr,
				    len,
				    type,
				    dev->name);
#ifdef NET_21
			KLIPS_PRINTMORE(debug_tunnel & DB_TN_REVEC,
					"ip=%08x->%08x\n",
					(__u32)ntohl(skb->nh.iph->saddr),
					(__u32)ntohl(skb->nh.iph->daddr) );
#else /* NET_21 */
			KLIPS_PRINTMORE(debug_tunnel & DB_TN_REVEC,
					"ip=%08x->%08x\n",
					(__u32)ntohl(skb->ip_hdr->saddr),
					(__u32)ntohl(skb->ip_hdr->daddr) );
#endif /* NET_21 */
			stats->tx_dropped++;
			return -ENODEV;
		}
		
#define da ((struct device *)(prv->dev))->dev_addr
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_hard_header: "
			    "Revectored 0x%p->0x%p len=%d type=%d dev=%s->%s dev_addr=%02x:%02x:%02x:%02x:%02x:%02x ",
			    saddr,
			    daddr,
			    len,
			    type,
			    dev->name,
			    prv->dev->name,
			    da[0], da[1], da[2], da[3], da[4], da[5]);
#ifdef NET_21
		KLIPS_PRINTMORE(debug_tunnel & DB_TN_REVEC,
			    "ip=%08x->%08x\n",
			    (__u32)ntohl(skb->nh.iph->saddr),
			    (__u32)ntohl(skb->nh.iph->daddr) );
#else /* NET_21 */
		KLIPS_PRINTMORE(debug_tunnel & DB_TN_REVEC,
			    "ip=%08x->%08x\n",
			    (__u32)ntohl(skb->ip_hdr->saddr),
			    (__u32)ntohl(skb->ip_hdr->daddr) );
#endif /* NET_21 */
	} else {
		KLIPS_PRINT(debug_tunnel,
			    "klips_debug:ipsec_tunnel_hard_header: "
			    "is IPv6 packet, skip debugging messages, only revector and build linklocal header.\n");
	}                                                                       
	tmp = skb->dev;
	skb->dev = prv->dev;
	ret = prv->hard_header(skb, prv->dev, type, (void *)daddr, (void *)saddr, len);
	skb->dev = tmp;
	return ret;
}

DEBUG_NO_STATIC int
#ifdef NET_21
ipsec_tunnel_rebuild_header(struct sk_buff *skb)
#else /* NET_21 */
ipsec_tunnel_rebuild_header(void *buff, struct device *dev,
			unsigned long raddr, struct sk_buff *skb)
#endif /* NET_21 */
{
	struct ipsecpriv *prv = skb->dev->priv;
	struct device *tmp;
	int ret;
	struct net_device_stats *stats;	/* This device's statistics */
	
	if(skb->dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_rebuild_header: "
			    "no device...");
		return -ENODEV;
	}

	if(prv == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_rebuild_header: "
			    "no private space associated with dev=%s",
			    skb->dev->name ? skb->dev->name : "NULL");
		return -ENODEV;
	}

	stats = (struct net_device_stats *) &(prv->mystats);

	if(prv->dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_rebuild_header: "
			    "no physical device associated with dev=%s",
			    skb->dev->name ? skb->dev->name : "NULL");
		stats->tx_dropped++;
		return -ENODEV;
	}

	if(!prv->rebuild_header) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_rebuild_header: "
			    "physical device has been detached, packet dropped skb->dev=%s->NULL ",
			    skb->dev->name);
#ifdef NET_21
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "ip=%08x->%08x\n",
			    (__u32)ntohl(skb->nh.iph->saddr),
			    (__u32)ntohl(skb->nh.iph->daddr) );
#else /* NET_21 */
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "ip=%08x->%08x\n",
			    (__u32)ntohl(skb->ip_hdr->saddr),
			    (__u32)ntohl(skb->ip_hdr->daddr) );
#endif /* NET_21 */
		stats->tx_dropped++;
		return -ENODEV;
	}

	KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
		    "klips_debug:ipsec_tunnel: "
		    "Revectored rebuild_header dev=%s->%s ",
		    skb->dev->name, prv->dev->name);
#ifdef NET_21
	KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
		    "ip=%08x->%08x\n",
		    (__u32)ntohl(skb->nh.iph->saddr),
		    (__u32)ntohl(skb->nh.iph->daddr) );
#else /* NET_21 */
	KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
		    "ip=%08x->%08x\n",
		    (__u32)ntohl(skb->ip_hdr->saddr),
		    (__u32)ntohl(skb->ip_hdr->daddr) );
#endif /* NET_21 */
	tmp = skb->dev;
	skb->dev = prv->dev;
	
#ifdef NET_21
	ret = prv->rebuild_header(skb);
#else /* NET_21 */
	ret = prv->rebuild_header(buff, prv->dev, raddr, skb);
#endif /* NET_21 */
	skb->dev = tmp;
	return ret;
}

DEBUG_NO_STATIC int
ipsec_tunnel_set_mac_address(struct device *dev, void *addr)
{
	struct ipsecpriv *prv = dev->priv;
	
	struct net_device_stats *stats;	/* This device's statistics */
	
	if(dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_set_mac_address: "
			    "no device...");
		return -ENODEV;
	}

	if(prv == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_set_mac_address: "
			    "no private space associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		return -ENODEV;
	}

	stats = (struct net_device_stats *) &(prv->mystats);

	if(prv->dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_set_mac_address: "
			    "no physical device associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		stats->tx_dropped++;
		return -ENODEV;
	}

	if(!prv->set_mac_address) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_set_mac_address: "
			    "physical device has been detached, cannot set - skb->dev=%s->NULL\n",
			    dev->name);
		return -ENODEV;
	}

	KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
		    "klips_debug:ipsec_tunnel_set_mac_address: "
		    "Revectored dev=%s->%s addr=%p\n",
		    dev->name, prv->dev->name, addr);
	return prv->set_mac_address(prv->dev, addr);

}

#ifndef NET_21
DEBUG_NO_STATIC void
ipsec_tunnel_cache_bind(struct hh_cache **hhp, struct device *dev,
				 unsigned short htype, __u32 daddr)
{
	struct ipsecpriv *prv = dev->priv;
	
	struct net_device_stats *stats;	/* This device's statistics */
	
	if(dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_cache_bind: "
			    "no device...");
		return;
	}

	if(prv == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_cache_bind: "
			    "no private space associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		return;
	}

	stats = (struct net_device_stats *) &(prv->mystats);

	if(prv->dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_cache_bind: "
			    "no physical device associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		stats->tx_dropped++;
		return;
	}

	if(!prv->header_cache_bind) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_cache_bind: "
			    "physical device has been detached, cannot set - skb->dev=%s->NULL\n",
			    dev->name);
		stats->tx_dropped++;
		return;
	}

	KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
		    "klips_debug:ipsec_tunnel_cache_bind: "
		    "Revectored \n");
	prv->header_cache_bind(hhp, prv->dev, htype, daddr);
	return;
}
#endif /* !NET_21 */


DEBUG_NO_STATIC void
ipsec_tunnel_cache_update(struct hh_cache *hh, struct device *dev, unsigned char *  haddr)
{
	struct ipsecpriv *prv = dev->priv;
	
	struct net_device_stats *stats;	/* This device's statistics */
	
	if(dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_cache_update: "
			    "no device...");
		return;
	}

	if(prv == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_cache_update: "
			    "no private space associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		return;
	}

	stats = (struct net_device_stats *) &(prv->mystats);

	if(prv->dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_cache_update: "
			    "no physical device associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		stats->tx_dropped++;
		return;
	}

	if(!prv->header_cache_update) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_cache_update: "
			    "physical device has been detached, cannot set - skb->dev=%s->NULL\n",
			    dev->name);
		return;
	}

	KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
		    "klips_debug:ipsec_tunnel: "
		    "Revectored cache_update\n");
	prv->header_cache_update(hh, prv->dev, haddr);
	return;
}

#ifdef NET_21
DEBUG_NO_STATIC int
ipsec_tunnel_neigh_setup(struct neighbour *n)
{
	KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
		    "klips_debug:ipsec_tunnel_neigh_setup:\n");

        if (n->nud_state == NUD_NONE) {
                n->ops = &arp_broken_ops;
                n->output = n->ops->output;
        }
        return 0;
}

DEBUG_NO_STATIC int
ipsec_tunnel_neigh_setup_dev(struct device *dev, struct neigh_parms *p)
{
	KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
		    "klips_debug:ipsec_tunnel_neigh_setup_dev: "
		    "setting up %s\n",
		    dev ? dev->name : "NULL");

        if (p->tbl->family == AF_INET) {
                p->neigh_setup = ipsec_tunnel_neigh_setup;
                p->ucast_probes = 0;
                p->mcast_probes = 0;
        }
        return 0;
}
#endif /* NET_21 */

/*
 * We call the attach routine to attach another device.
 */

DEBUG_NO_STATIC int
ipsec_tunnel_attach(struct device *dev, struct device *physdev)
{
        int i;
	struct ipsecpriv *prv = dev->priv;

	if(dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_attach: "
			    "no device...");
		return -ENODEV;
	}

	if(prv == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_attach: "
			    "no private space associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		return -ENODATA;
	}

	prv->dev = physdev;
	prv->hard_start_xmit = physdev->hard_start_xmit;
	prv->get_stats = physdev->get_stats;

	if (physdev->hard_header) {
		prv->hard_header = physdev->hard_header;
		dev->hard_header = ipsec_tunnel_hard_header;
	} else
		dev->hard_header = NULL;
	
	if (physdev->rebuild_header) {
		prv->rebuild_header = physdev->rebuild_header;
		dev->rebuild_header = ipsec_tunnel_rebuild_header;
	} else
		dev->rebuild_header = NULL;
	
	if (physdev->set_mac_address) {
		prv->set_mac_address = physdev->set_mac_address;
		dev->set_mac_address = ipsec_tunnel_set_mac_address;
	} else
		dev->set_mac_address = NULL;
	
#ifndef NET_21
	if (physdev->header_cache_bind) {
		prv->header_cache_bind = physdev->header_cache_bind;
		dev->header_cache_bind = ipsec_tunnel_cache_bind;
	} else
		dev->header_cache_bind = NULL;
#endif /* !NET_21 */

	if (physdev->header_cache_update) {
		prv->header_cache_update = physdev->header_cache_update;
		dev->header_cache_update = ipsec_tunnel_cache_update;
	} else
		dev->header_cache_update = NULL;

	dev->hard_header_len = physdev->hard_header_len;

#ifdef NET_21
/*	prv->neigh_setup        = physdev->neigh_setup; */
	dev->neigh_setup        = ipsec_tunnel_neigh_setup_dev;
#endif /* NET_21 */
	dev->mtu = 16260; /* 0xfff0; */ /* dev->mtu; */
	prv->mtu = physdev->mtu;

#ifdef PHYSDEV_TYPE
	dev->type = physdev->type /* ARPHRD_TUNNEL */;	/* initially */
#endif /*  PHYSDEV_TYPE */

	dev->addr_len = physdev->addr_len;
	for (i=0; i<dev->addr_len; i++) {
		dev->dev_addr[i] = physdev->dev_addr[i];
	}
#ifdef CONFIG_IPSEC_DEBUG
	if(debug_tunnel & DB_TN_INIT) {
		printk(KERN_INFO "klips_debug:ipsec_tunnel_attach: "
		       "physical device %s being attached has HW address: %2x",
		       physdev->name, physdev->dev_addr[0]);
		for (i=1; i < physdev->addr_len; i++) {
			printk(":%02x", physdev->dev_addr[i]);
		}
		printk("\n");
	}
#endif /* CONFIG_IPSEC_DEBUG */

	return 0;
}

/*
 * We call the detach routine to detach the ipsec tunnel from another device.
 */

DEBUG_NO_STATIC int
ipsec_tunnel_detach(struct device *dev)
{
        int i;
	struct ipsecpriv *prv = dev->priv;

	if(dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_detach: "
			    "no device...");
		return -ENODEV;
	}

	if(prv == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_detach: "
			    "no private space associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		return -ENODATA;
	}

	KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
		    "klips_debug:ipsec_tunnel_detach: "
		    "physical device %s being detached from virtual device %s\n",
		    prv->dev ? prv->dev->name : "NULL",
		    dev->name);

	prv->dev = NULL;
	prv->hard_start_xmit = NULL;
	prv->get_stats = NULL;

	prv->hard_header = NULL;
#ifdef DETACH_AND_DOWN
	dev->hard_header = NULL;
#endif /* DETACH_AND_DOWN */
	
	prv->rebuild_header = NULL;
#ifdef DETACH_AND_DOWN
	dev->rebuild_header = NULL;
#endif /* DETACH_AND_DOWN */
	
	prv->set_mac_address = NULL;
#ifdef DETACH_AND_DOWN
	dev->set_mac_address = NULL;
#endif /* DETACH_AND_DOWN */
	
#ifndef NET_21
	prv->header_cache_bind = NULL;
#ifdef DETACH_AND_DOWN
	dev->header_cache_bind = NULL;
#endif /* DETACH_AND_DOWN */
#endif /* !NET_21 */

	prv->header_cache_update = NULL;
#ifdef DETACH_AND_DOWN
	dev->header_cache_update = NULL;
#endif /* DETACH_AND_DOWN */

#ifdef NET_21
/*	prv->neigh_setup        = NULL; */
#ifdef DETACH_AND_DOWN
	dev->neigh_setup        = NULL;
#endif /* DETACH_AND_DOWN */
#endif /* NET_21 */
	dev->hard_header_len = 0;
#ifdef DETACH_AND_DOWN
	dev->mtu = 0;
#endif /* DETACH_AND_DOWN */
	prv->mtu = 0;
	for (i=0; i<MAX_ADDR_LEN; i++) {
		dev->dev_addr[i] = 0;
	}
	dev->addr_len = 0;
#ifdef PHYSDEV_TYPE
	dev->type = ARPHRD_TUNNEL;
#endif /*  PHYSDEV_TYPE */
	
	return 0;
}

/*
 * We call the clear routine to detach all ipsec tunnels from other devices.
 */
DEBUG_NO_STATIC int
ipsec_tunnel_clear(void)
{
	int i;
	struct device *ipsecdev = NULL, *prvdev;
	struct ipsecpriv *prv;
	char name[9];
	int ret;

	KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
		    "klips_debug:ipsec_tunnel_clear: .\n");

	for(i = 0; i < IPSEC_NUM_IF; i++) {
		sprintf(name, "ipsec%d", i);
		if((ipsecdev = ipsec_dev_get(name)) != NULL) {
			if((prv = (struct ipsecpriv *)(ipsecdev->priv))) {
				prvdev = (struct device *)(prv->dev);
				if(prvdev) {
					KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
						    "klips_debug:ipsec_tunnel_clear: "
						    "physical device for device %s is %s\n",
						    name, prvdev->name);
					if((ret = ipsec_tunnel_detach(ipsecdev))) {
						KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
							    "klips_debug:ipsec_tunnel_clear: "
							    "error %d detatching device %s from device %s.\n",
							    ret, name, prvdev->name);
						return ret;
					}
				}
			}
		}
	}
	return 0;
}

DEBUG_NO_STATIC int
ipsec_tunnel_ioctl(struct device *dev, struct ifreq *ifr, int cmd)
{
	struct ipsectunnelconf *cf = (struct ipsectunnelconf *)&ifr->ifr_data;
	struct ipsecpriv *prv = dev->priv;
	struct device *them; /* physical device */
#if defined(NET_21) && defined(CONFIG_IP_ALIAS)
	char *colon;
	char realphysname[IFNAMSIZ];
#endif /* NET_21 && CONFIG_IP_ALIAS */
	
	if(dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_tunnel_ioctl: "
			    "device not supplied.\n");
		return -ENODEV;
	}

	KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
		    "klips_debug:ipsec_tunnel_ioctl: "
		    "tncfg service call #%d for dev=%s\n",
		    cmd,
		    dev->name ? dev->name : "NULL");
	switch (cmd) {
	/* attach a virtual ipsec? device to a physical device */
	case IPSEC_SET_DEV:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_tunnel_ioctl: "
			    "calling ipsec_tunnel_attatch...\n");
#if defined(NET_21) && defined(CONFIG_IP_ALIAS)
		/* If this is an IP alias interface, get its real physical name */
		strncpy(realphysname, cf->cf_name, IFNAMSIZ);
		realphysname[IFNAMSIZ-1] = 0;
		colon = strchr(realphysname, ':');
		if (colon) *colon = 0;
		them = ipsec_dev_get(realphysname);
#else /* NET_21 && CONFIG_IP_ALIAS */
		them = ipsec_dev_get(cf->cf_name);
#endif /* NET_21 && CONFIG_IP_ALIAS */

		if (them == NULL) {
			KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
				    "klips_debug:ipsec_tunnel_ioctl: "
				    "physical device %s requested is null\n",
				    cf->cf_name);
			return -ENXIO;
		}
		
#if 0
		if (them->flags & IFF_UP) {
			KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
				    "klips_debug:ipsec_tunnel_ioctl: "
				    "physical device %s requested is not up.\n",
				    cf->cf_name);
			return -ENXIO;
		}
#endif
		
		if (prv && prv->dev) {
			KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
				    "klips_debug:ipsec_tunnel_ioctl: "
				    "virtual device is already connected to %s.\n",
				    prv->dev->name ? prv->dev->name : "NULL");
			return -EBUSY;
		}
		return ipsec_tunnel_attach(dev, them);

	case IPSEC_DEL_DEV:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_tunnel_ioctl: "
			    "calling ipsec_tunnel_detatch.\n");
		if (! prv->dev) {
			KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
				    "klips_debug:ipsec_tunnel_ioctl: "
				    "physical device not connected.\n");
			return -ENODEV;
		}
		return ipsec_tunnel_detach(dev);
	       
	case IPSEC_CLR_DEV:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_tunnel_ioctl: "
			    "calling ipsec_tunnel_clear.\n");
		return ipsec_tunnel_clear();

	default:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_tunnel_ioctl: "
			    "unknown command %d.\n",
			    cmd);
		return -EOPNOTSUPP;
	}
}

int
ipsec_device_event(struct notifier_block *unused, unsigned long event, void *ptr)
{
	struct device *dev = ptr;
	struct device *ipsec_dev;
	struct ipsecpriv *priv;
	char name[9];
	int i;

	if (dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_device_event: "
			    "dev=NULL for event type %ld.\n",
			    event);
		return(NOTIFY_DONE);
	}

	/* check for loopback devices */
	if (dev && (dev->flags & IFF_LOOPBACK)) {
		return(NOTIFY_DONE);
	}

	switch (event) {
	case NETDEV_DOWN:
		/* look very carefully at the scope of these compiler
		   directives before changing anything... -- RGB */
#ifdef NET_21
	case NETDEV_UNREGISTER:
		switch (event) {
		case NETDEV_DOWN:
#endif /* NET_21 */
			KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
				    "klips_debug:ipsec_device_event: "
				    "NETDEV_DOWN dev=%s flags=%x\n",
				    dev->name,
				    dev->flags);
			if(strncmp(dev->name, "ipsec", strlen("ipsec")) == 0) {
				printk(KERN_CRIT "IPSEC EVENT: KLIPS device %s shut down.\n",
				       dev->name);
			}
#ifdef NET_21
			break;
		case NETDEV_UNREGISTER:
			KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
				    "klips_debug:ipsec_device_event: "
				    "NETDEV_UNREGISTER dev=%s flags=%x\n",
				    dev->name,
				    dev->flags);
			break;
		}
#endif /* NET_21 */
		
		/* find the attached physical device and detach it. */
		for(i = 0; i < IPSEC_NUM_IF; i++) {
			sprintf(name, "ipsec%d", i);
			ipsec_dev = ipsec_dev_get(name);
			if(ipsec_dev) {
				priv = (struct ipsecpriv *)(ipsec_dev->priv);
				if(priv) {
					;
					if(((struct device *)(priv->dev)) == dev) {
						/* dev_close(ipsec_dev); */
						/* return */ ipsec_tunnel_detach(ipsec_dev);
						KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
							    "klips_debug:ipsec_device_event: "
							    "device '%s' has been detached.\n",
							    ipsec_dev->name);
						break;
					}
				} else {
					KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
						    "klips_debug:ipsec_device_event: "
						    "device '%s' has no private data space!\n",
						    ipsec_dev->name);
				}
			}
		}
		break;
	case NETDEV_UP:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_device_event: "
			    "NETDEV_UP dev=%s\n",
			    dev->name);
		break;
#ifdef NET_21
	case NETDEV_REBOOT:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_device_event: "
			    "NETDEV_REBOOT dev=%s\n",
			    dev->name);
		break;
	case NETDEV_CHANGE:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_device_event: "
			    "NETDEV_CHANGE dev=%s flags=%x\n",
			    dev->name,
			    dev->flags);
		break;
	case NETDEV_REGISTER:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_device_event: "
			    "NETDEV_REGISTER dev=%s\n",
			    dev->name);
		break;
	case NETDEV_CHANGEMTU:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_device_event: "
			    "NETDEV_CHANGEMTU dev=%s to mtu=%d\n",
			    dev->name,
			    dev->mtu);
		break;
	case NETDEV_CHANGEADDR:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_device_event: "
			    "NETDEV_CHANGEADDR dev=%s\n",
			    dev->name);
		break;
	case NETDEV_GOING_DOWN:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_device_event: "
			    "NETDEV_GOING_DOWN dev=%s\n",
			    dev->name);
		break;
	case NETDEV_CHANGENAME:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_device_event: "
			    "NETDEV_CHANGENAME dev=%s\n",
			    dev->name);
		break;
#endif /* NET_21 */
	default:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_device_event: "
			    "event type %ld unrecognised for dev=%s\n",
			    event,
			    dev->name);
		break;
	}
	return NOTIFY_DONE;
}

/*
 *	Called when an ipsec tunnel device is initialized.
 *	The ipsec tunnel device structure is passed to us.
 */
 
int
ipsec_tunnel_init(struct device *dev)
{
	int i;

#if 0
	printk(KERN_INFO
	       "klips_debug:ipsec_tunnel_init: "
	       "initialisation of device: %s\n",
	       dev->name ? dev->name : "NULL");
#endif

	/* Add our tunnel functions to the device */
	dev->open		= ipsec_tunnel_open;
	dev->stop		= ipsec_tunnel_close;
	dev->hard_start_xmit	= ipsec_tunnel_start_xmit;
	dev->get_stats		= ipsec_tunnel_get_stats;

	dev->priv = kmalloc(sizeof(struct ipsecpriv), GFP_KERNEL);
	if (dev->priv == NULL)
		return -ENOMEM;
	memset(dev->priv, 0, sizeof(struct ipsecpriv));

	for(i = 0; i < sizeof(zeroes); i++) {
		((__u8*)(zeroes))[i] = 0;
	}
	
#ifndef NET_21
	/* Initialize the tunnel device structure */
	for (i = 0; i < DEV_NUMBUFFS; i++)
		skb_queue_head_init(&dev->buffs[i]);
#endif /* !NET_21 */

	dev->set_multicast_list = NULL;
	dev->do_ioctl		= ipsec_tunnel_ioctl;
	dev->hard_header	= NULL;
	dev->rebuild_header 	= NULL;
	dev->set_mac_address 	= NULL;
#ifndef NET_21
	dev->header_cache_bind 	= NULL;
#endif /* !NET_21 */
	dev->header_cache_update= NULL;

#ifdef NET_21
/*	prv->neigh_setup        = NULL; */
	dev->neigh_setup        = ipsec_tunnel_neigh_setup_dev;
#endif /* NET_21 */
	dev->hard_header_len 	= 0;
	dev->mtu		= 0;
	dev->addr_len		= 0;
	dev->type		= ARPHRD_TUNNEL; /* 0 */ /* ARPHRD_ETHER; */ /* initially */
	dev->tx_queue_len	= 10;		/* Small queue */
	memset(dev->broadcast,0xFF, ETH_ALEN);	/* what if this is not attached to ethernet? */

	/* New-style flags. */
	dev->flags		= IFF_NOARP /* 0 */ /* Petr Novak */;
#ifdef NET_21
	dev_init_buffers(dev);
#else /* NET_21 */
	dev->family		= AF_INET;
	dev->pa_addr		= 0;
	dev->pa_brdaddr 	= 0;
	dev->pa_mask		= 0;
	dev->pa_alen		= 4;
#endif /* NET_21 */

	/* We're done.  Have I forgotten anything? */
	return 0;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*  Module specific interface (but it links with the rest of IPSEC  */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

int
ipsec_tunnel_probe(struct device *dev)
{
	ipsec_tunnel_init(dev); 
	return 0;
}

static struct device dev_ipsec3 = 
{
	"ipsec3\0   ",		/* name */
	0,			/* recv memory end */
	0,			/* recv memory start */
	0,			/* memory end */
	0,			/* memory start */
 	0x0,			/* base I/O address */
	0,			/* IRQ */
	0, 0, 0,		/* flags */
	NULL,			/* next device */
	ipsec_tunnel_probe	/* setup */
};

static struct device dev_ipsec2 = 
{
	"ipsec2\0   ",		/* name */
	0,			/* recv memory end */
	0,			/* recv memory start */
	0,			/* memory end */
	0,			/* memory start */
 	0x0,			/* base I/O address */
	0,			/* IRQ */
	0, 0, 0,		/* flags */
	NULL,			/* next device */
	ipsec_tunnel_probe	/* setup */
};

static struct device dev_ipsec1 = 
{
	"ipsec1\0   ",		/* name */
	0,			/* recv memory end */
	0,			/* recv memory start */
	0,			/* memory end */
	0,			/* memory start */
 	0x0,			/* base I/O address */
	0,			/* IRQ */
	0, 0, 0,		/* flags */
	NULL,			/* next device */
	ipsec_tunnel_probe	/* setup */
};

static struct device dev_ipsec0 = 
{
	"ipsec0\0   ",		/* name */
	0,			/* recv memory end */
	0,			/* recv memory start */
	0,			/* memory end */
	0,			/* memory start */
 	0x0,			/* base I/O address */
	0,			/* IRQ */
	0, 0, 0,		/* flags */
	NULL,			/* next device */
	ipsec_tunnel_probe	/* setup */
};

int 
ipsec_tunnel_init_devices(void)
{
#if 0
	KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
		    "klips_debug:ipsec_tunnel_init_devices: "
		    "registering device %s\n",
		    dev_ipsec0.name);
#endif
	if (register_netdev(&dev_ipsec0) != 0)
		return -EIO;
#if 0
	KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
		    "klips_debug:ipsec_tunnel_init_devices: "
		    "registering device %s\n",
		    dev_ipsec1.name);
#endif
	if (register_netdev(&dev_ipsec1) != 0)
		return -EIO;
#if 0
	KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
		    "klips_debug:ipsec_tunnel_init_devices: "
		    "registering device %s\n",
		    dev_ipsec2.name);
#endif
	if (register_netdev(&dev_ipsec2) != 0)
		return -EIO;
#if 0
	KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
		    "klips_debug:ipsec_tunnel_init_devices: "
		    "registering device %s\n",
		    dev_ipsec3.name);
#endif
	if (register_netdev(&dev_ipsec3) != 0)
		return -EIO;
	return 0;
}

/* void */
int
ipsec_tunnel_cleanup_devices(void)
{
	int error = 0;

	unregister_netdev(&dev_ipsec0);
	unregister_netdev(&dev_ipsec1);
	unregister_netdev(&dev_ipsec2);
	unregister_netdev(&dev_ipsec3);
	kfree(dev_ipsec0.priv);
	kfree(dev_ipsec1.priv);
	kfree(dev_ipsec2.priv);
	kfree(dev_ipsec3.priv);
	dev_ipsec0.priv=NULL;
	dev_ipsec1.priv=NULL;
	dev_ipsec2.priv=NULL;
	dev_ipsec3.priv=NULL;

	return error;
}

/*
 * $Log: ipsec_tunnel.c,v $
 * Revision 1.187  2002/03/23 19:55:17  rgb
 * Fix for 2.2 local IKE fragmentation blackhole.  Still won't work if
 * iptraf or another pcap app is running.
 *
 * Revision 1.186  2002/03/19 03:26:22  rgb
 * Applied DHR's tunnel patch to streamline IKE/specialSA processing.
 *
 * Revision 1.185  2002/02/20 04:13:05  rgb
 * Send back ICMP_PKT_FILTERED upon %reject.
 *
 * Revision 1.184  2002/01/29 17:17:56  mcr
 * 	moved include of ipsec_param.h to after include of linux/kernel.h
 * 	otherwise, it seems that some option that is set in ipsec_param.h
 * 	screws up something subtle in the include path to kernel.h, and
 * 	it complains on the snprintf() prototype.
 *
 * Revision 1.183  2002/01/29 04:00:53  mcr
 * 	more excise of kversions.h header.
 *
 * Revision 1.182  2002/01/29 02:13:18  mcr
 * 	introduction of ipsec_kversion.h means that include of
 * 	ipsec_param.h must preceed any decisions about what files to
 * 	include to deal with differences in kernel source.
 *
 * Revision 1.181  2002/01/07 20:00:33  rgb
 * Added IKE destination port debugging.
 *
 * Revision 1.180  2001/12/21 21:49:54  rgb
 * Fixed bug as a result of moving IKE bypass above %trap/%hold code.
 *
 * Revision 1.179  2001/12/19 21:08:14  rgb
 * Added transport protocol ports to ipsec_print_ip().
 * Update eroute info for non-SA targets.
 * Added obey DF code disabled.
 * Fixed formatting bugs in ipsec_tunnel_hard_header().
 *
 * Revision 1.178  2001/12/05 09:36:10  rgb
 * Moved the UDP/500 IKE check just above the %hold/%trap checks to avoid
 * IKE packets being stolen by the %hold (and returned to the sending KMd
 * in an ACQUIRE, ironically  ;-).
 *
 * Revision 1.177  2001/11/26 09:23:50  rgb
 * Merge MCR's ipsec_sa, eroute, proc and struct lifetime changes.
 *
 * Revision 1.170.2.1  2001/09/25 02:28:27  mcr
 * 	struct tdb -> struct ipsec_sa.
 * 	lifetime checks moved to common routines.
 * 	cleaned up includes.
 *
 * Revision 1.170.2.2  2001/10/22 21:08:01  mcr
 * 	include des.h, removed phony prototypes and fixed calling
 * 	conventions to match real prototypes.
 *
 * Revision 1.176  2001/11/09 18:32:31  rgb
 * Added Hans Schultz' fragmented UDP/500 IKE socket port selector.
 *
 * Revision 1.175  2001/11/06 20:47:00  rgb
 * Added Eric Espie's TRAPSUBNET fix, minus spin-lock-bh dabbling.
 *
 * Revision 1.174  2001/11/06 19:50:43  rgb
 * Moved IP_SEND, ICMP_SEND, DEV_QUEUE_XMIT macros to ipsec_tunnel.h for
 * use also by pfkey_v2_parser.c
 *
 * Revision 1.173  2001/10/29 21:53:44  henry
 * tone down the device-down message slightly, until we can make it smarter
 *
 * Revision 1.172  2001/10/26 04:59:37  rgb
 * Added a critical level syslog message if an ipsec device goes down.
 *
 * Revision 1.171  2001/10/18 04:45:21  rgb
 * 2.4.9 kernel deprecates linux/malloc.h in favour of linux/slab.h,
 * lib/freeswan.h version macros moved to lib/kversions.h.
 * Other compiler directive cleanups.
 *
 * Revision 1.170  2001/09/25 00:09:50  rgb
 * Added NetCelo's TRAPSUBNET code to convert a new type TRAPSUBNET into a
 * HOLD.
 *
 * Revision 1.169  2001/09/15 16:24:05  rgb
 * Re-inject first and last HOLD packet when an eroute REPLACE is done.
 *
 * Revision 1.168  2001/09/14 16:58:37  rgb
 * Added support for storing the first and last packets through a HOLD.
 *
 * Revision 1.167  2001/09/08 21:13:33  rgb
 * Added pfkey ident extension support for ISAKMPd. (NetCelo)
 *
 * Revision 1.166  2001/08/27 19:47:59  rgb
 * Clear tdb  before usage.
 * Added comment: clear IF before calling routing?
 *
 * Revision 1.165  2001/07/03 01:23:53  rgb
 * Send back ICMP iff DF set, !ICMP, offset==0, sysctl_icmp, iph->tot_len >
 * emtu, and don't drop.
 *
 * Revision 1.164  2001/06/14 19:35:10  rgb
 * Update copyright date.
 *
 * Revision 1.163  2001/06/06 20:28:51  rgb
 * Added sanity checks for NULL skbs and devices.
 * Added more debugging output to various functions.
 * Removed redundant dev->priv argument to ipsec_tunnel_{at,de}tach().
 * Renamed ipsec_tunnel_attach() virtual and physical device arguments.
 * Corrected neigh_setup() device function assignment.
 * Keep valid pointers to ipsec_tunnel_*() on detach.
 * Set dev->type to the originally-initiallised value.
 *
 * Revision 1.162  2001/06/01 07:28:04  rgb
 * Added sanity checks for detached devices.  Don't down virtual devices
 * to prevent packets going out in the clear if the detached device comes
 * back up.
 *
 * Revision 1.161  2001/05/30 08:14:52  rgb
 * Removed vestiges of esp-null transforms.
 * NetDev Notifier instrumentation to track down disappearing devices.
 *
 * Revision 1.160  2001/05/29 05:15:12  rgb
 * Added SS' PMTU patch which notifies sender if packet doesn't fit
 * physical MTU (if it wasn't ICMP) and then drops it.
 *
 * Revision 1.159  2001/05/27 06:12:12  rgb
 * Added structures for pid, packet count and last access time to eroute.
 * Added packet count to beginning of /proc/net/ipsec_eroute.
 *
 * Revision 1.158  2001/05/24 05:39:33  rgb
 * Applied source zeroing to 2.2 ip_route_output() call as well to enable
 * PASS eroutes for opportunism.
 *
 * Revision 1.157  2001/05/23 22:35:28  rgb
 * 2.4 source override simplification.
 *
 * Revision 1.156  2001/05/23 21:41:31  rgb
 * Added error return code printing on ip_route_output().
 *
 * Revision 1.155  2001/05/23 05:09:13  rgb
 * Fixed incorrect ip_route_output() failure message.
 *
 * Revision 1.154  2001/05/21 14:53:31  rgb
 * Added debug statement for case when ip_route_output() fails, causing
 * packet to be dropped, but log looked ok.
 *
 * Revision 1.153  2001/05/19 02:37:54  rgb
 * Fixed missing comment termination.
 *
 * Revision 1.152  2001/05/19 02:35:50  rgb
 * Debug code optimisation for non-debug speed.
 * Kernel version compiler define comments.
 * 2.2 and 2.4 kernel ip_send device and ip debug output added.
 *
 * Revision 1.151  2001/05/18 16:17:35  rgb
 * Changed reference from "magic" to "shunt" SAs.
 *
 * Revision 1.150  2001/05/18 16:12:19  rgb
 * Changed UDP/500 bypass test from 3 nested ifs to one anded if.
 *
 * Revision 1.149  2001/05/16 04:39:33  rgb
 * Add default == eroute.dest to IKE bypass conditions for magic eroutes.
 *
 * Revision 1.148  2001/05/05 03:31:41  rgb
 * IP frag debugging updates and enhancements.
 *
 * Revision 1.147  2001/05/03 19:41:40  rgb
 * Added SS' skb_cow fix for 2.4.4.
 *
 * Revision 1.146  2001/04/30 19:28:16  rgb
 * Update for 2.4.4.  ip_select_ident() now has 3 args.
 *
 * Revision 1.145  2001/04/23 14:56:10  rgb
 * Added spin_lock() check to prevent double-locking for multiple
 * transforms and hence kernel lock-ups with SMP kernels.
 *
 * Revision 1.144  2001/04/21 23:04:45  rgb
 * Define out skb->used for 2.4 kernels.
 * Check if soft expire has already been sent before sending another to
 * prevent ACQUIRE flooding.
 *
 * Revision 1.143  2001/03/16 07:37:21  rgb
 * Added comments to all #endifs.
 *
 * Revision 1.142  2001/02/28 05:03:27  rgb
 * Clean up and rationalise startup messages.
 *
 * Revision 1.141  2001/02/27 22:24:54  rgb
 * Re-formatting debug output (line-splitting, joining, 1arg/line).
 * Check for satoa() return codes.
 *
 * Revision 1.140  2001/02/27 06:40:12  rgb
 * Fixed TRAP->HOLD eroute byte order.
 *
 * Revision 1.139  2001/02/26 20:38:59  rgb
 * Added compiler defines for 2.4.x-specific code.
 *
 * Revision 1.138  2001/02/26 19:57:27  rgb
 * Implement magic SAs %drop, %reject, %trap, %hold, %pass as part
 * of the new SPD and to support opportunistic.
 * Drop sysctl_ipsec_{no_eroute_pass,opportunistic}, replaced by magic SAs.
 *
 * Revision 1.137  2001/02/19 22:29:49  rgb
 * Fixes for presence of active ipv6 segments which share ipsec physical
 * device (gg).
 *
 * Revision 1.136  2001/01/29 22:30:38  rgb
 * Fixed minor acquire debug printing bug.
 *
 * Revision 1.135  2001/01/29 22:19:45  rgb
 * Zero source address for 2.4 bypass route lookup.
 *
 * Revision 1.134  2001/01/23 20:19:49  rgb
 * 2.4 fix to remove removed is_clone member.
 *
 * Revision 1.133  2000/12/09 22:08:35  rgb
 * Fix NET_23 bug, should be NETDEV_23.
 *
 * Revision 1.132  2000/12/01 06:54:50  rgb
 * Fix for new 2.4 IP TTL default variable name.
 *
 * Revision 1.131  2000/11/09 20:52:15  rgb
 * More spinlock shuffling, locking earlier and unlocking later in rcv to
 * include ipcomp and prevent races, renaming some tdb variables that got
 * forgotten, moving some unlocks to include tdbs and adding a missing
 * unlock.  Thanks to Svenning for some of these.
 *
 * Revision 1.130  2000/11/09 20:11:22  rgb
 * Minor shuffles to fix non-standard kernel config option selection.
 *
 * Revision 1.129  2000/11/06 04:32:49  rgb
 * Clean up debug printing.
 * Copy skb->protocol for all kernel versions.
 * Ditched spin_lock_irqsave in favour of spin_lock.
 * Disabled TTL decrement, done in ip_forward.
 * Added debug printing before pfkey_acquire().
 * Fixed printk-deltdbchain-spin_lock races (Svenning).
 * Use defaultTTL for 2.1+ kernels.
 * Add Svenning's adaptive content compression.
 * Fix up debug display arguments.
 *
 * Revision 1.128  2000/09/28 00:58:57  rgb
 * Moved the IKE passthrough check after the eroute lookup so we can pass
 * IKE through intermediate tunnels.
 *
 * Revision 1.127  2000/09/22 17:52:11  rgb
 * Fixed misleading ipcomp debug output.
 *
 * Revision 1.126  2000/09/22 04:22:56  rgb
 * Fixed dumb spi->cpi conversion error.
 *
 * Revision 1.125  2000/09/21 04:34:48  rgb
 * A few debug-specific things should be hidden under
 * CONFIG_IPSEC_DEBUG.(MB)
 * Improved ip_send() error handling.(MB)
 *
 * Revision 1.124  2000/09/21 03:40:58  rgb
 * Added more debugging to try and track down the cpi outward copy problem.
 *
 * Revision 1.123  2000/09/19 07:08:49  rgb
 * Added debugging to outgoing compression report.
 *
 * Revision 1.122  2000/09/18 19:21:26  henry
 * RGB-supplied fix for RH5.2 problem
 *
 * Revision 1.121  2000/09/17 21:05:09  rgb
 * Added tdb to skb_compress call to write in cpi.
 *
 * Revision 1.120  2000/09/17 16:57:16  rgb
 * Added Svenning's patch to remove restriction of ipcomp to innermost
 * transform.
 *
 * Revision 1.119  2000/09/15 11:37:01  rgb
 * Merge in heavily modified Svenning Soerensen's <svenning@post5.tele.dk>
 * IPCOMP zlib deflate code.
 *
 * Revision 1.118  2000/09/15 04:57:16  rgb
 * Moved debug output after sanity check.
 * Added tos copy sysctl.
 *
 * Revision 1.117  2000/09/12 03:22:51  rgb
 * Converted ipsec_icmp, no_eroute_pass, opportunistic and #if0 debugs to
 * sysctl.
 *
 * Revision 1.116  2000/09/08 19:18:19  rgb
 * Change references from DEBUG_IPSEC to CONFIG_IPSEC_DEBUG.
 * Added outgoing opportunistic hook, ifdef'ed out.
 *
 * Revision 1.115  2000/08/30 05:27:29  rgb
 * Removed all the rest of the references to tdb_spi, tdb_proto, tdb_dst.
 * Kill remainder of tdb_xform, tdb_xdata, xformsw.
 *
 * Revision 1.114  2000/08/28 18:15:46  rgb
 * Added MB's nf-debug reset patch.
 *
 * Revision 1.113  2000/08/27 02:26:40  rgb
 * Send all no-eroute-bypass, pluto-bypass and passthrough packets through
 * fragmentation machinery for 2.0, 2.2 and 2.4 kernels.
 *
 * Revision 1.112  2000/08/20 21:37:33  rgb
 * Activated pfkey_expire() calls.
 * Added a hard/soft expiry parameter to pfkey_expire(). (Momchil)
 * Re-arranged the order of soft and hard expiry to conform to RFC2367.
 * Clean up references to CONFIG_IPSEC_PFKEYv2.
 *
 * Revision 1.111  2000/08/01 14:51:51  rgb
 * Removed _all_ remaining traces of DES.
 *
 * Revision 1.110  2000/07/28 14:58:31  rgb
 * Changed kfree_s to kfree, eliminating extra arg to fix 2.4.0-test5.
 *
 * Revision 1.109  2000/07/28 13:50:54  rgb
 * Changed enet_statistics to net_device_stats and added back compatibility
 * for pre-2.1.19.
 *
 * Revision 1.108  2000/05/16 03:03:11  rgb
 * Updates for 2.3.99pre8 from MB.
 *
 * Revision 1.107  2000/05/10 23:08:21  rgb
 * Print a debug warning about bogus packets received by the outgoing
 * processing machinery only when klipsdebug is not set to none.
 * Comment out the device initialisation informational messages.
 *
 * Revision 1.106  2000/05/10 19:17:14  rgb
 * Define an IP_SEND macro, intending to have all packet passthroughs
 * use fragmentation.  This didn't quite work, but is a step in the
 * right direction.
 * Added buffer allocation debugging statements.
 * Added configure option to shut off no eroute passthrough.
 * Only check usetime against soft and hard limits if the tdb has been
 * used.
 * Cast output of ntohl so that the broken prototype doesn't make our
 * compile noisy.
 *
 * Revision 1.105  2000/03/22 16:15:37  rgb
 * Fixed renaming of dev_get (MB).
 *
 * Revision 1.104  2000/03/16 14:04:15  rgb
 * Indented headers for readability.
 * Fixed debug scope to enable compilation with debug off.
 * Added macros for ip_chk_addr and IS_MYADDR for identifying self.
 *
 * Revision 1.103  2000/03/16 07:11:07  rgb
 * Hardcode PF_KEYv2 support.
 * Fixed bug which allowed UDP/500 packet from another machine
 * through in the clear.
 * Added disabled skb->protocol fix for ISDN/ASYNC PPP from Matjaz Godec.
 *
 * Revision 1.102  2000/03/14 12:26:59  rgb
 * Added skb->nfct support for clearing netfilter conntrack bits (MB).
 *
 * Revision 1.101  2000/02/14 21:05:22  rgb
 * Added MB's netif_queue fix for kernels 2.3.43+.
 *
 * Revision 1.100  2000/01/26 10:04:57  rgb
 * Fixed noisy 2.0 printk arguments.
 *
 * Revision 1.99  2000/01/21 06:16:25  rgb
 * Added sanity checks on skb_push(), skb_pull() to prevent panics.
 * Switched to AF_ENCAP macro.
 * Shortened debug output per packet and re-arranging debug_tunnel
 * bitmap flags, while retaining necessary information to avoid
 * trampling the kernel print ring buffer.
 * Reformatted recursion switch code.
 * Changed all references to tdb_proto to tdb_said.proto for clarity.
 *
 * Revision 1.98  2000/01/13 08:09:31  rgb
 * Shuffled debug_tunnel switches to focus output.
 * Fixed outgoing recursion bug, limiting to recursing only if the remote
 * SG changes and if it is valid, ie. not passthrough.
 * Clarified a number of debug messages.
 *
 * Revision 1.97  2000/01/10 16:37:16  rgb
 * MB support for new ip_select_ident() upon disappearance of
 * ip_id_count in 2.3.36+.
 *
 * Revision 1.96  1999/12/31 14:59:08  rgb
 * MB fix to use new skb_copy_expand in kernel 2.3.35.
 *
 * Revision 1.95  1999/12/29 21:15:44  rgb
 * Fix tncfg to aliased device bug.
 *
 * Revision 1.94  1999/12/22 04:26:06  rgb
 * Converted all 'static' functions to 'DEBUG_NO_STATIC' to enable
 * debugging by providing external labels to all functions with debugging
 * turned on.
 *
 * Revision 1.93  1999/12/13 13:30:14  rgb
 * Changed MTU reports and HW address reporting back to debug only.
 *
 * Revision 1.92  1999/12/07 18:57:56  rgb
 * Fix PFKEY symbol compile error (SADB_*) without pfkey enabled.
 *
 * Revision 1.91  1999/12/01 22:15:36  rgb
 * Add checks for LARVAL and DEAD SAs.
 * Change state of SA from MATURE to DYING when a soft lifetime is
 * reached and print debug warning.
 *
 * Revision 1.90  1999/11/23 23:04:04  rgb
 * Use provided macro ADDRTOA_BUF instead of hardcoded value.
 * Sort out pfkey and freeswan headers, putting them in a library path.
 *
 * Revision 1.89  1999/11/18 18:50:59  rgb
 * Changed all device registrations for static linking to
 * dynamic to reduce the number and size of patches.
 *
 * Revision 1.88  1999/11/18 04:09:19  rgb
 * Replaced all kernel version macros to shorter, readable form.
 *
 * Revision 1.87  1999/11/17 15:53:40  rgb
 * Changed all occurrences of #include "../../../lib/freeswan.h"
 * to #include <freeswan.h> which works due to -Ilibfreeswan in the
 * klips/net/ipsec/Makefile.
 *
 * Revision 1.86  1999/10/16 18:25:37  rgb
 * Moved SA lifetime expiry checks before packet processing.
 * Expire SA on replay counter rollover.
 *
 * Revision 1.85  1999/10/16 04:24:31  rgb
 * Add stats for time since last packet.
 *
 * Revision 1.84  1999/10/16 00:30:47  rgb
 * Added SA lifetime counting.
 *
 * Revision 1.83  1999/10/15 22:15:57  rgb
 * Clean out cruft.
 * Add debugging.
 *
 * Revision 1.82  1999/10/08 18:26:19  rgb
 * Fix 2.0.3x outgoing fragmented packet memory leak.
 *
 * Revision 1.81  1999/10/05 02:38:54  rgb
 * Lower the default mtu of virtual devices to 16260.
 *
 * Revision 1.80  1999/10/03 18:56:41  rgb
 * Spinlock support for 2.3.xx.
 * Don't forget to undo spinlocks on error!
 * Check for valid eroute before copying the structure.
 *
 * Revision 1.79  1999/10/01 15:44:53  rgb
 * Move spinlock header include to 2.1> scope.
 *
 * Revision 1.78  1999/10/01 00:02:43  rgb
 * Added tdb structure locking.
 * Added eroute structure locking.
 *
 * Revision 1.77  1999/09/30 02:52:29  rgb
 * Add Marc Boucher's Copy-On-Write code (same as ipsec_rcv.c).
 *
 * Revision 1.76  1999/09/25 19:31:27  rgb
 * Refine MSS hack to affect SYN, but not SYN+ACK packets.
 *
 * Revision 1.75  1999/09/24 22:52:38  rgb
 * Fix two things broken in 2.0.38 by trying to fix network notifiers.
 *
 * Revision 1.74  1999/09/24 00:30:37  rgb
 * Add test for changed source as well as destination to check for
 * recursion.
 *
 * Revision 1.73  1999/09/23 20:52:24  rgb
 * Add James Morris' MSS hack patch, disabled.
 *
 * Revision 1.72  1999/09/23 20:22:40  rgb
 * Enable, tidy and fix network notifier code.
 *
 * Revision 1.71  1999/09/23 18:09:05  rgb
 * Clean up 2.2.x fragmenting traces.
 * Disable dev->type switching, forcing ARPHRD_TUNNEL.
 *
 * Revision 1.70  1999/09/22 14:14:24  rgb
 * Add sanity checks for revectored calls to prevent calling a downed I/F.
 *
 * Revision 1.69  1999/09/21 15:00:57  rgb
 * Add Marc Boucher's packet size check.
 * Flesh out network device notifier code.
 *
 * Revision 1.68  1999/09/18 11:39:57  rgb
 * Start to add (disabled) netdevice notifier code.
 *
 * Revision 1.67  1999/09/17 23:44:40  rgb
 * Add a comment warning potential code hackers to stay away from mac.raw.
 *
 * Revision 1.66  1999/09/17 18:04:02  rgb
 * Add fix for unpredictable hard_header_len for ISDN folks (thanks MB).
 * Ditch TTL decrement in 2.2 (MB).
 *
 * Revision 1.65  1999/09/15 23:15:35  henry
 * Marc Boucher's PPP fixes
 *
 * Revision 1.64  1999/09/07 13:40:53  rgb
 * Ditch unreliable references to skb->mac.raw.
 *
 * Revision 1.63  1999/08/28 11:33:09  rgb
 * Check for null skb->mac pointer.
 *
 * Revision 1.62  1999/08/28 02:02:30  rgb
 * Add Marc Boucher's fix for properly dealing with skb->sk.
 *
 * Revision 1.61  1999/08/27 05:23:05  rgb
 * Clean up skb->data/raw/nh/h manipulation.
 * Add Marc Boucher's mods to aid tcpdump.
 * Add sanity checks to skb->raw/nh/h pointer copies in skb_copy_expand.
 * Re-order hard_header stripping -- might be able to remove it...
 *
 * Revision 1.60  1999/08/26 20:01:02  rgb
 * Tidy up compiler directives and macros.
 * Re-enable ICMP for tunnels where inner_dst !=  outer_dst.
 * Remove unnecessary skb->dev = physdev assignment affecting 2.2.x.
 *
 * Revision 1.59  1999/08/25 15:44:41  rgb
 * Clean up from 2.2.x instrumenting for compilation under 2.0.36.
 *
 * Revision 1.58  1999/08/25 15:00:54  rgb
 * Add dst cache code for 2.2.xx.
 * Add sanity check for skb packet header pointers.
 * Add/modify debugging instrumentation to *_start_xmit, *_hard_header and
 * *_rebuild_header.
 * Add neigh_* cache code.
 * Change dev->type back to ARPHRD_TUNNEL.
 *
 * Revision 1.57  1999/08/17 21:50:23  rgb
 * Fixed minor debug output bugs.
 * Regrouped error recovery exit code.
 * Added compiler directives to remove unwanted code and symbols.
 * Shut off ICMP messages: to be refined to only send ICMP to remote systems.
 * Add debugging code for output function addresses.
 * Fix minor bug in (possibly unused) header_cache_bind function.
 * Add device neighbour caching code.
 * Change dev->type from ARPHRD_TUNNEL to physdev->type.
 *
 * Revision 1.56  1999/08/03 17:22:56  rgb
 * Debug output clarification using KERN_* macros.  Other inactive changes
 * added.
 *
 * Revision 1.55  1999/08/03 16:58:46  rgb
 * Fix skb_copy_expand size bug.  Was getting incorrect size.
 *
 * Revision 1.54  1999/07/14 19:32:38  rgb
 * Fix oversize packet crash and ssh stalling in 2.2.x kernels.
 *
 * Revision 1.53  1999/06/10 15:44:02  rgb
 * Minor reformatting and clean-up.
 *
 * Revision 1.52  1999/05/09 03:25:36  rgb
 * Fix bug introduced by 2.2 quick-and-dirty patch.
 *
 * Revision 1.51  1999/05/08 21:24:59  rgb
 * Add casting to silence the 2.2.x compile.
 *
 * Revision 1.50  1999/05/05 22:02:32  rgb
 * Add a quick and dirty port to 2.2 kernels by Marc Boucher <marc@mbsi.ca>.
 *
 * Revision 1.49  1999/04/29 15:18:52  rgb
 * Change gettdb parameter to a pointer to reduce stack loading and
 * facilitate parameter sanity checking.
 * Fix undetected bug that might have tried to access a null pointer.
 * Eliminate unnessessary usage of tdb_xform member to further switch
 * away from the transform switch to the algorithm switch.
 * Add return values to init and cleanup functions.
 *
 * Revision 1.48  1999/04/16 15:38:00  rgb
 * Minor rearrangement of freeing code to avoid memory leaks with impossible or
 * rare situations.
 *
 * Revision 1.47  1999/04/15 15:37:25  rgb
 * Forward check changes from POST1_00 branch.
 *
 * Revision 1.32.2.4  1999/04/13 21:00:18  rgb
 * Ditch 'things I wish I had known before...'.
 *
 * Revision 1.32.2.3  1999/04/13 20:34:38  rgb
 * Free skb after fragmentation.
 * Use stats more effectively.
 * Add I/F to mtu notch-down reporting.
 *
 * Revision 1.32.2.2  1999/04/02 04:26:14  rgb
 * Backcheck from HEAD, pre1.0.
 *
 * Revision 1.46  1999/04/11 00:29:00  henry
 * GPL boilerplate
 *
 * Revision 1.45  1999/04/07 15:42:01  rgb
 * Fix mtu/ping bug AGAIN!
 *
 * Revision 1.44  1999/04/06 04:54:27  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 * Revision 1.43  1999/04/04 03:57:07  rgb
 * ip_fragment() doesn't free the supplied skb.  Freed.
 *
 * Revision 1.42  1999/04/01 23:27:15  rgb
 * Preload size of virtual mtu.
 *
 * Revision 1.41  1999/04/01 09:31:23  rgb
 * Invert meaning of ICMP PMTUD config option and clarify.
 * Code clean-up.
 *
 * Revision 1.40  1999/04/01 04:37:17  rgb
 * SSH stalling bug fix.
 *
 * Revision 1.39  1999/03/31 23:44:28  rgb
 * Don't send ICMP on DF and frag_off.
 *
 * Revision 1.38  1999/03/31 15:20:10  rgb
 * Quiet down debugging.
 *
 * Revision 1.37  1999/03/31 08:30:31  rgb
 * Add switch to shut off ICMP PMTUD packets.
 *
 * Revision 1.36  1999/03/31 05:44:47  rgb
 * Keep PMTU reduction private.
 *
 * Revision 1.35  1999/03/27 15:13:02  rgb
 * PMTU/fragmentation bug fix.
 *
 * Revision 1.34  1999/03/17 21:19:26  rgb
 * Fix kmalloc nonatomic bug.
 *
 * Revision 1.33  1999/03/17 15:38:42  rgb
 * Code clean-up.
 * ESP_NULL IV bug fix.
 *
 * Revision 1.32  1999/03/01 20:44:25  rgb
 * Code clean-up.
 * Memory leak bug fix.
 *
 * Revision 1.31  1999/02/27 00:02:09  rgb
 * Tune to report the MTU reduction once, rather than after every recursion
 * through the encapsulating code, preventing tcp stream stalling.
 *
 * Revision 1.30  1999/02/24 20:21:01  rgb
 * Reformat debug printk's.
 * Fix recursive encapsulation, dynamic MTU bugs and add debugging code.
 * Clean-up.
 *
 * Revision 1.29  1999/02/22 17:08:14  rgb
 * Fix recursive encapsulation code.
 *
 * Revision 1.28  1999/02/19 18:27:02  rgb
 * Improve DF, fragmentation and PMTU behaviour and add dynamic MTU discovery.
 *
 * Revision 1.27  1999/02/17 16:51:37  rgb
 * Clean out unused cruft.
 * Temporarily tone down volume of debug output.
 * Temporarily shut off fragment rejection.
 * Disabled temporary failed recursive encapsulation loop.
 *
 * Revision 1.26  1999/02/12 21:21:26  rgb
 * Move KLIPS_PRINT to ipsec_netlink.h for accessibility.
 *
 * Revision 1.25  1999/02/11 19:38:27  rgb
 * More clean-up.
 * Add sanity checking for skb_copy_expand() to prevent kernel panics on
 * skb_put() values out of range.
 * Fix head/tailroom calculation causing skb_put() out-of-range values.
 * Fix return values to prevent 'nonatomic alloc_skb' warnings.
 * Allocate new skb iff needed.
 * Added more debug statements.
 * Make headroom depend on structure, not hard-coded values.
 *
 * Revision 1.24  1999/02/10 23:20:33  rgb
 * Shut up annoying 'statement has no effect' compiler warnings with
 * debugging compiled out.
 *
 * Revision 1.23  1999/02/10 22:36:30  rgb
 * Clean-up obsolete, unused and messy code.
 * Converted most IPSEC_DEBUG statements to KLIPS_PRINT macros.
 * Rename ipsec_tunnel_do_xmit to ipsec_tunnel_start_xmit and eliminated
 * original ipsec_tunnel_start_xmit.
 * Send all packet with different inner and outer destinations directly to
 * the attached physical device, rather than back through ip_forward,
 * preventing disappearing routes problems.
 * Do sanity checking before investing too much CPU in allocating new
 * structures.
 * Fail on IP header options: We cannot process them yet.
 * Add some helpful comments.
 * Use virtual device for parameters instead of physical device.
 *
 * Revision 1.22  1999/02/10 03:03:02  rgb
 * Duh.  Fixed the TTL bug: forgot to update the checksum.
 *
 * Revision 1.21  1999/02/09 23:17:53  rgb
 * Add structure members to ipsec_print_ip debug function.
 * Temporarily fix TTL bug preventing tunnel mode from functioning.
 *
 * Revision 1.20  1999/02/09 00:14:25  rgb
 * Add KLIPSPRINT macro.  (Not used yet, though.)
 * Delete old ip_tunnel code (BADCODE).
 * Decrement TTL in outgoing packet.
 * Set TTL on new IPIP_TUNNEL to default, not existing packet TTL.
 * Delete ethernet only feature and fix hard-coded hard_header_len.
 *
 * Revision 1.19  1999/01/29 17:56:22  rgb
 * 64-bit re-fix submitted by Peter Onion.
 *
 * Revision 1.18  1999/01/28 22:43:24  rgb
 * Fixed bug in ipsec_print_ip that caused an OOPS, found by P.Onion.
 *
 * Revision 1.17  1999/01/26 02:08:16  rgb
 * Removed CONFIG_IPSEC_ALGO_SWITCH macro.
 * Removed dead code.
 *
 * Revision 1.16  1999/01/22 06:25:26  rgb
 * Cruft clean-out.
 * Added algorithm switch code.
 * 64-bit clean-up.
 * Passthrough on IPIP protocol, spi 0x0 fix.
 * Enhanced debugging.
 *
 * Revision 1.15  1998/12/01 13:22:04  rgb
 * Added support for debug printing of version info.
 *
 * Revision 1.14  1998/11/30 13:22:55  rgb
 * Rationalised all the klips kernel file headers.  They are much shorter
 * now and won't conflict under RH5.2.
 *
 * Revision 1.13  1998/11/17 21:13:52  rgb
 * Put IKE port bypass debug output in user-switched debug statements.
 *
 * Revision 1.12  1998/11/13 13:20:25  rgb
 * Fixed ntohs bug in udp/500 hole for IKE.
 *
 * Revision 1.11  1998/11/10 08:01:19  rgb
 * Kill tcp/500 hole,  keep udp/500 hole.
 *
 * Revision 1.10  1998/11/09 21:29:26  rgb
 * If no eroute is found, discard packet and incr. tx_error.
 *
 * Revision 1.9  1998/10/31 06:50:00  rgb
 * Add tcp/udp/500 bypass.
 * Fixed up comments in #endif directives.
 *
 * Revision 1.8  1998/10/27 00:34:31  rgb
 * Reformat debug output of IP headers.
 * Newlines added before calls to ipsec_print_ip.
 *
 * Revision 1.7  1998/10/19 14:44:28  rgb
 * Added inclusion of freeswan.h.
 * sa_id structure implemented and used: now includes protocol.
 *
 * Revision 1.6  1998/10/09 04:31:35  rgb
 * Added 'klips_debug' prefix to all klips printk debug statements.
 *
 * Revision 1.5  1998/08/28 03:09:51  rgb
 * Prevent kernel log spam with default route through ipsec.
 *
 * Revision 1.4  1998/08/05 22:23:09  rgb
 * Change setdev return code to ENXIO for a non-existant physical device.
 *
 * Revision 1.3  1998/07/29 20:41:11  rgb
 * Add ipsec_tunnel_clear to clear all tunnel attachments.
 *
 * Revision 1.2  1998/06/25 20:00:33  rgb
 * Clean up #endif comments.
 * Rename dev_ipsec to dev_ipsec0 for consistency.
 * Document ipsec device fields.
 * Make ipsec_tunnel_probe visible from rest of kernel for static linking.
 * Get debugging report for *every* ipsec device initialisation.
 * Comment out redundant code.
 *
 * Revision 1.1  1998/06/18 21:27:50  henry
 * move sources from klips/src to klips/net/ipsec, to keep stupid
 * kernel-build scripts happier in the presence of symlinks
 *
 * Revision 1.8  1998/06/14 23:49:40  rgb
 * Clarify version reporting on module loading.
 *
 * Revision 1.7  1998/05/27 23:19:20  rgb
 * Added version reporting.
 *
 * Revision 1.6  1998/05/18 21:56:23  rgb
 * Clean up for numerical consistency of output and cleaning up debug code.
 *
 * Revision 1.5  1998/05/12 02:44:23  rgb
 * Clarifying 'no e-route to host' message.
 *
 * Revision 1.4  1998/04/30 15:34:35  rgb
 * Enclosed most remaining debugging statements in #ifdef's to make it quieter.
 *
 * Revision 1.3  1998/04/21 21:28:54  rgb
 * Rearrange debug switches to change on the fly debug output from user
 * space.  Only kernel changes checked in at this time.  radij.c was also
 * changed to temporarily remove buggy debugging code in rj_delete causing
 * an OOPS and hence, netlink device open errors.
 *
 * Revision 1.2  1998/04/12 22:03:24  rgb
 * Updated ESP-3DES-HMAC-MD5-96,
 * 	ESP-DES-HMAC-MD5-96,
 * 	AH-HMAC-MD5-96,
 * 	AH-HMAC-SHA1-96 since Henry started freeswan cvs repository
 * from old standards (RFC182[5-9] to new (as of March 1998) drafts.
 *
 * Fixed eroute references in /proc/net/ipsec*.
 *
 * Started to patch module unloading memory leaks in ipsec_netlink and
 * radij tree unloading.
 *
 * Revision 1.1  1998/04/09 03:06:12  henry
 * sources moved up from linux/net/ipsec
 *
 * Revision 1.1.1.1  1998/04/08 05:35:04  henry
 * RGB's ipsec-0.8pre2.tar.gz ipsec-0.8
 *
 * Revision 0.5  1997/06/03 04:24:48  ji
 * Added transport mode.
 * Changed the way routing is done.
 * Lots of bug fixes.
 *
 * Revision 0.4  1997/01/15 01:28:15  ji
 * No changes.
 *
 * Revision 0.3  1996/11/20 14:39:04  ji
 * Minor cleanups.
 * Rationalized debugging code.
 *
 * Revision 0.2  1996/11/02 00:18:33  ji
 * First limited release.
 *
 *
 */
