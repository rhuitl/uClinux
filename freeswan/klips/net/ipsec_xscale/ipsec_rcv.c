/*
 * receive code
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

char ipsec_rcv_c_version[] = "RCSID $Id: ipsec_rcv.c,v 1.2.2.1 2004/08/31 05:59:47 philipc Exp $";

#include <linux/config.h>
#include <linux/version.h>

#define __NO_VERSION__
#include <linux/module.h>
#include <linux/kernel.h> /* printk() */

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

#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/ip.h>          /* struct iphdr */
#include <linux/skbuff.h>
#include <freeswan.h>
#ifdef SPINLOCK
# ifdef SPINLOCK_23
#  include <linux/spinlock.h> /* *lock* */
# else /* SPINLOCK_23 */
#  include <asm/spinlock.h> /* *lock* */
# endif /* SPINLOCK_23 */
#endif /* SPINLOCK */
#ifdef NET_21
# include <asm/uaccess.h>
# include <linux/in6.h>
# define proto_priv cb
#endif /* NET21 */
#include <asm/checksum.h>
#include <net/ip.h>
#ifdef CONFIG_LEDMAN
#include <linux/ledman.h>
#endif

#include "radij.h"
#include "ipsec_encap.h"
#include "ipsec_sa.h"

#include "ipsec_radij.h"
#include "ipsec_netlink.h"
#include "ipsec_xform.h"
#include "ipsec_tunnel.h"
#include "ipsec_rcv.h"
#if defined(CONFIG_IPSEC_ESP) || defined(CONFIG_IPSEC_AH)
# include "ipsec_ah.h"
#endif /* defined(CONFIG_IPSEC_ESP) || defined(CONFIG_IPSEC_AH) */
#ifdef CONFIG_IPSEC_ESP
# include "ipsec_esp.h"
#endif /* !CONFIG_IPSEC_ESP */
#ifdef CONFIG_IPSEC_IPCOMP
# include "ipcomp.h"
#endif /* CONFIG_IPSEC_COMP */

#include <pfkeyv2.h>
#include <pfkey.h>

#include "ipsec_proto.h"

/* IXP425 cryptoAcc Glue Code */
#include "IxCryptoAcc.h"
#include "IxOsBuffMgt.h"
#include "ipsec_glue_mbuf.h"
#include "ipsec_glue.h"
#include "ipsec_glue_desc.h"
#include "tqueue.h"

#define PROTO	9   /* Protocol field offset in IP Header */
#define MAX_RCV_TASK_IN_SOFTIRQ 384

#ifdef SPINLOCK
spinlock_t rcv_lock = SPIN_LOCK_UNLOCKED;
#else /* SPINLOCK */
spinlock_t rcv_lock = 0;
#endif /* SPINLOCK */

static void ipsec_rcv_next_transform (void *data);
static struct tq_struct rcv_task[MAX_RCV_TASK_IN_SOFTIRQ];
static __u32 rcvProducer = 0;
static __u32 rcvConsumer = 0;

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
#include <linux/udp.h>
#endif

#ifdef CONFIG_IPSEC_DEBUG
int debug_ah = 0;
int debug_esp = 0;
int debug_rcv = 0;
#endif /* CONFIG_IPSEC_DEBUG */

int sysctl_ipsec_inbound_policy_check = 1;


/*
 * Check-replay-window routine, adapted from the original 
 * by J. Hughes, from draft-ietf-ipsec-esp-des-md5-03.txt
 *
 *  This is a routine that implements a 64 packet window. This is intend-
 *  ed on being an implementation sample.
 */

DEBUG_NO_STATIC int
ipsec_checkreplaywindow(struct ipsec_sa*tdbp, __u32 seq)
{
	__u32 diff;
	
	if (tdbp->tdb_replaywin == 0)	/* replay shut off */
		return 1;
	if (seq == 0) 
		return 0;		/* first == 0 or wrapped */

	/* new larger sequence number */
	if (seq > tdbp->tdb_replaywin_lastseq) {
		return 1;		/* larger is good */
	}
	diff = tdbp->tdb_replaywin_lastseq - seq;

	/* too old or wrapped */ /* if wrapped, kill off SA? */
	if (diff >= tdbp->tdb_replaywin) {
		return 0;
	}
	/* this packet already seen */
	if (tdbp->tdb_replaywin_bitmap & (1 << diff))
		return 0;
	return 1;			/* out of order but good */
}

DEBUG_NO_STATIC int
ipsec_updatereplaywindow(struct ipsec_sa*tdbp, __u32 seq)
{
	__u32 diff;
	
	if (tdbp->tdb_replaywin == 0)	/* replay shut off */
		return 1;
	if (seq == 0) 
		return 0;		/* first == 0 or wrapped */

	/* new larger sequence number */
	if (seq > tdbp->tdb_replaywin_lastseq) {
		diff = seq - tdbp->tdb_replaywin_lastseq;

		/* In win, set bit for this pkt */
		if (diff < tdbp->tdb_replaywin)
			tdbp->tdb_replaywin_bitmap =
				(tdbp->tdb_replaywin_bitmap << diff) | 1;
		else
			/* This packet has way larger seq num */
			tdbp->tdb_replaywin_bitmap = 1;

		if(seq - tdbp->tdb_replaywin_lastseq - 1 > tdbp->tdb_replaywin_maxdiff) {
			tdbp->tdb_replaywin_maxdiff = seq - tdbp->tdb_replaywin_lastseq - 1;
		}
		tdbp->tdb_replaywin_lastseq = seq;
		return 1;		/* larger is good */
	}
	diff = tdbp->tdb_replaywin_lastseq - seq;

	/* too old or wrapped */ /* if wrapped, kill off SA? */
	if (diff >= tdbp->tdb_replaywin) {
/*
		if(seq < 0.25*max && tdbp->tdb_replaywin_lastseq > 0.75*max) {
			deltdbchain(tdbp);
		}
*/	
		return 0;
	}
	/* this packet already seen */
	if (tdbp->tdb_replaywin_bitmap & (1 << diff))
		return 0;
	tdbp->tdb_replaywin_bitmap |= (1 << diff);	/* mark as seen */
	return 1;			/* out of order but good */
}


/* IXP425 cryptoAcc Glue Code : ipsec_rcv_cb */
void ipsec_rcv_cb(
    UINT32 cryptoCtxId,
    IX_MBUF *pSrcMbuf,
    IX_MBUF *pDestMbuf,
    IxCryptoAccStatus status)
{
    struct sk_buff *skb;
    IpsecRcvDesc *pRcvDesc = NULL;

    if (pSrcMbuf == NULL)
    {
        KLIPS_PRINT(debug_rcv,
                "klips_debug:ipsec_rcv: "
                "skb is NULL\n");
        return;
    }

    switch (status)
    {
        case IX_CRYPTO_ACC_STATUS_SUCCESS:
            KLIPS_PRINT(debug_rcv,
                    "klips_debug:ipsec_rcv: "
                    "transform successful.\n");

            spin_lock(&rcv_lock);

            if ((rcvProducer - rcvConsumer) != MAX_RCV_TASK_IN_SOFTIRQ)
            {
                rcvProducer = rcvProducer % MAX_RCV_TASK_IN_SOFTIRQ;
                INIT_LIST_HEAD(&rcv_task[rcvProducer].list);
                rcv_task[rcvProducer].sync = 0;
                rcv_task[rcvProducer].routine = ipsec_rcv_next_transform;
                rcv_task[rcvProducer].data = (void *) pSrcMbuf;
                queue_task(&rcv_task[rcvProducer], &tq_immediate);
                rcvProducer++;
                mark_bh(IMMEDIATE_BH);
            }
            else
            {
                KLIPS_PRINT(debug_rcv,
                    "klips_debug:ipsec_rcv: "
                    "soft IRQ task queue full.\n");

                /* Detach skb from mbuf */
                skb = mbuf_swap_skb(pSrcMbuf, NULL);
                /* get rcv desc from mbuf */
                pRcvDesc = (IpsecRcvDesc *) IX_MBUF_NEXT_PKT_IN_CHAIN_PTR (pSrcMbuf);
                ipsec_glue_mbuf_header_rel (pSrcMbuf);

                if (pRcvDesc)
                {
                    if(pRcvDesc->stats) {
                        (pRcvDesc->stats)->rx_dropped++;
                    }

                    if (pRcvDesc->tdbp)
                    {
                        spin_lock(&tdb_lock);
			delRcvDesc_from_salist(pRcvDesc->tdbp, pRcvDesc);
			spin_unlock(&tdb_lock);
                    }

                    /* release desc */
                    ipsec_glue_rcv_desc_release (pRcvDesc);
                }

                if(skb) {
#ifdef NET_21
                    kfree_skb(skb);
#else /* NET_21 */
                    kfree_skb(skb, FREE_WRITE);
#endif /* NET_21 */
                }

                MOD_DEC_USE_COUNT;
            }

            spin_unlock(&rcv_lock);
            break;

        case IX_CRYPTO_ACC_STATUS_AUTH_FAIL:
            /* Detach skb from mbuf */
            skb = mbuf_swap_skb(pSrcMbuf, NULL);
            /* get rcv desc from mbuf */
            pRcvDesc = (IpsecRcvDesc *) IX_MBUF_NEXT_PKT_IN_CHAIN_PTR (pSrcMbuf);
            ipsec_glue_mbuf_header_rel (pSrcMbuf);

            KLIPS_PRINT(debug_rcv & DB_RX_INAU,
                    "klips_debug:ipsec_rcv: "
                    "auth failed on incoming packet, dropped\n");

            if (pRcvDesc)
            {
                if(pRcvDesc->stats) {
                    (pRcvDesc->stats)->rx_dropped++;
                }

                if (pRcvDesc->tdbp)
                {
                    spin_lock(&tdb_lock);
                    (pRcvDesc->tdbp)->tdb_auth_errs += 1;
		    delRcvDesc_from_salist(pRcvDesc->tdbp, pRcvDesc);
		    spin_unlock(&tdb_lock);
                }
                /* release desc */
                ipsec_glue_rcv_desc_release (pRcvDesc);
            }

            if(skb) {
#ifdef NET_21
                kfree_skb(skb);
#else /* NET_21 */
                kfree_skb(skb, FREE_WRITE);
#endif /* NET_21 */
            }

            MOD_DEC_USE_COUNT;
            break;
        default:
            KLIPS_PRINT(debug_rcv,
                    "klips_debug:ipsec_rcv: "
                    "decapsulation on incoming packet failed, dropped\n");

            /* Detach skb from mbuf */
            skb = mbuf_swap_skb(pSrcMbuf, NULL);
            /* get rcv desc from mbuf */
            pRcvDesc = (IpsecRcvDesc *) IX_MBUF_NEXT_PKT_IN_CHAIN_PTR (pSrcMbuf);
            ipsec_glue_mbuf_header_rel (pSrcMbuf);

            if (pRcvDesc)
            {
                if(pRcvDesc->stats) {
                    (pRcvDesc->stats)->rx_dropped++;
                }

                if (pRcvDesc->tdbp)
                {
                    spin_lock(&tdb_lock);
		    delRcvDesc_from_salist(pRcvDesc->tdbp, pRcvDesc);
		    spin_unlock(&tdb_lock);
                }
                /* release desc */
                ipsec_glue_rcv_desc_release (pRcvDesc);
            }

            if(skb) {
#ifdef NET_21
                kfree_skb(skb);
#else /* NET_21 */
                kfree_skb(skb, FREE_WRITE);
#endif /* NET_21 */
            }

            MOD_DEC_USE_COUNT;
            break;
    } /* end of switch (status) */
} /* end of ipsec_rcv_cb () */


static void ipsec_rcv_next_transform (void *data)
{
    struct sk_buff *skb = NULL;
    IpsecRcvDesc *pRcvDesc = NULL;
    IX_MBUF *pRetSrcMbuf = NULL;

    struct iphdr *ipp;
    int authlen;

#ifdef CONFIG_IPSEC_ESP
	struct esp *espp = NULL;
    char *ivp = NULL;
    int ivlen = 0;
	int esphlen = 0;
    char iv[ESP_IV_MAXSZ];
    int pad = 0, padlen;
#endif /* !CONFIG_IPSEC_ESP */
#ifdef CONFIG_IPSEC_AH
	struct ah *ahp = NULL;
	int ahhlen = 0;
#endif /* CONFIG_IPSEC_AH */

#ifdef CONFIG_IPSEC_IPCOMP
	struct ipcomphdr*compp = NULL;
#endif /* CONFIG_IPSEC_IPCOMP */

	int iphlen;
	unsigned char *dat;
	struct ipsec_sa *tdbp = NULL;
	struct sa_id said;

	char sa[SATOA_BUF];
	size_t sa_len;
	char ipaddr_txt[ADDRTOA_BUF];
	int i;
	struct in_addr ipaddr;
	__u8 next_header = 0;
	__u8 proto;

    int len;	/* packet length */
	int replay = 0;	/* replay value in AH or ESP packet */

    struct ipsec_sa* tdbprev = NULL;	/* previous SA from outside of packet */
	struct ipsec_sa* tdbnext = NULL;	/* next SA towards inside of packet */
#ifdef INBOUND_POLICY_CHECK_eroute
	struct sockaddr_encap matcher;	/* eroute search key */
	struct eroute *er;
	struct ipsec_sa* policy_tdb = NULL;
	struct sa_id policy_said;
	struct sockaddr_encap policy_eaddr;
	struct sockaddr_encap policy_emask;
#endif /* INBOUND_POLICY_CHECK_eroute */

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	__u16 natt_len = 0, natt_sport = 0, natt_dport = 0;
	__u8 natt_type = 0;
#endif
	__u32 auth_start_offset = 0;
	__u32 auth_data_len = 0;
	__u32 crypt_start_offset = 0;
	__u32 crypt_data_len = 0;
	__u32 icv_offset = 0;
	IX_MBUF *src_mbuf;

	pRetSrcMbuf = (IX_MBUF *) data;

	spin_lock(&rcv_lock);
	rcvConsumer++;
	spin_unlock(&rcv_lock);

	if (pRetSrcMbuf == NULL)
	{
	      KLIPS_PRINT(debug_rcv,
			  "klips_debug:ipsec_rcv: "
			  "NULL mbuf passed in.\n");
	      return;
	}

	/* Detach skb from mbuf */
	skb = mbuf_swap_skb(pRetSrcMbuf, NULL);

	/* get rcv desc from mbuf */
	pRcvDesc = (IpsecRcvDesc *) IX_MBUF_NEXT_PKT_IN_CHAIN_PTR (pRetSrcMbuf);

	/* release src mbuf */
	ipsec_glue_mbuf_header_rel (pRetSrcMbuf);

	if (pRcvDesc == NULL) {
	KLIPS_PRINT(debug_rcv,
			  "klips_debug:ipsec_rcv: "
			  "NULL Rcv Descriptor passed in.\n");
	      goto rcvleave_cb;
	}

	if (skb == NULL) {
	      KLIPS_PRINT(debug_rcv, 
			    "klips_debug:ipsec_rcv: "
			    "NULL skb passed in.\n");
		goto rcvleave_cb;
	}
		
	if (skb->data == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NULL skb->data passed in, packet is bogus, dropping.\n");
		goto rcvleave_cb;
	}

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	if (skb->sk && skb->nh.iph && skb->nh.iph->protocol==IPPROTO_UDP) {
		/**
		 * Packet comes from udp_queue_rcv_skb so it is already defrag,
		 * checksum verified, ... (ie safe to use)
		 *
		 * If the packet is not for us, return -1 and udp_queue_rcv_skb
		 * will continue to handle it (do not kfree skb !!).
		 */
		struct udp_opt *tp =  &(skb->sk->tp_pinfo.af_udp);
		struct iphdr *ip = (struct iphdr *)skb->nh.iph;
		struct udphdr *udp = (struct udphdr *)((__u32 *)ip+ip->ihl);
		__u8 *udpdata = (__u8 *)udp + sizeof(struct udphdr);
		__u32 *udpdata32 = (__u32 *)udpdata;

		natt_sport = ntohs(udp->source);
		natt_dport = ntohs(udp->dest);

		KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv: "
		    "suspected ESPinUDP packet (NAT-Traversal) [%d].\n",
			tp->esp_in_udp);
		KLIPS_IP_PRINT(debug_rcv, ip);

		if (udpdata < skb->tail) {
			unsigned int len = skb->tail - udpdata;
			if ((len==1) && (udpdata[0]==0xff)) {
				KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
					/* not IPv6 compliant message */
				    "NAT-keepalive from %d.%d.%d.%d.\n", NIPQUAD(ip->saddr));
				goto rcvleave_cb;
			}
			else if ( (tp->esp_in_udp == ESPINUDP_WITH_NON_IKE) &&
				(len > (2*sizeof(__u32) + sizeof(struct esp))) &&
				(udpdata32[0]==0) && (udpdata32[1]==0) ) {
				/* ESP Packet with Non-IKE header */
				KLIPS_PRINT(debug_rcv, 
					"klips_debug:ipsec_rcv: "
					"ESPinUDP pkt with Non-IKE - spi=0x%x\n",
					udpdata32[2]);
				natt_type = ESPINUDP_WITH_NON_IKE;
				natt_len = sizeof(struct udphdr)+(2*sizeof(__u32));
			}
			else if ( (tp->esp_in_udp == ESPINUDP_WITH_NON_ESP) &&
				(len > sizeof(struct esp)) &&
				(udpdata32[0]!=0) ) {
				/* ESP Packet without Non-ESP header */
				natt_type = ESPINUDP_WITH_NON_ESP;
				natt_len = sizeof(struct udphdr);
				KLIPS_PRINT(debug_rcv, 
					"klips_debug:ipsec_rcv: "
					"ESPinUDP pkt without Non-ESP - spi=0x%x\n",
					udpdata32[0]);
			}
			else {
				KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
					"IKE packet - not handled here\n");
				MOD_DEC_USE_COUNT;
				return -1;
			}
		}
		else {
			MOD_DEC_USE_COUNT;
			return -1;
		}
	}
#endif
		

    /* Restore tdbp from desc */
    tdbp = pRcvDesc->tdbp;

    if (tdbp == NULL)
    {
	      KLIPS_PRINT(debug_rcv,
			  "klips_debug:ipsec_rcv: "
			  "Corrupted descriptor, dropping.\n");
	      goto rcvleave_cb;
    }

    /* get ip header from skb */
    ipp = (struct iphdr *)skb->data;
    iphlen = ipp->ihl << 2;
    len  = skb->len;
	ipaddr.s_addr = ipp->saddr;
    addrtoa(ipaddr, 0, ipaddr_txt, sizeof(ipaddr_txt));

    switch(ipp->protocol) {
#ifdef CONFIG_IPSEC_ESP
	case IPPROTO_ESP:
		espp = (struct esp *)(skb->data + iphlen);
		replay = ntohl(espp->esp_rpl);
		if (!ipsec_updatereplaywindow(tdbp, replay)) {
		    spin_lock(&tdb_lock);
		    tdbp->tdb_replaywin_errs += 1;
		    delRcvDesc_from_salist(tdbp, pRcvDesc);
		    spin_unlock(&tdb_lock);
		    KLIPS_PRINT(debug_rcv & DB_RX_REPLAY,
			    "klips_debug:ipsec_rcv: "
			    "duplicate frame from %s, packet dropped\n",
			    ipaddr_txt);
		    if(pRcvDesc->stats) {
			    (pRcvDesc->stats)->rx_dropped++;
		    }
		    goto rcvleave_cb;
		}
		replay = 0; /* reset */

		next_header = skb->data[pRcvDesc->icv_offset - 1];
		padlen = skb->data[pRcvDesc->icv_offset - 2];
		esphlen = sizeof(struct esp);
		pad = padlen + 2 + (len - pRcvDesc->icv_offset);
		{
		    int badpad = 0;

		    KLIPS_PRINT(debug_rcv & DB_RX_IPAD,
			    "klips_debug:ipsec_rcv: "
			    "padlen=%d, contents: 0x<offset>: 0x<value> 0x<value> ...\n",
			    padlen);

		    for (i = 1; i <= padlen; i++) {
			if((i % 16) == 1) {
			    KLIPS_PRINT(debug_rcv & DB_RX_IPAD,
				    "klips_debug:	    %02x:",
				    i - 1);
			}
			KLIPS_PRINTMORE(debug_rcv & DB_RX_IPAD,
				" %02x",
				skb->data[pRcvDesc->icv_offset - 2 - padlen + i -1]);

			if(i != skb->data[pRcvDesc->icv_offset - 2 - padlen + i -1]) {
				badpad = 1;
			}
			if((i % 16) == 0) {
			    KLIPS_PRINTMORE(debug_rcv & DB_RX_IPAD,
				    "\n");
			}
		    }
		    if((i % 16) != 1) {
			KLIPS_PRINTMORE(debug_rcv & DB_RX_IPAD,
				"\n");
		    }
		    if(badpad) {
			KLIPS_PRINT(debug_rcv & DB_RX_IPAD,
				"klips_debug:ipsec_rcv: "
				"warning, decrypted packet from %s has bad padding\n",
				ipaddr_txt);
			KLIPS_PRINT(debug_rcv & DB_RX_IPAD,
				"klips_debug:ipsec_rcv: "
				"...may be bad decryption -- not dropped\n");
			spin_lock(&tdb_lock);
			(pRcvDesc->tdbp)->tdb_encpad_errs += 1;
		      delRcvDesc_from_salist(pRcvDesc->tdbp, pRcvDesc);
		      spin_unlock(&tdb_lock);
		    }

		    KLIPS_PRINT(debug_rcv & DB_RX_IPAD,
			    "klips_debug:ipsec_rcv: "
			    "packet decrypted: next_header = %d, padding = %d\n",
			    next_header,
			    pad - 2 - (len - pRcvDesc->icv_offset));
		}

		/* Discard ESP header */
		ipp->tot_len = htons(ntohs(ipp->tot_len) - (esphlen + pRcvDesc->ivlen + pad));
		memmove((void *)(skb->data + esphlen + pRcvDesc->ivlen),
		      (void *)(skb->data), iphlen);
		if(skb->len < (esphlen + pRcvDesc->ivlen)) {
		      printk(KERN_WARNING
			      "klips_error:ipsec_rcv: "
			      "tried to skb_pull esphlen=%d, ivlen=%d, %d available.  This should never happen, please report.\n",
		      esphlen, pRcvDesc->ivlen, (int)(skb->len));
		      spin_lock (&tdb_lock);
		      delRcvDesc_from_salist(tdbp, pRcvDesc);
		      spin_unlock (&tdb_lock);
		      goto rcvleave_cb;
		}
		skb_pull(skb, esphlen + pRcvDesc->ivlen);

		KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
			"klips_debug:ipsec_rcv: "
			"trimming to %d.\n",
			len - esphlen - pad - pRcvDesc->ivlen);
		if(pad + esphlen + pRcvDesc->ivlen <= len) {
			skb_trim(skb, len - esphlen - pad - pRcvDesc->ivlen);
		} else {
		      KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
			      "klips_debug:ipsec_rcv: "
			      "bogus packet, size is zero or negative, dropping.\n");
		      spin_lock (&tdb_lock);
		      delRcvDesc_from_salist(tdbp, pRcvDesc);
		      spin_unlock (&tdb_lock);
		      goto rcvleave_cb;
		}

		break;
#endif /* !CONFIG_IPSEC_ESP */
#ifdef CONFIG_IPSEC_AH
      case IPPROTO_AH:
	      /* Restore original IP header */
		ipp->frag_off = pRcvDesc->ip_frag_off;
		ipp->ttl = pRcvDesc->ip_ttl;

		ahp = (struct ah *) (skb->data + iphlen);
		/* get AH header len */
		ahhlen = (ahp->ah_hl << 2) +
				  ((caddr_t)&(ahp->ah_rpl) - (caddr_t)ahp);
		replay = ntohl(ahp->ah_rpl);
		if (!ipsec_updatereplaywindow(tdbp, replay)) {
		      spin_lock (&tdb_lock);
		      tdbp->tdb_replaywin_errs += 1;
		      delRcvDesc_from_salist(tdbp, pRcvDesc);
		      spin_unlock(&tdb_lock);
		      KLIPS_PRINT(debug_rcv & DB_RX_REPLAY,
			      "klips_debug:ipsec_rcv: "
			      "duplicate frame from %s, packet dropped\n",
			      ipaddr_txt);
		      if (pRcvDesc->stats) {
			      (pRcvDesc->stats)->rx_dropped++;
		      }
		      goto rcvleave_cb;
		}
		replay = 0; /* reset */

		next_header = ahp->ah_nh;

		/* DIscard AH header */
		ipp->tot_len = htons(ntohs(ipp->tot_len) - ahhlen);
		memmove((void *)(skb->data + ahhlen),
		      (void *)(skb->data), iphlen);
		if(skb->len < ahhlen) {
		      printk(KERN_WARNING
			      "klips_error:ipsec_rcv: "
			      "tried to skb_pull ahhlen=%d, %d available.  This should never happen, please report.\n",
			      ahhlen,
			      (int)(skb->len));
		      spin_lock (&tdb_lock);
		      delRcvDesc_from_salist(tdbp, pRcvDesc);
		      spin_unlock (&tdb_lock);
		      goto rcvleave_cb;
		}
		skb_pull(skb, ahhlen);
		break;
#endif /* CONFIG_IPSEC_AH */
      }

    /* set next header */
    skb->data[PROTO] = next_header; /* Update next header protocol into IP header */

    /*
    * Adjust pointers
    */

    len = skb->len;
    dat = skb->data;

#ifdef NET_21
/*	      skb->h.ipiph=(struct iphdr *)skb->data; */
    skb->nh.raw = skb->data;
    skb->h.raw = skb->nh.raw + (skb->nh.iph->ihl << 2);

    memset(&(IPCB(skb)->opt), 0, sizeof(struct ip_options));
#else /* NET_21 */
    skb->h.iph=(struct iphdr *)skb->data;
    skb->ip_hdr=(struct iphdr *)skb->data;
    memset(skb->proto_priv, 0, sizeof(struct options));
#endif /* NET_21 */

    ipp = (struct iphdr *)dat;
    ipp->check = 0;
    ipp->check = ip_fast_csum((unsigned char *)dat, iphlen >> 2);

    KLIPS_IP_PRINT(debug_rcv & DB_RX_PKTRX, ipp);

    skb->protocol = htons(ETH_P_IP);
    skb->ip_summed = 0;

    tdbprev = tdbp;
      tdbnext = tdbp->tdb_inext;

    if(sysctl_ipsec_inbound_policy_check) {
      if(tdbnext) {
	      if(tdbnext->tdb_onext != tdbp) {
		      if(pRcvDesc->stats) {
			      (pRcvDesc->stats)->rx_dropped++;
		      }
		      spin_lock (&tdb_lock);
		      delRcvDesc_from_salist(tdbp, pRcvDesc);
		      spin_unlock (&tdb_lock);
		      goto rcvleave_cb;
	      }

	      if( ipp->protocol != IPPROTO_AH
		      && ipp->protocol != IPPROTO_ESP
#ifdef CONFIG_IPSEC_IPCOMP
		      && ipp->protocol != IPPROTO_COMP
		      && (tdbnext->tdb_said.proto != IPPROTO_COMP
		      || (tdbnext->tdb_said.proto == IPPROTO_COMP
		      && tdbnext->tdb_inext))
#endif /* CONFIG_IPSEC_IPCOMP */
		      && ipp->protocol != IPPROTO_IPIP
		      ) {
		      if(pRcvDesc->stats) {
			      (pRcvDesc->stats)->rx_dropped++;
		      }
		      spin_lock (&tdb_lock);
		      delRcvDesc_from_salist(tdbp, pRcvDesc);
		      spin_unlock (&tdb_lock);
		      goto rcvleave_cb;
	      }
      }
    }

    /* lock TDB lock */
    spin_lock(&tdb_lock);

#ifdef CONFIG_IPSEC_IPCOMP
    /* update ipcomp ratio counters, even if no ipcomp packet is present */
    if (tdbnext
    && tdbnext->tdb_said.proto == IPPROTO_COMP
    && ipp->protocol != IPPROTO_COMP) {
	tdbnext->tdb_comp_ratio_cbytes += ntohs(ipp->tot_len);
	tdbnext->tdb_comp_ratio_dbytes += ntohs(ipp->tot_len);
    }
#endif /* CONFIG_IPSEC_IPCOMP */

    tdbp->ips_life.ipl_bytes.ipl_count += len;
    tdbp->ips_life.ipl_bytes.ipl_last	= len;

    if(!tdbp->ips_life.ipl_usetime.ipl_count) {
	tdbp->ips_life.ipl_usetime.ipl_count = jiffies / HZ;
    }
    tdbp->ips_life.ipl_usetime.ipl_last = jiffies / HZ;
    tdbp->ips_life.ipl_packets.ipl_count += 1;

    delRcvDesc_from_salist(tdbp, pRcvDesc);
    spin_unlock(&tdb_lock);

    /* begin decapsulating loop here */
    while((ipp->protocol == IPPROTO_ESP )
      || (ipp->protocol == IPPROTO_AH  )
#ifdef CONFIG_IPSEC_IPCOMP
      || (ipp->protocol == IPPROTO_COMP)
#endif /* CONFIG_IPSEC_IPCOMP */
      ){
      authlen = 0;
#ifdef CONFIG_IPSEC_ESP
      espp = NULL;
	ivp = NULL;
	ivlen = 0;
      esphlen = 0;
#endif /* !CONFIG_IPSEC_ESP */
#ifdef CONFIG_IPSEC_AH
      ahp = NULL;
      ahhlen = 0;
#endif /* CONFIG_IPSEC_AH */
#ifdef CONFIG_IPSEC_IPCOMP
      compp = NULL;
#endif /* CONFIG_IPSEC_IPCOMP */

      len = skb->len;
      dat = skb->data;
      ipp = (struct iphdr *)skb->data;
      proto = ipp->protocol;
	ipaddr.s_addr = ipp->saddr;
      addrtoa(ipaddr, 0, ipaddr_txt, sizeof(ipaddr_txt));
      iphlen = ipp->ihl << 2;
      ipp->check = 0;		      /* we know the sum is good */

#ifdef CONFIG_IPSEC_ESP
#endif /* !CONFIG_IPSEC_ESP */

      /*
      * Find tunnel control block and (indirectly) call the
      * appropriate tranform routine. The resulting sk_buf
      * is a valid IP packet ready to go through input processing.
      */

      said.dst.s_addr = ipp->daddr;
      switch(proto) {
#ifdef CONFIG_IPSEC_ESP
	      case IPPROTO_ESP:
		      /* XXX this will need to be 8 for IPv6 */
		      if ((len - iphlen) % 4) {
			      printk("klips_error:ipsec_rcv: "
			      "got packet with content length = %d from %s -- should be on 4 octet boundary, packet dropped\n",
			      len - iphlen,
			      ipaddr_txt);
			      if(pRcvDesc->stats) {
				      (pRcvDesc->stats)->rx_errors++;
			      }
			      goto rcvleave_cb;
		      }

		      if(skb->len < (pRcvDesc->hard_header_len + sizeof(struct iphdr) + sizeof(struct esp))) {
			      KLIPS_PRINT(debug_rcv & DB_RX_INAU,
				      "klips_debug:ipsec_rcv: "
				      "runt esp packet of skb->len=%d received from %s, dropped.\n",
				      skb->len,
				      ipaddr_txt);
			      if(pRcvDesc->stats) {
				      (pRcvDesc->stats)->rx_errors++;
			      }
			      goto rcvleave_cb;
		      }

		      espp = (struct esp *)(skb->data + iphlen);
		      /* Get IV location pointer in payload - after ESP header */
		      ivp = (char *) espp + sizeof (struct esp);
			      said.spi = espp->esp_spi;
		      replay = ntohl(espp->esp_rpl);
		      break;
#endif /* !CONFIG_IPSEC_ESP */
#ifdef CONFIG_IPSEC_AH
	      case IPPROTO_AH:
		      if((skb->len
			      < (pRcvDesc->hard_header_len + sizeof(struct iphdr) + sizeof(struct ah)))
			      || (skb->len
			      < (pRcvDesc->hard_header_len + sizeof(struct iphdr)
			      + ((ahp = (struct ah *) (skb->data + iphlen))->ah_hl << 2)))) {
				      KLIPS_PRINT(debug_rcv & DB_RX_INAU,
					      "klips_debug:ipsec_rcv: "
					      "runt ah packet of skb->len=%d received from %s, dropped.\n",
					      skb->len,
					      ipaddr_txt);
			      if(pRcvDesc->stats) {
				      (pRcvDesc->stats)->rx_errors++;
			      }
			      goto rcvleave_cb;
		      }
		      said.spi = ahp->ah_spi;
		      replay = ntohl(ahp->ah_rpl);
		      ahhlen = (ahp->ah_hl << 2) +
			      ((caddr_t)&(ahp->ah_rpl) - (caddr_t)ahp);
		      next_header = ahp->ah_nh;
		      if (ahhlen != sizeof(struct ah)) {
			      KLIPS_PRINT(debug_rcv & DB_RX_INAU,
					  "klips_debug:ipsec_rcv: "
					  "bad authenticator length %d, expected %d from %s.\n",
					  ahhlen - ((caddr_t)(ahp->ah_data) - (caddr_t)ahp),
					  AHHMAC_HASHLEN,
					  ipaddr_txt);
			      if(pRcvDesc->stats) {
				      (pRcvDesc->stats)->rx_errors++;
			      }
			      goto rcvleave_cb;
		      }
		      break;
#endif /* CONFIG_IPSEC_AH */
#ifdef CONFIG_IPSEC_IPCOMP
	      case IPPROTO_COMP:
		      if(skb->len < (pRcvDesc->hard_header_len + sizeof(struct iphdr) + sizeof(struct ipcomphdr))) {
			      KLIPS_PRINT(debug_rcv & DB_RX_INAU,
					  "klips_debug:ipsec_rcv: "
					  "runt comp packet of skb->len=%d received from %s, dropped.\n",
					  skb->len,
					  ipaddr_txt);
			      if(pRcvDesc->stats) {
				      (pRcvDesc->stats)->rx_errors++;
			      }
			      goto rcvleave_cb;
		      }

		      compp = (struct ipcomphdr *)(skb->data + iphlen);
		      said.spi = htonl((__u32)ntohs(compp->ipcomp_cpi));
		      break;
#endif /* CONFIG_IPSEC_IPCOMP */
	      default:
		      if(pRcvDesc->stats) {
			      (pRcvDesc->stats)->rx_errors++;
		      }
		      goto rcvleave_cb;
      }
      said.proto = proto;

      sa_len = satoa(said, 0, sa, SATOA_BUF);
      if(sa_len == 0) {
	      strcpy(sa, "(error)");
      }


#ifdef CONFIG_IPSEC_IPCOMP
      if (proto == IPPROTO_COMP) {
	      unsigned int flags = 0;

	      if (tdbp == NULL) {
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "Incoming packet with outer IPCOMP header SA:%s: not yet supported by KLIPS, dropped\n",
			      sa_len ? sa : " (error)");
		      if(pRcvDesc->stats) {
			      (pRcvDesc->stats)->rx_dropped++;
		      }
		      goto rcvleave_cb;
	      }


	      tdbprev = tdbp;
	      spin_lock(&tdb_lock);
	      tdbp = tdbnext;

	      /* store current tdbp into rcv descriptor */
	      pRcvDesc->tdbp = tdbp;

	      if(sysctl_ipsec_inbound_policy_check
		      && ((tdbp == NULL)
		      || (((ntohl(tdbp->tdb_said.spi) & 0x0000ffff)
		      != ntohl(said.spi))
		      /* next line is a workaround for peer
		      non-compliance with rfc2393 */
		      && (tdbp->tdb_encalg != ntohl(said.spi))
		      ))) {

		      char sa2[SATOA_BUF];
		      size_t sa_len2 = 0;
		      spin_unlock(&tdb_lock);

		      if(tdbp) {
			      sa_len2 = satoa(tdbp->tdb_said, 0, sa2, SATOA_BUF);
		      }

		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "Incoming packet with SA(IPCA):%s does not match policy SA(IPCA):%s cpi=%04x cpi->spi=%08x spi=%08x, spi->cpi=%04x for SA grouping, dropped.\n",
			      sa_len ? sa : " (error)",
			      tdbp ? (sa_len2 ? sa2 : " (error)") : "NULL",
			      ntohs(compp->ipcomp_cpi),
			      (__u32)ntohl(said.spi),
			      tdbp ? (__u32)ntohl((tdbp->tdb_said.spi)) : 0,
			      tdbp ? (__u16)(ntohl(tdbp->tdb_said.spi) & 0x0000ffff) : 0);
		      if(pRcvDesc->stats) {
			      (pRcvDesc->stats)->rx_dropped++;
		      }
		      goto rcvleave_cb;
	      }

	      next_header = compp->ipcomp_nh;

	      if (tdbp) {
		      addRcvDesc_to_salist(tdbp, pRcvDesc);
		      tdbp->tdb_comp_ratio_cbytes += ntohs(ipp->tot_len);
		      tdbnext = tdbp->tdb_inext;
	      }

	      skb = skb_decompress(skb, tdbp, &flags);
	      if (!skb || flags) {
		      delRcvDesc_from_salist(tdbp, pRcvDesc);
		      spin_unlock(&tdb_lock);
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "skb_decompress() returned error flags=%x, dropped.\n",
			      flags);
		      if (pRcvDesc->stats) {
			      if (flags)
				      (pRcvDesc->stats)->rx_errors++;
			      else
				  (pRcvDesc->stats)->rx_dropped++;
		      }
		      goto rcvleave_cb;
	      }
#ifdef NET_21
	      ipp = skb->nh.iph;
#else /* NET_21 */
	      ipp = skb->ip_hdr;
#endif /* NET_21 */

	      if (tdbp) {
		      tdbp->tdb_comp_ratio_dbytes += ntohs(ipp->tot_len);
		      delRcvDesc_from_salist(tdbp, pRcvDesc);
	      }

	      KLIPS_PRINT(debug_rcv,
		      "klips_debug:ipsec_rcv: "
		      "packet decompressed SA(IPCA):%s cpi->spi=%08x spi=%08x, spi->cpi=%04x, nh=%d.\n",
		      sa_len ? sa : " (error)",
		      (__u32)ntohl(said.spi),
		      tdbp ? (__u32)ntohl((tdbp->tdb_said.spi)) : 0,
		      tdbp ? (__u16)(ntohl(tdbp->tdb_said.spi) & 0x0000ffff) : 0,
		      next_header);
	      KLIPS_IP_PRINT(debug_rcv & DB_RX_PKTRX, ipp);

	      spin_unlock(&tdb_lock);

	      continue;
	    /* Skip rest of stuff and decapsulate next inner
			 packet, if any */
      }
#endif /* CONFIG_IPSEC_IPCOMP */

      tdbp = ipsec_sa_getbyid(&said);
	pRcvDesc->tdbp = tdbp;

      if (tdbp == NULL) {
	      KLIPS_PRINT(debug_rcv,
		      "klips_debug:ipsec_rcv: "
		      "no Tunnel Descriptor Block for SA:%s: incoming packet with no SA dropped\n",
		      sa_len ? sa : " (error)");
	      if(pRcvDesc->stats) {
		      (pRcvDesc->stats)->rx_dropped++;
	      }
	      goto rcvleave_cb;
      }

	spin_lock(&tdb_lock);
	addRcvDesc_to_salist(tdbp, pRcvDesc);
	
#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
		if ((natt_type) &&
			( (ipp->saddr != (((struct sockaddr_in*)(tdbp->tdb_addr_s))->sin_addr.s_addr)) ||
			  (natt_sport != tdbp->ips_natt_sport)
			)) {
			struct sockaddr sipaddr;
			/** Advertise NAT-T addr change to pluto **/
			sipaddr.sa_family = AF_INET;
			((struct sockaddr_in*)&sipaddr)->sin_addr.s_addr = ipp->saddr;
			((struct sockaddr_in*)&sipaddr)->sin_port = htons(natt_sport);
			pfkey_nat_t_new_mapping(tdbp, &sipaddr, natt_sport);
			/**
			 * Then allow or block packet depending on
			 * sysctl_ipsec_inbound_policy_check.
			 *
			 * In all cases, pluto will update SA if new mapping is
			 * accepted.
			 */
			if (sysctl_ipsec_inbound_policy_check) {
				spin_unlock(&tdb_lock);
				ipaddr.s_addr = ipp->saddr;
				addrtoa(ipaddr, 0, ipaddr_txt, sizeof(ipaddr_txt));
				KLIPS_PRINT(debug_rcv,
					"klips_debug:ipsec_rcv: "
					"SA:%s, src=%s:%u of pkt does not agree with expected "
					"SA source address policy (pluto has been informed).\n",
					sa_len ? sa : " (error)",
					ipaddr_txt, natt_sport);
				if(pRcvDesc->stats) {
					pRcvDesc->stats->rx_dropped++;
				}
				goto rcvleave_cb;
			}
		}
#endif

      if(sysctl_ipsec_inbound_policy_check) {
	      if(ipp->saddr != ((struct sockaddr_in*)(tdbp->tdb_addr_s))->sin_addr.s_addr) {
		      delRcvDesc_from_salist(tdbp, pRcvDesc);
		      spin_unlock(&tdb_lock);
		      ipaddr.s_addr = ipp->saddr;
		      addrtoa(ipaddr, 0, ipaddr_txt, sizeof(ipaddr_txt));

		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "SA:%s, src=%s of pkt does not agree with expected SA source address policy.\n",
			      sa_len ? sa : " (error)",
			      ipaddr_txt);
		      if(pRcvDesc->stats) {
			      (pRcvDesc->stats)->rx_dropped++;
		      }
		      goto rcvleave_cb;
	      }

	      ipaddr.s_addr = ipp->saddr;
	      addrtoa(ipaddr, 0, ipaddr_txt, sizeof(ipaddr_txt));
	      KLIPS_PRINT(debug_rcv,
		      "klips_debug:ipsec_rcv: "
		      "SA:%s, src=%s of pkt agrees with expected SA source address policy.\n",
		      sa_len ? sa : " (error)",
		      ipaddr_txt);
	      if(tdbnext) {
		      if(tdbnext != tdbp) {
			      delRcvDesc_from_salist(tdbp, pRcvDesc);
			      spin_unlock(&tdb_lock);
			      KLIPS_PRINT(debug_rcv,
				      "klips_debug:ipsec_rcv: "
				      "unexpected SA:%s: does not agree with tdb->inext policy, dropped\n",
				      sa_len ? sa : " (error)");
			      if(pRcvDesc->stats) {
				      (pRcvDesc->stats)->rx_dropped++;
			      }
			      goto rcvleave_cb;
		      }
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "SA:%s grouping from previous SA is OK.\n",
			      sa_len ? sa : " (error)");
	      } else {
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "SA:%s First SA in group.\n",
			      sa_len ? sa : " (error)");
	      }

	      if(tdbp->tdb_onext) {
		      if(tdbprev != tdbp->tdb_onext) {
			      delRcvDesc_from_salist(tdbp, pRcvDesc);
			      spin_unlock(&tdb_lock);
			      KLIPS_PRINT(debug_rcv,
				      "klips_debug:ipsec_rcv: "
				      "unexpected SA:%s: does not agree with tdb->onext policy, dropped.\n",
				      sa_len ? sa : " (error)");
			      if(pRcvDesc->stats) {
				      (pRcvDesc->stats)->rx_dropped++;
			      }
			      goto rcvleave_cb;
		      } else {
			      KLIPS_PRINT(debug_rcv,
				      "klips_debug:ipsec_rcv: "
				      "SA:%s grouping to previous SA is OK.\n",
				      sa_len ? sa : " (error)");
		      }
	      } else {
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "SA:%s No previous backlink in group.\n",
			      sa_len ? sa : " (error)");
	      }
#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
			KLIPS_PRINT(debug_rcv,
				"klips_debug:ipsec_rcv: "
				"natt_type=%u tdbp->ips_natt_type=%u : %s\n",
				natt_type, tdbp->ips_natt_type,
				(natt_type==tdbp->ips_natt_type)?"ok":"bad");
			if (natt_type != tdbp->ips_natt_type) {
				spin_unlock(&tdb_lock);
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "SA:%s does not agree with expected NAT-T policy.\n",
					    sa_len ? sa : " (error)");
				if(pRcvDesc->stats) {
					pRcvDesc->stats->rx_dropped++;
				}
				goto rcvleave_cb;
			}
#endif
      }

      /* If it is in larval state, drop the packet, we cannot process yet. */
      if(tdbp->ips_state == SADB_SASTATE_LARVAL) {
	      delRcvDesc_from_salist(tdbp, pRcvDesc);
	      spin_unlock(&tdb_lock);
	      KLIPS_PRINT(debug_rcv,
		      "klips_debug:ipsec_rcv: "
		      "TDB in larval state, cannot be used yet, dropping packet.\n");
	      if(pRcvDesc->stats) {
		      (pRcvDesc->stats)->rx_dropped++;
	      }
	      goto rcvleave_cb;
      }

      if(tdbp->ips_state == SADB_SASTATE_DEAD) {
	      delRcvDesc_from_salist(tdbp, pRcvDesc);
	      KLIPS_PRINT(debug_rcv,
		      "klips_debug:ipsec_rcv: "
		      "TDB in dead state, cannot be used any more, dropping packet.\n");
	      if(pRcvDesc->stats) {
		      (pRcvDesc->stats)->rx_dropped++;
	      }
	      if(tdbp->ips_teardown_initiated == 1)
		      ipsec_sa_delchain(tdbp);
	      spin_unlock(&tdb_lock);
	      goto rcvleave_cb;
      }

      if(ipsec_lifetime_check(&tdbp->ips_life.ipl_bytes,   "bytes", sa,
			      ipsec_life_countbased, ipsec_incoming, tdbp) == ipsec_life_harddied ||
      ipsec_lifetime_check(&tdbp->ips_life.ipl_addtime, "addtime",sa,
			      ipsec_life_timebased,  ipsec_incoming, tdbp) == ipsec_life_harddied ||
      ipsec_lifetime_check(&tdbp->ips_life.ipl_addtime, "usetime",sa,
			      ipsec_life_timebased,  ipsec_incoming, tdbp) == ipsec_life_harddied ||
      ipsec_lifetime_check(&tdbp->ips_life.ipl_packets, "packets",sa,
			      ipsec_life_countbased, ipsec_incoming, tdbp) == ipsec_life_harddied){
	      delRcvDesc_from_salist(tdbp, pRcvDesc);
	      ipsec_sa_delchain(tdbp);
	      spin_unlock(&tdb_lock);
	      if(pRcvDesc->stats) {
		      (pRcvDesc->stats)->rx_dropped++;
	      }
	      goto rcvleave_cb;
      }

	if (!ipsec_checkreplaywindow(tdbp, replay)) {
	      tdbp->tdb_replaywin_errs += 1;
	      delRcvDesc_from_salist(tdbp, pRcvDesc);
	      spin_unlock(&tdb_lock);
	      KLIPS_PRINT(debug_rcv & DB_RX_REPLAY,
		      "klips_debug:ipsec_rcv: "
		      "duplicate frame from %s, packet dropped\n",
		      ipaddr_txt);
	      if(pRcvDesc->stats) {
		      (pRcvDesc->stats)->rx_dropped++;
	      }
	      goto rcvleave_cb;
      }

      KLIPS_PRINT(debug_rcv,
	      "klips_debug:ipsec_rcv: "
	      "encalg = %d, authalg = %d.\n",
	      tdbp->tdb_encalg,
	      tdbp->tdb_authalg);

      /* If the sequence number == 0, expire SA, it had rolled */
      if(tdbp->tdb_replaywin && !replay /* !tdbp->tdb_replaywin_lastseq */) {
	      delRcvDesc_from_salist(tdbp, pRcvDesc);
	      ipsec_sa_delchain(tdbp);
	      spin_unlock(&tdb_lock);
	      KLIPS_PRINT(debug_rcv,
		      "klips_debug:ipsec_rcv: "
		      "replay window counter rolled, expiring SA.\n");
	      if(pRcvDesc->stats) {
		      (pRcvDesc->stats)->rx_dropped++;
	      }
	      goto rcvleave_cb;
      }

	spin_unlock(&tdb_lock);


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
		      authlen = 0;
		      break;
	      default:
		      spin_lock(&tdb_lock);
		      delRcvDesc_from_salist(tdbp, pRcvDesc);
		      tdbp->tdb_alg_errs += 1;
		      spin_unlock(&tdb_lock);
		      if(pRcvDesc->stats) {
			      (pRcvDesc->stats)->rx_errors++;
		      }
		      goto rcvleave_cb;
      }

#ifdef CONFIG_IPSEC_ESP
      KLIPS_PRINT(proto == IPPROTO_ESP && debug_rcv,
	      "klips_debug:ipsec_rcv: "
	      "packet from %s received with seq=%d (iv)=0x%08x%08x%8x%8x iplen=%d esplen=%d sa=%s\n",
	      ipaddr_txt,
	      (__u32)ntohl(espp->esp_rpl),
	      (__u32)ntohl(*((__u32 *)(ivp)    )),
	      (__u32)ntohl(*((__u32 *)(ivp) + 1)),
	      (__u32)ntohl(*((__u32 *)(ivp) + 2)),
	      (__u32)ntohl(*((__u32 *)(ivp) + 3)),
	      len,
	      auth_data_len,
	      sa_len ? sa : " (error)");
#endif /* !CONFIG_IPSEC_ESP */

      switch(proto) {
#ifdef CONFIG_IPSEC_ESP
	      case IPPROTO_ESP:
/*
		 AFTER APPLYING ESP
	    -------------------------------------------------
      IPv4  |orig IP hdr  | ESP |     |      |   ESP   | ESP|
	    |(any options)| Hdr | TCP | Data | Trailer |Auth|
	    -------------------------------------------------
				|<----- encrypted ---->|
			  |<------ authenticated ----->|
*/

		      esphlen = sizeof(struct esp);
		      ivlen = tdbp->ips_iv_size;
		      /* Keep IV length in descriptor for callback use */
		      pRcvDesc->ivlen = ivlen;
		      auth_start_offset = iphlen;
		      auth_data_len = len - iphlen - authlen;
		      icv_offset = len - authlen;
		      crypt_start_offset = iphlen + esphlen + ivlen; /* IV is not included as payload for encryption */
		      crypt_data_len = len - iphlen - authlen - esphlen - ivlen;

		      if ((crypt_data_len) % 8) {
			      spin_lock(&tdb_lock);
			      delRcvDesc_from_salist(tdbp, pRcvDesc);
			      tdbp->tdb_encsize_errs += 1;
			      spin_unlock(&tdb_lock);
			      if(pRcvDesc->stats) {
				      (pRcvDesc->stats)->rx_errors++;
			      }
			      goto rcvleave_cb;
		      }

		      switch(tdbp->tdb_encalg) {
# ifdef CONFIG_IPSEC_ENC_DES
			      case ESP_DES:
				      memcpy (iv, ivp, ivlen);
				      break;
# endif /* CONFIG_IPSEC_ENC_DES */
#ifdef CONFIG_IPSEC_ENC_3DES
			      case ESP_3DES:
				      memcpy (iv, ivp, ivlen);
				      break;
#endif /* CONFIG_IPSEC_ENC_3DES */
#ifdef CONFIG_IPSEC_ALG
			      case ESP_AES:
				      memcpy (iv, ivp, ivlen);
				      break;
#endif /* CONFIG_IPSEC_ALG */
			      default:
				      spin_lock(&tdb_lock);
				      delRcvDesc_from_salist(tdbp, pRcvDesc);
				      tdbp->tdb_alg_errs += 1;
				      spin_unlock(&tdb_lock);
				      if(pRcvDesc->stats) {
					      (pRcvDesc->stats)->rx_errors++;
				      }
				      goto rcvleave_cb;
			      }
		      break;
#endif /* !CONFIG_IPSEC_ESP */
#ifdef CONFIG_IPSEC_AH
	      case IPPROTO_AH:
/*
		  AFTER APPLYING AH
	    ---------------------------------
      IPv4  |orig IP hdr  |    |     |      |
	    |(any options)| AH | TCP | Data |
	    ---------------------------------
	    |<------- authenticated ------->|
		 except for mutable fields
*/

		      auth_start_offset = 0; /* start at the beginning */
		      auth_data_len = len;
		      icv_offset = iphlen + AUTH_DATA_IN_AH_OFFSET;

		      /* IXP425 glue code : mutable field, need to keep a copy of original IP header and
		      restore the original IP header after callback received.
		      Modify the mutable fields in header*/
		      pRcvDesc->ip_frag_off = ipp->frag_off;
		      pRcvDesc->ip_ttl = ipp->ttl;
		      ipp->frag_off = 0;
		      ipp->ttl = 0;
		      ipp->check = 0;
		      break;
#endif /* CONFIG_IPSEC_AH */
      }

      if(auth_data_len <= 0) {
	      spin_lock (&tdb_lock);
	      delRcvDesc_from_salist(tdbp, pRcvDesc);
	      spin_unlock (&tdb_lock);
	      KLIPS_PRINT(debug_rcv,
		      "klips_debug:ipsec_rcv: "
		      "runt AH packet with no data, dropping.\n");
	      if(pRcvDesc->stats) {
		      (pRcvDesc->stats)->rx_dropped++;
	      }
	      goto rcvleave_cb;
      }

	/* IXP425 glue code */
#if defined(CONFIG_IPSEC_AH) || defined(CONFIG_IPSEC_ESP)
	if ((proto == IPPROTO_AH) || (proto == IPPROTO_ESP))
	{
	      /* store ICV_offset */
	      pRcvDesc->icv_offset = icv_offset;

	      /* get mbuf */
	      if(IPSEC_GLUE_STATUS_SUCCESS != ipsec_glue_mbuf_header_get(&src_mbuf))
	      {
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "running out of mbufs, dropped\n");
		      spin_lock (&tdb_lock);
		      delRcvDesc_from_salist(tdbp, pRcvDesc);
		      spin_unlock (&tdb_lock);
		      if(pRcvDesc->stats) {
			      (pRcvDesc->stats)->rx_dropped++;
		      }
		      goto rcvleave_cb;
	      }

	      /* attach mbuf to sk_buff */
	      mbuf_swap_skb(src_mbuf, skb);

	      /* store rcv desc in mbuf */
	      (IpsecRcvDesc *) IX_MBUF_NEXT_PKT_IN_CHAIN_PTR (src_mbuf) = pRcvDesc;

	      /* call crypto perform */
	      if (IX_CRYPTO_ACC_STATUS_SUCCESS != ixCryptoAccAuthCryptPerform (
		      tdbp->ips_crypto_context_id,
		      src_mbuf,
		      NULL,
		      auth_start_offset,
		      auth_data_len,
		      crypt_start_offset,
		      crypt_data_len,
		      icv_offset,
		      iv))
	      {
		      spin_lock(&tdb_lock);
		      delRcvDesc_from_salist(tdbp, pRcvDesc);
		      spin_unlock(&tdb_lock);
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "warning, decrapsulation packet from %s cannot be started\n",
			      ipaddr_txt);

		      ipsec_glue_mbuf_header_rel(src_mbuf);

		      if(pRcvDesc->stats) {
			      (pRcvDesc->stats)->rx_dropped++;
		      }
		      goto rcvleave_cb;
	      }
	      return;
	} /* end of if ((proto == IPPROTO_AH) || (proto == IPPROTO_ESP))*/
#endif /* defined(CONFIG_IPSEC_AH) || defined(CONFIG_IPSEC_ESP)*/

	/* set next header */
	skb->data[PROTO] = next_header;

      /*
      *       Adjust pointers
      */

      len = skb->len;
      dat = skb->data;

#ifdef NET_21
      /* skb->h.ipiph=(struct iphdr *)skb->data; */
      skb->nh.raw = skb->data;
      skb->h.raw = skb->nh.raw + (skb->nh.iph->ihl << 2);

      memset(&(IPCB(skb)->opt), 0, sizeof(struct ip_options));
#else /* NET_21 */
      skb->h.iph=(struct iphdr *)skb->data;
      skb->ip_hdr=(struct iphdr *)skb->data;
      memset(skb->proto_priv, 0, sizeof(struct options));
#endif /* NET_21 */

      ipp = (struct iphdr *)dat;
      ipp->check = 0;
      ipp->check = ip_fast_csum((unsigned char *)dat, iphlen >> 2);

      KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
	      "klips_debug:ipsec_rcv: "
	      "after <%s%s%s>, SA:%s:\n",
	      IPS_XFORM_NAME(tdbp),
	      sa_len ? sa : " (error)");
      KLIPS_IP_PRINT(debug_rcv & DB_RX_PKTRX, ipp);

      skb->protocol = htons(ETH_P_IP);
      skb->ip_summed = 0;

      tdbprev = tdbp;
      tdbnext = tdbp->tdb_inext;

	spin_lock (&tdb_lock);

      if(sysctl_ipsec_inbound_policy_check) {
	      if(tdbnext) {
		      if(tdbnext->tdb_onext != tdbp) {
			      delRcvDesc_from_salist(tdbp, pRcvDesc);
			      spin_unlock(&tdb_lock);
			      KLIPS_PRINT(debug_rcv,
				      "klips_debug:ipsec_rcv: "
				      "SA:%s, backpolicy does not agree with fwdpolicy.\n",
				      sa_len ? sa : " (error)");
			      if(pRcvDesc->stats) {
				      (pRcvDesc->stats)->rx_dropped++;
			      }
			      goto rcvleave_cb;
		      }
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "SA:%s, backpolicy agrees with fwdpolicy.\n",
			      sa_len ? sa : " (error)");
		      if(
#ifdef CONFIG_IPSEC_IPCOMP
			      ipp->protocol != IPPROTO_COMP
			      && (tdbnext->tdb_said.proto != IPPROTO_COMP
			      || (tdbnext->tdb_said.proto == IPPROTO_COMP
			      && tdbnext->tdb_inext))
#endif /* CONFIG_IPSEC_IPCOMP */
			      && ipp->protocol != IPPROTO_IPIP
			      ) {
			      delRcvDesc_from_salist(tdbp, pRcvDesc);
			      spin_unlock(&tdb_lock);
			      KLIPS_PRINT(debug_rcv,
				      "klips_debug:ipsec_rcv: "
				      "packet with incomplete policy dropped, last successful SA:%s.\n",
				      sa_len ? sa : " (error)");
			      if(pRcvDesc->stats) {
				      (pRcvDesc->stats)->rx_dropped++;
			      }
			      goto rcvleave_cb;
		      }
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "SA:%s, Another IPSEC header to process.\n",
			      sa_len ? sa : " (error)");
	      } else {
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "No tdb_inext from this SA:%s.\n",
			      sa_len ? sa : " (error)");
	      } /* end of if(tdbnext)*/
      } /* end of if(sysctl_ipsec_inbound_policy_check) */

#ifdef CONFIG_IPSEC_IPCOMP
      /* update ipcomp ratio counters, even if no ipcomp packet is present */
      if (tdbnext
	      && tdbnext->tdb_said.proto == IPPROTO_COMP
	      && ipp->protocol != IPPROTO_COMP) {
	      tdbnext->tdb_comp_ratio_cbytes += ntohs(ipp->tot_len);
	      tdbnext->tdb_comp_ratio_dbytes += ntohs(ipp->tot_len);
      }
#endif /* CONFIG_IPSEC_IPCOMP */

      tdbp->ips_life.ipl_bytes.ipl_count += len;
      tdbp->ips_life.ipl_bytes.ipl_last   = len;

      if(!tdbp->ips_life.ipl_usetime.ipl_count) {
	      tdbp->ips_life.ipl_usetime.ipl_count = jiffies / HZ;
      }
      tdbp->ips_life.ipl_usetime.ipl_last = jiffies / HZ;
      tdbp->ips_life.ipl_packets.ipl_count += 1;
      delRcvDesc_from_salist(tdbp, pRcvDesc);
      spin_unlock(&tdb_lock);
    } /* end decapsulation loop here */

    spin_lock(&tdb_lock);
    addRcvDesc_to_salist(tdbp, pRcvDesc);

#ifdef CONFIG_IPSEC_IPCOMP
    if(tdbnext && tdbnext->tdb_said.proto == IPPROTO_COMP) {
      tdbprev = tdbp;
      delRcvDesc_from_salist(tdbp, pRcvDesc);
      tdbp = tdbnext;
      pRcvDesc->tdbp = tdbp;
      addRcvDesc_to_salist(tdbp, pRcvDesc);
      tdbnext = tdbp->tdb_inext;
    }
#endif /* CONFIG_IPSEC_IPCOMP */

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	if ((natt_type) && (ipp->protocol != IPPROTO_IPIP)) {
		/**
		 * NAT-Traversal and Transport Mode:
		 *   we need to correct TCP/UDP checksum
		 *
		 * If we've got NAT-OA, we can fix checksum without recalculation.
		 */
		__u32 natt_oa = tdbp->ips_natt_oa ?
			((struct sockaddr_in*)(tdbp->ips_natt_oa))->sin_addr.s_addr : 0;
		__u16 pkt_len = skb->tail - (unsigned char *)ipp;
		__u16 data_len = pkt_len - (ipp->ihl << 2);

		switch (ipp->protocol) {
			case IPPROTO_TCP:
				if (data_len >= sizeof(struct tcphdr)) {
					struct tcphdr *tcp = (struct tcphdr *)((__u32 *)ipp+ipp->ihl);
					if (natt_oa) {
						__u32 buff[2] = { ~natt_oa, ipp->saddr };
						KLIPS_PRINT(debug_rcv,
				    		"klips_debug:ipsec_rcv: "
							"NAT-T & TRANSPORT: "
							"fix TCP checksum using NAT-OA\n");
						tcp->check = csum_fold(
							csum_partial((unsigned char *)buff, sizeof(buff),
							tcp->check^0xffff));
					}
					else {
						KLIPS_PRINT(debug_rcv,
			    			"klips_debug:ipsec_rcv: "
							"NAT-T & TRANSPORT: recalc TCP checksum\n");
						if (pkt_len > (ntohs(ipp->tot_len)))
							data_len -= (pkt_len - ntohs(ipp->tot_len));
						tcp->check = 0;
						tcp->check = csum_tcpudp_magic(ipp->saddr, ipp->daddr,
							data_len, IPPROTO_TCP,
							csum_partial((unsigned char *)tcp, data_len, 0));
					}
				}
				else {
					KLIPS_PRINT(debug_rcv,
			    		"klips_debug:ipsec_rcv: "
						"NAT-T & TRANSPORT: can't fix TCP checksum\n");
				}
				break;
			case IPPROTO_UDP:
				if (data_len >= sizeof(struct udphdr)) {
					struct udphdr *udp = (struct udphdr *)((__u32 *)ipp+ipp->ihl);
					if (udp->check == 0) {
						KLIPS_PRINT(debug_rcv,
				    		"klips_debug:ipsec_rcv: "
							"NAT-T & TRANSPORT: UDP checksum already 0\n");
					}
					else if (natt_oa) {
						__u32 buff[2] = { ~natt_oa, ipp->saddr };
						KLIPS_PRINT(debug_rcv,
				    		"klips_debug:ipsec_rcv: "
							"NAT-T & TRANSPORT: "
							"fix UDP checksum using NAT-OA\n");
						udp->check = csum_fold(
							csum_partial((unsigned char *)buff, sizeof(buff),
							udp->check^0xffff));
					}
					else {
						KLIPS_PRINT(debug_rcv,
				    		"klips_debug:ipsec_rcv: "
							"NAT-T & TRANSPORT: zero UDP checksum\n");
						udp->check = 0;
					}
				}
				else {
					KLIPS_PRINT(debug_rcv,
			    		"klips_debug:ipsec_rcv: "
						"NAT-T & TRANSPORT: can't fix UDP checksum\n");
				}
				break;
			default:
				KLIPS_PRINT(debug_rcv,
			    	"klips_debug:ipsec_rcv: "
					"NAT-T & TRANSPORT: non TCP/UDP packet -- do nothing\n");
				break;
		}
	}
#endif

   /*
    * XXX this needs to be locked from when it was first looked
    * up in the decapsulation loop.  Perhaps it is better to put
    * the IPIP decap inside the loop.
    */
    if(tdbnext) {
      delRcvDesc_from_salist(tdbp, pRcvDesc);
      tdbp = tdbnext;
      addRcvDesc_to_salist(tdbp, pRcvDesc);
      pRcvDesc->tdbp = tdbp;


#ifdef CONFIG_IPSEC_DEBUG
      sa_len = satoa(tdbp->tdb_said, 0, sa, SATOA_BUF);
#endif /* CONFIG_IPSEC_DEBUG */
      if(ipp->protocol != IPPROTO_IPIP) {
	      delRcvDesc_from_salist(tdbp, pRcvDesc);
	      spin_unlock(&tdb_lock);
	      KLIPS_PRINT(debug_rcv,
		      "klips_debug:ipsec_rcv: "
		      "SA:%s, Hey!  How did this get through?  Dropped.\n",
		      sa_len ? sa : " (error)");
	      if(pRcvDesc->stats) {
		      (pRcvDesc->stats)->rx_dropped++;
	      }
	      goto rcvleave_cb;
      }
      if(sysctl_ipsec_inbound_policy_check) {
	      tdbnext = tdbp->tdb_inext;
	      if(tdbnext) {
		      char sa2[SATOA_BUF];
		      size_t sa_len2;
		      sa_len2 = satoa(tdbnext->tdb_said, 0, sa2, SATOA_BUF);
		      delRcvDesc_from_salist(tdbp, pRcvDesc);
		      spin_unlock(&tdb_lock);
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "unexpected SA:%s after IPIP SA:%s\n",
			      sa_len2 ? sa2 : " (error)",
			      sa_len ? sa : " (error)");
		      if(pRcvDesc->stats) {
			      (pRcvDesc->stats)->rx_dropped++;
		      }
		      goto rcvleave_cb;
	      }
	      if(ipp->saddr != ((struct sockaddr_in*)(tdbp->tdb_addr_s))->sin_addr.s_addr) {
		      delRcvDesc_from_salist(tdbp, pRcvDesc);
		      spin_unlock(&tdb_lock);
		      ipaddr.s_addr = ipp->saddr;
		      addrtoa(ipaddr, 0, ipaddr_txt, sizeof(ipaddr_txt));
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "SA:%s, src=%s of pkt does not agree with expected SA source address policy.\n",
			      sa_len ? sa : " (error)",
			      ipaddr_txt);
		      if(pRcvDesc->stats) {
			      (pRcvDesc->stats)->rx_dropped++;
		      }
		      goto rcvleave_cb;
	      }
      } /* end of if(sysctl_ipsec_inbound_policy_check) */

      /*
      * XXX this needs to be locked from when it was first looked
      * up in the decapsulation loop.  Perhaps it is better to put
      * the IPIP decap inside the loop.
      */
      tdbp->ips_life.ipl_bytes.ipl_count += len;
      tdbp->ips_life.ipl_bytes.ipl_last   = len;

      if(!tdbp->ips_life.ipl_usetime.ipl_count) {
	      tdbp->ips_life.ipl_usetime.ipl_count = jiffies / HZ;
      }
      tdbp->ips_life.ipl_usetime.ipl_last = jiffies / HZ;
      tdbp->ips_life.ipl_packets.ipl_count += 1;

      if(skb->len < iphlen) {
	      printk(KERN_WARNING "klips_debug:ipsec_rcv: "
		      "tried to skb_pull iphlen=%d, %d available.  This should never happen, please report.\n",
		      iphlen,
		      (int)(skb->len));

	      delRcvDesc_from_salist(tdbp, pRcvDesc);
	      spin_unlock (&tdb_lock);
	      goto rcvleave_cb;
      }
      skb_pull(skb, iphlen);

#ifdef NET_21
      ipp = (struct iphdr *)skb->nh.raw = skb->data;
      skb->h.raw = skb->nh.raw + (skb->nh.iph->ihl << 2);

      memset(&(IPCB(skb)->opt), 0, sizeof(struct ip_options));
#else /* NET_21 */
      ipp = skb->ip_hdr = skb->h.iph = (struct iphdr *)skb->data;

      memset(skb->proto_priv, 0, sizeof(struct options));
#endif /* NET_21 */

      skb->protocol = htons(ETH_P_IP);
      skb->ip_summed = 0;
      KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
	      "klips_debug:ipsec_rcv: "
	      "IPIP tunnel stripped.\n");
      KLIPS_IP_PRINT(debug_rcv & DB_RX_PKTRX, ipp);

      if(sysctl_ipsec_inbound_policy_check
      /*
	      Note: "xor" (^) logically replaces "not equal"
	      (!=) and "bitwise or" (|) logically replaces
	      "boolean or" (||).  This is done to speed up
	      execution by doing only bitwise operations and
	      no branch operations
      */
	      && (((ipp->saddr & tdbp->tdb_mask_s.u.v4.sin_addr.s_addr)
	      ^ tdbp->tdb_flow_s.u.v4.sin_addr.s_addr)
	      | ((ipp->daddr & tdbp->tdb_mask_d.u.v4.sin_addr.s_addr)
	      ^ tdbp->tdb_flow_d.u.v4.sin_addr.s_addr)) )
      {
	      struct in_addr daddr, saddr;
	      char saddr_txt[ADDRTOA_BUF], daddr_txt[ADDRTOA_BUF];
	      char sflow_txt[SUBNETTOA_BUF], dflow_txt[SUBNETTOA_BUF];

	      subnettoa(tdbp->tdb_flow_s.u.v4.sin_addr,
	      tdbp->tdb_mask_s.u.v4.sin_addr,
	      0, sflow_txt, sizeof(sflow_txt));
	      subnettoa(tdbp->tdb_flow_d.u.v4.sin_addr,
	      tdbp->tdb_mask_d.u.v4.sin_addr,
	      0, dflow_txt, sizeof(dflow_txt));
	      saddr.s_addr = ipp->saddr;
	      daddr.s_addr = ipp->daddr;
	      addrtoa(saddr, 0, saddr_txt, sizeof(saddr_txt));
	      addrtoa(daddr, 0, daddr_txt, sizeof(daddr_txt));
	      KLIPS_PRINT(debug_rcv,
		      "klips_debug:ipsec_rcv: "
		      "SA:%s, inner tunnel policy [%s -> %s] does not agree with pkt contents [%s -> %s].\n",
		      sa_len ? sa : " (error)",
		      sflow_txt,
		      dflow_txt,
		      saddr_txt,
		      daddr_txt);
	      if(pRcvDesc->stats) {
		      (pRcvDesc->stats)->rx_dropped++;
	      }
	      delRcvDesc_from_salist(tdbp, pRcvDesc);
	      spin_unlock (&tdb_lock);
	      goto rcvleave_cb;
      }
    } /* end of if(tdbnext) */

    delRcvDesc_from_salist(tdbp, pRcvDesc);
    spin_unlock(&tdb_lock);


#ifdef INBOUND_POLICY_CHECK_eroute
    /*
    Do *not* enable this without thoroughly checking spinlock issues
    first.  In particular, nesting an eroute spinlock within a tdb
    spinlock could result in a deadlock.  (Well, only on a SMP machine
    under 2.4?)
    */
    
    /*
    * First things first -- look us up in the erouting tables.
    */
    matcher.sen_len = sizeof (struct sockaddr_encap);
    matcher.sen_family = AF_ENCAP;
    matcher.sen_type = SENT_IP4;
    if(ipp->protocol == IPPROTO_IPIP) {
      struct iphdr *ipp2;

      ipp2 = (struct iphdr*) (((char*)ipp) + (ipp->ihl << 2));
      matcher.sen_ip_src.s_addr = ipp2->saddr;
      matcher.sen_ip_dst.s_addr = ipp2->daddr;
    } else {
      matcher.sen_ip_src.s_addr = ipp->saddr;
      matcher.sen_ip_dst.s_addr = ipp->daddr;
    }

    /*
    * The spinlock is to prevent any other process from accessing or
    * deleting the eroute while we are using and updating it.
    */
    spin_lock(&eroute_lock);
    
    er = ipsec_findroute(&matcher);
    if(er) {
      policy_said = er->er_said;
      policy_eaddr = er->er_eaddr;
      policy_emask = er->er_emask;
      er->er_count++;
      er->er_lasttime = jiffies/HZ;
    }

    spin_unlock(&eroute_lock);

    if(er) {
      /*
      * The spinlock is to prevent any other process from
      * accessing or deleting the tdb while we are using and
      * updating it.
      */
      spin_lock(&tdb_lock);

      policy_tdb = gettdb(&policy_said);
      if (policy_tdb == NULL) {
	      spin_unlock(&tdb_lock);
	      KLIPS_PRINT(debug_rcv,
		      "klips_debug:ipsec_rcv: "
		      "no Tunnel Descriptor Block for SA%s: incoming packet with no policy SA, dropped.\n",
		      sa_len ? sa : " (error)");
	      goto rcvleave_cb;
      }

      sa_len = satoa(policy_said, 0, sa, SATOA_BUF);

      KLIPS_PRINT(debug_rcv,
	      "klips_debug:ipsec_rcv: "
	      "found policy Tunnel Descriptor Block -- SA:%s\n",
	      sa_len ? sa : " (error)");
      while(1) {
	      if(policy_tdb->tdb_inext) {
		      policy_tdb = policy_tdb->tdb_inext;
	      } else {
		      break;
	      }
      }

      if(policy_tdb != tdbp) {
	      spin_unlock(&tdb_lock);
	      KLIPS_PRINT(debug_rcv,
		      "klips_debug:ipsec_rcv: "
		      "Tunnel Descriptor Block for SA%s: incoming packet with different policy SA, dropped.\n",
		      sa_len ? sa : " (error)");
	      goto rcvleave_cb;
      }

      spin_unlock(&tdb_lock);
    } /* end of if(er) */
#endif /* INBOUND_POLICY_CHECK_eroute */

#ifdef NET_21
    if(pRcvDesc->stats) {
      (pRcvDesc->stats)->rx_bytes += skb->len;
    }
    if(skb->dst) {
      dst_release(skb->dst);
      skb->dst = NULL;
    }
    skb->pkt_type = PACKET_HOST;
    if(pRcvDesc->hard_header_len &&
      (skb->mac.raw != (skb->data - pRcvDesc->hard_header_len)) &&
      (pRcvDesc->hard_header_len <= skb_headroom(skb))) {
      /* copy back original MAC header */
      memmove(skb->data - pRcvDesc->hard_header_len, skb->mac.raw, pRcvDesc->hard_header_len);
      skb->mac.raw = skb->data - pRcvDesc->hard_header_len;
    }
#endif /* NET_21 */

#ifdef CONFIG_IPSEC_IPCOMP
    if(ipp->protocol == IPPROTO_COMP) {
      unsigned int flags = 0;

      if(sysctl_ipsec_inbound_policy_check) {
	      KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
		      "klips_debug:ipsec_rcv: "
		      "inbound policy checking enabled, IPCOMP follows IPIP, dropped.\n");
	      if (pRcvDesc->stats) {
		      (pRcvDesc->stats)->rx_errors++;
	      }
	      goto rcvleave_cb;
      }
      /*
      XXX need a TDB for updating ratio counters but it is not
      following policy anyways so it is not a priority
      */
      skb = skb_decompress(skb, NULL, &flags);
      if (!skb || flags) {
	      KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
		      "klips_debug:ipsec_rcv: "
		      "skb_decompress() returned error flags: %d, dropped.\n",
		      flags);
	      if (pRcvDesc->stats) {
		      (pRcvDesc->stats)->rx_errors++;
	      }
	      goto rcvleave_cb;
      }
    }
#endif /* CONFIG_IPSEC_IPCOMP */

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

    KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
      "klips_debug:ipsec_rcv: "
      "netif_rx() called.\n");
    netif_rx(skb);

    /* release desc */
    if (pRcvDesc)
      ipsec_glue_rcv_desc_release (pRcvDesc);

    MOD_DEC_USE_COUNT;
    return;

rcvleave_cb:
/* release desc */
    if (pRcvDesc)
      ipsec_glue_rcv_desc_release (pRcvDesc);

    if(skb) {
#ifdef NET_21
      kfree_skb(skb);
#else /* NET_21 */
      kfree_skb(skb, FREE_WRITE);
#endif /* NET_21 */
    }

    MOD_DEC_USE_COUNT;
    return;
}


int
#ifdef PROTO_HANDLER_SINGLE_PARM
ipsec_rcv(struct sk_buff *skb)
#else /* PROTO_HANDLER_SINGLE_PARM */
#ifdef NET_21
ipsec_rcv(struct sk_buff *skb, unsigned short xlen)
#else /* NET_21 */
ipsec_rcv(struct sk_buff *skb, struct device *dev, struct options *opt,
      __u32 daddr_unused, unsigned short xlen, __u32 saddr,
      int redo, struct inet_protocol *protocol)
#endif /* NET_21 */
#endif /* PROTO_HANDLER_SINGLE_PARM */
{
#ifdef NET_21
#ifdef CONFIG_IPSEC_DEBUG
    struct device *dev = skb->dev;
#endif /* CONFIG_IPSEC_DEBUG */
#endif /* NET_21 */
    unsigned char protoc;
    struct iphdr *ipp;
    int authlen;
#ifdef CONFIG_IPSEC_ESP
    struct esp *espp = NULL;
    char *ivp = NULL;
    int ivlen = 0;
    int esphlen = 0;
    char iv[ESP_IV_MAXSZ];
#endif /* !CONFIG_IPSEC_ESP */
#ifdef CONFIG_IPSEC_AH
    struct ah *ahp = NULL;
    int ahhlen = 0;
#endif /* CONFIG_IPSEC_AH */

#ifdef CONFIG_IPSEC_IPCOMP
    struct ipcomphdr*compp = NULL;
#endif /* CONFIG_IPSEC_IPCOMP */

    int iphlen;
    unsigned char *dat;
    struct ipsec_sa *tdbp = NULL;
    struct sa_id said;

    struct device *ipsecdev = NULL, *prvdev;
    struct ipsecpriv *prv;
    char name[9];
    char sa[SATOA_BUF];
    size_t sa_len;
    char ipaddr_txt[ADDRTOA_BUF];
    int i;
    struct in_addr ipaddr;
    __u8 next_header = 0;
    __u8 proto;

    int len;  /* packet length */
    int replay = 0;   /* replay value in AH or ESP packet */

    struct ipsec_sa* tdbprev = NULL;  /* previous SA from outside of packet */
    struct ipsec_sa* tdbnext = NULL;  /* next SA towards inside of packet */
#ifdef INBOUND_POLICY_CHECK_eroute
    struct sockaddr_encap matcher;    /* eroute search key */
    struct eroute *er;
    struct ipsec_sa* policy_tdb = NULL;
    struct sa_id policy_said;
    struct sockaddr_encap policy_eaddr;
    struct sockaddr_encap policy_emask;
#endif /* INBOUND_POLICY_CHECK_eroute */

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	__u16 natt_len = 0, natt_sport = 0, natt_dport = 0;
	__u8 natt_type = 0;
#endif

    __u32 auth_start_offset = 0;
    __u32 auth_data_len = 0;
    __u32 crypt_start_offset = 0;
    __u32 crypt_data_len = 0;
    __u32 icv_offset = 0;
    IX_MBUF *src_mbuf;
    IpsecRcvDesc *pRcvDesc = NULL;

    /* Don't unlink in the middle of a turnaround */
    MOD_INC_USE_COUNT;

    if (skb == NULL) {
      KLIPS_PRINT(debug_rcv,
	  "klips_debug:ipsec_rcv: "
	  "NULL skb passed in.\n");
      goto rcvleave;
    }

    if (skb->data == NULL) {
      KLIPS_PRINT(debug_rcv,
	      "klips_debug:ipsec_rcv: "
	      "NULL skb->data passed in, packet is bogus, dropping.\n");
      goto rcvleave;
    }

    /* Get rcv desc */
    if (ipsec_glue_rcv_desc_get(&pRcvDesc) != IPSEC_GLUE_STATUS_SUCCESS){
      KLIPS_PRINT(debug_rcv,
	      "klips_debug:ipsec_rcv: "
	      "run out of rcv descriptors, dropping.\n");
	goto rcvleave;
    }

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	if (skb->sk && skb->nh.iph && skb->nh.iph->protocol==IPPROTO_UDP) {
		/**
		 * Packet comes from udp_queue_rcv_skb so it is already defrag,
		 * checksum verified, ... (ie safe to use)
		 *
		 * If the packet is not for us, return -1 and udp_queue_rcv_skb
		 * will continue to handle it (do not kfree skb !!).
		 */
		struct udp_opt *tp =  &(skb->sk->tp_pinfo.af_udp);
		struct iphdr *ip = (struct iphdr *)skb->nh.iph;
		struct udphdr *udp = (struct udphdr *)((__u32 *)ip+ip->ihl);
		__u8 *udpdata = (__u8 *)udp + sizeof(struct udphdr);
		__u32 *udpdata32 = (__u32 *)udpdata;

		natt_sport = ntohs(udp->source);
		natt_dport = ntohs(udp->dest);

		KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv: "
		    "suspected ESPinUDP packet (NAT-Traversal) [%d].\n",
			tp->esp_in_udp);
		KLIPS_IP_PRINT(debug_rcv, ip);

		if (udpdata < skb->tail) {
			unsigned int len = skb->tail - udpdata;
			if ((len==1) && (udpdata[0]==0xff)) {
				KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
					/* not IPv6 compliant message */
				    "NAT-keepalive from %d.%d.%d.%d.\n", NIPQUAD(ip->saddr));
				goto rcvleave;
			}
			else if ( (tp->esp_in_udp == ESPINUDP_WITH_NON_IKE) &&
				(len > (2*sizeof(__u32) + sizeof(struct esp))) &&
				(udpdata32[0]==0) && (udpdata32[1]==0) ) {
				/* ESP Packet with Non-IKE header */
				KLIPS_PRINT(debug_rcv, 
					"klips_debug:ipsec_rcv: "
					"ESPinUDP pkt with Non-IKE - spi=0x%x\n",
					udpdata32[2]);
				natt_type = ESPINUDP_WITH_NON_IKE;
				natt_len = sizeof(struct udphdr)+(2*sizeof(__u32));
			}
			else if ( (tp->esp_in_udp == ESPINUDP_WITH_NON_ESP) &&
				(len > sizeof(struct esp)) &&
				(udpdata32[0]!=0) ) {
				/* ESP Packet without Non-ESP header */
				natt_type = ESPINUDP_WITH_NON_ESP;
				natt_len = sizeof(struct udphdr);
				KLIPS_PRINT(debug_rcv, 
					"klips_debug:ipsec_rcv: "
					"ESPinUDP pkt without Non-ESP - spi=0x%x\n",
					udpdata32[0]);
			}
			else {
				KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
					"IKE packet - not handled here\n");
				/* release desc */
				if (pRcvDesc)
					ipsec_glue_rcv_desc_release (pRcvDesc);
				MOD_DEC_USE_COUNT;
				return -1;
			}
		}
		else {
			/* release desc */
			if (pRcvDesc)
				ipsec_glue_rcv_desc_release (pRcvDesc);
			MOD_DEC_USE_COUNT;
			return -1;
		}
	}
#endif

#ifdef IPH_is_SKB_PULLED
    /* In Linux 2.4.4, the IP header has been skb_pull()ed before the
    packet is passed to us. So we'll skb_push() to get back to it. */
    if (skb->data == skb->h.raw) {
      skb_push(skb, skb->h.raw - skb->nh.raw);
    }
#endif /* IPH_is_SKB_PULLED */

    ipp = (struct iphdr *)skb->data;
    iphlen = ipp->ihl << 2;

    /* dev->hard_header_len is unreliable and should not be used */
    pRcvDesc->hard_header_len = skb->mac.raw ? (skb->data - skb->mac.raw) : 0;
    if((pRcvDesc->hard_header_len < 0) || (pRcvDesc->hard_header_len > skb_headroom(skb)))
      pRcvDesc->hard_header_len = 0;

#ifdef NET_21
    /* if skb was cloned (most likely due to a packet sniffer such as
    tcpdump being momentarily attached to the interface), make
    a copy of our own to modify */
    if(skb_cloned(skb)) {
      /* include any mac header while copying.. */
      if(skb_headroom(skb) < pRcvDesc->hard_header_len) {
	      printk(KERN_WARNING "klips_error:ipsec_rcv: "
	      "tried to skb_push hhlen=%d, %d available.  This should never happen, please report.\n",
	      pRcvDesc->hard_header_len,
	      skb_headroom(skb));
	      goto rcvleave;
      }
      skb_push(skb, pRcvDesc->hard_header_len);
      if
#ifdef SKB_COW_NEW
               (skb_cow(skb, skb_headroom(skb)) != 0)
#else /* SKB_COW_NEW */
               ((skb = skb_cow(skb, skb_headroom(skb))) == NULL)
#endif /* SKB_COW_NEW */
		{
			goto rcvleave;
		}
		if(skb->len < pRcvDesc->hard_header_len) {
			printk(KERN_WARNING "klips_error:ipsec_rcv: "
			       "tried to skb_pull hhlen=%d, %d available.  This should never happen, please report.\n",
			       pRcvDesc->hard_header_len,
			       skb->len);
			goto rcvleave;
		}
		skb_pull(skb, pRcvDesc->hard_header_len);
	}
	
#endif /* NET_21 */
		
#if IP_FRAGMENT_LINEARIZE
	/* In Linux 2.4.4, we may have to reassemble fragments. They are
	   not assembled automatically to save TCP from having to copy
	   twice.
	*/
      if (skb_is_nonlinear(skb)) {
	if (skb_linearize(skb, GFP_ATOMIC) != 0) {
	  goto rcvleave;
	}
      }
      ipp = (struct iphdr *)skb->nh.iph;
      iphlen = ipp->ihl << 2;
#endif
	
#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	if (natt_len) {
		/**
		 * Now, we are sure packet is ESPinUDP. Remove natt_len bytes from
		 * packet and modify protocol to ESP.
		 */
		if (((unsigned char *)skb->data > (unsigned char *)skb->nh.iph) &&
			((unsigned char *)skb->nh.iph > (unsigned char *)skb->head)) {
			unsigned int _len = (unsigned char *)skb->data -
				(unsigned char *)skb->nh.iph;
			KLIPS_PRINT(debug_rcv,
				"klips_debug:ipsec_rcv: adjusting skb: skb_push(%u)\n",
				_len);
			skb_push(skb, _len);
		}
		KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv: "
			"removing %d bytes from ESPinUDP packet\n", natt_len);
		ipp = (struct iphdr *)skb->data;
		iphlen = ipp->ihl << 2;
		ipp->tot_len = htons(ntohs(ipp->tot_len) - natt_len);
		if (skb->len < iphlen + natt_len) {
			printk(KERN_WARNING
		       "klips_error:ipsec_rcv: "
		       "ESPinUDP packet is too small (%d < %d+%d). "
			   "This should never happen, please report.\n",
		       (int)(skb->len), iphlen, natt_len);
			goto rcvleave;
		}
		memmove(skb->data + natt_len, skb->data, iphlen);
		skb_pull(skb, natt_len);

		/* update nh.iph */
		ipp = skb->nh.iph = (struct iphdr *)skb->data;

		/* modify protocol */
		ipp->protocol = IPPROTO_ESP;

		skb->sk = NULL;

		KLIPS_IP_PRINT(debug_rcv, skb->nh.iph);
	}
#endif

	KLIPS_PRINT(debug_rcv, 
		    "klips_debug:ipsec_rcv: "
		    "<<< Info -- ");
	KLIPS_PRINTMORE(debug_rcv && skb->dev, "skb->dev=%s ",
		    skb->dev->name ? skb->dev->name : "NULL");
	KLIPS_PRINTMORE(debug_rcv && dev, "dev=%s ",
		    dev->name ? dev->name : "NULL");
	KLIPS_PRINTMORE(debug_rcv, "\n");

	KLIPS_PRINT(debug_rcv && !(skb->dev && dev && (skb->dev == dev)),
		    "klips_debug:ipsec_rcv: "
		    "Informational -- **if this happens, find out why** skb->dev:%s is not equal to dev:%s\n",
		    skb->dev ? (skb->dev->name ? skb->dev->name : "NULL") : "NULL",
		    dev ? (dev->name ? dev->name : "NULL") : "NULL");

	protoc = ipp->protocol;
#ifndef NET_21
	if((!protocol) || (protocol->protocol != protoc)) {
		KLIPS_PRINT(debug_rcv & DB_RX_TDB,
			    "klips_debug:ipsec_rcv: "
			    "protocol arg is NULL or unequal to the packet contents, this is odd, using value in packet.\n");
	}
#endif /* !NET_21 */

	if( (protoc != IPPROTO_AH) &&
#ifdef CONFIG_IPSEC_IPCOMP_disabled_until_we_register_IPCOMP_HANDLER
	    (protoc != IPPROTO_COMP) &&
#endif /* CONFIG_IPSEC_IPCOMP */
	    (protoc != IPPROTO_ESP) ) {
		KLIPS_PRINT(debug_rcv & DB_RX_TDB,
			    "klips_debug:ipsec_rcv: Why the hell is someone "
			    "passing me a non-ipsec protocol = %d packet? -- dropped.\n",
			    protoc);
		goto rcvleave;
	}

	if(skb->dev) {
		for(i = 0; i < IPSEC_NUM_IF; i++) {
			sprintf(name, "ipsec%d", i);
			if(!strcmp(name, skb->dev->name)) {
				prv = (struct ipsecpriv *)(skb->dev->priv);
				if(prv) {
					pRcvDesc->stats = (struct net_device_stats *) &(prv->mystats);
				}
				ipsecdev = skb->dev;
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "Info -- pkt already proc'ed a group of ipsec headers, processing next group of ipsec headers.\n");
				break;
			}
			if((ipsecdev = ipsec_dev_get(name)) == NULL) {
				KLIPS_PRINT(debug_rcv,
					    "klips_error:ipsec_rcv: "
					    "device %s does not exist\n",
					    name);
			}
			prv = ipsecdev ? (struct ipsecpriv *)(ipsecdev->priv) : NULL;
			prvdev = prv ? (struct device *)(prv->dev) : NULL;
			
#if 0
			KLIPS_PRINT(debug_rcv && prvdev, 
				    "klips_debug:ipsec_rcv: "
				    "physical device for device %s is %s\n",
				    name,
				    prvdev->name);
#endif
			if(prvdev && skb->dev &&
			   !strcmp(prvdev->name, skb->dev->name)) {
				pRcvDesc->stats = prv ? ((struct net_device_stats *) &(prv->mystats)) : NULL;
				skb->dev = ipsecdev;
#if (defined(CONFIG_BRIDGE) || defined(CONFIG_BRIDGE_MODULE)) && defined(CONFIG_NETFILTER)
							if (skb->nf_bridge)
		                        skb->nf_bridge->physindev = ipsecdev;
#endif
				KLIPS_PRINT(debug_rcv && prvdev, 
					    "klips_debug:ipsec_rcv: "
					    "assigning packet ownership to virtual device %s from physical device %s.\n",
					    name, prvdev->name);
				if(pRcvDesc->stats) {
					pRcvDesc->stats->rx_packets++;
				}
				break;
			}
		}
	} else {
		KLIPS_PRINT(debug_rcv, 
			    "klips_debug:ipsec_rcv: "
			    "device supplied with skb is NULL\n");
	}
			
	if(!pRcvDesc->stats) {
		ipsecdev = NULL;
	}
	KLIPS_PRINT((debug_rcv && !pRcvDesc->stats),
		    "klips_error:ipsec_rcv: "
		    "packet received from physical I/F (%s) not connected to ipsec I/F.  Cannot record stats.  May not have SA for decoding.  Is IPSEC traffic expected on this I/F?  Check routing.\n",
		    skb->dev ? (skb->dev->name ? skb->dev->name : "NULL") : "NULL");

	KLIPS_IP_PRINT(debug_rcv, ipp);

#ifdef CONFIG_LEDMAN
	ledman_cmd(LEDMAN_CMD_SET, LEDMAN_VPN_RX);
#endif

	/* begin decapsulating loop here */
	do {
		authlen = 0;
#ifdef CONFIG_IPSEC_ESP
		espp = NULL;
		esphlen = 0;
		ivlen =0;
		esphlen = 0;
#endif /* !CONFIG_IPSEC_ESP */
#ifdef CONFIG_IPSEC_AH
		ahp = NULL;
		ahhlen = 0;
#endif /* CONFIG_IPSEC_AH */
#ifdef CONFIG_IPSEC_IPCOMP
		compp = NULL;
#endif /* CONFIG_IPSEC_IPCOMP */

		len = skb->len;
		dat = skb->data;
		ipp = (struct iphdr *)skb->data;
		proto = ipp->protocol;
		ipaddr.s_addr = ipp->saddr;
		addrtoa(ipaddr, 0, ipaddr_txt, sizeof(ipaddr_txt));
		
		iphlen = ipp->ihl << 2;
		ipp->check = 0;			/* we know the sum is good */
		
#ifdef CONFIG_IPSEC_ESP
#endif /* !CONFIG_IPSEC_ESP */
		
		/*
		 * Find tunnel control block and (indirectly) call the
		 * appropriate tranform routine. The resulting sk_buf
		 * is a valid IP packet ready to go through input processing.
		 */
		
		said.dst.s_addr = ipp->daddr;
		switch(proto) {
#ifdef CONFIG_IPSEC_ESP
		case IPPROTO_ESP:
		      /* XXX this will need to be 8 for IPv6 */
		      if ((len - iphlen) % 4) {
			      printk("klips_error:ipsec_rcv: "
			      "got packet with content length = %d from %s -- should be on 4 octet boundary, packet dropped\n",
			      len - iphlen,
			      ipaddr_txt);
			      if(pRcvDesc->stats) {
				      (pRcvDesc->stats)->rx_errors++;
			      }
			      goto rcvleave;
		      }

		      if(skb->len < (pRcvDesc->hard_header_len + sizeof(struct iphdr) + sizeof(struct esp))) {
			      KLIPS_PRINT(debug_rcv & DB_RX_INAU,
				      "klips_debug:ipsec_rcv: "
				      "runt esp packet of skb->len=%d received from %s, dropped.\n",
				      skb->len,
				      ipaddr_txt);
			      if(pRcvDesc->stats) {
				      (pRcvDesc->stats)->rx_errors++;
			      }
			      goto rcvleave;
		      }

		      espp = (struct esp *)(skb->data + iphlen);
		      /* Get IV location pointer in payload - after ESP header */
		      ivp = (char *) espp + sizeof (struct esp);
		      said.spi = espp->esp_spi;
		      replay = ntohl(espp->esp_rpl);

		      break;
#endif /* !CONFIG_IPSEC_ESP */
#ifdef CONFIG_IPSEC_AH
	      case IPPROTO_AH:
		      if((skb->len
			      < (pRcvDesc->hard_header_len + sizeof(struct iphdr) + sizeof(struct ah)))
			      || (skb->len
			      < (pRcvDesc->hard_header_len + sizeof(struct iphdr)
			      + ((ahp = (struct ah *) (skb->data + iphlen))->ah_hl << 2)))) {
			      KLIPS_PRINT(debug_rcv & DB_RX_INAU,
				      "klips_debug:ipsec_rcv: "
				      "runt ah packet of skb->len=%d received from %s, dropped.\n",
				      skb->len,
				      ipaddr_txt);
			      if(pRcvDesc->stats) {
				      (pRcvDesc->stats)->rx_errors++;
			      }
			      goto rcvleave;
		      }
		      said.spi = ahp->ah_spi;
		      replay = ntohl(ahp->ah_rpl);
		      ahhlen = (ahp->ah_hl << 2) +
		      ((caddr_t)&(ahp->ah_rpl) - (caddr_t)ahp);
		      next_header = ahp->ah_nh;
		      if (ahhlen != sizeof(struct ah)) {
			      KLIPS_PRINT(debug_rcv & DB_RX_INAU,
					  "klips_debug:ipsec_rcv: "
					  "bad authenticator length %d, expected %d from %s.\n",
					  ahhlen - ((caddr_t)(ahp->ah_data) - (caddr_t)ahp),
					  AHHMAC_HASHLEN,
					  ipaddr_txt);
			      if(pRcvDesc->stats) {
				      (pRcvDesc->stats)->rx_errors++;
			      }
			      goto rcvleave;
		      }
		      break;
#endif /* CONFIG_IPSEC_AH */
#ifdef CONFIG_IPSEC_IPCOMP
	      case IPPROTO_COMP:
		      if(skb->len < (pRcvDesc->hard_header_len + sizeof(struct iphdr) + sizeof(struct ipcomphdr))) {
			      KLIPS_PRINT(debug_rcv & DB_RX_INAU,
					  "klips_debug:ipsec_rcv: "
					  "runt comp packet of skb->len=%d received from %s, dropped.\n",
					  skb->len,
					  ipaddr_txt);
			      if(pRcvDesc->stats) {
				      (pRcvDesc->stats)->rx_errors++;
			      }
			      goto rcvleave;
		      }

		      compp = (struct ipcomphdr *)(skb->data + iphlen);
		      said.spi = htonl((__u32)ntohs(compp->ipcomp_cpi));
		      break;
#endif /* CONFIG_IPSEC_IPCOMP */
	      default:
		      if(pRcvDesc->stats) {
			      (pRcvDesc->stats)->rx_errors++;
		      }
		      goto rcvleave;
	      }
	      said.proto = proto;

	      sa_len = satoa(said, 0, sa, SATOA_BUF);
	if(sa_len == 0) {
	      strcpy(sa, "(error)");
      }


#ifdef CONFIG_IPSEC_IPCOMP
      if (proto == IPPROTO_COMP) {
	      unsigned int flags = 0;
	      if (tdbp == NULL) {
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "Incoming packet with outer IPCOMP header SA:%s: not yet supported by KLIPS, dropped\n",
			      sa_len ? sa : " (error)");
		      if(pRcvDesc->stats) {
			      (pRcvDesc->stats)->rx_dropped++;
		      }

		      goto rcvleave;
	      }


	      tdbprev = tdbp;
	      spin_lock(&tdb_lock);
	      tdbp = tdbnext;

	      /* store current tdbp into rcv descriptor */
	      pRcvDesc->tdbp = tdbp;

	      if(sysctl_ipsec_inbound_policy_check
		      && ((tdbp == NULL)
		      || (((ntohl(tdbp->tdb_said.spi) & 0x0000ffff)
		      != ntohl(said.spi))
		      /* next line is a workaround for peer
		      non-compliance with rfc2393 */
		      && (tdbp->tdb_encalg != ntohl(said.spi))
		      ))) {

		      char sa2[SATOA_BUF];
		      size_t sa_len2 = 0;
		      spin_unlock(&tdb_lock);

		      if(tdbp) {
			      sa_len2 = satoa(tdbp->tdb_said, 0, sa2, SATOA_BUF);
		      }

		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "Incoming packet with SA(IPCA):%s does not match policy SA(IPCA):%s cpi=%04x cpi->spi=%08x spi=%08x, spi->cpi=%04x for SA grouping, dropped.\n",
			      sa_len ? sa : " (error)",
			      tdbp ? (sa_len2 ? sa2 : " (error)") : "NULL",
			      ntohs(compp->ipcomp_cpi),
			      (__u32)ntohl(said.spi),
			      tdbp ? (__u32)ntohl((tdbp->tdb_said.spi)) : 0,
			      tdbp ? (__u16)(ntohl(tdbp->tdb_said.spi) & 0x0000ffff) : 0);
		      if(pRcvDesc->stats) {
			      (pRcvDesc->stats)->rx_dropped++;
		      }
		      goto rcvleave;
	      }

	      next_header = compp->ipcomp_nh;

	      if (tdbp) {
		      addRcvDesc_to_salist(tdbp, pRcvDesc);
		      tdbp->tdb_comp_ratio_cbytes += ntohs(ipp->tot_len);
		      tdbnext = tdbp->tdb_inext;
	      }

	      skb = skb_decompress(skb, tdbp, &flags);
	      if (!skb || flags) {
		      delRcvDesc_from_salist(tdbp, pRcvDesc);
		      spin_unlock(&tdb_lock);
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "skb_decompress() returned error flags=%x, dropped.\n",
			      flags);
		      if (pRcvDesc->stats) {
			      if (flags)
				      (pRcvDesc->stats)->rx_errors++;
			      else
				      (pRcvDesc->stats)->rx_dropped++;
		      }
		      goto rcvleave;
	      }
#ifdef NET_21
	      ipp = skb->nh.iph;
#else /* NET_21 */
	      ipp = skb->ip_hdr;
#endif /* NET_21 */

	      if (tdbp) {
		      tdbp->tdb_comp_ratio_dbytes += ntohs(ipp->tot_len);
		      delRcvDesc_from_salist(tdbp, pRcvDesc);
	      }

	      KLIPS_PRINT(debug_rcv,
		      "klips_debug:ipsec_rcv: "
		      "packet decompressed SA(IPCA):%s cpi->spi=%08x spi=%08x, spi->cpi=%04x, nh=%d.\n",
		      sa_len ? sa : " (error)",
		      (__u32)ntohl(said.spi),
		      tdbp ? (__u32)ntohl((tdbp->tdb_said.spi)) : 0,
		      tdbp ? (__u16)(ntohl(tdbp->tdb_said.spi) & 0x0000ffff) : 0,
		      next_header);
	      KLIPS_IP_PRINT(debug_rcv & DB_RX_PKTRX, ipp);

	      spin_unlock(&tdb_lock);

	      continue;
	      /* Skip rest of stuff and decapsulate next inner
			 packet, if any */
      }
#endif /* CONFIG_IPSEC_IPCOMP */

      tdbp = ipsec_sa_getbyid(&said);
      pRcvDesc->tdbp = tdbp;

      if (tdbp == NULL) {
	      KLIPS_PRINT(debug_rcv,
		      "klips_debug:ipsec_rcv: "
		      "no Tunnel Descriptor Block for SA:%s: incoming packet with no SA dropped\n",
		      sa_len ? sa : " (error)");
	      if(pRcvDesc->stats) {
		      (pRcvDesc->stats)->rx_dropped++;
	      }
	      goto rcvleave;
      }

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
		if ((natt_type) &&
			( (ipp->saddr != (((struct sockaddr_in*)(tdbp->tdb_addr_s))->sin_addr.s_addr)) ||
			  (natt_sport != tdbp->ips_natt_sport)
			)) {
			struct sockaddr sipaddr;
			/** Advertise NAT-T addr change to pluto **/
			sipaddr.sa_family = AF_INET;
			((struct sockaddr_in*)&sipaddr)->sin_addr.s_addr = ipp->saddr;
			((struct sockaddr_in*)&sipaddr)->sin_port = htons(natt_sport);
			pfkey_nat_t_new_mapping(tdbp, &sipaddr, natt_sport);
			/**
			 * Then allow or block packet depending on
			 * sysctl_ipsec_inbound_policy_check.
			 *
			 * In all cases, pluto will update SA if new mapping is
			 * accepted.
			 */
			if (sysctl_ipsec_inbound_policy_check) {
				spin_unlock(&tdb_lock);
				ipaddr.s_addr = ipp->saddr;
				addrtoa(ipaddr, 0, ipaddr_txt, sizeof(ipaddr_txt));
				KLIPS_PRINT(debug_rcv,
					"klips_debug:ipsec_rcv: "
					"SA:%s, src=%s:%u of pkt does not agree with expected "
					"SA source address policy (pluto has been informed).\n",
					sa_len ? sa : " (error)",
					ipaddr_txt, natt_sport);
				if(pRcvDesc->stats) {
					pRcvDesc->stats->rx_dropped++;
				}
				goto rcvleave;
			}
		}
#endif


#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
			KLIPS_PRINT(debug_rcv,
				"klips_debug:ipsec_rcv: "
				"natt_type=%u tdbp->ips_natt_type=%u : %s\n",
				natt_type, tdbp->ips_natt_type,
				(natt_type==tdbp->ips_natt_type)?"ok":"bad");
			if (natt_type != tdbp->ips_natt_type) {
				spin_unlock(&tdb_lock);
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "SA:%s does not agree with expected NAT-T policy.\n",
					    sa_len ? sa : " (error)");
				if(pRcvDesc->stats) {
					pRcvDesc->stats->rx_dropped++;
				}
				goto rcvleave;
			}
#endif

	spin_lock(&tdb_lock);
	addRcvDesc_to_salist(tdbp, pRcvDesc);
      if(sysctl_ipsec_inbound_policy_check) {
	      if(ipp->saddr != ((struct sockaddr_in*)(tdbp->tdb_addr_s))->sin_addr.s_addr) {
		      delRcvDesc_from_salist(tdbp, pRcvDesc);
		      spin_unlock(&tdb_lock);
		      ipaddr.s_addr = ipp->saddr;
		      addrtoa(ipaddr, 0, ipaddr_txt, sizeof(ipaddr_txt));

		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "SA:%s, src=%s of pkt does not agree with expected SA source address policy.\n",
			      sa_len ? sa : " (error)",
			      ipaddr_txt);
		      if(pRcvDesc->stats) {
			      (pRcvDesc->stats)->rx_dropped++;
		      }
		      goto rcvleave;
	      }

	      ipaddr.s_addr = ipp->saddr;
	      addrtoa(ipaddr, 0, ipaddr_txt, sizeof(ipaddr_txt));
	      KLIPS_PRINT(debug_rcv,
		      "klips_debug:ipsec_rcv: "
		      "SA:%s, src=%s of pkt agrees with expected SA source address policy.\n",
		      sa_len ? sa : " (error)",
		      ipaddr_txt);
	      if(tdbnext) {
		      if(tdbnext != tdbp) {
			      delRcvDesc_from_salist(tdbp, pRcvDesc);
			      spin_unlock(&tdb_lock);
			      KLIPS_PRINT(debug_rcv,
				      "klips_debug:ipsec_rcv: "
				      "unexpected SA:%s: does not agree with tdb->inext policy, dropped\n",
				      sa_len ? sa : " (error)");
			      if(pRcvDesc->stats) {
				      (pRcvDesc->stats)->rx_dropped++;
			      }
			      goto rcvleave;
		      }
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "SA:%s grouping from previous SA is OK.\n",
			      sa_len ? sa : " (error)");
	      } else {
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "SA:%s First SA in group.\n",
			      sa_len ? sa : " (error)");
	      }

	      if(tdbp->tdb_onext) {
		      if(tdbprev != tdbp->tdb_onext) {
			      delRcvDesc_from_salist(tdbp, pRcvDesc);
			      spin_unlock(&tdb_lock);
			      KLIPS_PRINT(debug_rcv,
				      "klips_debug:ipsec_rcv: "
				      "unexpected SA:%s: does not agree with tdb->onext policy, dropped.\n",
				      sa_len ? sa : " (error)");
			      if(pRcvDesc->stats) {
				      (pRcvDesc->stats)->rx_dropped++;
			      }
			      goto rcvleave;
		      } else {
			      KLIPS_PRINT(debug_rcv,
				      "klips_debug:ipsec_rcv: "
				      "SA:%s grouping to previous SA is OK.\n",
				      sa_len ? sa : " (error)");
		      }
	      } else {
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "SA:%s No previous backlink in group.\n",
			      sa_len ? sa : " (error)");
	      }
#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
			KLIPS_PRINT(debug_rcv,
				"klips_debug:ipsec_rcv: "
				"natt_type=%u tdbp->ips_natt_type=%u : %s\n",
				natt_type, tdbp->ips_natt_type,
				(natt_type==tdbp->ips_natt_type)?"ok":"bad");
			if (natt_type != tdbp->ips_natt_type) {
				spin_unlock(&tdb_lock);
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "SA:%s does not agree with expected NAT-T policy.\n",
					    sa_len ? sa : " (error)");
				if((pRcvDesc->stats)) {
					(pRcvDesc->stats)->rx_dropped++;
				}
				goto rcvleave;
			}
#endif
      }
		
		/* If it is in larval state, drop the packet, we cannot process yet. */
		if(tdbp->tdb_state == SADB_SASTATE_LARVAL) {
			spin_unlock(&tdb_lock);
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "TDB in larval state, cannot be used yet, dropping packet.\n");
			if(pRcvDesc->stats) {
				pRcvDesc->stats->rx_dropped++;
			}
			goto rcvleave;
		}
		
		if(tdbp->tdb_state == SADB_SASTATE_DEAD) {
			spin_unlock(&tdb_lock);
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "TDB in dead state, cannot be used any more, dropping packet.\n");
			if(pRcvDesc->stats) {
				pRcvDesc->stats->rx_dropped++;
			}
			goto rcvleave;
		}
		
		if(ipsec_lifetime_check(&tdbp->ips_life.ipl_bytes,   "bytes", sa,
					ipsec_life_countbased, ipsec_incoming, tdbp) == ipsec_life_harddied ||
		   ipsec_lifetime_check(&tdbp->ips_life.ipl_addtime, "addtime",sa,
					ipsec_life_timebased,  ipsec_incoming, tdbp) == ipsec_life_harddied ||
		   ipsec_lifetime_check(&tdbp->ips_life.ipl_addtime, "usetime",sa,
					ipsec_life_timebased,  ipsec_incoming, tdbp) == ipsec_life_harddied ||
		   ipsec_lifetime_check(&tdbp->ips_life.ipl_packets, "packets",sa, 
					ipsec_life_countbased, ipsec_incoming, tdbp) == ipsec_life_harddied) {
			ipsec_sa_delchain(tdbp);
			spin_unlock(&tdb_lock);
			if(pRcvDesc->stats) {
				pRcvDesc->stats->rx_dropped++;
			}
			goto rcvleave;
		}

	if (!ipsec_checkreplaywindow(tdbp, replay)) {
	      tdbp->tdb_replaywin_errs += 1;
	      delRcvDesc_from_salist(tdbp, pRcvDesc);
	      spin_unlock(&tdb_lock);
	      KLIPS_PRINT(debug_rcv & DB_RX_REPLAY,
		      "klips_debug:ipsec_rcv: "
		      "duplicate frame from %s, packet dropped\n",
		      ipaddr_txt);
	      if(pRcvDesc->stats) {
		      (pRcvDesc->stats)->rx_dropped++;
	      }
	      goto rcvleave;
      }

      KLIPS_PRINT(debug_rcv,
	      "klips_debug:ipsec_rcv: "
	      "encalg = %d, authalg = %d.\n",
	      tdbp->tdb_encalg,
	      tdbp->tdb_authalg);

      /* If the sequence number == 0, expire SA, it had rolled */
      if(tdbp->tdb_replaywin && !replay /* !tdbp->tdb_replaywin_lastseq */) {
	      delRcvDesc_from_salist(tdbp, pRcvDesc);
	      ipsec_sa_delchain(tdbp);
	      spin_unlock(&tdb_lock);
	      KLIPS_PRINT(debug_rcv,
		      "klips_debug:ipsec_rcv: "
		      "replay window counter rolled, expiring SA.\n");
	      if(pRcvDesc->stats) {
		      (pRcvDesc->stats)->rx_dropped++;
	      }
	      goto rcvleave;
      }

	spin_unlock(&tdb_lock);

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
			authlen = 0;
			break;
		default:
			spin_lock(&tdb_lock);
			delRcvDesc_from_salist(tdbp, pRcvDesc);
			tdbp->tdb_alg_errs += 1;
			spin_unlock(&tdb_lock);
			if(pRcvDesc->stats) {
				pRcvDesc->stats->rx_errors++;
			}
			goto rcvleave;
		}

#ifdef CONFIG_IPSEC_ESP
      KLIPS_PRINT(proto == IPPROTO_ESP && debug_rcv,
	      "klips_debug:ipsec_rcv: "
	      "packet from %s received with seq=%d (iv)=0x%08x%08x%8x%8x iplen=%d esplen=%d sa=%s\n",
	      ipaddr_txt,
	      (__u32)ntohl(espp->esp_rpl),
	      (__u32)ntohl(*((__u32 *)(ivp)    )),
	      (__u32)ntohl(*((__u32 *)(ivp) + 1)),
	      (__u32)ntohl(*((__u32 *)(ivp) + 2)),
	      (__u32)ntohl(*((__u32 *)(ivp) + 3)),
	      len,
	      auth_data_len,
	      sa_len ? sa : " (error)");
#endif /* !CONFIG_IPSEC_ESP */

      switch(proto) {
#ifdef CONFIG_IPSEC_ESP
	      case IPPROTO_ESP:
      /*
		 AFTER APPLYING ESP
	    -------------------------------------------------
      IPv4  |orig IP hdr  | ESP |     |      |   ESP   | ESP|
	    |(any options)| Hdr | TCP | Data | Trailer |Auth|
	    -------------------------------------------------
				|<----- encrypted ---->|
			  |<------ authenticated ----->|
      */

		      esphlen = sizeof(struct esp);
		      ivlen = tdbp->ips_iv_size;
		      /* Keep IV length in descriptor for callback use */
		      pRcvDesc->ivlen = ivlen;
		      auth_start_offset = iphlen;
		      auth_data_len = len - iphlen - authlen;
		      icv_offset = len - authlen;
		      crypt_start_offset = iphlen + esphlen + ivlen; /* IV is not included as payload for encryption */
		      crypt_data_len = len - iphlen - authlen - esphlen - ivlen;

		      if ((crypt_data_len) % 8) {
			      spin_lock(&tdb_lock);
			      delRcvDesc_from_salist(tdbp, pRcvDesc);
			      tdbp->tdb_encsize_errs += 1;
			      spin_unlock(&tdb_lock);
			      if(pRcvDesc->stats) {
				      (pRcvDesc->stats)->rx_errors++;
			      }
			      goto rcvleave;
		      }

		      switch(tdbp->tdb_encalg) {
# ifdef CONFIG_IPSEC_ENC_DES
			      case ESP_DES:
				      memcpy (iv, ivp, ivlen);
				      break;
# endif /* CONFIG_IPSEC_ENC_DES */
#ifdef CONFIG_IPSEC_ENC_3DES
			      case ESP_3DES:
				      memcpy (iv, ivp, ivlen);
				      break;
#endif /* CONFIG_IPSEC_ENC_3DES */
#ifdef CONFIG_IPSEC_ALG
			      case ESP_AES:
				      memcpy (iv, ivp, ivlen);
				      break;
#endif /* CONFIG_IPSEC_ALG */
			      default:
				      spin_lock(&tdb_lock);
				      delRcvDesc_from_salist(tdbp, pRcvDesc);
				      tdbp->tdb_alg_errs += 1;
				      spin_unlock(&tdb_lock);
				      if(pRcvDesc->stats) {
					      (pRcvDesc->stats)->rx_errors++;
				      }
				      goto rcvleave;
		      }
		      break;
#endif /* !CONFIG_IPSEC_ESP */
#ifdef CONFIG_IPSEC_AH
	      case IPPROTO_AH:
      /*
		  AFTER APPLYING AH
	    ---------------------------------
      IPv4  |orig IP hdr  |    |     |      |
	    |(any options)| AH | TCP | Data |
	    ---------------------------------
	    |<------- authenticated ------->|
		 except for mutable fields
      */

		      auth_start_offset = 0; /* start at the beginning */
		      auth_data_len = len;
		      icv_offset = iphlen + AUTH_DATA_IN_AH_OFFSET;

		      /* IXP425 glue code : mutable field, need to keep a copy of original IP header and
		      restore the original IP header after callback received.
		      Modify the mutable fields in header*/
		      pRcvDesc->ip_frag_off = ipp->frag_off;
		      pRcvDesc->ip_ttl = ipp->ttl;
		      ipp->frag_off = 0;
		      ipp->ttl = 0;
		      ipp->check = 0;
		      break;
#endif /* CONFIG_IPSEC_AH */
      }

      if(auth_data_len <= 0) {
	      spin_lock (&tdb_lock);
	      delRcvDesc_from_salist(tdbp, pRcvDesc);
	      spin_unlock (&tdb_lock);
	      KLIPS_PRINT(debug_rcv,
		      "klips_debug:ipsec_rcv: "
		      "runt AH packet with no data, dropping.\n");
	      if(pRcvDesc->stats) {
		      (pRcvDesc->stats)->rx_dropped++;
	      }
	      goto rcvleave;
      }

	/* IXP425 glue code */
#if defined(CONFIG_IPSEC_AH) || defined(CONFIG_IPSEC_ESP)

	if ((proto == IPPROTO_AH) || (proto == IPPROTO_ESP))
	{
	      /* store ICV_offset */
	      pRcvDesc->icv_offset = icv_offset;

	      /* get mbuf */
	      if(IPSEC_GLUE_STATUS_SUCCESS != ipsec_glue_mbuf_header_get(&src_mbuf))
	      {
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "running out of mbufs, dropped\n");
		      spin_lock (&tdb_lock);
			      delRcvDesc_from_salist(tdbp, pRcvDesc);
			      spin_unlock (&tdb_lock);
		      if(pRcvDesc->stats) {
			      (pRcvDesc->stats)->rx_dropped++;
		      }
		      goto rcvleave;
	      }

	      /* attach mbuf to sk_buff */
	      mbuf_swap_skb(src_mbuf, skb);

	      /* store rcv desc in mbuf */
	      (IpsecRcvDesc *) IX_MBUF_NEXT_PKT_IN_CHAIN_PTR (src_mbuf) = pRcvDesc;

	      /* call crypto perform */
	      if (IX_CRYPTO_ACC_STATUS_SUCCESS != ixCryptoAccAuthCryptPerform (
			      tdbp->ips_crypto_context_id,
			      src_mbuf,
			      NULL,
			      auth_start_offset,
			      auth_data_len,
			      crypt_start_offset,
			      crypt_data_len,
			      icv_offset,
			      iv))
	      {
		      spin_lock(&tdb_lock);
		      delRcvDesc_from_salist(tdbp, pRcvDesc);
		      spin_unlock(&tdb_lock);
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "warning, decrapsulation packet from %s cannot be started\n",
			      ipaddr_txt);

		      ipsec_glue_mbuf_header_rel(src_mbuf);

		      if(pRcvDesc->stats) {
			      (pRcvDesc->stats)->rx_dropped++;
		      }
		      goto rcvleave;
	      }
	      return 0;
	} /* end of if ((proto == IPPROTO_AH) || (proto == IPPROTO_ESP))*/
#endif /* defined(CONFIG_IPSEC_AH) || defined(CONFIG_IPSEC_ESP)*/

	/* set next header */
	skb->data[PROTO] = next_header;

      /*
      *       Adjust pointers
      */

      len = skb->len;
      dat = skb->data;

#ifdef NET_21
      /* skb->h.ipiph=(struct iphdr *)skb->data; */
      skb->nh.raw = skb->data;
      skb->h.raw = skb->nh.raw + (skb->nh.iph->ihl << 2);

      memset(&(IPCB(skb)->opt), 0, sizeof(struct ip_options));
#else /* NET_21 */
      skb->h.iph=(struct iphdr *)skb->data;
      skb->ip_hdr=(struct iphdr *)skb->data;
      memset(skb->proto_priv, 0, sizeof(struct options));
#endif /* NET_21 */

      ipp = (struct iphdr *)dat;
      ipp->check = 0;
      ipp->check = ip_fast_csum((unsigned char *)dat, iphlen >> 2);

      KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
	      "klips_debug:ipsec_rcv: "
	      "after <%s%s%s>, SA:%s:\n",
	      IPS_XFORM_NAME(tdbp),
	      sa_len ? sa : " (error)");
      KLIPS_IP_PRINT(debug_rcv & DB_RX_PKTRX, ipp);

      skb->protocol = htons(ETH_P_IP);
      skb->ip_summed = 0;

      tdbprev = tdbp;
      tdbnext = tdbp->tdb_inext;

	spin_lock(&tdb_lock);

      if(sysctl_ipsec_inbound_policy_check) {
	      if(tdbnext) {
		      if(tdbnext->tdb_onext != tdbp) {
			      delRcvDesc_from_salist(tdbp, pRcvDesc);
			      spin_unlock(&tdb_lock);
			      KLIPS_PRINT(debug_rcv,
				      "klips_debug:ipsec_rcv: "
				      "SA:%s, backpolicy does not agree with fwdpolicy.\n",
				      sa_len ? sa : " (error)");
			      if(pRcvDesc->stats) {
				      (pRcvDesc->stats)->rx_dropped++;
			      }
			      goto rcvleave;
		      }
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "SA:%s, backpolicy agrees with fwdpolicy.\n",
			      sa_len ? sa : " (error)");
		      if(
#ifdef CONFIG_IPSEC_IPCOMP
			      ipp->protocol != IPPROTO_COMP
			      && (tdbnext->tdb_said.proto != IPPROTO_COMP
			      || (tdbnext->tdb_said.proto == IPPROTO_COMP
				      && tdbnext->tdb_inext))
#endif /* CONFIG_IPSEC_IPCOMP */
			      && ipp->protocol != IPPROTO_IPIP
			      ) {
			      delRcvDesc_from_salist(tdbp, pRcvDesc);
			      spin_unlock(&tdb_lock);
			      KLIPS_PRINT(debug_rcv,
				      "klips_debug:ipsec_rcv: "
				      "packet with incomplete policy dropped, last successful SA:%s.\n",
				      sa_len ? sa : " (error)");
			      if(pRcvDesc->stats) {
				      (pRcvDesc->stats)->rx_dropped++;
			      }
			      goto rcvleave;
		      }
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "SA:%s, Another IPSEC header to process.\n",
			      sa_len ? sa : " (error)");
	      } else {
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "No tdb_inext from this SA:%s.\n",
			      sa_len ? sa : " (error)");
	      } /* end of if(tdbnext)*/
      } /* end of if(sysctl_ipsec_inbound_policy_check) */

#ifdef CONFIG_IPSEC_IPCOMP
      /* update ipcomp ratio counters, even if no ipcomp packet is present */
      if (tdbnext
	      && tdbnext->tdb_said.proto == IPPROTO_COMP
	      && ipp->protocol != IPPROTO_COMP) {
	      tdbnext->tdb_comp_ratio_cbytes += ntohs(ipp->tot_len);
	      tdbnext->tdb_comp_ratio_dbytes += ntohs(ipp->tot_len);
      }
#endif /* CONFIG_IPSEC_IPCOMP */

      tdbp->ips_life.ipl_bytes.ipl_count += len;
      tdbp->ips_life.ipl_bytes.ipl_last   = len;

      if(!tdbp->ips_life.ipl_usetime.ipl_count) {
	      tdbp->ips_life.ipl_usetime.ipl_count = jiffies / HZ;
      }
      tdbp->ips_life.ipl_usetime.ipl_last = jiffies / HZ;
      tdbp->ips_life.ipl_packets.ipl_count += 1;
	delRcvDesc_from_salist(tdbp, pRcvDesc);
      spin_unlock(&tdb_lock);

    } while(   (ipp->protocol == IPPROTO_ESP )
	      || (ipp->protocol == IPPROTO_AH  )
#ifdef CONFIG_IPSEC_IPCOMP
	      || (ipp->protocol == IPPROTO_COMP)
#endif /* CONFIG_IPSEC_IPCOMP */
	      );
    /* end decapsulation loop here */

    spin_lock(&tdb_lock);
    addRcvDesc_to_salist(tdbp, pRcvDesc);
	
#ifdef CONFIG_IPSEC_IPCOMP
    if(tdbnext && tdbnext->tdb_said.proto == IPPROTO_COMP) {

      tdbprev = tdbp;
      delRcvDesc_from_salist(tdbp, pRcvDesc);
      tdbp = tdbnext;
      pRcvDesc->tdbp = tdbp;
      addRcvDesc_to_salist(tdbp, pRcvDesc);
      tdbnext = tdbp->tdb_inext;
    }
#endif /* CONFIG_IPSEC_IPCOMP */

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	if ((natt_type) && (ipp->protocol != IPPROTO_IPIP)) {
		/**
		 * NAT-Traversal and Transport Mode:
		 *   we need to correct TCP/UDP checksum
		 *
		 * If we've got NAT-OA, we can fix checksum without recalculation.
		 */
		__u32 natt_oa = tdbp->ips_natt_oa ?
			((struct sockaddr_in*)(tdbp->ips_natt_oa))->sin_addr.s_addr : 0;
		__u16 pkt_len = skb->tail - (unsigned char *)ipp;
		__u16 data_len = pkt_len - (ipp->ihl << 2);

		switch (ipp->protocol) {
			case IPPROTO_TCP:
				if (data_len >= sizeof(struct tcphdr)) {
					struct tcphdr *tcp = (struct tcphdr *)((__u32 *)ipp+ipp->ihl);
					if (natt_oa) {
						__u32 buff[2] = { ~natt_oa, ipp->saddr };
						KLIPS_PRINT(debug_rcv,
				    		"klips_debug:ipsec_rcv: "
							"NAT-T & TRANSPORT: "
							"fix TCP checksum using NAT-OA\n");
						tcp->check = csum_fold(
							csum_partial((unsigned char *)buff, sizeof(buff),
							tcp->check^0xffff));
					}
					else {
						KLIPS_PRINT(debug_rcv,
			    			"klips_debug:ipsec_rcv: "
							"NAT-T & TRANSPORT: recalc TCP checksum\n");
						if (pkt_len > (ntohs(ipp->tot_len)))
							data_len -= (pkt_len - ntohs(ipp->tot_len));
						tcp->check = 0;
						tcp->check = csum_tcpudp_magic(ipp->saddr, ipp->daddr,
							data_len, IPPROTO_TCP,
							csum_partial((unsigned char *)tcp, data_len, 0));
					}
				}
				else {
					KLIPS_PRINT(debug_rcv,
			    		"klips_debug:ipsec_rcv: "
						"NAT-T & TRANSPORT: can't fix TCP checksum\n");
				}
				break;
			case IPPROTO_UDP:
				if (data_len >= sizeof(struct udphdr)) {
					struct udphdr *udp = (struct udphdr *)((__u32 *)ipp+ipp->ihl);
					if (udp->check == 0) {
						KLIPS_PRINT(debug_rcv,
				    		"klips_debug:ipsec_rcv: "
							"NAT-T & TRANSPORT: UDP checksum already 0\n");
					}
					else if (natt_oa) {
						__u32 buff[2] = { ~natt_oa, ipp->saddr };
						KLIPS_PRINT(debug_rcv,
				    		"klips_debug:ipsec_rcv: "
							"NAT-T & TRANSPORT: "
							"fix UDP checksum using NAT-OA\n");
						udp->check = csum_fold(
							csum_partial((unsigned char *)buff, sizeof(buff),
							udp->check^0xffff));
					}
					else {
						KLIPS_PRINT(debug_rcv,
				    		"klips_debug:ipsec_rcv: "
							"NAT-T & TRANSPORT: zero UDP checksum\n");
						udp->check = 0;
					}
				}
				else {
					KLIPS_PRINT(debug_rcv,
			    		"klips_debug:ipsec_rcv: "
						"NAT-T & TRANSPORT: can't fix UDP checksum\n");
				}
				break;
			default:
				KLIPS_PRINT(debug_rcv,
			    	"klips_debug:ipsec_rcv: "
					"NAT-T & TRANSPORT: non TCP/UDP packet -- do nothing\n");
				break;
		}
	}
#endif

    /*
    * XXX this needs to be locked from when it was first looked
    * up in the decapsulation loop.  Perhaps it is better to put
    * the IPIP decap inside the loop.
    */
    if(tdbnext) {
      delRcvDesc_from_salist(tdbp, pRcvDesc);
      tdbp = tdbnext;
      addRcvDesc_to_salist(tdbp, pRcvDesc);
      pRcvDesc->tdbp = tdbp;


#ifdef CONFIG_IPSEC_DEBUG
      sa_len = satoa(tdbp->tdb_said, 0, sa, SATOA_BUF);
#endif /* CONFIG_IPSEC_DEBUG */
      if(ipp->protocol != IPPROTO_IPIP) {
	      delRcvDesc_from_salist(tdbp, pRcvDesc);
	      spin_unlock(&tdb_lock);
	      KLIPS_PRINT(debug_rcv,
		      "klips_debug:ipsec_rcv: "
		      "SA:%s, Hey!  How did this get through?  Dropped.\n",
		      sa_len ? sa : " (error)");
	      if(pRcvDesc->stats) {
		      (pRcvDesc->stats)->rx_dropped++;
	      }
	      goto rcvleave;
      }
      if(sysctl_ipsec_inbound_policy_check) {
	      tdbnext = tdbp->tdb_inext;
	      if(tdbnext) {
		      char sa2[SATOA_BUF];
		      size_t sa_len2;
		      sa_len2 = satoa(tdbnext->tdb_said, 0, sa2, SATOA_BUF);
		      delRcvDesc_from_salist(tdbp, pRcvDesc);
		      spin_unlock(&tdb_lock);
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "unexpected SA:%s after IPIP SA:%s\n",
			      sa_len2 ? sa2 : " (error)",
			      sa_len ? sa : " (error)");
		      if(pRcvDesc->stats) {
			      (pRcvDesc->stats)->rx_dropped++;
		      }
		      goto rcvleave;
	      }
	      if(ipp->saddr != ((struct sockaddr_in*)(tdbp->tdb_addr_s))->sin_addr.s_addr) {
		      delRcvDesc_from_salist(tdbp, pRcvDesc);
		      spin_unlock(&tdb_lock);
		      ipaddr.s_addr = ipp->saddr;
		      addrtoa(ipaddr, 0, ipaddr_txt, sizeof(ipaddr_txt));
		      KLIPS_PRINT(debug_rcv,
			      "klips_debug:ipsec_rcv: "
			      "SA:%s, src=%s of pkt does not agree with expected SA source address policy.\n",
			      sa_len ? sa : " (error)",
			      ipaddr_txt);
		      if(pRcvDesc->stats) {
			      (pRcvDesc->stats)->rx_dropped++;
		      }
		      goto rcvleave;
	      }
      } /* end of if(sysctl_ipsec_inbound_policy_check) */

      /*
      * XXX this needs to be locked from when it was first looked
      * up in the decapsulation loop.  Perhaps it is better to put
      * the IPIP decap inside the loop.
      */
      tdbp->ips_life.ipl_bytes.ipl_count += len;
      tdbp->ips_life.ipl_bytes.ipl_last   = len;

      if(!tdbp->ips_life.ipl_usetime.ipl_count) {
	      tdbp->ips_life.ipl_usetime.ipl_count = jiffies / HZ;
      }
      tdbp->ips_life.ipl_usetime.ipl_last = jiffies / HZ;
      tdbp->ips_life.ipl_packets.ipl_count += 1;

      if(skb->len < iphlen) {
	      printk(KERN_WARNING "klips_debug:ipsec_rcv: "
	      "tried to skb_pull iphlen=%d, %d available.  This should never happen, please report.\n",
	      iphlen,
	      (int)(skb->len));

	      delRcvDesc_from_salist(tdbp, pRcvDesc);
	      spin_unlock (&tdb_lock);
	      goto rcvleave;
      }
      skb_pull(skb, iphlen);

#ifdef NET_21
      ipp = (struct iphdr *)skb->nh.raw = skb->data;
      skb->h.raw = skb->nh.raw + (skb->nh.iph->ihl << 2);

      memset(&(IPCB(skb)->opt), 0, sizeof(struct ip_options));
#else /* NET_21 */
      ipp = skb->ip_hdr = skb->h.iph = (struct iphdr *)skb->data;

      memset(skb->proto_priv, 0, sizeof(struct options));
#endif /* NET_21 */

      skb->protocol = htons(ETH_P_IP);
      skb->ip_summed = 0;
      KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
	      "klips_debug:ipsec_rcv: "
	      "IPIP tunnel stripped.\n");
      KLIPS_IP_PRINT(debug_rcv & DB_RX_PKTRX, ipp);

      if(sysctl_ipsec_inbound_policy_check
	      /*
	      Note: "xor" (^) logically replaces "not equal"
	      (!=) and "bitwise or" (|) logically replaces
	      "boolean or" (||).  This is done to speed up
	      execution by doing only bitwise operations and
	      no branch operations
	      */
	      && (((ipp->saddr & tdbp->tdb_mask_s.u.v4.sin_addr.s_addr)
	      ^ tdbp->tdb_flow_s.u.v4.sin_addr.s_addr)
	      | ((ipp->daddr & tdbp->tdb_mask_d.u.v4.sin_addr.s_addr)
	      ^ tdbp->tdb_flow_d.u.v4.sin_addr.s_addr)) )
      {
	      struct in_addr daddr, saddr;
#ifdef CONFIG_IPSEC_DEBUG
		char saddr_txt[ADDRTOA_BUF], daddr_txt[ADDRTOA_BUF];
		char sflow_txt[SUBNETTOA_BUF], dflow_txt[SUBNETTOA_BUF];

		subnettoa(tdbp->tdb_flow_s.u.v4.sin_addr,
		      tdbp->tdb_mask_s.u.v4.sin_addr,
		      0, sflow_txt, sizeof(sflow_txt));
		subnettoa(tdbp->tdb_flow_d.u.v4.sin_addr,
		      tdbp->tdb_mask_d.u.v4.sin_addr,
		      0, dflow_txt, sizeof(dflow_txt));
#endif /* CONFIG_IPSEC_DEBUG */
		saddr.s_addr = ipp->saddr;
		daddr.s_addr = ipp->daddr;
#ifdef CONFIG_IPSEC_DEBUG
		addrtoa(saddr, 0, saddr_txt, sizeof(saddr_txt));
		addrtoa(daddr, 0, daddr_txt, sizeof(daddr_txt));
		KLIPS_PRINT(debug_rcv,
			"klips_debug:ipsec_rcv: "
			"SA:%s, inner tunnel policy [%s -> %s] does not agree with pkt contents [%s -> %s].\n",
			sa_len ? sa : " (error)",
			sflow_txt,
			dflow_txt,
			saddr_txt,
			daddr_txt);
#endif
		if(pRcvDesc->stats) {
		    (pRcvDesc->stats)->rx_dropped++;
		}
		delRcvDesc_from_salist(tdbp, pRcvDesc);
	      spin_unlock (&tdb_lock);
		goto rcvleave;
      }
     } /* end of if(tdbnext) */

    delRcvDesc_from_salist(tdbp, pRcvDesc);
    spin_unlock(&tdb_lock);


#ifdef INBOUND_POLICY_CHECK_eroute
    /*
    Do *not* enable this without thoroughly checking spinlock issues
    first.  In particular, nesting an eroute spinlock within a tdb
    spinlock could result in a deadlock.  (Well, only on a SMP machine
    under 2.4?)
    */

    /*
    * First things first -- look us up in the erouting tables.
    */
    matcher.sen_len = sizeof (struct sockaddr_encap);
    matcher.sen_family = AF_ENCAP;
    matcher.sen_type = SENT_IP4;
    if(ipp->protocol == IPPROTO_IPIP) {
      struct iphdr *ipp2;

      ipp2 = (struct iphdr*) (((char*)ipp) + (ipp->ihl << 2));
      matcher.sen_ip_src.s_addr = ipp2->saddr;
      matcher.sen_ip_dst.s_addr = ipp2->daddr;
    } else {
      matcher.sen_ip_src.s_addr = ipp->saddr;
      matcher.sen_ip_dst.s_addr = ipp->daddr;
    }

    /*
    * The spinlock is to prevent any other process from accessing or
    * deleting the eroute while we are using and updating it.
    */
    spin_lock(&eroute_lock);

    er = ipsec_findroute(&matcher);
    if(er) {
      policy_said = er->er_said;
      policy_eaddr = er->er_eaddr;
      policy_emask = er->er_emask;
      er->er_count++;
      er->er_lasttime = jiffies/HZ;
    }

    spin_unlock(&eroute_lock);

    if(er) {
      /*
      * The spinlock is to prevent any other process from
      * accessing or deleting the tdb while we are using and
      * updating it.
      */
      spin_lock(&tdb_lock);

      policy_tdb = gettdb(&policy_said);
      if (policy_tdb == NULL) {
	      spin_unlock(&tdb_lock);
	      KLIPS_PRINT(debug_rcv,
		      "klips_debug:ipsec_rcv: "
		      "no Tunnel Descriptor Block for SA%s: incoming packet with no policy SA, dropped.\n",
		      sa_len ? sa : " (error)");
	      goto rcvleave;
      }

      sa_len = satoa(policy_said, 0, sa, SATOA_BUF);

      KLIPS_PRINT(debug_rcv,
	      "klips_debug:ipsec_rcv: "
	      "found policy Tunnel Descriptor Block -- SA:%s\n",
	      sa_len ? sa : " (error)");
      while(1) {
	      if(policy_tdb->tdb_inext) {
	      policy_tdb = policy_tdb->tdb_inext;
	      } else {
	      break;
	      }
      }

      if(policy_tdb != tdbp) {
	      spin_unlock(&tdb_lock);
	      KLIPS_PRINT(debug_rcv,
		      "klips_debug:ipsec_rcv: "
		      "Tunnel Descriptor Block for SA%s: incoming packet with different policy SA, dropped.\n",
		      sa_len ? sa : " (error)");
	      goto rcvleave;
      }

      spin_unlock(&tdb_lock);
     } /* end of if(er) */
#endif /* INBOUND_POLICY_CHECK_eroute */

#ifdef NET_21
    if(pRcvDesc->stats) {
      (pRcvDesc->stats)->rx_bytes += skb->len;
    }
    if(skb->dst) {
      dst_release(skb->dst);
      skb->dst = NULL;
    }
    skb->pkt_type = PACKET_HOST;
    if(pRcvDesc->hard_header_len &&
      (skb->mac.raw != (skb->data - pRcvDesc->hard_header_len)) &&
      (pRcvDesc->hard_header_len <= skb_headroom(skb))) {
      /* copy back original MAC header */
      memmove(skb->data - pRcvDesc->hard_header_len, skb->mac.raw, pRcvDesc->hard_header_len);
      skb->mac.raw = skb->data - pRcvDesc->hard_header_len;
    }
#endif /* NET_21 */

#ifdef CONFIG_IPSEC_IPCOMP
    if(ipp->protocol == IPPROTO_COMP) {
      unsigned int flags = 0;

      if(sysctl_ipsec_inbound_policy_check) {
	      KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
	      "klips_debug:ipsec_rcv: "
	      "inbound policy checking enabled, IPCOMP follows IPIP, dropped.\n");
	      if (pRcvDesc->stats) {
		      (pRcvDesc->stats)->rx_errors++;
	      }
	      goto rcvleave;
      }
      /*
      XXX need a TDB for updating ratio counters but it is not
      following policy anyways so it is not a priority
      */
      skb = skb_decompress(skb, NULL, &flags);
      if (!skb || flags) {
	      KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
	      "klips_debug:ipsec_rcv: "
	      "skb_decompress() returned error flags: %d, dropped.\n",
	      flags);
	      if (pRcvDesc->stats) {
	      (pRcvDesc->stats)->rx_errors++;
	      }
	      goto rcvleave;
      }
    }
#endif /* CONFIG_IPSEC_IPCOMP */

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

    KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
      "klips_debug:ipsec_rcv: "
      "netif_rx() called.\n");
    netif_rx(skb);

/* release desc */
    if (pRcvDesc)
      ipsec_glue_rcv_desc_release (pRcvDesc);

    MOD_DEC_USE_COUNT;
    return(0);

rcvleave:
    /* release desc */
    if (pRcvDesc)
	ipsec_glue_rcv_desc_release (pRcvDesc);

    if(skb) {
#ifdef NET_21
      kfree_skb(skb);
#else /* NET_21 */
      kfree_skb(skb, FREE_WRITE);
#endif /* NET_21 */
    }

	MOD_DEC_USE_COUNT;
	return(0);
}

struct inet_protocol ah_protocol =
{
	ipsec_rcv,				/* AH handler */
	NULL,				/* TUNNEL error control */
	0,				/* next */
	IPPROTO_AH,			/* protocol ID */
	0,				/* copy */
	NULL,				/* data */
	"AH"				/* name */
};

struct inet_protocol esp_protocol = 
{
	ipsec_rcv,			/* ESP handler          */
	NULL,				/* TUNNEL error control */
	0,				/* next */
	IPPROTO_ESP,			/* protocol ID */
	0,				/* copy */
	NULL,				/* data */
	"ESP"				/* name */
};

#if 0
/* We probably don't want to install a pure IPCOMP protocol handler, but
   only want to handle IPCOMP if it is encapsulated inside an ESP payload
   (which is already handled) */
#ifdef CONFIG_IPSEC_IPCOMP
struct inet_protocol comp_protocol =
{
	ipsec_rcv,			/* COMP handler		*/
	NULL,				/* COMP error control	*/
	0,				/* next */
	IPPROTO_COMP,			/* protocol ID */
	0,				/* copy */
	NULL,				/* data */
	"COMP"				/* name */
};
#endif /* CONFIG_IPSEC_IPCOMP */
#endif

/*
 * $Log: ipsec_rcv.c,v $
 * Revision 1.2.2.1  2004/08/31 05:59:47  philipc
 * The NAT traversal support was not releasing descriptors for IKE packets.
 * This happens even if NAT traversal is not being used.  Result was that
 * 1000 IKE packets later we ran out of descriptors.
 *
 * Additionally, once we did run out of descriptors, we started releasing
 * uninitialised pointers back to the descriptor pool.  If you were lucky
 * this would merely result in a null pointer access;  other values cause
 * varying unusual effects.
 *
 * rt://150996
 *
 * Revision 1.2  2004/06/11 01:15:08  davidm
 *
 * Allow kernel to compile with ipsec debug disabled.
 * rt://95179
 *
 * Revision 1.1  2004/05/11 00:38:42  danield
 * Added support for hardware acceleration on the xscale. To make use of this
 * ability you will need to select CONFIG_IXP4XX_CRYPTO in your kernel config
 *
 * rt://112828
 *
 * Revision 1.9.2.1  2003/06/30 05:04:07  matthewn
 * We need to set the physindev when we receive a packet via IPSec.
 *
 * Revision 1.102  2002/01/29 17:17:56  mcr
 * 	moved include of ipsec_param.h to after include of linux/kernel.h
 * 	otherwise, it seems that some option that is set in ipsec_param.h
 * 	screws up something subtle in the include path to kernel.h, and
 * 	it complains on the snprintf() prototype.
 *
 * Revision 1.101  2002/01/29 04:00:52  mcr
 * 	more excise of kversions.h header.
 *
 * Revision 1.100  2002/01/29 02:13:17  mcr
 * 	introduction of ipsec_kversion.h means that include of
 * 	ipsec_param.h must preceed any decisions about what files to
 * 	include to deal with differences in kernel source.
 *
 * Revision 1.99  2002/01/28 21:40:59  mcr
 * 	should use #if to test boolean option rather than #ifdef.
 *
 * Revision 1.98  2002/01/20 20:19:36  mcr
 * 	renamed option to IP_FRAGMENT_LINEARIZE.
 *
 * Revision 1.97  2002/01/12 02:55:36  mcr
 * 	fix for post-2.4.4 to linearize skb's when ESP packet
 * 	was assembled from fragments.
 *
 * Revision 1.96  2001/11/26 09:23:49  rgb
 * Merge MCR's ipsec_sa, eroute, proc and struct lifetime changes.
 *
 * Revision 1.93.2.2  2001/10/22 20:54:07  mcr
 * 	include des.h, removed phony prototypes and fixed calling
 * 	conventions to match real prototypes.
 *
 * Revision 1.93.2.1  2001/09/25 02:22:22  mcr
 * 	struct tdb -> struct ipsec_sa.
 * 	lifetime checks moved to ipsec_life.c
 * 	some sa(tdb) manipulation functions renamed.
 *
 * Revision 1.95  2001/11/06 19:49:07  rgb
 * Added variable descriptions.
 * Removed unauthenticated sequence==0 check to prevent DoS.
 *
 * Revision 1.94  2001/10/18 04:45:20  rgb
 * 2.4.9 kernel deprecates linux/malloc.h in favour of linux/slab.h,
 * lib/freeswan.h version macros moved to lib/kversions.h.
 * Other compiler directive cleanups.
 *
 * Revision 1.93  2001/09/07 22:17:24  rgb
 * Fix for removal of transport layer protocol handler arg in 2.4.4.
 * Fix to accomodate peer non-conformance to IPCOMP rfc2393.
 *
 * Revision 1.92  2001/08/27 19:44:41  rgb
 * Fix error in comment.
 *
 * Revision 1.91  2001/07/20 19:31:48  dhr
 * [DHR] fix source and destination subnets of policy in diagnostic
 *
 * Revision 1.90  2001/07/06 19:51:09  rgb
 * Added inbound policy checking code for IPIP SAs.
 * Renamed unused function argument for ease and intuitive naming.
 *
 * Revision 1.89  2001/06/22 19:35:23  rgb
 * Disable ipcomp processing if we are handed a ipcomp packet with no esp
 * or ah header.
 * Print protocol if we are handed a non-ipsec packet.
 *
 * Revision 1.88  2001/06/20 06:30:47  rgb
 * Fixed transport mode IPCOMP policy check bug.
 *
 * Revision 1.87  2001/06/13 20:58:40  rgb
 * Added parentheses around assignment used as truth value to silence
 * compiler.
 *
 * Revision 1.86  2001/06/07 22:25:23  rgb
 * Added a source address policy check for tunnel mode.  It still does
 * not check client addresses and masks.
 * Only decapsulate IPIP if it is expected.
 *
 * Revision 1.85  2001/05/30 08:14:02  rgb
 * Removed vestiges of esp-null transforms.
 *
 * Revision 1.84  2001/05/27 06:12:11  rgb
 * Added structures for pid, packet count and last access time to eroute.
 * Added packet count to beginning of /proc/net/ipsec_eroute.
 *
 * Revision 1.83  2001/05/04 16:45:47  rgb
 * Remove unneeded code.  ipp is not used after this point.
 *
 * Revision 1.82  2001/05/04 16:36:00  rgb
 * Fix skb_cow() call for 2.4.4. (SS)
 *
 * Revision 1.81  2001/05/02 14:46:53  rgb
 * Fix typo for compiler directive to pull IPH back.
 *
 * Revision 1.80  2001/04/30 19:46:34  rgb
 * Update for 2.4.4.  We now receive the skb with skb->data pointing to
 * h.raw.
 *
 * Revision 1.79  2001/04/23 15:01:15  rgb
 * Added spin_lock() check to prevent double-locking for multiple
 * transforms and hence kernel lock-ups with SMP kernels.
 * Minor spin_unlock() adjustments to unlock before non-dependant prints
 * and IPSEC device stats updates.
 *
 * Revision 1.78  2001/04/21 23:04:24  rgb
 * Check if soft expire has already been sent before sending another to
 * prevent ACQUIRE flooding.
 *
 * Revision 1.77  2001/03/16 07:35:20  rgb
 * Ditch extra #if 1 around now permanent policy checking code.
 *
 * Revision 1.76  2001/02/27 22:24:54  rgb
 * Re-formatting debug output (line-splitting, joining, 1arg/line).
 * Check for satoa() return codes.
 *
 * Revision 1.75  2001/02/19 22:28:30  rgb
 * Minor change to virtual device discovery code to assert which I/F has
 * been found.
 *
 * Revision 1.74  2000/11/25 03:50:36  rgb
 * Oops fix by minor re-arrangement of code to avoid accessing a freed tdb.
 *
 * Revision 1.73  2000/11/09 20:52:15  rgb
 * More spinlock shuffling, locking earlier and unlocking later in rcv to
 * include ipcomp and prevent races, renaming some tdb variables that got
 * forgotten, moving some unlocks to include tdbs and adding a missing
 * unlock.  Thanks to Svenning for some of these.
 *
 * Revision 1.72  2000/11/09 20:11:22  rgb
 * Minor shuffles to fix non-standard kernel config option selection.
 *
 * Revision 1.71  2000/11/06 04:36:18  rgb
 * Ditched spin_lock_irqsave in favour of spin_lock.
 * Minor initial protocol check rewrite.
 * Clean up debug printing.
 * Clean up tdb handling on ipcomp.
 * Fixed transport mode null pointer de-reference without ipcomp.
 * Add Svenning's adaptive content compression.
 * Disabled registration of ipcomp handler.
 *
 * Revision 1.70  2000/10/30 23:41:43  henry
 * Hans-Joerg Hoexer's null-pointer fix
 *
 * Revision 1.69  2000/10/10 18:54:16  rgb
 * Added a fix for incoming policy check with ipcomp enabled but
 * uncompressible.
 *
 * Revision 1.68  2000/09/22 17:53:12  rgb
 * Fixed ipcomp tdb pointers update for policy checking.
 *
 * Revision 1.67  2000/09/21 03:40:58  rgb
 * Added more debugging to try and track down the cpi outward copy problem.
 *
 * Revision 1.66  2000/09/20 04:00:10  rgb
 * Changed static functions to DEBUG_NO_STATIC to reveal function names for
 * debugging oopsen.
 *
 * Revision 1.65  2000/09/19 07:07:16  rgb
 * Added debugging to inbound policy check for ipcomp.
 * Added missing spin_unlocks (thanks Svenning!).
 * Fixed misplaced tdbnext pointers causing mismatched ipip policy check.
 * Protect ipcomp policy check following ipip decap with sysctl switch.
 *
 * Revision 1.64  2000/09/18 21:27:29  rgb
 * 2.0 fixes.
 *
 * Revision 1.63  2000/09/18 02:35:50  rgb
 * Added policy checking to ipcomp and re-enabled policy checking by
 * default.
 * Optimised satoa calls.
 *
 * Revision 1.62  2000/09/17 21:02:32  rgb
 * Clean up debugging, removing slow timestamp debug code.
 *
 * Revision 1.61  2000/09/16 01:07:55  rgb
 * Fixed erroneous ref from struct ipcomp to struct ipcomphdr.
 *
 * Revision 1.60  2000/09/15 11:37:01  rgb
 * Merge in heavily modified Svenning Soerensen's <svenning@post5.tele.dk>
 * IPCOMP zlib deflate code.
 *
 * Revision 1.59  2000/09/15 04:56:20  rgb
 * Remove redundant satoa() call, reformat comment.
 *
 * Revision 1.58  2000/09/13 08:00:52  rgb
 * Flick on inbound policy checking.
 *
 * Revision 1.57  2000/09/12 03:22:19  rgb
 * Converted inbound_policy_check to sysctl.
 * Re-enabled policy backcheck.
 * Moved policy checks to top and within tdb lock.
 *
 * Revision 1.56  2000/09/08 19:12:56  rgb
 * Change references from DEBUG_IPSEC to CONFIG_IPSEC_DEBUG.
 *
 * Revision 1.55  2000/08/28 18:15:46  rgb
 * Added MB's nf-debug reset patch.
 *
 * Revision 1.54  2000/08/27 01:41:26  rgb
 * More minor tweaks to the bad padding debug code.
 *
 * Revision 1.53  2000/08/24 16:54:16  rgb
 * Added KLIPS_PRINTMORE macro to continue lines without KERN_INFO level
 * info.
 * Tidied up device reporting at the start of ipsec_rcv.
 * Tidied up bad padding debugging and processing.
 *
 * Revision 1.52  2000/08/20 21:36:03  rgb
 * Activated pfkey_expire() calls.
 * Added a hard/soft expiry parameter to pfkey_expire().
 * Added sanity checking to avoid propagating zero or smaller-length skbs
 * from a bogus decryption.
 * Re-arranged the order of soft and hard expiry to conform to RFC2367.
 * Clean up references to CONFIG_IPSEC_PFKEYv2.
 *
 * Revision 1.51  2000/08/18 21:23:30  rgb
 * Improve bad padding warning so that the printk buffer doesn't get
 * trampled.
 *
 * Revision 1.50  2000/08/01 14:51:51  rgb
 * Removed _all_ remaining traces of DES.
 *
 * Revision 1.49  2000/07/28 13:50:53  rgb
 * Changed enet_statistics to net_device_stats and added back compatibility
 * for pre-2.1.19.
 *
 * Revision 1.48  2000/05/10 19:14:40  rgb
 * Only check usetime against soft and hard limits if the tdb has been
 * used.
 * Cast output of ntohl so that the broken prototype doesn't make our
 * compile noisy.
 *
 * Revision 1.47  2000/05/09 17:45:43  rgb
 * Fix replay bitmap corruption bug upon receipt of bogus packet
 * with correct SPI.  This was a DoS.
 *
 * Revision 1.46  2000/03/27 02:31:58  rgb
 * Fixed authentication failure printout bug.
 *
 * Revision 1.45  2000/03/22 16:15:37  rgb
 * Fixed renaming of dev_get (MB).
 *
 * Revision 1.44  2000/03/16 08:17:24  rgb
 * Hardcode PF_KEYv2 support.
 * Fixed minor bug checking AH header length.
 *
 * Revision 1.43  2000/03/14 12:26:59  rgb
 * Added skb->nfct support for clearing netfilter conntrack bits (MB).
 *
 * Revision 1.42  2000/01/26 10:04:04  rgb
 * Fixed inbound policy checking on transport mode bug.
 * Fixed noisy 2.0 printk arguments.
 *
 * Revision 1.41  2000/01/24 20:58:02  rgb
 * Improve debugging/reporting support for (disabled) inbound
 * policy checking.
 *
 * Revision 1.40  2000/01/22 23:20:10  rgb
 * Fixed up inboud policy checking code.
 * Cleaned out unused crud.
 *
 * Revision 1.39  2000/01/21 06:15:29  rgb
 * Added sanity checks on skb_push(), skb_pull() to prevent panics.
 * Fixed cut-and-paste debug_tunnel to debug_rcv.
 * Added inbound policy checking code, disabled.
 * Simplified output code by updating ipp to post-IPIP decapsulation.
 *
 * Revision 1.38  1999/12/22 05:08:36  rgb
 * Checked for null skb, skb->dev, skb->data, skb->dev->name, dev->name,
 * protocol and take appropriate action for sanity.
 * Set ipsecdev to NULL if device could not be determined.
 * Fixed NULL stats access bug if device could not be determined.
 *
 * Revision 1.37  1999/12/14 20:07:59  rgb
 * Added a default switch case to catch bogus encalg values.
 *
 * Revision 1.36  1999/12/07 18:57:57  rgb
 * Fix PFKEY symbol compile error (SADB_*) without pfkey enabled.
 *
 * Revision 1.35  1999/12/01 22:15:35  rgb
 * Add checks for LARVAL and DEAD SAs.
 * Change state of SA from MATURE to DYING when a soft lifetime is
 * reached and print debug warning.
 *
 * Revision 1.34  1999/11/23 23:04:03  rgb
 * Use provided macro ADDRTOA_BUF instead of hardcoded value.
 * Sort out pfkey and freeswan headers, putting them in a library path.
 *
 * Revision 1.33  1999/11/19 01:10:06  rgb
 * Enable protocol handler structures for static linking.
 *
 * Revision 1.32  1999/11/18 04:09:19  rgb
 * Replaced all kernel version macros to shorter, readable form.
 *
 * Revision 1.31  1999/11/17 15:53:39  rgb
 * Changed all occurrences of #include "../../../lib/freeswan.h"
 * to #include <freeswan.h> which works due to -Ilibfreeswan in the
 * klips/net/ipsec/Makefile.
 *
 * Revision 1.30  1999/10/26 15:09:07  rgb
 * Used debug compiler directives to shut up compiler for decl/assign
 * statement.
 *
 * Revision 1.29  1999/10/16 18:25:37  rgb
 * Moved SA lifetime expiry checks before packet processing.
 * Expire SA on replay counter rollover.
 *
 * Revision 1.28  1999/10/16 04:23:07  rgb
 * Add stats for replaywin_errs, replaywin_max_sequence_difference,
 * authentication errors, encryption size errors, encryption padding
 * errors, and time since last packet.
 *
 * Revision 1.27  1999/10/16 00:30:47  rgb
 * Added SA lifetime counting.
 *
 * Revision 1.26  1999/10/15 22:14:37  rgb
 * Add debugging.
 *
 * Revision 1.25  1999/10/08 18:37:34  rgb
 * Fix end-of-line spacing to sate whining PHMs.
 *
 * Revision 1.24  1999/10/03 18:54:51  rgb
 * Spinlock support for 2.3.xx.
 * Don't forget to undo spinlocks on error!
 *
 * Revision 1.23  1999/10/01 15:44:53  rgb
 * Move spinlock header include to 2.1> scope.
 *
 * Revision 1.22  1999/10/01 00:01:54  rgb
 * Added tdb structure locking.
 *
 * Revision 1.21  1999/09/18 11:42:12  rgb
 * Add Marc Boucher's tcpdump cloned packet fix.
 *
 * Revision 1.20  1999/09/17 23:50:25  rgb
 * Add Marc Boucher's hard_header_len patches.
 *
 * Revision 1.19  1999/09/10 05:31:36  henry
 * tentative fix for 2.0.38-crash bug (move chunk of new code into 2.2 #ifdef)
 *
 * Revision 1.18  1999/08/28 08:28:06  rgb
 * Delete redundant sanity check.
 *
 * Revision 1.17  1999/08/28 02:00:58  rgb
 * Add an extra sanity check for null skbs.
 *
 * Revision 1.16  1999/08/27 05:21:38  rgb
 * Clean up skb->data/raw/nh/h manipulation.
 * Add Marc Boucher's mods to aid tcpdump.
 *
 * Revision 1.15  1999/08/25 14:22:40  rgb
 * Require 4-octet boundary check only for ESP.
 *
 * Revision 1.14  1999/08/11 08:36:44  rgb
 * Add compiler directives to allow configuring out AH, ESP or transforms.
 *
 * Revision 1.13  1999/08/03 17:10:49  rgb
 * Cosmetic fixes and clarification to debug output.
 *
 * Revision 1.12  1999/05/09 03:25:36  rgb
 * Fix bug introduced by 2.2 quick-and-dirty patch.
 *
 * Revision 1.11  1999/05/08 21:23:57  rgb
 * Add casting to silence the 2.2.x compile.
 *
 * Revision 1.10  1999/05/05 22:02:31  rgb
 * Add a quick and dirty port to 2.2 kernels by Marc Boucher <marc@mbsi.ca>.
 *
 * Revision 1.9  1999/04/29 15:18:01  rgb
 * hange debugging to respond only to debug_rcv.
 * Change gettdb parameter to a pointer to reduce stack loading and
 * facilitate parameter sanity checking.
 *
 * Revision 1.8  1999/04/15 15:37:24  rgb
 * Forward check changes from POST1_00 branch.
 *
 * Revision 1.4.2.2  1999/04/13 20:32:45  rgb
 * Move null skb sanity check.
 * Silence debug a bit more when off.
 * Use stats more effectively.
 *
 * Revision 1.4.2.1  1999/03/30 17:10:32  rgb
 * Update AH+ESP bugfix.
 *
 * Revision 1.7  1999/04/11 00:28:59  henry
 * GPL boilerplate
 *
 * Revision 1.6  1999/04/06 04:54:27  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 * Revision 1.5  1999/03/17 15:39:23  rgb
 * Code clean-up.
 * Bundling bug fix.
 * ESP_NULL esphlen and IV bug fix.
 *
 * Revision 1.4  1999/02/17 16:51:02  rgb
 * Ditch NET_IPIP dependancy.
 * Decapsulate recursively for an entire bundle.
 *
 * Revision 1.3  1999/02/12 21:22:47  rgb
 * Convert debugging printks to KLIPS_PRINT macro.
 * Clean-up cruft.
 * Process IPIP tunnels internally.
 *
 * Revision 1.2  1999/01/26 02:07:36  rgb
 * Clean up debug code when switched off.
 * Remove references to INET_GET_PROTOCOL.
 *
 * Revision 1.1  1999/01/21 20:29:11  rgb
 * Converted from transform switching to algorithm switching.
 *
 *
 * Id: ipsec_esp.c,v 1.16 1998/12/02 03:08:11 rgb Exp $
 *
 * Log: ipsec_esp.c,v $
 * Revision 1.16  1998/12/02 03:08:11  rgb
 * Fix incoming I/F bug in AH and clean up inconsistencies in the I/F
 * discovery routine in both AH and ESP.
 *
 * Revision 1.15  1998/11/30 13:22:51  rgb
 * Rationalised all the klips kernel file headers.  They are much shorter
 * now and won't conflict under RH5.2.
 *
 * Revision 1.14  1998/11/10 05:55:37  rgb
 * Add even more detail to 'wrong I/F' debug statement.
 *
 * Revision 1.13  1998/11/10 05:01:30  rgb
 * Clean up debug output to be quiet when disabled.
 * Add more detail to 'wrong I/F' debug statement.
 *
 * Revision 1.12  1998/10/31 06:39:32  rgb
 * Fixed up comments in #endif directives.
 * Tidied up debug printk output.
 * Convert to addrtoa and satoa where possible.
 *
 * Revision 1.11  1998/10/27 00:49:30  rgb
 * AH+ESP bundling bug has been squished.
 * Cosmetic brace fixing in code.
 * Newlines added before calls to ipsec_print_ip.
 * Fix debug output function ID's.
 *
 * Revision 1.10  1998/10/22 06:37:22  rgb
 * Fixed run-on error message to fit 80 columns.
 *
 * Revision 1.9  1998/10/20 02:41:04  rgb
 * Fixed a replay window size sanity test bug.
 *
 * Revision 1.8  1998/10/19 18:55:27  rgb
 * Added inclusion of freeswan.h.
 * sa_id structure implemented and used: now includes protocol.
 * \n bugfix to printk debug message.
 *
 * Revision 1.7  1998/10/09 04:23:03  rgb
 * Fixed possible DoS caused by invalid transform called from an ESP
 * packet.  This should not be a problem when protocol is added to the SA.
 * Sanity check added for null xf_input routine.  Sanity check added for null
 * socket buffer returned from xf_input routine.
 * Added 'klips_debug' prefix to all klips printk debug statements.
 *
 * Revision 1.6  1998/07/14 15:56:04  rgb
 * Set sdb->dev to virtual ipsec I/F.
 *
 * Revision 1.5  1998/06/30 18:07:46  rgb
 * Change for ah/esp_protocol stuct visible only if module.
 *
 * Revision 1.4  1998/06/30 00:12:46  rgb
 * Clean up a module compile error.
 *
 * Revision 1.3  1998/06/25 19:28:06  rgb
 * Readjust premature unloading of module on packet receipt.
 * Make protocol structure abailable to rest of kernel.
 * Use macro for protocol number.
 *
 * Revision 1.2  1998/06/23 02:49:34  rgb
 * Fix minor #include bug that prevented compiling without debugging.
 * Added code to check for presence of IPIP protocol if an incoming packet
 * is IPIP encapped.
 *
 * Revision 1.1  1998/06/18 21:27:44  henry
 * move sources from klips/src to klips/net/ipsec, to keep stupid
 * kernel-build scripts happier in the presence of symlinks
 *
 * Revision 1.9  1998/06/14 23:48:42  rgb
 * Fix I/F name comparison oops bug.
 *
 * Revision 1.8  1998/06/11 07:20:04  rgb
 * Stats fixed for rx_packets.
 *
 * Revision 1.7  1998/06/11 05:53:34  rgb
 * Added stats for rx error and good packet reporting.
 *
 * Revision 1.6  1998/06/05 02:27:28  rgb
 * Add rx_errors stats.
 * Fix DoS bug:  skb's not being freed on dropped packets.
 *
 * Revision 1.5  1998/05/27 21:21:29  rgb
 * Fix DoS potential bug.  skb was not being freed if the packet was bad.
 *
 * Revision 1.4  1998/05/18 22:31:37  rgb
 * Minor change in debug output and comments.
 *
 * Revision 1.3  1998/04/21 21:29:02  rgb
 * Rearrange debug switches to change on the fly debug output from user
 * space.  Only kernel changes checked in at this time.  radij.c was also
 * changed to temporarily remove buggy debugging code in rj_delete causing
 * an OOPS and hence, netlink device open errors.
 *
 * Revision 1.2  1998/04/12 22:03:19  rgb
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
 * Revision 1.1  1998/04/09 03:05:59  henry
 * sources moved up from linux/net/ipsec
 *
 * Revision 1.1.1.1  1998/04/08 05:35:04  henry
 * RGB's ipsec-0.8pre2.tar.gz ipsec-0.8
 *
 * Revision 0.4  1997/01/15 01:28:15  ji
 * Minor cosmetic changes.
 *
 * Revision 0.3  1996/11/20 14:35:48  ji
 * Minor Cleanup.
 * Rationalized debugging code.
 *
 * Revision 0.2  1996/11/02 00:18:33  ji
 * First limited release.
 *
 *
 */
