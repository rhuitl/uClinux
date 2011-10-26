/*
 * @(#) Definitions of IPsec Security Association (ipsec_sa)
 *
 * Copyright (C) 2001  Richard Guy Briggs  <rgb@freeswan.org>
 *                 and Michael Richardson  <mcr@freeswan.org>
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
 *
 * RCSID $Id: ipsec_sa.h,v 1.2 2001/11/26 09:16:15 rgb Exp $
 *
 * This file derived from ipsec_xform.h on 2001/9/18 by mcr.
 *
 */

/* 
 * This file describes the IPsec Security Association Structure.
 *
 * This structure keeps track of a single transform that may be done
 * to a set of packets. It can describe applying the transform or
 * apply the reverse. (e.g. compression vs expansion). However, it
 * only describes one at a time. To describe both, two structures would
 * be used, but since the sides of the transform are performed 
 * on different machines typically it is usual to have only one side
 * of each association.
 * 
 */

#ifndef _IPSEC_SA_H_
#ifdef USE_IXP4XX_CRYPTO
#define _IPSEC_SA_H_
#endif /* USE_IXP4XX_CRYPTO */

#include "ipsec_stats.h"
#include "ipsec_life.h"
#include "ipsec_eroute.h"

struct _IpsecXmitDesc;
struct _IpsecRcvDesc;

/* 'struct ipsec_sa' should be 64bit aligned when allocated. */
struct ipsec_sa 	                        
{
	atomic_t         ips_usecount;       /* use count for this struct */
	struct ipsec_sa	*ips_hnext;	     /* next in hash chain */
	struct ipsec_sa	*ips_inext;	     /* pointer to next xform */
	struct ipsec_sa	*ips_onext;	     /* pointer to prev xform */

	struct ifnet	*ips_rcvif;	     /* related rcv encap interface */

	struct sa_id	ips_said;	     /* SA ID */

	__u32		ips_seq;    /* seq num of msg that initiated this SA */
	__u32		ips_pid;    /* PID of process that initiated this SA */
	__u8		ips_authalg;	     /* auth algorithm for this SA */
	__u8		ips_encalg;	     /* enc algorithm for this SA */

	struct ipsec_stats ips_errs;

	__u8		ips_replaywin;		/* replay window size */
	__u8		ips_state;		/* state of SA */
#ifdef USE_IXP4XX_CRYPTO
	__u8		ips_teardown_initiated;/* to initiate teardown */
#endif /* USE_IXP4XX_CRYPTO */
	__u32		ips_replaywin_lastseq;	/* last pkt sequence num */
	__u64		ips_replaywin_bitmap;	/* bitmap of received pkts */
	__u32		ips_replaywin_maxdiff;	/* max pkt sequence difference */

	__u32		ips_flags;		/* generic xform flags */


	struct ipsec_lifetimes ips_life;             /* lifetime records */

	/* selector information */
	struct sockaddr*ips_addr_s;		/* src sockaddr */
	struct sockaddr*ips_addr_d;		/* dst sockaddr */
	struct sockaddr*ips_addr_p;		/* proxy sockaddr */
	__u16		ips_addr_s_size;
	__u16		ips_addr_d_size;
	__u16		ips_addr_p_size;
	ip_address	ips_flow_s;
	ip_address	ips_flow_d;
	ip_address	ips_mask_s;
	ip_address	ips_mask_d;

	__u16		ips_key_bits_a;	    /* size of authkey in bits */
	__u16		ips_auth_bits;	    /* size of authenticator in bits */
	__u16		ips_key_bits_e;	    /* size of enckey in bits */
	__u16		ips_iv_bits;	    /* size of IV in bits */
	__u8		ips_iv_size;
	__u16		ips_key_a_size;
	__u16		ips_key_e_size;

#ifdef USE_IXP4XX_CRYPTO
#ifdef CONFIG_IPSEC_ALG
	__u16       ips_enc_blksize;    /* cipher block size in bytes */
#endif /* CONFIG_IPSEC_ALG */
#endif /* USE_IXP4XX_CRYPTO */
	caddr_t		ips_key_a;		/* authentication key */
	caddr_t		ips_key_e;		/* encryption key */
	caddr_t	        ips_iv;			/* Initialisation Vector */

	struct ident	ips_ident_s;		/* identity src */
	struct ident	ips_ident_d;		/* identity dst */

#ifdef CONFIG_IPSEC_IPCOMP
	__u16		ips_comp_adapt_tries;	/* ipcomp self-adaption tries */
	__u16		ips_comp_adapt_skip;	/* ipcomp self-adaption to-skip */
	__u64		ips_comp_ratio_cbytes;	/* compressed bytes */
	__u64		ips_comp_ratio_dbytes;	/* decompressed (or uncompressed) bytes */
#endif /* CONFIG_IPSEC_IPCOMP */

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	__u8        ips_natt_type;
	__u8        ips_natt_reserved[3];
	__u16       ips_natt_sport;
	__u16       ips_natt_dport;
 
	struct sockaddr *ips_natt_oa;
	__u16		ips_natt_oa_size;
	__u16		ips_natt_reserved2;
#endif

#if 0
	__u32		ips_sens_dpd;
	__u8		ips_sens_sens_level;
	__u8		ips_sens_sens_len;
	__u64*		ips_sens_sens_bitmap;
	__u8		ips_sens_integ_level;
	__u8		ips_sens_integ_len;
	__u64*		ips_sens_integ_bitmap;
#endif
#ifdef USE_IXP4XX_CRYPTO
	__u32		ips_crypto_state;
	__u32		ips_crypto_context_id;	 /*  IXP4XX Cryto Context ID  */
	
	/* The two lists below - XmitDesc_head and RcvDesc_head
	   are used for check and balance of the packets. When we tear down 
	   a tunnel we reset the sa's to NULL in the descriptor lists for that sa. */
	struct _IpsecXmitDesc *XmitDesc_head; /* used to keep track of which xmit descriptors belong to the sa */
	struct _IpsecRcvDesc *RcvDesc_head; /* used to keep track of which rcv descriptors belong to the sa */
	struct _IpsecXmitDesc *XmitDesc_tail; /* used to keep track of which xmit descriptors belong to the sa */
	struct _IpsecRcvDesc *RcvDesc_tail; /* used to keep track of which rcv descriptors belong to the sa */	
#endif /* USE_IXP4XX_CRYPTO */
	struct ipsec_alg_enc *ips_alg_enc;
	struct ipsec_alg_auth *ips_alg_auth;
};

enum ipsec_direction {
	ipsec_incoming = 1,
	ipsec_outgoing = 2
};

#ifdef IPSEC_KLIPS1_COMPAT
#define tdb_hnext ips_hnext
#define tdb_inext ips_inext
#define tdb_onext ips_onext
#define tdb_said  ips_said
#define tdb_addr_s ips_addr_s
#define tdb_addr_s_size ips_addr_s_size
#define tdb_addr_d ips_addr_d
#define tdb_addr_d_size ips_addr_d_size
#define tdb_addr_p ips_addr_p
#define tdb_addr_p_size ips_addr_p_size
#define tdb_ident_s ips_ident_s
#define tdb_ident_d ips_ident_d
#define tdb_state   ips_state

#define tdb_replaywin ips_replaywin
#define tdb_replaywin_lastseq ips_replaywin_lastseq
#define tdb_replaywin_bitmap  ips_replaywin_bitmap
#define tdb_replaywin_maxdiff ips_replaywin_maxdiff
#define tdb_replaywin_errs    ips_errs.ips_replaywin_errs

#define tdb_encalg    ips_encalg
#define tdb_encsize_errs ips_errs.ips_encsize_errs
#define tdb_encpad_errs  ips_errs.ips_encpad_errs
#define tdb_alg_errs  ips_errs.ips_alg_errs
#define tdb_authalg   ips_authalg
#define tdb_auth_errs ips_errs.ips_auth_errs
#define tdb_iv        ips_iv
#define tdb_iv_size   ips_iv_size
#define tdb_iv_bits   ips_iv_bits
#define tdb_key_e     ips_key_e
#define tdb_key_e_size ips_key_e_size
#define tdb_key_bits_e ips_key_bits_e
#define tdb_key_bits_a ips_key_bits_a
#define tdb_key_a     ips_key_a
#define tdb_auth_bits ips_auth_bits
#define tdb_key_a_size ips_key_a_size

#define tdb_comp_ratio_cbytes ips_comp_ratio_cbytes 
#define tdb_comp_ratio_dbytes ips_comp_ratio_dbytes 
#define tdb_comp_adapt_tries  ips_comp_adapt_tries
#define tdb_comp_adapt_skip   ips_comp_adapt_skip

#define tdb_mask_s    ips_mask_s
#define tdb_flow_s    ips_flow_s
#define tdb_mask_d    ips_mask_d
#define tdb_flow_d    ips_flow_d

#define tdb_flags     ips_flags
#define tdb_rcvif     ips_rcvif

#endif /* IPSEC_KLIPS1_COMPAT */

#ifndef USE_IXP4XX_CRYPTO
#define _IPSEC_SA_H
#endif /* USE_IXP4XX_CRYPTO */
#endif /* _IPSEC_SA_H_ */

/*
 * $Log: ipsec_sa.h,v $
 * Revision 1.2  2001/11/26 09:16:15  rgb
 * Merge MCR's ipsec_sa, eroute, proc and struct lifetime changes.
 *
 * Revision 1.1.2.1  2001/09/25 02:24:58  mcr
 * 	struct tdb -> struct ipsec_sa.
 * 	sa(tdb) manipulation functions renamed and moved to ipsec_sa.c
 * 	ipsec_xform.c removed. header file still contains useful things.
 *
 *
 * Local variables:
 * c-file-style: "linux"
 * End:
 *
 */
