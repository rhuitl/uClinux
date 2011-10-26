/*
 * @(#) /proc file system interface code.
 *
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs <rgb@freeswan.org>
 *                                 2001  Michael Richardson <mcr@freeswan.org>
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
 * Split out from ipsec_init.c version 1.70.
 */

char ipsec_proc_c_version[] = "RCSID $Id: ipsec_proc.c,v 1.8 2002/01/29 17:17:55 mcr Exp $";

#include <linux/config.h>
#include <linux/version.h>
#define __NO_VERSION__
#include <linux/module.h>
#include <linux/kernel.h> /* printk() */

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
#include <linux/in.h>          /* struct sockaddr_in */
#include <linux/skbuff.h>
#include <freeswan.h>
#ifdef SPINLOCK
#ifdef SPINLOCK_23
#include <linux/spinlock.h> /* *lock* */
#else /* SPINLOCK_23 */
#include <asm/spinlock.h> /* *lock* */
#endif /* SPINLOCK_23 */
#endif /* SPINLOCK */
#ifdef NET_21
#include <asm/uaccess.h>
#include <linux/in6.h>
#endif /* NET_21 */
#include <asm/checksum.h>
#include <net/ip.h>
#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>
#endif /* CONFIG_PROC_FS */
#ifdef NETLINK_SOCK
#include <linux/netlink.h>
#else
#include <net/netlink.h>
#endif

#include "radij.h"

#include "ipsec_life.h"
#include "ipsec_stats.h"
#include "ipsec_sa.h"

#include "ipsec_encap.h"
#include "ipsec_radij.h"
#include "ipsec_netlink.h"
#include "ipsec_xform.h"
#include "ipsec_tunnel.h"

#include "ipsec_rcv.h"
#include "ipsec_ah.h"
#include "ipsec_esp.h"

#ifdef CONFIG_IPSEC_IPCOMP
#include "ipcomp.h"
#endif /* CONFIG_IPSEC_IPCOMP */

#include "ipsec_proto.h"

#include <pfkeyv2.h>
#include <pfkey.h>

#ifdef CONFIG_PROC_FS

#if 0
static struct proc_dir_entry *proc_net_ipsec_dir;
#endif

IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_eroute_get_info(char *buffer, 
		      char **start, 
		      off_t offset, 
		      int length        IPSEC_PROC_LAST_ARG)
{
	struct wsbuf w = {buffer, length, offset, 0, 0, 0, 0};

#ifdef CONFIG_IPSEC_DEBUG
	if (debug_radij & DB_RJ_DUMPTREES)
	  rj_dumptrees();			/* XXXXXXXXX */
#endif /* CONFIG_IPSEC_DEBUG */

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_eroute_get_info: "
		    "buffer=0x%p, *start=0x%x, offset=%d, length=%d\n",
		    buffer,
		    (u_int)*start,
		    (int)offset,
		    length);

	spin_lock_bh(&eroute_lock);

	rj_walktree(rnh, ipsec_rj_walker_procprint, &w);
/*	rj_walktree(mask_rjhead, ipsec_rj_walker_procprint, &w); */

	spin_unlock_bh(&eroute_lock);

	*start = buffer + (offset - w.begin);	/* Start of wanted data */
	w.len -= (offset - w.begin);			/* Start slop */
	if (w.len > length)
		w.len = length;
	return w.len;
}

IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_spi_get_info(char *buffer,
		   char **start,
		   off_t offset,
		   int length    IPSEC_PROC_LAST_ARG)
{
	int len = 0;
	off_t pos = 0, begin = 0;
	int i;
	struct ipsec_sa *sa_p;
	char sa[SATOA_BUF];
	char buf_s[SUBNETTOA_BUF];
	char buf_d[SUBNETTOA_BUF];
	char buf_l[LIFETIMETOA_BUF];
	size_t sa_len;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_spi_get_info: "
		    "buffer=0x%p, *start=0x%x, offset=%d, length=%d\n",
		    buffer,
		    (u_int)*start,
		    (int)offset,
		    length);
	
	spin_lock_bh(&tdb_lock);


	
	for (i = 0; i < SADB_HASHMOD; i++) {
		for (sa_p = ipsec_sadb_hash[i];
		     sa_p;
		     sa_p = sa_p->ips_hnext) {
			sa_len = satoa(sa_p->ips_said, 0, sa, SATOA_BUF);
			len += sprintf(buffer + len, "%s ",
				       sa_len ? sa : " (error)");

			len += sprintf(buffer + len, "%s%s%s",
				       IPS_XFORM_NAME(sa_p));

			len += sprintf(buffer + len, ": dir=%s",
				       (sa_p->ips_flags & EMT_INBOUND) ?
				       "in " : "out");

			if(sa_p->ips_addr_s) {
				addrtoa(((struct sockaddr_in*)(sa_p->ips_addr_s))->sin_addr,
					0, buf_s, sizeof(buf_s));
				len += sprintf(buffer + len, " src=%s",
					       buf_s);
			}

			if((sa_p->ips_said.proto == IPPROTO_IPIP)
			   && (sa_p->ips_flags & SADB_X_SAFLAGS_INFLOW)) {
				subnettoa(sa_p->ips_flow_s.u.v4.sin_addr,
					  sa_p->ips_mask_s.u.v4.sin_addr,
					  0,
					  buf_s,
					  sizeof(buf_s));

				subnettoa(sa_p->ips_flow_d.u.v4.sin_addr,
					  sa_p->ips_mask_d.u.v4.sin_addr,
					  0,
					  buf_d,
					  sizeof(buf_d));

				len += sprintf(buffer + len, " policy=%s->%s",
					       buf_s, buf_d);
			}
			
			if(sa_p->ips_iv_bits) {
				int j;
				len += sprintf(buffer + len, " iv_bits=%dbits iv=0x",
					       sa_p->ips_iv_bits);

				for(j = 0; j < sa_p->ips_iv_bits / 8; j++) {
					len += sprintf(buffer + len, "%02x",
						       (__u32)((__u8*)(sa_p->ips_iv))[j]);
				}
			}

			if(sa_p->ips_encalg || sa_p->ips_authalg) {
				if(sa_p->ips_replaywin) {
					len += sprintf(buffer + len, " ooowin=%d",
						       sa_p->ips_replaywin);
				}
				if(sa_p->ips_errs.ips_replaywin_errs) {
					len += sprintf(buffer + len, " ooo_errs=%d",
						       sa_p->ips_errs.ips_replaywin_errs);
				}
				if(sa_p->ips_replaywin_lastseq) {
                                       len += sprintf(buffer + len, " seq=%d",
						      sa_p->ips_replaywin_lastseq);
				}
				if(sa_p->ips_replaywin_bitmap) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
					len += sprintf(buffer + len, " bit=0x%Lx",
						       sa_p->ips_replaywin_bitmap);
#else
					len += sprintf(buffer + len, " bit=0x%x%08x",
						       (__u32)(sa_p->ips_replaywin_bitmap >> 32),
						       (__u32)sa_p->ips_replaywin_bitmap);
#endif
				}
				if(sa_p->ips_replaywin_maxdiff) {
					len += sprintf(buffer + len, " max_seq_diff=%d",
						       sa_p->ips_replaywin_maxdiff);
				}
			}
			if(sa_p->ips_flags & ~EMT_INBOUND) {
				len += sprintf(buffer + len, " flags=0x%x",
					       sa_p->ips_flags & ~EMT_INBOUND);
				len += sprintf(buffer + len, "<");
				/* flag printing goes here */
				len += sprintf(buffer + len, ">");
			}
			if(sa_p->ips_auth_bits) {
				len += sprintf(buffer + len, " alen=%d",
					       sa_p->ips_auth_bits);
			}
			if(sa_p->ips_key_bits_a) {
				len += sprintf(buffer + len, " aklen=%d",
					       sa_p->ips_key_bits_a);
			}
			if(sa_p->ips_errs.ips_auth_errs) {
				len += sprintf(buffer + len, " auth_errs=%d",
					       sa_p->ips_errs.ips_auth_errs);
			}
			if(sa_p->ips_key_bits_e) {
				len += sprintf(buffer + len, " eklen=%d",
					       sa_p->ips_key_bits_e);
			}
			if(sa_p->ips_errs.ips_encsize_errs) {
				len += sprintf(buffer + len, " encr_size_errs=%d",
					       sa_p->ips_errs.ips_encsize_errs);
			}
			if(sa_p->ips_errs.ips_encpad_errs) {
				len += sprintf(buffer + len, " encr_pad_errs=%d",
					       sa_p->ips_errs.ips_encpad_errs);
			}
			
			len += sprintf(buffer + len, " life(c,s,h)=");

			if (ipsec_lifetime_format(buf_l, 
						     sizeof(buf_l),
						     "alloc", 
						     ipsec_life_countbased,
						     &sa_p->ips_life.ipl_allocations)) {
				len += snprintf(buffer + len, sizeof(buf_l), "%s", buf_l);
			}

			if (ipsec_lifetime_format(buf_l,
						     sizeof(buf_l),
						     "bytes",
						     ipsec_life_countbased,
						     &sa_p->ips_life.ipl_bytes)) {
				len += snprintf(buffer + len, sizeof(buf_l), "%s", buf_l);
			}

			if (ipsec_lifetime_format(buf_l, 
						     sizeof(buf_l),
						     "addtime",
						     ipsec_life_timebased,
						     &sa_p->ips_life.ipl_addtime)) {
				len += snprintf(buffer + len, sizeof(buf_l), "%s", buf_l);
			}

			if (ipsec_lifetime_format(buf_l, 
						     sizeof(buf_l),
						     "usetime",
						     ipsec_life_timebased,
						     &sa_p->ips_life.ipl_usetime)) {
				len += snprintf(buffer + len, sizeof(buf_l), "%s", buf_l);
			}
			
			if (ipsec_lifetime_format(buf_l, 
						     sizeof(buf_l),
						     "packets",
						     ipsec_life_countbased,
						     &sa_p->ips_life.ipl_packets)) {
				len += snprintf(buffer + len, sizeof(buf_l), "%s", buf_l);
			}
			
			if(sa_p->ips_life.ipl_usetime.ipl_last) { /* XXX-MCR should be last? */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
				len += sprintf(buffer + len, " idle=%Ld",
					       jiffies / HZ - sa_p->ips_life.ipl_usetime.ipl_last);
#else
				len += sprintf(buffer + len, " idle=%lu",
					       jiffies / HZ - (unsigned long)sa_p->ips_life.ipl_usetime.ipl_last);
#endif
			}

#ifdef CONFIG_IPSEC_IPCOMP
			if(sa_p->ips_said.proto == IPPROTO_COMP &&
			   (sa_p->ips_comp_ratio_dbytes ||
			    sa_p->ips_comp_ratio_cbytes)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
				len += sprintf(buffer + len, " ratio=%Ld:%Ld",
					       sa_p->ips_comp_ratio_dbytes,
					       sa_p->ips_comp_ratio_cbytes);
#else
				len += sprintf(buffer + len, " ratio=%lu:%lu",
					       (unsigned long)sa_p->ips_comp_ratio_dbytes,
					       (unsigned long)sa_p->ips_comp_ratio_cbytes);
#endif
			}
#endif /* CONFIG_IPSEC_IPCOMP */

			len += sprintf(buffer + len, "\n");

			pos = begin + len;
			if(pos < offset) {
				len = 0;
				begin = pos;
			}
			if (pos > offset + length) {
				goto done_spi_i;
			}
		}
	}

 done_spi_i:	
	spin_unlock_bh(&tdb_lock);

	*start = buffer + (offset - begin);	/* Start of wanted data */
	len -= (offset - begin);			/* Start slop */
	if (len > length)
		len = length;
	return len;
}

IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_spigrp_get_info(char *buffer,
		      char **start,
		      off_t offset,
		      int length     IPSEC_PROC_LAST_ARG)
{
	int len = 0;
	off_t pos = 0, begin = 0;
	int i;
	struct ipsec_sa *sa_p, *sa_p2;
	char sa[SATOA_BUF];
	size_t sa_len;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_spigrp_get_info: "
		    "buffer=0x%p, *start=0x%x, offset=%d, length=%d\n",
		    buffer,
		    (u_int)*start,
		    (int)offset,
		    length);

	spin_lock_bh(&tdb_lock);
	
	for (i = 0; i < SADB_HASHMOD; i++) {
		for (sa_p = ipsec_sadb_hash[i];
		     sa_p;
		     sa_p = sa_p->ips_hnext)
		{
			if(!sa_p->ips_inext)
			{
				sa_p2 = sa_p;
				while(sa_p2) {
					sa_len = satoa(sa_p2->ips_said,
						       0, sa, SATOA_BUF);
					
					len += sprintf(buffer + len, "%s ",
						       sa_len ? sa : " (error)");
					sa_p2 = sa_p2->ips_onext;
				}
				len += sprintf(buffer + len, "\n");
				pos = begin + len;
				if(pos < offset) {
					len = 0;
					begin = pos;
				}
				if (pos > offset + length) {
					goto done_spigrp_i;
				}
			}
		}
	}

 done_spigrp_i:	
	spin_unlock_bh(&tdb_lock);

	*start = buffer + (offset - begin);	/* Start of wanted data */
	len -= (offset - begin);			/* Start slop */
	if (len > length)
		len = length;
	return len;
}

IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_tncfg_get_info(char *buffer,
		     char **start,
		     off_t offset,
		     int length     IPSEC_PROC_LAST_ARG)
{
	int len = 0;
	off_t pos = 0, begin = 0;
	int i;
	char name[9];
	struct device *dev, *privdev;
	struct ipsecpriv *priv;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_tncfg_get_info: "
		    "buffer=0x%p, *start=0x%x, offset=%d, length=%d\n",
		    buffer,
		    (u_int)*start,
		    (int)offset,
		    length);

	for(i = 0; i < IPSEC_NUM_IF; i++) {
		sprintf(name, "ipsec%d", i);
		dev = ipsec_dev_get(name);
		if(dev) {
			priv = (struct ipsecpriv *)(dev->priv);
			len += sprintf(buffer + len, "%s",
				       dev->name);
			if(priv) {
				privdev = (struct device *)(priv->dev);
				len += sprintf(buffer + len, " -> %s",
					       privdev ? privdev->name : "NULL");
				len += sprintf(buffer + len, " mtu=%d(%d) -> %d",
					       dev->mtu,
					       priv->mtu,
					       privdev ? privdev->mtu : 0);
			} else {
				KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
					    "klips_debug:ipsec_tncfg_get_info: device '%s' has no private data space!\n",
					    dev->name);
			}
			len += sprintf(buffer + len, "\n");

			pos = begin + len;
			if(pos < offset) {
				len = 0;
				begin = pos;
			}
			else if (pos > offset + length)	{
				break;
			}
		}
	}
	*start = buffer + (offset - begin);	/* Start of wanted data */
	len -= (offset - begin);			/* Start slop */
	if (len > length)
		len = length;
	return len;
}

IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_version_get_info(char *buffer,
		       char **start,
		       off_t offset,
		       int length  IPSEC_PROC_LAST_ARG)
{
	int len = 0;
	off_t begin = 0;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_version_get_info: "
		    "buffer=0x%p, *start=0x%x, offset=%d, length=%d\n",
		    buffer,
		    (u_int)*start,
		    (int)offset,
		    length);

	len += sprintf(buffer + len, "FreeS/WAN version: %s\n",
		       ipsec_version_code());
#if 0
	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_version_get_info: "
		    "ipsec_init version: %s\n",
		    ipsec_init_c_version);
	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_version_get_info: "
		    "ipsec_tunnel version: %s\n",
		    ipsec_tunnel_c_version);
	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_version_get_info: "
		    "ipsec_netlink version: %s\n",
		    ipsec_netlink_c_version);
	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_version_get_info: "
		    "radij_c_version: %s\n",
		    radij_c_version);
#endif

	*start = buffer + (offset - begin);	/* Start of wanted data */
	len -= (offset - begin);			/* Start slop */
	if (len > length)
		len = length;
	return len;
}

#ifdef CONFIG_IPSEC_DEBUG
IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_klipsdebug_get_info(char *buffer,
			  char **start,
			  off_t offset,
			  int length      IPSEC_PROC_LAST_ARG)
{
	int len = 0;
	off_t begin = 0;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_klipsdebug_get_info: "
		    "buffer=0x%p, *start=0x%x, offset=%d, length=%d\n",
		    buffer,
		    (u_int)*start,
		    (int)offset,
		    length);

	len += sprintf(buffer + len, "debug_tunnel=%08x.\n", debug_tunnel);
	len += sprintf(buffer + len, "debug_netlink=%08x.\n", debug_netlink);
	len += sprintf(buffer + len, "debug_xform=%08x.\n", debug_xform);
	len += sprintf(buffer + len, "debug_eroute=%08x.\n", debug_eroute);
	len += sprintf(buffer + len, "debug_spi=%08x.\n", debug_spi);
	len += sprintf(buffer + len, "debug_radij=%08x.\n", debug_radij);
	len += sprintf(buffer + len, "debug_esp=%08x.\n", debug_esp);
	len += sprintf(buffer + len, "debug_ah=%08x.\n", debug_ah);
	len += sprintf(buffer + len, "debug_rcv=%08x.\n", debug_rcv);
	len += sprintf(buffer + len, "debug_pfkey=%08x.\n", debug_pfkey);

	*start = buffer + (offset - begin);	/* Start of wanted data */
	len -= (offset - begin);			/* Start slop */
	if (len > length)
		len = length;
	return len;
}
#endif /* CONFIG_IPSEC_DEBUG */

#ifndef PROC_FS_2325
struct proc_dir_entry ipsec_eroute =
{
	0,
	12, "ipsec_eroute",
	S_IFREG | S_IRUGO, 1, 0, 0, 0,
	&proc_net_inode_operations,
	ipsec_eroute_get_info,
	NULL, NULL, NULL, NULL, NULL
};

struct proc_dir_entry ipsec_spi =
{
	0,
	9, "ipsec_spi",
	S_IFREG | S_IRUGO, 1, 0, 0, 0,
	&proc_net_inode_operations,
	ipsec_spi_get_info,
	NULL, NULL, NULL, NULL, NULL
};

struct proc_dir_entry ipsec_spigrp =
{
	0,
	12, "ipsec_spigrp",
	S_IFREG | S_IRUGO, 1, 0, 0, 0,
	&proc_net_inode_operations,
	ipsec_spigrp_get_info,
	NULL, NULL, NULL, NULL, NULL
};

struct proc_dir_entry ipsec_tncfg =
{
	0,
	11, "ipsec_tncfg",
	S_IFREG | S_IRUGO, 1, 0, 0, 0,
	&proc_net_inode_operations,
	ipsec_tncfg_get_info,
	NULL, NULL, NULL, NULL, NULL
};

struct proc_dir_entry ipsec_version =
{
	0,
	13, "ipsec_version",
	S_IFREG | S_IRUGO, 1, 0, 0, 0,
	&proc_net_inode_operations,
	ipsec_version_get_info,
	NULL, NULL, NULL, NULL, NULL
};

#ifdef CONFIG_IPSEC_DEBUG
struct proc_dir_entry ipsec_klipsdebug =
{
	0,
	16, "ipsec_klipsdebug",
	S_IFREG | S_IRUGO, 1, 0, 0, 0,
	&proc_net_inode_operations,
	ipsec_klipsdebug_get_info,
	NULL, NULL, NULL, NULL, NULL
};
#endif /* CONFIG_IPSEC_DEBUG */
#endif /* !PROC_FS_2325 */
#endif /* CONFIG_PROC_FS */

int
ipsec_proc_init()
{
	int error = 0;

	/* compile a dummy function if no /proc/-fs */

	/* XXX-mcr probably should just complain because pluto won't
	 * run without /proc!
	 */

#ifdef CONFIG_PROC_FS 
#  ifndef PROC_FS_2325
#    ifdef PROC_FS_21
	error |= proc_register(proc_net, &ipsec_eroute);
	error |= proc_register(proc_net, &ipsec_spi);
	error |= proc_register(proc_net, &ipsec_spigrp);
	error |= proc_register(proc_net, &ipsec_tncfg);
	error |= proc_register(proc_net, &ipsec_version);
#      ifdef CONFIG_IPSEC_DEBUG
	error |= proc_register(proc_net, &ipsec_klipsdebug);
#      endif /* CONFIG_IPSEC_DEBUG */
#    else /* PROC_FS_21 */
	error |= proc_register_dynamic(&proc_net, &ipsec_eroute);
	error |= proc_register_dynamic(&proc_net, &ipsec_spi);
	error |= proc_register_dynamic(&proc_net, &ipsec_spigrp);
	error |= proc_register_dynamic(&proc_net, &ipsec_tncfg);
	error |= proc_register_dynamic(&proc_net, &ipsec_version);
#      ifdef CONFIG_IPSEC_DEBUG
	error |= proc_register_dynamic(&proc_net, &ipsec_klipsdebug);
#      endif /* CONFIG_IPSEC_DEBUG */
#    endif /* PROC_FS_21 */
#  else /* !PROC_FS_2325 */
	/* create /proc/net/ipsec */
#if 0
	proc_net_ipsec_dir = proc_mkdir("ipsec", proc_net);
	if(proc_net_ipsec_dir == NULL) {
		error |= 1;
	} else{
		error |= proc_register();
	}		
#endif

	proc_net_create ("ipsec_eroute", 0, ipsec_eroute_get_info);
	proc_net_create ("ipsec_spi", 0, ipsec_spi_get_info);
	proc_net_create ("ipsec_spigrp", 0, ipsec_spigrp_get_info);
	proc_net_create ("ipsec_tncfg", 0, ipsec_tncfg_get_info);
	proc_net_create ("ipsec_version", 0, ipsec_version_get_info);
#    ifdef CONFIG_IPSEC_DEBUG
	proc_net_create ("ipsec_klipsdebug", 0, ipsec_klipsdebug_get_info);
#    endif /* CONFIG_IPSEC_DEBUG */
#  endif /* !PROC_FS_2325 */
#endif /* CONFIG_PROC_FS */

	return error;
}

void
ipsec_proc_cleanup()
{
#ifdef CONFIG_PROC_FS
#  ifndef PROC_FS_2325
#    ifdef CONFIG_IPSEC_DEBUG
	if (proc_net_unregister(ipsec_klipsdebug.low_ino) != 0)
		printk("klips_debug:ipsec_cleanup: "
		       "cannot unregister /proc/net/ipsec_klipsdebug\n");
#    endif /* CONFIG_IPSEC_DEBUG */
	if (proc_net_unregister(ipsec_version.low_ino) != 0)
		printk("klips_debug:ipsec_cleanup: "
		       "cannot unregister /proc/net/ipsec_version\n");
	if (proc_net_unregister(ipsec_eroute.low_ino) != 0)
		printk("klips_debug:ipsec_cleanup: "
		       "cannot unregister /proc/net/ipsec_eroute\n");
	if (proc_net_unregister(ipsec_spi.low_ino) != 0)
		printk("klips_debug:ipsec_cleanup: "
		       "cannot unregister /proc/net/ipsec_spi\n");
	if (proc_net_unregister(ipsec_spigrp.low_ino) != 0)
		printk("klips_debug:ipsec_cleanup: "
		       "cannot unregister /proc/net/ipsec_spigrp\n");
	if (proc_net_unregister(ipsec_tncfg.low_ino) != 0)
		printk("klips_debug:ipsec_cleanup: "
		       "cannot unregister /proc/net/ipsec_tncfg\n");
#  else /* !PROC_FS_2325 */
#    ifdef CONFIG_IPSEC_DEBUG
	proc_net_remove ("ipsec_klipsdebug");
#    endif /* CONFIG_IPSEC_DEBUG */
	proc_net_remove ("ipsec_eroute");
	proc_net_remove ("ipsec_spi");
	proc_net_remove ("ipsec_spigrp");
	proc_net_remove ("ipsec_tncfg");
	proc_net_remove ("ipsec_version");
#  endif /* !PROC_FS_2325 */
#endif          /* CONFIG_PROC_FS */
}

/*
 * $Log: ipsec_proc.c,v $
 * Revision 1.8  2002/01/29 17:17:55  mcr
 * 	moved include of ipsec_param.h to after include of linux/kernel.h
 * 	otherwise, it seems that some option that is set in ipsec_param.h
 * 	screws up something subtle in the include path to kernel.h, and
 * 	it complains on the snprintf() prototype.
 *
 * Revision 1.7  2002/01/29 04:00:52  mcr
 * 	more excise of kversions.h header.
 *
 * Revision 1.6  2002/01/29 02:13:17  mcr
 * 	introduction of ipsec_kversion.h means that include of
 * 	ipsec_param.h must preceed any decisions about what files to
 * 	include to deal with differences in kernel source.
 *
 * Revision 1.5  2002/01/12 02:54:30  mcr
 * 	beginnings of /proc/net/ipsec dir.
 *
 * Revision 1.4  2001/12/11 02:21:05  rgb
 * Don't include module version here, fixing 2.2 compile bug.
 *
 * Revision 1.3  2001/12/05 07:19:44  rgb
 * Fixed extraneous #include "version.c" bug causing modular KLIPS failure.
 *
 * Revision 1.2  2001/11/26 09:16:14  rgb
 * Merge MCR's ipsec_sa, eroute, proc and struct lifetime changes.
 *
 * Revision 1.74  2001/11/22 05:44:11  henry
 * new version stuff
 *
 * Revision 1.1.2.1  2001/09/25 02:19:40  mcr
 * 	/proc manipulation code moved to new ipsec_proc.c
 *
 *
 * Local variables:
 * c-file-style: "linux"
 * End:
 *
 */
