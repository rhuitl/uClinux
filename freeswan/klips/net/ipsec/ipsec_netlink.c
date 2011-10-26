/*
 * IPSEC <> netlink interface
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

char ipsec_netlink_c_version[] = "RCSID $Id: ipsec_netlink.c,v 1.56 2002/01/29 17:17:55 mcr Exp $";

#include <linux/config.h>
#include <linux/version.h>
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
#include <linux/skbuff.h>
#include <freeswan.h>
#ifdef SPINLOCK
# ifdef SPINLOCK_23
#  include <linux/spinlock.h> /* *lock* */
# else /* 23_SPINLOCK */
#  include <asm/spinlock.h> /* *lock* */
# endif /* 23_SPINLOCK */
#endif /* SPINLOCK */
#ifdef NET_21
# include <asm/uaccess.h>
# include <linux/in6.h>
# define ip_chk_addr inet_addr_type
# define IS_MYADDR RTN_LOCAL
#endif
#include <asm/checksum.h>
#include <net/ip.h>
#ifdef NETLINK_SOCK
# include <linux/netlink.h>
#else
# include <net/netlink.h>
#endif

#include "radij.h"
#include "ipsec_encap.h"
#include "ipsec_radij.h"
#include "ipsec_netlink.h"
#include "ipsec_xform.h"

#include "ipsec_rcv.h"
#include "ipsec_ah.h"
#include "ipsec_esp.h"

#ifdef CONFIG_IPSEC_DEBUG
# include "ipsec_tunnel.h"
#endif /* CONFIG_IPSEC_DEBUG */

#include <pfkeyv2.h>
#include <pfkey.h>

#ifdef CONFIG_IPSEC_DEBUG
 int debug_netlink = 0;
#endif /* CONFIG_IPSEC_DEBUG */

#define SENDERR(_x) do { len = -(_x); goto errlab; } while (0)

#if 0
int 
#ifdef NETLINK_SOCK
ipsec_callback(int proto, struct sk_buff *skb)
#else /* NETLINK_SOCK */
ipsec_callback(struct sk_buff *skb)
#endif /* NETLINK_SOCK */
{
	/*
	 * this happens when we write to /dev/ipsec (c 36 10)
	 */
	int len = skb->len;
	u_char *dat = (u_char *)skb->data;
	struct encap_msghdr *em	= (struct encap_msghdr *)dat;
	struct tdb *tdbp, *tprev;
	int i, nspis, error = 0;
#ifdef CONFIG_IPSEC_DEBUG
	struct eroute *eret;
	char sa[SATOA_BUF];
	size_t sa_len;
	struct sk_buff *first, *last;


	sa_len = satoa(em->em_said, 0, sa, SATOA_BUF);

	if(debug_netlink) {
		printk("klips_debug:ipsec_callback: "
		       "skb=0x%p skblen=%ld em_magic=%d em_type=%d\n",
		       skb,
		       (unsigned long int)skb->len,
		       em->em_magic,
		       em->em_type);
		switch(em->em_type) {
		case EMT_SETDEBUG:
			printk("klips_debug:ipsec_callback: "
			       "set ipsec_debug level\n");
			break;
		case EMT_DELEROUTE:
		case EMT_CLREROUTE:
		case EMT_CLRSPIS:
			break;
		default:
			printk("klips_debug:ipsec_callback: "
			       "called for SA:%s\n",
			       sa_len ? sa : " (error)");
		}
	}
#endif /* CONFIG_IPSEC_DEBUG */

	/* XXXX Temporarily disable netlink I/F code until it gets permanantly
	   ripped out in favour of PF_KEYv2 I/F. */
	SENDERR(EPROTONOSUPPORT);

	/*	em = (struct encap_msghdr *)dat; */
	if (em->em_magic != EM_MAGIC) {
		printk("klips_debug:ipsec_callback: "
		       "bad magic=%d failed, should be %d\n",
		       em->em_magic,
		       EM_MAGIC);
		SENDERR(EINVAL);
	}
	switch (em->em_type) {
	case EMT_SETDEBUG:
#ifdef CONFIG_IPSEC_DEBUG
		if(em->em_db_nl >> (sizeof(em->em_db_nl) * 8 - 1)) {
			em->em_db_nl &= ~(1 << (sizeof(em->em_db_nl) * 8 -1));
			debug_tunnel  |= em->em_db_tn;
			debug_netlink |= em->em_db_nl;
			debug_xform   |= em->em_db_xf;
			debug_eroute  |= em->em_db_er;
			debug_spi     |= em->em_db_sp;
			debug_radij   |= em->em_db_rj;
			debug_esp     |= em->em_db_es;
			debug_ah      |= em->em_db_ah;
			debug_rcv     |= em->em_db_rx;
			debug_pfkey   |= em->em_db_ky;
			if(debug_netlink)
				printk("klips_debug:ipsec_callback: set\n");
		} else {
			if(debug_netlink)
				printk("klips_debug:ipsec_callback: unset\n");
			debug_tunnel  &= em->em_db_tn;
			debug_netlink &= em->em_db_nl;
			debug_xform   &= em->em_db_xf;
			debug_eroute  &= em->em_db_er;
			debug_spi     &= em->em_db_sp;
			debug_radij   &= em->em_db_rj;
			debug_esp     &= em->em_db_es;
			debug_ah      &= em->em_db_ah;
			debug_rcv     &= em->em_db_rx;
			debug_pfkey   &= em->em_db_ky;
		}
#else /* CONFIG_IPSEC_DEBUG */
		printk("klips_debug:ipsec_callback: "
		       "debugging not enabled\n");
		SENDERR(EINVAL);
#endif /* CONFIG_IPSEC_DEBUG */
		break;

	case EMT_SETEROUTE:
		if ((error = ipsec_makeroute(&(em->em_eaddr), &(em->em_emask), em->em_ersaid, 0, NULL, NULL, NULL)))
			SENDERR(-error);
		break;

	case EMT_REPLACEROUTE:
		if ((error = ipsec_breakroute(&(em->em_eaddr), &(em->em_emask), &first, &last)) == EINVAL) {
			kfree_skb(first);
			kfree_skb(last);
			SENDERR(-error);
		}
		if ((error = ipsec_makeroute(&(em->em_eaddr), &(em->em_emask), em->em_ersaid, NULL, NULL)))
			SENDERR(-error);
		break;

	case EMT_DELEROUTE:
		if ((error = ipsec_breakroute(&(em->em_eaddr), &(em->em_emask), &first, &last)))
			kfree_skb(first);
			kfree_skb(last);
			SENDERR(-error);
		break;

	case EMT_CLREROUTE:
		if ((error = ipsec_cleareroutes()))
			SENDERR(-error);
		break;

	case EMT_SETSPI:
		if (em->em_if >= 5)	/* XXX -- why 5? */
			SENDERR(ENODEV);
		
		tdbp = gettdb(&(em->em_said));
		if (tdbp == NULL) {
			tdbp = (struct tdb *)kmalloc(sizeof (*tdbp), GFP_ATOMIC);

			if (tdbp == NULL)
				SENDERR(ENOBUFS);
			
			memset((caddr_t)tdbp, 0, sizeof(*tdbp));
			
			tdbp->tdb_said = em->em_said;
			tdbp->tdb_flags = em->em_flags;
			
			if(ip_chk_addr((unsigned long)em->em_said.dst.s_addr) == IS_MYADDR) {
				tdbp->tdb_flags |= EMT_INBOUND;
			}
			KLIPS_PRINT(debug_netlink & DB_NL_TDBCB,
				    "klips_debug:ipsec_callback: "
				    "existing Tunnel Descriptor Block not found (this is good) for SA: %s, %s-bound, allocating.\n",
				    sa_len ? sa : " (error)",
				    (tdbp->tdb_flags & EMT_INBOUND) ? "in" : "out");

/* XXX  		tdbp->tdb_rcvif = &(enc_softc[em->em_if].enc_if);*/
			tdbp->tdb_rcvif = NULL;
		} else {
			KLIPS_PRINT(debug_netlink & DB_NL_TDBCB,
				    "klips_debug:ipsec_callback: "
				    "EMT_SETSPI found an old Tunnel Descriptor Block for SA: %s, delete it first.\n",
				    sa_len ? sa : " (error)");
			SENDERR(EEXIST);
		}
		
		if ((error = tdb_init(tdbp, em))) {
			KLIPS_PRINT(debug_netlink & DB_NL_TDBCB,
				    "klips_debug:ipsec_callback: "
				    "EMT_SETSPI not successful for SA: %s, deleting.\n",
				    sa_len ? sa : " (error)");
			ipsec_tdbwipe(tdbp);
			
			SENDERR(-error);
		}

		tdbp->tdb_lifetime_addtime_c = jiffies/HZ;
		tdbp->tdb_state = 1;
		if(!tdbp->tdb_lifetime_allocations_c) {
			tdbp->tdb_lifetime_allocations_c += 1;
		}

		puttdb(tdbp);
		KLIPS_PRINT(debug_netlink & DB_NL_TDBCB,
			    "klips_debug:ipsec_callback: "
			    "EMT_SETSPI successful for SA: %s\n",
			    sa_len ? sa : " (error)");
		break;
		
	case EMT_DELSPI:
		if (em->em_if >= 5)	/* XXX -- why 5? */
			SENDERR(ENODEV);
		
		spin_lock_bh(&tdb_lock);
		
		tdbp = gettdb(&(em->em_said));
		if (tdbp == NULL) {
			KLIPS_PRINT(debug_netlink & DB_NL_TDBCB,
				    "klips_debug:ipsec_callback: "
				    "EMT_DELSPI Tunnel Descriptor Block not found for SA%s, could not delete.\n",
				    sa_len ? sa : " (error)");
			spin_unlock_bh(&tdb_lock);
			SENDERR(ENXIO);  /* XXX -- wrong error message... */
		} else {
			if((error = deltdbchain(tdbp))) {
				spin_unlock_bh(&tdb_lock);
				SENDERR(-error);
			}
		}
		spin_unlock_bh(&tdb_lock);

		break;
		
	case EMT_GRPSPIS:
		nspis = (len - EMT_GRPSPIS_FLEN) / sizeof(em->em_rel[0]);
		if ((nspis * (sizeof(em->em_rel[0]))) != (len - EMT_GRPSPIS_FLEN)) {
			printk("klips_debug:ipsec_callback: "
			       "EMT_GRPSPI message size incorrect, expected nspis(%d)*%d, got %d.\n",
			       nspis,
			       sizeof(em->em_rel[0]),
			       (len - EMT_GRPSPIS_FLEN));
			SENDERR(EINVAL);
			break;
		}
		
		spin_lock_bh(&tdb_lock);

		for (i = 0; i < nspis; i++) {
			KLIPS_PRINT(debug_netlink,
				    "klips_debug:ipsec_callback: "
				    "EMT_GRPSPI for SA(%d) %s,\n",
				    i,
				    sa_len ? sa : " (error)");
			if ((tdbp = gettdb(&(em->em_rel[i].emr_said))) == NULL) {
				KLIPS_PRINT(debug_netlink,
					    "klips_debug:ipsec_callback: "
					    "EMT_GRPSPI Tunnel Descriptor Block not found for SA%s, could not group.\n",
					    sa_len ? sa : " (error)");
				spin_unlock_bh(&tdb_lock);
				SENDERR(ENXIO);
			} else {
				if(tdbp->tdb_inext || tdbp->tdb_onext) {
					KLIPS_PRINT(debug_netlink,
						    "klips_debug:ipsec_callback: "
						    "EMT_GRPSPI Tunnel Descriptor Block already grouped for SA: %s, can't regroup.\n",
						    sa_len ? sa : " (error)");
					spin_unlock_bh(&tdb_lock);
					SENDERR(EBUSY);
				}
				em->em_rel[i].emr_tdb = tdbp;
			}
		}
		tprev = em->em_rel[0].emr_tdb;
		tprev->tdb_inext = NULL;
		for (i = 1; i < nspis; i++) {
			tdbp = em->em_rel[i].emr_tdb;
			tprev->tdb_onext = tdbp;
			tdbp->tdb_inext = tprev;
			tprev = tdbp;
		}
		tprev->tdb_onext = NULL;

		spin_unlock_bh(&tdb_lock);

		error = 0;
		break;
		
	case EMT_UNGRPSPIS:
		if (len != (8 + (sizeof(struct sa_id) + sizeof(struct tdb *)) /* 12 */) ) {
			printk("klips_debug:ipsec_callback: "
			       "EMT_UNGRPSPIS message size incorrect, expected %d, got %d.\n",
			       8 + (sizeof(struct sa_id) + sizeof(struct tdb *)),
				    len);
			SENDERR(EINVAL);
			break;
		}
		
		spin_lock_bh(&tdb_lock);

		if ((tdbp = gettdb(&(em->em_rel[0].emr_said))) == NULL) {
			KLIPS_PRINT(debug_netlink,
				    "klips_debug:ipsec_callback: "
				    "EMT_UGRPSPI Tunnel Descriptor Block not found for SA%s, could not ungroup.\n",
				    sa_len ? sa : " (error)");
			spin_unlock_bh(&tdb_lock);
			SENDERR(ENXIO);
		}
		while(tdbp->tdb_onext) {
			tdbp = tdbp->tdb_onext;
		}
		while(tdbp->tdb_inext) {
			tprev = tdbp;
			tdbp = tdbp->tdb_inext;
			tprev->tdb_inext = NULL;
			tdbp->tdb_onext = NULL;
		}

		spin_unlock_bh(&tdb_lock);

		break;
		
	case EMT_CLRSPIS:
		KLIPS_PRINT(debug_netlink,
			    "klips_debug:ipsec_callback: "
			    "spi clear called.\n");
		if (em->em_if >= 5)	/* XXX -- why 5? */
			SENDERR(ENODEV);
		ipsec_tdbcleanup(0);
		break;
	default:
		KLIPS_PRINT(debug_netlink,
			    "klips_debug:ipsec_callback: "
			    "unknown message type\n");
		SENDERR(EINVAL);
	}
 errlab:
#ifdef NET_21
	kfree_skb(skb);
#else /* NET_21 */
	kfree_skb(skb, FREE_WRITE);
#endif /* NET_21 */
	return len;
}
#endif

/*
 * $Log: ipsec_netlink.c,v $
 * Revision 1.56  2002/01/29 17:17:55  mcr
 * 	moved include of ipsec_param.h to after include of linux/kernel.h
 * 	otherwise, it seems that some option that is set in ipsec_param.h
 * 	screws up something subtle in the include path to kernel.h, and
 * 	it complains on the snprintf() prototype.
 *
 * Revision 1.55  2002/01/29 04:00:51  mcr
 * 	more excise of kversions.h header.
 *
 * Revision 1.54  2001/10/18 04:45:19  rgb
 * 2.4.9 kernel deprecates linux/malloc.h in favour of linux/slab.h,
 * lib/freeswan.h version macros moved to lib/kversions.h.
 * Other compiler directive cleanups.
 *
 * Revision 1.53  2001/09/15 16:24:04  rgb
 * Re-inject first and last HOLD packet when an eroute REPLACE is done.
 *
 * Revision 1.52  2001/09/14 16:58:36  rgb
 * Added support for storing the first and last packets through a HOLD.
 *
 * Revision 1.51  2001/09/08 21:13:32  rgb
 * Added pfkey ident extension support for ISAKMPd. (NetCelo)
 *
 * Revision 1.50  2001/07/06 19:49:00  rgb
 * Renamed EMT_RPLACEROUTE to EMT_REPLACEROUTE for clarity and logical text
 * searching.
 *
 * Revision 1.49  2001/06/14 19:35:08  rgb
 * Update copyright date.
 *
 * Revision 1.48  2001/02/27 22:24:54  rgb
 * Re-formatting debug output (line-splitting, joining, 1arg/line).
 * Check for satoa() return codes.
 *
 * Revision 1.47  2000/11/06 04:32:08  rgb
 * Ditched spin_lock_irqsave in favour of spin_lock_bh.
 *
 * Revision 1.46  2000/09/08 19:16:50  rgb
 * Change references from DEBUG_IPSEC to CONFIG_IPSEC_DEBUG.
 * Removed all references to CONFIG_IPSEC_PFKEYv2.
 *
 * Revision 1.45  2000/08/30 05:23:55  rgb
 * Compiler-define out ipsec_callback() function of ipsec_netlink.c.
 * Nothing should be using it anyways.
 *
 * Revision 1.44  2000/03/16 14:01:26  rgb
 * Indented headers for readability.
 *
 * Revision 1.43  2000/03/16 07:13:04  rgb
 * Hardcode PF_KEYv2 support.
 * Disable NET_LINK support.
 *
 * Revision 1.42  2000/01/21 06:14:27  rgb
 * Moved debug message for expected output on set or clear.
 *
 * Revision 1.41  1999/12/01 22:14:37  rgb
 * Added debugging message for bad netlink magic.
 * Initialise tdb_sastate to MATURE (1).
 * Added UNGRPSPIS bad length debugging message.
 *
 * Revision 1.40  1999/11/23 23:06:25  rgb
 * Sort out pfkey and freeswan headers, putting them in a library path.
 *
 * Revision 1.39  1999/11/18 04:09:18  rgb
 * Replaced all kernel version macros to shorter, readable form.
 *
 * Revision 1.38  1999/11/17 15:53:39  rgb
 * Changed all occurrences of #include "../../../lib/freeswan.h"
 * to #include <freeswan.h> which works due to -Ilibfreeswan in the
 * klips/net/ipsec/Makefile.
 *
 * Revision 1.37  1999/10/26 13:58:32  rgb
 * Put spinlock flags variable declaration outside the debug compiler
 * directive to enable compilation with debug shut off.
 *
 * Revision 1.36  1999/10/16 18:24:22  rgb
 * Initialize lifetime_addtime_c and lifetime_allocations_c.
 * Clean-up unused cruft.
 *
 * Revision 1.35  1999/10/08 18:37:34  rgb
 * Fix end-of-line spacing to sate whining PHMs.
 *
 * Revision 1.34  1999/10/03 18:49:11  rgb
 * Spinlock fixes for 2.0.xx and 2.3.xx.
 *
 * Revision 1.33  1999/10/01 15:44:53  rgb
 * Move spinlock header include to 2.1> scope.
 *
 * Revision 1.32  1999/10/01 00:00:53  rgb
 * Fix for proper netlink debugging operation.
 * Added tdb structure locking.
 * Minor formatting changes.
 *
 * Revision 1.31  1999/05/25 21:21:43  rgb
 * Fix deltdbchain() error return code checking.
 *
 * Revision 1.30  1999/05/09 03:25:36  rgb
 * Fix bug introduced by 2.2 quick-and-dirty patch.
 *
 * Revision 1.29  1999/05/08 21:23:27  rgb
 * Simplify satoa() calling.
 * Fix error return reporting.
 * Add casting to silence the 2.2.x compile.
 *
 * Revision 1.28  1999/05/05 22:02:31  rgb
 * Add a quick and dirty port to 2.2 kernels by Marc Boucher <marc@mbsi.ca>.
 *
 * Revision 1.27  1999/04/29 15:16:24  rgb
 * Add pfkey support to debugging.
 * Change gettdb parameter to a pointer to reduce stack loading and
 * facilitate
 * parameter sanity checking.
 * Add IS_MYADDR support obviating the necessity of doing this in user
 * space.
 * Fix undetected bug by moving puttdb in SETSPI until after initialisation
 * to
 * prevent tdb usage before it is ready and to save work if it does not
 * initialise.
 * Clean up deltdb/wipe code.
 * Fix undetected bug of returning error as positive value.
 * Add a parameter to tdbcleanup to be able to delete a class of SAs.
 *
 * Revision 1.26  1999/04/16 15:39:35  rgb
 * Fix already fixed unbalanced #endif.
 *
 * Revision 1.25  1999/04/15 15:37:24  rgb
 * Forward check changes from POST1_00 branch.
 *
 * Revision 1.21.2.1  1999/04/13 20:30:26  rgb
 * Add experimental 'getdebug'.
 *
 * Revision 1.24  1999/04/11 00:28:58  henry
 * GPL boilerplate
 *
 * Revision 1.23  1999/04/07 17:44:21  rgb
 * Fix ipsec_callback memory leak, skb not freed after use.
 *
 * Revision 1.22  1999/04/06 04:54:26  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 * Revision 1.21  1999/02/17 16:50:11  rgb
 * Consolidate satoa()s for space and speed efficiency.
 * Convert DEBUG_IPSEC to KLIPS_PRINT
 * Clean out unused cruft.
 *
 * Revision 1.20  1999/01/28 23:20:49  rgb
 * Replace hard-coded numbers in macros and code with meaningful values
 * automatically generated from sizeof() and offsetof() to further the
 * goal of platform independance.
 *
 * Revision 1.19  1999/01/26 02:07:07  rgb
 * Removed CONFIG_IPSEC_ALGO_SWITCH macro.
 * Remove ah/esp switching on include files.
 * Removed dead code.
 *
 * Revision 1.18  1999/01/22 06:20:36  rgb
 * Cruft clean-out.
 * 64-bit clean-up.
 * Added algorithm switch code.
 *
 * Revision 1.17  1998/12/02 03:09:39  rgb
 * Clean up debug printing conditionals to compile with debugging off.
 *
 * Revision 1.16  1998/12/01 05:56:57  rgb
 * Add support for debug printing of version info.
 * Fail on unknown error for breakroute in replace command.
 *
 * Revision 1.15  1998/11/30 13:22:54  rgb
 * Rationalised all the klips kernel file headers.  They are much shorter
 * now and won't conflict under RH5.2.
 *
 * Revision 1.14  1998/11/10 05:36:14  rgb
 * Clean up debug output.
 * Add direction to spi setup debug code.
 * Add support for SA direction flag.
 *
 * Revision 1.13  1998/10/31 06:51:56  rgb
 * Get zeroize to return something useful.
 * Clean up code to isolate 'spi --add/del' memory leak.
 * Fixed up comments in #endif directives.
 *
 * Revision 1.12  1998/10/27 00:35:02  rgb
 * Supressed debug output during normal operation.
 *
 * Revision 1.11  1998/10/25 02:40:21  rgb
 * Selective debug printing, depending upon called service.
 * Institute more precise error return codes from eroute commands.
 * Fix bug in size of stucture passed in from user space for grpspi command.
 *
 * Revision 1.10  1998/10/22 06:44:58  rgb
 * Convert to use satoa for printk.
 * Moved break; in 'set debug level code to avoid undetected bug.
 * Fixed run-on error message to fit 80 columns.
 *
 * Revision 1.9  1998/10/19 14:44:28  rgb
 * Added inclusion of freeswan.h.
 * sa_id structure implemented and used: now includes protocol.
 *
 * Revision 1.8  1998/10/09 04:29:51  rgb
 * Added support for '-replace' option to eroute.
 * Fixed spiungroup bug.
 * Added 'klips_debug' prefix to all klips printk debug statements.
 *
 * Revision 1.7  1998/08/12 00:10:06  rgb
 * Fixed minor error return code syntax.
 *
 * Revision 1.6  1998/07/29 20:22:57  rgb
 * Cosmetic cleanup.
 *
 * Revision 1.5  1998/07/27 21:53:11  rgb
 * Check for proper return code from eroute clear command.
 * Use appropriate error return codes from kernel.
 * Add an option to clear the SA table.
 *
 * Revision 1.4  1998/07/14 18:02:40  rgb
 * Add a command to clear the eroute table.
 * Clean up some error codes.
 *
 * Revision 1.3  1998/06/25 19:52:33  rgb
 * Code cosmetic changes only.
 *
 * Revision 1.2  1998/06/23 02:57:58  rgb
 * Clean up after an error condition in setspi.
 *
 * Revision 1.9  1998/06/18 21:29:06  henry
 * move sources from klips/src to klips/net/ipsec, to keep stupid kernel
 * build scripts happier in presence of symbolic links
 *
 * Revision 1.8  1998/06/08 17:57:15  rgb
 * Very minor spacing change.
 *
 * Revision 1.7  1998/05/18 21:46:45  rgb
 * Clean up for numerical consistency of output.
 *
 * Added debugging switch output.
 *
 * SETSPI will refuse to overwrite a previous SA.  This is to make it
 * consistent with the eroute command.
 *
 * spidel now deletes entire chain of spi's.
 *
 * spigrp can now ungroup a set of spi's.
 *
 * spigrp will not regroup a previously grouped spi.
 *
 * Key data is properly cleaned up, ie. zeroed.
 *
 * Revision 1.6  1998/05/07 20:36:27  rgb
 * Fixed case where debugging not enabled that caused ipsec_netlink.c to
 * not compile.
 *
 * Revision 1.5  1998/05/06 03:34:21  rgb
 * Updated debugging output statements.
 *
 * Revision 1.4  1998/04/23 21:03:59  rgb
 * Completed kernel development for userspace access to klips kernel debugging
 * switches.
 * Added detail to the kernel error message when trying to group non-existant
 * spi's.
 *
 * Revision 1.3  1998/04/21 21:29:06  rgb
 * Rearrange debug switches to change on the fly debug output from user
 * space.  Only kernel changes checked in at this time.  radij.c was also
 * changed to temporarily remove buggy debugging code in rj_delete causing
 * an OOPS and hence, netlink device open errors.
 *
 * Revision 1.2  1998/04/12 22:03:23  rgb
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
 * Revision 1.1  1998/04/09 03:06:08  henry
 * sources moved up from linux/net/ipsec
 *
 * Revision 1.1.1.1  1998/04/08 05:35:02  henry
 * RGB's ipsec-0.8pre2.tar.gz ipsec-0.8
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
