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
 *
 * RCSID $Id: ipsec_netlink.h,v 1.31 2001/11/26 09:23:48 rgb Exp $
 */

#include <linux/stddef.h>

#ifndef NETLINK_IPSEC
#define NETLINK_IPSEC          10      /* IPSEC */ 
#endif /* !NETLINK_IPSEC */

#define EM_MAXRELSPIS	4		/* at most five chained xforms */
#define EM_MAGIC	0x5377616e	/* "Swan" */

#define EMT_IFADDR	1	/* set enc if addr */
#define EMT_SETSPI	2	/* Set SPI properties */
#define EMT_DELSPI	3	/* Delete an SPI */
#define EMT_GRPSPIS	4	/* Group SPIs (output order)  */
#define EMT_SETEROUTE	5	/* set an extended route */
#define EMT_DELEROUTE	6	/* del an extended route */
#define EMT_TESTROUTE	7	/* try to find route, print to console */
#define EMT_SETDEBUG	8	/* set debug level if active */
#define EMT_UNGRPSPIS	9	/* UnGroup SPIs (output order)  */
#define EMT_CLREROUTE	10	/* clear the extended route table */
#define EMT_CLRSPIS	11	/* clear the spi table */
#define EMT_REPLACEROUTE	12	/* set an extended route */
#define EMT_GETDEBUG	13	/* get debug level if active */
#define EMT_INEROUTE	14	/* set incoming policy for IPIP on a chain */

#ifdef CONFIG_IPSEC_DEBUG
#define DB_NL_TDBCB	0x0001
#endif /* CONFIG_IPSEC_DEBUG */

/* em_flags constants */
/* be mindful that this flag conflicts with SADB_SAFLAGS_PFS in pfkeyv2 */
/* perhaps it should be moved... */
#define EMT_INBOUND	0x01	/* SA direction, 1=inbound */

struct encap_msghdr
{
	__u32	em_magic;		/* EM_MAGIC */
#if 0
	__u16	em_msglen;		/* message length */
#endif
	__u8	em_msglen;		/* message length */
	__u8	em_flags;		/* message flags */
	__u8	em_version;		/* for future expansion */
	__u8	em_type;		/* message type */
	union
	{
		__u8	C;		/* Free-text */
		
		struct 
		{
			struct sa_id Said; /* SA ID */
			struct sockaddr_encap Eaddr;
			struct sockaddr_encap Emask;
		} Ert;

		struct
		{
			struct in_addr Ia;
			__u8	Ifn;
			__u8  xxx[3];	/* makes life a lot easier */
		} Ifa;

		struct
		{
			struct sa_id Said; /* SA ID */
			int If;		/* enc i/f for input */
			int Alg;	/* Algorithm to use */

                        /* The following union is a surrogate for
                         * algorithm-specific data.  To insure
                         * proper alignment, worst-case fields
                         * should be included.  It would be even
                         * better to include the types that will
                         * actually be used, but they may not be
                         * defined for each use of this header.
                         * The actual length is expected to be longer
                         * than is declared here.  References are normally
                         * made using the em_dat macro, as if it were a
                         * field name.
                         */
                        union { /* Data */
                                __u8 Dat[1];
                                __u64 Datq[1];  /* maximal alignment (?) */
                        } u;
		} Xfm;
		
		struct
		{
			struct sa_id emr_said; /* SA ID */
			struct ipsec_sa * emr_tdb; /* used internally! */
			
		} Rel[EM_MAXRELSPIS];
		
#ifdef CONFIG_IPSEC_DEBUG
		struct
		{
			int debug_tunnel;
			int debug_netlink;
			int debug_xform;
			int debug_eroute;
			int debug_spi;
			int debug_radij;
			int debug_esp;
			int debug_ah;
			int debug_rcv;
			int debug_pfkey;
			int debug_ipcomp;
			int debug_verbose;
		} Dbg;
#endif /* CONFIG_IPSEC_DEBUG */
	} Eu;
};

#define EM_MINLEN	offsetof(struct encap_msghdr, Eu)
#define EMT_SETSPI_FLEN	offsetof(struct encap_msghdr, em_dat)
#define EMT_GRPSPIS_FLEN offsetof(struct encap_msghdr, Eu.Rel)
#define EMT_SETDEBUG_FLEN (offsetof(struct encap_msghdr, Eu.Dbg + \
			sizeof(((struct encap_msghdr*)0)->Eu.Dbg)))

#define em_c	Eu.C
#define em_eaddr Eu.Ert.Eaddr
#define em_emask Eu.Ert.Emask
#define em_ersaid Eu.Ert.Said
#define em_erdst Eu.Ert.Said.dst
#define em_erspi Eu.Ert.Said.spi
#define em_erproto Eu.Ert.Said.proto

#define em_ifa	Eu.Ifa.Ia
#define em_ifn	Eu.Ifa.Ifn

#define em_said	Eu.Xfm.Said
#define em_spi	Eu.Xfm.Said.spi
#define em_dst	Eu.Xfm.Said.dst
#define em_proto	Eu.Xfm.Said.proto
#define em_if	Eu.Xfm.If
#define em_alg	Eu.Xfm.Alg
#define em_dat	Eu.Xfm.u.Dat

#define em_rel	Eu.Rel
#define emr_dst emr_said.dst
#define emr_spi emr_said.spi
#define emr_proto emr_said.proto

#ifdef CONFIG_IPSEC_DEBUG
#define em_db_tn Eu.Dbg.debug_tunnel
#define em_db_nl Eu.Dbg.debug_netlink
#define em_db_xf Eu.Dbg.debug_xform
#define em_db_er Eu.Dbg.debug_eroute
#define em_db_sp Eu.Dbg.debug_spi
#define em_db_rj Eu.Dbg.debug_radij
#define em_db_es Eu.Dbg.debug_esp
#define em_db_ah Eu.Dbg.debug_ah
#define em_db_rx Eu.Dbg.debug_rcv
#define em_db_ky Eu.Dbg.debug_pfkey
#define em_db_gz Eu.Dbg.debug_ipcomp
#define em_db_vb Eu.Dbg.debug_verbose
#endif /* CONFIG_IPSEC_DEBUG */

#ifdef __KERNEL__
extern char ipsec_netlink_c_version[];
#ifndef KERNEL_VERSION
#  include <linux/version.h>
#endif
#ifdef NETLINK_SOCK
extern int ipsec_callback(int proto, struct sk_buff *skb);
#else /* NETLINK_SOCK */
extern int ipsec_callback(struct sk_buff *skb);
#endif /* NETLINK_SOCK */
extern void ipsec_print_ip(struct iphdr *ip);

#ifdef CONFIG_IPSEC_DEBUG
	#define KLIPS_PRINT(flag, format, args...) \
		((flag) ? printk(KERN_INFO format , ## args) : 0)
	#define KLIPS_PRINTMORE(flag, format, args...) \
		((flag) ? printk(format , ## args) : 0)
	#define KLIPS_IP_PRINT(flag, ip) \
		((flag) ? ipsec_print_ip(ip) : 0)
#else /* CONFIG_IPSEC_DEBUG */
	#define KLIPS_PRINT(flag, format, args...) do ; while(0)
	#define KLIPS_PRINTMORE(flag, format, args...) do ; while(0)
	#define KLIPS_IP_PRINT(flag, ip) do ; while(0)
#endif /* CONFIG_IPSEC_DEBUG */

#ifdef CONFIG_IPSEC_DEBUG
extern int debug_netlink;
#endif /* CONFIG_IPSEC_DEBUG */
#endif /* __KERNEL__ */

/*
 * $Log: ipsec_netlink.h,v $
 * Revision 1.31  2001/11/26 09:23:48  rgb
 * Merge MCR's ipsec_sa, eroute, proc and struct lifetime changes.
 *
 * Revision 1.30  2001/07/06 19:49:16  rgb
 * Renamed EMT_RPLACEROUTE to EMT_REPLACEROUTE for clarity and logical text
 * searching.
 * Added EMT_INEROUTE for supporting incoming policy checks.
 *
 * Revision 1.29  2001/06/14 19:35:09  rgb
 * Update copyright date.
 *
 * Revision 1.28  2000/10/10 20:10:18  rgb
 * Added support for debug_ipcomp and debug_verbose to klipsdebug.
 *
 * Revision 1.27  2000/09/12 03:20:28  rgb
 * Cleared out now unused pfkeyv2 switch.
 *
 * Revision 1.26  2000/09/08 19:16:50  rgb
 * Change references from DEBUG_IPSEC to CONFIG_IPSEC_DEBUG.
 * Removed all references to CONFIG_IPSEC_PFKEYv2.
 *
 * Revision 1.25  2000/08/24 16:51:59  rgb
 * Added KLIPS_PRINTMORE macro to continue lines without KERN_INFO level
 * info.
 *
 * Revision 1.24  2000/08/09 20:43:34  rgb
 * Fixed bitmask value for SADB_X_SAFLAGS_CLEAREROUTE.
 *
 * Revision 1.23  2000/03/16 14:01:48  rgb
 * Hardwired CONFIG_IPSEC_PFKEYv2 on.
 *
 * Revision 1.22  1999/12/08 20:31:32  rgb
 * Moved IPPROTO_COMP to lib/freeswan.h to simplify userspace includes.
 *
 * Revision 1.21  1999/11/18 18:47:41  rgb
 * Added "#define NETLINK_IPSEC" in case kernel was not compiled with it.
 *
 * Revision 1.20  1999/11/18 04:09:18  rgb
 * Replaced all kernel version macros to shorter, readable form.
 *
 * Revision 1.19  1999/08/28 08:27:05  rgb
 * Add a temporary kludge for 2.0.37-38 to compile even if one patch failed.
 *
 * Revision 1.18  1999/08/03 17:09:33  rgb
 * Tidy up debug output, use KERN_INFO macro in printk's.
 *
 * Revision 1.17  1999/05/25 01:45:37  rgb
 * Fix version macros for 2.0.x as a module.
 *
 * Revision 1.16  1999/05/05 22:02:31  rgb
 * Add a quick and dirty port to 2.2 kernels by Marc Boucher <marc@mbsi.ca>.
 *
 * Revision 1.15  1999/04/29 15:16:55  rgb
 * Add pfkey support to debugging.
 *
 * Revision 1.14  1999/04/15 15:37:24  rgb
 * Forward check changes from POST1_00 branch.
 *
 * Revision 1.13  1999/04/11 00:28:58  henry
 * GPL boilerplate
 *
 * Revision 1.12  1999/04/06 04:54:26  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 * Revision 1.11  1999/02/12 21:13:17  rgb
 * Moved KLIPS_PRINT into a more accessible place.
 *
 * Revision 1.10  1999/01/28 23:20:49  rgb
 * Replace hard-coded numbers in macros and code with meaningful values
 * automatically generated from sizeof() and offsetof() to further the
 * goal of platform independance.
 *
 * Revision 1.9  1999/01/22 06:21:23  rgb
 * Added algorithm switch code.
 * Cruft clean-out.
 * 64-bit clean-up.
 *
 * Revision 1.8  1998/12/01 05:57:42  rgb
 * Add support for printing debug version info.
 *
 * Revision 1.7  1998/11/10 05:37:35  rgb
 * Add support for SA direction flag.
 *
 * Revision 1.6  1998/10/25 02:40:45  rgb
 * Fix bug in size of stucture passed in from user space for grpspi command.
 *
 * Revision 1.5  1998/10/19 14:44:29  rgb
 * Added inclusion of freeswan.h.
 * sa_id structure implemented and used: now includes protocol.
 *
 * Revision 1.4  1998/10/09 04:30:11  rgb
 * Added support for '-replace' option to eroute.
 *
 * Revision 1.3  1998/07/27 21:54:22  rgb
 * Rearrange structures for consistent alignment within a union.
 * Add an option for clearing SA table.
 *
 * Revision 1.2  1998/07/14 18:05:51  rgb
 * Added #ifdef __KERNEL__ directives to restrict scope of header.
 *
 * Revision 1.1  1998/06/18 21:27:49  henry
 * move sources from klips/src to klips/net/ipsec, to keep stupid
 * kernel-build scripts happier in the presence of symlinks
 *
 * Revision 1.4  1998/05/18 21:48:24  rgb
 * Added switch for ungrouping spi's.
 *
 * Revision 1.3  1998/04/23 21:01:50  rgb
 * Added a macro for userspace access to klips kernel debugging switches.
 *
 * Revision 1.2  1998/04/21 21:29:09  rgb
 * Rearrange debug switches to change on the fly debug output from user
 * space.  Only kernel changes checked in at this time.  radij.c was also
 * changed to temporarily remove buggy debugging code in rj_delete causing
 * an OOPS and hence, netlink device open errors.
 *
 * Revision 1.1  1998/04/09 03:06:09  henry
 * sources moved up from linux/net/ipsec
 *
 * Revision 1.1.1.1  1998/04/08 05:35:03  henry
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
