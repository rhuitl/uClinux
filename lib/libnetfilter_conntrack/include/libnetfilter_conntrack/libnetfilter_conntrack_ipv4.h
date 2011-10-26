/*
 * (C) 2005 by Pablo Neira Ayuso <pablo@eurodev.net>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#ifndef _LIBNETFILTER_CONNTRACK_IPV4_H_
#define _LIBNETFILTER_CONNTRACK_IPV4_H_

#ifdef __cplusplus
extern "C" {
#endif

enum ipv4_flags {
	IPV4_ORIG_SRC_BIT = 0,
	IPV4_ORIG_SRC = (1 << IPV4_ORIG_SRC_BIT),

	IPV4_ORIG_DST_BIT = 1,
	IPV4_ORIG_DST = (1 << IPV4_ORIG_DST_BIT),

	IPV4_ORIG = (IPV4_ORIG_SRC | IPV4_ORIG_DST),

	IPV4_REPL_SRC_BIT = 2,
	IPV4_REPL_SRC = (1 << IPV4_REPL_SRC_BIT),

	IPV4_REPL_DST_BIT = 3,
	IPV4_REPL_DST = (1 << IPV4_REPL_DST_BIT),

	IPV4_REPL = (IPV4_REPL_SRC | IPV4_REPL_DST)
};

#ifdef __cplusplus
}
#endif

#endif
