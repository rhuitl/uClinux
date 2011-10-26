/*
 * (C) 2005 by Pablo Neira Ayuso <pablo@eurodev.net>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#ifndef _LIBNETFILTER_CONNTRACK_IPV6_H_
#define _LIBNETFILTER_CONNTRACK_IPV6_H_

#ifdef __cplusplus
extern "C" {
#endif

enum ipv6_flags {
	IPV6_ORIG_SRC_BIT = 0,
	IPV6_ORIG_SRC = (1 << IPV6_ORIG_SRC_BIT),

	IPV6_ORIG_DST_BIT = 1,
	IPV6_ORIG_DST = (1 << IPV6_ORIG_DST_BIT),

	IPV6_ORIG = (IPV6_ORIG_SRC | IPV6_ORIG_DST),

	IPV6_REPL_SRC_BIT = 2,
	IPV6_REPL_SRC = (1 << IPV6_REPL_SRC_BIT),

	IPV6_REPL_DST_BIT = 3,
	IPV6_REPL_DST = (1 << IPV6_REPL_DST_BIT),

	IPV6_REPL = (IPV6_REPL_SRC | IPV6_REPL_DST)
};

#ifdef __cplusplus
}
#endif

#endif
