/*
 * (C) 2005 by Pablo Neira Ayuso <pablo@eurodev.net>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#ifndef _LIBNETFILTER_CONNTRACK_SCTP_H_
#define _LIBNETFILTER_CONNTRACK_SCTP_H_

#ifdef __cplusplus
extern "C" {
#endif

enum sctp_flags {
	SCTP_ORIG_SPORT_BIT = 0,
	SCTP_ORIG_SPORT = (1 << SCTP_ORIG_SPORT_BIT),

	SCTP_ORIG_DPORT_BIT = 1,
	SCTP_ORIG_DPORT = (1 << SCTP_ORIG_DPORT_BIT),

	SCTP_REPL_SPORT_BIT = 2,
	SCTP_REPL_SPORT = (1 << SCTP_REPL_SPORT_BIT),

	SCTP_REPL_DPORT_BIT = 3,
	SCTP_REPL_DPORT = (1 << SCTP_REPL_DPORT_BIT),

	SCTP_MASK_SPORT_BIT = 4,
	SCTP_MASK_SPORT = (1 << SCTP_MASK_SPORT_BIT),

	SCTP_MASK_DPORT_BIT = 5,
	SCTP_MASK_DPORT = (1 << SCTP_MASK_DPORT_BIT),

	SCTP_STATE_BIT = 6,
	SCTP_STATE = (1 << SCTP_STATE_BIT),

	SCTP_EXPTUPLE_SPORT_BIT = 7,
	SCTP_EXPTUPLE_SPORT = (1 << SCTP_EXPTUPLE_SPORT_BIT),

	SCTP_EXPTUPLE_DPORT_BIT = 8,
	SCTP_EXPTUPLE_DPORT = (1 << SCTP_EXPTUPLE_DPORT_BIT)
};

#ifdef __cplusplus
}
#endif

#endif
