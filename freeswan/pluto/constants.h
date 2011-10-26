/* manifest constants
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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
 * RCSID $Id$
 */

extern void init_constants(void);

/*
 * NOTE:For debugging purposes, constants.c has tables to map numbers back to names.
 * Any changes here should be reflected there.
 */

#define elemsof(array) (sizeof(array) / sizeof(*(array)))	/* number of elements in an array */

/* Many routines return only success or failure, but wish to describe
 * the failure in a message.  We use the convention that they return
 * a NULL on success and a pointer to constant string on failure.
 * The fact that the string is a constant is limiting, but it
 * avoids storage management issues: the recipient is allowed to assume
 * that the string will live "long enough" (usually forever).
 * <freeswan.h> defines err_t for this return type.
 */

typedef int bool;
#define FALSE	0
#define TRUE	1

#define NULL_FD	(-1)	/* NULL file descriptor */
#define dup_any(fd) ((fd) == NULL_FD? NULL_FD : dup(fd))
#define close_any(fd) { if ((fd) != NULL_FD) { close(fd); (fd) = NULL_FD; } }

#define BITS_PER_BYTE	8

#define streq(a, b) (strcmp((a), (b)) == 0)	/* clearer shorthand */

/* set type with room for at least 32 elements */

typedef unsigned long long lset_t;
#define LEMPTY 0ULL
#define LELEM(opt) (1ULL << (opt))
#define LRANGE(lwb, upb) LRANGES(LELEM(lwb), LELEM(upb))
#define LRANGES(first, last) (last - first + last)
#define LALLIN(set, probe)	(((set) & (probe)) == (probe))

/* Control and lock pathnames */

#ifndef DEFAULT_CTLBASE
# define DEFAULT_CTLBASE "/var/run/pluto"
#endif

#define CTL_SUFFIX ".ctl"	/* for UNIX domain socket pathname */
#define LOCK_SUFFIX ".pid"	/* for pluto's lock */

/* Routines to check and display values.
 *
 * An enum_names describes an enumeration.
 * enum_name() returns the name of an enum value, or NULL if invalid.
 * enum_show() is like enum_name, except it formats a numeric representation
 *    for any invalid value (in a static area!)
 *
 * bitnames() formats a display of a set of named bits (in a static area)
 */

typedef const struct enum_names enum_names;

extern const char *enum_name(enum_names *ed, unsigned long val);
extern const char *enum_show(enum_names *ed, unsigned long val);
extern int enum_search(enum_names *ed, const char *string);

extern bool testset(const char *const table[], lset_t val);
extern const char *bitnamesof(const char *const table[], lset_t val);

/* sparse_names is much like enum_names, except values are
 * not known to be contiguous or ordered.
 * The array of names is ended with one with the name sparse_end
 * (this avoids having to reserve a value to signify the end).
 * Often appropriate for enums defined by others.
 */
struct sparse_name {
    unsigned long val;
    const char *const name;
};
typedef const struct sparse_name sparse_names[];

extern const char *sparse_name(sparse_names sd, unsigned long val);
extern const char *sparse_val_show(sparse_names sd, unsigned long val);
extern const char sparse_end[];

#define FULL_INET_ADDRESS_SIZE    6

/* Group parameters from draft-ietf-ike-01.txt section 6 */

#define MODP_GENERATOR "2"

#define MODP768_MODULUS \
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 " \
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD " \
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 " \
    "E485B576 625E7EC6 F44C42E9 A63A3620 FFFFFFFF FFFFFFFF"

#define MODP1024_MODULUS \
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 " \
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD " \
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 " \
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED " \
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381 " \
    "FFFFFFFF FFFFFFFF"

#define MODP1536_MODULUS \
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 " \
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD " \
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 " \
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED " \
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D " \
    "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F " \
    "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D " \
    "670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF "

/* draft-ietf-ipsec-ike-modp-groups-03.txt */
#define MODP2048_MODULUS \
	"FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1" \
	"29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD" \
	"EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245" \
	"E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED" \
	"EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D" \
	"C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F" \
	"83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D" \
	"670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B" \
	"E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9" \
	"DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510" \
	"15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"

#define MODP3072_MODULUS \
	"FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1" \
	"29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD" \
	"EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245" \
	"E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED" \
	"EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D" \
	"C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F" \
	"83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D" \
	"670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B" \
	"E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9" \
	"DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510" \
	"15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64" \
	"ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7" \
	"ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B" \
	"F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C" \
	"BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31" \
	"43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF"

#define MODP4096_MODULUS \
	"FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1" \
	"29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD" \
	"EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245" \
	"E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED" \
	"EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D" \
	"C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F" \
	"83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D" \
	"670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B" \
	"E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9" \
	"DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510" \
	"15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64" \
	"ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7" \
	"ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B" \
	"F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C" \
	"BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31" \
	"43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7" \
	"88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA" \
	"2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6" \
	"287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED" \
	"1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9" \
	"93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199" \
	"FFFFFFFF FFFFFFFF"

#define LOCALSECRETSIZE		(256 / BITS_PER_BYTE)

/* limits on nonce sizes.  See RFC2409 "The internet key exchange (IKE)" 5 */
#define MINIMUM_NONCE_SIZE	8	/* bytes */
#define DEFAULT_NONCE_SIZE	16	/* bytes */
#define MAXIMUM_NONCE_SIZE	256	/* bytes */

#define COOKIE_SIZE 8
#define MAX_ISAKMP_SPI_SIZE 16

#define MD2_DIGEST_SIZE		(128 / BITS_PER_BYTE)	/* ought to be supplied by md2.h */
#define MD5_DIGEST_SIZE		(128 / BITS_PER_BYTE)	/* ought to be supplied by md5.h */
#define SHA1_DIGEST_SIZE	(160 / BITS_PER_BYTE)	/* ought to be supplied by sha1.h */

#define DES_CBC_BLOCK_SIZE	(64 / BITS_PER_BYTE)

#define DSS_QBITS	160	/* bits in DSS's "q" (FIPS 186-1) */

/* to statically allocate IV, we need max of
 * MD5_DIGEST_SIZE, SHA1_DIGEST_SIZE, and DES_CBC_BLOCK_SIZE.
 * To avoid combinatorial explosion, we leave out DES_CBC_BLOCK_SIZE.
 */
#define MAX_DIGEST_LEN_OLD (MD5_DIGEST_SIZE > SHA1_DIGEST_SIZE? MD5_DIGEST_SIZE : SHA1_DIGEST_SIZE)

/* for max: SHA2_512 */
#define MAX_DIGEST_LEN (512/BITS_PER_BYTE)
/* draft-ietf-ipsec-auth-hmac-sha196-01.txt section 3 */
#define HMAC_SHA1_KEY_LEN    SHA1_DIGEST_SIZE

/* draft-ietf-ipsec-auth-hmac-md5-96-01.txt section 3 */
#define HMAC_MD5_KEY_LEN    MD5_DIGEST_SIZE

#define IKE_UDP_PORT	500

/* Timer events */

extern enum_names timer_event_names;

enum event_type {
    EVENT_NULL,	/* non-event */
    EVENT_REINIT_SECRET,	/* Refresh cookie secret */
#ifdef KLIPS
    EVENT_SHUNT_SCAN,	/* scan shunt eroutes known to kernel */
#endif
    EVENT_SO_DISCARD,	/* discard unfinished state object */
    EVENT_RETRANSMIT,	/* Retransmit packet */
    EVENT_SA_REPLACE,	/* SA replacement event */
    EVENT_SA_EXPIRE,	/* SA expiration event */
#ifdef NAT_TRAVERSAL
    EVENT_NAT_T_KEEPALIVE,
#endif
    EVENT_DPD,		/* dead peer detection */
    EVENT_DPD_TIMEOUT	/* dead peer detection timeout */
};

#define EVENT_REINIT_SECRET_DELAY		3600 /* 1 hour */
#define EVENT_RETRANSMIT_DELAY_0		10   /* 10 seconds */

/* Misc. stuff */

#define MAXIMUM_RETRANSMISSIONS              2
#define MAXIMUM_RETRANSMISSIONS_INITIAL      20

/* We don't really want to handle 64k byte packets */
#include <net/ethernet.h>
#define MAX_INPUT_UDP_SIZE             4096
#define MAX_OUTPUT_UDP_SIZE            4096

/* Version numbers */

#define ISAKMP_MAJOR_VERSION   0x1
#define ISAKMP_MINOR_VERSION   0x0

extern enum_names version_names;

/* Domain of Interpretation */

extern enum_names doi_names;

#define ISAKMP_DOI_ISAKMP          0
#define ISAKMP_DOI_IPSEC           1

/* IPsec DOI things */

#define IPSEC_DOI_SITUATION_LENGTH 4
#define IPSEC_DOI_LDI_LENGTH       4
#define IPSEC_DOI_SPI_SIZE         4

/* SPI value 0 is invalid and values 1-255 are reserved to IANA.
 * ESP: RFC 2402 2.4; AH: RFC 2406 2.1
 * IPComp RFC 2393 substitutes a CPI in the place of an SPI.
 * see also draft-shacham-ippcp-rfc2393bis-05.txt.
 * We (FreeS/WAN) reserve 0x100 to 0xFFF for manual keying, so
 * Pluto won't generate these values.
 */
#define IPSEC_DOI_SPI_MIN          0x100
#define IPSEC_DOI_SPI_OUR_MIN      0x1000

/* debugging settings: a set selections for reporting
 * These would be more naturally situated in log.h,
 * but they are shared with whack.
 */
#ifdef DEBUG
extern const char *const debug_bit_names[];

#define DBG_RAW		0x01	/* raw packet I/O */
#define DBG_CRYPT	0x02	/* encryption/decryption of messages */
#define DBG_PARSING	0x04	/* show decoding of messages */
#define DBG_EMITTING	0x08	/* show encoding of messages */
#define DBG_CONTROL	0x10	/* control flow within Pluto */
#define DBG_LIFECYCLE	0x20	/* SA lifecycle */
#define DBG_KLIPS	0x40	/* messages to KLIPS */
#ifdef NAT_TRAVERSAL
#define DBG_NATT	0x80	/* NAT-Traversal */
#define DBG_DNS		0x100	/* DNS activity */
#define DBG_PRIVATE	0x200	/* private information: DANGER! */
#else
#define DBG_DNS		0x80	/* DNS activity */
#define DBG_PRIVATE	0x100	/* private information: DANGER! */
#endif

#define DBG_NONE	0	/* no options on */
#define DBG_ALL		LRANGES(DBG_RAW, DBG_DNS)	/* all options on EXCEPT DBG_PRIVATE */
#endif

/* State of exchanges
 *
 * The name of the state describes the last message sent, not the
 * message currently being input or output (except during retry).
 * In effect, the state represents the last completed action.
 *
 * Messages are named [MQ][IR]n where
 * - M stands for Main Mode (Phase 1);
 *   Q stands for Quick Mode (Phase 2)
 * - I stands for Initiator;
 *   R stands for Responder
 * - n, a digit, stands for the number of the message
 *
 * It would be more convenient if each state accepted a message
 * and produced one.  This is the case for states at the start
 * or end of an exchange.  To fix this, we pretend that there are
 * MR0 and QR0 messages before the MI1 and QR1 messages.  Similarly,
 * we pretend that there are MR4 and QR2 messages.
 *
 * STATE_MAIN_R0 and STATE_QUICK_R0 are intermediate states (not
 * retained between messages) representing the state that accepts the
 * first message of an exchange has been read but not processed.
 *
 * state_microcode state_microcode_table in demux.c describes
 * other important details.
 */

extern enum_names state_names;
extern const char *const state_story[];

enum state_kind {
    STATE_UNDEFINED,	/* 0 -- most likely accident */

    /*  Opportunism states: see "Opportunistic Encryption" 2.2 */

    OPPO_ACQUIRE,	/* got an ACQUIRE message for this pair */
    OPPO_GW_DISCOVERED,	/* got TXT specifying gateway */

    /* IKE states */

    STATE_MAIN_R0,
    STATE_MAIN_I1,
    STATE_MAIN_R1,
    STATE_MAIN_I2,
    STATE_MAIN_R2,
    STATE_MAIN_I3,
    STATE_MAIN_R3,
    STATE_MAIN_I4,

    STATE_AGGR_R0,
    STATE_AGGR_I1,
    STATE_AGGR_R1,
    STATE_AGGR_I2,
    STATE_AGGR_R2,

    STATE_QUICK_R0,
    STATE_QUICK_I1,
    STATE_QUICK_R1,
    STATE_QUICK_I2,
    STATE_QUICK_R2,

    STATE_INFO,
    STATE_INFO_PROTECTED
};

#define STATE_IKE_FLOOR	STATE_MAIN_R0
#define STATE_IKE_ROOF	(STATE_INFO_PROTECTED + 1)

#define IS_PHASE1(s) (STATE_MAIN_R0 <= (s) && ((s) <= STATE_MAIN_I4 || (s) <= STATE_AGGR_R2))
#define IS_QUICK(s) (STATE_QUICK_R0 <= (s) && (s) <= STATE_QUICK_R2)
#define IS_ISAKMP_SA_ESTABLISHED(s) ((s) == STATE_MAIN_R3 || (s) == STATE_MAIN_I4 \
				|| (s) == STATE_AGGR_I2 || (s) == STATE_AGGR_R2)
#define IS_IPSEC_SA_ESTABLISHED(s) ((s) == STATE_QUICK_I2 || (s) == STATE_QUICK_R2)
#define IS_ONLY_INBOUND_IPSEC_SA_ESTABLISHED(s) ((s) == STATE_QUICK_R1)

/* kind of struct connection */

extern enum_names connection_kind_names;

enum connection_kind {
    CK_TEMPLATE,	/* abstract connection, with wildcard */
    CK_PERMANENT,	/* normal connection */
    CK_INSTANCE,	/* instance of template, created for a particular attempt */
    CK_GOING_AWAY	/* instance being deleted -- don't delete again */
};


/* routing status.
 * Note: routing ignores source address, but erouting does not!
 */

extern enum_names routing_story;

enum routing_t {
    RT_UNROUTED,	/* unrouted */
    RT_UNROUTED_HOLD,	/* unrouted, but HOLD shunt installed */
    RT_ROUTED_PROSPECTIVE,	/* routed, and TRAP shunt installed */
    RT_ROUTED_HOLD,	/* routed, and HOLD shunt installed */
    RT_ROUTED_FAILURE,	/* routed, and failure-context shunt installed */
    RT_ROUTED_TUNNEL	/* routed, and erouted to an IPSEC SA group */
};

#define routed(rs) ((rs) > RT_UNROUTED_HOLD)
#define erouted(rs) ((rs) != RT_UNROUTED)
#define shunt_erouted(rs) (erouted(rs) && (rs) != RT_ROUTED_TUNNEL)

/* Payload types
 * RFC2408 Internet Security Association and Key Management Protocol (ISAKMP)
 * section 3.1
 *
 * RESERVED 14-127
 * Private USE 128-255
 */

extern enum_names payload_names;
extern const char *const payload_name[];

#define ISAKMP_NEXT_NONE       0	/* No other payload following */
#define ISAKMP_NEXT_SA         1	/* Security Association */
#define ISAKMP_NEXT_P          2	/* Proposal */
#define ISAKMP_NEXT_T          3	/* Transform */
#define ISAKMP_NEXT_KE         4	/* Key Exchange */
#define ISAKMP_NEXT_ID         5	/* Identification */
#define ISAKMP_NEXT_CERT       6	/* Certificate */
#define ISAKMP_NEXT_CR         7	/* Certificate Request */
#define ISAKMP_NEXT_HASH       8	/* Hash */
#define ISAKMP_NEXT_SIG        9	/* Signature */
#define ISAKMP_NEXT_NONCE      10	/* Nonce */
#define ISAKMP_NEXT_N          11	/* Notification */
#define ISAKMP_NEXT_D          12	/* Delete */
#define ISAKMP_NEXT_VID        13	/* Vendor ID */

#ifdef NAT_TRAVERSAL
#define ISAKMP_NEXT_NATD_RFC   15   /* NAT-Traversal: NAT-D (rfc) */
#define ISAKMP_NEXT_NATOA_RFC  16   /* NAT-Traversal: NAT-OA (rfc) */
#define ISAKMP_NEXT_ROOF       17	/* roof on payload types */
#define ISAKMP_NEXT_NATD_DRAFTS   130  /* NAT-Traversal: NAT-D (drafts) */
#define ISAKMP_NEXT_NATOA_DRAFTS  131  /* NAT-Traversal: NAT-OA (drafts) */
#else
#define ISAKMP_NEXT_ROOF       14	/* roof on payload types */
#endif

/* Exchange types
 * RFC2408 "Internet Security Association and Key Management Protocol (ISAKMP)"
 * section 3.1
 *
 * ISAKMP Future Use     6 - 31
 * DOI Specific Use     32 - 239
 * Private Use         240 - 255
 *
 * Note: draft-ietf-ipsec-dhless-enc-mode-00.txt Appendix A
 * defines "DHless RSA Encryption" as 6.
 */

extern enum_names exchange_names;

#define ISAKMP_XCHG_NONE       0
#define ISAKMP_XCHG_BASE       1
#define ISAKMP_XCHG_IDPROT     2	/* ID Protection */
#define ISAKMP_XCHG_AO         3	/* Authentication Only */
#define ISAKMP_XCHG_AGGR       4	/* Aggressive */
#define ISAKMP_XCHG_INFO       5	/* Informational */

/* Extra exchange types, defined by Oakley
 * RFC2409 "The Internet Key Exchange (IKE)", near end of Appendix A
 */
#define ISAKMP_XCHG_QUICK      32	/* Oakley Quick Mode */
#define ISAKMP_XCHG_NGRP       33	/* Oakley New Group Mode */
/* added in draft-ietf-ipsec-ike-01.txt, near end of Appendix A */
#define ISAKMP_XCHG_ACK_INFO   34	/* Oakley Acknowledged Informational */

/* Flag bits */

extern const char *const flag_bit_names[];

#define ISAKMP_FLAG_ENCRYPTION   0x1
#define ISAKMP_FLAG_COMMIT       0x2

/* Situation definition for IPsec DOI */

extern const char *const sit_bit_names[];

#define SIT_IDENTITY_ONLY        0x01
#define SIT_SECRECY              0x02
#define SIT_INTEGRITY            0x04

/* Protocol IDs
 * RFC2407 The Internet IP security Domain of Interpretation for ISAKMP 4.4.1
 */

extern enum_names protocol_names;

#define PROTO_ISAKMP             1
#define PROTO_IPSEC_AH           2
#define PROTO_IPSEC_ESP          3
#define PROTO_IPCOMP             4

/* warning: trans_show uses enum_show, so same static buffer is used */
#define trans_show(p, t) \
    ((p)==PROTO_IPSEC_AH ? enum_show(&ah_transformid_names, (t)) \
    : (p)==PROTO_IPSEC_ESP ? enum_show(&esp_transformid_names, (t)) \
    : (p)==PROTO_IPCOMP ? enum_show(&ipcomp_transformid_names, (t)) \
    : "??")

/* IPsec ISAKMP transform values
 * RFC2407 The Internet IP security Domain of Interpretation for ISAKMP 4.4.2
 */

extern enum_names isakmp_transformid_names;

#define KEY_IKE               1

/* IPsec AH transform values
 * RFC2407 The Internet IP security Domain of Interpretation for ISAKMP 4.4.3
 * and in http://www.isi.edu/in-notes/iana/assignments/isakmp-registry
 */

extern enum_names ah_transformid_names;

#define AH_MD5                   2
#define AH_SHA                   3
#define AH_DES                   4
#define AH_SHA2_256              5
#define AH_SHA2_384              6
#define AH_SHA2_512              7

/* IPsec ESP transform values
 * RFC2407 The Internet IP security Domain of Interpretation for ISAKMP 4.4.4
 * and from http://www.isi.edu/in-notes/iana/assignments/isakmp-registry
 */

extern enum_names esp_transformid_names;

#define ESP_reserved             0
#define ESP_DES_IV64             1
#define ESP_DES                  2
#define ESP_3DES                 3
#define ESP_RC5                  4
#define ESP_IDEA                 5
#define ESP_CAST                 6
#define ESP_BLOWFISH             7
#define ESP_3IDEA                8
#define ESP_DES_IV32             9
#define ESP_RC4                 10
#define ESP_NULL                11
#define ESP_AES                 12

/* IPCOMP transform values
 * RFC2407 The Internet IP security Domain of Interpretation for ISAKMP 4.4.5
 */

extern enum_names ipcomp_transformid_names;

#define IPCOMP_OUI               1
#define IPCOMP_DEFLATE           2
#define IPCOMP_LZS               3
#define IPCOMP_V42BIS            4

/* the following are from RFC 2393/draft-shacham-ippcp-rfc2393bis-05.txt 3.3 */
typedef u_int16_t cpi_t;
#define IPCOMP_CPI_SIZE          2
#define IPCOMP_FIRST_NEGOTIATED  256
#define IPCOMP_LAST_NEGOTIATED   61439

/* Identification type values
 * RFC 2407 The Internet IP security Domain of Interpretation for ISAKMP 4.6.2.1
 */

extern enum_names ident_names;

#define ID_NONE                     0	/* private to Pluto */
#define ID_IPV4_ADDR                1
#define ID_FQDN                     2
#define ID_USER_FQDN                3
#define ID_IPV4_ADDR_SUBNET         4
#define ID_IPV6_ADDR                5
#define ID_IPV6_ADDR_SUBNET         6
#define ID_IPV4_ADDR_RANGE          7
#define ID_IPV6_ADDR_RANGE          8
#define ID_DER_ASN1_DN              9
#define ID_DER_ASN1_GN              10
#define ID_KEY_ID                   11

/* Certificate type values
 * RFC 2408 ISAKMP, chapter 3.9
 */

extern enum_names cert_type_names;

#define CERT_NONE			0
#define CERT_PKCS7_WRAPPED_X509		1
#define CERT_PGP			2
#define CERT_DNS_SIGNED_KEY		3
#define CERT_X509_SIGNATURE		4
#define CERT_X509_KEY_EXCHANGE		5
#define CERT_KERBEROS_TOKENS		6
#define CERT_CRL			7
#define CERT_ARL			8
#define CERT_SPKI			9
#define CERT_X509_ATTRIBUTE		10

/* Policies for establishing an SA
 *
 * These are used to specify attributes (eg. encryption) and techniques
 * (eg PFS) for an SA.
 */

extern const char *const sa_policy_bit_names[];

/* ISAKMP auth techniques */
#define POLICY_AGGRESSIVE    LELEM(0)
#define POLICY_PSK           LELEM(1)
#define POLICY_RSASIG        LELEM(2)

#define POLICY_ISAKMP_SHIFT	1	/* log2(POLICY_PSK) */
#define POLICY_ID_AUTH_MASK	LRANGES(POLICY_AGGRESSIVE, POLICY_RSASIG)
#define POLICY_ISAKMP_MASK	POLICY_ID_AUTH_MASK	/* all so far */

/* Quick Mode (IPSEC) attributes */
#define POLICY_ENCRYPT       LELEM(3)	/* must be first of IPSEC policies */
#define POLICY_AUTHENTICATE  LELEM(4)	/* must be second */
#define POLICY_COMPRESS      LELEM(5)	/* must be third */
#define POLICY_TUNNEL        LELEM(6)
#define POLICY_PFS           LELEM(7)
#define POLICY_DISABLEARRIVALCHECK  LELEM(8)	/* supress tunnel egress address checking */

#define POLICY_IPSEC_SHIFT	3	/* log2(POLICY_ENCRYPT) */
#define POLICY_IPSEC_MASK	LRANGES(POLICY_ENCRYPT, POLICY_DISABLEARRIVALCHECK)

/* opportunistic attributes: what to do with a packet without a tunnel */
#define POLICY_PASS     LELEM(9)
#define POLICY_DROP     LELEM(10)
/* PASS | DROP is construed as REJECT */

#define POLICY_OPPO_SHIFT	9	/* log2(POLICY_PASS) */
#define POLICY_OPPO_MASK	(POLICY_PASS | POLICY_DROP)

/* connection policy
 * Other policies could vary per state object.  These live in connection.
 */
#define POLICY_DONT_REKEY     LELEM(11)	/* don't rekey state either Phase */
#define POLICY_OPPO     LELEM(12)	/* is this opportunistic? */


/* Any IPsec policy?  If not, a connection description
 * is only for ISAKMP SA, not IPSEC SA.  (A pun, I admit.)
 */
#define HAS_IPSEC_POLICY(p) (((p) & POLICY_IPSEC_MASK) != 0)

/* Oakley transform attributes
 * draft-ietf-ipsec-ike-01.txt appendix A
 */

extern enum_names oakley_attr_names;
extern const char *const oakley_attr_bit_names[];

#define OAKLEY_ENCRYPTION_ALGORITHM    1
#define OAKLEY_HASH_ALGORITHM          2
#define OAKLEY_AUTHENTICATION_METHOD   3
#define OAKLEY_GROUP_DESCRIPTION       4
#define OAKLEY_GROUP_TYPE              5
#define OAKLEY_GROUP_PRIME             6	/* B/V */
#define OAKLEY_GROUP_GENERATOR_ONE     7	/* B/V */
#define OAKLEY_GROUP_GENERATOR_TWO     8	/* B/V */
#define OAKLEY_GROUP_CURVE_A           9	/* B/V */
#define OAKLEY_GROUP_CURVE_B          10	/* B/V */
#define OAKLEY_LIFE_TYPE              11
#define OAKLEY_LIFE_DURATION          12	/* B/V */
#define OAKLEY_PRF                    13
#define OAKLEY_KEY_LENGTH             14
#define OAKLEY_FIELD_SIZE             15
#define OAKLEY_GROUP_ORDER            16	/* B/V */
#define OAKLEY_BLOCK_SIZE             17

/* for each Oakley attribute, which enum_names describes its values? */
extern enum_names *oakley_attr_val_descs[];

/* IPsec DOI attributes
 * RFC2407 The Internet IP security Domain of Interpretation for ISAKMP 4.5
 */

extern enum_names ipsec_attr_names;

#define SA_LIFE_TYPE             1
#define SA_LIFE_DURATION         2	/* B/V */
#define GROUP_DESCRIPTION        3
#define ENCAPSULATION_MODE       4
#define AUTH_ALGORITHM           5
#define KEY_LENGTH               6
#define KEY_ROUNDS               7
#define COMPRESS_DICT_SIZE       8
#define COMPRESS_PRIVATE_ALG     9	/* B/V */

/* for each IPsec attribute, which enum_names describes its values? */
extern enum_names *ipsec_attr_val_descs[];

/* SA Lifetime Type attribute
 * RFC2407 The Internet IP security Domain of Interpretation for ISAKMP 4.5
 * Default time specified in 4.5
 *
 * There are two defaults for IPSEC SA lifetime, SA_LIFE_DURATION_DEFAULT,
 * and PLUTO_SA_LIFE_DURATION_DEFAULT.
 * SA_LIFE_DURATION_DEFAULT is specified in RFC2407 "The Internet IP
 * Security Domain of Interpretation for ISAKMP" 4.5.  It applies when
 * an ISAKMP negotiation does not explicitly specify a life duration.
 * PLUTO_SA_LIFE_DURATION_DEFAULT is specified in pluto(8).  It applies
 * when a connection description does not specify --ipseclifetime.
 * The value of SA_LIFE_DURATION_MAXIMUM is our local policy.
 */

extern enum_names sa_lifetime_names;

#define SA_LIFE_TYPE_SECONDS   1
#define SA_LIFE_TYPE_KBYTES    2

#define SA_LIFE_DURATION_DEFAULT    28800 /* eight hours (RFC2407 4.5) */
#define PLUTO_SA_LIFE_DURATION_DEFAULT    28800 /* eight hours (pluto(8)) */
#define SA_LIFE_DURATION_MAXIMUM    86400 /* one day */

#define SA_REPLACEMENT_MARGIN_DEFAULT	    540	  /* (IPSEC & IKE) nine minutes */
#define SA_REPLACEMENT_FUZZ_DEFAULT	    100	  /* (IPSEC & IKE) 100% of MARGIN */
#define SA_REPLACEMENT_RETRIES_DEFAULT	    3	/*  (IPSEC & IKE) */

#define SA_LIFE_DURATION_K_DEFAULT  0xFFFFFFFFlu

/* Encapsulation Mode attribute */

extern enum_names enc_mode_names;

#define ENCAPSULATION_MODE_UNSPECIFIED 0	/* not legal -- used internally */
#define ENCAPSULATION_MODE_TUNNEL      1
#define ENCAPSULATION_MODE_TRANSPORT   2

#ifdef NAT_TRAVERSAL
#define ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS       61443
#define ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS    61444
#define ENCAPSULATION_MODE_UDP_TUNNEL_RFC          3
#define ENCAPSULATION_MODE_UDP_TRANSPORT_RFC       4
#endif

/* Auth Algorithm attribute */

extern enum_names auth_alg_names, extended_auth_alg_names;

#define AUTH_ALGORITHM_NONE        0	/* our private designation */
#define AUTH_ALGORITHM_HMAC_MD5    1
#define AUTH_ALGORITHM_HMAC_SHA1   2
#define AUTH_ALGORITHM_DES_MAC     3
#define AUTH_ALGORITHM_KPDK        4
#define AUTH_ALGORITHM_HMAC_SHA2_256   5
#define AUTH_ALGORITHM_HMAC_SHA2_384   6
#define AUTH_ALGORITHM_HMAC_SHA2_512   7
#define AUTH_ALGORITHM_HMAC_RIPEMD     8


/* Oakley Lifetime Type attribute
 * draft-ietf-ipsec-ike-01.txt appendix A
 * As far as I can see, there is not specification for
 * OAKLEY_ISAKMP_SA_LIFETIME_DEFAULT.  This could lead to interop problems!
 * For no particular reason, we chose one hour.
 * The value of OAKLEY_ISAKMP_SA_LIFETIME_MAXIMUM is our local policy.
 */
extern enum_names oakley_lifetime_names;

#define OAKLEY_LIFE_SECONDS   1
#define OAKLEY_LIFE_KILOBYTES 2

#define OAKLEY_ISAKMP_SA_LIFETIME_DEFAULT 3600    /* one hour */
#define OAKLEY_ISAKMP_SA_LIFETIME_MAXIMUM 86400   /* one day */

/* Oakley PRF attribute (none defined)
 * draft-ietf-ipsec-ike-01.txt appendix A
 */
extern enum_names oakley_prf_names;

/* HMAC (see rfc2104.txt) */

#define HMAC_IPAD            0x36
#define HMAC_OPAD            0x5C
#define HMAC_BUFSIZE         64

/* Oakley Encryption Algorithm attribute
 * draft-ietf-ipsec-ike-01.txt appendix A
 * and from http://www.isi.edu/in-notes/iana/assignments/ipsec-registry
 */

extern enum_names oakley_enc_names;

#define OAKLEY_DES_CBC          1
#define OAKLEY_IDEA_CBC         2
#define OAKLEY_BLOWFISH_CBC     3
#define OAKLEY_RC5_R16_B64_CBC  4
#define OAKLEY_3DES_CBC         5
#define OAKLEY_CAST_CBC         6
#define OAKLEY_AES_CBC          7

#define OAKLEY_ENCRYPT_MAX      65535	/* pretty useless :) */

/* Oakley Hash Algorithm attribute
 * draft-ietf-ipsec-ike-01.txt appendix A
 * and from http://www.isi.edu/in-notes/iana/assignments/ipsec-registry
 */

extern enum_names oakley_hash_names;

#define OAKLEY_MD5      1
#define OAKLEY_SHA      2
#define OAKLEY_TIGER    3
#define OAKLEY_SHA2_256        4
#define OAKLEY_SHA2_384        5
#define OAKLEY_SHA2_512        6

#define OAKLEY_HASH_MAX      7

/* Oakley Authentication Method attribute
 * draft-ietf-ipsec-ike-01.txt appendix A
 * Goofy Hybrid extensions from draft-ietf-ipsec-isakmp-hybrid-auth-05.txt
 * Goofy XAUTH extensions from draft-ietf-ipsec-isakmp-xauth-06.txt
 */

extern enum_names oakley_auth_names;

#define OAKLEY_PRESHARED_KEY       1
#define OAKLEY_DSS_SIG             2
#define OAKLEY_RSA_SIG             3
#define OAKLEY_RSA_ENC             4
#define OAKLEY_RSA_ENC_REV         5
#define OAKLEY_ELGAMAL_ENC         6
#define OAKLEY_ELGAMAL_ENC_REV     7

#define OAKLEY_AUTH_ROOF           8	/* roof on auth values THAT WE SUPPORT */

#define HybridInitRSA                                     64221
#define HybridRespRSA                                     64222
#define HybridInitDSS                                     64223
#define HybridRespDSS                                     64224

#define XAUTHInitPreShared                                65001
#define XAUTHRespPreShared                                65002
#define XAUTHInitDSS                                      65003
#define XAUTHRespDSS                                      65004
#define XAUTHInitRSA                                      65005
#define XAUTHRespRSA                                      65006
#define XAUTHInitRSAEncryption                            65007
#define XAUTHRespRSAEncryption                            65008
#define XAUTHInitRSARevisedEncryption                     65009
#define XAUTHRespRSARevisedEncryption                     65010

/* Oakley Group Description attribute
 * draft-ietf-ipsec-ike-01.txt appendix A
 */
extern enum_names oakley_group_names;

#define OAKLEY_GROUP_MODP768       1
#define OAKLEY_GROUP_MODP1024      2
#define OAKLEY_GROUP_GP155         3
#define OAKLEY_GROUP_GP185         4
#define OAKLEY_GROUP_MODP1536      5

/*	you must also touch: constants.c, crypto.c */
#define OAKLEY_GROUP_MODP2048      42048
#define OAKLEY_GROUP_MODP3072      43072
#define OAKLEY_GROUP_MODP4096      44096

/* Oakley Group Type attribute
 * draft-ietf-ipsec-ike-01.txt appendix A
 */
extern enum_names oakley_group_type_names;

#define OAKLEY_GROUP_TYPE_MODP     1
#define OAKLEY_GROUP_TYPE_ECP      2
#define OAKLEY_GROUP_TYPE_EC2N     3


/* Notify messages -- error types
 * See RFC2408 ISAKMP 3.14.1
 */

extern enum_names notification_names;
extern enum_names ipsec_notification_names;

typedef enum {
    NOTHING_WRONG =             0,  /* unofficial! */

    INVALID_PAYLOAD_TYPE =       1,
    DOI_NOT_SUPPORTED =          2,
    SITUATION_NOT_SUPPORTED =    3,
    INVALID_COOKIE =             4,
    INVALID_MAJOR_VERSION =      5,
    INVALID_MINOR_VERSION =      6,
    INVALID_EXCHANGE_TYPE =      7,
    INVALID_FLAGS =              8,
    INVALID_MESSAGE_ID =         9,
    INVALID_PROTOCOL_ID =       10,
    INVALID_SPI =               11,
    INVALID_TRANSFORM_ID =      12,
    ATTRIBUTES_NOT_SUPPORTED =  13,
    NO_PROPOSAL_CHOSEN =        14,
    BAD_PROPOSAL_SYNTAX =       15,
    PAYLOAD_MALFORMED =         16,
    INVALID_KEY_INFORMATION =   17,
    INVALID_ID_INFORMATION =    18,
    INVALID_CERT_ENCODING =     19,
    INVALID_CERTIFICATE =       20,
    CERT_TYPE_UNSUPPORTED =     21,
    INVALID_CERT_AUTHORITY =    22,
    INVALID_HASH_INFORMATION =  23,
    AUTHENTICATION_FAILED =     24,
    INVALID_SIGNATURE =         25,
    ADDRESS_NOTIFICATION =      26,
    NOTIFY_SA_LIFETIME =        27,
    CERTIFICATE_UNAVAILABLE =   28,
    UNSUPPORTED_EXCHANGE_TYPE = 29,
    UNEQUAL_PAYLOAD_LENGTHS =   30,

    /* ISAKMP status type */
    CONNECTED =              16384,

    /* IPSEC DOI additions; status types (RFC2407 IPSEC DOI 4.6.3)
     * These must be sent under the protection of an ISAKMP SA.
     */
    IPSEC_RESPONDER_LIFETIME = 24576,
    IPSEC_REPLAY_STATUS =      24577,
    IPSEC_INITIAL_CONTACT =    24578,

    /* DPD notification types */
    R_U_THERE =                36136,
    R_U_THERE_ACK =            36137
    } notification_t;


/* Public key algorithm number
 * Same numbering as used in DNSsec
 * See RFC 2535 DNSsec 3.2 The KEY Algorithm Number Specification.
 * Also found in BIND 8.2.2 include/isc/dst.h as DST algorithm codes.
 */

enum pubkey_alg
{
    PUBKEY_ALG_RSA = 1,
    PUBKEY_ALG_DSA = 3,
};

/* Limits on size of RSA moduli.
 * The upper bound matches that of DNSsec (see RFC 2537).
 * The lower bound must be more than 11 octets for certain
 * the encoding to work, but it must be much larger for any
 * real security.  For now, we require 512 bits.
 */

#define RSA_MIN_OCTETS_RFC	12

#define RSA_MIN_OCTETS	(512 / BITS_PER_BYTE)
#define RSA_MIN_OCTETS_UGH	"RSA modulus too small for security: less than 512 bits"

#define RSA_MAX_OCTETS	(4096 / BITS_PER_BYTE)
#define RSA_MAX_OCTETS_UGH	"RSA modulus too large: more than 4096 bits"

/* socket address family info */

struct af_info
{
    int af;
    const char *name;
    size_t ia_sz;
    size_t sa_sz;
    int mask_cnt;
    u_int8_t id_addr, id_subnet, id_range;
    const ip_address *any;
    const ip_subnet *wildcard;	/* 0.0.0.0/32 or IPv6 equivalent */
    const ip_subnet *all;	/* 0.0.0.0/0 or IPv6 equivalent */
};

extern const struct af_info
    af_inet4_info,
    af_inet6_info;

extern const struct af_info *aftoinfo(int af);

extern enum_names af_names;

/* BIND enumerated types */

extern enum_names
    rr_qtype_names,
    rr_type_names,
    rr_class_names;

/* How authenticated is info that might have come from DNS?
 * In order of increasing confidence.
 */
enum dns_auth_level {
    DAL_UNSIGNED,	/* AD in response, but no signature: no authentication */
    DAL_NOTSEC,	/* no AD in response: authentication impossible */
    DAL_SIGNED,	/* AD and signature in response: authentic */
    DAL_LOCAL	/* locally provided (pretty good) */
};

/* interfaces */
#define NUM_INTERFACES 4
extern char *phys_interfaces[NUM_INTERFACES];
