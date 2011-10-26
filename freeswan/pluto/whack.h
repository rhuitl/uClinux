/* Structure of messages from whack to Pluto proper.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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
 * RCSID $Id: whack.h,v 1.42 2002/03/09 01:26:30 dhr Exp $
 */

#include <freeswan.h>

/*
 * Since the message remains on one host, native representation is used.
 * Think of this as horizontal microcode: all selected operations are
 * to be done (in the order declared here).
 *
 * MAGIC is used to help detect version mismatches between whack and Pluto.
 * Whenever the interface (i.e. this struct) changes in form or
 * meaning, change this value (probably by changing the last number).
 */
#define WHACK_MAGIC (((((('w' << 8) + 'a') << 8) + 'k') << 8) + 18)

/* struct whack_end is a lot like connection.h's struct end
 * It differs because it is going to be shipped down a socket
 * and because whack is a separate program from pluto.
 */
struct whack_end {
    char *id;	/* id string (if any) -- decoded by pluto */
    char *cert;	/* path string (if any) -- loaded by pluto  */

    ip_address
	host_addr,
	host_nexthop;
    ip_subnet client;
    u_int16_t port;		/* host order */
    u_int8_t protocol;

    bool has_client;
    bool has_client_wildcard;
    char *updown;		/* string */
    u_int16_t host_port;	/* host order */
#ifdef VIRTUAL_IP
    char *virt;
#endif
};

struct whack_message {
    unsigned int magic;

    /* name is used in connection and initiate */
    size_t name_len;	/* string 1 */
    char *name;
    char *dnshostname;

    /* for WHACK_OPTIONS: */

    bool whack_options;

    unsigned int debugging;

    /* for WHACK_CONNECTION */

    bool whack_connection;
    bool whack_async;

    lset_t policy;
    time_t sa_ike_life_seconds;
    time_t sa_ipsec_life_seconds;
    time_t sa_rekey_margin;
    unsigned long sa_rekey_fuzz;
    unsigned long sa_keying_tries;
    time_t dpd_delay;
    time_t dpd_timeout;
    int cipher_p1;
    int dhg_p1; 
    int hash_p1;

    /*  note that each end contains string 2/5.id, string 3/6 cert,
     *  and string 4/7 updown
     */
    struct whack_end left;
    struct whack_end right;

    /* note: if the client is the gateway, the following must be equal */
    sa_family_t addr_family;	/* between gateways */
    sa_family_t tunnel_addr_family;	/* between clients */

    char *ike;		/* ike algo string (separated by commas) */
    char *pfsgroup;	/* pfsgroup will be "encapsulated" in esp string for pluto */
    char *esp;		/* esp algo string (separated by commas) */

    int retransmit_trigger;

    /* for WHACK_KEY: */
    bool whack_key;
    bool whack_addkey;
    char *keyid;	/* string 8 */
    enum pubkey_alg pubkey_alg;
    chunk_t keyval;	/* chunk */

    /* for WHACK_ROUTE: */
    bool whack_route;

    /* for WHACK_UNROUTE: */
    bool whack_unroute;

    /* for WHACK_INITIATE: */
    bool whack_initiate;

    /* for WHACK_OPINITIATE */
    bool whack_oppo_initiate;
    ip_address oppo_my_client, oppo_peer_client;

    /* for WHACK_TERMINATE: */
    bool whack_terminate;

    /* for WHACK_DELETE: */
    bool whack_delete;

    /* for WHACK_DELETESTATE: */
    bool whack_deletestate;
    so_serial_t whack_deletestateno;

    /* for WHACK_LISTEN: */
    bool whack_listen, whack_unlisten;

    /* for WHACK_LIST */
    bool whack_utc;
    u_char whack_list;

   /* for WHACK_REREAD */
    u_char whack_reread;

    /* for WHACK_STATUS: */
    bool whack_status;

    /* for WHACK_SHUTDOWN */
    bool whack_shutdown;

    /* space for strings (hope there is enough room):
     * Note that pointers don't travel on wire.
     * 1 connection name [name_len]
     * 2 left's name [left.host.name.len]
     * 3 left's cert
     * 4 left's updown
     * 5 right's name [left.host.name.len]
     * 6 right's cert
     * 7 right's updown
     * 8 keyid
     * plus keyval (limit: 8K bits + overhead), a chunk.
     */
    size_t str_size;
    char string[2048];
};

/* Codes for status messages returned to whack.
 * These are 3 digit decimal numerals.  The structure
 * is inspired by section 4.2 of RFC959 (FTP).
 * Since these will end up as the exit status of whack, they
 * must be less than 256.
 * NOTE: ipsec_auto(8) knows about some of these numbers -- change carefully.
 */
enum rc_type {
    RC_COMMENT,		/* non-commital utterance (does not affect exit status) */
    RC_WHACK_PROBLEM,	/* whack-detected problem */
    RC_LOG,		/* message aimed at log (does not affect exit status) */
    RC_LOG_SERIOUS,	/* serious message aimed at log (does not affect exit status) */
    RC_SUCCESS,		/* success (exit status 0) */

    /* failure, but not definitive */

    RC_RETRANSMISSION = 10,

    /* improper request */

    RC_DUPNAME = 20,	/* attempt to reuse a connection name */
    RC_UNKNOWN_NAME,	/* connection name unknown or state number */
    RC_ORIENT,	/* cannot orient connection: neither end is us */
    RC_CLASH,	/* clash between two Road Warrior connections OVERLOADED */
    RC_DEAF,	/* need --listen before --initiate */
    RC_ROUTE,	/* cannot route */
    RC_RTBUSY,	/* cannot unroute: route busy */
    RC_BADID,	/* malformed --id */
    RC_NOKEY,	/* no key found through DNS */
    RC_NOPEERIP,	/* cannot initiate when peer IP is unknown */

    /* permanent failure */

    RC_BADWHACKMESSAGE = 30,
    RC_NORETRANSMISSION,
    RC_INTERNALERR,
    RC_OPPOFAILURE,	/* Opportunism failed */

    /* progress: start of range for successful state transition.
     * Actual value is RC_NEW_STATE plus the new state code.
     */
    RC_NEW_STATE = 100,

    /* start of range for notification.
     * Actual value is RC_NOTIFICATION plus code for notification
     * that should be generated by this Pluto.
     */
    RC_NOTIFICATION = 200	/* as per IKE notification messages */
};

/* options of whack --list*** command */

#define LIST_NONE	0x00	/* don't list anything */
#define LIST_PUBKEYS	0x01	/* list all public keys */
#define LIST_CERTS	0x02	/* list all host/user certs */
#define LIST_CACERTS	0x04	/* list all ca certs */
#define LIST_CRLS	0x08	/* list all crls */

#define LIST_ALL	LRANGES(LIST_PUBKEYS, LIST_CRLS)  /* all list options */

/* options of whack --reread*** command */

#define REREAD_NONE	0x00	/* don't reread anything */
#define REREAD_SECRETS	0x01	/* reread /etc/ipsec.secrets */
#define REREAD_MYCERT	0x02	/* reread /etc/x509cert.der (deprecated) */
#define REREAD_CACERTS	0x04	/* reread certs in /etc/ipsec.d/cacerts */
#define REREAD_CRLS	0x08	/* reread crls in /etc/ipsec.d/crls */

#define REREAD_ALL	LRANGES(REREAD_SECRETS, REREAD_CRLS)  /* all reread options */
