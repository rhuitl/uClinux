/* Find public key in DNS
 * Copyright (C) 2000-2002  D. Hugh Redelmeier.
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
 * RCSID $Id: dnskey.h,v 1.18 2002/03/15 21:32:21 dhr Exp $
 */

extern int
    adns_qfd,	/* file descriptor for sending queries to adns */
    adns_afd;	/* file descriptor for receiving answers from adns */
extern const char *pluto_adns_option;	/* path from --pluto_adns */
extern void init_adns(void);
extern void stop_adns(void);
extern void handle_adns_answer(void);

/* (common prefix of) stuff remembered between async query and answer.
 * Filled in by start_adns_query.
 * Freed by call to release_adns_continuation.
 */

typedef void (*cont_fn_t)(struct adns_continuation *cr, err_t ugh);

struct adns_continuation {
    cont_fn_t cont_fn;	/* function to carry on suspended work */
    struct adns_query query;
    struct id id;	/* subject of query */
    bool sgw_specified;
    struct id sgw_id;	/* peer, if constrained */
};

extern err_t start_adns_query(const struct id *id	/* domain to query */
    , const struct id *sgw_id	/* if non-null, any accepted gw_info must match */
    , int type	/* T_TXT or T_KEY, selecting rr type of interest */
    , cont_fn_t cont_fn	/* continuation function */
    , struct adns_continuation *cr);

extern void release_adns_continuation(struct adns_continuation *cr);


extern struct pubkeyrec *keys_from_dns;	/* ephemeral! */

/* Gateway info gleaned from reverse DNS of client */
struct gw_info {
    unsigned refcnt;	/* reference counted! */
    unsigned pref;	/* preference: lower is better */
    enum dns_auth_level dns_auth_level;
    time_t created_time
	, last_tried_time
	, last_worked_time;
#define NO_TIME ((time_t) -2)	/* time_t value meaning "not_yet" */
    struct id client_id;	/* id of client of peer */
    struct id gw_id;	/* id of peer (if id_is_ipaddr, .ip_addr is address) */
    bool gw_key_present;
    struct RSA_public_key gw_key;
    struct gw_info *next;
};

extern struct gw_info *gateways_from_dns;	/* ephemeral! */

extern void gw_addref(struct gw_info *gw)
    , gw_delref(struct gw_info **gwp);
