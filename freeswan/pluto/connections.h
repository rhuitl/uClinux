/* information about connections between hosts and clients
 * Copyright (C) 1998-2001  D. Hugh Redelmeier
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
 * RCSID $Id: connections.h,v 1.59 2002/03/31 20:42:04 dhr Exp $
 */

/* There are two kinds of connections:
 * - ISAKMP connections, between hosts (for IKE communication)
 * - IPsec connections, between clients (for secure IP communication)
 *
 * An ISAKMP connection looks like:
 *   host<--->host
 *
 * An IPsec connection looks like:
 *   client-subnet<-->host<->nexthop<--->nexthop<->host<-->client-subnet
 *
 * For the connection to be relevant to this instance of Pluto,
 * exactly one of the hosts must be a public interface of our machine
 * known to this instance.
 *
 * The client subnet might simply be the host -- this is a
 * representation of "host mode".
 *
 * Each nexthop defaults to the neighbouring host's IP address.
 * The nexthop is a property of the pair of hosts, not each
 * individually.  It is only needed for IPsec because of the
 * way IPsec is mixed into the kernel routing logic.  Furthermore,
 * only this end's nexthop is actually used.  Eventually, nexthop
 * will be unnecessary.
 *
 * Other information represented:
 * - each connection has a name: a chunk of uninterpreted text
 *   that is unique for each connection.
 * - security requirements (currently just the "policy" flags from
 *   the whack command to initiate the connection, but eventually
 *   much more.  Different for ISAKMP and IPsec connections.
 * - rekeying parameters:
 *   + time an SA may live
 *   + time before SA death that a rekeying should be attempted
 *     (only by the initiator)
 *   + number of times to attempt rekeying
 * - With the current KLIPS, we must route packets for a client
 *   subnet through the ipsec interface (ipsec0).  Only one
 *   gateway can get traffic for a specific (client) subnet.
 *   Furthermore, if the routing isn't in place, packets will
 *   be sent in the clear.
 *   "routing" indicates whether the routing has been done for
 *   this connection.  Note that several connections may claim
 *   the same routing, as long as they agree about where the
 *   packets are to be sent.
 * - With the current KLIPS, only one outbound IPsec SA bundle can be
 *   used for a particular client.  This is due to a limitation
 *   of using only routing for selection.  So only one IPsec state (SA)
 *   may "own" the eroute.  "eroute_owner" is the serial number of
 *   this state, SOS_NOBODY if there is none.  "routing" indicates
 *   what kind of erouting has been done for this connection, if any.
 *
 * Operations on Connections:
 *
 * - add a new connection (with all details) [whack command]
 * - delete a connection (by name) [whack command]
 * - initiate a connection (by name) [whack command]
 * - find a connection (by IP addresses of hosts)
 *   [response to peer request; finding ISAKMP connection for IPsec connection]
 *
 * Some connections are templates, missing the address of the peer
 * (represented by INADDR_ANY).  These are always arranged so that the
 * missing end is "that" (there can only be one missing end).  These can
 * be instantiated (turned into real connections) by Pluto in one of two
 * different ways: Road Warrior Instantiation or Opportunistic
 * Instantiation.  A template connection is marked for Opportunistic
 * Instantiation by specifying the peer client as 0.0.0.0/32 (or the IPV6
 * equivalent).  Otherwise, it is suitable for Road Warrior Instantiation.
 *
 * Instantiation creates a new temporary connection, with the missing
 * details filled in.  The resulting template lasts only as long as there
 * is a state that uses it.
 */
#ifndef _CONNECTIONS_H
#define _CONNECTIONS_H

#ifdef VIRTUAL_IP
struct virtual_t;
#endif

struct end {
    struct id id;
    ip_address
	host_addr,
	host_nexthop;
    ip_subnet client;
    u_int16_t port;		/* host order */
    u_int8_t protocol;

    bool has_client;
    bool has_client_wildcard;
    char *updown;
    u_int16_t host_port;	/* host order */
    x509cert_t *cert;
#ifdef VIRTUAL_IP
    struct virtual_t *virt;
#endif
};

struct connection {
    char *name;
    char *dnshostname;
    lset_t policy;
    time_t sa_ike_life_seconds;
    time_t sa_ipsec_life_seconds;
    time_t sa_rekey_margin;
    unsigned long sa_rekey_fuzz;
    unsigned long sa_keying_tries;
    time_t dpd_delay;
    time_t dpd_timeout;
    struct {
    	int cipher;
    	int dhg;
    	int hash;
    } algorithm_p1;
    
    struct end
	this,
	that;

    /* internal fields: */

    enum connection_kind kind;
    const struct iface *interface;	/* filled in iff oriented */
    enum routing_t routing;	/* level of routing in place */
    bool initiated;

    so_serial_t	/* state object serial number */
	newest_isakmp_sa,
	newest_ipsec_sa,
	eroute_owner;

#ifdef DEBUG
    unsigned int extra_debugging;
#endif

    /* note: if the client is the gateway, the following must be equal */
    sa_family_t addr_family;	/* between gateways */
    sa_family_t tunnel_addr_family;	/* between clients */

    struct gw_info *gw_info;
    struct alg_info_esp *alg_info_esp;
    struct alg_info_ike *alg_info_ike;

    int retransmit_trigger;

    struct host_pair *host_pair;
    struct connection *hp_next;	/* host pair list link */

    struct connection *ac_next;	/* all connections list link */
};

#define oriented(c) ((c).interface != NULL)
extern bool orient(struct connection *c);

extern struct connection *
find_host_connection_mode(const ip_address *myaddr, u_int16_t myport
, const ip_address *hisaddr, u_int16_t hisport, bool main);

extern bool same_peer_ids(const struct connection *c
    , const struct connection *d, const struct id *his_id);

extern size_t format_end(char *buf, size_t buf_len
    , const struct end *this, const struct end *that, bool is_left);

struct whack_message;	/* forward declaration of tag whack_msg */
extern void add_connection(const struct whack_message *wm);
extern void initiate_connection(const char *name, int whackfd);
extern void initiate_connections_by_peer(struct connection *c);
extern void initiate_opportunistic(const ip_address *our_client
    , const ip_address *peer_client, bool held, int whackfd);
extern void terminate_connection(const char *nm);
extern void terminate_connections_by_peer(struct connection *c);
extern void release_connection(struct connection *c);
extern void delete_connection(struct connection *c);
extern void delete_every_connection(void);
extern void release_dead_interfaces(void);
extern void check_orientations(void);
extern struct connection *route_owner(struct connection *c
    , struct connection **erop);
extern struct connection *shunt_owner(const ip_subnet *ours
    , const ip_subnet *his);

extern bool uniqueIDs;	/* --uniqueids? */
extern void ISAKMP_SA_established(struct connection *c, so_serial_t serial);

#define his_id_was_instantiated(c) ((c)->kind == CK_INSTANCE \
    && id_is_ipaddr(&(c)->that.id) \
    && sameaddr(&(c)->that.id.ip_addr, &(c)->that.host_addr))

/* for Opportunism */
extern bool HasWildcardClient(const struct connection *c);
extern const ip_subnet *EffectivePeerClient(const struct connection *c);

/* for Aggressive Mode */
#define HasWildcardIP(c) (is_NO_IP((c).that.host_addr))
extern struct connection
    *rw_connection(const struct connection *c, ip_address *him);

struct state;	/* forward declaration of tag (defined in state.h) */
extern struct connection
    *con_by_name(const char *nm, bool strict),
    *find_host_connection(const ip_address *me, u_int16_t my_port
	, const ip_address *him, u_int16_t his_port),
    *refine_host_connection(const struct state *st, const struct id *id
	, bool initiator, bool aggrmode),
    *find_client_connection(struct connection *c
	, const ip_subnet *our_net
	, const ip_subnet *peer_net
	, const u_int8_t our_protocol
	, const u_int16_t out_port
	, const u_int8_t peer_protocol
	, const u_int16_t peer_port);

/* instantiating routines
 * Note: connection_discard() is in state.h because all its work
 * is looking through state objects.
 */
struct gw_info;	/* forward declaration of tag (defined in dnskey.h) */
struct alg_info;	/* forward declaration of tag (defined in alg_info.h) */
extern struct connection
    *rw_instantiate(const struct connection *c, const ip_address *him
#ifdef NAT_TRAVERSAL
	, u_int16_t his_port
#endif
#ifdef VIRTUAL_IP
	, const ip_subnet *his_net
#endif
	, const struct id *his_id),
    *oppo_instantiate(const struct connection *c, const ip_address *him
	, const struct id *his_id, struct gw_info *gw
	, const ip_address *our_client, const ip_address *peer_client),
    *build_outgoing_opportunistic_connection(struct gw_info *gw
	, const ip_address *our_client, const ip_address *peer_client);

#define CONN_INST_BUF	(ADDRTOT_BUF+1 + SUBNETTOT_BUF+1)
extern void fmt_conn_instance(const struct connection *c
    , char buf[CONN_INST_BUF]);

/* operations on "pending", the structure representing Quick Mode
 * negotiations delayed until a Keying Channel has been negotiated.
 */

struct pending;	/* forward declaration (opaque outside connections.c) */

extern void add_pending(int whack_sock
    , struct state *isakmp_sa
    , struct connection *c
    , lset_t policy
    , unsigned long try
    , so_serial_t replacing);

extern void release_pending_whacks(struct state *st, err_t story);
extern void unpend(struct state *st);
extern void update_pending(struct state *os, struct state *ns);
extern void flush_pending_by_state(struct state *st);

extern void connection_discard(struct connection *c);

/* print connection status */

extern void show_connections_status(void);

#ifdef NAT_TRAVERSAL
void
update_host_pair(const char *why, struct connection *c,
	const ip_address *myaddr, u_int16_t myport ,
	const ip_address *hisaddr, u_int16_t hisport);
#endif /* NAT_TRAVERSAL */

#endif
