/* information about connections between hosts and clients
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
 * RCSID $Id: connections.c,v 1.124 2002/03/23 20:15:31 dhr Exp $
 */

#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <arpa/nameser.h>	/* missing from <resolv.h> on old systems */

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "id.h"
#include "x509.h"
#include "connections.h"	/* needs id.h */
#include "packet.h"
#include "demux.h"	/* needs packet.h */
#include "state.h"
#include "timer.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "server.h"
#include "kernel.h"
#include "log.h"
#include "preshared.h"
#include "adns.h"	/* needs <resolv.h> */
#include "dnskey.h"	/* needs preshared.h and adns.h */
#include "whack.h"
#include "alg_info.h"
#include "ike_alg.h"
#include "kernel_alg.h"

#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

#ifdef VIRTUAL_IP
#include "virtual.h"
#endif

static void flush_pending_by_connection(struct connection *c);	/* forward */

static struct connection *connections = NULL;

/* struct host_pair: a nexus of information about a pair of hosts.
 * A host is an IP address, UDP port pair.  This is a debatable choice:
 * - should port be considered (no choice of port in standard)?
 * - should ID be considered (hard because not always known)?
 * - should IP address matter on our end (we don't know our end)?
 * Only oriented connections are registered.
 * Unoriented connections are kept on the unoriented_connections
 * linked list (using hp_next).  For them, host_pair is NULL.
 */

struct host_pair {
    struct {
	ip_address addr;
	u_int16_t port;	/* host order */
    } me, him;
    bool initial_connection_sent;
    struct connection *connections;	/* connections with this pair */
    struct pending *pending;	/* awaiting Keying Channel */
    struct host_pair *next;
};

static struct host_pair *host_pairs = NULL;

static struct connection *unoriented_connections = NULL;

static int oppo_templates = 0;	/* count of opportunistic templates */

/* check to see that Ids of peers match */
bool
same_peer_ids(const struct connection *c, const struct connection *d
, const struct id *his_id)
{
    return same_id(&c->this.id, &d->this.id)
	&& same_id(his_id == NULL? &c->that.id : his_id, &d->that.id);
}

/* update the host pairs with the latest DNS ip address */
/* XXX: I don't like this, it assumes everything in a host pair
 * has the same dnshostname, which isn't a valid assumption,
 * even though it will nearly always be true. */
static bool
update_host_pairs(void)
{
    struct host_pair *p;
    struct connection *c;
    ip_address new_addr;
    
    for (p = host_pairs; p != NULL; p = p->next)
    {
	c = p->connections;
	if (c == NULL
	|| c->dnshostname == NULL
	|| ttoaddr(c->dnshostname, 0, c->addr_family, &new_addr) != NULL
	|| sameaddr(&new_addr, &p->him.addr))
	    continue;

	for (; c != NULL; c = c->hp_next)
	{
	    c->that.host_addr = new_addr;
	    state_rehash(c);
	}

	p->him.addr = new_addr;
    }	 
}	
	

struct connection *
find_host_connection_mode(const ip_address *myaddr, u_int16_t myport
, const ip_address *hisaddr, u_int16_t hisport, bool main)
{
    struct host_pair *p, *prev;
    struct connection *c;
    
    /* update the host pairs with the latest DNS ip address */
    update_host_pairs();
    
    /* default hisaddr to an appropriate any */
    if (hisaddr == NULL)
	hisaddr = aftoinfo(addrtypeof(myaddr))->any;

    for (prev = NULL, p = host_pairs; p != NULL; prev = p, p = p->next)
    {
	if (sameaddr(&p->me.addr, myaddr) && p->me.port == myport
		&& sameaddr(&p->him.addr, hisaddr) 
#ifdef DO_NOT_ACCEPT_IKE_FROM_DIFFERENT_SOURCE_PORT 
		&& (p->him.port == hisport)
#endif
	   )
	{
	    for (c = p->connections; c != NULL; c = c->hp_next)
	    {
		if(c->kind != CK_TEMPLATE && c->kind != CK_PERMANENT)
		    continue;	
			
		if (main) { 
			if(!LALLIN(c->policy, POLICY_AGGRESSIVE))
			{
			    if (prev != NULL )
			    {
				prev->next = p->next;	/* remove p from list */
				p->next = host_pairs;	/* and stick it on front */
				host_pairs = p;
			    }
			    return c;
			}
		} else {
			if (LALLIN(c->policy, POLICY_AGGRESSIVE))	{
			    if (prev != NULL )
			    {
				prev->next = p->next;	/* remove p from list */
				p->next = host_pairs;	/* and stick it on front */
				host_pairs = p;
			    }
			    return c;
			}
		
		}
	    }
	}
    }
    
    return NULL;
}


static struct host_pair *
find_host_pair(const ip_address *myaddr, u_int16_t myport
, const ip_address *hisaddr, u_int16_t hisport)
{
    struct host_pair *p, *prev;

    /* default hisaddr to an appropriate any */
    if (hisaddr == NULL)
	hisaddr = aftoinfo(addrtypeof(myaddr))->any;

#ifdef NAT_TRAVERSAL
    if (nat_traversal_enabled) {
	/**
	 * port is not relevant in host_pair. with nat_traversal we
	 * always use pluto_port (500)
	 */
	myport = pluto_port;
	hisport = pluto_port;
    }
#endif

    for (prev = NULL, p = host_pairs; p != NULL; prev = p, p = p->next)
    {
	if (sameaddr(&p->me.addr, myaddr) && p->me.port == myport
	&& sameaddr(&p->him.addr, hisaddr) && p->him.port == hisport)
	{
	    if (prev != NULL)
	    {
		prev->next = p->next;	/* remove p from list */
		p->next = host_pairs;	/* and stick it on front */
		host_pairs = p;
	    }
	    break;
	}
    }
    return p;
}

/* find head of list of connections with this pair of hosts */
static struct connection *
find_host_pair_connections(const ip_address *myaddr, u_int16_t myport
, const ip_address *hisaddr, u_int16_t hisport)
{
    struct host_pair *hp = find_host_pair(myaddr, myport, hisaddr, hisport);

#ifdef NAT_TRAVERSAL
    if (nat_traversal_enabled && hp && hisaddr) {
	struct connection *c;
	for (c = hp->connections; c != NULL; c = c->hp_next) {
	    if ((c->this.host_port==myport) && (c->that.host_port==hisport))
		return c;
	}
	return NULL;
    }
#endif

    return hp == NULL? NULL : hp->connections;
}

static void
connect_to_host_pair(struct connection *c)
{
    if (oriented(*c))
    {
	struct host_pair *hp = find_host_pair(&c->this.host_addr, c->this.host_port
	    , &c->that.host_addr, c->that.host_port);

	if (hp == NULL)
	{
	    /* no suitable host_pair -- build one */
	    hp = alloc_thing(struct host_pair, "host_pair");
	    hp->me.addr = c->this.host_addr;
	    hp->him.addr = c->that.host_addr;
#ifdef NAT_TRAVERSAL
	    hp->me.port = nat_traversal_enabled ? pluto_port : c->this.host_port;
	    hp->him.port = nat_traversal_enabled ? pluto_port : c->that.host_port;
#else
	    hp->me.port = c->this.host_port;
	    hp->him.port = c->that.host_port;
#endif
	    hp->initial_connection_sent = FALSE;
	    hp->connections = NULL;
	    hp->pending = NULL;
	    hp->next = host_pairs;
	    host_pairs = hp;
	}
	c->host_pair = hp;
	c->hp_next = hp->connections;
	hp->connections = c;
    }
    else
    {
	/* since this connection isn't oriented, we place it
	 * in the unoriented_connections list instead.
	 */
	c->host_pair = NULL;
	c->hp_next = unoriented_connections;
	unoriented_connections = c;
    }
}

/* find a connection by name.
 * If strict, don't accept a CK_INSTANCE.
 * Move the winner (if any) to the front.
 * If none is found, and strict, a diagnostic is logged to whack.
 */
struct connection *
con_by_name(const char *nm, bool strict)
{
    struct connection *p, *prev;

    for (prev = NULL, p = connections; ; prev = p, p = p->ac_next)
    {
	if (p == NULL)
	{
	    if (strict)
		whack_log(RC_UNKNOWN_NAME
		    , "no connection named \"%s\"", nm);
	    break;
	}
	if (streq(p->name, nm)
	&& (!strict || p->kind != CK_INSTANCE))
	{
	    if (prev != NULL)
	    {
		prev->ac_next = p->ac_next;	/* remove p from list */
		p->ac_next = connections;	/* and stick it on front */
		connections = p;
	    }
	    break;
	}
    }
    return p;
}

void
release_connection(struct connection *c)
{
    if (c->kind == CK_INSTANCE)
    {
	/* This does everything we need.
	 * Note that we will be called recursively by delete_connection,
	 * but kind will be CK_GOING_AWAY.
	 */
	delete_connection(c);
    }
    else
    {
	flush_pending_by_connection(c);
	delete_states_by_connection(c);
	unroute_connection(c);
    }
}

/* Delete a connection */

#define list_rm(etype, enext, e, ehead) { \
	etype **ep; \
	for (ep = &(ehead); *ep != (e); ep = &(*ep)->enext) \
	    passert(*ep != NULL);    /* we must not come up empty-handed */ \
	*ep = (e)->enext; \
    }


void
delete_connection(struct connection *c)
{
    struct connection *old_cur_connection
	= cur_connection == c? NULL : cur_connection;
#ifdef DEBUG
    unsigned int old_cur_debugging = cur_debugging;
#endif

    set_cur_connection(c);

    /* Must be careful to avoid circularity:
     * we mark c as going away so it won't get deleted recursively.
     */
    passert(c->kind != CK_GOING_AWAY);
    if (c->kind == CK_INSTANCE)
    {
	log("deleting connection \"%s\" instance with peer %s"
	    , c->name, ip_str(&c->that.host_addr));
	c->kind = CK_GOING_AWAY;
    }
    else
    {
	log("deleting connection");
    }
    release_connection(c);	/* won't delete c */

    /* find and delete c from connections list */
    list_rm(struct connection, ac_next, c, connections);
    cur_connection = old_cur_connection;

    /* find and delete c from the host pair list */
    if (c->host_pair == NULL)
    {
	list_rm(struct connection, hp_next, c, unoriented_connections);
    }
    else
    {
	struct host_pair *hp = c->host_pair;

	list_rm(struct connection, hp_next, c, hp->connections);
	c->host_pair = NULL;	/* redundant, but safe */

	/* if there are no more connections with this host_pair
	 * and we haven't even made an initial contact, let's delete
	 * this guy in case we were created by an attempted DOS attack.
	 */
	if (hp->connections == NULL
	&& !hp->initial_connection_sent)
	{
	    passert(hp->pending == NULL);	/* ??? must deal with this! */
	    list_rm(struct host_pair, next, hp, host_pairs);
	    pfree(hp);
	}
    }

#ifdef VIRTUAL_IP
    if (c->kind != CK_GOING_AWAY) pfreeany(c->that.virt);
#endif

    if (c->kind == CK_TEMPLATE && (c->policy & POLICY_OPPO))
	oppo_templates--;

#ifdef DEBUG
    cur_debugging = old_cur_debugging;
#endif
    pfreeany(c->name);
    pfreeany(c->dnshostname);
    free_id_content(&c->this.id);
    pfreeany(c->this.updown);
    release_x509cert(c->this.cert);
    free_id_content(&c->that.id);
    release_x509cert(c->that.cert);
    pfreeany(c->that.updown);
    gw_delref(&c->gw_info);
#ifndef NO_KERNEL_ALG
    alg_info_delref((struct alg_info **)&c->alg_info_esp);
#endif
#ifndef NO_IKE_ALG
    alg_info_delref((struct alg_info **)&c->alg_info_ike);
#endif
    pfree(c);
}

void
delete_every_connection(void)
{
    while (connections != NULL)
	delete_connection(connections);
}

void
release_dead_interfaces(void)
{
    struct host_pair *hp;

    for (hp = host_pairs; hp != NULL; hp = hp->next)
    {
	struct connection **pp
	    , *p;

	for (pp = &hp->connections; (p = *pp) != NULL; )
	{
	    if (p->interface->change == IFN_DELETE)
	    {
		/* this connection's interface is going away */
		enum connection_kind k = p->kind;

		release_connection(p);

		if (k == CK_PERMANENT || k == CK_TEMPLATE)
		{
		    /* The connection should have survived release:
		     * move it to the unoriented_connections list.
		     */
		    passert(p == *pp);

		    p->interface = NULL;

		    *pp = p->hp_next;	/* advance *pp */
		    p->host_pair = NULL;
		    p->hp_next = unoriented_connections;
		    unoriented_connections = p;
		}
		else
		{
		    /* The connection should have vanished,
		     * but the previous connection remains.
		     */
		    passert(p != *pp);
		}
	    }
	    else
	    {
		pp = &p->hp_next;	/* advance pp */
	    }
	}
    }
}

/* adjust orientations of connections to reflect newly added interfaces */
void
check_orientations(void)
{
    /* try to orient all the unoriented connections */
    {
	struct connection *c = unoriented_connections;

	unoriented_connections = NULL;

	while (c != NULL)
	{
	    struct connection *nxt = c->hp_next;

	    (void)orient(c);
	    connect_to_host_pair(c);
	    c = nxt;
	}
    }

    /* Check that no oriented connection has become double-oriented.
     * In other words, the far side must not match one of our new interfaces.
     */
    {
	struct iface *i;

	for (i = interfaces; i != NULL; i = i->next)
	{
	    if (i->change == IFN_ADD)
	    {
		struct host_pair *hp;

		for (hp = host_pairs; hp != NULL; hp = hp->next)
		{
		    if (sameaddr(&hp->him.addr, &i->addr)
		    && (!no_klips || hp->him.port == pluto_port))
		    {
			/* bad news: the whole chain of connections
			 * hanging off this host pair has both sides
			 * matching an interface.
			 * We'll get rid of them, using orient and
			 * connect_to_host_pair.  But we'll be lazy
			 * and not ditch the host_pair itself (the
			 * cost of leaving it is slight and cannot
			 * be induced by a foe).
			 */
			struct connection *c = hp->connections;

			hp->connections = NULL;
			while (c != NULL)
			{
			    struct connection *nxt = c->hp_next;

			    c->interface = NULL;
			    (void)orient(c);
			    connect_to_host_pair(c);
			    c = nxt;
			}
		    }
		}
	    }
	}
    }
}

static err_t
default_end(struct end *e, ip_address *dflt_nexthop)
{
    err_t ugh = NULL;
    const struct af_info *afi = aftoinfo(addrtypeof(&e->host_addr));

    if (afi == NULL)
	return "unknown address family in default_end";

    /* default ID to IP (but only if not NO_IP -- WildCard) */
    if (e->id.kind == ID_NONE && !isanyaddr(&e->host_addr))
    {
	e->id.kind = afi->id_addr;
	e->id.ip_addr = e->host_addr;
    }

    /* default nexthop to other side */
    if (isanyaddr(&e->host_nexthop))
	e->host_nexthop = *dflt_nexthop;

    /* default client to subnet containing only self
     * XXX This may mean that the client's address family doesn't match
     * tunnel_addr_family.
     */
    if (!e->has_client)
	ugh = initsubnet(&e->host_addr, afi->mask_cnt, '0', &e->client);

    return ugh;
}

/* format the topology of an end, leaving out defaults
 * Note: if that==NULL, skip nexthop
 */
size_t
format_end(char *buf, size_t buf_len
, const struct end *this, const struct end *that, bool is_left)
{
    char client[SUBNETTOT_BUF];
    const char *client_sep = "";
    char protoport[sizeof(":255/65535")];
    char host[ADDRTOT_BUF];
    char host_port[sizeof(":65535")];
    char host_id[IDTOA_BUF + 2];
    char hop[ADDRTOT_BUF];
    const char *hop_sep = "";
    const char *open_brackets  = "";
    const char *close_brackets = "";
    ip_address net;

    client[0] = '\0';

#ifdef VIRTUAL_IP
    if (is_virtual_end(this) && isanyaddr(&this->host_addr)) {
	snprintf(host, sizeof(host), "%%virtual");
    }
    else
#endif
    if (isanyaddr(&this->host_addr)
    && this->has_client
    && subnetishost(&this->client)
    && (networkof(&this->client, &net), isanyaddr(&net)))
    {
	/* %opportunistic subsumes client and host */
	snprintf(host, sizeof(host), "%%opportunistic");
    }
    else
    {
	/* [client===] */
	if (this->has_client)
	{
	    subnettot(&this->client, 0, client, sizeof(client));
	    client_sep = "===";
	}

	/* {client_subnet_wildcard} */
	if (this->has_client_wildcard)
	{
	    open_brackets  = "{";
	    close_brackets = "}";
	}

	/* host */
	if (isanyaddr(&this->host_addr))
	    snprintf(host, sizeof(host), "%%any");
	else
	    addrtot(&this->host_addr, 0, host, sizeof(host));
    }
    host_port[0] = '\0';
    if (this->host_port != IKE_UDP_PORT)
	snprintf(host_port, sizeof(host_port), ":%u"
	    , this->host_port);

    /* payload portocol and port */
    protoport[0] = '\0';
    if (this->port || this->protocol)
	snprintf(protoport, sizeof(protoport), ":%u/%u",
	    this->protocol, this->port);

    /* id, if different from host */
    host_id[0] = '\0';
    if (!(this->id.kind == ID_NONE
    || (id_is_ipaddr(&this->id) && sameaddr(&this->id.ip_addr, &this->host_addr))))
    {
	int len = idtoa(&this->id, host_id+1, sizeof(host_id)-2);

	host_id[0] = '[';
	strcpy(&host_id[len < 0? (ptrdiff_t)sizeof(host_id)-2 : 1 + len], "]");
    }

    /* [---hop] */
    hop[0] = '\0';
    hop_sep = "";
    if (that != NULL && !sameaddr(&this->host_nexthop, &that->host_addr))
    {
	addrtot(&this->host_nexthop, 0, hop, sizeof(hop));
	hop_sep = "---";
    }

    if (is_left)
	snprintf(buf, buf_len, "%s%s%s%s%s%s%s%s%s%s"
	    , open_brackets, client, close_brackets
	    , client_sep, host, host_port, host_id
	    , protoport, hop_sep, hop);
    else
	snprintf(buf, buf_len, "%s%s%s%s%s%s%s%s%s%s"
	    , hop, hop_sep, host, host_port, host_id
	    , protoport, client_sep
	    , open_brackets, client, close_brackets);
    return strlen(buf);
}

static void
unshare_connection_strings(struct connection *c)
{
    c->name = clone_str(c->name, "connection name");
    c->dnshostname = clone_str(c->dnshostname, "connection dnshostname");

    unshare_id_content(&c->this.id);
    c->this.updown = clone_str(c->this.updown, "updown");
    share_x509cert(c->this.cert);
    unshare_id_content(&c->that.id);
    c->that.updown = clone_str(c->that.updown, "updown");
    share_x509cert(c->that.cert);
}

static void
extract_end(struct end *dst, const struct whack_end *src, const char *which)
{
    /* decode id, if any */
    if (src->id == NULL)
    {
	dst->id.kind = ID_NONE;
    }
    else
    {
	err_t ugh = atoid(src->id, &dst->id);

	if (ugh != NULL)
	{
	    loglog(RC_BADID, "bad %s --id: %s (ignored)", which, ugh);
	    dst->id = empty_id;	/* ignore bad one */
	}
    }

    dst->cert = NULL;

    /* load local X.509 certificate, if any */
    if (src->cert != NULL)
    {
	x509cert_t *cert = load_host_cert(src->cert);

	if (cert != NULL)
	{
	    bool copy_subject_dn = TRUE;  /* ID is subject DN */

	    if (dst->id.kind != ID_NONE) /* check for matching subjectAltName */
	    {
		generalName_t *gn = cert->subjectAltName;

		 while (gn != NULL)
		{
		    struct id id = empty_id;

		    gntoid(&id, gn);
		    if (same_id(&id, &dst->id))
		    {
			copy_subject_dn = FALSE; /* take subjectAltName instead */
			break;
		    }
		    gn = gn->next;
		}
	    }
	    if (copy_subject_dn)
	    {
		if (dst->id.kind != ID_NONE && dst->id.kind != ID_DER_ASN1_DN)
		{
		     char buf[IDTOA_BUF];

		     idtoa(&dst->id, buf, IDTOA_BUF);
		     log("  no subjectAltName matches ID '%s', replaced by subject DN", buf);
		}
		dst->id.kind = ID_DER_ASN1_DN;
		dst->id.name.len = cert->subject.len;
		dst->id.name.ptr = temporary_cyclic_buffer();
		memcpy(dst->id.name.ptr, cert->subject.ptr, cert->subject.len);
	    }
	    if (check_validity(cert))
	    {
		add_x509_public_key(cert, DAL_LOCAL);
		dst->cert = add_x509cert(cert);
	    }
	    else
	    {
			time_t current_time;
			time(&current_time);
			log("  current time: %s", timetoa(&current_time, TRUE));
			log("  host certificate is invalid");
			free_x509cert(cert);
	    }
	}
    }

    /* the rest is simple copying of corresponding fields */
    dst->host_addr = src->host_addr;
    dst->host_nexthop = src->host_nexthop;
    dst->client = src->client;
    dst->port = src->port;
    dst->protocol = src->protocol;

    dst->has_client = src->has_client;
    dst->has_client_wildcard = src->has_client_wildcard;
    dst->updown = src->updown;
    dst->host_port = src->host_port;
}

static bool
check_connection_end(const struct whack_end *this, const struct whack_end *that
, const struct whack_message *wm)
{
    if (wm->addr_family != addrtypeof(&this->host_addr)
    || wm->addr_family != addrtypeof(&this->host_nexthop)
    || (this->has_client? wm->tunnel_addr_family : wm->addr_family)
      != subnettypeof(&this->client)
    || subnettypeof(&this->client) != subnettypeof(&that->client))
    {
	/* this should have been diagnosed by whack, so we need not be clear
	 * !!! overloaded use of RC_CLASH
	 */
	loglog(RC_CLASH, "address family inconsistency in connection");
	return FALSE;
    }

    if (isanyaddr(&that->host_addr))
    {
	/* other side is wildcard: we must check if other conditions met */
	if (isanyaddr(&this->host_addr))
	{
	    loglog(RC_ORIENT, "connection must specify host IP address for our side");
	    return FALSE;
	}
	else if ((wm->policy & POLICY_AGGRESSIVE) == 0)
	{
	    /* check that all main mode RW IKE policies agree because we must 
	     * implement them before the correct connection is known.
	     * We cannot enforce this for other non-RW connections because
	     * differentiation is possible when a command specifies which
	     * to initiate.
	     * aggressive mode IKE policies do not have to agree amongst
 	     * themselves as the ID is known from the outset.
	     */
	    const struct connection *c = NULL;

	    c = find_host_pair_connections(&this->host_addr
		, this->host_port, (const ip_address *)NULL, that->host_port);

	    for (; c != NULL; c = c->hp_next)
	    {
	    	if (c->policy & POLICY_AGGRESSIVE)
 		    continue;
		if ((c->policy ^ wm->policy) & (POLICY_PSK | POLICY_RSASIG))
		{
		    loglog(RC_CLASH
			, "authentication method disagrees with \"%s\", which is also for an unspecified peer"
			, c->name);
		    return FALSE;
		}
	    }
	}
    }
#ifdef VIRTUAL_IP
    if ((this->virt) && (!isanyaddr(&this->host_addr) || this->has_client)) {
	loglog(RC_CLASH,
	    "virtual IP must only be used with %%any and without client");
	return FALSE;
    }
#endif
    return TRUE;	/* happy */
}

void
add_connection(const struct whack_message *wm)
{
    if (con_by_name(wm->name, FALSE) != NULL)
    {
	loglog(RC_DUPNAME, "attempt to redefine connection \"%s\"", wm->name);
    }
    else if ((wm->policy & POLICY_ID_AUTH_MASK) == LEMPTY)
    {
	/* this should have been diagnosed by whack, so we need not be clear
	 * !!! overloaded use of RC_CLASH
	 */
	loglog(RC_CLASH, "must specify --rsasig or --psk for a connection");
    }
    else if (wm->right.protocol != wm->left.protocol)
    {
	/* this should haven been diagnosed by whack
	 * !!! overloaded use of RC_CLASH
	 */
	loglog(RC_CLASH, "the protocol must be the same for leftport and rightport");
    }
    else if (check_connection_end(&wm->right, &wm->left, wm)
    && check_connection_end(&wm->left, &wm->right, wm))
    {
	struct connection *c = alloc_thing(struct connection, "struct connection");

	c->name = wm->name;
	c->dnshostname = wm->dnshostname;

	c->policy = wm->policy;

	if ((c->policy & POLICY_COMPRESS) && !can_do_IPcomp)
	    loglog(RC_COMMENT
		, "ignoring --compress in \"%s\" because KLIPS is not configured to do IPCOMP"
		, c->name);

#ifndef NO_KERNEL_ALG
	/* if (wm->esp)  */
	{
		const char *ugh;
		DBG_log("from whack: got --esp=%s", wm->esp ? wm->esp: "NULL");
		c->alg_info_esp= alg_info_esp_create_from_str(wm->esp? wm->esp : "", &ugh);
		DBG(DBG_CRYPT|DBG_CONTROL, 
			static char buf[256]="<NULL>";
			if (c->alg_info_esp)
				alg_info_snprint(buf, sizeof(buf), 
					(struct alg_info *)c->alg_info_esp);
			DBG_log("esp string values: %s", buf);
		);
		if (c->alg_info_esp) {
			if (c->alg_info_esp->alg_info_cnt==0) {
				loglog(RC_LOG_SERIOUS
					, "got 0 transforms for esp=\"%s\""
					, wm->esp);
			}
		} else {
			loglog(RC_LOG_SERIOUS
				, "esp string error: %s"
				, ugh? ugh : "Unknown");
		}
	}
#endif	
#ifndef NO_IKE_ALG
	/* if (wm->ike) */
	{
		const char *ugh;
		DBG_log("from whack: got --ike=%s", wm->ike ? wm->ike: "NULL");
		c->alg_info_ike= alg_info_ike_create_from_str(wm->ike? wm->ike : "", &ugh);
		DBG(DBG_CRYPT|DBG_CONTROL, 
				static char buf[256]="<NULL>";
				if (c->alg_info_ike)
					alg_info_snprint(buf, sizeof(buf),
						(struct alg_info *)c->alg_info_ike);
				DBG_log("ike string values: %s", buf);
				);
		if (c->alg_info_ike) {
			if (c->alg_info_ike->alg_info_cnt==0) {
				loglog(RC_LOG_SERIOUS
					, "got 0 transforms for ike=\"%s\""
					, wm->ike);
			}
		} else {
			loglog(RC_LOG_SERIOUS
				, "ike string error: %s"
				, ugh? ugh : "Unknown");
		}
	}
#endif
	c->sa_ike_life_seconds = wm->sa_ike_life_seconds;
	c->sa_ipsec_life_seconds = wm->sa_ipsec_life_seconds;
	c->sa_rekey_margin = wm->sa_rekey_margin;
	c->sa_rekey_fuzz = wm->sa_rekey_fuzz;
	c->sa_keying_tries = wm->sa_keying_tries;
	c->retransmit_trigger = wm->retransmit_trigger;
	c->dpd_delay = wm->dpd_delay;
	c->dpd_timeout = wm->dpd_timeout;
	c->algorithm_p1.cipher = wm->cipher_p1;
	c->algorithm_p1.dhg = wm->dhg_p1;
	c->algorithm_p1.hash = wm->hash_p1;
	c->addr_family = wm->addr_family;
	c->tunnel_addr_family = wm->tunnel_addr_family;

	extract_end(&c->this, &wm->left, "left");
	extract_end(&c->that, &wm->right, "right");

	default_end(&c->this, &c->that.host_addr);
	default_end(&c->that, &c->this.host_addr);

	/* force any wildcard host IP address to that end */
	if (isanyaddr(&c->this.host_addr) || c->this.has_client_wildcard)
	{
	    struct end t = c->this;

	    DBG(DBG_CONTROL, DBG_log("add_connection - 1"));
	    c->this = c->that;
	    c->that = t;
	}

	/* set internal fields */
	c->initiated = FALSE;
	c->ac_next = connections;
	connections = c;
	c->interface = NULL;
	c->routing = RT_UNROUTED;
	c->newest_isakmp_sa = SOS_NOBODY;
	c->newest_ipsec_sa = SOS_NOBODY;
	c->eroute_owner = SOS_NOBODY;

	c->kind = (isanyaddr(&c->that.host_addr) || c->that.has_client_wildcard) ?
			CK_TEMPLATE : CK_PERMANENT;

#ifdef DEBUG
	c->extra_debugging = wm->debugging;
#endif

	c->gw_info = NULL;

#ifdef VIRTUAL_IP
	passert(!(wm->left.virt && wm->right.virt));
	if (wm->left.virt || wm->right.virt) {
	    passert(isanyaddr(&c->that.host_addr));
	    c->that.virt = create_virtual(c,
		wm->left.virt ? wm->left.virt : wm->right.virt);
	    if (c->that.virt)
		c->that.has_client = TRUE;
	}
#endif

	unshare_connection_strings(c);
#ifndef NO_KERNEL_ALG
	alg_info_addref((struct alg_info *)c->alg_info_esp);
#endif
#ifndef NO_IKE_ALG
	alg_info_addref((struct alg_info *)c->alg_info_ike);
#endif

	(void)orient(c);
	connect_to_host_pair(c);

	if (c->kind == CK_TEMPLATE && (c->policy & POLICY_OPPO))
	    oppo_templates++;

	/* log all about this connection */
	log("added connection description \"%s\"", c->name);
	DBG(DBG_CONTROL,
	    char lhs[SUBNETTOT_BUF + ADDRTOT_BUF + IDTOA_BUF + ADDRTOT_BUF];
	    char rhs[SUBNETTOT_BUF + ADDRTOT_BUF + IDTOA_BUF + ADDRTOT_BUF];

	    (void) format_end(lhs, sizeof(lhs), &c->this, &c->that, TRUE);
	    (void) format_end(rhs, sizeof(rhs), &c->that, &c->this, FALSE);

	    DBG_log("%s...%s", lhs, rhs);

	    /* Make sure that address families can be correctly inferred
	     * from printed ends.
	     */
	    passert(c->addr_family == addrtypeof(&c->this.host_addr)
		&& c->addr_family == addrtypeof(&c->this.host_nexthop)
		&& (c->this.has_client? c->tunnel_addr_family : c->addr_family)
		  == subnettypeof(&c->this.client)

		&& c->addr_family == addrtypeof(&c->that.host_addr)
		&& c->addr_family == addrtypeof(&c->that.host_nexthop)
		&& (c->that.has_client? c->tunnel_addr_family : c->addr_family)
		  == subnettypeof(&c->that.client));

	    DBG_log("ike_life: %lus; ipsec_life: %lus; rekey_margin: %lus;"
		" rekey_fuzz: %lu%%; keyingtries: %lu; policy: %s"
		, (unsigned long) c->sa_ike_life_seconds
		, (unsigned long) c->sa_ipsec_life_seconds
		, (unsigned long) c->sa_rekey_margin
		, (unsigned long) c->sa_rekey_fuzz
		, (unsigned long) c->sa_keying_tries
		, bitnamesof(sa_policy_bit_names, c->policy));
	);
    }
}

/* Common part of instantiating a Road Warrior or Opportunistic connection.
 * his_id can be used to carry over an ID discovered in Phase 1.
 * It must not disagree with the one in c, but if that is unspecified,
 * the new connection will use his_id.
 * If his_id is NULL, and c.that.id is uninstantiated (ID_NONE), the
 * new connection will continue to have an uninstantiated that.id.
 * Note: instantiation does not affect port numbers.
 */
static struct connection *
instantiate(const struct connection *c, const ip_address *him
#ifdef NAT_TRAVERSAL
, u_int16_t his_port
#endif
, const struct id *his_id)
{
    struct connection *d = clone_thing(*c, "temporary connection");

    passert(c->kind == CK_TEMPLATE);
    if (his_id != NULL)
    {
	passert(d->that.id.kind == ID_NONE || same_id(&d->that.id, his_id));
	d->that.id = *his_id;
    }
    unshare_connection_strings(d);
#ifndef NO_KERNEL_ALG
    alg_info_addref((struct alg_info *)d->alg_info_esp);
#endif
#ifndef NO_IKE_ALG
    alg_info_addref((struct alg_info *)d->alg_info_ike);
#endif

    d->kind = CK_INSTANCE;

    passert(oriented(*d));
    d->that.host_addr = *him;
#ifdef NAT_TRAVERSAL
    if (his_port) d->that.host_port = his_port;
#endif
    default_end(&d->that, &d->this.host_addr);

    /* We cannot guess what our next_hop should be, but if it was
     * explicitly specified as 0.0.0.0, we set it to be him.
     * (whack will not allow nexthop to be elided in RW case.)
     */
    default_end(&d->this, &d->that.host_addr);

    /* set internal fields */
    d->ac_next = connections;
    connections = d;
    d->routing = RT_UNROUTED;
    d->newest_isakmp_sa = SOS_NOBODY;
    d->newest_ipsec_sa = SOS_NOBODY;
    d->eroute_owner = SOS_NOBODY;

    connect_to_host_pair(d);

    return d;
}

struct connection *
rw_instantiate(const struct connection *c
, const ip_address *him
#ifdef NAT_TRAVERSAL
, u_int16_t his_port
#endif
#ifdef VIRTUAL_IP
, const ip_subnet *his_net
#endif
, const struct id *his_id)
{
#ifdef NAT_TRAVERSAL
    struct connection *d = instantiate(c, him, his_port, his_id);
#else
    struct connection *d = instantiate(c, him, his_id);
#endif

#ifdef VIRTUAL_IP
    if (d && his_net && is_virtual_connection(c)) {
	d->that.client = *his_net;
	d->that.virt = NULL;
	if (subnetishost(his_net) && addrinsubnet(him, his_net))
	    d->that.has_client = FALSE;
    }
#endif

    DBG(DBG_CONTROL
	, DBG_log("instantiated \"%s\" for %s" , d->name, ip_str(him)));
    return d;
}

struct connection *
oppo_instantiate(const struct connection *c
, const ip_address *him
, const struct id *his_id
, struct gw_info *gw
, const ip_address *our_client USED_BY_DEBUG
, const ip_address *peer_client)
{
#ifdef NAT_TRAVERSAL
    struct connection *d = instantiate(c, him, 0, his_id);
#else
    struct connection *d = instantiate(c, him, his_id);
#endif

    /* fill in our client side */
    if (d->this.has_client)
    {
	/* there was a client in the abstract connection
	 * so we demand that the required client is within that subnet.
	 */
	passert(addrinsubnet(our_client, &d->this.client));
	happy(addrtosubnet(our_client, &d->this.client));
    }
    else
    {
	/* there was no client in the abstract connection
	 * so we demand that the required client be the host
	 */
	passert(sameaddr(our_client, &d->this.host_addr));
    }

    /* fill in peer's client side.
     * If the client is the peer, excise the client from the connection.
     */
    passert((d->policy & POLICY_OPPO) && HasWildcardClient(d));
    happy(addrtosubnet(peer_client, &d->that.client));

    if (sameaddr(peer_client, &d->that.host_addr))
	d->that.has_client = FALSE;

    passert(d->gw_info == NULL);
    gw_addref(gw);
    d->gw_info = gw;

    DBG(DBG_CONTROL,
	char lhs[SUBNETTOT_BUF + ADDRTOT_BUF + IDTOA_BUF + ADDRTOT_BUF];
	char rhs[SUBNETTOT_BUF + ADDRTOT_BUF + IDTOA_BUF + ADDRTOT_BUF];

	(void) format_end(lhs, sizeof(lhs), &d->this, &d->that, TRUE);
	(void) format_end(rhs, sizeof(rhs), &d->that, &d->this, FALSE);

	DBG_log("instantiated \"%s\": %s...%s", d->name, lhs, rhs);
    );
    return d;
}

/* Format any information needed to identify an instance of a connection.
 * Fills any needed information into buf which MUST be big enough.
 */
void
fmt_conn_instance(const struct connection *c, char buf[CONN_INST_BUF])
{
    buf[0] = '\0';
    if (c->kind == CK_INSTANCE)
    {
	buf[0] = ' ';
	addrtot(&c->that.host_addr, 0, buf+1, ADDRTOT_BUF);
#ifdef NAT_TRAVERSAL
	if (c->that.host_port != pluto_port) {
	    size_t u = strlen(buf);

	    sprintf(buf+u, ":%d", c->that.host_port);
	}
#endif
	if (c->policy & POLICY_OPPO)
	{
	    size_t u = strlen(buf);

	    buf[u++] = ' ';
	    subnettot(&c->that.client, 0, buf+u, SUBNETTOT_BUF);
	}
    }
}

/* Find an existing connection for a trapped outbound packet.
 * This is attempted before we bother with gateway discovery.
 *   + this connection is routed (i.e. approved for on-demand)
 *   + this subnet contains our_client (or we are our_client)
 *   + that subnet contains peer_client (or peer is peer_client)
 *   + don't care about Phase 1 IDs (we don't know)
 *   + require that the connection HAS_IPSEC_POLICY (duh: to serve clients)
 * Give preference to the first one that has an SA (either phase).
 * Otherwise, give preference to one with highest routing.
 */
static struct connection *
find_connection_for_clients(const ip_address *our_client, const ip_address *peer_client)
{
    struct connection *c = connections
	, *best = NULL;

    passert(!isanyaddr(our_client) && !isanyaddr(peer_client));

    for (c = connections; c != NULL; c = c->ac_next)
    {
	if (HAS_IPSEC_POLICY(c->policy)
	&& routed(c->routing)
	&& addrinsubnet(our_client, &c->this.client)
	&& addrinsubnet(peer_client, &c->that.client))
	{
	    if ((best == NULL || best->routing <= c->routing))
		best = c;
	    if (c->newest_isakmp_sa != SOS_NOBODY
	    || c->newest_ipsec_sa != SOS_NOBODY)
		return c;
	}
    }
    return best;
}

/* Find and instantiate a connection for an outgoing Opportunistic connection.
 * We've already discovered its gateway.
 * We look for a the connection such that:
 *   + this is one of our interfaces
 *   + this subnet contains our_client (or we are our_client)
 *     (we will specialize the client).  We prefer the smallest such subnet.
 *   + is opportunistic
 *   + that peer is NO_IP
 *   + don't care about Phase 1 IDs (probably should be default)
 * We could look for a connection that already had the desired peer
 * (rather than NO_IP) specified, but it doesn't seem worth the
 * bother.
 */
struct connection *
build_outgoing_opportunistic_connection(struct gw_info *gw
, const ip_address *our_client, const ip_address *peer_client)
{
    struct iface *p;
    struct connection *best = NULL;

    passert(!isanyaddr(our_client) && !isanyaddr(peer_client));

    /* We don't know his ID yet, so gw id must be an ipaddr */
    passert(id_is_ipaddr(&gw->gw_id));

    /* for each of our addresses... */
    for (p = interfaces; p != NULL; p = p->next)
    {
	/* go through those connections with our address and NO_IP as hosts
	 * We cannot know what port the peer would use, so we assume
	 * that it is pluto_port (makes debugging easier).
	 */
	struct connection *c = find_host_pair_connections(&p->addr
	    , pluto_port, (ip_address *)NULL, pluto_port);

	for (; c != NULL; c = c->hp_next)
	    if (c->kind == CK_TEMPLATE
	    && addrinsubnet(our_client, &c->this.client)
	    && (c->policy & POLICY_OPPO)
	    && HAS_IPSEC_POLICY(c->policy)
	    && (best == NULL || !subnetinsubnet(&best->this.client, &c->this.client)))
		best = c;
    }
    return best == NULL? NULL
	: oppo_instantiate(best, &gw->gw_id.ip_addr, NULL, gw
	    , our_client, peer_client);
}


bool
orient(struct connection *c)
{
    if (!oriented(*c))
    {
	struct iface *p;

	/* Note: this loop does not stop when it finds a match:
	 * it continues checking to catch any ambiguity.
	 */
	for (p = interfaces; p != NULL; p = p->next)
	{
#ifdef NAT_TRAVERSAL
	    if (p->ike_float) continue;
#endif
	    for (;;)
	    {
		/* check if this interface matches this end */
		if (sameaddr(&c->this.host_addr, &p->addr)
		&& (!no_klips || c->this.host_port == pluto_port))
		{
		    if (oriented(*c))
		    {
			if (c->interface == p)
			    loglog(RC_LOG_SERIOUS
				, "both sides of \"%s\" are our interface %s!"
				, c->name, p->rname);
			else
			    loglog(RC_LOG_SERIOUS, "two interfaces match \"%s\" (%s, %s)"
				, c->name, c->interface->rname, p->rname);
			c->interface = NULL;	/* withdraw orientation */
			return FALSE;
		    }
		    c->interface = p;
		}

		/* done with this interface if it doesn't match that end */
		if (!(sameaddr(&c->that.host_addr, &p->addr)
		&& (!no_klips || c->that.host_port == pluto_port)))
		    break;

		/* swap ends and try again.
		 * It is a little tricky to see that this loop will stop.
		 * Only continue if the far side matches.
		 * If both sides match, there is an error-out.
		 */
		{
		    struct end t = c->this;

		    c->this = c->that;
		    c->that = t;
		}
	    }
	}
    }
    return oriented(*c);
}

void
initiate_connection(const char *name, int whackfd)
{
    struct connection *c = con_by_name(name, TRUE);

    if (c != NULL)
    {
	set_cur_connection(c);
	if (!oriented(*c))
	{
	    loglog(RC_ORIENT, "we have no ipsecN interface for either end of this connection");
	}
	else if (c->kind != CK_PERMANENT)
	{
	    loglog(RC_NOPEERIP, "cannot initiate connection without knowing peer IP address");
	}
	else
	{
	    /* We will only request an IPsec SA if policy isn't empty
	     * (ignoring Main Mode items).
	     * This is a fudge, but not yet important.
	     * If we are to proceed asynchronously, whackfd will be NULL_FD.
	     */
	    c->initiated = TRUE;
	    ipsecdoi_initiate(whackfd, c, c->policy, 1, SOS_NOBODY);
	    whackfd = NULL_FD;	/* protect from close */
	}
	reset_cur_connection();
    }
    close_any(whackfd);
}

void initiate_connections_by_peer(struct connection *c)
{
    struct connection *d;
    ip_address match;

    update_host_pairs();
    memcpy(&match, &c->that.host_addr, sizeof(ip_address));

    if (c->host_pair == NULL)
    	return;
    d = c->host_pair->connections;
    for (; d != NULL; d = d->hp_next) {
	   if (sameaddr(&d->that.host_addr, &match)) {
	       initiate_connection(d->name, NULL_FD);
	   }
    }
}

/* opportunistic initiation is broken in two:
 * - everything up to Async DNS lookup (initiate_opportunistic)
 * - everyting after (until first IKE message sent) (continue_oppo)
 * Afterwards, regular state machinery carries negotiation forward.
 */

struct oppo_continuation {
    struct adns_continuation ac;	/* common prefix */
    ip_address our_client;	/* not pointer! */
    ip_address peer_client;
    bool held;
    int whackfd;
};

static void
cannot_oppo(const ip_address *our_client
, const ip_address *peer_client, bool held USED_BY_KLIPS, err_t ugh)
{
    char pcb[ADDRTOT_BUF];
    char ocb[ADDRTOT_BUF];

    addrtot(peer_client, 0, pcb, sizeof(pcb));
    addrtot(our_client, 0, ocb, sizeof(ocb));

    loglog(RC_OPPOFAILURE
	, "Can't Opportunistically initiate for %s to %s: %s"
	, ocb, pcb, ugh);

#ifdef KLIPS
    if (held)
    {
	/* Replace HOLD with PASS.
	 * The type of replacement *ought* to be
	 * specified by policy.
	 */
	(void) replace_bare_shunt(our_client, peer_client
	    , SPI_PASS	/* fail into PASS */
	    , TRUE, "replace HOLD with PASS [no SG discovered]");
    }
#endif
}
static void continue_oppo(struct adns_continuation *acr, err_t ugh);	/* forward */

/* knowing clients (single IP addresses), try to build an SA */
void
initiate_opportunistic(const ip_address *our_client
, const ip_address *peer_client
, bool held
, int whackfd)
{
    struct connection *c;

    /* What connection shall we use?
     * First try for one that explicitly handles the clients.
     */
    DBG(DBG_CONTROL, DBG_log("not attempting to initiate opportunistic connection"));
    return;
    DBG(DBG_CONTROL,
	{
	    char ours[ADDRTOT_BUF];
	    char his[ADDRTOT_BUF];

	    addrtot(our_client, 0, ours, sizeof(ours));
	    addrtot(peer_client, 0, his, sizeof(his));
	    DBG_log("initiate on demand from %s to %s", ours, his);
	});

    c = find_connection_for_clients(our_client, peer_client);
    if (c != NULL)
    {
	/* We've found a connection that can serve.
	 * Do we have to initiate it?
	 * Not if there is currently an IPSEC SA.
	 * But if there is an IPSEC SA, then KLIPS would not
	 * have generated the acquire.  So we assume that there isn't one.
	 * This may be redundant if a non-opportunistic
	 * negotiation is already being attempted.
	 */

	/* We will only request an IPsec SA if policy isn't empty
	 * (ignoring Main Mode items).
	 * This is a fudge, but not yet important.
	 * If we are to proceed asynchronously, whackfd will be NULL_FD.
	 */

	passert(HAS_IPSEC_POLICY(c->policy));

#ifdef KLIPS
	if (held)
	{
	    /* what should we do on failure? */
	    (void) assign_hold(c, our_client, peer_client);
	}
#endif
	ipsecdoi_initiate(whackfd, c, c->policy, 1, SOS_NOBODY);
	whackfd = NULL_FD;	/* protect from close */
    }
    else if (oppo_templates == 0)
    {
	/* No connection explicitly handles the clients and there
	 * are no Opportunistic connections -- whine and give up.
	 */
	cannot_oppo(our_client, peer_client, held, "no Opportunistic template");
    }
    else
    {
	/* No connection explicitly handles the clients.
	 * So we don't even know the peer:
	 * try to discover peer via DNS query
	 */
	struct oppo_continuation *cr = alloc_thing(struct oppo_continuation
	    , "opportunistic continuation");
	struct id id;
	err_t ugh;

	cr->our_client = *our_client;
	cr->peer_client = *peer_client;
	cr->held = held;
	cr->whackfd = whackfd;	/* hand-off */

	/* note: {unshare|free}_id_content not needed for id */
	iptoid(peer_client, &id);

	ugh = start_adns_query(&id
	    , (const struct id *) NULL	/* security gateway unconstrained */
	    , T_TXT
	    , continue_oppo
	    , &cr->ac);
	if (ugh == NULL)
	    whackfd = NULL_FD;	/* complete hand-off */
	else
	    cannot_oppo(our_client, peer_client, held, ugh);
    }
    close_any(whackfd);
}

/* Continue opportunistic initiation now that DNS has answered.
 * List of gateways will be in gateways_from_dns -- we must manage the list.
 */
static void
continue_oppo(struct adns_continuation *acr, err_t ugh)
{
    struct oppo_continuation *cr = (void *)acr;	/* inherit! */
    const ip_address *our_client = &cr->our_client
	, *peer_client = &cr->peer_client;
    bool held = cr->held;
    int whackfd = cr->whackfd;

    /* note: cr->id has no resources; cr->sgw_id is id_none:
     * neither need freeing.
     */
    whack_log_fd = whackfd;
    if (ugh != NULL)
    {
	cannot_oppo(our_client, peer_client, held, ugh);
    }
    else
    {
	/* !!! we need to randomize the entry in gw that we choose */
	struct connection *c = build_outgoing_opportunistic_connection(
	    gateways_from_dns, our_client
	    , peer_client);

	if (c == NULL)
	{
	    char ocb[ADDRTOT_BUF]
		, pcb[ADDRTOT_BUF]
		, pb[ADDRTOT_BUF];

	    addrtot(our_client, 0, ocb, sizeof(ocb));
	    addrtot(peer_client, 0, pcb, sizeof(pcb));
	    passert(id_is_ipaddr(&gateways_from_dns->gw_id));
	    addrtot(&gateways_from_dns->gw_id.ip_addr, 0, pb, sizeof(pb));
	    loglog(RC_OPPOFAILURE
		, "no suitable connection for opportunism"
		  " between %s and %s with %s as peer"
		, ocb, pcb, pb);

#ifdef KLIPS
	    if (held)
	    {
		/* Replace HOLD with PASS.
		 * The type of replacement *ought* to be
		 * specified by policy.
		 */
		(void) replace_bare_shunt(our_client, peer_client
		    , SPI_PASS	/* fail into PASS */
		    , TRUE, "replace HOLD with PASS [no suitable connection]");
	    }
#endif
	}
	else
	{
	    /* If we are to proceed asynchronously, whackfd will be NULL_FD. */
	    passert(c->gw_info != NULL);
	    passert(HAS_IPSEC_POLICY(c->policy));
	    passert(c->routing == RT_UNROUTED);
#ifdef KLIPS
	    if (held)
	    {
		/* what should we do on failure? */
		(void) assign_hold(c, our_client, peer_client);
	    }
#endif
	    c->gw_info->last_tried_time = now();
	    ipsecdoi_initiate(whackfd, c, c->policy, 1, SOS_NOBODY);
	    whackfd = NULL_FD;	/* protect from close */
	}
    }
    gw_delref(&gateways_from_dns);
    whack_log_fd = NULL_FD;
    close_any(whackfd);
}

void
terminate_connection(const char *nm)
{
    /* Loop because more than one may match (master and instances)
     * But at least one is required (enforced by con_by_name).
     */
    struct connection *c, *n;

    for (c = con_by_name(nm, TRUE); c != NULL; c = n)
    {
	n = c->ac_next;	/* grab this before c might disappear */
	if (streq(c->name, nm))
	{
	    set_cur_connection(c);
	    log("terminating SAs using this connection");
	    c->initiated = FALSE;
	    delete_states_by_connection(c);
	    reset_cur_connection();
	}
    }
}

void terminate_connections_by_peer(struct connection *c)
{
    struct connection *d;

    d = c->host_pair->connections;

    for (; d != NULL; d = d->hp_next) {
	   if (sameaddr(&d->that.host_addr, &c->that.host_addr)) {
	       terminate_connection(d->name);
	   }
    }
}

/* check nexthop safety
 * Our nexthop must not be within a routed client subnet, and vice versa.
 * Note: we don't think this is true.  We think that KLIPS will
 * not process a packet output by an eroute.
 */
#ifdef NEVER
//bool
//check_nexthop(const struct connection *c)
//{
//    struct connection *d;
//
//    if (addrinsubnet(&c->this.host_nexthop, &c->that.client))
//    {
//	loglog(RC_LOG_SERIOUS, "cannot perform routing for connection \"%s\""
//	    " because nexthop is within peer's client network",
//	    c->name);
//	return FALSE;
//    }
//
//    for (d = connections; d != NULL; d = d->next)
//    {
//	if (d->routing != RT_UNROUTED)
//	{
//	    if (addrinsubnet(&c->this.host_nexthop, &d->that.client))
//	    {
//		loglog(RC_LOG_SERIOUS, "cannot do routing for connection \"%s\"
//		    " because nexthop is contained in"
//		    " existing routing for connection \"%s\"",
//		    c->name, d->name);
//		return FALSE;
//	    }
//	    if (addrinsubnet(&d->this.host_nexthop, &c->that.client))
//	    {
//		loglog(RC_LOG_SERIOUS, "cannot do routing for connection \"%s\"
//		    " because it contains nexthop of"
//		    " existing routing for connection \"%s\"",
//		    c->name, d->name);
//		return FALSE;
//	    }
//	}
//    }
//    return TRUE;
//}
#endif /* NEVER */

/* an ISAKMP SA has been established.
 * Note the serial number, and release any connections with
 * the same peer ID but different peer IP address.
 */
bool uniqueIDs = FALSE;	/* --uniqueids? */

void
ISAKMP_SA_established(struct connection *c, so_serial_t serial)
{
    c->newest_isakmp_sa = serial;

    if (uniqueIDs)
    {
	/* for all connections: if the same Phase 1 peer ID is used
	 * for a different IP address, unorient that connection.
	 */
	struct connection *d;

	for (d = connections; d != NULL; )
	{
	    struct connection *next = d->ac_next;	/* might move underneath us */

	    if (d->kind == CK_INSTANCE
	    && same_id(&c->that.id, &d->that.id)
	    && (c->newest_isakmp_sa > d->newest_isakmp_sa)) {
	    	struct state *st;

		st = state_with_serialno(d->newest_isakmp_sa);
		if (st) {
			log("deleting state #%lu", st->st_serialno);
			delete_state(st);
		}
	    } else 
#ifdef NAT_TRAVERSAL
	    if (d->kind != CK_TEMPLATE
	    && same_id(&c->that.id, &d->that.id)
	    && (!sameaddr(&c->that.host_addr, &d->that.host_addr) ||
	    (c->that.host_port != d->that.host_port)))
#else
	    if (d->kind != CK_TEMPLATE
	    && same_id(&c->that.id, &d->that.id)
	    && !sameaddr(&c->that.host_addr, &d->that.host_addr))
#endif
	    {
		release_connection(d);
	    }
	    d = next;
	}
    }
}

/* Find the connection to connection c's peer's client with the
 * largest value of .routing.  All other things being equal,
 * preference is given to c.  If none is routed, return NULL.
 *
 * If erop is non-null, set *erop to a connection sharing both
 * our client subnet and peer's client subnet with the largest value
 * of .routing.  If none is erouted, set *erop to NULL.
 *
 * The return value is used to find other connections sharing a route.
 * *erop is used to find other connections sharing an eroute.
 */
struct connection *
route_owner(struct connection *c, struct connection **erop)
{
    struct connection *d
	, *bestro = c
	, *bestero = c;
    const ip_subnet *cc = EffectivePeerClient(c);

    passert(oriented(*c));

    for (d = connections; d != NULL; d = d->ac_next)
    {
	if (d->routing != RT_UNROUTED	/* quick filter */
	&& samesubnet(cc, EffectivePeerClient(d)))
	{
	    passert(oriented(*d));
	    if (d->routing > bestro->routing)
		bestro = d;
	    if (d->routing > bestero->routing
	    && samesubnet(&c->this.client, &d->this.client))
		bestero = d;
	}
    }
    DBG(DBG_CONTROL,
	{
	    err_t m = builddiag("route owner of \"%s\" %s %s:"
		, c->name
		, enum_name(&connection_kind_names, c->kind)
		, enum_name(&routing_story, c->routing));

	    if (!routed(bestro->routing))
		m = builddiag("%s NULL", m);
	    else if (bestro == c)
		m = builddiag("%s self", m);
	    else
		m = builddiag("%s \"%s\" %s %s", m
		    , bestro->name
		    , enum_name(&connection_kind_names, bestro->kind)
		    , enum_name(&routing_story, bestro->routing));

	    if (erop != NULL)
	    {
		m = builddiag("%s; eroute owner:", m);
		if (!erouted(bestero->routing))
		    m = builddiag("%s NULL", m);
		else if (bestero == c)
		    m = builddiag("%s self", m);
		else
		    m = builddiag("%s \"%s\" %s %s", m
			, bestero->name
			, enum_name(&connection_kind_names, bestero->kind)
			, enum_name(&routing_story, bestero->routing));
	    }

	    DBG_log("%s", m);
 	});
    if (erop != NULL)
	*erop = erouted(bestero->routing)? bestero : NULL;
    return routed(bestro->routing)? bestro : NULL;
}

/* Find a connection that owns the shunt eroute between subnets.
 * There ought to be only one.
 * This might get to be a bottleneck -- try hashing if it does.
 */
struct connection *
shunt_owner(const ip_subnet *ours, const ip_subnet *his)
{
    struct connection *c;

    for (c = connections; c != NULL; c = c->ac_next)
    {
	if (shunt_erouted(c->routing)
	&& samesubnet(ours, &c->this.client)
	&& samesubnet(his, &c->that.client))
	    break;
    }
    return c;
}

/* Find some connection with this pair of hosts.
 * We don't know enough to chose amongst those available.
 * ??? no longer usefully different from find_host_pair_connections
 */
struct connection *
find_host_connection(const ip_address *me, u_int16_t my_port
, const ip_address *him, u_int16_t his_port)
{
    return find_host_pair_connections(me, my_port, him, his_port);
}

/* given an up-until-now satisfactory connection, find the best connection
 * now that we just got the Phase 1 Id Payload from the peer.
 *
 * Comments in the code describe the (tricky!) matching criteria.
 * Although this routine could handle the initiator case,
 * it isn't currently called in this case.
 * This routine won't do anything interesting for Opportunistic Connections;
 * it's not clear that anything useful could be done.
 *
 * In RFC 2409 "The Internet Key Exchange (IKE)",
 * in 5.1 "IKE Phase 1 Authenticated With Signatures", describing Main
 * Mode:
 *
 *         Initiator                          Responder
 *        -----------                        -----------
 *         HDR, SA                     -->
 *                                     <--    HDR, SA
 *         HDR, KE, Ni                 -->
 *                                     <--    HDR, KE, Nr
 *         HDR*, IDii, [ CERT, ] SIG_I -->
 *                                     <--    HDR*, IDir, [ CERT, ] SIG_R
 *
 * In 5.4 "Phase 1 Authenticated With a Pre-Shared Key":
 *
 *               HDR, SA             -->
 *                                   <--    HDR, SA
 *               HDR, KE, Ni         -->
 *                                   <--    HDR, KE, Nr
 *               HDR*, IDii, HASH_I  -->
 *                                   <--    HDR*, IDir, HASH_R
 *
 * refine_host_connection could be called in two case:
 *
 * - the Responder receives the IDii payload:
 *   + [PSK] after using PSK to decode this message
 *   + before sending its IDir payload
 *   + before using its ID in HASH_R computation
 *   + [DSig] before using its private key to sign SIG_R
 *   + before using the Initiator's ID in HASH_I calculation
 *   + [DSig] before using the Initiator's public key to check SIG_I
 *
 * - the Initiator receives the IDir payload:
 *   + [PSK] after using PSK to encode previous message and decode this message
 *   + after sending its IDii payload
 *   + after using its ID in HASH_I computation
 *   + [DSig] after using its private key to sign SIG_I
 *   + before using the Responder's ID to compute HASH_R
 *   + [DSig] before using Responder's public key to check SIG_R
 *
 * refine_host_connection can choose a different connection, as long as
 * nothing already used is changed.
 *
 * In the Initiator case, the particular connection might have been
 * specified by whatever provoked Pluto to initiate.  For example:
 *	whack --initiate connection-name
 * The advantages of switching connections when we're the Initiator seem
 * less important than the disadvantages, so after FreeS/WAN 1.9, we
 * don't do this.
 */
struct connection *
refine_host_connection(const struct state *st, const struct id *peer_id
, bool initiator, bool aggrmode)
{
    struct connection *c = st->st_connection;
    u_int16_t auth = st->st_oakley.auth;
    struct connection *d;
	const chunk_t *psk_check;
    lset_t auth_policy;
    lset_t p1mode_policy = aggrmode ? POLICY_AGGRESSIVE : LEMPTY;
    const chunk_t *psk;
    const struct RSA_private_key *my_RSA_pri = NULL;
    bool rw;

    if (same_id(&c->that.id, peer_id))
	return c;	/* peer ID matches current connection -- look no further */

    switch (auth)
    {
    case OAKLEY_PRESHARED_KEY:
    	DBG(DBG_CONTROL, DBG_log("refining connection with PSK"));
	auth_policy = POLICY_PSK;
	psk = get_preshared_secret(c);
	/* It should be virtually impossible to fail to find PSK:
	 * we just used it to decode the current message!
	 */
	if (psk == NULL) {
	    log("cannot determine PSK");
	    return NULL;	/* cannot determine PSK! */
	}
	break;

    case OAKLEY_RSA_SIG:
    	DBG(DBG_CONTROL, DBG_log("refining connection with RSA Sig"));
	auth_policy = POLICY_RSASIG;
	if (initiator)
	{
	    /* at this point, we've committed to our RSA private key:
	     * we used it in our previous message.
	     */
	    my_RSA_pri = get_RSA_private_key(c);
	    if (my_RSA_pri == NULL)
		return NULL;	/* cannot determine my RSA private key! */
	}
	break;

    default:
	impossible();
    }

    /* The current connection won't do: search for one that will.
     * First search for one with the same pair of hosts.
     * If that fails, search for one with a Road Warrior peer.
     * We need to match:
     * - peer_id (slightly complicated by instantiation)
     * - if PSK auth, the key must not change (we used it to decode message)
     * - policy-as-used must be acceptable to new connection
     * - if initiator, also:
     *   + our ID must not change (we sent it in previous message)
     *   + our RSA key must not change (we used in in previous message)
     */
    d = c->host_pair->connections;
    DBG(DBG_CONTROL, DBG_log("trying to refine connection to an exact match"));
    for (rw = FALSE; ; rw = TRUE)
    {
	struct connection *best_found = NULL;

	for (; d != NULL; d = d->hp_next)
	{
	    bool exact = same_id(peer_id, &d->that.id);	/* exact peer ID match? */

	    DBG(DBG_CONTROL, DBG_log("testing connection %s", d->name));
#ifdef NAT_TRAVERSAL
	    if ((c->that.host_port != d->that.host_port) &&
		(d->kind == CK_INSTANCE)) {
		DBG(DBG_CONTROL, DBG_log("instance port mismatch"));
		continue;
	    }
#endif

	    /* check if peer_id matches, exactly or after instantiation */
	    if (!exact && !(rw && d->that.id.kind == ID_NONE)) {
		DBG(DBG_CONTROL, DBG_log("peer ID mismatch"));
		continue;
	    }
	    /* if initiator, our ID must match exactly */
	    if (initiator && !same_id(&c->this.id, &d->this.id)) {
		DBG(DBG_CONTROL, DBG_log("our ID mismatch"));
		continue;
	    }
	    /* authentication used must fit policy of this connection */
	    if ((d->policy & auth_policy) == LEMPTY) {
		DBG(DBG_CONTROL, DBG_log("auth mismatch"));
		continue;	/* our auth isn't OK for this connection */
	    }
	    if ((d->policy & POLICY_AGGRESSIVE) ^ p1mode_policy) {
 		DBG(DBG_CONTROL, DBG_log("aggressive mode mismatch"));
		continue;	/* disallow phase1 main/aggressive mode mismatch */
 	    }
	    switch (auth)
	    {
	    case OAKLEY_PRESHARED_KEY:
		/* secret must match the one we already used */
		{
		    const chunk_t *dpsk = get_preshared_secret(d);

		    DBG(DBG_CONTROL, DBG_log("testing PSK"));
		    if (dpsk == NULL) {
			DBG(DBG_CONTROL, DBG_log("PSK not found"));
			continue;	/* no secret */
		    }
	
		    if (psk != dpsk && !aggrmode)
			if (psk->len != dpsk->len
			|| memcmp(psk->ptr, dpsk->ptr, psk->len) != 0) {
			    DBG(DBG_CONTROL, DBG_log("PSK mismatch"));
			    continue;	/* different secret */			    
		    }
		}
		break;

	    case OAKLEY_RSA_SIG:
		/* We must at least be able to find our private key.
		 * If we initiated, it must match the one we
		 * used in the SIG_I payload that we sent previously.
		 */
		{
		    const struct RSA_private_key *pri
			= get_RSA_private_key(d);

		    DBG(DBG_CONTROL, DBG_log("testing RSA Sig"));
		    if (pri == NULL
		    || (initiator
		        && !same_RSA_public_key(&my_RSA_pri->pub, &pri->pub))) {
			DBG(DBG_CONTROL, DBG_log("RSA Sig mismatch"));
			continue;
		    }
		}
		break;

	    default:
		impossible();
	    }

	    if (exact) {
		DBG(DBG_CONTROL, DBG_log("connection %s matches exactly", d->name));
		return d;	/* passed all the tests */
	    }
	    DBG(DBG_CONTROL, DBG_log("changing best found to %s", d->name));
	    best_found = d;	/* passed tests, but peer_id was wildcarded */
	}
	if (rw) {
	    if (best_found) {
		DBG(DBG_CONTROL, DBG_log("connection %s is best found", best_found->name));
	    } else {
		DBG(DBG_CONTROL, DBG_log("no connection"));
	    }
	    return best_found;	/* been around twice already */
	}
	/* for second time around: figure out RW host pair's connections */
	d = find_host_pair_connections(&c->this.host_addr, c->this.host_port
	    , (ip_address *)NULL, c->that.host_port);
	DBG(DBG_CONTROL, DBG_log("trying to refine connection to a wildcard match"));
     }
}

#ifdef VIRTUAL_IP
/**
 * With virtual addressing, we must not allow someone to use an already
 * used (by another id) addr/net.
 */
static bool
is_virtual_net_used(const ip_subnet *peer_net, const struct id *peer_id)
{
    struct connection *d;
    for (d = connections; d != NULL; d = d->ac_next)
    {
	switch (d->kind) {
	    case CK_PERMANENT:
	    case CK_TEMPLATE:
	    case CK_INSTANCE:
		if ((subnetinsubnet(peer_net,&d->that.client) ||
		     subnetinsubnet(&d->that.client,peer_net)) &&
		     !same_id(&d->that.id, peer_id)) {
		    char buf[IDTOA_BUF];
		    char client[SUBNETTOT_BUF];
		    subnettot(peer_net, 0, client, sizeof(client));
		    idtoa(&d->that.id, buf, sizeof(buf));
		    log("Virtual IP %s is already used by '%s'",
			client, buf);
		    idtoa(peer_id, buf, sizeof(buf));
			log("Your ID is '%s'", buf);
		    return TRUE; /* already used by another one */
		}
		break;
	    case CK_GOING_AWAY:
	    default:
		break;
	}
    }
    return FALSE; /* you can safely use it */
}
#endif

/* find_client_connection: given a connection suitable for ISAKMP
 * (i.e. the hosts match), find a one suitable for IPSEC
 * (i.e. with matching clients).
 *
 * If we don't find an exact match (not even our current connection),
 * we try for one that still needs instantiation.  Try Road Warrior
 * abstract connections and the Opportunistic abstract connections.
 * This requires inverse instantiation: abstraction.
 *
 * After failing to find an exact match, we abstract the peer
 * to be NO_IP (the wildcard value).  This enables matches with
 * Road Warrior and Opportunistic abstract connections.
 *
 * After failing that search, we also abstract the Phase 1 peer ID
 * if possible.  If the peer's ID was the peer's IP address, we make
 * it NO_ID; instantiation will make it the peer's IP address again.
 *
 * If searching for a Road Warrior abstract connection fails,
 * and conditions are suitable, we search for an Opportunistic
 * abstract connection.
 *
 * Note: in the end, both Phase 1 IDs must be preserved, after any
 * instantiation.  They are the IDs that have been authenticated.
 */

/* fc_try: a helper function for find_client_connection */
static struct connection *
fc_try(bool oppo
, const struct connection *c
, struct host_pair *hp
, const struct id *peer_id
, const ip_subnet *our_net
, const ip_subnet *peer_net
, const u_int8_t our_protocol, const u_int16_t our_port
, const u_int8_t peer_protocol, const u_int16_t peer_port)
{
    struct connection *d;
    struct connection *unrouted = NULL;
    const bool peer_net_is_host = subnetishost(peer_net)
	&& addrinsubnet(&c->that.host_addr, peer_net);

    if (!hp) {
	DBG_log("%s,%d: NULL pointer", __FILE__, __LINE__);
	return(unrouted);
    }

    for (d = hp->connections; d != NULL; d = d->hp_next)
    {
	if (!same_peer_ids(c, d, peer_id))
	    continue;

	/* compare protocol and port, zero means 'any' and does always match */
	if ((d->this.protocol && d->this.protocol != our_protocol) 
	|| (d->this.port && d->this.port != our_port)
	|| (d->that.protocol && d->that.protocol != peer_protocol)
	|| (d->that.port && d->that.port != peer_port)
	|| (our_protocol != peer_protocol))
	    continue;

	if (oppo)
	{
	    /* Opportunistic case:
	     * our_net must be inside d->this.client
	     * and d must have a Wildcard that.client.
	     */
	    if (!subnetinsubnet(our_net, &d->this.client)
	    || !HasWildcardClient(d))
		continue;
	}
	else
	{
	    /* non-Opportunistic case:
	     * our_client must match.
	     *
	     * So must peer_client, but the testing is complicated
	     * by the fact that the peer might be a wildcard
	     * and if so, the default value of that.client
	     * won't match the default peer_net.  The appropriate test:
	     *
	     * If d has a peer client, it must match peer_net.
	     * If d has no peer client, peer_net must just have peer itself.
	     */
	    if (!samesubnet(&d->this.client, our_net))
		continue;

	    if (d->that.has_client)
	    {
		if (d->that.has_client_wildcard) {
		    if (!subnetinsubnet(peer_net, &d->that.client))
			continue;
		} else {
#ifdef VIRTUAL_IP
		    if ((!samesubnet(&d->that.client, peer_net)) && (!is_virtual_connection(d)))
#else
		    if (!samesubnet(&d->that.client, peer_net))
#endif
			continue;
#ifdef VIRTUAL_IP
		    if ((is_virtual_connection(d)) &&
			( (!is_virtual_net_allowed(d, peer_net, &c->that.host_addr)) ||
			(is_virtual_net_used(peer_net, peer_id?peer_id:&c->that.id)) ))
			    continue;
#endif
		}
	    }
	    else
	    {
		if (!peer_net_is_host)
		    continue;
	    }
	}

	/* we've run the gauntlet -- success */
	if (routed(d->routing))
	    return d;

	if (unrouted == NULL)
	    unrouted = d;
    }
    return unrouted;
}

struct connection *
find_client_connection(struct connection *c
, const ip_subnet *our_net, const ip_subnet *peer_net
, const u_int8_t our_protocol, const u_int16_t our_port
, const u_int8_t peer_protocol, const u_int16_t peer_port)
{
    struct connection *d;

    /* give priority to current connection
     * but even greater priority to a routed concrete connection
     */
    {
	struct connection *unrouted = NULL;

	if (samesubnet(&c->this.client, our_net)
	&& samesubnet(&c->that.client, peer_net)
	/* protocol and port must matcht, too */
	&& (!c->this.protocol || c->this.protocol == our_protocol) 
	&& (!c->this.port || c->this.port == our_port)
	&& (!c->that.protocol || c->that.protocol == peer_protocol)
	&& (!c->that.port || c->that.port == peer_port)
	&& (our_protocol == peer_protocol))
	{
	    passert(oriented(*c));
	    if (routed(c->routing))
		return c;

	    unrouted = c;
	}

	/* exact match? */
	d = fc_try(FALSE, c, c->host_pair, NULL, our_net, peer_net
	    , our_protocol, our_port, peer_protocol, peer_port);
	if (d == NULL)
	    d = unrouted;
    }

    if (d == NULL)
    {
	/* look for an abstract connection to match */
	struct host_pair *const hp = find_host_pair(&c->this.host_addr
	    , c->this.host_port, NULL, c->that.host_port);

	if (hp != NULL)
	{
	    struct id abstract_peer_id;

	    abstract_peer_id.kind = ID_NONE;

	    /* RW match with actual peer_id? */
	    d = fc_try(FALSE, c, hp, NULL, our_net, peer_net
		, our_protocol, our_port, peer_protocol, peer_port);

	    if (d == NULL && his_id_was_instantiated(c))
	    {
		/* RW match with abstract peer_id?
		 * Note that later instantiation will result in the same peer_id.
		 */
		d = fc_try(FALSE, c, hp, &abstract_peer_id, our_net, peer_net
		    , our_protocol, our_port, peer_protocol, peer_port);
	    }

	    if (d == NULL
	    && subnetishost(our_net)
	    && subnetishost(peer_net))
	    {
		/* Opportunistic match?
		 * Always use abstract peer_id.
		 * Note that later instantiation will result in the same peer_id.
		 */
		d = fc_try(TRUE, c, hp, &abstract_peer_id, our_net, peer_net
		    , our_protocol, our_port, peer_protocol, peer_port);
	    }
	}
    }

    return d;
}

void
show_connections_status(void)
{
    struct connection *c;

    for (c = connections; c != NULL; c = c->ac_next)
    {
	const char *ifn = oriented(*c)? c->interface->rname : "";
	const char *instance = c->kind == CK_INSTANCE? " instance" : "";

	/* show topology */
	{
	    char lhs[SUBNETTOT_BUF + ADDRTOT_BUF + IDTOA_BUF + ADDRTOT_BUF];
	    char rhs[SUBNETTOT_BUF + ADDRTOT_BUF + IDTOA_BUF + ADDRTOT_BUF];

	    (void) format_end(lhs, sizeof(lhs), &c->this, &c->that, TRUE);
	    (void) format_end(rhs, sizeof(rhs), &c->that, &c->this, FALSE);

	    /* Display on one line.
	     * We used to split the line if would be long, but that makes
	     * output less consistent.
	     */
	    whack_log(RC_COMMENT, "\"%s\"%s: %s...%s"
		, c->name, instance, lhs, rhs);
	}

	whack_log(RC_COMMENT
	    , "\"%s\"%s:   ike_life: %lus; ipsec_life: %lus;"
	    " rekey_margin: %lus; rekey_fuzz: %lu%%; keyingtries: %lu"
	    , c->name
	    , instance
	    , (unsigned long) c->sa_ike_life_seconds
	    , (unsigned long) c->sa_ipsec_life_seconds
	    , (unsigned long) c->sa_rekey_margin
	    , (unsigned long) c->sa_rekey_fuzz
	    , (unsigned long) c->sa_keying_tries);

	whack_log(RC_COMMENT
	    , "\"%s\"%s:   policy: %s; interface: %s; %s"
	    , c->name
	    , instance
	    , bitnamesof(sa_policy_bit_names, c->policy)
	    , ifn
	    , enum_name(&routing_story, c->routing));

	whack_log(RC_COMMENT
	    , "\"%s\"%s:   newest ISAKMP SA: #%ld; newest IPsec SA: #%ld; eroute owner: #%lu"
	    , c->name
	    , instance
	    , c->newest_isakmp_sa
	    , c->newest_ipsec_sa
	    , c->eroute_owner);
#ifndef NO_IKE_ALG
	ike_alg_show_connection(c, instance);
#endif
#ifndef NO_KERNEL_ALG
	kernel_alg_show_connection(c, instance);
#endif
    }
}

/* Is c->that.client 0.0.0.0/32 (or IPV6 equivalent)?
 * This, along with c->that.host being 0.0.0.0 signifies Opportunism.
 */
bool
HasWildcardClient(const struct connection *c)
{
    if (c->that.has_client && subnetishost(&c->that.client))
    {
	ip_address addr;

	networkof(&c->that.client, &addr);
	if (isanyaddr(&addr))
	    return TRUE;
    }
    return FALSE;
}

/* peer client, but for wildcard, subrange containing all */
const ip_subnet *
EffectivePeerClient(const struct connection *c)
{
    return c->kind == CK_TEMPLATE && HasWildcardClient(c)
	? aftoinfo(subnettypeof(&c->that.client))->all
	: &c->that.client;
}

/* struct pending, the structure representing Quick Mode
 * negotiations delayed until a Keying Channel has been negotiated.
 * Essentially, a pending call to quick_outI1.
 */

struct pending {
    int whack_sock;
    struct state *isakmp_sa;
    struct connection *connection;
    lset_t policy;
    unsigned long try;
    so_serial_t replacing;

    struct pending *next;
};

/* queue a Quick Mode negotiation pending completion of a suitable Main Mode */
void
add_pending(int whack_sock
, struct state *isakmp_sa
, struct connection *c
, lset_t policy
, unsigned long try
, so_serial_t replacing)
{
    struct pending *p = alloc_thing(struct pending, "struct pending");

    DBG(DBG_CONTROL, DBG_log("Queuing pending Quick Mode with %s \"%s\""
	, ip_str(&c->that.host_addr)
	, c->name));
    p->whack_sock = whack_sock;
    p->isakmp_sa = isakmp_sa;
    p->connection = c;
    p->policy = policy;
    p->try = try;
    p->replacing = replacing;
    p->next = c->host_pair->pending;
    c->host_pair->pending = p;
}

/* Release all the whacks awaiting the completion of this state.
 * This is accomplished by closing all the whack socket file descriptors.
 * We go to a lot of trouble to tell each whack, but to not tell it twice.
 */
void
release_pending_whacks(struct state *st, err_t story)
{
    struct pending *p;
    struct stat stst;

    if (st->st_whack_sock == NULL_FD || fstat(st->st_whack_sock, &stst) != 0)
	zero(&stst);	/* resulting st_dev/st_ino ought to be distinct */

    release_whack(st);

    for (p = st->st_connection->host_pair->pending; p != NULL; p = p->next)
    {
	if (p->isakmp_sa == st && p->whack_sock != NULL_FD)
	{
	    struct stat pst;

	    if (fstat(p->whack_sock, &pst) == 0
	    && (stst.st_dev != pst.st_dev || stst.st_ino != pst.st_ino))
	    {
		passert(whack_log_fd == NULL_FD);
		whack_log_fd = p->whack_sock;
		whack_log(RC_COMMENT
		    , "%s for ISAKMP SA, but releasing whack for pending IPSEC SA"
		    , story);
		whack_log_fd = NULL_FD;
	    }
	    close(p->whack_sock);
	    p->whack_sock = NULL_FD;
	}
    }
}

static void
delete_pending(struct pending **pp)
{
    struct pending *p = *pp;

    *pp = p->next;
    if (p->connection != NULL)
	connection_discard(p->connection);
    close_any(p->whack_sock);
    pfree(p);
}

void
unpend(struct state *st)
{
    struct pending **pp
	, *p;

    DBG(DBG_CONTROL, DBG_log("unpend - 1"));
    for (pp = &st->st_connection->host_pair->pending; (p = *pp) != NULL; )
    {
    	DBG(DBG_CONTROL, DBG_log("unpend - 2"));
	if (p->isakmp_sa == st)
	{
	    DBG(DBG_CONTROL, DBG_log("unqueuing pending Quick Mode with %s \"%s\""
		, ip_str(&p->connection->that.host_addr)
		, p->connection->name));
	    DBG(DBG_CONTROL, DBG_log("unpend - 3"));
	    (void) quick_outI1(p->whack_sock, st, p->connection, p->policy
		, p->try, p->replacing);
	    p->whack_sock = NULL_FD;	/* ownership transferred */
	    p->connection = NULL;	/* ownership transferred */
	    delete_pending(pp);
	}
	else
	{
	    pp = &p->next;
	}
    }
}

/* a Main Mode negotiation has been replaced; update any pending */
void
update_pending(struct state *os, struct state *ns)
{
    struct pending *p;

    for (p = os->st_connection->host_pair->pending; p != NULL; p = p->next) {
	if (p->isakmp_sa == os)
	    p->isakmp_sa = ns;
#ifdef NAT_TRAVERSAL
	if (p->connection->this.host_port != ns->st_connection->this.host_port) {
	    p->connection->this.host_port = ns->st_connection->this.host_port;
	    p->connection->that.host_port = ns->st_connection->that.host_port;
	}
#endif
    }
}

/* a Main Mode negotiation has failed; discard any pending */
void
flush_pending_by_state(struct state *st)
{
    struct host_pair *hp = st->st_connection->host_pair;

    if (hp != NULL)
    {
	struct pending **pp
	    , *p;

	for (pp = &hp->pending; (p = *pp) != NULL; )
	{
	    if (p->isakmp_sa == st)
		delete_pending(pp);
	    else
		pp = &p->next;
	}
    }
}

/* a connection has been deleted; discard any related pending */
static void
flush_pending_by_connection(struct connection *c)
{
    if (c->host_pair != NULL)
    {
	struct pending **pp
	    , *p;

	for (pp = &c->host_pair->pending; (p = *pp) != NULL; )
	{
	    if (p->connection == c)
	    {
		p->connection = NULL;	/* prevent delete_pending from releasing */
		delete_pending(pp);
	    }
	    else
	    {
		pp = &p->next;
	    }
	}
    }
}

/* Delete a connection if it is an instance and it is no longer in use.
 * We must be careful to avoid circularity:
 * we don't touch it if it is CK_GOING_AWAY.
 */
void
connection_discard(struct connection *c)
{
    if (c->kind == CK_INSTANCE)
    {
	/* see if it is being used by a pending */
	struct pending *p;

	for (p = c->host_pair->pending; p != NULL; p = p->next)
	    if (p->connection == c)
		return;	/* in use, so we're done */

	if (!states_use_connection(c))
	    delete_connection(c);
    }
}

