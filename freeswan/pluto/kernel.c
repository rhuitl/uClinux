/* routines that interface with the kernel's IPsec mechanism
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
 * RCSID $Id: kernel.c,v 1.149 2002/04/01 08:46:54 dhr Exp $
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <wait.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <freeswan.h>

#ifdef KLIPS
#include <sys/time.h>	/* for select(2) */
#include <sys/types.h>	/* for select(2) */
# include <signal.h>
# include <pfkeyv2.h>
# include <pfkey.h>
#endif /* KLIPS */

#include <linux/config.h>
#ifdef CONFIG_LEDMAN
#include <linux/ledman.h>
#endif

#include "constants.h"
#include "defs.h"
#include "rnd.h"
#include "id.h"
#include "x509.h"
#include "connections.h"	/* needs id.h */
#include "state.h"
#include "timer.h"
#include "kernel.h"
#include "log.h"
#include "server.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */

#include "alg_info.h"
#include "kernel_alg.h"

#ifdef NAT_TRAVERSAL
#include "packet.h"  /* for pb_stream in nat_traversal.h */
#include "nat_traversal.h"
#endif

bool can_do_IPcomp = TRUE;  /* can system actually perform IPCOMP? */

/* How far can IPsec messages arrive out of order before the anti-replay
 * logic loses track and swats them?  64 is the best KLIPS can do.
 */
#define REPLAY_WINDOW	64

static bool route_and_eroute(struct connection *c
    , struct state *st);	/* forward declaration */

/* test if the routes required for two different connections agree
 * It is assumed that the destination subnets agree; we are only
 * testing that the interfaces and nexthops match.
 */
#define routes_agree(c, d) ((c)->interface == (d)->interface \
	&& sameaddr(&(c)->this.host_nexthop, &(d)->this.host_nexthop))

#ifndef KLIPS

bool no_klips = TRUE;	/* don't actually use KLIPS */

#else /* !KLIPS */

/* Declare eroute things early enough for uses.
 *
 * Flags are encoded above the low-order byte of verbs.
 * "real" eroutes are only outbound.  Inbound eroutes don't exist,
 * but an addflow with an INBOUND flag allows IPIP tunnels to be
 * limited to appropriate source and destination addresses.
 */

#define ERO_MASK	0xFF
#define ERO_FLAG_SHIFT	8

#define ERO_DELETE	SADB_X_DELFLOW
#define ERO_ADD	SADB_X_ADDFLOW
#define ERO_REPLACE	(SADB_X_ADDFLOW | (SADB_X_SAFLAGS_REPLACEFLOW << ERO_FLAG_SHIFT))
#define ERO_ADD_INBOUND	(SADB_X_ADDFLOW | (SADB_X_SAFLAGS_INFLOW << ERO_FLAG_SHIFT))

/* bare (connectionless) shunt (eroute) table
 *
 * Bare shunts are those that don't "belong" to a connection.
 * This happens because some %trapped traffic hasn't yet or cannot be
 * assigned to a connection.  The usual reason is that we cannot discover
 * the peer SG.  Another is that even when the peer has been discovered,
 * it may be that no connection matches all the particulars.
 * Bare shunts are either %hold or %pass.
 * We record them so that, with scanning, we can discover
 * which %holds are news and which %passes should expire.
 */

#define SHUNT_SCAN_INTERVAL	(60 * 2)   /* time between scans of eroutes */

/* SHUNT_PATIENCE only has resolution down to a multiple of the sample rate,
 * SHUNT_SCAN_INTERVAL.
 * By making SHUNT_PATIENCE an odd multiple of half of SHUNT_SCAN_INTERVAL,
 * we minimize the effects of jitter.
 */
#define SHUNT_PATIENCE	(SHUNT_SCAN_INTERVAL * 15 / 2)	/* inactivity timeout */

struct bare_shunt {
    ip_subnet ours;
    ip_subnet his;
    ip_said said;
    unsigned long count;
    time_t last_activity;
    struct bare_shunt *next;
};

static struct bare_shunt *bare_shunts = NULL;

#ifdef DEBUG
static void
DBG_bare_shunt(const char *op, const struct bare_shunt *bs)
{
    DBG(DBG_KLIPS,
	{
	    char ourst[SUBNETTOT_BUF];
	    char hist[SUBNETTOT_BUF];
	    char sat[SATOT_BUF];

	    subnettot(&(bs)->ours, 0, ourst, sizeof(ourst));
	    subnettot(&(bs)->his, 0, hist, sizeof(hist));
	    satot(&(bs)->said, 0, sat, sizeof(sat));
	    DBG_log("%s bare shunt %p %s -> %s => %s"
		, op, (const void *)(bs), ourst, hist, sat);
	});
}
#else /* !DEBUG */
#define DBG_bare_shunt(op, bs) {}
#endif /* !DEBUG */

/* information from /proc/net/ipsec_eroute */

struct eroute_info {
    unsigned long count;
    ip_subnet ours;
    ip_subnet his;
    ip_address dst;
    ip_said	said;
    struct eroute_info *next;
};

/* The orphaned_holds table records %holds for which we
 * scan_proc_shunts found no representation of in any connection.
 * The corresponding ACQUIRE message might have been lost.
 */
struct eroute_info *orphaned_holds = NULL;

static bool shunt_eroute(struct connection *c
    , unsigned int op, const char *opname);	/* forward declaration */

bool no_klips = FALSE;	/* don't actually use KLIPS */

int pfkeyfd = NULL_FD;

typedef u_int32_t pfkey_seq_t;
static pfkey_seq_t pfkey_seq = 0;	/* sequence number for our PF_KEY messages */

static pid_t pid;
static void pfkey_register(void);

#define NE(x) { x, #x }	/* Name Entry -- shorthand for sparse_names */

static sparse_names pfkey_type_names = {
	NE(SADB_RESERVED),
	NE(SADB_GETSPI),
	NE(SADB_UPDATE),
	NE(SADB_ADD),
	NE(SADB_DELETE),
	NE(SADB_GET),
	NE(SADB_ACQUIRE),
	NE(SADB_REGISTER),
	NE(SADB_EXPIRE),
	NE(SADB_FLUSH),
	NE(SADB_DUMP),
	NE(SADB_X_PROMISC),
	NE(SADB_X_PCHANGE),
	NE(SADB_X_GRPSA),
	NE(SADB_X_ADDFLOW),
	NE(SADB_X_DELFLOW),
	NE(SADB_X_DEBUG),
#ifdef NAT_TRAVERSAL
	NE(SADB_X_NAT_T_NEW_MAPPING),
#endif
	NE(SADB_MAX),
	{ 0, sparse_end }
};

#ifdef NEVER /* not needed yet */
static sparse_names pfkey_ext_names = {
	NE(SADB_EXT_RESERVED),
	NE(SADB_EXT_SA),
	NE(SADB_EXT_LIFETIME_CURRENT),
	NE(SADB_EXT_LIFETIME_HARD),
	NE(SADB_EXT_LIFETIME_SOFT),
	NE(SADB_EXT_ADDRESS_SRC),
	NE(SADB_EXT_ADDRESS_DST),
	NE(SADB_EXT_ADDRESS_PROXY),
	NE(SADB_EXT_KEY_AUTH),
	NE(SADB_EXT_KEY_ENCRYPT),
	NE(SADB_EXT_IDENTITY_SRC),
	NE(SADB_EXT_IDENTITY_DST),
	NE(SADB_EXT_SENSITIVITY),
	NE(SADB_EXT_PROPOSAL),
	NE(SADB_EXT_SUPPORTED_AUTH),
	NE(SADB_EXT_SUPPORTED_ENCRYPT),
	NE(SADB_EXT_SPIRANGE),
	NE(SADB_X_EXT_KMPRIVATE),
	NE(SADB_X_EXT_SATYPE2),
	NE(SADB_X_EXT_SA2),
	NE(SADB_X_EXT_ADDRESS_DST2),
	NE(SADB_X_EXT_ADDRESS_SRC_FLOW),
	NE(SADB_X_EXT_ADDRESS_DST_FLOW),
	NE(SADB_X_EXT_ADDRESS_SRC_MASK),
	NE(SADB_X_EXT_ADDRESS_DST_MASK),
	NE(SADB_X_EXT_DEBUG),
	{ 0, sparse_end }
};
#endif /* NEVER */

#undef NE

static void
init_pfkey(void)
{
    pid = getpid();

    /* open PF_KEY socket */

    pfkeyfd = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);

    if (pfkeyfd == -1)
	exit_log_errno((e, "socket() in init_pfkeyfd()"));

#ifdef NEVER	/* apparently unsupported! */
    if (fcntl(pfkeyfd, F_SETFL, O_NONBLOCK) != 0)
	exit_log_errno((e, "fcntl() in init_pfkeyfd()"));
#endif

    DBG(DBG_KLIPS,
	DBG_log("process %u listening for PF_KEY_V2 on file descriptor %d", (unsigned)pid, pfkeyfd));

    pfkey_register();	/* register SA types that we can negotiate */
}

/* Kinds of PF_KEY message from the kernel:
 * - response to a request from us
 *   + ACK/NAK
 *   + Register: indicates transforms supported by kernel
 *   + SPI requested by getspi
 * - Acquire, requesting us to deal with trapped clear packet
 * - expiration of of one of our SAs
 * - messages to other processes
 *
 * To minimize the effect on the event-driven structure of Pluto,
 * responses are dealt with synchronously.  We hope that the Kernel
 * produces them synchronously.  We must "read ahead" in the PF_KEY
 * stream, saving Acquire and Expiry messages that are encountered.
 * We ignore messages to other processes.
 */

typedef union {
	unsigned char bytes[PFKEYv2_MAX_MSGSIZE];
	struct sadb_msg msg;
    } pfkey_buf;

/* queue of unprocessed PF_KEY messages input from kernel
 * Note that the pfkey_buf may be partly allocated, reflecting
 * the variable length nature of the messages.  So the link field
 * must come first.
 */
typedef struct pfkey_item {
	struct pfkey_item *next;
	pfkey_buf buf;
    } pfkey_item;

static pfkey_item *pfkey_iq_head = NULL;	/* oldest */
static pfkey_item *pfkey_iq_tail;	/* youngest */

static bool
pfkey_input_ready(void)
{
    fd_set readfds;
    int ndes;
    struct timeval tm;

    tm.tv_sec = 0;	/* don't wait at all */
    tm.tv_usec = 0;

    FD_ZERO(&readfds);	/* we only care about pfkeyfd */
    FD_SET(pfkeyfd, &readfds);

    do {
	ndes = select(pfkeyfd + 1, &readfds, NULL, NULL, &tm);
    } while (ndes == -1 && errno == EINTR);

    if (ndes < 0)
    {
	log_errno((e, "select() failed in pfkey_get()"));
	return FALSE;
    }

    if (ndes == 0)
	return FALSE;	/* nothing to read */

    passert(ndes == 1 && FD_ISSET(pfkeyfd, &readfds));
    return TRUE;
}

/* get a PF_KEY message from kernel.
 * Returns TRUE is message found, FALSE if no message pending,
 * and aborts or keeps trying when an error is encountered.
 * The only validation of the message is that the message length
 * received matches that in the message header, and that the message
 * is for this process.
 */
static bool
pfkey_get(pfkey_buf *buf)
{
    for (;;)
    {
	ssize_t len;

	if (!pfkey_input_ready())
	    return FALSE;

	len = read(pfkeyfd, buf->bytes, sizeof(buf->bytes));

	if (len < 0)
	{
	    if (errno == EAGAIN)
		return FALSE;

	    log_errno((e, "read() failed in pfkey_get()"));
	    return FALSE;
	}
	else if ((size_t) len < sizeof(buf->msg))
	{
	    log("pfkey_get read truncated PF_KEY message: %d bytes; ignoring message", len);
	}
	else if ((size_t) len != buf->msg.sadb_msg_len * IPSEC_PFKEYv2_ALIGN)
	{
	    log("pfkey_get read PF_KEY message with length %d that doesn't equal sadb_msg_len %u * %d; ignoring message"
		, len, (unsigned) buf->msg.sadb_msg_len, IPSEC_PFKEYv2_ALIGN);
	}
	/*	for now, unsolicited messages can be: 
	 *	SADB_ACQUIRE, SADB_REGISTER 
	 */
	else if (!(buf->msg.sadb_msg_pid == (unsigned)pid
	|| (buf->msg.sadb_msg_pid == 0 && buf->msg.sadb_msg_type == SADB_ACQUIRE)
#ifdef NAT_TRAVERSAL
	|| (buf->msg.sadb_msg_pid == 0 && buf->msg.sadb_msg_type == SADB_X_NAT_T_NEW_MAPPING)
#endif
	|| (buf->msg.sadb_msg_type == SADB_REGISTER)))
	{
	    /* not for us: ignore */
	    DBG(DBG_KLIPS,
		DBG_log("pfkey_get: ignoring PF_KEY %s message %u for process %u"
		    , sparse_val_show(pfkey_type_names, buf->msg.sadb_msg_type)
		    , buf->msg.sadb_msg_seq
		    , buf->msg.sadb_msg_pid));
	}
	else
	{
	    DBG(DBG_KLIPS,
		DBG_log("pfkey_get: %s message %u"
		    , sparse_val_show(pfkey_type_names, buf->msg.sadb_msg_type)
		    , buf->msg.sadb_msg_seq));
	    return TRUE;
	}
    }
}

/* get a response to a specific message */
static bool
pfkey_get_response(pfkey_buf *buf, pfkey_seq_t seq)
{
    while (pfkey_get(buf))
    {
	if (buf->msg.sadb_msg_pid == (unsigned)pid
	&& buf->msg.sadb_msg_seq == seq)
	{
	    return TRUE;
	}
	else
	{
	    /* Not for us: queue it. */
	    size_t bl = buf->msg.sadb_msg_len * IPSEC_PFKEYv2_ALIGN;
	    pfkey_item *it = alloc_bytes(offsetof(pfkey_item, buf) + bl, "pfkey_item");

	    memcpy(&it->buf, buf, bl);

	    it->next = NULL;
	    if (pfkey_iq_head == NULL)
	    {
		pfkey_iq_head = it;
	    }
	    else
	    {
		pfkey_iq_tail->next = it;
	    }
	    pfkey_iq_tail = it;
	}
    }
    return FALSE;
}

/* Process a SADB_REGISTER message from KLIPS.
 * This will be a response to one of ours, but it may be asynchronous
 * (if KLIPS modules are loaded and unloaded).
 * Some sanity checking has already been performed.
 */
static void
process_pfkey_register_response(pfkey_buf *buf)
{
    /* Find out what the kernel can support.
     * In fact, the only question at the moment
     * is whether it can support IPcomp.
     * So we ignore the rest.
     * ??? we really should pay attention to what transforms are supported.
     */
    switch (buf->msg.sadb_msg_satype)
    {
    case SADB_SATYPE_AH:
	break;
    case SADB_SATYPE_ESP:
#ifndef NO_KERNEL_ALG
	kernel_alg_register_pfkey(buf, sizeof (pfkey_buf));
#endif
	break;
    case SADB_X_SATYPE_COMP:
	/* ??? There ought to be an extension to list the
	 * supported algorithms, but RFC 2367 doesn't
	 * list one for IPcomp.  KLIPS uses SADB_X_CALG_DEFLATE.
	 * Since we only implement deflate, we'll assume this.
	 */
	can_do_IPcomp = TRUE;
	break;
    case SADB_X_SATYPE_IPIP:
	break;
    default:
	break;
    }
}

/* Create ip_address out of sockaddr.  Ignore port! */
static err_t
sockaddr_to_ip_address(const struct sockaddr *src, ip_address *dest)
{
    switch (src->sa_family)
    {
    case AF_INET:
	initaddr((const void *) &((const struct sockaddr_in *)src)->sin_addr
	    , sizeof(((const struct sockaddr_in *)src)->sin_addr)
	    , src->sa_family, dest);
	return NULL;
    case AF_INET6:
	initaddr((const void *) &((const struct sockaddr_in6 *)src)->sin6_addr
	    , sizeof(((const struct sockaddr_in6 *)src)->sin6_addr)
	    , src->sa_family, dest);
	return NULL;
    default:
	return "unknown address family";
    }
}

static void
record_and_initiate_opportunistic(ip_subnet *ours, ip_subnet *his)
{
    passert(samesubnettype(ours, his));

    /* Add to bare shunt list.
     * We need to do this because the shunt was installed by KLIPS
     * which can't do this itself.
     */
    {
	struct bare_shunt *bs = alloc_thing(struct bare_shunt, "bare shunt");

	bs->ours = *ours;
	bs->his = *his;

	bs->said.proto = SA_INT;
	bs->said.spi = htonl(SPI_HOLD);
	bs->said.dst = *aftoinfo(subnettypeof(ours))->any;

	bs->count = 0;
	bs->last_activity = now();

	bs->next = bare_shunts;
	bare_shunts = bs;
	DBG_bare_shunt("add", bs);
    }

    /* actually initiate opportunism */
    {
	ip_address src, dst;

	networkof(ours, &src);
	networkof(his, &dst);
	initiate_opportunistic(&src, &dst, TRUE, NULL_FD);
    }

    /* if present, remove from orphaned_holds list.
     * NOTE: we do this last in case ours or his is a pointer into a member.
     */
    {
	struct eroute_info **pp, *p;

	for (pp = &orphaned_holds; (p = *pp) != NULL; pp = &p->next)
	{
	    if (samesubnet(ours, &p->ours) && samesubnet(his, &p->his))
	    {
		*pp = p->next;
		pfree(p);
		break;
	    }
	}
    }
}

/* Processs a SADB_ACQUIRE message from KLIPS.
 * Try to build an opportunistic connection!
 * See RFC 2367 "PF_KEY Key Management API, Version 2" 3.1.6
 * <base, address(SD), (address(P)), (identity(SD),) (sensitivity,) proposal>
 * - extensions for source and data IP addresses
 * - optional extensions for identity [not useful for us?]
 * - optional extension for sensitivity [not useful for us?]
 * - expension for proposal [not useful for us?]
 *
 * ??? We must use the sequence number in creating an SA.
 * We actually need to create up to 4 SAs each way.  Which one?
 * I guess it depends on the protocol present in the sadb_msg_satype.
 * For now, we'll ignore this requirement.
 *
 * ??? We need some mechanism to make sure that multiple ACQUIRE messages
 * don't cause a whole bunch of redundant negotiations.
 */
static void
process_pfkey_acquire(pfkey_buf *buf, struct sadb_ext *extensions[SADB_EXT_MAX + 1])
{
    struct sadb_address *srcx = (void *) extensions[SADB_EXT_ADDRESS_SRC];
    struct sadb_address *dstx = (void *) extensions[SADB_EXT_ADDRESS_DST];
    ip_address src, dst;
    ip_subnet ours, his;
    err_t ugh = NULL;

    /* assumption: we're only catching our own outgoing packets
     * so source is our end and destination is the other end.
     * Verifying this is not actually convenient.
     *
     * This stylized control structure yields a complaint or
     * desired results.  For compactness, a pointer value is
     * treated as a boolean.  Logically, the structure is:
     * keep going as long as things are OK.
     */
    if (buf->msg.sadb_msg_pid == 0	/* we only wish to hear from kernel */
    && !(ugh = sockaddr_to_ip_address((struct sockaddr *)(void *)&srcx[1], &src))
    && !(ugh = sockaddr_to_ip_address((struct sockaddr *)(void *)&dstx[1], &dst))
    && !(ugh = addrtypeof(&src) == addrtypeof(&dst)? NULL : "conflicting address types")
    && !(ugh = addrtosubnet(&src, &ours))
    && !(ugh = addrtosubnet(&dst, &his)))
	record_and_initiate_opportunistic(&ours, &his);

    if (ugh != NULL)
	log("SADB_ACQUIRE message from KLIPS malformed: %s", ugh);

}

/* Handle PF_KEY messages from the kernel that are not dealt with
 * synchronously.  In other words, all but responses to PF_KEY messages
 * that we sent.
 */
static void
pfkey_async(pfkey_buf *buf)
{
    struct sadb_ext *extensions[SADB_EXT_MAX + 1];

    if (pfkey_msg_parse(&buf->msg, NULL, extensions, EXT_BITS_OUT))
    {
	log("pfkey_async:"
	    " unparseable PF_KEY message:"
	    " %s len=%d, errno=%d, seq=%d, pid=%d; message ignored"
	    , sparse_val_show(pfkey_type_names, buf->msg.sadb_msg_type)
	    , buf->msg.sadb_msg_len
	    , buf->msg.sadb_msg_errno
	    , buf->msg.sadb_msg_seq
	    , buf->msg.sadb_msg_pid);
    }
    else
    {
	DBG(DBG_CONTROL | DBG_KLIPS, DBG_log("pfkey_async:"
	    " %s len=%u, errno=%u, satype=%u, seq=%u, pid=%u"
	    , sparse_val_show(pfkey_type_names, buf->msg.sadb_msg_type)
	    , buf->msg.sadb_msg_len
	    , buf->msg.sadb_msg_errno
	    , buf->msg.sadb_msg_satype
	    , buf->msg.sadb_msg_seq
	    , buf->msg.sadb_msg_pid));

	switch (buf->msg.sadb_msg_type)
	{
	case SADB_REGISTER:
	    process_pfkey_register_response(buf);
	    break;
	case SADB_ACQUIRE:
	    /* to simulate loss of ACQUIRE, delete this call */
	    process_pfkey_acquire(buf, extensions);
	    break;
#ifdef NAT_TRAVERSAL
	case SADB_X_NAT_T_NEW_MAPPING:
	    process_pfkey_nat_t_new_mapping(&(buf->msg), extensions);
	    break;
#endif
	default:
	    /* ignored */
	    break;
	}
    }
}

/* asynchronous messages from our queue */
void
pfkey_dequeue(void)
{
    while (pfkey_iq_head != NULL)
    {
	pfkey_item *it = pfkey_iq_head;

	pfkey_async(&it->buf);
	pfkey_iq_head = it->next;
	pfree(it);
    }

    /* Handle any orphaned holds, but only if no pfkey input is pending.
     * For each, we initiate Opportunistic.
     * note: we don't need to advance the pointer because
     * record_and_initiate_opportunistic will remove the current
     * record each time we call it.
     */
    while (orphaned_holds != NULL && !pfkey_input_ready())
	record_and_initiate_opportunistic(&orphaned_holds->ours
	    , &orphaned_holds->his);

}

/* asynchronous messages directly from PF_KEY socket */
void
pfkey_event(void)
{
    pfkey_buf buf;

    if (pfkey_get(&buf))
	pfkey_async(&buf);
}

#endif /* KLIPS */

/* Generate Unique SPI numbers.
 *
 * The specs say that the number must not be less than IPSEC_DOI_SPI_MIN.
 * Pluto generates numbers not less than IPSEC_DOI_SPI_OUR_MIN,
 * reserving numbers in between for manual keying (but we cannot so
 * restrict numbers generated by our peer).
 * XXX This should be replaced by a call to the kernel when
 * XXX we get an API.
 * The returned SPI is in network byte order.
 * We use a random number as the initial SPI so that there is
 * a good chance that different Pluto instances will choose
 * different SPIs.  This is good for two reasons.
 * - the keying material for the initiator and responder only
 *   differs if the SPIs differ.
 * - if Pluto is restarted, it would otherwise recycle the SPI
 *   numbers and confuse everything.  When the kernel generates
 *   SPIs, this will no longer matter.
 * We then allocate numbers sequentially.  Thus we don't have to
 * check if the number was previously used (assuming that no
 * SPI lives longer than 4G of its successors).
 */
ipsec_spi_t
get_ipsec_spi(ipsec_spi_t avoid)
{
    static ipsec_spi_t spi = 0;	/* host order, so not returned directly! */

    spi++;
    while (spi < IPSEC_DOI_SPI_OUR_MIN || spi == ntohl(avoid))
	get_rnd_bytes((u_char *)&spi, sizeof(spi));

    DBG(DBG_CONTROL,
	{
	    ipsec_spi_t spi_net = htonl(spi);

	    DBG_dump("generate SPI:", (u_char *)&spi_net, sizeof(spi_net));
	});

    return htonl(spi);
}

/* Generate Unique CPI numbers.
 * The result is returned as an SPI (4 bytes) in network order!
 * The real bits are in the nework-low-order 2 bytes.
 * Modelled on get_ipsec_spi, but range is more limited:
 * 256-61439.
 * If we can't find one easily, return 0 (a bad SPI,
 * no matter what order) indicating failure.
 */
ipsec_spi_t
get_my_cpi(void)
{
    static cpi_t
	first_busy_cpi = 0,
	latest_cpi;

    while (!(IPCOMP_FIRST_NEGOTIATED <= first_busy_cpi && first_busy_cpi < IPCOMP_LAST_NEGOTIATED))
    {
	get_rnd_bytes((u_char *)&first_busy_cpi, sizeof(first_busy_cpi));
	latest_cpi = first_busy_cpi;
    }

    latest_cpi++;

    if (latest_cpi == first_busy_cpi)
	find_my_cpi_gap(&latest_cpi, &first_busy_cpi);

    if (latest_cpi > IPCOMP_LAST_NEGOTIATED)
	latest_cpi = IPCOMP_FIRST_NEGOTIATED;

    return htonl((ipsec_spi_t)latest_cpi);
}

/* invoke the updown script to do the routing and firewall commands required
 *
 * The user-specified updown script is run.  Parameters are fed to it in
 * the form of environment variables.  All such environment variables
 * have names starting with "PLUTO_".
 *
 * The operation to be performed is specified by PLUTO_VERB.  This
 * verb has a suffix "-host" if the client on this end is just the
 * host; otherwise the suffix is "-client".  If the address family
 * of the host is IPv6, an extra suffix of "-v6" is added.
 *
 * "prepare-host" and "prepare-client" are used to delete a route
 * that may exist (due to forces outside of Pluto).  It is used to
 * prepare for pluto creating a route.
 *
 * "route-host" and "route-client" are used to install a route.
 * Since routing is based only on destination, the PLUTO_MY_CLIENT_*
 * values are probably of no use (using them may signify a bug).
 *
 * "unroute-host" and "unroute-client" are used to delete a route.
 * Since routing is based only on destination, the PLUTO_MY_CLIENT_*
 * values are probably of no use (using them may signify a bug).
 *
 * "up-host" and "up-client" are run when an eroute is added (not replaced).
 * They are useful for adjusting a firewall: usually for adding a rule
 * to let processed packets flow between clients.  Note that only
 * one eroute may exist for a pair of client subnets but inbound
 * IPsec SAs may persist without an eroute.
 *
 * "down-host" and "down-client" are run when an eroute is deleted.
 * They are useful for adjusting a firewall.
 */

#ifndef DEFAULT_UPDOWN
# define DEFAULT_UPDOWN	"ipsec _updown"
#endif

static bool
do_command(struct connection *c, const char *verb)
{
    char cmd[1536];	/* arbitrary limit on shell command length */
    const char *verb_suffix;

    /* figure out which verb suffix applies */
    {
	const char *hs, *cs;

	switch (addrtypeof(&c->this.host_addr))
	{
	    case AF_INET:
		hs = "-host";
		cs = "-client";
		break;
	    case AF_INET6:
		hs = "-host-v6";
		cs = "-client-v6";
		break;
	    default:
		loglog(RC_LOG_SERIOUS, "unknown address family");
		return FALSE;
	}
	verb_suffix = subnetishost(&c->this.client) && addrinsubnet(&c->this.host_addr, &c->this.client)
	    ? hs : cs;
    }

    /* form the command string */
    {
	const ip_subnet *epc = EffectivePeerClient(c);
	char
	    nexthop_str[ADDRTOT_BUF],
	    me_str[ADDRTOT_BUF],
	    myid_str[IDTOA_BUF],
	    myclient_str[SUBNETTOT_BUF],
	    myclientnet_str[ADDRTOT_BUF],
	    myclientmask_str[ADDRTOT_BUF],
	    peer_str[ADDRTOT_BUF],
	    peerid_str[IDTOA_BUF],
	    peerclient_str[SUBNETTOT_BUF],
	    peerclientnet_str[ADDRTOT_BUF],
	    peerclientmask_str[ADDRTOT_BUF];
	ip_address ta;

	addrtot(&c->this.host_nexthop, 0, nexthop_str, sizeof(nexthop_str));

	addrtot(&c->this.host_addr, 0, me_str, sizeof(me_str));
	idtoa(&c->this.id, myid_str, sizeof(myid_str));
	subnettot(&c->this.client, 0, myclient_str, sizeof(myclientnet_str));
	networkof(&c->this.client, &ta);
	addrtot(&ta, 0, myclientnet_str, sizeof(myclientnet_str));
	maskof(&c->this.client, &ta);
	addrtot(&ta, 0, myclientmask_str, sizeof(myclientmask_str));

	addrtot(&c->that.host_addr, 0, peer_str, sizeof(peer_str));
	idtoa(&c->that.id, peerid_str, sizeof(peerid_str));
	subnettot(epc, 0, peerclient_str, sizeof(peerclientnet_str));
	networkof(epc, &ta);
	addrtot(&ta, 0, peerclientnet_str, sizeof(peerclientnet_str));
	maskof(epc, &ta);
	addrtot(&ta, 0, peerclientmask_str, sizeof(peerclientmask_str));

#ifdef SIMPLE_SCRIPTS
# define SE "setenv "
# define EQ " "
# define NL "\n"
#else
# define SE ""
# define EQ "="
# define NL " "
#endif
	if (-1 == snprintf(cmd, sizeof(cmd),
#ifdef SIMPLE_SCRIPTS
	    "#!/bin/sh" NL
#endif
 	    /* change VERSION when interface spec changes */
	    SE "PLUTO_VERSION"          EQ "'1.1'" NL
	    SE "PLUTO_VERB"             EQ "'%s%s'" NL
	    SE "PLUTO_CONNECTION"       EQ "'%s'" NL
	    SE "PLUTO_NEXT_HOP"         EQ "'%s'" NL
	    SE "PLUTO_INTERFACE"        EQ "'%s'" NL
	    SE "PLUTO_ME"               EQ "'%s'" NL
	    SE "PLUTO_MY_ID"            EQ "'%s'" NL
	    SE "PLUTO_MY_CLIENT"        EQ "'%s'" NL
	    SE "PLUTO_MY_CLIENT_NET"    EQ "'%s'" NL
	    SE "PLUTO_MY_CLIENT_MASK"   EQ "'%s'" NL
	    SE "PLUTO_MY_PORT"          EQ "'%u'" NL
	    SE "PLUTO_MY_PROTOCOL"      EQ "'%u'" NL
	    SE "PLUTO_PEER"             EQ "'%s'" NL
	    SE "PLUTO_PEER_ID"          EQ "'%s'" NL
	    SE "PLUTO_PEER_CLIENT"      EQ "'%s'" NL
	    SE "PLUTO_PEER_CLIENT_NET"  EQ "'%s'" NL
	    SE "PLUTO_PEER_CLIENT_MASK" EQ "'%s'" NL
	    SE "PLUTO_PEER_PORT"        EQ "'%u'" NL
	    SE "PLUTO_PEER_PROTOCOL"    EQ "'%u'" NL
	    "%s"                                  NL	/* actual script */
#ifndef SIMPLE_SCRIPTS
	    "2>&1 "	/* capture stderr along with stdout */
#endif
	    , verb, verb_suffix
	    , c->name
	    , nexthop_str
	    , c->interface->vname
	    , me_str
	    , myid_str
	    , myclient_str
	    , myclientnet_str
	    , myclientmask_str
	    , c->this.port
	    , c->this.protocol
	    , peer_str
	    , peerid_str
	    , peerclient_str
	    , peerclientnet_str
	    , peerclientmask_str
	    , c->that.port
	    , c->that.protocol
	    , c->this.updown == NULL? DEFAULT_UPDOWN : c->this.updown))
	{
	    loglog(RC_LOG_SERIOUS, "%s%s command too long!", verb, verb_suffix);
	    return FALSE;
	}
    }

    DBG(DBG_CONTROL, DBG_log("executing %s%s: %s"
	, verb, verb_suffix, cmd));

#ifdef KLIPS

#ifdef SIMPLE_SCRIPTS
    if (!no_klips)
    {
    	const char *temp_name = "/var/log/pluto_script";
	int fd;

	unlink(temp_name);
    	fd = open(temp_name, O_WRONLY|O_CREAT|O_TRUNC, 0777);
	if (fd == -1) {
	    loglog(RC_LOG_SERIOUS, "unable to open %s", temp_name);
	    return FALSE;
	}
	if (write(fd, cmd, strlen(cmd)) != strlen(cmd)) {
	    loglog(RC_LOG_SERIOUS, "unable to write to %s", temp_name);
	    return FALSE;
	}
	if (close(fd) == -1) {
	    loglog(RC_LOG_SERIOUS, "unable to close %s", temp_name);
	    return FALSE;
	}
	strncpy(cmd, temp_name, sizeof(cmd));
    }
#endif

    if (!no_klips)
    {
	/* invoke the script, catching stderr and stdout
	 * It may be of concern that some file descriptors will
	 * be inherited.  For the ones under our control, we
	 * have done fcntl(fd, F_SETFD, FD_CLOEXEC) to prevent this.
	 * Any used by library routines (perhaps the resolver or syslog)
	 * will remain.
	 */
	FILE *f = popen(cmd, "r");
	
	if (f == NULL)
	{
	    loglog(RC_LOG_SERIOUS, "unable to popen %s%s command", verb, verb_suffix);
#ifdef SIMPLE_SCRIPTS
	    unlink(cmd); /* don't need it now */
#endif
	    return FALSE;
	}

	/* log any output */
	for (;;)
	{
	    /* if response doesn't fit in this buffer, it will be folded */
	    char resp[256];

	    if (fgets(resp, sizeof(resp), f) == NULL)
	    {
		if (ferror(f))
		{
		    log_errno((e, "fgets failed on output of %s%s command"
			, verb, verb_suffix));
#ifdef SIMPLE_SCRIPTS
		    unlink(cmd); /* don't need it now */
#endif
		    return FALSE;
		}
		else
		{
		    passert(feof(f));
		    break;
		}
	    }
	    else
	    {
		char *e = resp + strlen(resp);

		if (e > resp && e[-1] == '\n')
		    e[-1] = '\0';	/* trim trailing '\n' */
		//log("%s%s output: %s", verb, verb_suffix, resp);
	    }
	}
	
#ifdef SIMPLE_SCRIPTS
	unlink(cmd); /* don't need it now */
#endif
	/* report on and react to return code */
	{
	    int r = pclose(f);

	    if (r == -1)
	    {
		if (errno ==  ECHILD)
 			return TRUE;
		log_errno((e, "pclose failed for %s%s command"
		    , verb, verb_suffix));
		return FALSE;
	    }
	    else if (WIFEXITED(r))
	    {
		if (WEXITSTATUS(r) != 0)
		{
		    loglog(RC_LOG_SERIOUS, "%s%s command exited with status %d"
			, verb, verb_suffix, WEXITSTATUS(r));
		    return FALSE;
		}
	    }
	    else if (WIFSIGNALED(r))
	    {
		loglog(RC_LOG_SERIOUS, "%s%s command exited with signal %d"
		    , verb, verb_suffix, WTERMSIG(r));
		return FALSE;
	    }
	    else
	    {
		loglog(RC_LOG_SERIOUS, "%s%s command exited with unknown status %d"
		    , verb, verb_suffix, r);
		return FALSE;
	    }
	}
    }
#endif /* KLIPS */
    return TRUE;
}

/* Check that we can route (and eroute).  Diagnose if we cannot. */

static bool
could_route(struct connection *c)
{
    struct connection *ero	/* who, if anyone, owns our eroute? */
	, *ro = route_owner(c, &ero);	/* who owns our route? */

#if 0
    /* if this is a Road Warrior template, we cannot route.
     * Opportunistic template is OK.
     */
    if (c->kind == CK_TEMPLATE && !(c->policy & POLICY_OPPO))
    {
	loglog(RC_ROUTE, "cannot route Road Warrior template");
	return FALSE;
    }
#endif

    /* if we don't know nexthop, we cannot route */
    if (isanyaddr(&c->this.host_nexthop))
    {
	loglog(RC_ROUTE, "cannot route connection without knowing our nexthop");
	return FALSE;
    }

    /* if routing would affect IKE messages, reject */
    if (!no_klips
#ifdef NAT_TRAVERSAL
    && c->this.host_port != NAT_T_IKE_FLOAT_PORT
#endif
    && c->this.host_port != IKE_UDP_PORT
    && addrinsubnet(&c->that.host_addr, EffectivePeerClient(c)))
    {
	loglog(RC_LOG_SERIOUS, "cannot install route: peer is within its client");
	return FALSE;
    }

    /* If there is already a route for peer's client subnet
     * and it disagrees about interface or nexthop, we cannot steal it.
     * Note: if this connection is already routed (perhaps for another
     * state object), the route will agree.
     * This is as it should be -- it will arise during rekeying.
     */
    if (ro != NULL && !routes_agree(ro, c))
    {
	loglog(RC_LOG_SERIOUS, "cannot route -- route already in use for \"%s\""
	    , ro->name);
	return FALSE;	/* another connection already using the eroute */
    }

#ifdef KLIPS
    /* if there is an eroute for another connection, there is a problem */
    if (ero != NULL && ero != c)
    {
	char inst[CONN_INST_BUF];

	fmt_conn_instance(ero, inst);

	loglog(RC_LOG_SERIOUS
	    , "cannot install eroute -- it is in use for \"%s\"%s #%lu"
	    , ero->name, inst, ero->eroute_owner);
	return FALSE;	/* another connection already using the eroute */
    }
#endif /* KLIPS */
    return TRUE;
}

bool
trap_connection(struct connection *c)
{
    /* RT_ROUTED_TUNNEL is treated specially: we don't override
     * because we don't want to lose track of the IPSEC_SAs etc.
     */
    return could_route(c)
	&& (c->routing == RT_ROUTED_TUNNEL || route_and_eroute(c, NULL));
}

/* delete any eroute for a connection and unroute it if route isn't shared */
void
unroute_connection(struct connection *c)
{
    enum routing_t cr = c->routing;

    if (erouted(cr))
    {
	passert(cr != RT_ROUTED_TUNNEL);	/* cannot handle a live one */
#ifdef KLIPS
	shunt_eroute(c, ERO_DELETE, "delete");
#endif
    }

    c->routing = RT_UNROUTED;	/* do now so route_owner won't find us */

    /* only unroute if no other connection shares it */
    if (routed(cr)
    && route_owner(c, NULL) == NULL)
	(void) do_command(c, "unroute");
}


#ifdef KLIPS

static void
set_text_said(char *text_said, const ip_address *dst, ipsec_spi_t spi, int proto)
{
    ip_said said;

    initsaid(dst, spi, proto, &said);
    satot(&said, 0, text_said, SATOT_BUF);
}

static bool
pfkey_build(int error
, const char *description
, const char *text_said
, struct sadb_ext *extensions[SADB_EXT_MAX + 1])
{
    if (error == 0)
    {
	return TRUE;
    }
    else
    {
	loglog(RC_LOG_SERIOUS, "building of %s %s failed, code %d"
	    , description, text_said, error);
	pfkey_extensions_free(extensions);
	return FALSE;
    }
}

/* pfkey_extensions_init + pfkey_build + pfkey_msg_hdr_build */
static bool
pfkey_msg_start(u_int8_t msg_type
, u_int8_t satype
, const char *description
, const char *text_said
, struct sadb_ext *extensions[SADB_EXT_MAX + 1])
{
    pfkey_extensions_init(extensions);
    return pfkey_build(pfkey_msg_hdr_build(&extensions[0], msg_type
	    , satype, 0, ++pfkey_seq, pid)
	, description, text_said, extensions);
}

/* pfkey_build + pfkey_address_build */
static bool
pfkeyext_address(u_int16_t exttype
, const ip_address *address
, const char *description
, const char *text_said
, struct sadb_ext *extensions[SADB_EXT_MAX + 1])
{
    /* the following variable is only needed to silence
     * a warning caused by the fact that the argument
     * to sockaddrof is NOT pointer to const!
     */
    ip_address t = *address;

    return pfkey_build(pfkey_address_build(extensions + exttype
	    , exttype, 0, 0, sockaddrof(&t))
	, description, text_said, extensions);
}

/* Finish (building, sending, accepting response for) PF_KEY message.
 * If response isn't NULL, the response from the kernel will be
 * placed there (and its errno field will not be examined).
 * Returns TRUE iff all appears well.
 */
static bool
finish_pfkey_msg(struct sadb_ext *extensions[SADB_EXT_MAX + 1]
, const char *description
, const char *text_said
, pfkey_buf *response)
{
    struct sadb_msg *pfkey_msg;
    bool success = TRUE;
    int error = pfkey_msg_build(&pfkey_msg, extensions, EXT_BITS_IN);

    if (error != 0)
    {
	loglog(RC_LOG_SERIOUS, "pfkey_msg_build of %s %s failed, code %d"
	    , description, text_said, error);
	success = FALSE;
    }
    else
    {
	size_t len = pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN;

	DBG(DBG_KLIPS,
	    DBG_log("finish_pfkey_msg: %s message %u for %s %s"
		, sparse_val_show(pfkey_type_names, pfkey_msg->sadb_msg_type)
		, pfkey_msg->sadb_msg_seq
		, description, text_said);
	    DBG_dump(NULL, (void *) pfkey_msg, len));

	if (!no_klips)
	{
	    ssize_t r = write(pfkeyfd, pfkey_msg, len);

	    if (r != (ssize_t)len)
	    {
		if (r < 0)
		{
		    if (!strcmp("SADB_DELETE", sparse_val_show(pfkey_type_names
			    , pfkey_msg->sadb_msg_type))) {
			    log("This connection is probably expecting a road warrior or the IP address"
		        	" of the remote host's DNS hostname has changed");
		    }
		    log_errno((e
			, "pfkey write() of %s message %u"
			  " for %s %s failed"
			, sparse_val_show(pfkey_type_names
			    , pfkey_msg->sadb_msg_type)
			, pfkey_msg->sadb_msg_seq
			, description, text_said));
		}
		else
		{
		    loglog(RC_LOG_SERIOUS
			, "ERROR: pfkey write() of %s message %u"
			  " for %s %s truncated: %ld instead of %ld"
			, sparse_val_show(pfkey_type_names
			    , pfkey_msg->sadb_msg_type)
			, pfkey_msg->sadb_msg_seq
			, description, text_said
			, (long)r, (long)len);
		}
		success = FALSE;

		/* if we were compiled with debugging, but we haven't already
		 * dumped the KLIPS command, do so.
		 */
#ifdef DEBUG
		if ((cur_debugging & DBG_KLIPS) == 0)
		    DBG_dump(NULL, (void *) pfkey_msg, len);
#endif
	    }
	    else
	    {
		/* Check response from KLIPS.
		 * It ought to be an echo, perhaps with additional info.
		 * If the caller wants it, response will point to space.
		 */
		pfkey_buf b;
		pfkey_buf *bp = response != NULL? response : &b;

		if (!pfkey_get_response(bp, ((struct sadb_msg *) extensions[0])->sadb_msg_seq))
		{
		    loglog(RC_LOG_SERIOUS
			, "ERROR: no response to our PF_KEY %s message for %s %s"
			, sparse_val_show(pfkey_type_names, pfkey_msg->sadb_msg_type)
			, description, text_said);
		    success = FALSE;
		}
		else if (pfkey_msg->sadb_msg_type != bp->msg.sadb_msg_type)
		{
		    loglog(RC_LOG_SERIOUS
			, "FreeS/WAN ERROR: response to our PF_KEY %s message for %s %s was of wrong type (%s)"
			, sparse_name(pfkey_type_names, pfkey_msg->sadb_msg_type)
			, description, text_said
			, sparse_val_show(pfkey_type_names, bp->msg.sadb_msg_type));
		    success = FALSE;
		}
		else if (response == NULL && bp->msg.sadb_msg_errno != 0)
		{
		    /* KLIPS is signalling a problem */
		    loglog(RC_LOG_SERIOUS
			, "ERROR: PF_KEY %s response for %s %s included errno %u: %s"
			, sparse_val_show(pfkey_type_names, pfkey_msg->sadb_msg_type)
			, description, text_said
			, (unsigned) bp->msg.sadb_msg_errno
			, strerror(bp->msg.sadb_msg_errno));
		    success = FALSE;
		}
	    }
	}
    }

    /* all paths must exit this way to free resources */
    pfkey_extensions_free(extensions);
    pfkey_msg_free(&pfkey_msg);
    return success;
}

/*  register SA types that can be negotiated */
static void
pfkey_register_proto(uint8_t satype, const char *satypename)
{
    struct sadb_ext *extensions[SADB_EXT_MAX + 1];
    pfkey_buf pfb;

    if (!(pfkey_msg_start(SADB_REGISTER
      , satype
      , satypename, NULL, extensions)
    && finish_pfkey_msg(extensions, satypename, "", &pfb)))
    {
	/* ??? should this be loglog */
	log("no KLIPS support for %s", satypename);
    }
    else
    {
	process_pfkey_register_response(&pfb);
	DBG(DBG_KLIPS,
	    DBG_log("%s registered with kernel.", satypename));
    }
}

void
pfkey_register(void)
{
    pfkey_register_proto(SADB_SATYPE_AH, "AH");
    pfkey_register_proto(SADB_SATYPE_ESP, "ESP");
    can_do_IPcomp = FALSE;  /* until we get a response from KLIPS */
    pfkey_register_proto(SADB_X_SATYPE_COMP, "IPCOMP");
    pfkey_register_proto(SADB_X_SATYPE_IPIP, "IPIP");
}

/* find an entry in the bare_shunt table.
 * Trick: return a pointer to the pointer to the entry;
 * this allows the entry to be deleted.
 */
static struct bare_shunt **
bare_shunt_ptr(const ip_subnet *ours, const ip_subnet *his)
{
    struct bare_shunt *p, **pp;

    for (pp = &bare_shunts; (p = *pp) != NULL; pp = &p->next)
	if (samesubnet(ours, &p->ours)
	&& samesubnet(his, &p->his))
	    return pp;
    return NULL;
}

/* free a bare_shunt entry, given a pointer to the pointer */
static void
free_bare_shunt(struct bare_shunt **pp)
{
    struct bare_shunt *p = *pp;

    *pp = p->next;
    DBG_bare_shunt("delete", p);
    pfree(p);
}

/* Setup an IPsec route entry. Code taken from addrt.c.
 * We are only dealing with outbound SAs.
 * op is one of the ERO_* operators.
 */

static bool
raw_eroute(const ip_address *this_host, const ip_subnet *this_client
, const ip_address *that_host, const ip_subnet *that_client
, ipsec_spi_t spi, unsigned int proto, unsigned int satype
, unsigned int op, const char *opname USED_BY_DEBUG)
{
    struct sadb_ext *extensions[SADB_EXT_MAX + 1];
    ip_address
    	sflow_ska,
    	dflow_ska,
    	smask_ska,
    	dmask_ska;
    char text_said[SATOT_BUF];

    set_text_said(text_said, that_host, spi, proto);

    networkof(this_client, &sflow_ska);
    maskof(this_client, &smask_ska);

    networkof(that_client, &dflow_ska);
    maskof(that_client, &dmask_ska);

    DBG(DBG_CONTROL | DBG_KLIPS,
	{
	    char mybuf[SUBNETTOT_BUF];
	    char peerbuf[SUBNETTOT_BUF];

	    subnettot(this_client, 0, mybuf, sizeof(mybuf));
	    subnettot(that_client, 0, peerbuf, sizeof(peerbuf));
	    DBG_log("%s eroute %s -> %s => %s"
		, opname, mybuf, peerbuf, text_said);
	});

    return pfkey_msg_start(op & ERO_MASK, satype
	, "pfkey_msg_hdr flow", text_said, extensions)

    && (op == ERO_DELETE
	|| (pfkey_build(pfkey_sa_build(&extensions[SADB_EXT_SA]
	    	, SADB_EXT_SA
		, spi	/* in network order */
	    	, 0, 0, 0, 0, op >> ERO_FLAG_SHIFT)
	    , "pfkey_sa add flow", text_said, extensions)

	    && pfkeyext_address(SADB_EXT_ADDRESS_SRC, this_host
		, "pfkey_addr_s add flow", text_said, extensions)

	    && pfkeyext_address(SADB_EXT_ADDRESS_DST, that_host
		, "pfkey_addr_d add flow", text_said, extensions)))

    && pfkeyext_address(SADB_X_EXT_ADDRESS_SRC_FLOW, &sflow_ska
	, "pfkey_addr_sflow", text_said, extensions)

    && pfkeyext_address(SADB_X_EXT_ADDRESS_DST_FLOW, &dflow_ska
	, "pfkey_addr_dflow", text_said, extensions)

    && pfkeyext_address(SADB_X_EXT_ADDRESS_SRC_MASK, &smask_ska
	, "pfkey_addr_smask", text_said, extensions)

    && pfkeyext_address(SADB_X_EXT_ADDRESS_DST_MASK, &dmask_ska
	, "pfkey_addr_dmask", text_said, extensions)

    && finish_pfkey_msg(extensions, "flow", text_said, NULL);
}

/* Replace (or delete) a shunt that is in the bare_shunts table.
 * Issues the PF_KEY commands and updates the bare_shunts table.
 */
bool
replace_bare_shunt(const ip_address *src, const ip_address *dst
, ipsec_spi_t shunt_spi	/* in host order! */
, bool repl, const char *opname)
{
    ip_subnet this_client, that_client;
    const ip_address *null_host = aftoinfo(addrtypeof(src))->any;
    unsigned int op = repl? ERO_REPLACE : ERO_DELETE;

    passert(addrtypeof(src) == addrtypeof(dst));
    happy(addrtosubnet(src, &this_client));
    happy(addrtosubnet(dst, &that_client));

    if (raw_eroute(null_host, &this_client, null_host, &that_client
    , htonl(shunt_spi), SA_INT, SADB_X_SATYPE_INT, op, opname))
    {
	struct bare_shunt **bs_pp = bare_shunt_ptr(&this_client, &that_client);

	if (repl)
	{
	    /* change over to new bare eroute */
	    struct bare_shunt *bs = *bs_pp;

	    bs->said.spi = htonl(shunt_spi);
	    bs->said.proto = SA_INT;
	    bs->said.dst = *null_host;
	    bs->count = 0;
	    bs->last_activity = now();
	    DBG_bare_shunt("change", bs);
	}
	else
	{
	    /* delete bare eroute */
	    free_bare_shunt(bs_pp);
	}
	return TRUE;
    }
    else
    {
	return FALSE;
    }
}

static bool
eroute_connection(struct connection *c
, ipsec_spi_t spi, unsigned int proto, unsigned int satype
, unsigned int op, const char *opname)
{
    const ip_address *peer = &c->that.host_addr;

    return raw_eroute(&c->this.host_addr, &c->this.client
	, proto == SA_INT? aftoinfo(addrtypeof(peer))->any : peer
	, EffectivePeerClient(c)
	, spi, proto, satype, op, opname);
}

/* assign a bare hold to a connection */

bool
assign_hold(struct connection *c
, const ip_address *src, const ip_address *dst)
{
    /* either the automatically installed %hold eroute is broad enough
     * or we try to add a broader one and delete the automatic one.
     * Beware: this %hold might be already handled, but still squeak
     * through because of a race.
     */
    enum routing_t ro = c->routing	/* routing, old */
	, rn = ro;	/* routing, new */

    /* figure out what routing should become */
    switch (ro)
    {
    case RT_UNROUTED:
	rn = RT_UNROUTED_HOLD;
	break;
    case RT_ROUTED_PROSPECTIVE:
	rn = RT_ROUTED_HOLD;
	break;
    default:
	/* no change: this %hold is old news and should just be deleted */
	break;
    }

    if (subnetishost(&c->this.client) && subnetishost(&c->that.client))
    {
	/* although %hold is appropriately broad, it will no longer be bare
	 * so we must ditch it from the bare table.
	 */
	free_bare_shunt(bare_shunt_ptr(&c->this.client, &c->that.client));
    }
    else
    {
	/* we need a broad %hold, not the narrow one.
	 * First we ensure that there is a broad %hold.
	 * There may already be one (race condition): no need to create one.
	 * There may already be a %trap: replace it.
	 * There may not be any broad eroute: add %hold.
	 * Once the broad %hold is in place, delete the narrow one.
	 */
	if (rn != ro)
	{
	    if (erouted(ro)
	    ? !eroute_connection(c, htonl(SPI_HOLD), SA_INT, SADB_X_SATYPE_INT
		, ERO_REPLACE, "replace %trap with broad %hold")
	    : !eroute_connection(c, htonl(SPI_HOLD), SA_INT, SADB_X_SATYPE_INT
		, ERO_ADD, "add broad %hold"))
	    {
		return FALSE;
	    }
	}
	if (!replace_bare_shunt(src, dst, SPI_HOLD, FALSE, "delete narrow %hold"))
	    return FALSE;
    }
    c->routing = rn;
    return TRUE;
}

/* install or remove eroute for SA Group */
static bool
sag_eroute(struct state *st, unsigned op, const char *opname)
{
    struct connection *c = st->st_connection;
    unsigned int
    	inner_proto,
	inner_satype;
    ipsec_spi_t inner_spi;

    /* figure out the SPI and protocol (in two forms)
     * for the innermost transformation.
     */

    if (st->st_ah.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL
    || st->st_esp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL
    || st->st_ipcomp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
    {
	inner_spi = st->st_tunnel_out_spi;
	inner_proto = SA_IPIP;
	inner_satype = SADB_X_SATYPE_IPIP;
    }
    else if (st->st_ipcomp.present)
    {
	inner_spi = st->st_ipcomp.attrs.spi;
	inner_proto = SA_COMP;
	inner_satype = SADB_X_SATYPE_COMP;
    }
    else if (st->st_esp.present)
    {
	inner_spi = st->st_esp.attrs.spi;
	inner_proto = SA_ESP;
	inner_satype = SADB_SATYPE_ESP;
    }
    else if (st->st_ah.present)
    {
	inner_spi = st->st_ah.attrs.spi;
	inner_proto = SA_AH;
	inner_satype = SADB_SATYPE_AH;
    }
    else
    {
	impossible();	/* no transform at all! */
    }

    return eroute_connection(c
	, inner_spi, inner_proto, inner_satype
	, op, opname);
}

/* Add/replace/delete a shunt eroute.
 * Such an eroute determines the fate of packets without the use
 * of any SAs.  These are defaults, in effect.
 * If a negotiation has not been attempted, use %trap.
 * If negotiation has failed, the choice between %trap/%pass/%drop/%reject
 * is specified in the policy of connection c.
 */
static bool
shunt_eroute(struct connection *c, unsigned int op, const char *opname)
{
    /* We are constructing a special SAID for the eroute.
     * The destination doesn't seem to matter, but the family does.
     * The protocol is SA_INT -- mark this as shunt.
     * The satype has no meaning, but is required for PF_KEY header!
     * The SPI signifies the kind of shunt.
     */

    /* note: these are in host order :-( */
    static ipsec_spi_t shunt_spi[] = { SPI_TRAP /* */
	, SPI_PASS	/* --pass */
	, SPI_DROP	/* --drop */
	, SPI_REJECT };	/* --pass --drop */

    ipsec_spi_t spi = c->routing == RT_ROUTED_PROSPECTIVE? SPI_TRAP
	: shunt_spi[(c->policy & POLICY_OPPO_MASK) >> POLICY_OPPO_SHIFT];

    return eroute_connection(c, htonl(spi), SA_INT, SADB_X_SATYPE_INT, op, opname);
}

/* scan /proc/net/ipsec_eroute every once in a while, looking for:
 *
 * - %hold shunts of which Pluto isn't aware.  This situation could
 *   be caused by lost ACQUIRE messages.  When found, they will
 *   added to orphan_holds.  This in turn will lead to Opportunistic
 *   initiation.
 *
 * - %pass shunts that haven't been used recently.  These will be
 *   deleted.
 *
 * - (eventually) other shunt eroutes that haven't been used in a while.
 *
 * Here are some sample lines:
 * 10         10.3.2.1.0/24    -> 0.0.0.0/0          => %trap
 * 259        10.3.2.1.115/32  -> 10.19.75.161/32    => tun0x1002@10.19.75.145
 * 71         10.44.73.97/32   -> 0.0.0.0/0          => %trap
 * 4119       10.44.73.97/32   -> 10.114.121.41/32   => %pass
 * Newer versions of KLIPS start each line with a 32-bit packet count.
 * If available, the count is used to detect whether a %pass shunt is in use.
 */
void
scan_proc_shunts(void)
{
    static const char procname[] = "/proc/net/ipsec_eroute";
    FILE *f;
    time_t nw = now();
    int lino;
    struct eroute_info *expired = NULL;

    event_schedule(EVENT_SHUNT_SCAN, SHUNT_SCAN_INTERVAL, NULL);

    /* free any leftover entries: they will be refreshed if still current */
    while (orphaned_holds != NULL)
    {
	struct eroute_info *p = orphaned_holds;

	orphaned_holds = p->next;
	pfree(p);
    }

    /* decode the /proc file.  Don't do anything strenuous to it
     * (certainly no PF_KEY stuff) to minimize the chance that it
     * might change underfoot.
     */

    f = fopen(procname, "r");
    if (f == NULL)
	return;

    /* for each line... */
    for (lino = 1; ; lino++)
    {
	unsigned char buf[1024];	/* should be big enough */
	chunk_t field[10];	/* 10 is loose upper bound */
	chunk_t *ff;	/* fixed fields (excluding optional count) */
	int fi;
	struct eroute_info eri;
	char *cp;
	err_t context = ""
	    , ugh = NULL;

	cp = fgets(buf, sizeof(buf), f);
	if (cp == NULL)
	    break;

	/* break out each field
	 * Note: if there are too many fields, just stop;
	 * it will be diagnosed a little later.
	 */
	for (fi = 0; fi < (int)elemsof(field); fi++)
	{
	    static const char sep[] = " \t\n";	/* field-separating whitespace */
	    size_t w;

	    cp += strspn(cp, sep);	/* find start of field */
	    w = strcspn(cp, sep);	/* find width of field */
	    setchunk(field[fi], cp, w);
	    cp += w;
	    if (w == 0)
		break;
	}

	/* This odd do-hickey is to share error reporting code.
	 * A break will get to that common code.  The setting
	 * of "ugh" and "context" parameterize it.
	 */
	do {
	    /* Old entries have no packet count; new ones do.
	     * check if things are as they should be.
	     */
	    if (fi == 5)
		ff = &field[0];	/* old form, with no count */
	    else if (fi == 6)
		ff = &field[1];	/* new form, with count */
	    else
	    {
		ugh = "has wrong number of fields";
		break;
	    }

	    if (ff[1].len != 2
	    || strncmp(ff[1].ptr, "->", 2) != 0
	    || ff[3].len != 2
	    || strncmp(ff[3].ptr, "=>", 2) != 0)
	    {
		ugh = "is missing -> or =>";
		break;
	    }

	    /* actually digest fields of interest */

	    /* packet count */

	    eri.count = 0;
	    if (ff != field)
	    {
		context = "count field is malformed: ";
		ugh = ttoul(field[0].ptr, field[0].len, 10, &eri.count);
		if (ugh != NULL)
		    break;
	    }

	    /* our client */

	    context = "source subnet field malformed: ";
	    ugh = ttosubnet(ff[0].ptr, ff[0].len, AF_INET, &eri.ours);
	    if (ugh != NULL)
		break;

	    /* his client */

	    context = "source subnet field malformed: ";
	    ugh = ttosubnet(ff[2].ptr, ff[2].len, AF_INET, &eri.his);
	    if (ugh != NULL)
		break;

	    /* SAID */

	    context = "SA ID field malformed: ";
	    ugh = ttosa(ff[4].ptr, ff[4].len, &eri.said);
	} while (FALSE);

	if (ugh != NULL)
	{
	    log("INTERNAL ERROR: %s line %d %s%s"
		, procname, lino, context, ugh);
	    continue;	/* ignore rest of line */
	}

	/* Now we have decoded eroute, let's consider it.
	 * We only care about shunt eroutes.
	 *
	 * %hold: if not known, add to orphaned_holds list for initiation
	 *    because ACQUIRE might have been lost.
	 *
	 * %pass: determine if idle; if so, blast it away.
	 *    Can occur bare (if DNS provided insufficient information)
	 *    or with a connection (failure context).
	 *    Could even be installed by ipsec manual.
	 *
	 * %trap: always welcome.
	 *
	 * others: handling as yet undesigned.  Generally associated
	 *    with a failure context.
	 */
	if (eri.said.proto == SA_INT)
	{
	    switch (ntohl(eri.said.spi))
	    {
	    case SPI_HOLD:
		if (bare_shunt_ptr(&eri.ours, &eri.his) == NULL
		&& shunt_owner(&eri.ours, &eri.his) == NULL)
		{
		    eri.next = orphaned_holds;
		    orphaned_holds = clone_thing(eri, "orphaned %hold");
		}
		break;

	    case SPI_PASS:
		/* nothing sensible to do if we don't have counts */
		if (ff != field)
		{
		    struct bare_shunt **bs_pp
			= bare_shunt_ptr(&eri.ours, &eri.his);

		    if (bs_pp != NULL)
		    {
			struct bare_shunt *bs = *bs_pp;

			if (eri.count != bs->count)
			{
			    bs->count = eri.count;
			    bs->last_activity = nw;
			}
			else if (nw - bs->last_activity > SHUNT_PATIENCE)
			{
			    eri.next = expired;
			    expired = clone_thing(eri, "expired %pass");
			}
		    }
		}
		break;

	    case SPI_DROP:
	    case SPI_REJECT:
	    case SPI_TRAP:
		break;

	    default:
		impossible();
	    }
	}
    }	/* for each line */
    fclose(f);

    /* Now that we've finished processing the /proc file,
     * it is safe to delete the expired %pass shunts.
     */
    while (expired != NULL)
    {
	struct eroute_info *p = expired;
	ip_address src, dst;

	networkof(&p->ours, &src);
	networkof(&p->his, &dst);
	(void) replace_bare_shunt(&src, &dst
	    , SPI_PASS, FALSE, "delete expired %pass");
	expired = p->next;
	pfree(p);
    }
}

static bool
del_spi(ipsec_spi_t spi, int proto
, const ip_address *src, const ip_address *dest)
{
    struct sadb_ext *extensions[SADB_EXT_MAX + 1];
    char text_said[SATOT_BUF];

    set_text_said(text_said, dest, spi, proto);

    DBG(DBG_KLIPS, DBG_log("delete %s", text_said));

    return pfkey_msg_start(SADB_DELETE, proto2satype(proto)
	, "pfkey_msg_hdr delete SA", text_said, extensions)

    && pfkey_build(pfkey_sa_build(&extensions[SADB_EXT_SA]
	    , SADB_EXT_SA
	    , spi	/* in host order */
	    , 0, SADB_SASTATE_MATURE, 0, 0, 0)
	, "pfkey_sa delete SA", text_said, extensions)

    && pfkeyext_address(SADB_EXT_ADDRESS_SRC, src
	, "pfkey_addr_s delete SA", text_said, extensions)

    && pfkeyext_address(SADB_EXT_ADDRESS_DST, dest
	, "pfkey_addr_d delete SA", text_said, extensions)

    && finish_pfkey_msg(extensions, "Delete SA", text_said, NULL);
}

/* Setup a pair of SAs. Code taken from setsa.c and spigrp.c, in
 * ipsec-0.5.
 */

static bool
setup_half_ipsec_sa(struct state *st, bool inbound)
{
    /* Build an inbound or outbound SA */

    struct connection *c = st->st_connection;
    ip_address
	src = inbound? c->that.host_addr : c->this.host_addr,
	dst = inbound? c->this.host_addr : c->that.host_addr;

    /* SPIs, saved for spigrouping or undoing, if necessary */
    ip_said
	said[EM_MAXRELSPIS],
	*said_next = said;

    struct sadb_ext *extensions[SADB_EXT_MAX + 1];
    char text_said[SATOT_BUF];

    /* set up AH SA, if any */

    if (st->st_ah.present)
    {
	ipsec_spi_t ah_spi = inbound? st->st_ah.our_spi : st->st_ah.attrs.spi;
	u_char *ah_dst_keymat = inbound? st->st_ah.our_keymat : st->st_ah.peer_keymat;

	unsigned char authalg;

	switch (st->st_ah.attrs.auth)
	{
	case AUTH_ALGORITHM_HMAC_MD5:
	    authalg = SADB_AALG_MD5HMAC;
	    break;

	case AUTH_ALGORITHM_HMAC_SHA1:
	    authalg = SADB_AALG_SHA1HMAC;
	    break;

	case AUTH_ALGORITHM_KPDK:
	case AUTH_ALGORITHM_DES_MAC:
	default:
	    loglog(RC_LOG_SERIOUS, "%s not implemented yet"
		, enum_show(&auth_alg_names, st->st_ah.attrs.auth));
	    goto fail;
	}

	set_text_said(text_said, &dst, ah_spi, SA_AH);

	if (!(pfkey_msg_start(SADB_ADD, SADB_SATYPE_AH
	    , "pfkey_msg_hdr Add AH SA", text_said, extensions)

	&& pfkey_build(pfkey_sa_build(&extensions[SADB_EXT_SA]
		, SADB_EXT_SA
		, ah_spi	/* in network order */
		, REPLAY_WINDOW, SADB_SASTATE_MATURE, authalg, 0, 0)
	    , "pfkey_sa Add AH SA", text_said, extensions)

	&& pfkeyext_address(SADB_EXT_ADDRESS_SRC, &src
	    , "pfkey_addr_s Add AH SA", text_said, extensions)

	&& pfkeyext_address(SADB_EXT_ADDRESS_DST, &dst
	    , "pfkey_addr_d Add AH SA", text_said, extensions)

	&& pfkey_build(pfkey_key_build(&extensions[SADB_EXT_KEY_AUTH]
		, SADB_EXT_KEY_AUTH, st->st_ah.keymat_len * IPSEC_PFKEYv2_ALIGN
		, ah_dst_keymat)
	    , "pfkey_key_a Add AH SA", text_said, extensions)

	&& finish_pfkey_msg(extensions, "Add AH SA", text_said, NULL)))

	    goto fail;

	initsaid(&dst, ah_spi, SA_AH, said_next);
	said_next++;
    }

    /* set up ESP SA, if any */

    if (st->st_esp.present)
    {
	ipsec_spi_t esp_spi = inbound? st->st_esp.our_spi : st->st_esp.attrs.spi;
	u_char *esp_dst_keymat = inbound? st->st_esp.our_keymat : st->st_esp.peer_keymat;

#if 0+MOVED_TO_alg_info_h
	struct esp_info {
	    u_int8_t transid;	/* negotiated ESP transform */
	    u_int16_t auth;	/* negotiated AUTH */

	    size_t enckeylen;	/* keylength for ESP transform */
	    size_t authkeylen;	/* keylength for AUTH */
	    u_int8_t encryptalg;
	    u_int8_t authalg;
	};
#endif

	const struct esp_info *ei;
	u_int16_t key_len;

	static const struct esp_info esp_info[] = {
	    { ESP_NULL, AUTH_ALGORITHM_HMAC_MD5,
		0, HMAC_MD5_KEY_LEN,
		SADB_EALG_NULL, SADB_AALG_MD5HMAC },
	    { ESP_NULL, AUTH_ALGORITHM_HMAC_SHA1,
		0, HMAC_SHA1_KEY_LEN,
		SADB_EALG_NULL, SADB_AALG_SHA1HMAC },

	    { ESP_DES, AUTH_ALGORITHM_NONE,
		DES_CBC_BLOCK_SIZE, 0,
		SADB_EALG_DESCBC, SADB_AALG_NONE },
	    { ESP_DES, AUTH_ALGORITHM_HMAC_MD5,
		DES_CBC_BLOCK_SIZE, HMAC_MD5_KEY_LEN,
		SADB_EALG_DESCBC, SADB_AALG_MD5HMAC },
	    { ESP_DES, AUTH_ALGORITHM_HMAC_SHA1,
		DES_CBC_BLOCK_SIZE,
		HMAC_SHA1_KEY_LEN, SADB_EALG_DESCBC, SADB_AALG_SHA1HMAC },

	    { ESP_3DES, AUTH_ALGORITHM_NONE,
		DES_CBC_BLOCK_SIZE * 3, 0,
		SADB_EALG_3DESCBC, SADB_AALG_NONE },
	    { ESP_3DES, AUTH_ALGORITHM_HMAC_MD5,
		DES_CBC_BLOCK_SIZE * 3, HMAC_MD5_KEY_LEN,
		SADB_EALG_3DESCBC, SADB_AALG_MD5HMAC },
	    { ESP_3DES, AUTH_ALGORITHM_HMAC_SHA1,
		DES_CBC_BLOCK_SIZE * 3, HMAC_SHA1_KEY_LEN,
		SADB_EALG_3DESCBC, SADB_AALG_SHA1HMAC },
	};

#ifdef NAT_TRAVERSAL
	u_int8_t natt_type = 0;
	u_int16_t natt_sport = 0, natt_dport = 0;
	ip_address natt_oa;

	if (st->nat_traversal & NAT_T_DETECTED) {
	    natt_type = (st->nat_traversal & NAT_T_WITH_PORT_FLOATING) ?
		ESPINUDP_WITH_NON_ESP : ESPINUDP_WITH_NON_IKE;
	    natt_sport = inbound? c->that.host_port : c->this.host_port;
	    natt_dport = inbound? c->this.host_port : c->that.host_port;
	    natt_oa = st->nat_oa;
	}
#endif

	for (ei = esp_info; ; ei++)
	{
	    if (ei == &esp_info[elemsof(esp_info)])
	    {
		/* Check for additional kernel alg */
#ifndef NO_KERNEL_ALG
		if ((ei=kernel_alg_esp_info(st->st_esp.attrs.transid, 
					st->st_esp.attrs.auth))!=NULL) {
			log("ESP transform %s / auth %s implemented ",
		    enum_name(&esp_transformid_names, st->st_esp.attrs.transid),
		    enum_name(&auth_alg_names, st->st_esp.attrs.auth));
			break;
		}
#endif

		/* note: enum_show may use a static buffer, so two
		 * calls in one printf would be a mistake.
		 * enum_name does the same job, without a static buffer,
		 * assuming the name will be found.
		 */
		loglog(RC_LOG_SERIOUS, "ESP transform %s / auth %s not implemented yet",
		    enum_name(&esp_transformid_names, st->st_esp.attrs.transid),
		    enum_name(&auth_alg_names, st->st_esp.attrs.auth));
		goto fail;
	    }
	    
	    if (st->st_esp.attrs.transid == ei->transid
	    && st->st_esp.attrs.auth == ei->auth)
		break;
	}

	key_len = st->st_esp.attrs.key_len/8;

	if (key_len) {
		/* XXX: must change to check valid _range_ key_len */
		if (key_len > ei->enckeylen) {
			loglog(RC_LOG_SERIOUS, "ESP transform %s passed key_len=%d > %d",
			enum_name(&esp_transformid_names, st->st_esp.attrs.transid),
			key_len, ei->enckeylen);
			goto fail;
		}
	} else {
		key_len = ei->enckeylen;
		/* Grrrrr.... f*cking 7 bits jurassic algos 
		* 168 bits in kernel, need 192 bits for keymat_len */
		if (ei->transid == ESP_3DES && key_len == 21) 
			key_len = 24;
		if (ei->transid == ESP_DES && key_len == 21) 
			key_len = 24;

	}

	/* divide up keying material */
	DBG(DBG_KLIPS|DBG_CONTROL|DBG_PARSING, 
		if(st->st_esp.keymat_len != key_len + ei->authkeylen)
			DBG_log("keymat_len=%d key_len=%d authkeylen=%d",
				st->st_esp.keymat_len, key_len, ei->authkeylen);
	);
	
	passert(st->st_esp.keymat_len == key_len + ei->authkeylen);

	set_text_said(text_said, &dst, esp_spi, SA_ESP);

	if (!(pfkey_msg_start(SADB_ADD, SADB_SATYPE_ESP
	    , "pfkey_msg_hdr Add ESP SA", text_said, extensions)

	&& pfkey_build(pfkey_sa_build(&extensions[SADB_EXT_SA]
		, SADB_EXT_SA
		, esp_spi	/* in network order */
		, REPLAY_WINDOW, SADB_SASTATE_MATURE, ei->authalg, ei->encryptalg, 0)
	    , "pfkey_sa Add ESP SA", text_said, extensions)

	&& pfkeyext_address(SADB_EXT_ADDRESS_SRC, &src
	    , "pfkey_addr_s Add ESP SA", text_said, extensions)

	&& pfkeyext_address(SADB_EXT_ADDRESS_DST, &dst
	    , "pfkey_addr_d Add ESP SA", text_said, extensions)

	&& (ei->authkeylen == 0
	    || pfkey_build(pfkey_key_build(&extensions[SADB_EXT_KEY_AUTH]
		    , SADB_EXT_KEY_AUTH, ei->authkeylen * IPSEC_PFKEYv2_ALIGN
		    , esp_dst_keymat + key_len)
		, "pfkey_key_a Add ESP SA", text_said, extensions))

	&& (key_len == 0
	    || pfkey_build(pfkey_key_build(&extensions[SADB_EXT_KEY_ENCRYPT]
		    , SADB_EXT_KEY_ENCRYPT, key_len * IPSEC_PFKEYv2_ALIGN
		    , esp_dst_keymat)
		, "pfkey_key_a Add ESP SA", text_said, extensions))

#ifdef NAT_TRAVERSAL
	&& (natt_type == 0
		|| pfkey_build(pfkey_x_nat_t_type_build(
			&extensions[SADB_X_EXT_NAT_T_TYPE], natt_type),
			"pfkey_nat_t_type Add ESP SA", text_said, extensions))
	&& (natt_sport == 0
		|| pfkey_build(pfkey_x_nat_t_port_build(
			&extensions[SADB_X_EXT_NAT_T_SPORT], SADB_X_EXT_NAT_T_SPORT,
			natt_sport), "pfkey_nat_t_sport Add ESP SA", text_said,
			extensions))
	&& (natt_dport == 0
		|| pfkey_build(pfkey_x_nat_t_port_build(
			&extensions[SADB_X_EXT_NAT_T_DPORT], SADB_X_EXT_NAT_T_DPORT,
			natt_dport), "pfkey_nat_t_dport Add ESP SA", text_said,
			extensions))
	&& (natt_type ==0 || isanyaddr(&natt_oa)
		|| pfkeyext_address(SADB_X_EXT_NAT_T_OA, &natt_oa
	    , "pfkey_nat_t_oa Add ESP SA", text_said, extensions))
#endif

	&& finish_pfkey_msg(extensions, "Add ESP SA", text_said, NULL)))

	    goto fail;

	initsaid(&dst, esp_spi, SA_ESP, said_next);
	said_next++;
    }

    /* set up IPCOMP SA, if any */

    if (st->st_ipcomp.present)
    {
	ipsec_spi_t ipcomp_spi = inbound? st->st_ipcomp.our_spi : st->st_ipcomp.attrs.spi;
	u_int8_t compalg;

	switch (st->st_ipcomp.attrs.transid)
	{
	    case IPCOMP_DEFLATE:
		compalg = SADB_X_CALG_DEFLATE;
		break;

	    case IPCOMP_LZS:
		compalg = SADB_X_CALG_LZS;
		break;

	    default:
		loglog(RC_LOG_SERIOUS, "IPCOMP transform %s not implemented",
		    enum_name(&ipcomp_transformid_names, st->st_ipcomp.attrs.transid));
		goto fail;
	}

	set_text_said(text_said, &dst, ipcomp_spi, SA_COMP);

	if (!(pfkey_msg_start(SADB_ADD, SADB_X_SATYPE_COMP
	    , "pfkey_msg_hdr Add IPCOMP SA", text_said, extensions)

	&& pfkey_build(pfkey_sa_build(&extensions[SADB_EXT_SA]
		, SADB_EXT_SA
		, ipcomp_spi	/* in network order */
		, 0, SADB_SASTATE_MATURE, 0, compalg, 0)
	    , "pfkey_sa Add IPCOMP SA", text_said, extensions)

	&& pfkeyext_address(SADB_EXT_ADDRESS_SRC, &src
	    , "pfkey_addr_s Add IPCOMP SA", text_said, extensions)

	&& pfkeyext_address(SADB_EXT_ADDRESS_DST, &dst
	    , "pfkey_addr_d Add IPCOMP SA", text_said, extensions)

	&& finish_pfkey_msg(extensions, "Add IPCOMP SA", text_said, NULL)))

	    goto fail;

	initsaid(&dst, ipcomp_spi, SA_COMP, said_next);
	said_next++;
    }

    /* If we are tunnelling, set up IP in IP pseudo SA */

    if (st->st_ah.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL
    || st->st_esp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL
    || st->st_ipcomp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
    {
	/* XXX hack alert -- we SHOULD NOT HAVE TO HAVE A DIFFERENT SPI
	 * XXX FOR IP-in-IP ENCAPSULATION!
	 */

	ipsec_spi_t ipip_spi;

	/* Allocate an SPI for the tunnel.
	 * Since our peer will never see this,
	 * and it comes from its own number space,
	 * it is purely a local implementation wart.
	 */
	{
	    static ipsec_spi_t last_tunnel_spi = IPSEC_DOI_SPI_OUR_MIN;

	    ipip_spi = htonl(++last_tunnel_spi);
	    if (inbound)
		st->st_tunnel_in_spi = ipip_spi;
	    else
		st->st_tunnel_out_spi = ipip_spi;
	}

	set_text_said(text_said
	    , &c->that.host_addr, ipip_spi, SA_IPIP);

	if (!(pfkey_msg_start(SADB_ADD, SADB_X_SATYPE_IPIP
	    , "pfkey_msg_hdr Add IPIP SA", text_said, extensions)

	&& pfkey_build(pfkey_sa_build(&extensions[SADB_EXT_SA]
		, SADB_EXT_SA
		, ipip_spi		/* in network order */
		, 0, SADB_SASTATE_MATURE
		, 0
		, 0
		, 0)
	    , "pfkey_sa Add IPIP SA", text_said, extensions)

	&& pfkeyext_address(SADB_EXT_ADDRESS_SRC, &src
	    , "pfkey_addr_s Add IPIP SA", text_said, extensions)

	&& pfkeyext_address(SADB_EXT_ADDRESS_DST, &dst
	    , "pfkey_addr_d Add IPIP SA", text_said, extensions)

	&& finish_pfkey_msg(extensions, "Add IPIP SA", text_said, NULL)))

	    goto fail;

	initsaid(&dst, ipip_spi, SA_IPIP, said_next);
	said_next++;

	/* If inbound, and policy does not specifie DISABLEARRIVALCHECK,
	 * tell KLIPS to enforce the IP addresses appropriate for this tunnel.
	 * Note reversed ends.
	 * Not much to be done on failure.
	 */
	if (inbound && (c->policy & POLICY_DISABLEARRIVALCHECK) == 0)
	    (void) raw_eroute(&c->that.host_addr, &c->that.client
		, &c->this.host_addr, &c->this.client
		, ipip_spi, SA_IPIP, SADB_X_SATYPE_IPIP
		, ERO_ADD_INBOUND, "add inbound");
    }

    /* If there are multiple SPIs, group them. */

    if (said_next > &said[1])
    {
	ip_said *s;

	/* group SAs, two at a time, inner to outer (backwards in said[])
	 * The grouping is by pairs.  So if said[] contains ah esp ipip,
	 * the grouping would be ipip:esp, esp:ah.
	 */
	for (s = said_next-1; s != said; )
	{
	    struct sadb_ext *extensions[SADB_EXT_MAX + 1];
	    char
	    	text_said0[SATOT_BUF],
		text_said1[SATOT_BUF];

	    s--;

	    /* group s[1] and s[0], in that order */

	    set_text_said(text_said0, &s[0].dst, s[0].spi, s[0].proto);
	    set_text_said(text_said1, &s[1].dst, s[1].spi, s[1].proto);

	    DBG(DBG_KLIPS, DBG_log("grouping %s and %s", text_said1, text_said0));

	    if (!(pfkey_msg_start(SADB_X_GRPSA, proto2satype(s[1].proto)
		, "pfkey_msg_hdr group", text_said1, extensions)

	    && pfkey_build(pfkey_sa_build(&extensions[SADB_EXT_SA]
		    , SADB_EXT_SA
		    , s[1].spi	/* in network order */
		    , 0, 0, 0, 0, 0)
		, "pfkey_sa group", text_said1, extensions)

	    && pfkeyext_address(SADB_EXT_ADDRESS_DST, &s[1].dst
		, "pfkey_addr_d group", text_said1, extensions)

	    && pfkey_build(pfkey_x_satype_build(&extensions[SADB_X_EXT_SATYPE2]
		    , proto2satype(s[0].proto))
		, "pfkey_satype group", text_said0, extensions)

	    && pfkey_build(pfkey_sa_build(&extensions[SADB_X_EXT_SA2]
		    , SADB_X_EXT_SA2
		    , s[0].spi	/* in network order */
		    , 0, 0, 0, 0, 0)
		, "pfkey_sa2 group", text_said0, extensions)

	    && pfkeyext_address(SADB_X_EXT_ADDRESS_DST2, &s[0].dst
		, "pfkey_addr_d2 group", text_said0, extensions)

	    && finish_pfkey_msg(extensions, "group", text_said1, NULL)))
	    	goto fail;
	}
	/* could update said, but it will not be used */
    }

    return TRUE;

fail:
    {
	/* undo the done SPIs */
	while (said_next-- != said)
	    (void) del_spi(said_next->spi, said_next->proto
		, &src, &said_next->dst);
	return FALSE;
    }
}

/* teardown_ipsec_sa is a canibalized version of setup_ipsec_sa */

static bool
teardown_half_ipsec_sa(struct state *st, bool inbound)
{
    /* We need to delete AH, ESP, and IP in IP SPIs.
     * But if there is more than one, they have been grouped
     * so deleting any one will do.  So we just delete the
     * first one found.  It may or may not be the only one.
     */
    struct connection *c = st->st_connection;
    struct ipsec_proto_info *f;	/* first SA found */
    unsigned proto;

    if (st->st_ah.present)
    {
	f = &st->st_ah;
	proto = SA_AH;
    }
    else if (st->st_esp.present)
    {
	f = &st->st_esp;
	proto = SA_ESP;
    }
    else
    {
	impossible();	/* neither AH nor ESP in outbound SA bundle! */
    }

    if (c->dnshostname != NULL)
    {
	ip_address new_addr;

	if (ttoaddr(c->dnshostname, 0, c->addr_family, &new_addr) == NULL
	&& !sameaddr(&new_addr, &c->that.host_addr))
	{
	    c->that.host_addr = new_addr;
	    state_rehash(c);
	}
    }

    return inbound
	? del_spi(f->our_spi, proto, &c->that.host_addr, &c->this.host_addr)
	: del_spi(f->attrs.spi, proto, &c->this.host_addr, &c->that.host_addr);
}
#endif /* KLIPS */


void
init_kernel(void)
{
#ifdef KLIPS
    if (!no_klips)
    {
	init_pfkey();
	event_schedule(EVENT_SHUNT_SCAN, SHUNT_SCAN_INTERVAL, NULL);
    }
#endif
}

/* Note: install_inbound_ipsec_sa is only used by the Responder.
 * The Responder will subsequently use install_ipsec_sa for the outbound.
 * The Initiator uses install_ipsec_sa to install both at once.
 */
bool
install_inbound_ipsec_sa(struct state *st)
{
    struct connection *const c = st->st_connection;

    /* If our peer has a fixed-address client, check if we already
     * have a route for that client that conflicts.  We will take this
     * as proof that that route and the connections using it are
     * obsolete and should be eliminated.  Interestingly, this is
     * the only case in which we can tell that a connection is obsolete.
     */
    passert(c->kind != CK_TEMPLATE);
    if (c->that.has_client)
    {
	for (;;)
	{
	    struct connection *o = route_owner(c, NULL);

	    if (o == NULL)
		break;	/* nobody has a route */

	    /* note: we ignore the client addresses at this end */
	    if (sameaddr(&o->that.host_addr, &c->that.host_addr)
	    && o->interface == c->interface)
		break;	/* existing route is compatible */

	    loglog(RC_LOG_SERIOUS, "route to peer's client conflicts with \"%s\" %s; releasing old connection to free the route"
		, o->name, ip_str(&o->that.host_addr));
	    release_connection(o);
	}
    }

    /* check that we will be able to route and eroute */
    if (!could_route(c))
	return FALSE;

#ifdef KLIPS
    /* (attempt to) actually set up the SAs */
    return setup_half_ipsec_sa(st, TRUE);
#else /* !KLIPS */
    DBG(DBG_CONTROL, DBG_log("install_inbound_ipsec_sa()"));
    return TRUE;
#endif /* !KLIPS */
}

/* Install a route and then a prospective shunt eroute or an SA group eroute.
 * Assumption: could_route gave a go-ahead.
 * Any SA Group must have already been created.
 * On failure, steps will be unwound (where feasible: old shunt
 * will be lost -- this may matter).
 */
static bool
route_and_eroute(struct connection *c USED_BY_KLIPS
, struct state *st USED_BY_KLIPS)
{
#ifdef KLIPS
    struct connection *ero	/* who, if anyone, owns our eroute? */
	, *ro = route_owner(c, &ero);
    bool eroute_installed = FALSE
	, firewall_notified = FALSE
	, route_installed = FALSE;

    struct bare_shunt **bspp = (ero == NULL)
	? bare_shunt_ptr(&c->this.client, EffectivePeerClient(c)) : NULL;

    /* install the eroute */

    passert(ero == NULL || ero == c);
    if (ero != NULL || bspp != NULL)
    {
	/* We're replacing an eroute */

	eroute_installed = st == NULL
	    ? shunt_eroute(c, ERO_REPLACE, "replace")
	    : sag_eroute(st, ERO_REPLACE, "replace");

	if (eroute_installed && bspp != NULL)
	    free_bare_shunt(bspp);
    }
    else
    {
	/* we're adding an eroute */
	eroute_installed = st == NULL
	    ? shunt_eroute(c, ERO_ADD, "add")
	    : sag_eroute(st, ERO_ADD, "add");
    }

    /* notify the firewall of a new tunnel */

    if (eroute_installed)
    {
	/* do we have to notify the firewall?  Yes, if we are installing
	 * a tunnel eroute and the firewall wasn't notified
	 * for a previous tunnel with the same clients.  Any Previous
	 * tunnel would have to be for our connection, so the actual
	 * test is simple.
	 */
	firewall_notified = st == NULL	/* not a tunnel eroute */
	    || c->eroute_owner != SOS_NOBODY	/* already notified */
	    || do_command(c, "up");	/* go ahead and notify */
    }

    /* install the route */

    if (!firewall_notified)
    {
	/* we're in trouble -- don't do routing */
    }
    else if (ro == NULL)
    {
	/* a new route: no deletion required, but preparation is */
	(void) do_command(c, "prepare");	/* just in case; ignore failure */
	route_installed = do_command(c, "route");
    }
    else if (routed(c->routing)
    || routes_agree(ro, c))
    {
	route_installed = TRUE;	/* nothing to be done */
    }
    else
    {
	/* Some other connection must own the route
	 * and the route must disagree.  But since could_route
	 * must have allowed our stealing it, we'll do so.
	 *
	 * A feature of LINUX allows us to install the new route
	 * before deleting the old if the nexthops differ.
	 * This reduces the "window of vulnerability" when packets
	 * might flow in the clear.
	 */
	if (sameaddr(&c->this.host_nexthop, &ro->this.host_nexthop))
	{
	    (void) do_command(ro, "unroute");
	    route_installed = do_command(c, "route");
	}
	else
	{
	    route_installed = do_command(c, "route");
	    (void) do_command(ro, "unroute");
	}

	/* record unrouting */
	if (route_installed)
	{
	    do {
		passert(!erouted(ro->routing));
		ro->routing = RT_UNROUTED;
		ro = route_owner(c, NULL);	/* no need to keep old value */
	    } while (ro != NULL);
	}
    }

    /* all done -- clean up */
    if (route_installed)
    {
	/* Success! */
	if (st == NULL)
	{
	    passert(c->eroute_owner == SOS_NOBODY);
	    c->routing = RT_ROUTED_PROSPECTIVE;
	}
	else
	{
	    c->routing = RT_ROUTED_TUNNEL;
	    c->eroute_owner = st->st_serialno;
	}

	return TRUE;
    }
    else
    {
	/* Failure!  Unwind our work. */
	if (firewall_notified && c->eroute_owner == SOS_NOBODY)
	    (void) do_command(c, "down");

	if (eroute_installed)
	{
	    if (st == NULL)
		(void) shunt_eroute(c, ERO_DELETE, "delete");
	    else
		(void) sag_eroute(st, ERO_DELETE, "delete");
	}

	return FALSE;
    }
#else /* !KLIPS */
    return TRUE;
#endif /* !KLIPS */
}

#ifdef CONFIG_LEDMAN
static int num_ipsec_sa = 0;
#endif

bool
install_ipsec_sa(struct state *st, bool inbound_also USED_BY_KLIPS)
{
    if (!could_route(st->st_connection))
	return FALSE;

#ifdef KLIPS
    /* (attempt to) actually set up the SA group */
    if ((inbound_also && !setup_half_ipsec_sa(st, TRUE))
    || !setup_half_ipsec_sa(st, FALSE))
	return FALSE;

    if (!route_and_eroute(st->st_connection, st))
    {
	delete_ipsec_sa(st, FALSE);
	return FALSE;
    }

#ifdef CONFIG_LEDMAN
    num_ipsec_sa++;
    ledman_cmd(LEDMAN_CMD_ON, LEDMAN_VPN);
#endif

#else /* !KLIPS */
    if (!could_route(st->st_connection))
	return FALSE;

    DBG(DBG_CONTROL, DBG_log("install_ipsec_sa() %s"
	, inbound_also? "inbound and oubound" : "outbound only"));
#endif /* !KLIPS */

    return TRUE;
}

/* delete an IPSEC SA.
 * we may not succeed, but we bull ahead anyway because
 * we cannot do anything better by recognizing failure
 */
void
delete_ipsec_sa(struct state *st USED_BY_KLIPS, bool inbound_only USED_BY_KLIPS)
{
#ifdef KLIPS
    if (inbound_only)
    {
	(void) teardown_half_ipsec_sa(st, TRUE);
    }
    else
    {
	struct connection *c = st->st_connection;

	if (c->eroute_owner == st->st_serialno)
	{
	    passert(c->routing == RT_ROUTED_TUNNEL);
	    c->eroute_owner = SOS_NOBODY;

	    /* strictly speaking, routing should become RT_ROUTED_FAILURE,
	     * but it is perhaps simpler to use RT_ROUTED_PROSPECTIVE
	     * if the shunt will be TRAP.
	     */
	    c->routing = (c->policy & POLICY_OPPO_MASK) == LEMPTY
		? RT_ROUTED_PROSPECTIVE : RT_ROUTED_FAILURE;

	    (void) do_command(c, "down");
	    (void) shunt_eroute(c, ERO_REPLACE, "replace with shunt");
	}
	(void) teardown_half_ipsec_sa(st, FALSE);
	(void) teardown_half_ipsec_sa(st, TRUE);

#ifdef CONFIG_LEDMAN
	num_ipsec_sa--;
	if (num_ipsec_sa == 0)
	    ledman_cmd(LEDMAN_CMD_OFF, LEDMAN_VPN);    
#endif
    }

    return;
#else /* !KLIPS */
    DBG(DBG_CONTROL, DBG_log("if I knew how, I'd eroute() and teardown_ipsec_sa()"));
    return;
#endif /* !KLIPS */
}

#ifdef NAT_TRAVERSAL
#ifdef KLIPS
static bool update_nat_t_ipsec_esp_sa (struct state *st, bool inbound)
{
	struct connection *c = st->st_connection;
	ip_address
		src = inbound? c->that.host_addr : c->this.host_addr,
		dst = inbound? c->this.host_addr : c->that.host_addr;
	
	struct sadb_ext *extensions[SADB_EXT_MAX + 1];
	char text_said[SATOT_BUF];

	ipsec_spi_t esp_spi = inbound? st->st_esp.our_spi : st->st_esp.attrs.spi;

	u_int16_t
		natt_sport = inbound? c->that.host_port : c->this.host_port,
		natt_dport = inbound? c->this.host_port : c->that.host_port;

	set_text_said(text_said, &dst, esp_spi, SA_ESP);

	return (!(pfkey_msg_start(SADB_UPDATE, SADB_SATYPE_ESP
		, "pfkey_msg_hdr Update ESP SA", text_said, extensions)

	&& pfkey_build(pfkey_sa_build(&extensions[SADB_EXT_SA]
		, SADB_EXT_SA
		, esp_spi   /* in network order */
		, 0, SADB_SASTATE_MATURE, st->st_esp.attrs.auth /* dummy, not used */,
			st->st_esp.attrs.transid /* dummy, not used */, 0)
		, "pfkey_sa Update ESP SA", text_said, extensions)

	&& pfkeyext_address(SADB_EXT_ADDRESS_SRC, &src
		, "pfkey_addr_s Update ESP SA", text_said, extensions)

	&& pfkeyext_address(SADB_EXT_ADDRESS_DST, &dst
		, "pfkey_addr_d Update ESP SA", text_said, extensions)

	&& pfkey_build(pfkey_x_nat_t_port_build(
		&extensions[SADB_X_EXT_NAT_T_SPORT], SADB_X_EXT_NAT_T_SPORT,
		natt_sport), "pfkey_nat_t_sport Update ESP SA", text_said,
		extensions)

	&& pfkey_build(pfkey_x_nat_t_port_build(
		&extensions[SADB_X_EXT_NAT_T_DPORT], SADB_X_EXT_NAT_T_DPORT,
		natt_dport), "pfkey_nat_t_dport Update ESP SA", text_said,
		extensions)

	&& finish_pfkey_msg(extensions, "Update ESP SA", text_said, NULL)))

	? FALSE : TRUE;
}
#endif

bool update_ipsec_sa (struct state *st USED_BY_KLIPS)
{
#ifdef KLIPS
	if (IS_IPSEC_SA_ESTABLISHED(st->st_state)) {
		if ((st->st_esp.present) && (
			(!update_nat_t_ipsec_esp_sa (st, TRUE)) ||
			(!update_nat_t_ipsec_esp_sa (st, FALSE)))) {
			return FALSE;
		}
	}
	else if (IS_ONLY_INBOUND_IPSEC_SA_ESTABLISHED(st->st_state)) {
		if ((st->st_esp.present) && (!update_nat_t_ipsec_esp_sa (st, FALSE))) {
			return FALSE;
		}
	}
	else {
		DBG_log("assert failed at %s:%d st_state=%d", __FILE__, __LINE__,
			st->st_state);
		return FALSE;
	}
	return TRUE;
#else /* !KLIPS */
    DBG(DBG_CONTROL, DBG_log("if I knew how, I'd update_ipsec_sa()"));
    return TRUE;
#endif /* !KLIPS */
}
#endif

