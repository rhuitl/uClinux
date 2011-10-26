/* command interface to Pluto
 * Copyright (C) 1997 Angelos D. Keromytis.
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
 * RCSID $Id: whack.c,v 1.91 2002/03/19 07:17:01 dhr Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <assert.h>

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "whack.h"

static void
help(void)
{
    fprintf(stderr,
	"Usage:\n\n"
	"all forms:"
	    " [--optionsfrom <filename>]"
	    " [--ctlbase <path>]"
	    " [--label <string>]"
	    "\n\n"
	"help: whack"
	    " [--help]"
	    " [--version]"
	    "\n\n"
	"connection: whack"
	    " --name <connection_name>"
	    " \\\n   "
	    " [--ipv4 | --ipv6 ]"
	    " [--tunnelipv4 | --tunnelipv6 ]"
	    " \\\n   "
	    " (--host <ip-address> | --id <identity> | --cert <path>)"
	    " [--ikeport <port-number>]"
	    " \\\n   "
	    "   "
	    " [--nexthop <ip-address>]"
	    " [--client <subnet>] | [--clientwithin <address range>])"
	    " [--clientprotoport <protocol>/<port>]"
	    " [--updown <updown>]"
	    " --to"
	    " (--host <ip-address> | --id <identity> | --cert <path>)"
	    " [--ikeport <port-number>]"
	    " \\\n   "
	    "   "
	    " [--nexthop <ip-address>]"
	    " [--client <subnet>] | [--clientwithin <address range>])"
	    " [--clientprotoport <protocol>/<port>]"
	    " [--updown <updown>]"
	    " [--aggrmode]"
	    " [--psk]"
	    " [--rsasig]"
	    " \\\n   "
	    " [--encrypt]"
	    " [--authenticate]"
	    " [--compress]"
	    " [--tunnel]"
	    " [--pfs]"
	    " \\\n   "
	    " [--ikelifetime <seconds>]"
	    " [--ipseclifetime <seconds>]"
	    " \\\n   "
	    " [--reykeymargin <seconds>]"
	    " [--reykeyfuzz <percentage>]"
	    " \\\n   "
	    " [--keyingtries <count>]"
	    " \\\n   "
	    " [--esp <esp-algos>]"
	    " \\\n   "
	    " [--dpddelay <seconds> --dpdtimeout <seconds>]"
	    " [--cipher_p1 <Phase 1 encryption algorithm> --dhg_p1 <Phase 1 Diffie Helman group>]"
	    " [--hash_p1 <Phase 1 hash algorithm>]"
	    " [--dontrekey]"
	    "\n\n"
	"routing: whack"
	    " (--route | --unroute)"
	    " --name <connection_name>"
	    "\n\n"
	"initiation: whack"
	    " (--initiate | --terminate)"
	    " --name <connection_name>"
	    " [--asynchronous]"
	    "\n\n"
	"opportunistic initiation:"
	    "\n"
	    " whack"
	    " [--ipv4 | --ipv6 ]"
	    " [--tunnelipv4 | --tunnelipv6 ]"
	    " \\\n   "
	    " --oppohere <ip-address>"
	    " --oppothere <ip-address>"
	    "\n\n"
	"delete: whack"
	    " --delete"
	    " --name <connection_name>"
	    "\n\n"
	"deletestate: whack"
	    " --deletestate <state_object_number>"
	    "\n\n"
	"pubkey: whack"
	    " --keyid <id>"
	    " [--addkey]"
	    " [--pubkeyrsa <key>]"
	    "\n\n"
#ifdef DEBUG
	"debug: whack [--name <connection_name>]"
	    " \\\n   "
	    " [--debug-none]"
	    " [--debug-all]"
	    " \\\n   "
	    " [--debug-raw]"
	    " [--debug-crypt]"
	    " [--debug-parsing]"
	    " [--debug-emitting]"
	    " \\\n   "
	    " [--debug-control]"
	    " [--debug-klips]"
	    " [--debug-dns]"
	    " [--debug-private]"
	    "\n\n"
#endif
	"listen: whack"
	    " (--listen | --unlisten)"
	    "\n\n"
	"list: whack [--utc]"
	    " [--listpubkeys]"
	    " [--listcerts]"
	    " [--listcacerts]"
	    " [--listcrls]"
	    " [--listall]"
	    "\n\n"
	"reread: whack"
	    " [--rereadsecrets]"
	    " [--rereadmycert]"
	    " [--rereadcacerts]"
	    " [--rereadcrls]"
	    " [--rereadall]"
	    "\n\n"
	"status: whack"
	    " --status"
	    "\n\n"
	"shutdown: whack"
	    " --shutdown"
	    "\n\n"
	"FreeS/WAN %s\n",
	ipsec_version_code());
}

static const char *label = NULL;	/* --label operand, saved for diagnostics */

static const char *name = NULL;	/* --name operand, saved for diagnostics */

/* print a string as a diagnostic, then exit whack unhappily */
static void
diag(const char *mess)
{
    if (mess != NULL)
    {
	fprintf(stderr, "whack error: ");
	if (label != NULL)
	    fprintf(stderr, "%s ", label);
	if (name != NULL)
	    fprintf(stderr, "\"%s\" ", name);
	fprintf(stderr, "%s\n", mess);
    }

    exit(RC_WHACK_PROBLEM);
}

/* conditially calls diag; prints second arg, if non-NULL, as quoted string */
static void
diagq(err_t ugh, const char *this)
{
    if (ugh != NULL)
    {
	if (this == NULL)
	{
	    diag(ugh);
	}
	else
	{
	    char buf[120];	/* arbitrary limit */

	    snprintf(buf, sizeof(buf), "%s \"%s\"", ugh, this);
	    diag(buf);
	}
    }
}

/* complex combined operands return one of these enumerated values
 * Note: these become flags in an lset_t.  Since there are more than
 * 32, we partition them into:
 * - OPT_* options (most random options)
 * - DBGOPT_* option (DEBUG options)
 * - CD_* options (Connection Description options)
 */
enum {
    OPT_NAME,

    OPT_CD,

    OPT_KEYID,
    OPT_ADDKEY,
    OPT_PUBKEYRSA,

    OPT_ROUTE,
    OPT_UNROUTE,
    
 
    /* put all options that don't require opts_seen service at end */
    OPT_INITIATE,
    OPT_TERMINATE,
    OPT_DELETE,
    OPT_DELETESTATE,
    OPT_LISTEN,
    OPT_UNLISTEN,
    OPT_UTC,
    OPT_LISTPUBKEYS,
    OPT_LISTCERTS,
    OPT_LISTCACERTS,
    OPT_LISTCRLS,
    OPT_LISTALL,

    OPT_REREADSECRETS,
    OPT_REREADMYCERT,
    OPT_REREADCACERTS,
    OPT_REREADCRLS,
    OPT_REREADALL,

    OPT_STATUS,
    OPT_SHUTDOWN,

    OPT_OPPO_HERE,
    OPT_OPPO_THERE,

    OPT_CTLBASE,
    OPT_ASYNC,

#   define OPT_LAST OPT_ASYNC	/* last "normal" option */

/* Connection Description options -- segregated */

#   define CD_FIRST CD_TO	/* first connection description */
    CD_TO,
    CD_HOST,	/* first per-end */
    CD_ID,
    CD_CERT,
    CD_IKEPORT,
    CD_NEXTHOP,
    CD_CLIENT,
    CD_CLIENTWITHIN,
    CD_CLIENTPROTOPORT,
    CD_UPDOWN,	/* last per-end */

#   define CD_POLICY_FIRST  CD_AGGRESSIVE
    CD_AGGRESSIVE, /* same order as POLICY_* */
    CD_PSK,	/* same order as POLICY_* */
    CD_RSASIG,	/* same order as POLICY_* */
    CD_ENCRYPT,	/* same order as POLICY_* */
    CD_AUTHENTICATE,	/* same order as POLICY_* */
    CD_COMPRESS,	/* same order as POLICY_* */
    CD_TUNNEL,	/* same order as POLICY_* */
    CD_PFS,	/* same order as POLICY_* */
    CD_DISABLEARRIVALCHECK,	/* same order as POLICY_* */
    CD_FAIL_PASS,	/* same order as POLICY_* */
    CD_FAIL_DROP,	/* same order as POLICY_* */
    CD_DONT_REKEY,	/* same order as POLICY_* */
    CD_TUNNELIPV4,
    CD_TUNNELIPV6,
    CD_CONNIPV4,
    CD_CONNIPV6,

    CD_IKELIFETIME,
    CD_IPSECLIFETIME,
    CD_RKMARGIN,
    CD_RKFUZZ,
    CD_KTRIES,
    CD_DPDDELAY,
    CD_DPDTIMEOUT,
    CD_CIPHER_P1,
    CD_DHG_P1,
    CD_HASH_P1,
    CD_IKE,
    CD_PFSGROUP,
    CD_ESP,
    CD_RETRANSMIT
#   define CD_LAST CD_RETRANSMIT		/* last connection description */

#ifdef DEBUG	/* must be last so others are less than 32 to fit in lset_t */
#   define DBGOPT_FIRST DBGOPT_NONE
    ,
    DBGOPT_NONE,
    DBGOPT_ALL,

    DBGOPT_RAW,		/* same order as DBG_* */
    DBGOPT_CRYPT,	/* same order as DBG_* */
    DBGOPT_PARSING,	/* same order as DBG_* */
    DBGOPT_EMITTING,	/* same order as DBG_* */
    DBGOPT_CONTROL,	/* same order as DBG_* */
    DBGOPT_LIFECYCLE,	/* same order as DBG_* */
    DBGOPT_KLIPS,	/* same order as DBG_* */
    DBGOPT_DNS,		/* same order as DBG_* */
    DBGOPT_PRIVATE	/* same order as DBG_* */
#   define DBGOPT_LAST DBGOPT_PRIVATE
#endif

};

#define OPTION_OFFSET	256	/* to get out of the way of letter options */
#define NUMERIC_ARG (1 << 7)	/* expect a numeric argument */

static const struct option long_opts[] = {
#   define OO	OPTION_OFFSET
    /* name, has_arg, flag, val */

    { "help", no_argument, NULL, 'h' },
    { "version", no_argument, NULL, 'v' },
    { "optionsfrom", required_argument, NULL, '+' },
    { "label", required_argument, NULL, 'l' },

    { "ctlbase", required_argument, NULL, OPT_CTLBASE + OO },
    { "name", required_argument, NULL, OPT_NAME + OO },

    { "keyid", required_argument, NULL, OPT_KEYID + OO },
    { "addkey", no_argument, NULL, OPT_ADDKEY + OO },
    { "pubkeyrsa", required_argument, NULL, OPT_PUBKEYRSA + OO },

    { "route", no_argument, NULL, OPT_ROUTE + OO },
    { "unroute", no_argument, NULL, OPT_UNROUTE + OO },

    { "initiate", no_argument, NULL, OPT_INITIATE + OO },
    { "terminate", no_argument, NULL, OPT_TERMINATE + OO },
    { "delete", no_argument, NULL, OPT_DELETE + OO },
    { "deletestate", required_argument, NULL, OPT_DELETESTATE + OO + NUMERIC_ARG },
    { "listen", no_argument, NULL, OPT_LISTEN + OO },
    { "unlisten", no_argument, NULL, OPT_UNLISTEN + OO },
    { "utc", no_argument, NULL, OPT_UTC + OO },
    { "listpubkeys", no_argument, NULL, OPT_LISTPUBKEYS + OO },
    { "listcerts", no_argument, NULL, OPT_LISTCERTS + OO },
    { "listcacerts", no_argument, NULL, OPT_LISTCACERTS + OO },
    { "listcrls", no_argument, NULL, OPT_LISTCRLS + OO },
    { "listall", no_argument, NULL, OPT_LISTALL + OO },
    { "rereadsecrets", no_argument, NULL, OPT_REREADSECRETS + OO },
    { "rereadmycert", no_argument, NULL, OPT_REREADMYCERT + OO },
    { "rereadcacerts", no_argument, NULL, OPT_REREADCACERTS + OO },
    { "rereadcrls", no_argument, NULL, OPT_REREADCRLS + OO },
    { "rereadall", no_argument, NULL, OPT_REREADALL + OO },
    { "status", no_argument, NULL, OPT_STATUS + OO },
    { "shutdown", no_argument, NULL, OPT_SHUTDOWN + OO },

    { "oppohere", required_argument, NULL, OPT_OPPO_HERE + OO },
    { "oppothere", required_argument, NULL, OPT_OPPO_THERE + OO },

    { "asynchronous", no_argument, NULL, OPT_ASYNC + OO },


    /* options for a connection description */

    { "to", no_argument, NULL, CD_TO + OO },

    { "host", required_argument, NULL, CD_HOST + OO },
    { "id", required_argument, NULL, CD_ID + OO },
    { "cert", required_argument, NULL, CD_CERT + OO },
    { "ikeport", required_argument, NULL, CD_IKEPORT + OO + NUMERIC_ARG },
    { "nexthop", required_argument, NULL, CD_NEXTHOP + OO },
    { "client", required_argument, NULL, CD_CLIENT + OO },
    { "clientwithin", required_argument, NULL, CD_CLIENTWITHIN + OO },
    { "clientprotoport", required_argument, NULL, CD_CLIENTPROTOPORT + OO },
    { "updown", required_argument, NULL, CD_UPDOWN + OO },
    
    { "aggrmode", no_argument, NULL, CD_AGGRESSIVE + OO },
    { "psk", no_argument, NULL, CD_PSK + OO },
    { "rsasig", no_argument, NULL, CD_RSASIG + OO },

    { "encrypt", no_argument, NULL, CD_ENCRYPT + OO },
    { "authenticate", no_argument, NULL, CD_AUTHENTICATE + OO },
    { "compress", no_argument, NULL, CD_COMPRESS + OO },
    { "tunnel", no_argument, NULL, CD_TUNNEL + OO },
    { "tunnelipv4", no_argument, NULL, CD_TUNNELIPV4 + OO },
    { "tunnelipv6", no_argument, NULL, CD_TUNNELIPV6 + OO },
    { "pfs", no_argument, NULL, CD_PFS + OO },
    { "disablearrivalcheck", no_argument, NULL, CD_DISABLEARRIVALCHECK + OO },
    { "pass", no_argument, NULL, CD_FAIL_PASS + OO },
    { "drop", no_argument, NULL, CD_FAIL_DROP + OO },
    { "dontrekey", no_argument, NULL, CD_DONT_REKEY + OO },
    { "ipv4", no_argument, NULL, CD_CONNIPV4 + OO },
    { "ipv6", no_argument, NULL, CD_CONNIPV6 + OO },

    { "ikelifetime", required_argument, NULL, CD_IKELIFETIME + OO + NUMERIC_ARG },
    { "ipseclifetime", required_argument, NULL, CD_IPSECLIFETIME + OO + NUMERIC_ARG },
    { "rekeymargin", required_argument, NULL, CD_RKMARGIN + OO + NUMERIC_ARG },
    { "rekeywindow", required_argument, NULL, CD_RKMARGIN + OO + NUMERIC_ARG },	/* OBSOLETE */
    { "rekeyfuzz", required_argument, NULL, CD_RKFUZZ + OO + NUMERIC_ARG },
    { "keyingtries", required_argument, NULL, CD_KTRIES + OO + NUMERIC_ARG },
    { "dpddelay", required_argument, NULL, CD_DPDDELAY + OO + NUMERIC_ARG },
    { "dpdtimeout", required_argument, NULL, CD_DPDTIMEOUT + OO + NUMERIC_ARG },
    { "cipher_p1", required_argument, NULL, CD_CIPHER_P1 + OO },
    { "dhg_p1", required_argument, NULL, CD_DHG_P1 + OO + NUMERIC_ARG },
    { "hash_p1", required_argument, NULL, CD_HASH_P1 + OO },
    { "ike", required_argument, NULL, CD_IKE + OO },
    { "pfsgroup", required_argument, NULL, CD_PFSGROUP + OO },
    { "esp", required_argument, NULL, CD_ESP + OO },
    { "retransmit_trigger", required_argument, NULL, CD_RETRANSMIT + OO + NUMERIC_ARG},
#ifdef DEBUG
    { "debug-none", no_argument, NULL, DBGOPT_NONE + OO },
    { "debug-all]", no_argument, NULL, DBGOPT_ALL + OO },
    { "debug-raw", no_argument, NULL, DBGOPT_RAW + OO },
    { "debug-crypt", no_argument, NULL, DBGOPT_CRYPT + OO },
    { "debug-parsing", no_argument, NULL, DBGOPT_PARSING + OO },
    { "debug-emitting", no_argument, NULL, DBGOPT_EMITTING + OO },
    { "debug-control", no_argument, NULL, DBGOPT_CONTROL + OO },
    { "debug-lifecycle", no_argument, NULL, DBGOPT_LIFECYCLE + OO },
    { "debug-klips", no_argument, NULL, DBGOPT_KLIPS + OO },
    { "debug-dns", no_argument, NULL, DBGOPT_DNS + OO },
    { "debug-private", no_argument, NULL, DBGOPT_PRIVATE + OO },
#endif
#   undef OO
    { 0,0,0,0 }
};

struct sockaddr_un ctl_addr = { AF_UNIX, DEFAULT_CTLBASE CTL_SUFFIX };

/* helper variables and function to encode strings from whack message */

static char
    *next_str,
    *str_roof;

static bool
pack_str(char **p)
{
    const char *s = *p == NULL? "" : *p;	/* note: NULL becomes ""! */
    size_t len = strlen(s) + 1;

    if (str_roof - next_str < (ptrdiff_t)len)
    {
	return FALSE;	/* fishy: no end found */
    }
    else
    {
	strcpy(next_str, s);
	next_str += len;
	*p = NULL;	/* don't send pointers on the wire! */
	return TRUE;
    }
}

static void
check_life_time(time_t life, time_t limit, const char *which
, const struct whack_message *msg)
{
    time_t mint = msg->sa_rekey_margin * (100 + msg->sa_rekey_fuzz) / 100;

    if (life > limit)
    {
	char buf[200];	/* arbitrary limit */

	snprintf(buf, sizeof(buf)
	    , "%s [%lu seconds] must be less than %lu seconds"
	    , which, (unsigned long)life, (unsigned long)limit);
	diag(buf);
    }
    if ((msg->policy & POLICY_DONT_REKEY) == LEMPTY && life <= mint)
    {
	char buf[200];	/* arbitrary limit */

	snprintf(buf, sizeof(buf)
	    , "%s [%lu] must be greater than"
	    " rekeymargin*(100+rekeyfuzz)/100 [%lu*(100+%lu)/100 = %lu]"
	    , which
	    , (unsigned long)life
	    , (unsigned long)msg->sa_rekey_margin
	    , (unsigned long)msg->sa_rekey_fuzz
	    , (unsigned long)mint);
	diag(buf);
    }
}

static void
check_end(struct whack_end *this, struct whack_end *that
, lset_t policy, bool default_nexthop, sa_family_t caf, sa_family_t taf)
{
    if (caf != addrtypeof(&this->host_addr))
	diag("address family of host inconsistent");

    if (default_nexthop)
    {
	if (isanyaddr(&that->host_addr))
	    diag("our nexthop must be specified when other host is a %any or %opportunistic");
	this->host_nexthop = that->host_addr;
    }

    if (caf != addrtypeof(&this->host_nexthop))
	diag("address family of nexthop inconsistent");

    if (this->has_client)
    {
	ip_address cn;

	networkof(&this->client, &cn);

	if (taf != addrtypeof(&cn))
	    diag("address family of client subnet inconsistent");

	if (isanyaddr(&cn) && subnetishost(&this->client))
	{
	    /* client is 0.0.0.0/32: Opportunism connection */
	    if (!isanyaddr(&this->host_addr))
		diag("normal client network must not be 0.0.0.0/32 or 0::0/128");
	    if ((policy & (POLICY_PSK | POLICY_RSASIG)) != POLICY_RSASIG)
		diag("only RSASIG is supported for opportunism");
	    if ((policy & POLICY_PFS) == 0)
		diag("PFS required for opportunism");
	    if ((policy & POLICY_ENCRYPT) == 0)
		diag("encryption required for opportunism");
	}
    }
    else
    {
	/* fill in anyaddr-anyaddr as (missing) client subnet */
	ip_address cn;

	diagq(anyaddr(caf, &cn), NULL);
	diagq(rangetosubnet(&cn, &cn, &this->client), NULL);
    }

    /* check protocol */
    if (this->protocol != that->protocol)
	diagq("the protocol for leftprotoport and rightprotoport must be the same", NULL);
}

/* This is a hack for initiating ISAKMP exchanges. */

int
main(int argc, char **argv)
{
    struct whack_message msg;
    char esp_buf[256];	/* uses snprintf */
    lset_t
	opts_seen = LEMPTY,
	cd_seen = LEMPTY,
	cd_seen_before_to;
    const char
	*af_used_by = NULL,
	*tunnel_af_used_by = NULL;

    zero(&msg);
    msg.magic = WHACK_MAGIC;
    msg.right.host_port = IKE_UDP_PORT;

    msg.name = NULL;
    msg.dnshostname = NULL;
    msg.left.id = NULL;
    msg.left.cert = NULL;
    msg.left.updown = NULL;
    msg.right.id = NULL;
    msg.right.cert = NULL;
    msg.right.updown = NULL;
    msg.keyid = NULL;
    msg.keyval.ptr = NULL;
    msg.cipher_p1 = NULL;
    msg.dhg_p1 = NULL;
    msg.hash_p1 = NULL;
    msg.esp = NULL;
    msg.pfsgroup = NULL;
    msg.ike = NULL;
    msg.retransmit_trigger = 2;

    msg.sa_ike_life_seconds = OAKLEY_ISAKMP_SA_LIFETIME_DEFAULT;
    msg.sa_ipsec_life_seconds = PLUTO_SA_LIFE_DURATION_DEFAULT;
    msg.sa_rekey_margin = SA_REPLACEMENT_MARGIN_DEFAULT;
    msg.sa_rekey_fuzz = SA_REPLACEMENT_FUZZ_DEFAULT;
    msg.sa_keying_tries = SA_REPLACEMENT_RETRIES_DEFAULT;

    msg.addr_family = AF_INET;
    msg.tunnel_addr_family = AF_INET;
    
    for (;;)
    {
	int long_index;
	unsigned long opt_whole;	/* numeric argument for some flags */

	/* Note: we don't like the way short options get parsed
	 * by getopt_long, so we simply pass an empty string as
	 * the list.  It could be "hp:d:c:o:eatfs" "NARXPECK".
	 */
	int c = getopt_long(argc, argv, "", long_opts, &long_index) - OPTION_OFFSET;

	/* decode a numeric argument, if expected */
	if (0 <= c && (c & NUMERIC_ARG))
	{
	    char *endptr;

	    c -= NUMERIC_ARG;
	    opt_whole = strtoul(optarg, &endptr, 0);

	    if (*endptr != '\0' || endptr == optarg)
		diagq("badly formed numeric argument", optarg);
	}

	/* per-class option processing */
	if (0 <= c && c < OPT_LAST)
	{
	    /* OPT_* options get added opts_seen.
	     * Reject repeated options (unless later code intervenes).
	     */
	    lset_t f = LELEM(c);

	    if (opts_seen & f)
		diagq("duplicated flag", long_opts[long_index].name);
	    opts_seen |= f;
	}
#ifdef DEBUG
	else if (DBGOPT_FIRST <= c && c <= DBGOPT_LAST)
	{
	    /* DBGOPT_* options are treated separately to reduce
	     * potential members of opts_seen.
	     */
	    msg.whack_options = TRUE;
	}
#endif
	else if (CD_FIRST <= c && c <= CD_LAST)
	{
	    /* CD_* options are added to cd_seen.
	     * Reject repeated options (unless later code intervenes).
	     */
	    lset_t f = LELEM(c - CD_FIRST);

	    if ((CD_FIRST+32) <= c)
 	    	f = 0;
	    if (cd_seen & f)
		diagq("duplicated flag", long_opts[long_index].name);
	    cd_seen |= f;
	    opts_seen |= LELEM(OPT_CD);
	}

	/* Note: "break"ing from switch terminates loop.
	 * most cases should end with "continue".
	 */
	switch (c)
	{
	case EOF - OPTION_OFFSET:	/* end of flags */
	    break;

	case 0 - OPTION_OFFSET: /* long option already handled */
	    continue;

	case ':' - OPTION_OFFSET:	/* diagnostic already printed by getopt_long */
	case '?' - OPTION_OFFSET:	/* diagnostic already printed by getopt_long */
	    diag(NULL);	/* print no additional diagnostic, but exit sadly */
	    break;	/* not actually reached */

	case 'h' - OPTION_OFFSET:	/* --help */
	    help();
	    return 0;	/* GNU coding standards say to stop here */

	case 'v' - OPTION_OFFSET:	/* --version */
	    {
		const char **sp = ipsec_copyright_notice();

		printf("%s\n", ipsec_version_string());
		for (; *sp != NULL; sp++)
		    puts(*sp);
	    }
	    return 0;	/* GNU coding standards say to stop here */

	case 'l' - OPTION_OFFSET:	/* --label <string> */
	    label = optarg;	/* remember for diagnostics */
	    continue;

	case '+' - OPTION_OFFSET:	/* --optionsfrom <filename> */
	    optionsfrom(optarg, &argc, &argv, optind, stderr);
	    fprintf(stderr, "DAN %s", optarg);
	    /* does not return on error */
	    continue;

	/* the rest of the options combine in complex ways */

	case OPT_CTLBASE:	/* --port <ctlbase> */
	    if (snprintf(ctl_addr.sun_path, sizeof(ctl_addr.sun_path)
	    , "%s%s", optarg, CTL_SUFFIX) == -1)
		diag("<ctlbase>" CTL_SUFFIX " must be fit in a sun_addr");
	    continue;

	case OPT_NAME:	/* --name <connection-name> */
	    name = optarg;
	    msg.name = optarg;
	    continue;

	case OPT_KEYID:	/* --keyid <identity> */
	    msg.whack_key = TRUE;
	    msg.keyid = optarg;	/* decoded by Pluto */
	    continue;

	case OPT_ADDKEY:	/* --addkey */
	    msg.whack_addkey = TRUE;
	    continue;

	case OPT_PUBKEYRSA:	/* --pubkeyrsa <key> */
	    {
		static char keyspace[1024 + 4];	/* room for 8K bit key */
		char diag_space[TTODATAV_BUF];
		const char *ugh = ttodatav(optarg, 0, 0
		    , keyspace, sizeof(keyspace)
		    , &msg.keyval.len, diag_space, sizeof(diag_space));

		if (ugh != NULL)
		{
		    char ugh_space[80];	/* perhaps enough space */

		    snprintf(ugh_space, sizeof(ugh_space)
			, "RSA public-key data malformed (%s)", ugh);
		    diagq(ugh_space, optarg);
		}
		msg.pubkey_alg = PUBKEY_ALG_RSA;
		msg.keyval.ptr = keyspace;
	    }
	    continue;

	case OPT_ROUTE:	/* --route */
	    msg.whack_route = TRUE;
	    continue;

	case OPT_UNROUTE:	/* --unroute */
	    msg.whack_unroute = TRUE;
	    continue;

	case OPT_INITIATE:	/* --initiate */
	    msg.whack_initiate = TRUE;
	    continue;

	case OPT_TERMINATE:	/* --terminate */
	    msg.whack_terminate = TRUE;
	    continue;

	case OPT_DELETE:	/* --delete */
	    msg.whack_delete = TRUE;
	    continue;

	case OPT_DELETESTATE:	/* --deletestate <state_object_number> */
	    msg.whack_deletestate = TRUE;
	    msg.whack_deletestateno = opt_whole;
	    continue;

	case OPT_LISTEN:	/* --listen */
	    msg.whack_listen = TRUE;
	    continue;

	case OPT_UNLISTEN:	/* --unlisten */
	    msg.whack_unlisten = TRUE;
	    continue;

        case OPT_UTC:   	/* --utc */
            msg.whack_utc = TRUE;
            continue;

	case OPT_LISTPUBKEYS:	/* --listpubkeys */
	case OPT_LISTCERTS:	/* --listcerts */
	case OPT_LISTCACERTS:	/* --listcacerts */
	case OPT_LISTCRLS:	/* --listcrls */
	    msg.whack_list |= LELEM(c-OPT_LISTPUBKEYS);
	    continue;

	case OPT_LISTALL:	/* --listall */
	    msg.whack_list = LIST_ALL;
	    continue;

	case OPT_REREADSECRETS:	/* --rereadsecrets */
	case OPT_REREADMYCERT:	/* --rereadmycert */
	case OPT_REREADCACERTS:	/* --rereadcacerts */
	case OPT_REREADCRLS:	/* --rereadcrls */
	    msg.whack_reread |= LELEM(c-OPT_REREADSECRETS);
	    continue;

	case OPT_REREADALL:	/* --rereadall */
	    msg.whack_reread = REREAD_ALL;
	    continue;

	case OPT_STATUS:	/* --status */
	    msg.whack_status = TRUE;
	    continue;

	case OPT_SHUTDOWN:	/* --shutdown */
	    msg.whack_shutdown = TRUE;
	    continue;

	case OPT_OPPO_HERE:	/* --oppohere <ip-address> */
	    af_used_by = long_opts[long_index].name;
	    diagq(ttoaddr(optarg, 0, msg.addr_family, &msg.oppo_my_client), optarg);
	    if (isanyaddr(&msg.oppo_my_client))
		diagq("0.0.0.0 or 0::0 isn't a valid client address", optarg);
	    continue;

	case OPT_OPPO_THERE:	/* --oppohere <ip-address> */
	    af_used_by = long_opts[long_index].name;
	    diagq(ttoaddr(optarg, 0, msg.addr_family, &msg.oppo_peer_client), optarg);
	    if (isanyaddr(&msg.oppo_peer_client))
		diagq("0.0.0.0 or 0::0 isn't a valid client address", optarg);
	    continue;

	case OPT_ASYNC:
	    msg.whack_async = TRUE;
	    continue;


	/* Connection Description options */

	case CD_HOST:	/* --host <ip-address> */
	    af_used_by = long_opts[long_index].name;
	    if (streq(optarg, "%any") || streq(optarg, "0.0.0.0"))
	    {
		diagq(anyaddr(msg.addr_family, &msg.right.host_addr), optarg);
	    }
	    else if (streq(optarg, "%opportunistic"))
	    {
		/* we also fill in --client to 0.0.0.0/32 or IPV6 equivalent */
		ip_address  any;

		if (cd_seen & LELEM(CD_CLIENT - CD_FIRST))
		    diag("%opportunistic clashes with --client");

		cd_seen |= LELEM(CD_CLIENT - CD_FIRST);
		tunnel_af_used_by = optarg;
		diagq(anyaddr(msg.addr_family, &msg.right.host_addr), optarg);
		diagq(anyaddr(msg.tunnel_addr_family, &any), optarg);
		diagq(rangetosubnet(&any, &any, &msg.right.client), optarg);
		msg.right.has_client = TRUE;
		/* always use tunnel mode; mark as opportunistic */
		msg.policy |= POLICY_TUNNEL | POLICY_OPPO;
	    }
	    else
	    {
	        if (msg.left.id != NULL) {
			msg.dnshostname = optarg;
		}
		diagq(ttoaddr(optarg, 0, msg.addr_family
		    , &msg.right.host_addr), optarg);
	    }
	    continue;

	case CD_ID:	/* --id <identity> */
	    msg.right.id = optarg;	/* decoded by Pluto */
	    continue;

	case CD_CERT:	/* --cert <path> */
	    msg.right.cert = optarg;	/* decoded by Pluto */
	    continue;

	case CD_IKEPORT:	/* --ikeport <port-number> */
	    if (opt_whole<=0 || opt_whole >= 0x10000)
		diagq("<port-number> must be a number between 1 and 65535", optarg);
	    msg.right.host_port = opt_whole;
	    continue;

	case CD_NEXTHOP:	/* --nexthop <ip-address> */
	    af_used_by = long_opts[long_index].name;
	    if (streq(optarg, "%direct"))
		diagq(anyaddr(msg.addr_family
		    , &msg.right.host_nexthop), optarg);
	    else
		diagq(ttoaddr(optarg, 0, msg.addr_family
		    , &msg.right.host_nexthop), optarg);
	    continue;

	case CD_CLIENT:	/* --client <subnet> */
	    if (cd_seen & LELEM(CD_CLIENTWITHIN - CD_FIRST))
		diag("--client conflicts with --clientwithin");
	    tunnel_af_used_by = long_opts[long_index].name;
#ifdef VIRTUAL_IP
	    if ( ((strlen(optarg)>=6) && (strncmp(optarg,"vhost:",6)==0)) ||
		((strlen(optarg)>=5) && (strncmp(optarg,"vnet:",5)==0)) ) {
		msg.right.virt = optarg;
	    }
	    else {
		diagq(ttosubnet(optarg, 0, msg.tunnel_addr_family, &msg.right.client), optarg);
		msg.right.has_client = TRUE;
	    }
#else
	    diagq(ttosubnet(optarg, 0, msg.tunnel_addr_family, &msg.right.client), optarg);
	    msg.right.has_client = TRUE;
#endif
	    msg.policy |= POLICY_TUNNEL;	/* client => tunnel */
	    continue;

	case CD_CLIENTWITHIN:	/* --clienwithin <address range> */
	    if (cd_seen & LELEM(CD_CLIENT - CD_FIRST))
		diag("--clientwithin conflicts with --client");
	    tunnel_af_used_by = long_opts[long_index].name;
	    diagq(ttosubnet(optarg, 0, msg.tunnel_addr_family, &msg.right.client), optarg);
	    msg.right.has_client = TRUE;
	    msg.policy |= POLICY_TUNNEL;	/* client => tunnel */
	    msg.right.has_client_wildcard = TRUE;
	    continue;

	case CD_CLIENTPROTOPORT: /* --clientprotoport <protocol>/<port> */
	    diagq(ttoprotoport(optarg, 0, &msg.right.protocol,
		&msg.right.port), optarg);
	    continue;

	case CD_UPDOWN:	/* --updown <updown> */
	    msg.right.updown = optarg;
	    continue;

	case CD_TO:		/* --to */
	    /* process right end, move it to left, reset it */
	    if ((cd_seen & LELEM(CD_HOST-CD_FIRST)) == 0)
		diag("connection missing --host before --to");
	    msg.left = msg.right;
	    zero(&msg.right);
	    msg.right.id = NULL;
	    msg.right.cert = NULL;
	    msg.right.updown = NULL;
	    msg.right.host_port = IKE_UDP_PORT;
	    cd_seen_before_to = cd_seen;
	    cd_seen &= ~LRANGE(CD_HOST-CD_FIRST, CD_UPDOWN-CD_FIRST);
	    continue;

	case CD_AGGRESSIVE:	/* --aggrmode */
	case CD_PSK:		/* --psk */
	case CD_RSASIG:		/* --rsasig */
	case CD_ENCRYPT:	/* --encrypt */
	case CD_AUTHENTICATE:	/* --authenticate */
	case CD_COMPRESS:	/* --compress */
	case CD_TUNNEL:		/* --tunnel */
	case CD_PFS:		/* --pfs */
	case CD_DISABLEARRIVALCHECK:	/* --disablearrivalcheck */
	case CD_FAIL_PASS:	/* --pass */
	case CD_FAIL_DROP:	/* --drop */
	case CD_DONT_REKEY:	/* --donotrekey */
	    msg.policy |= LELEM(c - CD_POLICY_FIRST);
	    continue;

	case CD_IKELIFETIME:	/* --ikelifetime <seconds> */
	    msg.sa_ike_life_seconds = opt_whole;
	    continue;

	case CD_IPSECLIFETIME:	/* --ipseclifetime <seconds> */
	    msg.sa_ipsec_life_seconds = opt_whole;
	    continue;

	case CD_RKMARGIN:	/* --rekeymargin <seconds> */
	    msg.sa_rekey_margin = opt_whole;
	    continue;

	case CD_RKFUZZ:	/* --rekeyfuzz <percentage> */
	    msg.sa_rekey_fuzz = opt_whole;
	    continue;

	case CD_KTRIES:	/* --keyingtries <count> */
	    msg.sa_keying_tries = opt_whole;
	    continue;

	case CD_DPDDELAY:	/* --dpddelay */
	    msg.dpd_delay = opt_whole;
	    continue;

	case CD_DPDTIMEOUT:	/* --dpdtimeout */
	    msg.dpd_timeout = opt_whole;
	    continue;

	case CD_CIPHER_P1:	/* --cipher */
	    if (streq(optarg, "des"))
	    	msg.cipher_p1 = OAKLEY_DES_CBC;
	    else if (streq(optarg, "3des"))
	    	msg.cipher_p1 = OAKLEY_3DES_CBC;
	    continue;

	case CD_DHG_P1:	/* --dhg */
	    msg.dhg_p1 = opt_whole;
	    continue;
	
	case CD_HASH_P1:	/* --hash */
	    if (streq(optarg, "md5"))
	    	msg.hash_p1 = OAKLEY_MD5;
	    else if (streq(optarg, "sha"))
	    	msg.hash_p1 = OAKLEY_SHA;
	    continue;

	case CD_IKE:	/* --ike <ike_alg1,ike_alg2,...> */
	    msg.ike = optarg;
	    continue;
	    
	case CD_PFSGROUP:	/* --pfsgroup modpXXXX */
	    msg.pfsgroup = optarg;
	    continue;

	case CD_ESP:	/* --esp <esp_alg1,esp_alg2,...> */
	    msg.esp = optarg;
	    continue;

	case CD_RETRANSMIT:
	    msg.retransmit_trigger = opt_whole;
	    continue;

	case CD_CONNIPV4:
	    if (cd_seen & LELEM(CD_CONNIPV6 - CD_FIRST))
		diag("--ipv4 conflicts with --ipv6");

	    /* Since this is the default, the flag is redundant.
	     * So we don't need to set msg.addr_family
	     * and we don't need to check af_used_by
	     * and we don't have to consider defaulting tunnel_addr_family.
	     */
	    continue;

	case CD_CONNIPV6:
	    if (cd_seen & LELEM(CD_CONNIPV4 - CD_FIRST))
		diag("--ipv6 conflicts with --ipv4");

	    if (af_used_by != NULL)
		diagq("--ipv6 must precede", af_used_by);

	    af_used_by = long_opts[long_index].name;
	    msg.addr_family = AF_INET6;

	    /* Consider defaulting tunnel_addr_family to AF_INET6.
	     * Do so only if it hasn't yet been specified or used.
	     */
	    if ((cd_seen & (LELEM(CD_TUNNELIPV4 - CD_FIRST) | LELEM(CD_TUNNELIPV6 - CD_FIRST))) == 0
	    && tunnel_af_used_by == NULL)
		msg.tunnel_addr_family = AF_INET6;
	    continue;

	case CD_TUNNELIPV4:
	    if (cd_seen & LELEM(CD_TUNNELIPV6 - CD_FIRST))
		diag("--tunnelipv4 conflicts with --tunnelipv6");

	    if (tunnel_af_used_by != NULL)
		diagq("--tunnelipv4 must precede", af_used_by);

	    msg.tunnel_addr_family = AF_INET;
	    continue;

	case CD_TUNNELIPV6:
	    if (cd_seen & LELEM(CD_TUNNELIPV4 - CD_FIRST))
		diag("--tunnelipv6 conflicts with --tunnelipv4");

	    if (tunnel_af_used_by != NULL)
		diagq("--tunnelipv6 must precede", af_used_by);

	    msg.tunnel_addr_family = AF_INET6;
	    continue;

#ifdef DEBUG
	case DBGOPT_NONE:	/* --debug-none */
	    msg.debugging = DBG_NONE;
	    continue;

	case DBGOPT_ALL:	/* --debug-all */
	    msg.debugging |= DBG_ALL;	/* note: does not include PRIVATE */
	    continue;

	case DBGOPT_RAW:	/* --debug-raw */
	case DBGOPT_CRYPT:	/* --debug-crypt */
	case DBGOPT_PARSING:	/* --debug-parsing */
	case DBGOPT_EMITTING:	/* --debug-emitting */
	case DBGOPT_CONTROL:	/* --debug-control */
	case DBGOPT_LIFECYCLE:	/* --debug-lifecycle */
	case DBGOPT_KLIPS:	/* --debug-klips */
	case DBGOPT_DNS:	/* --debug-dns */
	case DBGOPT_PRIVATE:	/* --debug-private */
	    msg.debugging |= LELEM(c-DBGOPT_RAW);
	    continue;
#endif
	default:
	    assert(FALSE);	/* unknown return value */
	}
	break;
    }

    if (optind != argc) {
	fprintf(stderr, "optind %d ", optind);
	fprintf(stderr, "argc %d ", argc);
	fprintf(stderr, "optarg %s ", optarg);
	diagq("unexpected argument", argv[optind]);
    }
    /* For each possible form of the command, figure out if an argument
     * suggests whether that form was intended, and if so, whether all
     * required information was supplied.
     */

    /* check opportunistic initiation simulation request */
    switch (opts_seen & (LELEM(OPT_OPPO_HERE) | LELEM(OPT_OPPO_THERE)))
    {
    case LELEM(OPT_OPPO_HERE):
    case LELEM(OPT_OPPO_THERE):
	diag("--oppohere and --oppothere must be used together");
	/*NOTREACHED*/
    case LELEM(OPT_OPPO_HERE) | LELEM(OPT_OPPO_THERE):
	msg.whack_oppo_initiate = TRUE;
	break;
    }

    /* check connection description */
    if (opts_seen & LELEM(OPT_CD))
    {
	if (!LALLIN(cd_seen, LELEM(CD_TO-CD_FIRST)))
	    diag("connection description option, but no --to");

	if ((cd_seen & LELEM(CD_HOST-CD_FIRST)) == 0)
	    diag("connection missing --host after --to");

	if ((cd_seen & (CD_PSK | CD_RSASIG)) == 0)
	    diag("connection must have --psk or --rsasig or both");

	if (isanyaddr(&msg.left.host_addr)
	&& isanyaddr(&msg.right.host_addr))
	    diag("hosts cannot both be 0.0.0.0 or 0::0");

	check_end(&msg.left, &msg.right, msg.policy, (cd_seen_before_to & LELEM(CD_NEXTHOP-CD_FIRST)) == 0
	    , msg.addr_family, msg.tunnel_addr_family);

	check_end(&msg.right, &msg.left, msg.policy, (cd_seen & LELEM(CD_NEXTHOP-CD_FIRST)) == 0
	    , msg.addr_family, msg.tunnel_addr_family);

	if (subnettypeof(&msg.left.client) != subnettypeof(&msg.right.client))
	    diag("endpoints clash: one is IPv4 and the other is IPv6");

	if ((msg.policy & POLICY_ID_AUTH_MASK) == LEMPTY)
	    diag("must specify --rsasig or --psk for a connection");

	if (!HAS_IPSEC_POLICY(msg.policy)
	&& (msg.left.has_client || msg.right.has_client))
	    diag("must not specify clients for ISAKMP-only connection");

	msg.whack_connection = TRUE;
    }

    /* decide whether --name is mandatory or forbidden */
    if (opts_seen & (LELEM(OPT_ROUTE) | LELEM(OPT_UNROUTE)
    | LELEM(OPT_INITIATE) | LELEM(OPT_TERMINATE)
    | LELEM(OPT_DELETE) | LELEM(OPT_CD)))
    {
	if ((opts_seen & LELEM(OPT_NAME)) == 0)
	    diag("missing --name <connection_name>");
    }
    else if (!msg.whack_options)
    {
	if ((opts_seen & LELEM(OPT_NAME)) != 0)
	    diag("no reason for --name");
    }

    if (opts_seen & (LELEM(OPT_PUBKEYRSA) | LELEM(OPT_ADDKEY)))
    {
	if ((opts_seen & LELEM(OPT_KEYID)) == 0)
	    diag("--addkey and --pubkeyrsa require --keyid");
    }

    if (!(msg.whack_connection || msg.whack_key
    || msg.whack_delete || msg.whack_deletestate
    || msg.whack_initiate || msg.whack_oppo_initiate || msg.whack_terminate
    || msg.whack_route || msg.whack_unroute || msg.whack_listen
    || msg.whack_unlisten || msg.whack_list || msg.whack_reread
    || msg.whack_status || msg.whack_options || msg.whack_shutdown))
    {
	diag("no action specified; try --help for hints");
    }

    /* tricky quick and dirty check for wild values */
    if (msg.sa_rekey_margin != 0
    && msg.sa_rekey_fuzz * msg.sa_rekey_margin * 4 / msg.sa_rekey_margin / 4
     != msg.sa_rekey_fuzz)
	diag("rekeymargin or rekeyfuzz values are so large that they cause oveflow");

    check_life_time (msg.sa_ike_life_seconds, OAKLEY_ISAKMP_SA_LIFETIME_MAXIMUM
	, "ikelifetime", &msg);

    check_life_time(msg.sa_ipsec_life_seconds, SA_LIFE_DURATION_MAXIMUM
	, "ipseclifetime", &msg);

    if (msg.dpd_delay && !msg.dpd_timeout)
	diag("dpddelay specified, but dpdtimeout is zero");

    /* build esp message as esp="<esp>;<pfsgroup>" */
    if (msg.pfsgroup) {
	    snprintf(esp_buf, sizeof (esp_buf), "%s;%s", 
		    msg.esp ? msg.esp : "",
		    msg.pfsgroup ? msg.pfsgroup : "");
	    msg.esp=esp_buf;
    }
    /* pack strings for inclusion in message */
    next_str = msg.string;
    str_roof = &msg.string[sizeof(msg.string)];

    if (!pack_str(&msg.name)		/* string 1 */
    || !pack_str(&msg.left.id)		/* string 2 */
    || !pack_str(&msg.left.cert)	/* string 3 */
    || !pack_str(&msg.left.updown)	/* string 4 */
#ifdef VIRTUAL_IP
    || !pack_str(&msg.left.virt)
#endif
    || !pack_str(&msg.right.id)		/* string 5 */
    || !pack_str(&msg.right.cert)	/* string 6 */
    || !pack_str(&msg.right.updown)	/* string 7 */
#ifdef VIRTUAL_IP
    || !pack_str(&msg.right.virt)
#endif
    || !pack_str(&msg.keyid)		/* string 8 */
    || !pack_str(&msg.ike)		/* string 9 */
    || !pack_str(&msg.esp)		/* string 10 */
    || !pack_str(&msg.dnshostname)	/* string 11 */
    || str_roof - next_str < (ptrdiff_t)msg.keyval.len)    /* chunk (sort of string 5) */
	diag("too many bytes of strings to fit in message to pluto");

    memcpy(next_str, msg.keyval.ptr, msg.keyval.len);
    msg.keyval.ptr = NULL;
    next_str += msg.keyval.len;

    /* send message to Pluto */
    if (access(ctl_addr.sun_path, R_OK | W_OK) < 0)
    {
	int e = errno;

	switch(e)
	{
	case EACCES:
	    fprintf(stderr, "whack: no right to communicate with pluto (access(\"%s\"))\n"
		, ctl_addr.sun_path);
	    break;
	case ENOENT:
	    fprintf(stderr, "whack: Pluto is not running (no \"%s\")\n"
		, ctl_addr.sun_path);
	    break;
	default:
	    fprintf(stderr, "whack: access(\"%s\") failed with %d %s\n"
		, ctl_addr.sun_path, errno, strerror(e));
	    break;
	}
	exit(RC_WHACK_PROBLEM);
    }
    else
    {
	int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	int exit_status = 0;
	ssize_t len = next_str - (char *)&msg;

	if (sock == -1)
	{
	    int e = errno;

	    fprintf(stderr, "whack: socket() failed (%d %s)\n", e, strerror(e));
	    exit(RC_WHACK_PROBLEM);
	}

	if (connect(sock, (struct sockaddr *)&ctl_addr
	, offsetof(struct sockaddr_un, sun_path) + strlen(ctl_addr.sun_path)) < 0)
	{
	    int e = errno;

	    fprintf(stderr, "whack:%s connect() for \"%s\" failed (%d %s)\n"
		, e == ECONNREFUSED? " is Pluto running? " : ""
		, ctl_addr.sun_path, e, strerror(e));
	    exit(RC_WHACK_PROBLEM);
	}

	if (write(sock, &msg, len) != len)
	{
	    int e = errno;

	    fprintf(stderr, "whack: write() failed (%d %s)\n", e, strerror(e));
	    exit(RC_WHACK_PROBLEM);
	}

	/* for now, just copy reply back to stdout */

	{
	    char buf[4097];	/* arbitrary limit on log line length */
	    char *be = buf;

	    for (;;)
	    {
		char *ls = buf;
		ssize_t rl = read(sock, be, (buf + sizeof(buf)-1) - be);

		if (rl < 0)
		{
		    int e = errno;

		    fprintf(stderr, "whack: read() failed (%d %s)\n", e, strerror(e));
		    exit(RC_WHACK_PROBLEM);
		}
		if (rl == 0)
		{
		    if (be != buf)
			fprintf(stderr, "whack: last line from pluto too long or unterminated\n");
		    break;
		}

		be += rl;
		*be = '\0';

		for (;;)
		{
		    char *le = strchr(ls, '\n');

		    if (le == NULL)
		    {
			/* move last, partial line to start of buffer */
			memmove(buf, ls, be-ls);
			be -= ls - buf;
			break;
		    }

		    le++;	/* include NL in line */

		    /* figure out prefix number
		     * and how it should affect our exit status
		     */
		    {
			unsigned long s = strtoul(ls, NULL, 10);

			switch (s)
			{
			case RC_COMMENT:
			case RC_LOG:
			    /* ignore */
			    break;
			case RC_SUCCESS:
			    /* be happy */
			    exit_status = 0;
			    break;
			/* case RC_LOG_SERIOUS: */
			default:
			    /* pass through */
			    exit_status = s;
			    break;
			}
		    }
		    write(1, ls, le - ls);
		    ls = le;
		}
	    }
	}
	return exit_status;
    }
}
