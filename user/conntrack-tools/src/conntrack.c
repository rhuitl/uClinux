/*
 * (C) 2005-2007 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Note:
 *	Yes, portions of this code has been stolen from iptables ;)
 *	Special thanks to the the Netfilter Core Team.
 *	Thanks to Javier de Miguel Rodriguez <jmiguel at talika.eii.us.es>
 *	for introducing me to advanced firewalling stuff.
 *
 *						--pablo 13/04/2005
 *
 * 2005-04-16 Harald Welte <laforge@netfilter.org>: 
 * 	Add support for conntrack accounting and conntrack mark
 * 2005-06-23 Harald Welte <laforge@netfilter.org>:
 * 	Add support for expect creation
 * 2005-09-24 Harald Welte <laforge@netfilter.org>:
 * 	Remove remaints of "-A"
 * 2007-04-22 Pablo Neira Ayuso <pablo@netfilter.org>:
 * 	Ported to the new libnetfilter_conntrack API
 *
 */
#include <stdio.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#include <fcntl.h>
#include <dlfcn.h>
#include <signal.h>
#include <string.h>
#include "linux_list.h"
#include "conntrack.h"
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_ipv4.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_ipv6.h>

static const char cmdflags[NUMBER_OF_CMD]
= {'L','I','U','D','G','F','E','V','h','L','I','D','G','F','E'};

static const char cmd_need_param[NUMBER_OF_CMD]
= { 2,  0,  0,  0,  0,  2,  2,  2,  2,  2,  0,  0,  0,  2,  2 };

static const char *optflags[NUMBER_OF_OPT] = {
"src","dst","reply-src","reply-dst","protonum","timeout","status","zero",
"event-mask","tuple-src","tuple-dst","mask-src","mask-dst","nat-range","mark",
"id","family","src-nat","dst-nat","output" };

static struct option original_opts[] = {
	{"dump", 2, 0, 'L'},
	{"create", 1, 0, 'I'},
	{"delete", 1, 0, 'D'},
	{"update", 1, 0, 'U'},
	{"get", 1, 0, 'G'},
	{"flush", 1, 0, 'F'},
	{"event", 1, 0, 'E'},
	{"version", 0, 0, 'V'},
	{"help", 0, 0, 'h'},
	{"orig-src", 1, 0, 's'},
	{"src", 1, 0, 's'},
	{"orig-dst", 1, 0, 'd'},
	{"dst", 1, 0, 'd'},
	{"reply-src", 1, 0, 'r'},
	{"reply-dst", 1, 0, 'q'},
	{"protonum", 1, 0, 'p'},
	{"timeout", 1, 0, 't'},
	{"status", 1, 0, 'u'},
	{"zero", 0, 0, 'z'},
	{"event-mask", 1, 0, 'e'},
	{"tuple-src", 1, 0, '['},
	{"tuple-dst", 1, 0, ']'},
	{"mask-src", 1, 0, '{'},
	{"mask-dst", 1, 0, '}'},
	{"nat-range", 1, 0, 'a'},	/* deprecated */
	{"mark", 1, 0, 'm'},
	{"id", 2, 0, 'i'},		/* deprecated */
	{"family", 1, 0, 'f'},
	{"src-nat", 2, 0, 'n'},
	{"dst-nat", 2, 0, 'g'},
	{"output", 1, 0, 'o'},
	{0, 0, 0, 0}
};

#define OPTION_OFFSET 256

static struct nfct_handle *cth;
static struct option *opts = original_opts;
static unsigned int global_option_offset = 0;

/* Table of legal combinations of commands and options.  If any of the
 * given commands make an option legal, that option is legal (applies to
 * CMD_LIST and CMD_ZERO only).
 * Key:
 *  0  illegal
 *  1  compulsory
 *  2  optional
 */

static char commands_v_options[NUMBER_OF_CMD][NUMBER_OF_OPT] =
/* Well, it's better than "Re: Linux vs FreeBSD" */
{
          /*   s d r q p t u z e [ ] { } a m i f n g o */
/*CT_LIST*/   {2,2,2,2,2,0,0,2,0,0,0,0,0,0,2,2,2,2,2,2},
/*CT_CREATE*/ {2,2,2,2,1,1,1,0,0,0,0,0,0,2,2,0,0,2,2,0},
/*CT_UPDATE*/ {2,2,2,2,1,2,2,0,0,0,0,0,0,0,2,2,0,0,0,0},
/*CT_DELETE*/ {2,2,2,2,2,0,0,0,0,0,0,0,0,0,0,2,0,0,0,0},
/*CT_GET*/    {2,2,2,2,1,0,0,0,0,0,0,0,0,0,0,2,0,0,0,2},
/*CT_FLUSH*/  {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
/*CT_EVENT*/  {2,2,2,2,2,0,0,0,2,0,0,0,0,0,2,0,0,2,2,2},
/*VERSION*/   {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
/*HELP*/      {0,0,0,0,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
/*EXP_LIST*/  {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,2,0,0,0},
/*EXP_CREATE*/{1,1,2,2,1,1,2,0,0,1,1,1,1,0,0,0,0,0,0,0},
/*EXP_DELETE*/{1,1,2,2,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
/*EXP_GET*/   {1,1,2,2,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
/*EXP_FLUSH*/ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
/*EXP_EVENT*/ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
};

static LIST_HEAD(proto_list);

static unsigned int options;
static unsigned int command;

#define CT_COMPARISON (CT_OPT_PROTO | CT_OPT_ORIG | CT_OPT_REPL | CT_OPT_MARK)

void register_proto(struct ctproto_handler *h)
{
	if (strcmp(h->version, VERSION) != 0) {
		fprintf(stderr, "plugin `%s': version %s (I'm %s)\n",
			h->name, h->version, VERSION);
		exit(1);
	}
	list_add(&h->head, &proto_list);
}

static struct ctproto_handler *findproto(char *name)
{
	struct list_head *i;
	struct ctproto_handler *cur = NULL, *handler = NULL;

	if (!name) 
		return handler;

	list_for_each(i, &proto_list) {
		cur = (struct ctproto_handler *) i;
		if (strcmp(cur->name, name) == 0) {
			handler = cur;
			break;
		}
	}

	return handler;
}

void extension_help(struct ctproto_handler *h)
{
	fprintf(stdout, "\n");
	fprintf(stdout, "Proto `%s' help:\n", h->name);
	h->help();
}

void
exit_tryhelp(int status)
{
	fprintf(stderr, "Try `%s -h' or '%s --help' for more information.\n",
			PROGNAME, PROGNAME);
	exit(status);
}

void exit_error(enum exittype status, char *msg, ...)
{
	va_list args;

	/* On error paths, make sure that we don't leak the memory
	 * reserved during options merging */
	if (opts != original_opts) {
		free(opts);
		opts = original_opts;
		global_option_offset = 0;
	}
	va_start(args, msg);
	fprintf(stderr,"%s v%s: ", PROGNAME, VERSION);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, "\n");
	if (status == PARAMETER_PROBLEM)
		exit_tryhelp(status);
	exit(status);
}

static void
generic_cmd_check(int command, int options)
{
	if (cmd_need_param[command] == 0 && !options)
		exit_error(PARAMETER_PROBLEM,
			   "You need to supply parameters to `-%c'\n",
			   cmdflags[command]);
}

static int bit2cmd(int command)
{
	int i;

	for (i = 0; i < NUMBER_OF_CMD; i++)
		if (command & (1<<i))
			break;

	return i;
}

void generic_opt_check(int options, 
		       int num_opts,
		       char *optset, 
		       const char *optflg[])
{
	int i;

	for (i = 0; i < num_opts; i++) {
		if (!(options & (1<<i))) {
			if (optset[i] == 1)
				exit_error(PARAMETER_PROBLEM, 
					   "You need to supply the "
					   "`--%s' option for this "
					   "command\n", optflg[i]);
		} else {
			if (optset[i] == 0)
				exit_error(PARAMETER_PROBLEM, "Illegal "
					   "option `--%s' with this "
					   "command\n", optflg[i]);
		}
	}
}

static struct option *
merge_options(struct option *oldopts, const struct option *newopts,
	      unsigned int *option_offset)
{
	unsigned int num_old, num_new, i;
	struct option *merge;

	for (num_old = 0; oldopts[num_old].name; num_old++);
	for (num_new = 0; newopts[num_new].name; num_new++);

	global_option_offset += OPTION_OFFSET;
	*option_offset = global_option_offset;

	merge = malloc(sizeof(struct option) * (num_new + num_old + 1));
	memcpy(merge, oldopts, num_old * sizeof(struct option));
	for (i = 0; i < num_new; i++) {
		merge[num_old + i] = newopts[i];
		merge[num_old + i].val += *option_offset;
	}
	memset(merge + num_old + num_new, 0, sizeof(struct option));

	return merge;
}

/* From linux/errno.h */
#define ENOTSUPP        524     /* Operation is not supported */

/* Translates errno numbers into more human-readable form than strerror. */
const char *
err2str(int err, enum action command)
{
	unsigned int i;
	struct table_struct {
		enum action act;
		int err;
		const char *message;
	} table [] =
	  { { CT_LIST, ENOTSUPP, "function not implemented" },
	    { 0xFFFF, EINVAL, "invalid parameters" },
	    { CT_CREATE, EEXIST, "Such conntrack exists, try -U to update" },
	    { CT_CREATE|CT_GET|CT_DELETE, ENOENT, 
		    "such conntrack doesn't exist" },
	    { CT_CREATE|CT_GET, ENOMEM, "not enough memory" },
	    { CT_GET, EAFNOSUPPORT, "protocol not supported" },
	    { CT_CREATE, ETIME, "conntrack has expired" },
	    { EXP_CREATE, ENOENT, "master conntrack not found" },
	    { EXP_CREATE, EINVAL, "invalid parameters" },
	    { ~0UL, EPERM, "sorry, you must be root or get "
		    	   "CAP_NET_ADMIN capability to do this"}
	  };

	for (i = 0; i < sizeof(table)/sizeof(struct table_struct); i++) {
		if ((table[i].act & command) && table[i].err == err)
			return table[i].message;
	}

	return strerror(err);
}

#define PARSE_STATUS 0
#define PARSE_EVENT 1
#define PARSE_OUTPUT 2
#define PARSE_MAX 3

static struct parse_parameter {
	char 	*parameter[6];
	size_t  size;
	unsigned int value[6];
} parse_array[PARSE_MAX] = {
	{ {"ASSURED", "SEEN_REPLY", "UNSET", "FIXED_TIMEOUT"}, 4,
	  { IPS_ASSURED, IPS_SEEN_REPLY, 0, IPS_FIXED_TIMEOUT} },
	{ {"ALL", "NEW", "UPDATES", "DESTROY"}, 4,
	  {~0U, NF_NETLINK_CONNTRACK_NEW, NF_NETLINK_CONNTRACK_UPDATE, 
	   NF_NETLINK_CONNTRACK_DESTROY} },
	{ {"xml", "extended", "timestamp" }, 3, 
	  { _O_XML, _O_EXT, _O_TMS },
	},
};

static int
do_parse_parameter(const char *str, size_t strlen, unsigned int *value, 
		   int parse_type)
{
	int i, ret = 0;
	struct parse_parameter *p = &parse_array[parse_type];

	if (strncasecmp(str, "SRC_NAT", strlen) == 0) {
		printf("skipping SRC_NAT, use --src-nat instead\n");
		return 1;
	}

	if (strncasecmp(str, "DST_NAT", strlen) == 0) {
		printf("skipping DST_NAT, use --dst-nat instead\n");
		return 1;
	}

	for (i = 0; i < p->size; i++)
		if (strncasecmp(str, p->parameter[i], strlen) == 0) {
			*value |= p->value[i];
			ret = 1;
			break;
		}
	
	return ret;
}

static void
parse_parameter(const char *arg, unsigned int *status, int parse_type)
{
	const char *comma;

	while ((comma = strchr(arg, ',')) != NULL) {
		if (comma == arg 
		    || !do_parse_parameter(arg, comma-arg, status, parse_type))
			exit_error(PARAMETER_PROBLEM,"Bad parameter `%s'", arg);
		arg = comma+1;
	}

	if (strlen(arg) == 0
	    || !do_parse_parameter(arg, strlen(arg), status, parse_type))
		exit_error(PARAMETER_PROBLEM, "Bad parameter `%s'", arg);
}

static void
add_command(unsigned int *cmd, const int newcmd, const int othercmds)
{
	if (*cmd & (~othercmds))
		exit_error(PARAMETER_PROBLEM, "Invalid commands combination\n");
	*cmd |= newcmd;
}

unsigned int check_type(int argc, char *argv[])
{
	char *table = NULL;

	/* Nasty bug or feature in getopt_long ? 
	 * It seems that it behaves badly with optional arguments.
	 * Fortunately, I just stole the fix from iptables ;) */
	if (optarg)
		return 0;
	else if (optind < argc && argv[optind][0] != '-' 
			&& argv[optind][0] != '!')
		table = argv[optind++];
	
	if (!table)
		return 0;
		
	if (strncmp("expect", table, 6) == 0)
		return 1;
	else if (strncmp("conntrack", table, 9) == 0)
		return 0;
	else
		exit_error(PARAMETER_PROBLEM, "unknown type `%s'\n", table);

	return 0;
}

static void set_family(int *family, int new)
{
	if (*family == AF_UNSPEC)
		*family = new;
	else if (*family != new)
		exit_error(PARAMETER_PROBLEM, "mismatched address family\n");
}

struct addr_parse {
	struct in_addr addr;
	struct in6_addr addr6;
	unsigned int family;
};

int parse_inetaddr(const char *cp, struct addr_parse *parse)
{
	if (inet_aton(cp, &parse->addr))
		return AF_INET;
#ifdef HAVE_INET_PTON_IPV6
	else if (inet_pton(AF_INET6, cp, &parse->addr6) > 0)
		return AF_INET6;
#endif

	exit_error(PARAMETER_PROBLEM, "Invalid IP address `%s'.", cp);
}

union ct_address {
	u_int32_t v4;
	u_int32_t v6[4];
};

int parse_addr(const char *cp, union ct_address *address)
{
	struct addr_parse parse;
	int ret;

	if ((ret = parse_inetaddr(cp, &parse)) == AF_INET)
		address->v4 = parse.addr.s_addr;
	else if (ret == AF_INET6)
		memcpy(address->v6, &parse.addr6, sizeof(parse.addr6));

	return ret;
}

/* Shamelessly stolen from libipt_DNAT ;). Ranges expected in network order. */
static void
nat_parse(char *arg, int portok, struct nf_conntrack *obj, int type)
{
	char *colon, *dash, *error;
	union ct_address parse;

	colon = strchr(arg, ':');

	if (colon) {
		u_int16_t port;

		if (!portok)
			exit_error(PARAMETER_PROBLEM,
				   "Need TCP or UDP with port specification");

		port = atoi(colon+1);
		if (port == 0)
			exit_error(PARAMETER_PROBLEM,
				   "Port `%s' not valid\n", colon+1);

		error = strchr(colon+1, ':');
		if (error)
			exit_error(PARAMETER_PROBLEM,
				   "Invalid port:port syntax\n");

		if (type == CT_OPT_SRC_NAT)
			nfct_set_attr_u16(obj, ATTR_SNAT_PORT, port);
		else if (type == CT_OPT_DST_NAT)
			nfct_set_attr_u16(obj, ATTR_DNAT_PORT, port);
	}

	if (parse_addr(arg, &parse) != AF_INET)
		return;

	if (type == CT_OPT_SRC_NAT)
		nfct_set_attr_u32(obj, ATTR_SNAT_IPV4, parse.v4);
	else if (type == CT_OPT_DST_NAT)
		nfct_set_attr_u32(obj, ATTR_DNAT_IPV4, parse.v4);
}

static void event_sighandler(int s)
{
	fprintf(stdout, "Now closing conntrack event dumping...\n");
	nfct_close(cth);
	exit(0);
}

static const char usage_commands[] =
	"Commands:\n"
	"  -L [table] [options]\t\tList conntrack or expectation table\n"
	"  -G [table] parameters\t\tGet conntrack or expectation\n"
	"  -D [table] parameters\t\tDelete conntrack or expectation\n"
	"  -I [table] parameters\t\tCreate a conntrack or expectation\n"
	"  -U [table] parameters\t\tUpdate a conntrack\n"
	"  -E [table] [options]\t\tShow events\n"
	"  -F [table]\t\t\tFlush table\n";

static const char usage_tables[] =
	"Tables: conntrack, expect\n";

static const char usage_conntrack_parameters[] =
	"Conntrack parameters and options:\n"
	"  -n, --src-nat ip\t\t\tsource NAT ip\n"
	"  -g, --dst-nat ip\t\t\tdestination NAT ip\n"
	"  -m, --mark mark\t\t\tSet mark\n"
	"  -e, --event-mask eventmask\t\tEvent mask, eg. NEW,DESTROY\n"
	"  -z, --zero \t\t\t\tZero counters while listing\n"
	"  -o, --output type[,...]\t\tOutput format, eg. xml\n";
	;

static const char usage_expectation_parameters[] =
	"Expectation parameters and options:\n"
	"  --tuple-src ip\tSource address in expect tuple\n"
	"  --tuple-dst ip\tDestination address in expect tuple\n"
	"  --mask-src ip\t\tSource mask address\n"
	"  --mask-dst ip\t\tDestination mask address\n";

static const char usage_parameters[] =
	"Common parameters and options:\n"
	"  -s, --orig-src ip\t\tSource address from original direction\n"
	"  -d, --orig-dst ip\t\tDestination address from original direction\n"
	"  -r, --reply-src ip\t\tSource addres from reply direction\n"
	"  -q, --reply-dst ip\t\tDestination address from reply direction\n"
	"  -p, --protonum proto\t\tLayer 4 Protocol, eg. 'tcp'\n"
	"  -f, --family proto\t\tLayer 3 Protocol, eg. 'ipv6'\n"
	"  -t, --timeout timeout\t\tSet timeout\n"
	"  -u, --status status\t\tSet status, eg. ASSURED\n"
	;
  

void usage(char *prog) {
	fprintf(stdout, "Command line interface for the connection "
			"tracking system. Version %s\n", VERSION);
	fprintf(stdout, "Usage: %s [commands] [options]\n", prog);

	fprintf(stdout, "\n%s", usage_commands);
	fprintf(stdout, "\n%s", usage_tables);
	fprintf(stdout, "\n%s", usage_conntrack_parameters);
	fprintf(stdout, "\n%s", usage_expectation_parameters);
	fprintf(stdout, "\n%s", usage_parameters);
}

static unsigned int output_mask;

static int event_cb(enum nf_conntrack_msg_type type,
		    struct nf_conntrack *ct,
		    void *data)
{
	char buf[1024];
	struct nf_conntrack *obj = data;
	unsigned int output_type = NFCT_O_DEFAULT;
	unsigned int output_flags = 0;

	if (options & CT_OPT_SRC_NAT && options & CT_OPT_DST_NAT) {
		if (!nfct_getobjopt(ct, NFCT_GOPT_IS_SNAT) &&
		    !nfct_getobjopt(ct, NFCT_GOPT_IS_DNAT))
			return NFCT_CB_CONTINUE;
	} else if (options & CT_OPT_SRC_NAT && 
		   !nfct_getobjopt(ct, NFCT_GOPT_IS_SNAT)) {
	 	return NFCT_CB_CONTINUE;
	} else if (options & CT_OPT_DST_NAT &&
		   !nfct_getobjopt(ct, NFCT_GOPT_IS_DNAT)) {
		return NFCT_CB_CONTINUE;
	}

	if (options & CT_COMPARISON && !nfct_compare(obj, ct))
		return NFCT_CB_CONTINUE;

	if (output_mask & _O_XML)
		output_type = NFCT_O_XML;
	if (output_mask & _O_EXT)
		output_flags = NFCT_OF_SHOW_LAYER3;
	if ((output_mask & _O_TMS) && !(output_mask & _O_XML)) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		printf("[%-8ld.%-6ld]\t", tv.tv_sec, tv.tv_usec);
	}

	nfct_snprintf(buf, 1024, ct, type, output_type, output_flags);
	printf("%s\n", buf);
	fflush(stdout);

	return NFCT_CB_CONTINUE;
}

static int dump_cb(enum nf_conntrack_msg_type type,
		   struct nf_conntrack *ct,
		   void *data)
{
	char buf[1024];
	struct nf_conntrack *obj = data;
	unsigned int output_type = NFCT_O_DEFAULT;
	unsigned int output_flags = 0;

	if (options & CT_OPT_SRC_NAT && options & CT_OPT_DST_NAT) {
		if (!nfct_getobjopt(ct, NFCT_GOPT_IS_SNAT) &&
		    !nfct_getobjopt(ct, NFCT_GOPT_IS_DNAT))
			return NFCT_CB_CONTINUE;
	} else if (options & CT_OPT_SRC_NAT && 
		   !nfct_getobjopt(ct, NFCT_GOPT_IS_SNAT)) {
	 	return NFCT_CB_CONTINUE;
	} else if (options & CT_OPT_DST_NAT &&
		   !nfct_getobjopt(ct, NFCT_GOPT_IS_DNAT)) {
		return NFCT_CB_CONTINUE;
	}

	if (options & CT_COMPARISON && !nfct_compare(obj, ct))
		return NFCT_CB_CONTINUE;

	if (output_mask & _O_XML)
		output_type = NFCT_O_XML;
	if (output_mask & _O_EXT)
		output_flags = NFCT_OF_SHOW_LAYER3;

	nfct_snprintf(buf, 1024, ct, NFCT_T_UNKNOWN, output_type, output_flags);
	printf("%s\n", buf);

	return NFCT_CB_CONTINUE;
}

static int dump_exp_cb(enum nf_conntrack_msg_type type,
		      struct nf_expect *exp,
		      void *data)
{
	char buf[1024];

	nfexp_snprintf(buf, 1024, exp, NFCT_T_UNKNOWN, NFCT_O_DEFAULT, 0);
	printf("%s\n", buf);

	return NFCT_CB_CONTINUE;
}

static struct ctproto_handler *h;

int main(int argc, char *argv[])
{
	int c, cmd;
	unsigned int type = 0, event_mask = 0, l4flags = 0, status = 0;
	int res = 0;
	int family = AF_UNSPEC;
	char __obj[nfct_maxsize()];
	char __exptuple[nfct_maxsize()];
	char __mask[nfct_maxsize()];
	struct nf_conntrack *obj = (struct nf_conntrack *) __obj;
	struct nf_conntrack *exptuple = (struct nf_conntrack *) __exptuple;
	struct nf_conntrack *mask = (struct nf_conntrack *) __mask;
	char __exp[nfexp_maxsize()];
	struct nf_expect *exp = (struct nf_expect *) __exp;
	int l3protonum;
	union ct_address ad;

	memset(__obj, 0, sizeof(__obj));
	memset(__exptuple, 0, sizeof(__exptuple));
	memset(__mask, 0, sizeof(__mask));
	memset(__exp, 0, sizeof(__exp));

	register_tcp();
	register_udp();
	register_icmp();

	while ((c = getopt_long(argc, argv, 
		"L::I::U::D::G::E::F::hVs:d:r:q:p:t:u:e:a:z[:]:{:}:m:i::f:o:", 
		opts, NULL)) != -1) {
	switch(c) {
		case 'L':
			type = check_type(argc, argv);
			if (type == 0)
				add_command(&command, CT_LIST, CT_NONE);
			else if (type == 1)
				add_command(&command, EXP_LIST, CT_NONE);
			break;
		case 'I':
			type = check_type(argc, argv);
			if (type == 0)
				add_command(&command, CT_CREATE, CT_NONE);
			else if (type == 1)
				add_command(&command, EXP_CREATE, CT_NONE);
			break;
		case 'U':
			type = check_type(argc, argv);
			if (type == 0)
				add_command(&command, CT_UPDATE, CT_NONE);
			else
				exit_error(PARAMETER_PROBLEM, "Can't update "
					   "expectations");
			break;
		case 'D':
			type = check_type(argc, argv);
			if (type == 0)
				add_command(&command, CT_DELETE, CT_NONE);
			else if (type == 1)
				add_command(&command, EXP_DELETE, CT_NONE);
			break;
		case 'G':
			type = check_type(argc, argv);
			if (type == 0)
				add_command(&command, CT_GET, CT_NONE);
			else if (type == 1)
				add_command(&command, EXP_GET, CT_NONE);
			break;
		case 'F':
			type = check_type(argc, argv);
			if (type == 0)
				add_command(&command, CT_FLUSH, CT_NONE);
			else if (type == 1)
				add_command(&command, EXP_FLUSH, CT_NONE);
			break;
		case 'E':
			type = check_type(argc, argv);
			if (type == 0)
				add_command(&command, CT_EVENT, CT_NONE);
			else if (type == 1)
				add_command(&command, EXP_EVENT, CT_NONE);
			break;
		case 'V':
			add_command(&command, CT_VERSION, CT_NONE);
			break;
		case 'h':
			add_command(&command, CT_HELP, CT_NONE);
			break;
		case 's':
			options |= CT_OPT_ORIG_SRC;
			if (!optarg)
				break;

			l3protonum = parse_addr(optarg, &ad);
			set_family(&family, l3protonum);
			if (l3protonum == AF_INET) {
				nfct_set_attr_u32(obj, 
						  ATTR_ORIG_IPV4_SRC, 
						  ad.v4);
			} else if (l3protonum == AF_INET6) {
				nfct_set_attr(obj,
					      ATTR_ORIG_IPV6_SRC, 
					      &ad.v6);
			}
			nfct_set_attr_u8(obj, ATTR_ORIG_L3PROTO, l3protonum);
			break;
		case 'd':
			options |= CT_OPT_ORIG_DST;
			if (!optarg)
				break;

			l3protonum = parse_addr(optarg, &ad);
			set_family(&family, l3protonum);
			if (l3protonum == AF_INET) {
				nfct_set_attr_u32(obj, 
						  ATTR_ORIG_IPV4_DST,
						  ad.v4);
			} else if (l3protonum == AF_INET6) {
				nfct_set_attr(obj,
					      ATTR_ORIG_IPV6_DST,
					      &ad.v6);
			}
			nfct_set_attr_u8(obj, ATTR_ORIG_L3PROTO, l3protonum);
			break;
		case 'r':
			options |= CT_OPT_REPL_SRC;
			if (!optarg)
				break;

			l3protonum = parse_addr(optarg, &ad);
			set_family(&family, l3protonum);
			if (l3protonum == AF_INET) {
				nfct_set_attr_u32(obj,
						  ATTR_REPL_IPV4_SRC, 
						  ad.v4);
			} else if (l3protonum == AF_INET6) {
				nfct_set_attr(obj,
					      ATTR_REPL_IPV6_SRC,
					      &ad.v6);
			}
			nfct_set_attr_u8(obj, ATTR_REPL_L3PROTO, l3protonum);
			break;
		case 'q':
			options |= CT_OPT_REPL_DST;
			if (!optarg)
				break;

			l3protonum = parse_addr(optarg, &ad);
			set_family(&family, l3protonum);
			if (l3protonum == AF_INET) {
				nfct_set_attr_u32(obj,
						  ATTR_REPL_IPV4_DST,
						  ad.v4);
			} else if (l3protonum == AF_INET6) {
				nfct_set_attr(obj,
					      ATTR_REPL_IPV6_DST,
					      &ad.v6);
			}
			nfct_set_attr_u8(obj, ATTR_REPL_L3PROTO, l3protonum);
			break;
		case 'p':
			options |= CT_OPT_PROTO;
			h = findproto(optarg);
			if (!h)
				exit_error(PARAMETER_PROBLEM, "proto needed\n");

			nfct_set_attr_u8(obj, ATTR_ORIG_L4PROTO, h->protonum);
			nfct_set_attr_u8(obj, ATTR_REPL_L4PROTO, h->protonum);
			nfct_set_attr_u8(exptuple, 
					 ATTR_ORIG_L4PROTO, 
					 h->protonum);
			nfct_set_attr_u8(mask, 
					 ATTR_ORIG_L4PROTO, 
					 h->protonum);
			opts = merge_options(opts, h->opts, &h->option_offset);
			break;
		case 't':
			options |= CT_OPT_TIMEOUT;
			if (!optarg)
				continue;

			nfct_set_attr_u32(obj, ATTR_TIMEOUT, atol(optarg));
			nfexp_set_attr_u32(exp, ATTR_EXP_TIMEOUT, atol(optarg));
			break;
		case 'u': {
			if (!optarg)
				continue;

			options |= CT_OPT_STATUS;
			parse_parameter(optarg, &status, PARSE_STATUS);
			nfct_set_attr_u32(obj, ATTR_STATUS, status);
			break;
		}
		case 'e':
			options |= CT_OPT_EVENT_MASK;
			parse_parameter(optarg, &event_mask, PARSE_EVENT);
			break;
		case 'z':
			options |= CT_OPT_ZERO;
			break;
		case '{':
			options |= CT_OPT_MASK_SRC;
			if (!optarg)
				break;

			l3protonum = parse_addr(optarg, &ad);
			set_family(&family, l3protonum);
			if (l3protonum == AF_INET) {
				nfct_set_attr_u32(mask, 
						  ATTR_ORIG_IPV4_SRC,
						  ad.v4);
			} else if (l3protonum == AF_INET6) {
				nfct_set_attr(mask,
					      ATTR_ORIG_IPV6_SRC,
					      &ad.v6);
			}
			nfct_set_attr_u8(mask, ATTR_ORIG_L3PROTO, l3protonum);
			break;
		case '}':
			options |= CT_OPT_MASK_DST;
			if (!optarg)
				break;

			l3protonum = parse_addr(optarg, &ad);
			set_family(&family, l3protonum);
			if (l3protonum == AF_INET) {
				nfct_set_attr_u32(mask, 
						  ATTR_ORIG_IPV4_DST,
						  ad.v4);
			} else if (l3protonum == AF_INET6) {
				nfct_set_attr(mask,
					      ATTR_ORIG_IPV6_DST,
					      &ad.v6);
			}
			nfct_set_attr_u8(mask, ATTR_ORIG_L3PROTO, l3protonum);
			break;
		case '[':
			options |= CT_OPT_EXP_SRC;
			if (!optarg)
				break;

			l3protonum = parse_addr(optarg, &ad);
			set_family(&family, l3protonum);
			if (l3protonum == AF_INET) {
				nfct_set_attr_u32(exptuple, 
						  ATTR_ORIG_IPV4_SRC,
						  ad.v4);
			} else if (l3protonum == AF_INET6) {
				nfct_set_attr(exptuple,
					      ATTR_ORIG_IPV6_SRC,
					      &ad.v6);
			}
			nfct_set_attr_u8(exptuple, 
					 ATTR_ORIG_L3PROTO, 
					 l3protonum);
			break;
		case ']':
			options |= CT_OPT_EXP_DST;
			if (!optarg)
				break;

			l3protonum = parse_addr(optarg, &ad);
			set_family(&family, l3protonum);
			if (l3protonum == AF_INET) {
				nfct_set_attr_u32(exptuple, 
						  ATTR_ORIG_IPV4_DST,
						  ad.v4);
			} else if (l3protonum == AF_INET6) {
				nfct_set_attr(exptuple,
					      ATTR_ORIG_IPV6_DST,
					      &ad.v6);
			}
			nfct_set_attr_u8(exptuple, 
					 ATTR_ORIG_L3PROTO, 
					 l3protonum);
			break;
		case 'a':
			printf("warning: ignoring --nat-range, "
			       "use --src-nat or --dst-nat instead.\n");
			break;
		case 'n':
			options |= CT_OPT_SRC_NAT;
			if (!optarg)
				break;
			set_family(&family, AF_INET);
			nat_parse(optarg, 1, obj, CT_OPT_SRC_NAT);
			break;
		case 'g':
			options |= CT_OPT_DST_NAT;
			if (!optarg)
				break;
			set_family(&family, AF_INET);
			nat_parse(optarg, 1, obj, CT_OPT_DST_NAT);
		case 'm':
			options |= CT_OPT_MARK;
			if (!optarg)
				continue;
			nfct_set_attr_u32(obj, ATTR_MARK, atol(optarg));
			break;
		case 'i':
			printf("warning: ignoring --id. deprecated option.\n");
			break;
		case 'f':
			options |= CT_OPT_FAMILY;
			if (strncmp(optarg, "ipv4", strlen("ipv4")) == 0)
				set_family(&family, AF_INET);
			else if (strncmp(optarg, "ipv6", strlen("ipv6")) == 0)
				set_family(&family, AF_INET6);
			else
				exit_error(PARAMETER_PROBLEM, "Unknown "
					   "protocol family\n");
			break;
		case 'o':
			options |= CT_OPT_OUTPUT;
			parse_parameter(optarg, &output_mask, PARSE_OUTPUT);
			break;
		default:
			if (h && h->parse_opts 
			    &&!h->parse_opts(c - h->option_offset, obj,
			    		     exptuple, mask, &l4flags))
				exit_error(PARAMETER_PROBLEM, "parse error\n");

			/* Unknown argument... */
			if (!h) {
				usage(argv[0]);
				exit_error(PARAMETER_PROBLEM, "Missing "
					   "arguments...\n");
			}
			break;
		}
	}

	/* default family */
	if (family == AF_UNSPEC)
		family = AF_INET;

	cmd = bit2cmd(command);
	generic_cmd_check(cmd, options);
	generic_opt_check(options,
			  NUMBER_OF_OPT,
			  commands_v_options[cmd],
			  optflags);

	if (!(command & CT_HELP) && h && h->final_check)
		h->final_check(l4flags, cmd, obj);

	switch(command) {

	case CT_LIST:
		cth = nfct_open(CONNTRACK, 0);
		if (!cth)
			exit_error(OTHER_PROBLEM, "Can't open handler");

		if (options & CT_COMPARISON && 
		    options & CT_OPT_ZERO)
			exit_error(PARAMETER_PROBLEM, "Can't use -z with "
						      "filtering parameters");

		nfct_callback_register(cth, NFCT_T_ALL, dump_cb, obj);

		if (options & CT_OPT_ZERO)
			res = nfct_query(cth, NFCT_Q_DUMP_RESET, &family);
		else
			res = nfct_query(cth, NFCT_Q_DUMP, &family);

		nfct_close(cth);
		break;

	case EXP_LIST:
		cth = nfct_open(EXPECT, 0);
		if (!cth)
			exit_error(OTHER_PROBLEM, "Can't open handler");

		nfexp_callback_register(cth, NFCT_T_ALL, dump_exp_cb, NULL);
		res = nfexp_query(cth, NFCT_Q_DUMP, &family);
		nfct_close(cth);
		break;
			
	case CT_CREATE:
		if ((options & CT_OPT_ORIG) && !(options & CT_OPT_REPL))
		    	nfct_setobjopt(obj, NFCT_SOPT_SETUP_REPLY);
		else if (!(options & CT_OPT_ORIG) && (options & CT_OPT_REPL))
			nfct_setobjopt(obj, NFCT_SOPT_SETUP_ORIGINAL);

		cth = nfct_open(CONNTRACK, 0);
		if (!cth)
			exit_error(OTHER_PROBLEM, "Can't open handler");

		res = nfct_query(cth, NFCT_Q_CREATE, obj);
		nfct_close(cth);
		break;

	case EXP_CREATE:
		nfexp_set_attr(exp, ATTR_EXP_MASTER, obj);
		nfexp_set_attr(exp, ATTR_EXP_EXPECTED, exptuple);
		nfexp_set_attr(exp, ATTR_EXP_MASK, mask);

		cth = nfct_open(EXPECT, 0);
		if (!cth)
			exit_error(OTHER_PROBLEM, "Can't open handler");

		res = nfexp_query(cth, NFCT_Q_CREATE, exp);
		nfct_close(cth);
		break;

	case CT_UPDATE:
		if ((options & CT_OPT_ORIG) && !(options & CT_OPT_REPL))
		    	nfct_setobjopt(obj, NFCT_SOPT_SETUP_REPLY);
		else if (!(options & CT_OPT_ORIG) && (options & CT_OPT_REPL))
			nfct_setobjopt(obj, NFCT_SOPT_SETUP_ORIGINAL);

		cth = nfct_open(CONNTRACK, 0);
		if (!cth)
			exit_error(OTHER_PROBLEM, "Can't open handler");

		res = nfct_query(cth, NFCT_Q_UPDATE, obj);
		nfct_close(cth);
		break;
		
	case CT_DELETE:
		if (!(options & CT_OPT_ORIG) && !(options & CT_OPT_REPL))
			exit_error(PARAMETER_PROBLEM, "Can't kill conntracks "
						      "just by its ID");
		cth = nfct_open(CONNTRACK, 0);
		if (!cth)
			exit_error(OTHER_PROBLEM, "Can't open handler");

		res = nfct_query(cth, NFCT_Q_DESTROY, obj);
		nfct_close(cth);
		break;

	case EXP_DELETE:
		nfexp_set_attr(exp, ATTR_EXP_EXPECTED, obj);

		cth = nfct_open(EXPECT, 0);
		if (!cth)
			exit_error(OTHER_PROBLEM, "Can't open handler");

		res = nfexp_query(cth, NFCT_Q_DESTROY, exp);
		nfct_close(cth);
		break;

	case CT_GET:
		cth = nfct_open(CONNTRACK, 0);
		if (!cth)
			exit_error(OTHER_PROBLEM, "Can't open handler");

		nfct_callback_register(cth, NFCT_T_ALL, dump_cb, obj);
		res = nfct_query(cth, NFCT_Q_GET, obj);
		nfct_close(cth);
		break;

	case EXP_GET:
		nfexp_set_attr(exp, ATTR_EXP_MASTER, obj);

		cth = nfct_open(EXPECT, 0);
		if (!cth)
			exit_error(OTHER_PROBLEM, "Can't open handler");

		nfexp_callback_register(cth, NFCT_T_ALL, dump_exp_cb, NULL);
		res = nfexp_query(cth, NFCT_Q_GET, exp);
		nfct_close(cth);
		break;

	case CT_FLUSH:
		cth = nfct_open(CONNTRACK, 0);
		if (!cth)
			exit_error(OTHER_PROBLEM, "Can't open handler");
		res = nfct_query(cth, NFCT_Q_FLUSH, &family);
		nfct_close(cth);
		break;

	case EXP_FLUSH:
		cth = nfct_open(EXPECT, 0);
		if (!cth)
			exit_error(OTHER_PROBLEM, "Can't open handler");
		res = nfexp_query(cth, NFCT_Q_FLUSH, &family);
		nfct_close(cth);
		break;
		
	case CT_EVENT:
		if (options & CT_OPT_EVENT_MASK)
			cth = nfct_open(CONNTRACK, event_mask);
		else
			cth = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);

		if (!cth)
			exit_error(OTHER_PROBLEM, "Can't open handler");
		signal(SIGINT, event_sighandler);
		nfct_callback_register(cth, NFCT_T_ALL, event_cb, obj);
		res = nfct_catch(cth);
		nfct_close(cth);
		break;

	case EXP_EVENT:
		cth = nfct_open(EXPECT, NF_NETLINK_CONNTRACK_EXP_NEW);
		if (!cth)
			exit_error(OTHER_PROBLEM, "Can't open handler");
		signal(SIGINT, event_sighandler);
		nfexp_callback_register(cth, NFCT_T_ALL, dump_exp_cb, NULL);
		res = nfexp_catch(cth);
		nfct_close(cth);
		break;
			
	case CT_VERSION:
		printf("%s v%s (conntrack-tools)\n", PROGNAME, VERSION);
		break;
	case CT_HELP:
		usage(argv[0]);
		if (options & CT_OPT_PROTO)
			extension_help(h);
		break;
	default:
		usage(argv[0]);
		break;
	}

	if (opts != original_opts) {
		free(opts);
		opts = original_opts;
		global_option_offset = 0;
	}

	if (res < 0) {
		fprintf(stderr, "Operation failed: %s\n", err2str(errno, command));
		exit(OTHER_PROBLEM);
	}

	return 0;
}
