/* ulogd_output_IPFIX.c, Version $Revision: 1628 $
 *
 * ulogd output plugin for IPFIX
 *
 * This target produces a file which looks the same like the syslog-entries
 * of the LOG target.
 *
 * (C) 2005 by Harald Welte <laforge@gnumonks.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id: ulogd_output_LOGEMU.c 1628 2005-11-04 15:23:12Z laforge $
 *
 * TODO:
 * - where to get a useable <sctp.h> for linux ?
 * - implement PR-SCTP (no api definition in draft sockets api)
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#ifdef IPPROTO_SCTP
/* temporarily disable sctp until we know which headers to use */
#undef IPPROTO_SCTP
#endif

#ifdef IPPROTO_SCTP
typedef u_int32_t sctp_assoc_t;

/* glibc doesn't yet have this, as defined by
 * draft-ietf-tsvwg-sctpsocket-11.txt */
struct sctp_sndrcvinfo {
	u_int16_t	sinfo_stream;
	u_int16_t	sinfo_ssn;
	u_int16_t	sinfo_flags;
	u_int32_t	sinfo_ppid;
	u_int32_t	sinfo_context;
	u_int32_t	sinfo_timetolive;
	u_int32_t	sinfo_tsn;
	u_int32_t	sinfo_cumtsn;
	sctp_assoc_t	sinfo_assoc_id;
};
#endif

#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include <ulogd/ipfix_protocol.h>

#define IPFIX_DEFAULT_TCPUDP_PORT	4739

static struct config_keyset ipfix_kset = {
	.num_ces = 3,
	.ces = {
		{
			.key 	 = "host",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
		{
			.key	 = "port",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u	 = { .string = "4739" },
		},
		{
			.key	 = "protocol",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u	= { .string = "udp" },
		},
	},
};

#define host_ce(x)	(x->ces[0])
#define port_ce(x)	(x->ces[1])
#define proto_ce(x)	(x->ces[2])

struct ipfix_template {
	struct ipfix_templ_rec_hdr hdr;
	char buf[0];
};

struct ipfix_instance {
	int fd;		/* socket that we use for sending IPFIX data */
	int sock_type;	/* type (SOCK_*) */
	int sock_proto;	/* protocol (IPPROTO_*) */

	struct ipfix_template *tmpl;
	unsigned int tmpl_len;
	char *tmpl_cur;	/* cursor into current template position */

	unsigned int total_length;	/* total size of all data elements */
};

/* Build the IPFIX template from the input keys */
static int build_template(struct ulogd_pluginstance *upi)
{
	struct ipfix_instance *ii = (struct ipfix_instance *) &upi->private;
	struct ipfix_templ_rec_hdr *rhdr;
	unsigned int i, j;

	if (ii->tmpl)
		free(ii->tmpl);

	ii->tmpl = malloc(sizeof(struct ipfix_template) +
			 (upi->input.num_keys*sizeof(struct ipfix_vendor_field)));
	if (!ii->tmpl)
		return -ENOMEM;

#define ULOGD_IPFIX_TEMPL_BASE 1024

	/* initialize template header */
	ii->tmpl->hdr.templ_id = htons(ULOGD_IPFIX_TEMPL_BASE);

	ii->tmpl_cur = ii->tmpl->buf;

	ii->total_length = 0;

	for (i = 0; i < upi->input.num_keys; i++) {
		struct ulogd_key *key = &upi->input.keys[i];
		int length = ulogd_key_size(key);

		if (length < 0 || length > 0xfffe)
			continue;

		if (key->ipfix.field_id == 0)
			continue;

		if (key->ipfix.vendor == IPFIX_VENDOR_IETF) {
			struct ipfix_ietf_field *field = 
				(struct ipfix_ietf_field *) ii->tmpl_cur;

			field->type = htons(key->ipfix.field_id | 0x8000000);
			field->length = htons(length);
			ii->tmpl_cur += sizeof(*field);
		} else {
			struct ipfix_vendor_field *field =
				(struct ipfix_vendor_field *) ii->tmpl_cur;

			field->enterprise_num = htonl(key->ipfix.vendor);
			field->type = htons(key->ipfix.field_id);
			field->length = htons(length);
			ii->tmpl_cur += sizeof(*field);
		}
		ii->total_length += length;
		j++;
	}

	ii->tmpl->hdr.field_count = htons(j);
	return 0;
}

static int output_ipfix(struct ulogd_pluginstance *upi)
{
	struct ipfix_instance *ii = (struct ipfix_instance *) &upi->private;
	int i;

	for (i = 0; i < upi->input.num_keys; i++) {
		struct ulogd_key *key = upi->input.keys[i].u.source;
	}

	return 0;
}

static int open_connect_socket(struct ulogd_pluginstance *pi)
{
	struct ipfix_instance *ii = (struct ipfix_instance *) &pi->private;
	struct addrinfo hint, *res, *resave;
	int ret;

	memset(&hint, 0, sizeof(hint));
	hint.ai_socktype = ii->sock_type;
	hint.ai_protocol = ii->sock_proto;
#ifdef AI_ADDRCONFIG
	hint.ai_flags = AI_ADDRCONFIG;
#endif

	ret = getaddrinfo(host_ce(pi->config_kset).u.string,
			  port_ce(pi->config_kset).u.string,
			  &hint, &res);
	if (ret != 0) {
		ulogd_log(ULOGD_ERROR, "can't resolve host/service: %s\n",
			  gai_strerror(ret));
		return -1;
	}

	resave = res;

	for (; res; res = res->ai_next) {
		ii->fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (ii->fd < 0) {
			switch (errno) {
			case EACCES:
			case EAFNOSUPPORT:
			case EINVAL:
			case EPROTONOSUPPORT:
				/* try next result */
				continue;
			default:
				ulogd_log(ULOGD_ERROR, "error: %s\n",
					  strerror(errno));
				break;
			}
		}

#ifdef IPPROTO_SCTP
		/* Set the number of SCTP output streams */
		if (res->ai_protocol == IPPROTO_SCTP) {
			struct sctp_initmsg initmsg;
			int ret; 
			memset(&initmsg, 0, sizeof(initmsg));
			initmsg.sinit_num_ostreams = 2;
			ret = setsockopt(ii->fd, IPPROTO_SCTP, SCTP_INITMSG,
					 &initmsg, sizeof(initmsg));
			if (ret < 0) {
				ulogd_log(ULOGD_ERROR, "cannot set number of"
					  "sctp streams: %s\n",
					  strerror(errno));
				close(ii->fd);
				freeaddrinfo(resave);
				return ret;
			}
#endif

		if (connect(ii->fd, res->ai_addr, res->ai_addrlen) != 0) {
			close(ii->fd);
			/* try next result */
			continue;
		}

		/* if we reach this, we have a working connection */
		ulogd_log(ULOGD_NOTICE, "connection established\n");
		freeaddrinfo(resave);
		return 0;
	}

	freeaddrinfo(resave);
	return -1;
}

static int start_ipfix(struct ulogd_pluginstance *pi)
{
	struct ipfix_instance *li = (struct ipfix_instance *) &pi->private;
	int ret;

	ulogd_log(ULOGD_DEBUG, "starting ipfix\n");

	ret = open_connect_socket(pi);
	if (ret < 0)
		return ret;

	ret = build_template(pi);
	if (ret < 0)
		return ret;

	return 0;
}

static int stop_ipfix(struct ulogd_pluginstance *pi) 
{
	struct ipfix_instance *li = (struct ipfix_instance *) &pi->private;

	close(li->fd);

	return 0;
}

static void signal_handler_ipfix(struct ulogd_pluginstance *pi, int signal)
{
	struct ipfix_instance *li = (struct ipfix_instance *) &pi->private;

	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "ipfix: reopening connection\n");
		stop_ipfix(pi);
		start_ipfix(pi);
		break;
	default:
		break;
	}
}
	
static int configure_ipfix(struct ulogd_pluginstance *pi,
			    struct ulogd_pluginstance_stack *stack)
{
	struct ipfix_instance *ii = (struct ipfix_instance *) &pi->private;
	char *proto_str = proto_ce(pi->config_kset).u.string;
	int ret;

	/* FIXME: error handling */
	ulogd_log(ULOGD_DEBUG, "parsing config file section %s\n", pi->id);
	ret = config_parse_file(pi->id, pi->config_kset);
	if (ret < 0)
		return ret;

	/* determine underlying protocol */
	if (!strcasecmp(proto_str, "udp")) {
		ii->sock_type = SOCK_DGRAM;
		ii->sock_proto = IPPROTO_UDP;
	} else if (!strcasecmp(proto_str, "tcp")) {
		ii->sock_type = SOCK_STREAM;
		ii->sock_proto = IPPROTO_TCP;
#ifdef IPPROTO_SCTP
	} else if (!strcasecmp(proto_str, "sctp")) {
		ii->sock_type = SOCK_SEQPACKET;
		ii->sock_proto = IPPROTO_SCTP;
#endif
#ifdef _HAVE_DCCP
	} else if (!strcasecmp(proto_str, "dccp")) {
		ii->sock_type = SOCK_SEQPACKET;
		ii->sock_proto = IPPROTO_DCCP;
#endif
	} else {
		ulogd_log(ULOGD_ERROR, "unknown protocol `%s'\n",
			  proto_ce(pi->config_kset));
		return -EINVAL;
	}

	/* postpone address lookup to ->start() time, since we want to 
	 * re-lookup an address on SIGHUP */

	return ulogd_wildcard_inputkeys(pi);
}

static struct ulogd_plugin ipfix_plugin = { 
	.name = "IPFIX",
	.input = {
		.keys = NULL,
		.num_keys = 0,
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW, 
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.config_kset 	= &ipfix_kset,
	.priv_size 	= sizeof(struct ipfix_instance),

	.configure	= &configure_ipfix,
	.start	 	= &start_ipfix,
	.stop	 	= &stop_ipfix,

	.interp 	= &output_ipfix, 
	.signal 	= &signal_handler_ipfix,
	.version	= ULOGD_VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&ipfix_plugin);
}
