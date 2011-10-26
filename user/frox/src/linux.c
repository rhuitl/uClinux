/***************************************

    This is part of frox: A simple transparent FTP proxy
    Copyright (C) 2000 James Hollingshead

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

  linux.c -- Nasty, non-portable, linux specific stuff which changes
             from kernel release to kernel release. ie the transparent 
             proxy calls.

***************************************/

#include <sys/utsname.h>
#include <sys/wait.h>
#include "common.h"
#include "transdata.h"

#if HAVE_LINUX_NETFILTER_IPV4_H
# include <limits.h>
# include <linux/netfilter_ipv4.h>
#endif

#if TRANS_DATA
#if USE_LIBIPTC
# include <libiptc.h>
# include <linux/netfilter_ipv4/ip_nat.h>
#endif
#endif

static enum {
	LINUX_2_0,
	LINUX_2_2,
	LINUX_2_4,
	OTHER
} kernel;

/* Had to add os_init() for the purpose of IP_FILTER on *BSD, but since
 * it's there might as well use it! */
int os_init(void)
{
	struct utsname tmp;

	uname(&tmp);
	if(!strncmp(tmp.release, "2.0.", 4))
		kernel = LINUX_2_0;
	else if(!strncmp(tmp.release, "2.2.", 4))
		kernel = LINUX_2_2;
	else if(!strncmp(tmp.release, "2.4.", 4))
		kernel = LINUX_2_4;
	else
		kernel = OTHER;
	return 0;
}

/* ------------------------------------------------------------- **
**  Get the original destination address of a transparently proxied
**  socket.
**  ------------------------------------------------------------- */
int get_orig_dest(int fd, struct sockaddr_in *addr)
{
	socklen_t len;

	len = sizeof(*addr);
	switch (kernel) {
	case LINUX_2_0:
	case LINUX_2_2:
		return (getsockname(fd, (struct sockaddr *) addr, &len));
	default:
#ifdef SO_ORIGINAL_DST		/*Header support for kernel 2.4 */
		if(getsockopt(fd, SOL_IP, SO_ORIGINAL_DST,
			      (struct sockaddr *) addr, &len))
			return -1;
		if(!addr->sin_addr.s_addr)
			return -1;
		return 0;
#else
		write_log(ERROR,
			  "Running on a kernel we haven't been compiled for. Oooops.");
		return (-1);
#endif
	}
}

/* ------------------------------------------------------------- **
**  Get the address of the interface we connect to the client through
**  for putting in our 227 reply. For 2.4 do a getsockname on the
**  control socket. For 2.2 this gives us the orriginal destination of
**  the transparently proxied connection, so we do some nasty hackery
**  instead.
**  ------------------------------------------------------------- */
int get_local_address(const int fd, struct sockaddr_in *addr)
{
	int sockfd;
	socklen_t len;

	/*If ListenAddress is in the config file then use the address
	 * from that*/
	*addr = config.listen_address;
	if(addr->sin_addr.s_addr != 0) {
		addr->sin_port = 0;
		return (0);
	}

	switch (kernel) {
	case LINUX_2_2:
		/* This piece of code ought to be taken out and shot
		 **  (yes - it opens a UDP socket, does a getsockname,
		 **  and then closes the socket before anything
		 **  happens!) Suggestions for an alternative welcomed */

		if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
			return (-1);

		addr->sin_family = AF_INET;
		addr->sin_addr = info->client_control.address.sin_addr;
		addr->sin_port = htons(12345);
		len = sizeof(*addr);

		if(connect(sockfd, (struct sockaddr *) addr, len) == -1) {
			close(sockfd);
			return (-1);
		}

		if(getsockname(sockfd, (struct sockaddr *) addr, &len) == -1) {
			close(sockfd);
			return (-1);
		}

		close(sockfd);

		addr->sin_port = 0;
		return (0);
	case LINUX_2_4:
	default:
		len = sizeof(*addr);
		return (getsockname(fd, (struct sockaddr *) addr, &len));
	}
}

int bindtodevice(int fd)
{
	if(!config.device)
		return (0);
	if(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
		      (void *) config.device,
		      (socklen_t) strlen(config.device) + 1) != 0) {
		debug_perr("Binding to device");
		return (-1);
	}
	write_log(IMPORT, "Bound to device %s", config.device);
	return (0);
}

#if TRANS_DATA

/* ------------------------------------------------------------- **
**  Functions below are designed for the data link between the client
**  and the proxy. We want to fool the client that this connection
**  comes from the ftp server it connected to, so we have to be able
**  to either connect to the client with a false source address
**  (active mode), or intercept the client trying to connect to the
**  server's data port (passive mode).
**
**  On kernel 2.4 we do this using netfilter snat or dnat through
**  libiptc. On 2.2 we simply do bind-to-foreign-address.[Not tested
**  recently :) ]
**
**  Most of this stuff is a bit of a mess. Perhaps that is
**  unavoidable...
**  ------------------------------------------------------------- */
#ifndef USE_LIBIPTC
int kernel_transdata_setup()
{
	if(kernel != LINUX_2_4)
		return (0);

	fprintf(stderr,
		"You appear to be running a 2.4.x Linux kernel,"
		" but frox was not configured\n"
		"with --enable-libiptc. Data connections will NOT"
		" be transparently proxied\n");
	return (-1);
}

int kernel_td_connect(struct fd_request req)
{
	uid_t uid;
	int sockfd, i;

	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		debug_perr("socket");
		return (-1);
	}

	uid = geteuid();
	write_log(VERBOSE,
		  "TDS: Regaining priveliges for bind-to-foreign-address");
	seteuid(0);
	i = bind(sockfd, (struct sockaddr *) &req.remote, sizeof(req.remote));
	write_log(VERBOSE, "TDS: Dropping them again");
	seteuid(uid);

	if(i) {
		debug_err("bind failed");
		close(sockfd);
		return (-1);
	}

	i = connect(sockfd, (struct sockaddr *) &req.remote,
		    sizeof(req.remote));

	if(i) {
		close(sockfd);
		return (-1);
	}

	return (sockfd);
}

int kernel_td_listen(struct fd_request req)
{
	uid_t uid;
	int i, sockfd;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	uid = geteuid();
	write_log(VERBOSE,
		  "TDS: Regaining privelidges for bind-to-foreign-address");
	seteuid(0);
	i = bind(sockfd, (struct sockaddr *) &req.local, sizeof(req.local));
	write_log(VERBOSE, "TDS: Dropping them again");
	seteuid(uid);

	if(i) {
		debug_err("bind failed");
		close(sockfd);
		return (-1);
	}

	if(listen(sockfd, 5)) {
		debug_perr("listen");
		close(sockfd);
		return (-1);
	}
	return (sockfd);
}

/*Kernel 2.2.x automatically cleans up after bind-to-foreign-address*/
int kernel_td_unlisten(struct fd_request req)
{
	return (0);
}

void kernel_td_flush(void)
{
}
#else /*USE_LIBIPTC */

#define FROXSNAT "froxsnat"
#define FROXDNAT "froxdnat"

int init_chains(void);
void serve_requests(int fd);
int add_entry(const struct ipt_entry *e, const char *chain);
int delete_entry(const struct ipt_entry *e, const char *chain);
struct ipt_entry *get_entry(struct sockaddr_in src, struct sockaddr_in dst,
			    struct sockaddr_in to, int snat);

int kernel_transdata_setup()
{
	if(kernel == LINUX_2_2)
		return (0);

	if(init_chains() == -1) {
		fprintf(stderr,
			"\nChains " FROXSNAT " and/or " FROXDNAT
			" do not exist. Data connections\n"
			"will not be transparently proxied. Read"
			" README.transdata for details\n\n");
		return (-1);
	}

	return 0;
}

int kernel_td_connect(struct fd_request req)
{
	struct sockaddr_in address;
	struct ipt_entry *e;
	int sockfd, i;

	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		debug_perr("socket");
		return (-1);
	}

	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	i = bind_me(sockfd, &address, req.ports);

	if(i) {
		debug_err("bind failed");
		close(sockfd);
		return (-1);
	}


	/* DO SNAT */
	address = config.listen_address;
	address.sin_port = 0;
	e = get_entry(address, req.remote, req.local, TRUE);
	if(e == NULL) {
		close(sockfd);
		return -1;
	}
	if(add_entry(e, FROXSNAT) == -1) {
		free(e);
		close(sockfd);
		return -1;
	}

	i = connect(sockfd, (struct sockaddr *) &req.remote,
		    sizeof(req.remote));

	/* UNDO SNAT */
	delete_entry(e, FROXSNAT);
	free(e);

	if(i) {
		close(sockfd);
		return (-1);
	}

	return (sockfd);
}

int kernel_td_listen(struct fd_request req)
{
	struct sockaddr_in address;
	struct ipt_entry *e;
	int i, sockfd;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	i = bind_me(sockfd, &req.local, req.ports);

	if(i) {
		debug_err("bind failed");
		close(sockfd);
		return (-1);
	}

	if(listen(sockfd, 5)) {
		debug_perr("listen");
		close(sockfd);
		return (-1);
	}

	/*DO DNAT */
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = 0;
	e = get_entry(address, req.remote, req.local, FALSE);
	if(e == NULL) {
		debug_err("Can't get entry");
		close(sockfd);
		return -1;
	}
	if(add_entry(e, FROXDNAT) == -1) {
		debug_err("Unable to add entry");
		free(e);
		close(sockfd);
		return -1;
	}

	return (sockfd);
}

int kernel_td_unlisten(struct fd_request req)
{
	struct ipt_entry *e;
	struct sockaddr_in address;

	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = 0;
	e = get_entry(address, req.remote, req.local, FALSE);
	if(e == NULL) {
		debug_err("Can't get entry");
		return -1;
	}
	if(delete_entry(e, FROXDNAT) == -1) {
		debug_err("Unable to delete entry");
		free(e);
		return -1;
	}
	return (0);
}

void kernel_td_flush(void)
{
	iptc_handle_t h;
	uid_t uid;

	uid = geteuid();
	write_log(VERBOSE, "TDS: Regaining privelidges for flushing chains");
	seteuid(0);
	write_log(VERBOSE, "Flushing chains...");
	if((h = iptc_init("nat"))) {
		iptc_flush_entries(FROXSNAT, &h);
		iptc_flush_entries(FROXDNAT, &h);
		if(iptc_commit(&h))
			write_log(VERBOSE, "   Success");
		else
			write_log(VERBOSE, "   Failed");
	}
	write_log(VERBOSE, "TDS: Dropping them again");
	seteuid(uid);
}

int init_chains()
{
	iptc_handle_t h;

	if(!(h = iptc_init("nat")))
		return (-1);
	if(!iptc_is_chain(FROXSNAT, h))
		return (-1);
	if(!iptc_is_chain(FROXDNAT, h))
		return (-1);
	return (0);
}

int add_entry(const struct ipt_entry *e, const char *chain)
{
	iptc_handle_t h;
	uid_t uid;
	int ret = -1;

	uid = geteuid();
	write_log(VERBOSE,
		  "TDS: Regaining privelidges for inserting firewall rules");
	seteuid(0);

	if((h = iptc_init("nat")) &&
	   iptc_append_entry(chain, e, &h) && iptc_commit(&h))
		ret = 0;
	else
		ret = -1;

	write_log(VERBOSE, "TDS: Dropping them again");
	seteuid(uid);

	return ret;
}

/*FIXME deletion by matching entry doesn't seem to be reliable. Should
  we keep track of rule numbers and delete those?*/
int delete_entry(const struct ipt_entry *e, const char *chain)
{
	iptc_handle_t h;
	unsigned char *matchmask = NULL;
	uid_t uid;
	int ret;

	uid = geteuid();
	write_log(VERBOSE,
		  "TDS: Regaining privelidges for deleting firewall rules");
	seteuid(0);

	if((h = iptc_init("nat")) &&
	   (matchmask = malloc(e->next_offset)) &&
	   iptc_delete_entry(chain, e, matchmask, &h) && iptc_commit(&h))
		ret = 0;
	else {
		debug_err(iptc_strerror(errno));
		ret = -1;
	}

	write_log(VERBOSE, "TDS: Dropping them again");
	seteuid(uid);

	if(matchmask)
		free(matchmask);
	return ret;
}

/* ------------------------------------------------------------- **
** Set up an ipt_entry structure. Which will do the equivalent of
** "iptables -p tcp -s src -d dst -j (SNAT|DNAT) --to to". If snat is
** TRUE we do snat, otherwise dnat. This probably isn't the correct
** way to use libiptc, but there isn't much sample code/documentation
** and I really couldn't face messing around with dlopen etc.
**
** The return value should be freed by the calling function.
**
** I want my bind-to-foreign-address back :)
** ------------------------------------------------------------- */
struct ipt_entry *get_entry(struct sockaddr_in src, struct sockaddr_in dst,
			    struct sockaddr_in to, int snat)
{
	struct ipt_entry *e;

	struct ipt_entry_match *match;
	struct ipt_tcp *tcpinfo;

	struct ipt_entry_target *target;
	struct ip_nat_multi_range *mr;

	unsigned int size1, size2, size3;

	size1 = IPT_ALIGN(sizeof(struct ipt_entry));
	size2 = IPT_ALIGN(sizeof(struct ipt_entry_match) +
			  sizeof(struct ipt_tcp));
	size3 = IPT_ALIGN(sizeof(struct ipt_entry_target) +
			  sizeof(struct ip_nat_multi_range));

	e = malloc(size1 + size2 + size3);
	if(e == NULL) {
		write_log(ERROR, "Malloc failure");
		return (NULL);
	}
	memset(e, 0, size1 + size2 + size3);

	/*Offsets to the other bits */
	e->target_offset = size1 + size2;
	e->next_offset = size1 + size2 + size3;

	/*Set up packet matching rules */
	if((e->ip.src.s_addr = src.sin_addr.s_addr) == INADDR_ANY)
		e->ip.smsk.s_addr = 0;
	else
		e->ip.smsk.s_addr = inet_addr("255.255.255.255");

	if((e->ip.dst.s_addr = dst.sin_addr.s_addr) == INADDR_ANY)
		e->ip.dmsk.s_addr = 0;
	else
		e->ip.dmsk.s_addr = inet_addr("255.255.255.255");

	e->ip.proto = IPPROTO_TCP;
	e->nfcache = NFC_UNKNOWN;	/*Think this stops caching. */

	/*TCP specific matching(ie. ports) */
	match = (struct ipt_entry_match *) e->elems;
	match->u.match_size = size2;
	strcpy(match->u.user.name, "tcp");

	tcpinfo = (struct ipt_tcp *) match->data;

	if(src.sin_port == 0) {
		tcpinfo->spts[0] = ntohs(0);
		tcpinfo->spts[1] = ntohs(0xFFFF);
	} else
		tcpinfo->spts[0] = tcpinfo->spts[1] = ntohs(src.sin_port);
	if(dst.sin_port == 0) {
		tcpinfo->dpts[0] = ntohs(0);
		tcpinfo->dpts[1] = ntohs(0xFFFF);
	} else
		tcpinfo->dpts[0] = tcpinfo->dpts[1] = ntohs(dst.sin_port);

	/*And the target */
	target = (struct ipt_entry_target *) (e->elems + size2);
	target->u.target_size = size3;
	if(snat)
		strcpy(target->u.user.name, "SNAT");
	else
		strcpy(target->u.user.name, "DNAT");

	mr = (struct ip_nat_multi_range *) target->data;
	mr->rangesize = 1;

	mr->range[0].flags = IP_NAT_RANGE_PROTO_SPECIFIED |
		IP_NAT_RANGE_MAP_IPS;
	mr->range[0].min.tcp.port = mr->range[0].max.tcp.port = to.sin_port;
	mr->range[0].min_ip = mr->range[0].max_ip = to.sin_addr.s_addr;

	return e;
}
#endif /*USE_LIBIPTC */
#endif /*TRANS_DATA */
