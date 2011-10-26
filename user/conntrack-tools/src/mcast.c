/*
 * (C) 2006 by Pablo Neira Ayuso <pablo@netfilter.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Description: multicast socket library
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "mcast.h"
#include "debug.h"

struct mcast_sock *mcast_server_create(struct mcast_conf *conf)
{
	int yes = 1;
	union {
		struct ip_mreq ipv4;
		struct ipv6_mreq ipv6;
	} mreq;
	struct mcast_sock *m;

	m = (struct mcast_sock *) malloc(sizeof(struct mcast_sock));
	if (!m)
		return NULL;
	memset(m, 0, sizeof(struct mcast_sock));

	switch(conf->ipproto) {
	case AF_INET:
		mreq.ipv4.imr_multiaddr.s_addr = conf->in.inet_addr.s_addr;
		mreq.ipv4.imr_interface.s_addr =conf->ifa.interface_addr.s_addr;

	        m->addr.ipv4.sin_family = AF_INET;
	        m->addr.ipv4.sin_port = htons(conf->port);
	        m->addr.ipv4.sin_addr.s_addr = htonl(INADDR_ANY);
		break;

	case AF_INET6:
		memcpy(&mreq.ipv6.ipv6mr_multiaddr, &conf->in.inet_addr6,
		       sizeof(u_int32_t) * 4);
		memcpy(&mreq.ipv6.ipv6mr_interface, &conf->ifa.interface_addr6,
		       sizeof(u_int32_t) * 4);

		m->addr.ipv6.sin6_family = AF_INET6;
		m->addr.ipv6.sin6_port = htons(conf->port);
		// already 0 from above
		// m->addr.ipv6.sin6_addr = in6addr_any;
		break;
	}

	if ((m->fd = socket(conf->ipproto, SOCK_DGRAM, 0)) == -1) {
		debug("mcast_sock_server_create:socket");
		free(m);
		return NULL;
	}

	if(conf->iface[0]) {
		struct ifreq ifr;

		strncpy(ifr.ifr_name, conf->iface, sizeof(ifr.ifr_name));

		if (ioctl(m->fd, SIOCGIFMTU, &ifr) == -1) {
			debug("ioctl");
			return NULL;
		}
		conf->mtu = ifr.ifr_mtu;
	}

	if (setsockopt(m->fd, SOL_SOCKET, SO_REUSEADDR, &yes, 
				sizeof(int)) == -1) {
		debug("mcast_sock_server_create:setsockopt1");
		close(m->fd);
		free(m);
		return NULL;
	}

	if (bind(m->fd, (struct sockaddr *) &m->addr, 
			 sizeof(struct sockaddr)) == -1) {
		debug("mcast_sock_server_create:bind");
		close(m->fd);
		free(m);
		return NULL;
	}

	switch(conf->ipproto) {
	case AF_INET:
		if (setsockopt(m->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
			       &mreq.ipv4, sizeof(mreq.ipv4)) < 0) {
			debug("mcast_sock_server_create:setsockopt2");
			close(m->fd);
			free(m);
			return NULL;
		}
		break;
	case AF_INET6:
		if (setsockopt(m->fd, IPPROTO_IPV6, IPV6_JOIN_GROUP,
			       &mreq.ipv6, sizeof(mreq.ipv6)) < 0) {
			debug("mcast_sock_server_create:setsockopt2");
			close(m->fd);
			free(m);
			return NULL;
		}
		break;
	}

	return m;
}

void mcast_server_destroy(struct mcast_sock *m)
{
	close(m->fd);
	free(m);
}

static int 
__mcast_client_create_ipv4(struct mcast_sock *m, struct mcast_conf *conf)
{
	int no = 0;

	m->addr.ipv4.sin_family = AF_INET;
	m->addr.ipv4.sin_port = htons(conf->port);
	m->addr.ipv4.sin_addr = conf->in.inet_addr;

	if (setsockopt(m->fd, IPPROTO_IP, IP_MULTICAST_LOOP, &no,
		       sizeof(int)) < 0) {
		debug("mcast_sock_client_create:setsockopt2");
		close(m->fd);
		return -1;
	}

	if (setsockopt(m->fd, IPPROTO_IP, IP_MULTICAST_IF,
		       &conf->ifa.interface_addr,
		       sizeof(struct in_addr)) == -1) {
		debug("mcast_sock_client_create:setsockopt3");
		close(m->fd);
		free(m);
		return -1;
	}

	return 0;
}

static int 
__mcast_client_create_ipv6(struct mcast_sock *m, struct mcast_conf *conf)
{
	int no = 0;

	m->addr.ipv6.sin6_family = AF_INET6;
	m->addr.ipv6.sin6_port = htons(conf->port);
	memcpy(&m->addr.ipv6.sin6_addr,
	       &conf->in.inet_addr6,
	       sizeof(struct in6_addr));

	if (setsockopt(m->fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &no,
		       sizeof(int)) < 0) {
		debug("mcast_sock_client_create:setsockopt2");
		close(m->fd);
		return -1;
	}

	if (setsockopt(m->fd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
		       &conf->ifa.interface_addr,
		       sizeof(struct in_addr)) == -1) {
		debug("mcast_sock_client_create:setsockopt3");
		close(m->fd);
		free(m);
		return -1;
	}

	return 0;
}

struct mcast_sock *mcast_client_create(struct mcast_conf *conf)
{
	int ret = 0;
	struct sockaddr_in addr;
	struct mcast_sock *m;

	m = (struct mcast_sock *) malloc(sizeof(struct mcast_sock));
	if (!m)
		return NULL;
	memset(m, 0, sizeof(struct mcast_sock));

	if ((m->fd = socket(conf->ipproto, SOCK_DGRAM, 0)) == -1) {
		debug("mcast_sock_client_create:socket");
		return NULL;
	}

	if (setsockopt(m->fd, SOL_SOCKET, SO_NO_CHECK, &conf->checksum, 
				sizeof(int)) == -1) {
		debug("mcast_sock_client_create:setsockopt1");
		close(m->fd);
		free(m);
		return NULL;
	}

	switch(conf->ipproto) {
		case AF_INET:
			ret = __mcast_client_create_ipv4(m, conf);
			break;
		case AF_INET6:
			ret = __mcast_client_create_ipv6(m, conf);
			break;
		default:
			break;
	}

	if (ret == -1) {
		free(m);
		m = NULL;
	}

	return m;
}

void mcast_client_destroy(struct mcast_sock *m)
{
	close(m->fd);
	free(m);
}

int mcast_send(struct mcast_sock *m, void *data, int size)
{
	int ret;
	
	ret = sendto(m->fd, 
		     data,
		     size,
		     0,
		     (struct sockaddr *) &m->addr,
		     sizeof(struct sockaddr));
	if (ret == -1) {
		debug("mcast_sock_send");
		m->stats.error++;
		return ret;
	}

	m->stats.bytes += ret;
	m->stats.messages++;  

	return ret;
}

int mcast_recv(struct mcast_sock *m, void *data, int size)
{
	int ret;
	socklen_t sin_size = sizeof(struct sockaddr_in);

        ret = recvfrom(m->fd,
		       data, 
		       size,
		       0,
		       (struct sockaddr *)&m->addr,
		       &sin_size);
	if (ret == -1) {
		debug("mcast_sock_recv");
		m->stats.error++;
		return ret;
	}

	m->stats.bytes += ret;
	m->stats.messages++;

	return ret;
}

struct mcast_stats *mcast_get_stats(struct mcast_sock *m)
{
	return &m->stats;
}

void mcast_dump_stats(int fd, struct mcast_sock *s, struct mcast_sock *r)
{
	char buf[512];
	int size;

	size = sprintf(buf, "multicast traffic:\n"
			    "%20llu Bytes sent "
			    "%20llu Bytes recv\n"
			    "%20llu Pckts sent "
			    "%20llu Pckts recv\n"
			    "%20llu Error send "
			    "%20llu Error recv\n\n",
			    s->stats.bytes, r->stats.bytes,
			    s->stats.messages, r->stats.messages,
			    s->stats.error, r->stats.error);

	send(fd, buf, size, 0);
}
