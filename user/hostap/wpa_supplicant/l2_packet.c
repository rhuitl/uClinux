/*
 * WPA Supplicant - Layer2 packet handling
 * Copyright (c) 2003-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef USE_DNET_PCAP
#include <pcap.h>
#include <dnet.h>
#else /* USE_DNET_PCAP */
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <net/if.h>
#endif /* USE_DNET_PCAP */

#include "common.h"
#include "eloop.h"
#include "wpa_supplicant.h"
#include "l2_packet.h"


struct l2_packet_data {
#ifdef USE_DNET_PCAP
	pcap_t *pcap;
	eth_t *eth;
#else /* USE_DNET_PCAP */
	int fd; /* packet socket for EAPOL frames */
#endif /* USE_DNET_PCAP */
	char ifname[20];
	u8 own_addr[ETH_ALEN];
	void (*rx_callback)(void *ctx, unsigned char *src_addr,
			    unsigned char *buf, size_t len);
	void *rx_callback_ctx;
};


int l2_packet_get_own_addr(struct l2_packet_data *l2, u8 *addr)
{
	memcpy(addr, l2->own_addr, ETH_ALEN);
	return 0;
}


#ifdef USE_DNET_PCAP

static int l2_packet_init_libdnet(struct l2_packet_data *l2)
{
	eth_addr_t own_addr;

	l2->eth = eth_open(l2->ifname);
	if (!l2->eth) {
		wpa_printf(MSG_ERROR, "Failed to open interface '%s'.",
			l2->ifname);
		perror("eth_open");
		return -1;
	}

	if (eth_get(l2->eth, &own_addr) < 0) {
		wpa_printf(MSG_ERROR, "Failed to get own hw address from "
			   "interface '%s'.", l2->ifname);
		perror("eth_get");
		eth_close(l2->eth);
		l2->eth = NULL;
		return -1;
	}
	memcpy(l2->own_addr, own_addr.data, ETH_ALEN);

	return 0;
}


int l2_packet_send(struct l2_packet_data *l2, u8 *buf, size_t len)
{
	return eth_send(l2->eth, buf, len);
}


static void l2_packet_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct l2_packet_data *l2 = eloop_ctx;
	pcap_t *pcap = sock_ctx;
	struct pcap_pkthdr hdr;
	const u_char *packet;
	struct eth_hdr *ethhdr;

	packet = pcap_next(pcap, &hdr);

	if (packet == NULL || hdr.caplen < sizeof(*ethhdr))
		return;

	ethhdr = (struct eth_hdr *) packet;
	l2->rx_callback(l2->rx_callback_ctx, ethhdr->eth_src.data,
			(unsigned char *) (ethhdr + 1),
			hdr.caplen - sizeof(*ethhdr));
}


static int l2_packet_init_libpcap(struct l2_packet_data *l2,
				  unsigned short protocol)
{
	bpf_u_int32 pcap_maskp, pcap_netp;
	char pcap_filter[100], pcap_err[PCAP_ERRBUF_SIZE];
	struct bpf_program pcap_fp;

	pcap_lookupnet(l2->ifname, &pcap_netp, &pcap_maskp, pcap_err);
	l2->pcap = pcap_open_live(l2->ifname, 1500, 0, 0, pcap_err);
	if (l2->pcap == NULL) {
		fprintf(stderr, "pcap_open_live: %s\n", pcap_err);
		return -1;
	}
	snprintf(pcap_filter, sizeof(pcap_filter),
		 "ether dst " MACSTR " and ether proto 0x%x",
		 MAC2STR(l2->own_addr), protocol);
	if (pcap_compile(l2->pcap, &pcap_fp, pcap_filter, 1, pcap_netp) < 0)
	{
		fprintf(stderr, "pcap_compile: %s\n",
			pcap_geterr(l2->pcap));
		return -1;
	}

	if (pcap_setfilter(l2->pcap, &pcap_fp) < 0) {
		fprintf(stderr, "pcap_setfilter: %s\n",
			pcap_geterr(l2->pcap));
		return -1;
	}

	pcap_freecode(&pcap_fp);

	eloop_register_read_sock(pcap_fileno(l2->pcap),
				 l2_packet_receive, l2, l2->pcap);

	return 0;
}



struct l2_packet_data * l2_packet_init(
	const char *ifname, unsigned short protocol,
	void (*rx_callback)(void *ctx, unsigned char *src_addr,
			    unsigned char *buf, size_t len),
	void *rx_callback_ctx)
{
	struct l2_packet_data *l2;

	l2 = malloc(sizeof(struct l2_packet_data));
	if (l2 == NULL)
		return NULL;
	memset(l2, 0, sizeof(*l2));
	strncpy(l2->ifname, ifname, sizeof(l2->ifname));
	l2->rx_callback = rx_callback;
	l2->rx_callback_ctx = rx_callback_ctx;

	if (l2_packet_init_libdnet(l2))
		return NULL;

	if (l2_packet_init_libpcap(l2, protocol)) {
		eth_close(l2->eth);
		free(l2);
		return NULL;
	}

	return l2;
}


void l2_packet_deinit(struct l2_packet_data *l2)
{
	if (l2 == NULL)
		return;

	if (l2->pcap)
		pcap_close(l2->pcap);
	if (l2->eth)
		eth_close(l2->eth);
	free(l2);
}

#else /* USE_DNET_PCAP */

int l2_packet_send(struct l2_packet_data *l2, u8 *buf, size_t len)
{
	int ret;
	ret = send(l2->fd, buf, len, 0);
	if (ret < 0)
		perror("l2_packet_send - send");
	return ret;
}


static void l2_packet_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct l2_packet_data *l2 = eloop_ctx;
	u8 buf[2300];
	int res;
	struct l2_ethhdr *ethhdr;

	res = recv(sock, buf, sizeof(buf), 0);
	if (res < 0) {
		perror("l2_packet_receive - recv");
		return;
	}
	if (res < sizeof(*ethhdr)) {
		wpa_printf(MSG_DEBUG, "l2_packet_receive: Dropped too short "
			   "%d packet", res);
		return;
	}

	ethhdr = (struct l2_ethhdr *) buf;

	l2->rx_callback(l2->rx_callback_ctx, ethhdr->h_source,
			(unsigned char *) (ethhdr + 1),
			res - sizeof(*ethhdr));
}


struct l2_packet_data * l2_packet_init(
	const char *ifname, unsigned short protocol,
	void (*rx_callback)(void *ctx, unsigned char *src_addr,
			    unsigned char *buf, size_t len),
	void *rx_callback_ctx)
{
	struct l2_packet_data *l2;
	struct ifreq ifr;
	struct sockaddr_ll ll;

	l2 = malloc(sizeof(struct l2_packet_data));
	if (l2 == NULL)
		return NULL;
	memset(l2, 0, sizeof(*l2));
	strncpy(l2->ifname, ifname, sizeof(l2->ifname));
	l2->rx_callback = rx_callback;
	l2->rx_callback_ctx = rx_callback_ctx;

	l2->fd = socket(PF_PACKET, SOCK_RAW, htons(protocol));
	if (l2->fd < 0) {
		perror("socket(PF_PACKET, SOCK_RAW)");
		free(l2);
		return NULL;
	}
	strncpy(ifr.ifr_name, l2->ifname, sizeof(ifr.ifr_name));
	if (ioctl(l2->fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl[SIOCGIFINDEX]");
		close(l2->fd);
		free(l2);
		return NULL;
	}

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = PF_PACKET;
	ll.sll_ifindex = ifr.ifr_ifindex;
	ll.sll_protocol = htons(protocol);
	if (bind(l2->fd, (struct sockaddr *) &ll, sizeof(ll)) < 0) {
		perror("bind[PF_PACKET]");
		close(l2->fd);
		free(l2);
		return NULL;
	}

	if (ioctl(l2->fd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl[SIOCGIFHWADDR]");
		close(l2->fd);
		free(l2);
		return NULL;
	}
	memcpy(l2->own_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	eloop_register_read_sock(l2->fd, l2_packet_receive, l2, NULL);

	return l2;
}


void l2_packet_deinit(struct l2_packet_data *l2)
{
	if (l2 == NULL)
		return;

	if (l2->fd >= 0) {
		eloop_unregister_read_sock(l2->fd);
		close(l2->fd);
	}
		
	free(l2);
}

#endif /* USE_DNET_PCAP */
