/*
 * Host AP (software wireless LAN access point) user space daemon for
 * Host AP kernel driver / IEEE 802.11f Inter-Access Point Protocol (IAPP)
 * Copyright (c) 2002-2003, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */

/* TODO:
 * - add support for MOVE-notify and MOVE-response (this requires support for
 *   finding out IP address for previous AP using RADIUS)
 * - add support for Send- and ACK-Security-Block to speedup IEEE 802.1X during
 *   reassociation to another AP
 * - implement counters etc. for IAPP MIB
 * - verify endianness of fields in IAPP messages; are they big-endian as
 *   used here?
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#ifdef USE_KERNEL_HEADERS
#include <linux/if_packet.h>
#else /* USE_KERNEL_HEADERS */
#include <netpacket/packet.h>
#endif /* USE_KERNEL_HEADERS */

#include "hostapd.h"
#include "ieee802_11.h"
#include "iapp.h"
#include "eloop.h"
#include "sta_info.h"
#include "driver.h"


static void iapp_send_add(hostapd *hapd, struct sta_info *sta)
{
	char buf[128];
	struct iapp_hdr *hdr;
	struct iapp_add_notify *add;
	struct ieee80211_mgmt *assoc;
	struct sockaddr_in addr;

	/* Send IAPP-ADD Packet to remove possible association from other APs
	 */

	hdr = (struct iapp_hdr *) buf;
	hdr->version = IAPP_VERSION;
	hdr->command = IAPP_CMD_ADD_notify;
	hdr->identifier = host_to_be16(hapd->iapp_identifier++);
	hdr->length = host_to_be16(sizeof(*hdr) + sizeof(*add));

	add = (struct iapp_add_notify *) (hdr + 1);
	add->addr_len = ETH_ALEN;
	add->reserved = 0;
	memcpy(add->mac_addr, sta->addr, ETH_ALEN);

	assoc = sta->last_assoc_req;
	if (assoc) {
		u16 seq = WLAN_GET_SEQ_SEQ(le_to_host16(assoc->seq_ctrl));
		add->seq_num = host_to_be16(seq);
	} else
		add->seq_num = 0;
	
	/* Send to local subnet address (UDP port IAPP_PORT) */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = hapd->iapp_broadcast.s_addr;
	addr.sin_port = htons(IAPP_PORT);
	if (sendto(hapd->iapp_udp_sock, buf, (char *) (add + 1) - buf, 0,
		   (struct sockaddr *) &addr, sizeof(addr)) < 0)
		perror("sendto[IAPP-ADD]");
}


static void iapp_send_layer2_update(hostapd *hapd, struct sta_info *sta)
{
	struct iapp_layer2_update msg;

	/* Send Level 2 Update Frame to update forwarding tables in layer 2
	 * bridge devices */

	/* 802.2 Type 1 Logical Link Control (LLC) Exchange Identifier (XID)
	 * Update response frame; IEEE Std 802.2-1998, 5.4.1.2.1 */

	memset(msg.da, 0xff, ETH_ALEN);
	memcpy(msg.sa, sta->addr, ETH_ALEN);
	msg.len = host_to_be16(8);
	msg.dsap = 0;
	msg.ssap = 0;
	msg.control = 0xaf; /* XID response lsb.1111F101.
			     * F=0 (no poll command; unsolicited frame) */
	msg.xid_info[0] = 0x81; /* XID format identifier */
	msg.xid_info[1] = 1; /* LLC types/classes: Type 1 LLC */
	msg.xid_info[2] = 1 << 1; /* XID sender's receive window size (RW)
				   * FIX: what is correct RW with 802.11? */

	if (send(hapd->iapp_packet_sock, &msg, sizeof(msg), 0) < 0)
		perror("send[L2 Update]");
}


void iapp_new_station(hostapd *hapd, struct sta_info *sta)
{
	struct ieee80211_mgmt *assoc;

	iapp_send_add(hapd, sta);
	iapp_send_layer2_update(hapd, sta);

	assoc = sta->last_assoc_req;
	if (assoc && WLAN_FC_GET_STYPE(le_to_host16(assoc->frame_control)) ==
	    WLAN_FC_STYPE_REASSOC_REQ) {
		/* Send IAPP-MOVE to old AP */
	}
}


static void iapp_process_add_notify(hostapd *hapd, struct sockaddr_in *from,
				    struct iapp_hdr *hdr, int len)
{
	struct iapp_add_notify *add = (struct iapp_add_notify *) (hdr + 1);
	struct sta_info *sta;

	if (len != sizeof(*add)) {
		printf("Invalid IAPP-ADD packet length %d (expected %d)\n",
		       len, sizeof(*add));
		return;
	}

	printf("Received IAPP-ADD for STA " MACSTR " (seq# %d) from %s:%d\n",
	       MAC2STR(add->mac_addr), be_to_host16(add->seq_num),
	       inet_ntoa(from->sin_addr), ntohs(from->sin_port));

	sta = ap_get_sta(hapd, add->mac_addr);
	if (!sta)
		return;

	/* TODO: could use seq_num to try to determine whether last association
	 * to this AP is newer than the one advertised in IAPP-ADD. Although,
	 * this is not really a reliable verification. */

	printf("Removing STA " MACSTR " due to IAPP-ADD notification from "
	       "%s\n", MAC2STR(sta->addr), inet_ntoa(from->sin_addr));
	sta->flags &= ~(WLAN_STA_AUTH | WLAN_STA_ASSOC);
	remove_sta(hapd->driver.data, sta->addr);
}


static void iapp_receive_udp(int sock, void *eloop_ctx, void *sock_ctx)
{
	hostapd *hapd = eloop_ctx;
	int len, hlen;
	unsigned char buf[128];
	struct sockaddr_in from;
	socklen_t fromlen;
	struct iapp_hdr *hdr;

	/* Handle incoming IAPP frames (over UDP/IP) */

	fromlen = sizeof(from);
	len = recvfrom(hapd->iapp_udp_sock, buf, sizeof(buf), 0,
		       (struct sockaddr *) &from, &fromlen);
	if (len < 0)
		perror("recvfrom");

	if (from.sin_addr.s_addr == hapd->iapp_own.s_addr)
		return; /* ignore own IAPP messages */

	HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL,
		      "Received %d byte IAPP frame from %s\n",
		      len, inet_ntoa(from.sin_addr));

	if (len < sizeof(*hdr)) {
		printf("Too short IAPP frame (len=%d)\n", len);
		return;
	}

	hdr = (struct iapp_hdr *) buf;
	hlen = be_to_host16(hdr->length);
	HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL,
		      "IAPP: version=%d command=%d id=%d len=%d\n",
		      hdr->version, hdr->command,
		      be_to_host16(hdr->identifier), hlen);
	if (hlen > len) {
		printf("Underflow IAPP frame (hlen=%d len=%d)\n", hlen, len);
		return;
	}
	if (hlen < len) {
		printf("Ignoring %d extra bytes from IAPP frame\n",
		       len - hlen);
		len = hlen;
	}

	if (hdr->command == IAPP_CMD_ADD_notify)
		iapp_process_add_notify(hapd, &from, hdr, hlen - sizeof(*hdr));
	else
		printf("Unknown IAPP command %d\n", hdr->command);
}


int iapp_init(hostapd *hapd)
{
	struct ifreq ifr;
	struct sockaddr_ll addr;
	int ifindex, one;
	struct sockaddr_in *paddr, uaddr;

	/* TODO:
	 * open socket for sending and receiving IAPP frames over TCP
	 */

	hapd->iapp_udp_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (hapd->iapp_udp_sock < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, hapd->conf->iapp_iface, sizeof(ifr.ifr_name));
	if (ioctl(hapd->iapp_udp_sock, SIOCGIFINDEX, &ifr) != 0) {
		perror("ioctl(SIOCGIFINDEX)");
		return -1;
	}
	ifindex = ifr.ifr_ifindex;

	if (ioctl(hapd->iapp_udp_sock, SIOCGIFADDR, &ifr) != 0) {
		perror("ioctl(SIOCGIFADDR)");
		return -1;
	}
	paddr = (struct sockaddr_in *) &ifr.ifr_addr;
	if (paddr->sin_family != AF_INET) {
		printf("Invalid address family %i (SIOCGIFADDR)\n",
		       paddr->sin_family);
		return -1;
	}
	hapd->iapp_own.s_addr = paddr->sin_addr.s_addr;

	if (ioctl(hapd->iapp_udp_sock, SIOCGIFBRDADDR, &ifr) != 0) {
		perror("ioctl(SIOCGIFBRDADDR)");
		return -1;
	}
	paddr = (struct sockaddr_in *) &ifr.ifr_addr;
	if (paddr->sin_family != AF_INET) {
		printf("Invalid address family %i (SIOCGIFBRDADDR)\n",
		       paddr->sin_family);
		return -1;
	}
	hapd->iapp_broadcast.s_addr = paddr->sin_addr.s_addr;

	one = 1;
	if (setsockopt(hapd->iapp_udp_sock, SOL_SOCKET, SO_BROADCAST,
		       (char *) &one, sizeof(one)) < 0) {
		perror("setsockopt[SOL_SOCKET,SO_BROADCAST]");
		return -1;
	}

	memset(&uaddr, 0, sizeof(uaddr));
	uaddr.sin_family = AF_INET;
	uaddr.sin_port = htons(IAPP_PORT);
	if (bind(hapd->iapp_udp_sock, (struct sockaddr *) &uaddr,
		 sizeof(uaddr)) < 0) {
		perror("bind[UDP]");
		return -1;
	}

	hapd->iapp_packet_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (hapd->iapp_packet_sock < 0) {
		perror("socket[PF_PACKET,SOCK_RAW]");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = ifindex;
	if (bind(hapd->iapp_packet_sock, (struct sockaddr *) &addr,
		 sizeof(addr)) < 0) {
		perror("bind[PACKET]");
		return -1;
	}

	if (eloop_register_read_sock(hapd->iapp_udp_sock, iapp_receive_udp,
				     hapd, NULL)) {
		printf("Could not register read socket for IAPP.\n");
		return -1;
	}

	printf("IEEE 802.11f (IAPP) using interface %s and broadcast address "
	       "%s\n", hapd->conf->iapp_iface,
	       inet_ntoa(hapd->iapp_broadcast));

	return 0;
}


void iapp_deinit(hostapd *hapd)
{
	if (hapd->iapp_udp_sock >= 0)
		close(hapd->iapp_udp_sock);
	if (hapd->iapp_packet_sock >= 0)
		close(hapd->iapp_packet_sock);
}
