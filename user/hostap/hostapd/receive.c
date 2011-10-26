/*
 * Host AP (software wireless LAN access point) user space daemon for
 * Host AP kernel driver / Incoming IEEE 802.11 (wlan#ap) frame handling
 * Copyright (c) 2002-2003, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#ifdef USE_KERNEL_HEADERS
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>   /* The L2 protocols */
#include <linux/if_arp.h>
#include <linux/wireless.h>
#else /* USE_KERNEL_HEADERS */
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include "wireless_copy.h"
#endif /* USE_KERNEL_HEADERS */


#include "eloop.h"
#include "hostapd.h"
#include "ieee802_11.h"
#include "sta_info.h"
#include "ieee802_1x.h"
#include "driver.h"


static void handle_data(hostapd *hapd, char *buf, size_t len, u16 stype)
{
	struct ieee80211_hdr *hdr;
	u16 fc, ethertype;
	u8 *pos, *sa;
	size_t left;
	struct sta_info *sta;

	if (len < sizeof(struct ieee80211_hdr))
		return;

	hdr = (struct ieee80211_hdr *) buf;
	fc = le_to_host16(hdr->frame_control);

	if ((fc & (WLAN_FC_FROMDS | WLAN_FC_TODS)) != WLAN_FC_TODS) {
		printf("Not ToDS data frame (fc=0x%04x)\n", fc);
		return;
	}

	sa = hdr->addr2;
	sta = ap_get_sta(hapd, sa);
	if (!sta || !(sta->flags & WLAN_STA_ASSOC)) {
		printf("Data frame from not associated STA " MACSTR "\n",
		       MAC2STR(sa));
		if (sta && (sta->flags & WLAN_STA_AUTH))
			ieee802_11_send_disassoc(
				hapd, sa,
				WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA);
		else
			ieee802_11_send_deauth(
				hapd, sa,
				WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA);
		return;
	}

	pos = (u8 *) (hdr + 1);
	left = len - sizeof(*hdr);

	if (left < sizeof(rfc1042_header)) {
		printf("Too short data frame\n");
		return;
	}

	if (memcmp(pos, rfc1042_header, sizeof(rfc1042_header)) != 0) {
		printf("Data frame with no RFC1042 header\n");
		return;
	}
	pos += sizeof(rfc1042_header);
	left -= sizeof(rfc1042_header);

	if (left < 2) {
		printf("No ethertype in data frame\n");
		return;
	}

	ethertype = *pos++ << 8;
	ethertype |= *pos++;
	left -= 2;
	switch (ethertype) {
	case ETH_P_PAE:
		ieee802_1x_receive(hapd, sa, pos, left);
		break;

	default:
		printf("Unknown ethertype 0x%04x in data frame\n", ethertype);
		break;
	}
}


static void handle_tx_callback(hostapd *hapd, char *buf, size_t len, int ok)
{
	struct ieee80211_hdr *hdr;
	u16 fc, type, stype;
	struct sta_info *sta;

	hdr = (struct ieee80211_hdr *) buf;
	fc = le_to_host16(hdr->frame_control);

	type = WLAN_FC_GET_TYPE(fc);
	stype = WLAN_FC_GET_STYPE(fc);

	switch (type) {
	case WLAN_FC_TYPE_MGMT:
		HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL,
			      "MGMT (TX callback) %s\n", ok ? "ACK" : "fail");
		ieee802_11_mgmt_cb(hapd, buf, len, stype, ok);
		break;
	case WLAN_FC_TYPE_CTRL:
		HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL,
			      "CTRL (TX callback) %s\n", ok ? "ACK" : "fail");
		break;
	case WLAN_FC_TYPE_DATA:
		HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL,
			      "DATA (TX callback) %s\n", ok ? "ACK" : "fail");
		sta = ap_get_sta(hapd, hdr->addr1);
		if (sta && sta->flags & WLAN_STA_PENDING_POLL) {
			HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL, "STA " MACSTR
				      " %s pending activity poll\n",
				      MAC2STR(sta->addr),
				      ok ? "ACKed" : "did not ACK");
			if (ok)
				sta->flags &= ~WLAN_STA_PENDING_POLL;
		}
		if (sta)
			ieee802_1x_tx_status(hapd, sta, buf, len, ok);
		break;
	default:
		printf("unknown TX callback frame type %d\n", type);
		break;
	}
}


static void handle_frame(hostapd *hapd, char *buf, size_t len)
{
	struct ieee80211_hdr *hdr;
	u16 fc, extra_len, type, stype;
	unsigned char *extra = NULL;
	size_t data_len = len;
	int ver;

	/* PSPOLL is only 16 bytes, but driver does not (at least yet) pass
	 * these to user space */
	if (len < 24) {
		HOSTAPD_DEBUG(HOSTAPD_DEBUG_VERBOSE, "handle_frame: too short "
			      "(%d)\n", len);
		return;
	}

	hdr = (struct ieee80211_hdr *) buf;
	fc = le_to_host16(hdr->frame_control);
	type = WLAN_FC_GET_TYPE(fc);
	stype = WLAN_FC_GET_STYPE(fc);

	if (type != WLAN_FC_TYPE_MGMT || stype != WLAN_FC_STYPE_BEACON ||
	    hapd->conf->debug >= HOSTAPD_DEBUG_EXCESSIVE) {
		HOSTAPD_DEBUG(HOSTAPD_DEBUG_VERBOSE,
			      "Received %d bytes management frame\n", len);
		if (HOSTAPD_DEBUG_COND(HOSTAPD_DEBUG_MSGDUMPS)) {
			hostapd_hexdump("RX frame", buf, len);
		}
	}

	ver = fc & WLAN_FC_PVER;

	/* protocol version 3 is reserved for indicating extra data after the
	 * payload, version 2 for indicating ACKed frame (TX callbacks), and
	 * version 1 for indicating failed frame (no ACK, TX callbacks) */
	if (ver == 3) {
		u8 *pos = buf + len - 2;
		extra_len = (u16) pos[1] << 8 | pos[0];
		printf("extra data in frame (elen=%d)\n", extra_len);
		if (extra_len + 2 > len) {
			printf("  extra data overflow\n");
			return;
		}
		len -= extra_len + 2;
		extra = buf + len;
	} else if (ver == 1 || ver == 2) {
		handle_tx_callback(hapd, buf, data_len, ver == 2 ? 1 : 0);
		return;
	} else if (ver != 0) {
		printf("unknown protocol version %d\n", ver);
		return;
	}

	switch (type) {
	case WLAN_FC_TYPE_MGMT:
		HOSTAPD_DEBUG(stype == WLAN_FC_STYPE_BEACON ?
			      HOSTAPD_DEBUG_EXCESSIVE : HOSTAPD_DEBUG_VERBOSE,
			      "MGMT\n");
		ieee802_11_mgmt(hapd, buf, data_len, stype);
		break;
	case WLAN_FC_TYPE_CTRL:
		HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL, "CTRL\n");
		break;
	case WLAN_FC_TYPE_DATA:
		HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL, "DATA\n");
		handle_data(hapd, buf, data_len, stype);
		break;
	default:
		printf("unknown frame type %d\n", type);
		break;
	}
}


static void handle_read(int sock, void *eloop_ctx, void *sock_ctx)
{
	hostapd *hapd = (hostapd *) eloop_ctx;
	int len;
	unsigned char buf[3000];

	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 0) {
		perror("recv");
		return;
	}

	handle_frame(hapd, buf, len);
}


int hostapd_init_sockets(struct hostap_driver_data *drv)
{
	struct hostapd_data *hapd = drv->hapd;
	struct ifreq ifr;
	struct sockaddr_ll addr;

	drv->sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (drv->sock < 0) {
		perror("socket[PF_PACKET,SOCK_RAW]");
		return -1;
	}

	if (eloop_register_read_sock(drv->sock, handle_read, drv->hapd, NULL))
	{
		printf("Could not register read socket\n");
		return -1;
	}

        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%sap", drv->iface);
        if (ioctl(drv->sock, SIOCGIFINDEX, &ifr) != 0) {
		perror("ioctl(SIOCGIFINDEX)");
		return -1;
        }

	if (hostapd_set_iface_flags(drv, 1)) {
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = ifr.ifr_ifindex;
	HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL,
		      "Opening raw packet socket for ifindex %d\n",
		      addr.sll_ifindex);

	if (bind(drv->sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("bind");
		return -1;
	}

        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", drv->iface);
        if (ioctl(drv->sock, SIOCGIFHWADDR, &ifr) != 0) {
		perror("ioctl(SIOCGIFHWADDR)");
		return -1;
        }

	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		printf("Invalid HW-addr family 0x%04x\n",
		       ifr.ifr_hwaddr.sa_family);
		return -1;
	}
	memcpy(drv->hapd->own_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	return 0;
}
