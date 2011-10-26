/*
 * Host AP (software wireless LAN access point) user space daemon for
 * Host AP kernel driver / Kernel driver communication
 * Copyright (c) 2002-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

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

#include "hostapd.h"
#include "driver.h"
#include "ieee802_1x.h"
#include "eloop.h"
#include "priv_netlink.h"
#include "ieee802_11.h"


static int hostapd_send_mgmt_frame(void *priv, const void *msg, size_t len,
				   int flags)
{
	struct hostap_driver_data *drv = priv;
	
	return send(drv->sock, msg, len, flags);
}


static int hostapd_send_eapol(void *priv, u8 *addr,
			      u8 *data, size_t data_len, int encrypt)
{
	struct hostap_driver_data *drv = priv;
	struct ieee80211_hdr *hdr;
	size_t len;
	u8 *pos;
	int res;

	len = sizeof(*hdr) + sizeof(rfc1042_header) + 2 + data_len;
	hdr = malloc(len);
	if (hdr == NULL) {
		printf("malloc() failed for hostapd_send_data(len=%d)\n", len);
		return -1;
	}

	memset(hdr, 0, len);
	hdr->frame_control =
		IEEE80211_FC(WLAN_FC_TYPE_DATA, WLAN_FC_STYPE_DATA);
	hdr->frame_control |= host_to_le16(WLAN_FC_FROMDS);
	/* Request TX callback */
	hdr->frame_control |= host_to_le16(BIT(1));
	if (encrypt)
		hdr->frame_control |= host_to_le16(WLAN_FC_ISWEP);
	memcpy(hdr->IEEE80211_DA_FROMDS, addr, ETH_ALEN);
	memcpy(hdr->IEEE80211_BSSID_FROMDS, drv->hapd->own_addr, ETH_ALEN);
	memcpy(hdr->IEEE80211_SA_FROMDS, drv->hapd->own_addr, ETH_ALEN);

	pos = (u8 *) (hdr + 1);
	memcpy(pos, rfc1042_header, sizeof(rfc1042_header));
	pos += sizeof(rfc1042_header);
	*((u16 *) pos) = htons(ETH_P_PAE);
	pos += 2;
	memcpy(pos, data, data_len);

	res = hostapd_send_mgmt_frame(drv, (u8 *) hdr, len, 0);
	free(hdr);

	if (res < 0) {
		perror("hostapd_send_eapol: send");
		printf("hostapd_send_eapol - packet len: %d - failed\n", len);
	}

	return res;
}


static void hostapd_set_sta_authorized(void *priv, u8 *addr, int authorized)
{
	struct hostap_driver_data *drv = priv;
	struct prism2_hostapd_param param;

	memset(&param, 0, sizeof(param));
	param.cmd = PRISM2_HOSTAPD_SET_FLAGS_STA;
	memcpy(param.sta_addr, addr, ETH_ALEN);
	if (authorized) {
		param.u.set_flags_sta.flags_or = WLAN_STA_AUTHORIZED;
		param.u.set_flags_sta.flags_and = ~0;
	} else {
		param.u.set_flags_sta.flags_and = ~WLAN_STA_AUTHORIZED;
	}

	if (hostapd_ioctl(drv, &param, sizeof(param)))
		printf("Could not set station flags for kernel driver.\n");
}


int hostapd_set_iface_flags(void *priv, int dev_up)
{
	struct hostap_driver_data *drv = priv;
	struct ifreq ifr;

	if (drv->ioctl_sock < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, IFNAMSIZ, "%sap", drv->iface);

	if (ioctl(drv->ioctl_sock, SIOCGIFFLAGS, &ifr) != 0) {
		perror("ioctl[SIOCGIFFLAGS]");
		return -1;
	}

	if (dev_up)
		ifr.ifr_flags |= IFF_UP;
	else
		ifr.ifr_flags &= ~IFF_UP;

	if (ioctl(drv->ioctl_sock, SIOCSIFFLAGS, &ifr) != 0) {
		perror("ioctl[SIOCSIFFLAGS]");
		return -1;
	}

	if (dev_up) {
		memset(&ifr, 0, sizeof(ifr));
		snprintf(ifr.ifr_name, IFNAMSIZ, "%sap", drv->iface);
		ifr.ifr_mtu = HOSTAPD_MTU;
		if (ioctl(drv->ioctl_sock, SIOCSIFMTU, &ifr) != 0) {
			perror("ioctl[SIOCSIFMTU]");
			printf("Setting MTU failed - trying to survive with "
			       "current value\n");
		}
	}

	return 0;
}


int hostapd_ioctl(void *priv, struct prism2_hostapd_param *param, int len)
{
	struct hostap_driver_data *drv = priv;
	struct iwreq iwr;

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) param;
	iwr.u.data.length = len;

	if (ioctl(drv->ioctl_sock, PRISM2_IOCTL_HOSTAPD, &iwr) < 0) {
		perror("ioctl[PRISM2_IOCTL_HOSTAPD]");
		return -1;
	}

	return 0;
}


int hostapd_set_encryption(void *priv, const char *alg, u8 *addr,
			   int idx, u8 *key, size_t key_len)
{
	struct hostap_driver_data *drv = priv;
	struct prism2_hostapd_param *param;
	u8 *buf;
	size_t blen;
	int ret = 0;

	blen = sizeof(*param) + key_len;
	buf = malloc(blen);
	if (buf == NULL)
		return -1;
	memset(buf, 0, blen);

	param = (struct prism2_hostapd_param *) buf;
	param->cmd = PRISM2_SET_ENCRYPTION;
	if (addr == NULL)
		memset(param->sta_addr, 0xff, ETH_ALEN);
	else
		memcpy(param->sta_addr, addr, ETH_ALEN);
	strncpy(param->u.crypt.alg, alg, HOSTAP_CRYPT_ALG_NAME_LEN);
	param->u.crypt.flags = HOSTAP_CRYPT_FLAG_SET_TX_KEY;
	param->u.crypt.idx = idx;
	param->u.crypt.key_len = key_len;
	memcpy((u8 *) (param + 1), key, key_len);

	if (hostapd_ioctl(drv, param, blen)) {
		printf("Failed to set encryption.\n");
		ret = -1;
	}
	free(buf);

	return ret;
}


int hostapd_get_seqnum(void *priv, u8 *addr, int idx, u8 *seq)
{
	struct hostap_driver_data *drv = priv;
	struct prism2_hostapd_param *param;
	u8 *buf;
	size_t blen;
	int ret = 0;

	blen = sizeof(*param) + 32;
	buf = malloc(blen);
	if (buf == NULL)
		return -1;
	memset(buf, 0, blen);

	param = (struct prism2_hostapd_param *) buf;
	param->cmd = PRISM2_GET_ENCRYPTION;
	if (addr == NULL)
		memset(param->sta_addr, 0xff, ETH_ALEN);
	else
		memcpy(param->sta_addr, addr, ETH_ALEN);
	param->u.crypt.idx = idx;

	if (hostapd_ioctl(drv, param, blen)) {
		printf("Failed to get encryption.\n");
		ret = -1;
	} else {
		memcpy(seq, param->u.crypt.seq, 8);
	}
	free(buf);

	return ret;
}


int hostap_ioctl_prism2param(void *priv, int param, int value)
{
	struct hostap_driver_data *drv = priv;
	struct iwreq iwr;
	int *i;

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	i = (int *) iwr.u.name;
	*i++ = param;
	*i++ = value;

	if (ioctl(drv->ioctl_sock, PRISM2_IOCTL_PRISM2_PARAM, &iwr) < 0) {
		perror("ioctl[PRISM2_IOCTL_PRISM2_PARAM]");
		return -1;
	}

	return 0;
}


int hostap_ioctl_setiwessid(void *priv, char *buf, int len)
{
	struct hostap_driver_data *drv = priv;
	struct iwreq iwr;

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	iwr.u.essid.flags = 1; /* SSID active */
	iwr.u.essid.pointer = (caddr_t) buf;
	iwr.u.essid.length = len + 1;

	if (ioctl(drv->ioctl_sock, SIOCSIWESSID, &iwr) < 0) {
		perror("ioctl[SIOCSIWESSID]");
		printf("len=%d\n", len);
		return -1;
	}

	return 0;
}


int hostapd_flush(void *priv)
{
	struct hostap_driver_data *drv = priv;
	struct prism2_hostapd_param param;

	memset(&param, 0, sizeof(param));
	param.cmd = PRISM2_HOSTAPD_FLUSH;
	return hostapd_ioctl(drv, &param, sizeof(param));
}


int hostapd_read_sta_driver_data(void *priv,
				 struct hostap_sta_driver_data *data,
				 u8 *addr)
{
	struct hostap_driver_data *drv = priv;
	char buf[1024], line[128], *pos;
	FILE *f;
	unsigned long val;

	memset(data, 0, sizeof(*data));
	snprintf(buf, sizeof(buf), "/proc/net/hostap/%s/" MACSTR,
		 drv->iface, MAC2STR(addr));

	f = fopen(buf, "r");
	if (!f)
		return -1;
	/* Need to read proc file with in one piece, so use large enough
	 * buffer. */
	setbuffer(f, buf, sizeof(buf));

	while (fgets(line, sizeof(line), f)) {
		pos = strchr(line, '=');
		if (!pos)
			continue;
		*pos++ = '\0';
		val = atoi(pos);
		if (strcmp(line, "rx_packets") == 0)
			data->rx_packets = val;
		else if (strcmp(line, "tx_packets") == 0)
			data->tx_packets = val;
		else if (strcmp(line, "rx_bytes") == 0)
			data->rx_bytes = val;
		else if (strcmp(line, "tx_bytes") == 0)
			data->tx_bytes = val;
	}

	fclose(f);

	return 0;
}


void remove_sta(void *priv, u8 *addr)
{
	struct hostap_driver_data *drv = priv;
	struct prism2_hostapd_param param;

	hostapd_set_sta_authorized(drv, addr, 0);

	memset(&param, 0, sizeof(param));
	param.cmd = PRISM2_HOSTAPD_REMOVE_STA;
	memcpy(param.sta_addr, addr, ETH_ALEN);
	if (hostapd_ioctl(drv, &param, sizeof(param))) {
		printf("Could not remove station from kernel driver.\n");
	}
}


int hostapd_set_generic_elem(void *priv,
			     const char *elem, size_t elem_len)
{
	struct hostap_driver_data *drv = priv;
	struct prism2_hostapd_param *param;
	int res;
	size_t blen = PRISM2_HOSTAPD_GENERIC_ELEMENT_HDR_LEN + elem_len;
	if (blen < sizeof(*param))
		blen = sizeof(*param);

	param = (struct prism2_hostapd_param *) malloc(blen);
	if (param == NULL)
		return -1;

	memset(param, 0, blen);
	param->cmd = PRISM2_HOSTAPD_SET_GENERIC_ELEMENT;
	param->u.generic_elem.len = elem_len;
	memcpy(param->u.generic_elem.data, elem, elem_len);
	res = hostapd_ioctl(drv, param, blen);

	free(param);

	return res;
}


static void
hostapd_wireless_event_wireless_custom(struct hostap_driver_data *drv,
				       char *custom)
{
	struct hostapd_data *hapd = drv->hapd;

	HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL, "Custom wireless event: '%s'\n",
		      custom);

	if (strncmp(custom, "MLME-MICHAELMICFAILURE.indication", 33) == 0) {
		char *pos;
		u8 addr[ETH_ALEN];
		pos = strstr(custom, "addr=");
		if (pos == NULL) {
			HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL,
				      "MLME-MICHAELMICFAILURE.indication "
				      "without sender address ignored\n");
			return;
		}
		pos += 5;
		if (hwaddr_aton(pos, addr) == 0) {
			ieee80211_michael_mic_failure(drv->hapd, addr, 1);
		} else {
			HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL,
				      "MLME-MICHAELMICFAILURE.indication "
				      "with invalid MAC address");
		}
	}
}


static void hostapd_wireless_event_wireless(struct hostap_driver_data *drv,
					    char *data, int len)
{
	struct hostapd_data *hapd = drv->hapd;
	struct iw_event *iwe;
	char *pos, *end, *custom, *buf;

	pos = data;
	end = data + len;

	while (pos + IW_EV_LCP_LEN <= end) {
		iwe = (struct iw_event *) pos;
		HOSTAPD_DEBUG(HOSTAPD_DEBUG_VERBOSE, "Wireless event: "
			      "cmd=0x%x len=%d\n", iwe->cmd, iwe->len);
		if (iwe->len <= IW_EV_LCP_LEN)
			return;
		switch (iwe->cmd) {
		case IWEVCUSTOM:
			custom = pos + IW_EV_POINT_LEN;
			if (custom + iwe->u.data.length > end)
				return;
			buf = malloc(iwe->u.data.length + 1);
			if (buf == NULL)
				return;
			memcpy(buf, custom, iwe->u.data.length);
			buf[iwe->u.data.length] = '\0';
			hostapd_wireless_event_wireless_custom(drv, buf);
			free(buf);
			break;
		}

		pos += iwe->len;
	}
}


static void hostapd_wireless_event_rtm_newlink(struct hostap_driver_data *drv,
					       struct nlmsghdr *h, int len)
{
	struct ifinfomsg *ifi;
	int attrlen, nlmsg_len, rta_len;
	struct rtattr * attr;

	if (len < sizeof(*ifi))
		return;

	ifi = NLMSG_DATA(h);

	/* TODO: use ifi->ifi_index to filter out wireless events from other
	 * interfaces */

	nlmsg_len = NLMSG_ALIGN(sizeof(struct ifinfomsg));

	attrlen = h->nlmsg_len - nlmsg_len;
	if (attrlen < 0)
		return;

	attr = (struct rtattr *) (((char *) ifi) + nlmsg_len);

	rta_len = RTA_ALIGN(sizeof(struct rtattr));
	while (RTA_OK(attr, attrlen)) {
		if (attr->rta_type == IFLA_WIRELESS) {
			hostapd_wireless_event_wireless(
				drv, ((char *) attr) + rta_len,
				attr->rta_len - rta_len);
		}
		attr = RTA_NEXT(attr, attrlen);
	}
}


static void hostapd_wireless_event_receive(int sock, void *eloop_ctx,
					   void *sock_ctx)
{
	char buf[256];
	int left;
	struct sockaddr_nl from;
	socklen_t fromlen;
	struct nlmsghdr *h;
	struct hostap_driver_data *drv = eloop_ctx;

	fromlen = sizeof(from);
	left = recvfrom(sock, buf, sizeof(buf), MSG_DONTWAIT,
			(struct sockaddr *) &from, &fromlen);
	if (left < 0) {
		if (errno != EINTR && errno != EAGAIN)
			perror("recvfrom(netlink)");
		return;
	}

	h = (struct nlmsghdr *) buf;
	while (left >= sizeof(*h)) {
		int len, plen;

		len = h->nlmsg_len;
		plen = len - sizeof(*h);
		if (len > left || plen < 0) {
			printf("Malformed netlink message: "
			       "len=%d left=%d plen=%d\n",
			       len, left, plen);
			break;
		}

		switch (h->nlmsg_type) {
		case RTM_NEWLINK:
			hostapd_wireless_event_rtm_newlink(drv, h, plen);
			break;
		}

		len = NLMSG_ALIGN(len);
		left -= len;
		h = (struct nlmsghdr *) ((char *) h + len);
	}

	if (left > 0) {
		printf("%d extra bytes in the end of netlink message\n", left);
	}
}


int hostapd_wireless_event_init(void *priv)
{
	struct hostap_driver_data *drv = priv;
	int s;
	struct sockaddr_nl local;

	drv->wext_sock = -1;

	s = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (s < 0) {
		perror("socket(PF_NETLINK,SOCK_RAW,NETLINK_ROUTE)");
		return -1;
	}

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = RTMGRP_LINK;
	if (bind(s, (struct sockaddr *) &local, sizeof(local)) < 0) {
		perror("bind(netlink)");
		close(s);
		return -1;
	}

	eloop_register_read_sock(s, hostapd_wireless_event_receive, drv,
				 NULL);
	drv->wext_sock = s;

	return 0;
}


void hostapd_wireless_event_deinit(void *priv)
{
	struct hostap_driver_data *drv = priv;
	if (drv->wext_sock < 0)
		return;
	eloop_unregister_read_sock(drv->wext_sock);
	close(drv->wext_sock);
}


int hostapd_driver_init(struct hostapd_data *hapd)
{
	struct hostap_driver_data *drv;

	drv = malloc(sizeof(struct hostap_driver_data));
	if (drv == NULL) {
		printf("Could not allocate memory for hostapd driver data\n");
		return -1;
	}

	memset(drv, 0, sizeof(*drv));
	hapd->driver.data = drv;

	drv->hapd = hapd;
	drv->ioctl_sock = drv->sock = -1;
	memcpy(drv->iface, hapd->conf->iface, sizeof(drv->iface));

	drv->ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (drv->ioctl_sock < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		return -1;
	}

	if (hostap_ioctl_prism2param(drv, PRISM2_PARAM_HOSTAPD, 1)) {
		printf("Could not enable hostapd mode for interface %s\n",
		       drv->iface);
		return -1;
	}

	if (hapd->conf->assoc_ap &&
	    hostap_ioctl_prism2param(drv, PRISM2_PARAM_HOSTAPD_STA, 1)) {
		printf("Could not enable hostapd STA mode for interface %s\n",
		       drv->iface);
		return -1;
	}

    if (hostapd_init_sockets(drv))
		return -1;
	
	/* register callback functions */
	hapd->driver.set_sta_authorized = hostapd_set_sta_authorized;
	hapd->driver.send_eapol = hostapd_send_eapol;
	hapd->driver.send_mgmt_frame = hostapd_send_mgmt_frame;

	return 0;
}


void hostapd_driver_deinit(struct hostapd_data *hapd)
{
	struct hostap_driver_data *drv = hapd->driver.data;

	hapd->driver.set_sta_authorized = NULL;
	hapd->driver.send_eapol = NULL;
	hapd->driver.send_mgmt_frame = NULL;

	(void) hostapd_set_iface_flags(drv, 0);
	(void) hostap_ioctl_prism2param(drv, PRISM2_PARAM_HOSTAPD, 0);
	(void) hostap_ioctl_prism2param(drv, PRISM2_PARAM_HOSTAPD_STA, 0);

	if (drv->ioctl_sock >= 0)
		close(drv->ioctl_sock);

	if (drv->sock >= 0)
		close(drv->sock);
	
	free(hapd->driver.data);
}
