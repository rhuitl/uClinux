/*
 * WPA Supplicant - driver interaction with generic Linux Wireless Extensions
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
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <net/if_arp.h>

#include "wireless_copy.h"
#include "common.h"
#include "driver.h"
#include "l2_packet.h"
#include "eloop.h"
#include "wpa_supplicant.h"
#include "priv_netlink.h"
#include "driver_wext.h"


int wpa_driver_wext_get_bssid(const char *ifname, char *bssid)
{
	struct iwreq iwr;
	int s, ret = 0;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		return -1;
	}

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(s, SIOCGIWAP, &iwr) < 0) {
		perror("ioctl[SIOCGIWAP]");
		ret = -1;
	}
	memcpy(bssid, iwr.u.ap_addr.sa_data, ETH_ALEN);

	close(s);
	return ret;
}


int wpa_driver_wext_set_bssid(const char *ifname, const char *bssid)
{
	struct iwreq iwr;
	int s, ret = 0;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		return -1;
	}

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);
	iwr.u.ap_addr.sa_family = ARPHRD_ETHER;
	memcpy(iwr.u.ap_addr.sa_data, bssid, ETH_ALEN);

	if (ioctl(s, SIOCSIWAP, &iwr) < 0) {
		perror("ioctl[SIOCSIWAP]");
		ret = -1;
	}

	close(s);
	return ret;
}


int wpa_driver_wext_get_ssid(const char *ifname, char *ssid)
{
	struct iwreq iwr;
	int s, ret = 0;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		return -1;
	}

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);
	iwr.u.essid.pointer = (caddr_t) ssid;
	iwr.u.essid.length = 32;

	if (ioctl(s, SIOCGIWESSID, &iwr) < 0) {
		perror("ioctl[SIOCGIWESSID]");
		ret = -1;
	} else
		ret = iwr.u.essid.length;

	close(s);
	return ret;
}


int wpa_driver_wext_set_ssid(const char *ifname, const char *ssid,
			     size_t ssid_len)
{
	struct iwreq iwr;
	int s, ret = 0;
	char buf[33];

	if (ssid_len > 32)
		return -1;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		return -1;
	}

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);
	/* flags: 1 = ESSID is active, 0 = not (promiscuous) */
	iwr.u.essid.flags = (ssid_len != 0);
	memset(buf, 0, sizeof(buf));
	memcpy(buf, ssid, ssid_len);
	iwr.u.essid.pointer = (caddr_t) buf;
	/* For historic reasons, set SSID length to include one extra
	 * character, C string nul termination, even though SSID is really an
	 * octet string that should not be presented as a C string. Some Linux
	 * drivers decrement the length by one and can thus end up missing the
	 * last octet of the SSID if the length is not incremented here. */
	iwr.u.essid.length = ssid_len ? ssid_len + 1 : 0;

	if (ioctl(s, SIOCSIWESSID, &iwr) < 0) {
		perror("ioctl[SIOCSIWESSID]");
		ret = -1;
	}

	close(s);
	return ret;
}


int wpa_driver_wext_set_freq(const char *ifname, int freq)
{
	struct iwreq iwr;
	int s, ret = 0;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		return -1;
	}

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);
	iwr.u.freq.m = freq * 100000;
	iwr.u.freq.e = 1;

	if (ioctl(s, SIOCSIWFREQ, &iwr) < 0) {
		perror("ioctl[SIOCSIWFREQ]");
		ret = -1;
	}

	close(s);
	return ret;
}


static void wpa_driver_wext_event_wireless_custom(void *ctx, char *custom)
{
	union wpa_event_data data;

	wpa_printf(MSG_DEBUG, "Custom wireless event: '%s'", custom);

	memset(&data, 0, sizeof(data));
	/* Host AP driver */
	if (strncmp(custom, "MLME-MICHAELMICFAILURE.indication", 33) == 0) {
		data.michael_mic_failure.unicast =
			strstr(custom, " unicast ") != NULL;
		/* TODO: parse parameters(?) */
		wpa_supplicant_event(ctx, EVENT_MICHAEL_MIC_FAILURE, &data);
	} else if (strncmp(custom, "ASSOCINFO(ReqIEs=", 17) == 0) {
		char *spos;
		int bytes;

		spos = custom + 17;

		bytes = strspn(spos, "0123456789abcdefABCDEF");
		if (!bytes || (bytes & 1))
			return;
		bytes /= 2;

		data.assoc_info.req_ies = malloc(bytes);
		if (data.assoc_info.req_ies == NULL)
			return;

		data.assoc_info.req_ies_len = bytes;
		hexstr2bin(spos, data.assoc_info.req_ies, bytes);

		spos += bytes * 2;

		data.assoc_info.resp_ies = NULL;
		data.assoc_info.resp_ies_len = 0;

		if (strncmp(spos, " RespIEs=", 9) == 0) {
			spos += 9;

			bytes = strspn(spos, "0123456789abcdefABCDEF");
			if (!bytes || (bytes & 1))
				goto done;
			bytes /= 2;

			data.assoc_info.resp_ies = malloc(bytes);
			if (data.assoc_info.resp_ies == NULL)
				goto done;

			data.assoc_info.resp_ies_len = bytes;
			hexstr2bin(spos, data.assoc_info.resp_ies, bytes);
		}

		wpa_supplicant_event(ctx, EVENT_ASSOCINFO, &data);

	done:
		free(data.assoc_info.resp_ies);
		free(data.assoc_info.req_ies);
	}
}


static void wpa_driver_wext_event_wireless(void *ctx, char *data, int len)
{
	struct iw_event iwe_buf, *iwe = &iwe_buf;
	char *pos, *end, *custom, *buf;

	pos = data;
	end = data + len;

	while (pos + IW_EV_LCP_LEN <= end) {
		/* Event data may be unaligned, so make a local, aligned copy
		 * before processing. */
		memcpy(&iwe_buf, pos, sizeof(struct iw_event));
		wpa_printf(MSG_DEBUG, "Wireless event: cmd=0x%x len=%d",
			   iwe->cmd, iwe->len);
		if (iwe->len <= IW_EV_LCP_LEN)
			return;
		switch (iwe->cmd) {
		case SIOCGIWAP:
			wpa_printf(MSG_DEBUG, "Wireless event: new AP: "
				   MACSTR,
				   MAC2STR((u8 *) iwe->u.ap_addr.sa_data));
			if (memcmp(iwe->u.ap_addr.sa_data,
				   "\x00\x00\x00\x00\x00\x00", ETH_ALEN) == 0
			    ||
			    memcmp(iwe->u.ap_addr.sa_data,
				   "\x44\x44\x44\x44\x44\x44", ETH_ALEN) == 0)
				wpa_supplicant_event(ctx, EVENT_DISASSOC,
						     NULL);
			else
				wpa_supplicant_event(ctx, EVENT_ASSOC, NULL);
			break;
		case IWEVCUSTOM:
			custom = pos + IW_EV_POINT_LEN;
			if (custom + iwe->u.data.length > end)
				return;
			buf = malloc(iwe->u.data.length + 1);
			if (buf == NULL)
				return;
			memcpy(buf, custom, iwe->u.data.length);
			buf[iwe->u.data.length] = '\0';
			wpa_driver_wext_event_wireless_custom(ctx, buf);
			free(buf);
			break;
		case SIOCGIWSCAN:
			eloop_cancel_timeout(wpa_driver_wext_scan_timeout,
					     NULL, ctx);
			wpa_supplicant_event(ctx, EVENT_SCAN_RESULTS, NULL);
			break;
		}

		pos += iwe->len;
	}
}


static void wpa_driver_wext_event_link(void *ctx, char *buf, size_t len,
				       int del)
{
	union wpa_event_data event;

	memset(&event, 0, sizeof(event));
	if (len > sizeof(event.interface_status.ifname))
		len = sizeof(event.interface_status.ifname) - 1;
	memcpy(event.interface_status.ifname, buf, len);
	event.interface_status.ievent = del ? EVENT_INTERFACE_REMOVED :
		EVENT_INTERFACE_ADDED;

	wpa_printf(MSG_DEBUG, "RTM_%sLINK, IFLA_IFNAME: Interface '%s' %s",
		   del ? "DEL" : "NEW",
		   event.interface_status.ifname,
		   del ? "removed" : "added");

	wpa_supplicant_event(ctx, EVENT_INTERFACE_STATUS, &event);
}


static void wpa_driver_wext_event_rtm_newlink(void *ctx, struct nlmsghdr *h,
					      int len)
{
	struct ifinfomsg *ifi;
	int attrlen, nlmsg_len, rta_len;
	struct rtattr * attr;

	if (len < sizeof(*ifi))
		return;

	ifi = NLMSG_DATA(h);

	/* TODO: use ifi->ifi_index to recognize the interface (?) */

	nlmsg_len = NLMSG_ALIGN(sizeof(struct ifinfomsg));

	attrlen = h->nlmsg_len - nlmsg_len;
	if (attrlen < 0)
		return;

	attr = (struct rtattr *) (((char *) ifi) + nlmsg_len);

	rta_len = RTA_ALIGN(sizeof(struct rtattr));
	while (RTA_OK(attr, attrlen)) {
		if (attr->rta_type == IFLA_WIRELESS) {
			wpa_driver_wext_event_wireless(
				ctx, ((char *) attr) + rta_len,
				attr->rta_len - rta_len);
		} else if (attr->rta_type == IFLA_IFNAME) {
			wpa_driver_wext_event_link(ctx,
						   ((char *) attr) + rta_len,
						   attr->rta_len - rta_len, 0);
		}
		attr = RTA_NEXT(attr, attrlen);
	}
}


static void wpa_driver_wext_event_rtm_dellink(void *ctx, struct nlmsghdr *h,
					      int len)
{
	struct ifinfomsg *ifi;
	int attrlen, nlmsg_len, rta_len;
	struct rtattr * attr;

	if (len < sizeof(*ifi))
		return;

	ifi = NLMSG_DATA(h);

	nlmsg_len = NLMSG_ALIGN(sizeof(struct ifinfomsg));

	attrlen = h->nlmsg_len - nlmsg_len;
	if (attrlen < 0)
		return;

	attr = (struct rtattr *) (((char *) ifi) + nlmsg_len);

	rta_len = RTA_ALIGN(sizeof(struct rtattr));
	while (RTA_OK(attr, attrlen)) {
		if (attr->rta_type == IFLA_IFNAME) {
			wpa_driver_wext_event_link(ctx,
						   ((char *) attr) + rta_len,
						   attr->rta_len - rta_len, 1);
		}
		attr = RTA_NEXT(attr, attrlen);
	}
}


static void wpa_driver_wext_event_receive(int sock, void *eloop_ctx,
					  void *sock_ctx)
{
	char buf[8192];
	int left;
	struct sockaddr_nl from;
	socklen_t fromlen;
	struct nlmsghdr *h;

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
			wpa_printf(MSG_DEBUG, "Malformed netlink message: "
				   "len=%d left=%d plen=%d",
				   len, left, plen);
			break;
		}

		switch (h->nlmsg_type) {
		case RTM_NEWLINK:
			wpa_driver_wext_event_rtm_newlink(eloop_ctx, h, plen);
			break;
		case RTM_DELLINK:
			wpa_driver_wext_event_rtm_dellink(eloop_ctx, h, plen);
			break;
		}

		len = NLMSG_ALIGN(len);
		left -= len;
		h = (struct nlmsghdr *) ((char *) h + len);
	}

	if (left > 0) {
		wpa_printf(MSG_DEBUG, "%d extra bytes in the end of netlink "
			   "message", left);
	}
}


struct wpa_driver_wext_events_data {
	int sock;
};


void * wpa_driver_wext_events_init(void *ctx)
{
	int s;
	struct sockaddr_nl local;
	struct wpa_driver_wext_events_data *data;

	data = malloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	memset(data, 0, sizeof(*data));

	s = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (s < 0) {
		perror("socket(PF_NETLINK,SOCK_RAW,NETLINK_ROUTE)");
		free(data);
		return NULL;
	}

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = RTMGRP_LINK;
	if (bind(s, (struct sockaddr *) &local, sizeof(local)) < 0) {
		perror("bind(netlink)");
		close(s);
		free(data);
		return NULL;
	}

	eloop_register_read_sock(s, wpa_driver_wext_event_receive, ctx, NULL);
	data->sock = s;

	return data;
}


int wpa_driver_wext_events_deinit(void *ctx, void *priv)
{
	struct wpa_driver_wext_events_data *data = priv;
	close(data->sock);
	free(data);
	return 0;
}


void wpa_driver_wext_scan_timeout(void *eloop_ctx, void *timeout_ctx)
{
	wpa_printf(MSG_DEBUG, "Scan timeout - try to get results");
	wpa_supplicant_event(timeout_ctx, EVENT_SCAN_RESULTS, NULL);
}


int wpa_driver_wext_scan(const char *ifname, void *ctx, u8 *ssid,
			 size_t ssid_len)
{
	struct iwreq iwr;
	int s, ret = 0;

	if (ssid)
		return -1;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		return -1;
	}

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(s, SIOCSIWSCAN, &iwr) < 0) {
		perror("ioctl[SIOCSIWSCAN]");
		ret = -1;
	}

	close(s);

	/* Not all drivers generate "scan completed" wireless event, so try to
	 * read results after a timeout. */
	eloop_register_timeout(3, 0, wpa_driver_wext_scan_timeout, NULL, ctx);

	return ret;
}


/* Compare function for sorting scan results. Return >0 if @b is consider
 * better. */
static int wpa_scan_result_compar(const void *a, const void *b)
{
	const struct wpa_scan_result *wa = a;
	const struct wpa_scan_result *wb = b;

	/* WPA/WPA2 support preferred */
	if ((wb->wpa_ie_len || wb->rsn_ie_len) &&
	    !(wa->wpa_ie_len || wa->rsn_ie_len))
		return 1;
	if (!(wb->wpa_ie_len || wb->rsn_ie_len) &&
	    (wa->wpa_ie_len || wa->rsn_ie_len))
		return -1;

	/* privacy support preferred */
	if ((wa->caps & IW_ENCODE_DISABLED) &&
	    (wb->caps & IW_ENCODE_DISABLED) == 0)
		return 1;
	if ((wa->caps & IW_ENCODE_DISABLED) == 0 &&
	    (wb->caps & IW_ENCODE_DISABLED))
		return -1;

	/* best/max rate preferred if signal level close enough XXX */
	if (wa->maxrate != wb->maxrate && abs(wb->level - wa->level) < 5)
		return wb->maxrate - wa->maxrate;

	/* use freq for channel preference */

	/* all things being equal, use signal level */
	return wb->level - wa->level;
}


int wpa_driver_wext_get_scan_results(const char *ifname,
				     struct wpa_scan_result *results,
				     size_t max_size)
{
	struct iwreq iwr;
	int s, ap_num = 0, first, maxrate;
	u8 res_buf[IW_SCAN_MAX_DATA];
	struct iw_event iwe_buf, *iwe = &iwe_buf;
	char *pos, *end, *custom;
	struct iw_param p;
	size_t len, clen;

	memset(results, 0, max_size * sizeof(struct wpa_scan_result));
	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		return -1;
	}

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);
	iwr.u.data.pointer = res_buf;
	iwr.u.data.length = IW_SCAN_MAX_DATA;

	if (ioctl(s, SIOCGIWSCAN, &iwr) < 0) {
		perror("ioctl[SIOCGIWSCAN]");
		close(s);
		return -1;
	}

	len = iwr.u.data.length;
	ap_num = 0;
	first = 1;

	pos = res_buf;
	end = res_buf + len;

	while (pos + IW_EV_LCP_LEN <= end) {
		int ssid_len;
		/* Event data may be unaligned, so make a local, aligned copy
		 * before processing. */
		memcpy(&iwe_buf, pos, sizeof(struct iw_event));
		if (iwe->len <= IW_EV_LCP_LEN)
			break;
		switch (iwe->cmd) {
		case SIOCGIWAP:
			if (!first)
				ap_num++;
			first = 0;
			if (ap_num < max_size) {
				memcpy(results[ap_num].bssid,
				       iwe->u.ap_addr.sa_data, ETH_ALEN);
			}
			break;
		case SIOCGIWESSID:
			ssid_len = iwe->u.essid.length;
			custom = pos + IW_EV_POINT_LEN;
			if (custom + ssid_len > end)
				break;
			if (iwe->u.essid.flags &&
			    ssid_len > 0 &&
			    ssid_len <= IW_ESSID_MAX_SIZE) {
				if (ap_num < max_size) {
					memcpy(results[ap_num].ssid, custom,
					       ssid_len);
					results[ap_num].ssid_len = ssid_len;
				}
			}
			break;
		case SIOCGIWFREQ:
			if (ap_num < max_size) {
				int div = 1000000, i;
				if (iwe->u.freq.e > 6) {
					wpa_printf(
						MSG_DEBUG, "Invalid freq "
						"in scan results (BSSID="
						MACSTR ": m=%d e=%d\n",
						MAC2STR(results[ap_num].bssid),
						iwe->u.freq.m, iwe->u.freq.e);
					break;
				}
				for (i = 0; i < iwe->u.freq.e; i++)
					div /= 10;
				results[ap_num].freq = iwe->u.freq.m / div;
			}
			break;
		case IWEVQUAL:
			if (ap_num < max_size) {
				results[ap_num].qual = iwe->u.qual.qual;
				results[ap_num].noise = iwe->u.qual.noise;
				results[ap_num].level = iwe->u.qual.level;
			}
			break;
		case SIOCGIWENCODE:
			if (ap_num < max_size)
				results[ap_num].caps = iwe->u.data.flags;
			break;
		case SIOCGIWRATE:
			custom = pos + IW_EV_LCP_LEN;
			clen = iwe->len;
			if (custom + clen > end)
				break;
			maxrate = 0;
			while (((ssize_t) clen) >= sizeof(struct iw_param)) {
				/* Note: may be misaligned, make a local,
				 * aligned copy */
				memcpy(&p, custom, sizeof(struct iw_param));
				if (p.value > maxrate)
					maxrate = p.value;
				clen -= sizeof(struct iw_param);
				custom += sizeof(struct iw_param);
			}
			if (ap_num < max_size)
				results[ap_num].maxrate = maxrate;
			break;
		case IWEVCUSTOM:
			custom = pos + IW_EV_POINT_LEN;
			clen = iwe->u.data.length;
			if (custom + clen > end)
				break;
			if (clen > 7 && strncmp(custom, "wpa_ie=", 7) == 0 &&
			    ap_num < max_size) {
				char *spos;
				int bytes;
				spos = custom + 7;
				bytes = custom + clen - spos;
				if (bytes & 1)
					break;
				bytes /= 2;
				if (bytes > SSID_MAX_WPA_IE_LEN) {
					wpa_printf(MSG_INFO, "Too long WPA IE "
						   "(%d)", bytes);
					break;
				}
				hexstr2bin(spos, results[ap_num].wpa_ie,
					   bytes);
				results[ap_num].wpa_ie_len = bytes;
			} else if (clen > 7 &&
				   strncmp(custom, "rsn_ie=", 7) == 0 &&
				   ap_num < max_size) {
				char *spos;
				int bytes;
				spos = custom + 7;
				bytes = custom + clen - spos;
				if (bytes & 1)
					break;
				bytes /= 2;
				if (bytes > SSID_MAX_WPA_IE_LEN) {
					wpa_printf(MSG_INFO, "Too long RSN IE "
						   "(%d)", bytes);
					break;
				}
				hexstr2bin(spos, results[ap_num].rsn_ie,
					   bytes);
				results[ap_num].rsn_ie_len = bytes;
			}
			break;
		}

		pos += iwe->len;
	}
	qsort(results, ap_num, sizeof(struct wpa_scan_result),
	      wpa_scan_result_compar);

	wpa_printf(MSG_DEBUG, "Received %d bytes of scan results (%d BSSes)",
		   len, first ? 0 : ap_num + 1);

	close(s);
	return first ? 0 : ap_num + 1;
}


static int wpa_driver_wext_set_wpa(const char *ifname, int enabled)
{
	wpa_printf(MSG_DEBUG, "%s: enabled=%d - not yet implemented",
		   __FUNCTION__, enabled);
	return 0;
}


static int wpa_driver_wext_set_key(const char *ifname, wpa_alg alg,
				   unsigned char *addr, int key_idx,
				   int set_tx, u8 *seq, size_t seq_len,
				   u8 *key, size_t key_len)
{
	struct iwreq iwr;
	int s, ret = 0;

	wpa_printf(MSG_DEBUG, "%s: alg=%d key_idx=%d set_tx=%d seq_len=%d "
		   "key_len=%d",
		   __FUNCTION__, alg, key_idx, set_tx, seq_len, key_len);

	if (alg != WPA_ALG_NONE && alg != WPA_ALG_WEP) {
		wpa_printf(MSG_DEBUG, "%s: alg=%d not yet supported",
			   __FUNCTION__, alg);
		/* TODO: add support for this once Linux wireless extensions
		 * get support for WPA */
		return -1;
	}

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		return -1;
	}

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);
	iwr.u.encoding.flags = key_idx + 1;
	if (alg == WPA_ALG_NONE)
		iwr.u.encoding.flags |= IW_ENCODE_DISABLED;
	iwr.u.encoding.pointer = (caddr_t) key;
	iwr.u.encoding.length = key_len;

	if (ioctl(s, SIOCSIWENCODE, &iwr) < 0) {
		perror("ioctl[SIOCSIWENCODE]");
		ret = -1;
	}

	if (set_tx && alg != WPA_ALG_NONE) {
		memset(&iwr, 0, sizeof(iwr));
		strncpy(iwr.ifr_name, ifname, IFNAMSIZ);
		iwr.u.encoding.flags = key_idx + 1;
		iwr.u.encoding.pointer = (caddr_t) key;
		iwr.u.encoding.length = 0;
		if (ioctl(s, SIOCSIWENCODE, &iwr) < 0) {
			perror("ioctl[SIOCSIWENCODE] (set_tx)");
			ret = -1;
		}
	}

	close(s);
	return ret;
}


static int wpa_driver_wext_set_countermeasures(const char *ifname,
					       int enabled)
{
	wpa_printf(MSG_DEBUG, "%s: enabled=%d - not yet implemented",
		   __FUNCTION__, enabled);
	return 0;
}


static int wpa_driver_wext_set_drop_unencrypted(const char *ifname,
						int enabled)
{
	wpa_printf(MSG_DEBUG, "%s: enabled=%d - not yet implemented",
		   __FUNCTION__, enabled);
	return 0;
}


static int wpa_driver_wext_deauthenticate(const char *ifname, u8 *addr,
					  int reason_code)
{
	wpa_printf(MSG_DEBUG, "%s - not yet implemented", __FUNCTION__);
	return 0;
}


static int wpa_driver_wext_disassociate(const char *ifname, u8 *addr,
					int reason_code)
{
	wpa_printf(MSG_DEBUG, "%s - not yet implemented", __FUNCTION__);
	return 0;
}


static int wpa_driver_wext_associate(const char *ifname, const char *bssid,
				     const char *ssid, size_t ssid_len,
				     int freq,
				     const char *wpa_ie, size_t wpa_ie_len,
				     wpa_cipher pairwise_suite,
				     wpa_cipher group_suite,
				     wpa_key_mgmt key_mgmt_suite)
{
	wpa_printf(MSG_DEBUG, "%s - not yet implemented", __FUNCTION__);
	return 0;
}


struct wpa_driver_ops wpa_driver_wext_ops = {
	.get_bssid = wpa_driver_wext_get_bssid,
	.get_ssid = wpa_driver_wext_get_ssid,
	.set_wpa = wpa_driver_wext_set_wpa,
	.set_key = wpa_driver_wext_set_key,
	.events_init = wpa_driver_wext_events_init,
	.events_deinit = wpa_driver_wext_events_deinit,
	.set_countermeasures = wpa_driver_wext_set_countermeasures,
	.set_drop_unencrypted = wpa_driver_wext_set_drop_unencrypted,
	.scan = wpa_driver_wext_scan,
	.get_scan_results = wpa_driver_wext_get_scan_results,
	.deauthenticate = wpa_driver_wext_deauthenticate,
	.disassociate = wpa_driver_wext_disassociate,
	.associate = wpa_driver_wext_associate,
};
