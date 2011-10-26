/*
 * WPA Supplicant - driver interaction with Linux ndiswrapper
 * Copyright (c) 2004, Giridhar Pemmasani <giri@lmc.cs.sunysb.edu>
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
#include "priv_netlink.h"
#include "driver_wext.h"

struct wpa_key
{
	wpa_alg alg;
	u8 *addr;
	int key_index;
	int set_tx;
	u8 *seq;
	size_t seq_len;
	u8 *key;
	size_t key_len;
};

struct wpa_assoc_info
{
	const char *bssid;
	const char *ssid;
	size_t ssid_len;
	int freq;
	const char *wpa_ie;
	size_t wpa_ie_len;
	wpa_cipher pairwise_suite;
	wpa_cipher group_suite;
	wpa_key_mgmt key_mgmt_suite;
};

#define PRIV_RESET	 		SIOCIWFIRSTPRIV+0
#define WPA_SET_WPA 			SIOCIWFIRSTPRIV+1
#define WPA_SET_KEY 			SIOCIWFIRSTPRIV+2
#define WPA_ASSOCIATE		 	SIOCIWFIRSTPRIV+3
#define WPA_DISASSOCIATE 		SIOCIWFIRSTPRIV+4
#define WPA_DROP_UNENCRYPTED 		SIOCIWFIRSTPRIV+5
#define WPA_SET_COUNTERMEASURES 	SIOCIWFIRSTPRIV+6
#define WPA_DEAUTHENTICATE	 	SIOCIWFIRSTPRIV+7
#define WPA_SET_AUTH_ALG	 	SIOCIWFIRSTPRIV+8

static int get_socket(void)
{
	static const int families[] = {
		AF_INET, AF_IPX, AF_AX25, AF_APPLETALK
	};
	unsigned int i;
	int sock;

	for (i = 0; i < sizeof(families) / sizeof(int); ++i) {
		sock = socket(families[i], SOCK_DGRAM, 0);
		if (sock >= 0)
			return sock;
	}

	return -1;
}

static int iw_set_ext(const char *ifname, int request, struct iwreq *pwrq)
{
	int s = get_socket();
	int ret;
	if (s < 0)
		return -1;
	strncpy(pwrq->ifr_name, ifname, IFNAMSIZ);
	ret = ioctl(s, request, pwrq);
	close(s);
	return ret;
}

static int wpa_ndiswrapper_set_wpa(const char *ifname, int enabled)
{
	struct iwreq priv_req;
	int ret = 0;

	memset(&priv_req, 0, sizeof(priv_req));

	priv_req.u.data.flags = enabled;
	if (iw_set_ext(ifname, WPA_SET_WPA, &priv_req) < 0)
		ret = -1;
	return ret;
}

static int wpa_ndiswrapper_set_key(const char *ifname, wpa_alg alg, u8 *addr,
				   int key_idx, int set_tx, u8 *seq,
				   size_t seq_len, u8 *key, size_t key_len)
{
	struct wpa_key wpa_key;
	int ret = 0;
	struct iwreq priv_req;

	memset(&priv_req, 0, sizeof(priv_req));

	wpa_key.alg = alg;
	wpa_key.addr = addr;
	wpa_key.key_index = key_idx;
	wpa_key.set_tx = set_tx;
	wpa_key.seq = seq;
	wpa_key.seq_len = seq_len;
	wpa_key.key = key;
	wpa_key.key_len = key_len;

	priv_req.u.data.pointer = (void *)&wpa_key;

	if (iw_set_ext(ifname, WPA_SET_KEY, &priv_req) < 0)
		ret = -1;
	return ret;
}

static int wpa_ndiswrapper_set_countermeasures(const char *ifname, int enabled)
{
	int ret = 0;
	struct iwreq priv_req;

	memset(&priv_req, 0, sizeof(priv_req));

	priv_req.u.param.value = enabled;
	if (iw_set_ext(ifname, WPA_SET_COUNTERMEASURES, &priv_req) < 0)
		ret = -1;

	return ret;
}

static int wpa_ndiswrapper_set_drop_unencrypted(const char *ifname,
						int enabled)
{
	int ret = 0;
	struct iwreq priv_req;

	memset(&priv_req, 0, sizeof(priv_req));

	priv_req.u.param.value = enabled;
	if (iw_set_ext(ifname, WPA_DROP_UNENCRYPTED, &priv_req) < 0)
		ret = -1;
	return ret;
}

static int wpa_ndiswrapper_deauthenticate(const char *ifname, u8 *addr,
					  int reason_code)
{
	int ret = 0;
	struct iwreq priv_req;

	memset(&priv_req, 0, sizeof(priv_req));

	priv_req.u.param.value = reason_code;
	memcpy(&priv_req.u.ap_addr.sa_data, addr, ETH_ALEN);
	if (iw_set_ext(ifname, WPA_DEAUTHENTICATE, &priv_req) < 0)
		ret = -1;
	return ret;
}

static int wpa_ndiswrapper_disassociate(const char *ifname, u8 *addr,
					int reason_code)
{
	int ret = 0;
	struct iwreq priv_req;

	memset(&priv_req, 0, sizeof(priv_req));

	memcpy(&priv_req.u.ap_addr.sa_data, addr, ETH_ALEN);
	if (iw_set_ext(ifname, WPA_DISASSOCIATE, &priv_req) < 0)
		ret = -1;
	return ret;
}

static int wpa_ndiswrapper_associate(const char *ifname, const char *bssid,
				     const char *ssid, size_t ssid_len,
				     int freq, const char *wpa_ie,
				     size_t wpa_ie_len,
				     wpa_cipher pairwise_suite,
				     wpa_cipher group_suite,
				     wpa_key_mgmt key_mgmt_suite)
{
	int ret = 0;
	struct wpa_assoc_info wpa_assoc_info;
	struct iwreq priv_req;
	char buf[IW_ESSID_MAX_SIZE];

	memset(&priv_req, 0, sizeof(priv_req));
	memset(&wpa_assoc_info, 0, sizeof(wpa_assoc_info));

	if (ssid_len > IW_ESSID_MAX_SIZE)
		return -1;
	memcpy(buf, ssid, ssid_len);
	wpa_assoc_info.bssid = bssid;
	wpa_assoc_info.ssid = buf;
	wpa_assoc_info.ssid_len = ssid_len;
	wpa_assoc_info.freq = freq;
	wpa_assoc_info.wpa_ie = wpa_ie;
	wpa_assoc_info.wpa_ie_len = wpa_ie_len;
	wpa_assoc_info.pairwise_suite = pairwise_suite;
	wpa_assoc_info.group_suite = group_suite;
	wpa_assoc_info.key_mgmt_suite = key_mgmt_suite;

	priv_req.u.data.pointer = (void *)&wpa_assoc_info;

	if (iw_set_ext(ifname, WPA_ASSOCIATE, &priv_req) < 0)
		ret = -1;
	return ret;
}

static int wpa_ndiswrapper_set_auth_alg(const char *ifname, int auth_alg)
{
	int ret = 0;
	struct iwreq priv_req;

	memset(&priv_req, 0, sizeof(priv_req));

	priv_req.u.param.value = auth_alg;
	if (iw_set_ext(ifname, WPA_SET_AUTH_ALG, &priv_req) < 0)
		ret = -1;
	return ret;
}

struct wpa_driver_ops wpa_driver_ndiswrapper_ops = {
	.set_wpa = wpa_ndiswrapper_set_wpa,
	.set_key = wpa_ndiswrapper_set_key,
	.set_countermeasures = wpa_ndiswrapper_set_countermeasures,
	.set_drop_unencrypted = wpa_ndiswrapper_set_drop_unencrypted,
	.deauthenticate = wpa_ndiswrapper_deauthenticate,
	.disassociate = wpa_ndiswrapper_disassociate,
	.associate = wpa_ndiswrapper_associate,
	.set_auth_alg = wpa_ndiswrapper_set_auth_alg,

	.get_bssid = wpa_driver_wext_get_bssid,
	.get_ssid = wpa_driver_wext_get_ssid,
	.events_init = wpa_driver_wext_events_init,
	.events_deinit = wpa_driver_wext_events_deinit,
	.scan = wpa_driver_wext_scan,
	.get_scan_results = wpa_driver_wext_get_scan_results,
};
