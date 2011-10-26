/*
 * WPA Supplicant - driver interaction with MADWIFI 802.11 driver
 * Copyright (c) 2004, Sam Leffler <sam@errno.com>
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

#include "common.h"
#include "driver.h"
#include "driver_wext.h"
#include "eloop.h"
#include "wpa_supplicant.h"

#include <include/compat.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_crypto.h>
#include <net80211/ieee80211_ioctl.h>

#include <net/if_arp.h>
#include <linux/wireless.h>

static	int s = -1;

static void
checksocket()
{
	if (s < 0 ? (s = socket(AF_INET, SOCK_DGRAM, 0)) == -1 : 0)
		perror("socket(SOCK_DRAGM)");
}

static int
set80211priv(const char *dev, int op, void *data, int len, int show_err)
{
	struct iwreq iwr;

	checksocket();

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, dev, IFNAMSIZ);
	if (len < IFNAMSIZ) {
		/*
		 * Argument data fits inline; put it there.
		 */
		memcpy(iwr.u.name, data, len);
	} else {
		/*
		 * Argument data too big for inline transfer; setup a
		 * parameter block instead; the kernel will transfer
		 * the data for the driver.
		 */
		iwr.u.data.pointer = data;
		iwr.u.data.length = len;
	}

	if (ioctl(s, op, &iwr) < 0) {
		if (show_err) {
			static const char *opnames[] = {
				"ioctl[IEEE80211_IOCTL_SETPARAM]",
				"ioctl[IEEE80211_IOCTL_GETPARAM]",
				"ioctl[IEEE80211_IOCTL_SETKEY]",
				"ioctl[IEEE80211_IOCTL_GETKEY]",
				"ioctl[IEEE80211_IOCTL_DELKEY]",
				NULL,
				"ioctl[IEEE80211_IOCTL_SETMLME]",
				NULL,
				"ioctl[IEEE80211_IOCTL_SETOPTIE]",
				"ioctl[IEEE80211_IOCTL_GETOPTIE]",
				"ioctl[IEEE80211_IOCTL_ADDMAC]",
				NULL,
				"ioctl[IEEE80211_IOCTL_DELMAC]",
				NULL,
				"ioctl[IEEE80211_IOCTL_CHANLIST]",
			};
			if (IEEE80211_IOCTL_SETPARAM <= op &&
			    op <= IEEE80211_IOCTL_CHANLIST)
				perror(opnames[op - SIOCIWFIRSTPRIV]);
			else
				perror("ioctl[unknown???]");
		}
		return -1;
	}
	return 0;
}

static int
set80211param(const char *dev, int op, int arg, int show_err)
{
	struct iwreq iwr;

	checksocket();

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, dev, IFNAMSIZ);
	iwr.u.mode = op;
	memcpy(iwr.u.name+sizeof(__u32), &arg, sizeof(arg));

	if (ioctl(s, IEEE80211_IOCTL_SETPARAM, &iwr) < 0) {
		if (show_err) 
			perror("ioctl[IEEE80211_IOCTL_SETPARAM]");
		return -1;
	}
	return 0;
}

static int
getifflags(const char *ifname, int *flags)
{
	struct ifreq ifr;

	checksocket();

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	if (ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
		perror("SIOCGIFFLAGS");
		return errno;
	}
	*flags = ifr.ifr_flags & 0xffff;
	return 0;
}

static int
setifflags(const char *ifname, int flags)
{
	struct ifreq ifr;

	checksocket();

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	ifr.ifr_flags = flags & 0xffff;
	if (ioctl(s, SIOCSIFFLAGS, (caddr_t)&ifr) < 0) {
		perror("SIOCSIFFLAGS");
		return errno;
	}
	return 0;
}

static int
wpa_driver_madwifi_set_wpa_ie(const char *ifname,
	const char *wpa_ie, size_t wpa_ie_len)
{
	struct iwreq iwr;

	checksocket();

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);
	/* NB: SETOPTIE is not fixed-size so must not be inlined */
	iwr.u.data.pointer = (void *) wpa_ie;
	iwr.u.data.length = wpa_ie_len;

	if (ioctl(s, IEEE80211_IOCTL_SETOPTIE, &iwr) < 0) {
		perror("ioctl[IEEE80211_IOCTL_SETOPTIE]");
		return -1;
	}
	return 0;
}

static int
wpa_driver_madwifi_set_wpa(const char *ifname, int enabled)
{
	int ret = 0;

	wpa_printf(MSG_DEBUG, "%s: enabled=%d", __FUNCTION__, enabled);

	if (!enabled && wpa_driver_madwifi_set_wpa_ie(ifname, NULL, 0) < 0)
		ret = -1;
	if (set80211param(ifname, IEEE80211_PARAM_ROAMING, enabled ? 2 : 0, 1) < 0)
		ret = -1;
	if (set80211param(ifname, IEEE80211_PARAM_PRIVACY, enabled, 1) < 0)
		ret = -1;
	if (set80211param(ifname, IEEE80211_PARAM_WPA, enabled ? 3 : 0, 1) < 0)
		ret = -1;

	return ret;
}

static int
wpa_driver_madwifi_del_key(const char *ifname, int key_idx, unsigned char *addr)
{
	struct ieee80211req_del_key wk;

	wpa_printf(MSG_DEBUG, "%s: keyidx=%d", __FUNCTION__, key_idx);
	memset(&wk, 0, sizeof(wk));
	wk.idk_keyix = key_idx;
	if (addr != NULL)
		memcpy(wk.idk_macaddr, addr, IEEE80211_ADDR_LEN);

	return set80211priv(ifname, IEEE80211_IOCTL_DELKEY, &wk, sizeof(wk), 1);
}

static int
wpa_driver_madwifi_set_key(const char *ifname, wpa_alg alg,
				     unsigned char *addr, int key_idx,
				     int set_tx, u8 *seq, size_t seq_len,
				     u8 *key, size_t key_len)
{
	struct ieee80211req_key wk;
	char *alg_name;
	u_int8_t cipher;

	if (alg == WPA_ALG_NONE)
		return wpa_driver_madwifi_del_key(ifname, key_idx, addr);

	switch (alg) {
	case WPA_ALG_WEP:
		alg_name = "WEP";
		cipher = IEEE80211_CIPHER_WEP;
		break;
	case WPA_ALG_TKIP:
		alg_name = "TKIP";
		cipher = IEEE80211_CIPHER_TKIP;
		break;
	case WPA_ALG_CCMP:
		alg_name = "CCMP";
		cipher = IEEE80211_CIPHER_AES_CCM;
		break;
	default:
		wpa_printf(MSG_DEBUG, "%s: unknown/unsupported algorithm %d",
			__FUNCTION__, alg);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "%s: alg=%s key_idx=%d set_tx=%d seq_len=%d "
		   "key_len=%d", __FUNCTION__, alg_name, key_idx, set_tx,
		   seq_len, key_len);

	if (seq_len > sizeof(u_int64_t)) {
		wpa_printf(MSG_DEBUG, "%s: seq_len %d too big",
			__FUNCTION__, seq_len);
		return -2;
	}
	if (key_len > sizeof(wk.ik_keydata)) {
		wpa_printf(MSG_DEBUG, "%s: key length %d too big",
			__FUNCTION__, key_len);
		return -3;
	}

	memset(&wk, 0, sizeof(wk));
	wk.ik_type = cipher;
	wk.ik_flags = IEEE80211_KEY_RECV;
	if (set_tx) {
		wk.ik_flags |= IEEE80211_KEY_XMIT | IEEE80211_KEY_DEFAULT;
		memcpy(wk.ik_macaddr, addr, IEEE80211_ADDR_LEN);
	} else
		memset(wk.ik_macaddr, 0, IEEE80211_ADDR_LEN);
	wk.ik_keyix = key_idx;
	wk.ik_keylen = key_len;
	memcpy(&wk.ik_keyrsc, seq, seq_len);
	memcpy(wk.ik_keydata, key, key_len);

	return set80211priv(ifname, IEEE80211_IOCTL_SETKEY, &wk, sizeof(wk), 1);
}

static int
wpa_driver_madwifi_set_countermeasures(const char *ifname, int enabled)
{
	wpa_printf(MSG_DEBUG, "%s: enabled=%d", __FUNCTION__, enabled);
	return set80211param(ifname, IEEE80211_PARAM_COUNTERMEASURES, enabled, 1);
}


static int
wpa_driver_madwifi_set_drop_unencrypted(const char *ifname, int enabled)
{
	wpa_printf(MSG_DEBUG, "%s: enabled=%d", __FUNCTION__, enabled);
	return set80211param(ifname, IEEE80211_PARAM_DROPUNENCRYPTED, enabled, 1);
}

static int
wpa_driver_madwifi_deauthenticate(const char *ifname, u8 *addr, int reason_code)
{
	struct ieee80211req_mlme mlme;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);
	mlme.im_op = IEEE80211_MLME_DEAUTH;
	mlme.im_reason = reason_code;
	memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
	return set80211priv(ifname, IEEE80211_IOCTL_SETMLME, &mlme, sizeof(mlme), 1);
}

static int
wpa_driver_madwifi_disassociate(const char *ifname, u8 *addr, int reason_code)
{
	struct ieee80211req_mlme mlme;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);
	mlme.im_op = IEEE80211_MLME_DISASSOC;
	mlme.im_reason = reason_code;
	memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
	return set80211priv(ifname, IEEE80211_IOCTL_SETMLME, &mlme, sizeof(mlme), 1);
}

static int
wpa_driver_madwifi_associate(const char *ifname, const char *bssid,
				       const char *ssid, size_t ssid_len,
				       int freq,
				       const char *wpa_ie, size_t wpa_ie_len,
				       wpa_cipher pairwise_suite,
				       wpa_cipher group_suite,
				       wpa_key_mgmt key_mgmt_suite)
{
	struct ieee80211req_mlme mlme;

	int ret = 0;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	/*
	 * NB: Don't need to set the freq or cipher-related state as
	 *     this is implied by the bssid which is used to locate
	 *     the scanned node state which holds it.  The ssid is
	 *     needed to disambiguate an AP that broadcasts multiple
	 *     ssid's but uses the same bssid.
	 */
	/* XXX error handling is wrong but unclear what to do... */
	if (wpa_driver_madwifi_set_wpa_ie(ifname, wpa_ie, wpa_ie_len) < 0)
		ret = -1;
	if (wpa_driver_wext_set_ssid(ifname, ssid, ssid_len) < 0)
		ret = -1;
	memset(&mlme, 0, sizeof(mlme));
	mlme.im_op = IEEE80211_MLME_ASSOC;
	memcpy(mlme.im_macaddr, bssid, IEEE80211_ADDR_LEN);
	if (set80211priv(ifname, IEEE80211_IOCTL_SETMLME, &mlme, sizeof(mlme), 1) < 0)
		ret = -1;

	return ret;
}

static int
wpa_driver_madwifi_scan(const char *ifname,
	void *ctx, u8 *ssid, size_t ssid_len)
{
	struct iwreq iwr;
	int flags;

	/* NB: interface must be marked UP to do a scan */
	if (getifflags(ifname, &flags) != 0 || setifflags(ifname, flags | IFF_UP) != 0)
		return -1;

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);

	/* set desired ssid before scan */
	if (wpa_driver_wext_set_ssid(ifname, ssid, ssid_len) < 0)
		return -1;

	if (ioctl(s, SIOCSIWSCAN, &iwr) < 0) {
		perror("ioctl[SIOCSIWSCAN]");
		return -1;
	}
	/* NB: madwifi delivers a scan complete event so no need to poll */
	return 0;
}

static void
wpa_driver_madwifi_cleanup(const char *ifname)
{
	int flags;

	/* NB: mark interface down */
	if (getifflags(ifname, &flags) == 0)
		(void) setifflags(ifname, flags &~ IFF_UP);

	(void) close(s);		/* close private socket */
}

struct wpa_driver_ops wpa_driver_madwifi_ops = {
	.get_bssid		= wpa_driver_wext_get_bssid,
	.get_ssid		= wpa_driver_wext_get_ssid,
	.set_wpa		= wpa_driver_madwifi_set_wpa,
	.set_key		= wpa_driver_madwifi_set_key,
	.events_init		= wpa_driver_wext_events_init,
	.events_deinit		= wpa_driver_wext_events_deinit,
	.set_countermeasures	= wpa_driver_madwifi_set_countermeasures,
	.set_drop_unencrypted	= wpa_driver_madwifi_set_drop_unencrypted,
	.scan			= wpa_driver_madwifi_scan,
	.get_scan_results	= wpa_driver_wext_get_scan_results,
	.deauthenticate		= wpa_driver_madwifi_deauthenticate,
	.disassociate		= wpa_driver_madwifi_disassociate,
	.associate		= wpa_driver_madwifi_associate,
	.cleanup		= wpa_driver_madwifi_cleanup,
};
