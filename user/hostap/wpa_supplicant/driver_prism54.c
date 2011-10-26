/*
 * WPA Supplicant - driver interaction with Linux Prism54.org driver
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

#include "wireless_copy.h"
#include "common.h"
#include "driver.h"
#include "driver_wext.h"
#include "wpa_supplicant.h"


static int wpa_driver_prism54_set_wpa(const char *ifname, int enabled)
{
	/* FIX */
	printf("wpa_driver_prism54_set_wpa - not yet implemented\n");
	return 0;
}


static int wpa_driver_prism54_set_key(const char *ifname, wpa_alg alg,
				      unsigned char *addr, int key_idx,
				      int set_tx, u8 *seq, size_t seq_len,
				      u8 *key, size_t key_len)
{
	/* FIX */
	printf("wpa_driver_prism54_set_key - not yet implemented\n");
	return 0;
}


static int wpa_driver_prism54_set_countermeasures(const char *ifname,
						 int enabled)
{
	/* FIX */
	printf("wpa_driver_prism54_set_countermeasures - not yet "
	       "implemented\n");
	return 0;
}


static int wpa_driver_prism54_set_drop_unencrypted(const char *ifname,
						  int enabled)
{
	/* FIX */
	printf("wpa_driver_prism54_set_drop_unencrypted - not yet "
	       "implemented\n");
	return 0;
}


static int wpa_driver_prism54_deauthenticate(const char *ifname, u8 *addr,
					     int reason_code)
{
	/* FIX */
	printf("wpa_driver_prism54_deauthenticate - not yet implemented\n");
	return 0;
}


static int wpa_driver_prism54_disassociate(const char *ifname, u8 *addr,
					   int reason_code)
{
	/* FIX */
	printf("wpa_driver_prism54_disassociate - not yet implemented\n");
	return 0;
}


static int wpa_driver_prism54_associate(const char *ifname, const char *bssid,
					const char *ssid, size_t ssid_len,
					int freq,
					const char *wpa_ie, size_t wpa_ie_len,
					wpa_cipher pairwise_suite,
					wpa_cipher group_suite,
					wpa_key_mgmt key_mgmt_suite)
{
	int ret = 0;

	/* FIX: set wpa_ie */
	printf("wpa_driver_prism54_associate - WPA IE setting not yet "
	       "implemented\n");
	if (wpa_driver_wext_set_freq(ifname, freq) < 0)
		ret = -1;
	if (wpa_driver_wext_set_ssid(ifname, ssid, ssid_len) < 0)
		ret = -1;
	if (wpa_driver_wext_set_bssid(ifname, bssid) < 0)
		ret = -1;

	return ret;
}


struct wpa_driver_ops wpa_driver_prism54_ops = {
	.get_bssid = wpa_driver_wext_get_bssid,
	.get_ssid = wpa_driver_wext_get_ssid,
	.set_wpa = wpa_driver_prism54_set_wpa,
	.set_key = wpa_driver_prism54_set_key,
	.events_init = wpa_driver_wext_events_init,
	.events_deinit = wpa_driver_wext_events_deinit,
	.set_countermeasures = wpa_driver_prism54_set_countermeasures,
	.set_drop_unencrypted = wpa_driver_prism54_set_drop_unencrypted,
	.scan = wpa_driver_wext_scan,
	.get_scan_results = wpa_driver_wext_get_scan_results,
	.deauthenticate = wpa_driver_prism54_deauthenticate,
	.disassociate = wpa_driver_prism54_disassociate,
	.associate = wpa_driver_prism54_associate,
};
