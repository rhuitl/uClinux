/*
 * WPA Supplicant
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
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <fcntl.h>

#include "common.h"
#include "wpa.h"
#include "driver.h"
#include "eloop.h"
#include "wpa_supplicant.h"
#include "config.h"
#include "l2_packet.h"
#include "eapol_sm.h"
#include "wpa_supplicant_i.h"
#include "ctrl_iface.h"
#include "pcsc_funcs.h"

static const char *wpa_supplicant_version =
"wpa_supplicant v0.2.5 - Copyright (c) 2003-2004, Jouni Malinen "
"<jkmaline@cc.hut.fi>";

static const char *wpa_supplicant_license =
"This program is free software. You can distribute it and/or modify it\n"
"under the terms of the GNU General Public License version 2.\n"
"\n"
"Alternatively, this software may be distributed under the terms of the\n"
"BSD license. See README and COPYING for more details.\n";

static const char *wpa_supplicant_full_license =
"This program is free software; you can redistribute it and/or modify\n"
"it under the terms of the GNU General Public License version 2 as\n"
"published by the Free Software Foundation.\n"
"\n"
"This program is distributed in the hope that it will be useful,\n"
"but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
"GNU General Public License for more details.\n"
"\n"
"You should have received a copy of the GNU General Public License\n"
"along with this program; if not, write to the Free Software\n"
"Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA\n"
"\n"
"Alternatively, this software may be distributed under the terms of the\n"
"BSD license.\n"
"\n"
"Redistribution and use in source and binary forms, with or without\n"
"modification, are permitted provided that the following conditions are\n"
"met:\n"
"\n"
"1. Redistributions of source code must retain the above copyright\n"
"   notice, this list of conditions and the following disclaimer.\n"
"\n"
"2. Redistributions in binary form must reproduce the above copyright\n"
"   notice, this list of conditions and the following disclaimer in the\n"
"   documentation and/or other materials provided with the distribution.\n"
"\n"
"3. Neither the name(s) of the above-listed copyright holder(s) nor the\n"
"   names of its contributors may be used to endorse or promote products\n"
"   derived from this software without specific prior written permission.\n"
"\n"
"THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS\n"
"\"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT\n"
"LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR\n"
"A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT\n"
"OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,\n"
"SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT\n"
"LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\n"
"DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY\n"
"THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n"
"(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE\n"
"OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n"
"\n";


static void wpa_supplicant_scan_results(struct wpa_supplicant *wpa_s);
static int wpa_supplicant_driver_init(struct wpa_supplicant *wpa_s,
				      int wait_for_interface);


static int wpa_debug_level = MSG_INFO;

void wpa_printf(int level, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (level >= wpa_debug_level) {
		vprintf(fmt, ap);
		printf("\n");
	}
	va_end(ap);
}


void wpa_msg(struct wpa_supplicant *wpa_s, int level, char *fmt, ...)
{
	va_list ap;
	char *buf;
	const int buflen = 2048;
	int len;

	buf = malloc(buflen);
	if (buf == NULL) {
		printf("Failed to allocate message buffer for:\n");
		va_start(ap, fmt);
		vprintf(fmt, ap);
		printf("\n");
		va_end(ap);
		return;
	}
	va_start(ap, fmt);
	len = vsnprintf(buf, buflen, fmt, ap);
	va_end(ap);
	wpa_printf(level, "%s", buf);
	wpa_supplicant_ctrl_iface_send(wpa_s, level, buf, len);
	free(buf);
}


void wpa_hexdump(int level, const char *title, const u8 *buf, size_t len)
{
	size_t i;
	if (level < wpa_debug_level)
		return;
	printf("%s - hexdump(len=%d):", title, len);
	for (i = 0; i < len; i++)
		printf(" %02x", buf[i]);
	printf("\n");
}


void wpa_hexdump_ascii(int level, const char *title, const u8 *buf, size_t len)
{
	int i, llen;
	const u8 *pos = buf;
	const int line_len = 16;

	if (level < wpa_debug_level)
		return;
	printf("%s - hexdump_ascii(len=%d):\n", title, len);
	while (len) {
		llen = len > line_len ? line_len : len;
		printf("    ");
		for (i = 0; i < llen; i++)
			printf(" %02x", pos[i]);
		for (i = llen; i < line_len; i++)
			printf("   ");
		printf("   ");
		for (i = 0; i < llen; i++) {
			if (isprint(pos[i]))
				printf("%c", pos[i]);
			else
				printf("_");
		}
		for (i = llen; i < line_len; i++)
			printf(" ");
		printf("\n");
		pos += llen;
		len -= llen;
	}
}


int wpa_eapol_send(void *ctx, int type, u8 *buf, size_t len)
{
	struct wpa_supplicant *wpa_s = ctx;
	u8 *msg, *dst, bssid[ETH_ALEN];
	size_t msglen;
	struct l2_ethhdr *ethhdr;
	struct ieee802_1x_hdr *hdr;
	int res;

	/* TODO: could add l2_packet_sendmsg that allows fragments to avoid
	 * extra copy here */

	if (wpa_s->key_mgmt == WPA_KEY_MGMT_PSK ||
	    wpa_s->key_mgmt == WPA_KEY_MGMT_NONE) {
		/* Current SSID is not using IEEE 802.1X/EAP, so drop possible
		 * EAPOL frames (mainly, EAPOL-Start) from EAPOL state
		 * machines. */
		wpa_printf(MSG_DEBUG, "WPA: drop TX EAPOL in non-IEEE 802.1X "
			   "mode (type=%d len=%d)", type, len);
		return -1;
	}

	if (wpa_s->pmksa && type == IEEE802_1X_TYPE_EAPOL_START) {
		/* Trying to use PMKSA caching - do not send EAPOL-Start frames
		 * since they will trigger full EAPOL authentication. */
		wpa_printf(MSG_DEBUG, "RSN: PMKSA caching - do not send "
			   "EAPOL-Start");
		return -1;
	}

	if (memcmp(wpa_s->bssid, "\x00\x00\x00\x00\x00\x00", ETH_ALEN) == 0) {
		wpa_printf(MSG_DEBUG, "BSSID not set when trying to send an "
			   "EAPOL frame");
		if (wpa_s->driver->get_bssid(wpa_s->ifname, bssid) == 0 &&
		    memcmp(bssid, "\x00\x00\x00\x00\x00\x00", ETH_ALEN) != 0) {
			dst = bssid;
			wpa_printf(MSG_DEBUG, "Using current BSSID " MACSTR
				   " from the driver as the EAPOL destination",
				   MAC2STR(dst));
		} else {
			dst = wpa_s->last_eapol_src;
			wpa_printf(MSG_DEBUG, "Using the source address of the"
				   " last received EAPOL frame " MACSTR " as "
				   "the EAPOL destination",
				   MAC2STR(dst));
		}
	} else {
		/* BSSID was already set (from (Re)Assoc event, so use it as
		 * the EAPOL destination. */
		dst = wpa_s->bssid;
	}

	msglen = sizeof(*ethhdr) + sizeof(*hdr) + len;
	msg = malloc(msglen);
	if (msg == NULL)
		return -1;

	ethhdr = (struct l2_ethhdr *) msg;
	memcpy(ethhdr->h_dest, dst, ETH_ALEN);
	memcpy(ethhdr->h_source, wpa_s->own_addr, ETH_ALEN);
	ethhdr->h_proto = htons(ETH_P_EAPOL);

	hdr = (struct ieee802_1x_hdr *) (ethhdr + 1);
	hdr->version = wpa_s->conf->eapol_version;
	hdr->type = type;
	hdr->length = htons(len);

	memcpy((u8 *) (hdr + 1), buf, len);

	wpa_hexdump(MSG_MSGDUMP, "TX EAPOL", msg, msglen);
	res = l2_packet_send(wpa_s->l2, msg, msglen);
	free(msg);
	return res;
}


int wpa_eapol_send_preauth(void *ctx, int type, u8 *buf, size_t len)
{
	struct wpa_supplicant *wpa_s = ctx;
	u8 *msg;
	size_t msglen;
	struct l2_ethhdr *ethhdr;
	struct ieee802_1x_hdr *hdr;
	int res;

	/* TODO: could add l2_packet_sendmsg that allows fragments to avoid
	 * extra copy here */

	if (wpa_s->l2_preauth == NULL)
		return -1;

	msglen = sizeof(*ethhdr) + sizeof(*hdr) + len;
	msg = malloc(msglen);
	if (msg == NULL)
		return -1;

	ethhdr = (struct l2_ethhdr *) msg;
	memcpy(ethhdr->h_dest, wpa_s->preauth_bssid, ETH_ALEN);
	memcpy(ethhdr->h_source, wpa_s->own_addr, ETH_ALEN);
	ethhdr->h_proto = htons(ETH_P_RSN_PREAUTH);

	hdr = (struct ieee802_1x_hdr *) (ethhdr + 1);
	hdr->version = wpa_s->conf->eapol_version;
	hdr->type = type;
	hdr->length = htons(len);

	memcpy((u8 *) (hdr + 1), buf, len);

	wpa_hexdump(MSG_MSGDUMP, "TX EAPOL (preauth)", msg, msglen);
	res = l2_packet_send(wpa_s->l2_preauth, msg, msglen);
	free(msg);
	return res;
}


/**
 * wpa_eapol_set_wep_key - set WEP key for the driver
 * @ctx: pointer to wpa_supplicant data
 * @unicast: 1 = individual unicast key, 0 = broadcast key
 * @keyidx: WEP key index (0..3)
 * @key: pointer to key data
 * @keylen: key length in bytes
 *
 * Returns 0 on success or < 0 on error.
 */
static int wpa_eapol_set_wep_key(void *ctx, int unicast, int keyidx,
				 u8 *key, size_t keylen)
{
	struct wpa_supplicant *wpa_s = ctx;
	if (wpa_s == NULL || wpa_s->driver == NULL ||
	    wpa_s->driver->set_key == NULL)
		return -1;

	return wpa_s->driver->set_key(wpa_s->ifname, WPA_ALG_WEP,
				      unicast ? wpa_s->bssid :
				      (u8 *) "\xff\xff\xff\xff\xff\xff",
				      keyidx, unicast, "", 0, key, keylen);
}


void wpa_supplicant_notify_eapol_done(void *ctx)
{
	struct wpa_supplicant *wpa_s = ctx;
	wpa_msg(wpa_s, MSG_DEBUG, "WPA: EAPOL processing complete");
	eloop_cancel_timeout(wpa_supplicant_scan, wpa_s, NULL);
	wpa_supplicant_cancel_auth_timeout(wpa_s);
}


const char * wpa_ssid_txt(u8 *ssid, size_t ssid_len)
{
	static char ssid_txt[MAX_SSID_LEN + 1];
	char *pos;

	if (ssid_len > MAX_SSID_LEN)
		ssid_len = MAX_SSID_LEN;
	memcpy(ssid_txt, ssid, ssid_len);
	ssid_txt[ssid_len] = '\0';
	for (pos = ssid_txt; *pos != '\0'; pos++) {
		if ((u8) *pos < 32 || (u8) *pos >= 127)
			*pos = '_';
	}
	return ssid_txt;
}


void wpa_supplicant_req_scan(struct wpa_supplicant *wpa_s, int sec, int usec)
{
	wpa_msg(wpa_s, MSG_DEBUG, "Setting scan request: %d sec %d usec",
		sec, usec);
	eloop_cancel_timeout(wpa_supplicant_scan, wpa_s, NULL);
	eloop_register_timeout(sec, usec, wpa_supplicant_scan, wpa_s, NULL);
}


void wpa_supplicant_cancel_scan(struct wpa_supplicant *wpa_s)
{
	wpa_msg(wpa_s, MSG_DEBUG, "Cancelling scan request");
	eloop_cancel_timeout(wpa_supplicant_scan, wpa_s, NULL);
}


static void wpa_supplicant_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	wpa_msg(wpa_s, MSG_INFO, "Authentication with " MACSTR " timed out.",
		MAC2STR(wpa_s->bssid));
	wpa_s->reassociate = 1;
	wpa_supplicant_req_scan(wpa_s, 0, 0);
}


void wpa_supplicant_req_auth_timeout(struct wpa_supplicant *wpa_s,
				     int sec, int usec)
{
	wpa_msg(wpa_s, MSG_DEBUG, "Setting authentication timeout: %d sec "
		"%d usec", sec, usec);
	eloop_cancel_timeout(wpa_supplicant_timeout, wpa_s, NULL);
	eloop_register_timeout(sec, usec, wpa_supplicant_timeout, wpa_s, NULL);
}


void wpa_supplicant_cancel_auth_timeout(struct wpa_supplicant *wpa_s)
{
	wpa_msg(wpa_s, MSG_DEBUG, "Cancelling authentication timeout");
	eloop_cancel_timeout(wpa_supplicant_timeout, wpa_s, NULL);
}


static void wpa_supplicant_initiate_eapol(struct wpa_supplicant *wpa_s)
{
	struct eapol_config eapol_conf;
	struct wpa_ssid *ssid = wpa_s->current_ssid;

	if (wpa_s->key_mgmt == WPA_KEY_MGMT_PSK) {
		eapol_sm_notify_eap_success(wpa_s->eapol, FALSE);
		eapol_sm_notify_eap_fail(wpa_s->eapol, FALSE);
	}
	if (wpa_s->key_mgmt == WPA_KEY_MGMT_NONE)
		eapol_sm_notify_portControl(wpa_s->eapol, ForceAuthorized);
	else
		eapol_sm_notify_portControl(wpa_s->eapol, Auto);

	memset(&eapol_conf, 0, sizeof(eapol_conf));
	if (wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X_NO_WPA) {
		eapol_conf.accept_802_1x_keys = 1;
		eapol_conf.required_keys = 0;
		if (ssid->eapol_flags & EAPOL_FLAG_REQUIRE_KEY_UNICAST) {
			eapol_conf.required_keys |= EAPOL_REQUIRE_KEY_UNICAST;
		}
		if (ssid->eapol_flags & EAPOL_FLAG_REQUIRE_KEY_BROADCAST) {
			eapol_conf.required_keys |=
				EAPOL_REQUIRE_KEY_BROADCAST;
		}
	}
	eapol_sm_notify_config(wpa_s->eapol, ssid, &eapol_conf);
}


static void wpa_supplicant_set_non_wpa_policy(struct wpa_supplicant *wpa_s,
					      struct wpa_ssid *ssid)
{
	int i;

	if (ssid->key_mgmt & WPA_KEY_MGMT_IEEE8021X_NO_WPA)
		wpa_s->key_mgmt = WPA_KEY_MGMT_IEEE8021X_NO_WPA;
	else
		wpa_s->key_mgmt = WPA_KEY_MGMT_NONE;
	free(wpa_s->ap_wpa_ie);
	wpa_s->ap_wpa_ie = NULL;
	wpa_s->ap_wpa_ie_len = 0;
	free(wpa_s->assoc_wpa_ie);
	wpa_s->assoc_wpa_ie = NULL;
	wpa_s->assoc_wpa_ie_len = 0;
	wpa_s->pairwise_cipher = WPA_CIPHER_NONE;
	wpa_s->group_cipher = WPA_CIPHER_NONE;

	for (i = 0; i < NUM_WEP_KEYS; i++) {
		if (ssid->wep_key_len[i] > 5) {
			wpa_s->pairwise_cipher = WPA_CIPHER_WEP104;
			wpa_s->group_cipher = WPA_CIPHER_WEP104;
			break;
		} else if (ssid->wep_key_len[i] > 0) {
			wpa_s->pairwise_cipher = WPA_CIPHER_WEP40;
			wpa_s->group_cipher = WPA_CIPHER_WEP40;
			break;
		}
	}

	wpa_s->cur_pmksa = FALSE;
}


static int wpa_supplicant_select_config(struct wpa_supplicant *wpa_s)
{
	struct wpa_ssid *ssid;

	if (wpa_s->conf->ap_scan)
		return 0;

	ssid = wpa_supplicant_get_ssid(wpa_s);
	if (ssid == NULL) {
		wpa_printf(MSG_INFO, "No network configuration found for the "
			   "current AP");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "Network configuration found for the current "
		   "AP");
	wpa_supplicant_set_non_wpa_policy(wpa_s, ssid);

	wpa_s->current_ssid = ssid;
	wpa_supplicant_initiate_eapol(wpa_s);

	return 0;
}


static void wpa_supplicant_cleanup(struct wpa_supplicant *wpa_s)
{
	scard_deinit(wpa_s->scard);
	wpa_s->scard = NULL;
	eapol_sm_register_scard_ctx(wpa_s->eapol, NULL);
	l2_packet_deinit(wpa_s->l2);
	wpa_s->l2 = NULL;

	if (wpa_s->dot1x_s > -1) {
		close(wpa_s->dot1x_s);
		wpa_s->dot1x_s = -1;
	}

	wpa_supplicant_ctrl_iface_deinit(wpa_s);
	if (wpa_s->conf != NULL) {
		wpa_config_free(wpa_s->conf);
		wpa_s->conf = NULL;
	}

	free(wpa_s->assoc_wpa_ie);
	wpa_s->assoc_wpa_ie = NULL;

	free(wpa_s->ap_wpa_ie);
	wpa_s->ap_wpa_ie = NULL;

	free(wpa_s->confname);
	wpa_s->confname = NULL;

	eapol_sm_deinit(wpa_s->eapol);
	wpa_s->eapol = NULL;

	rsn_preauth_deinit(wpa_s);

	pmksa_candidate_free(wpa_s);
	pmksa_cache_free(wpa_s);
}


static void wpa_clear_keys(struct wpa_supplicant *wpa_s, u8 *addr)
{
	wpa_s->driver->set_key(wpa_s->ifname, WPA_ALG_NONE,
			       "\xff\xff\xff\xff\xff\xff", 0, 0, NULL,
			       0, NULL, 0);
	wpa_s->driver->set_key(wpa_s->ifname, WPA_ALG_NONE,
			       "\xff\xff\xff\xff\xff\xff", 1, 0, NULL,
			       0, NULL, 0);
	wpa_s->driver->set_key(wpa_s->ifname, WPA_ALG_NONE,
			       "\xff\xff\xff\xff\xff\xff", 2, 0, NULL,
			       0, NULL, 0);
	wpa_s->driver->set_key(wpa_s->ifname, WPA_ALG_NONE,
			       "\xff\xff\xff\xff\xff\xff", 3, 0, NULL,
			       0, NULL, 0);
	if (addr) {
		wpa_s->driver->set_key(wpa_s->ifname, WPA_ALG_NONE, addr,
				       0, 0, NULL, 0, NULL, 0);
	}
}


static void wpa_supplicant_stop_countermeasures(void *eloop_ctx,
						void *sock_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;

	if (wpa_s->countermeasures) {
		wpa_s->countermeasures = 0;
		wpa_s->driver->set_countermeasures(wpa_s->ifname, 0);
		wpa_msg(wpa_s, MSG_INFO, "WPA: TKIP countermeasures stopped");
		wpa_supplicant_req_scan(wpa_s, 0, 0);
	}
}


static void wpa_supplicant_mark_disassoc(struct wpa_supplicant *wpa_s)
{
	wpa_s->wpa_state = WPA_DISCONNECTED;
	memset(wpa_s->bssid, 0, ETH_ALEN);
	eapol_sm_notify_portEnabled(wpa_s->eapol, FALSE);
	eapol_sm_notify_portValid(wpa_s->eapol, FALSE);
	if (wpa_s->key_mgmt == WPA_KEY_MGMT_PSK)
		eapol_sm_notify_eap_success(wpa_s->eapol, FALSE);
}


void wpa_supplicant_event(struct wpa_supplicant *wpa_s, wpa_event_type event,
			  union wpa_event_data *data)
{
	int pairwise, l, len;
	time_t now;
	u8 bssid[ETH_ALEN], *p;

	switch (event) {
	case EVENT_ASSOC:
		wpa_s->wpa_state = WPA_ASSOCIATED;
		wpa_printf(MSG_DEBUG, "Association event - clear replay "
			   "counter");
		memset(wpa_s->rx_replay_counter, 0, WPA_REPLAY_COUNTER_LEN);
		wpa_s->rx_replay_counter_set = 0;
		wpa_s->renew_snonce = 1;
		if (wpa_s->driver->get_bssid(wpa_s->ifname, bssid) >= 0 &&
		    memcmp(bssid, wpa_s->bssid, ETH_ALEN) != 0) {
			wpa_msg(wpa_s, MSG_DEBUG, "Associated to a new BSS: "
				"BSSID=" MACSTR, MAC2STR(bssid));
			memcpy(wpa_s->bssid, bssid, ETH_ALEN);
			if (wpa_s->key_mgmt != WPA_KEY_MGMT_NONE)
				wpa_clear_keys(wpa_s, bssid);
			wpa_supplicant_select_config(wpa_s);
		}
		eapol_sm_notify_portValid(wpa_s->eapol, FALSE);
		if (wpa_s->key_mgmt == WPA_KEY_MGMT_PSK)
			eapol_sm_notify_eap_success(wpa_s->eapol, FALSE);
		/* 802.1X::portControl = Auto */
		eapol_sm_notify_portEnabled(wpa_s->eapol, TRUE);
		wpa_s->eapol_received = 0;
		if (wpa_s->key_mgmt == WPA_KEY_MGMT_NONE) {
			wpa_supplicant_cancel_auth_timeout(wpa_s);
		} else {
			/* Timeout for receiving the first EAPOL packet */
			wpa_supplicant_req_auth_timeout(wpa_s, 10, 0);
		}
		break;
	case EVENT_DISASSOC:
		if (wpa_s->wpa_state >= WPA_ASSOCIATED)
			wpa_supplicant_req_scan(wpa_s, 0, 100000);
		wpa_supplicant_mark_disassoc(wpa_s);
		wpa_msg(wpa_s, MSG_DEBUG, "Disconnect event - remove keys");
		if (wpa_s->key_mgmt != WPA_KEY_MGMT_NONE)
			wpa_clear_keys(wpa_s, wpa_s->bssid);
		break;
	case EVENT_MICHAEL_MIC_FAILURE:
		wpa_msg(wpa_s, MSG_WARNING, "Michael MIC failure detected");
		pairwise = (data && data->michael_mic_failure.unicast);
		wpa_supplicant_key_request(wpa_s, 1, pairwise);
		time(&now);
		if (wpa_s->last_michael_mic_error &&
		    now - wpa_s->last_michael_mic_error <= 60) {
			/* initialize countermeasures */
			wpa_s->countermeasures = 1;
			wpa_msg(wpa_s, MSG_WARNING, "TKIP countermeasures "
				"started");

			/* Need to wait for completion of request frame. We do
			 * not get any callback for the message completion, so
			 * just wait a short while and hope for the best. */
			usleep(10000);

			wpa_s->driver->set_countermeasures(wpa_s->ifname, 1);
			wpa_supplicant_deauthenticate(
				wpa_s, REASON_MICHAEL_MIC_FAILURE);
			eloop_cancel_timeout(
				wpa_supplicant_stop_countermeasures, wpa_s,
				NULL);
			eloop_register_timeout(
				60, 0, wpa_supplicant_stop_countermeasures,
				wpa_s, NULL);
			/* TODO: mark the AP rejected for 60 second. STA is
			 * allowed to associate with another AP.. */
		}
		wpa_s->last_michael_mic_error = now;
		break;
	case EVENT_SCAN_RESULTS:
		wpa_supplicant_scan_results(wpa_s);
		break;
	case EVENT_ASSOCINFO:
		wpa_printf(MSG_DEBUG, "Association info event");
		wpa_hexdump(MSG_DEBUG, "req_ies", data->assoc_info.req_ies,
			    data->assoc_info.req_ies_len);
		if (wpa_s->assoc_wpa_ie) {
			free(wpa_s->assoc_wpa_ie);
			wpa_s->assoc_wpa_ie = NULL;
			wpa_s->assoc_wpa_ie_len = 0;
		}

		p = data->assoc_info.req_ies;
		l = data->assoc_info.req_ies_len;

		/* Go through the IEs and make a copy of the WPA/RSN IE, if
		 * present. */
		while (l >= 2) {
			len = p[1] + 2;
			if (len > l) {
				wpa_hexdump(MSG_DEBUG, "Truncated IE in "
					    "assoc_info", p, l);
				break;
			}
			if ((p[0] == GENERIC_INFO_ELEM && p[1] >= 6 &&
			     (memcmp(&p[2], "\x00\x50\xF2\x01\x01\x00", 6) ==
			      0)) ||
			    (p[0] == RSN_INFO_ELEM && p[1] >= 2)) {
				wpa_s->assoc_wpa_ie = malloc(len);
				if (wpa_s->assoc_wpa_ie == NULL)
					break;
				wpa_s->assoc_wpa_ie_len = len;
				memcpy(wpa_s->assoc_wpa_ie, p, len);
				wpa_hexdump(MSG_DEBUG, "assoc_wpa_ie",
					    wpa_s->assoc_wpa_ie,
					    wpa_s->assoc_wpa_ie_len);
				break;
			}
			l -= len;
			p += len;
		}
		break;
	case EVENT_INTERFACE_STATUS:
		if (strcmp(wpa_s->ifname, data->interface_status.ifname) != 0)
			break;
		switch (data->interface_status.ievent) {
		case EVENT_INTERFACE_ADDED:
			if (!wpa_s->interface_removed)
				break;
			wpa_s->interface_removed = 0;
			wpa_printf(MSG_DEBUG, "Configured interface was "
				   "added.");
			if (wpa_supplicant_driver_init(wpa_s, 1) < 0) {
				wpa_printf(MSG_INFO, "Failed to initialize "
					   "the driver after interface was "
					   "added.");
			}
			break;
		case EVENT_INTERFACE_REMOVED:
			wpa_printf(MSG_DEBUG, "Configured interface was "
				   "removed.");
			wpa_s->interface_removed = 1;
			wpa_supplicant_mark_disassoc(wpa_s);
			l2_packet_deinit(wpa_s->l2);
			break;
		}
		break;
	default:
		wpa_printf(MSG_INFO, "Unknown event %d", event);
		break;
	}
}


static void wpa_supplicant_terminate(int sig, void *eloop_ctx,
				     void *signal_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	wpa_msg(wpa_s, MSG_INFO, "Signal %d received - terminating", sig);
	eloop_terminate();
}


int wpa_supplicant_reload_configuration(struct wpa_supplicant *wpa_s)
{
	struct wpa_config *conf;
	int reconf_ctrl;
	if (wpa_s->confname == NULL)
		return -1;
	conf = wpa_config_read(wpa_s->confname);
	if (conf == NULL) {
		wpa_msg(wpa_s, MSG_ERROR, "Failed to parse the configuration "
			"file '%s' - exiting", wpa_s->confname);
		return -1;
	}

	reconf_ctrl = !!conf->ctrl_interface != !!wpa_s->conf->ctrl_interface
		|| (conf->ctrl_interface && wpa_s->conf->ctrl_interface &&
		    strcmp(conf->ctrl_interface, wpa_s->conf->ctrl_interface)
		    != 0);

	if (reconf_ctrl)
		wpa_supplicant_ctrl_iface_deinit(wpa_s);

	wpa_s->current_ssid = NULL;
	eapol_sm_notify_config(wpa_s->eapol, NULL, NULL);
	rsn_preauth_deinit(wpa_s);
	wpa_config_free(wpa_s->conf);
	wpa_s->conf = conf;
	if (reconf_ctrl)
		wpa_supplicant_ctrl_iface_init(wpa_s);
	wpa_s->reassociate = 1;
	wpa_supplicant_req_scan(wpa_s, 0, 0);
	wpa_msg(wpa_s, MSG_DEBUG, "Reconfiguration completed");
	return 0;
}


static void wpa_supplicant_reconfig(int sig, void *eloop_ctx,
				    void *signal_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	wpa_printf(MSG_DEBUG, "Signal %d received - reconfiguring", sig);
	if (wpa_supplicant_reload_configuration(wpa_s) < 0) {
		eloop_terminate();
	}
}


static void wpa_supplicant_gen_assoc_event(struct wpa_supplicant *wpa_s)
{
	struct wpa_ssid *ssid;
	union wpa_event_data data;

	ssid = wpa_supplicant_get_ssid(wpa_s);
	if (ssid == NULL)
		return;

	wpa_printf(MSG_DEBUG, "Already associated with a configured network - "
		   "generating associated event");
	memset(&data, 0, sizeof(data));
	wpa_supplicant_event(wpa_s, EVENT_ASSOC, &data);
}


void wpa_supplicant_scan(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	struct wpa_ssid *ssid;

	if (!wpa_s->conf->ap_scan) {
		wpa_supplicant_gen_assoc_event(wpa_s);
		return;
	}

	if (wpa_s->wpa_state == WPA_DISCONNECTED)
		wpa_s->wpa_state = WPA_SCANNING;

	ssid = wpa_s->conf->ssid;
	if (wpa_s->prev_scan_ssid != BROADCAST_SSID_SCAN) {
		while (ssid) {
			if (ssid == wpa_s->prev_scan_ssid) {
				ssid = ssid->next;
				break;
			}
			ssid = ssid->next;
		}
	}
	while (ssid) {
		if (ssid->scan_ssid)
			break;
		ssid = ssid->next;
	}

	wpa_printf(MSG_DEBUG, "Starting AP scan (%s SSID)",
		   ssid ? "specific": "broadcast");
	if (ssid) {
		wpa_hexdump_ascii(MSG_DEBUG, "Scan SSID",
				  ssid->ssid, ssid->ssid_len);
		wpa_s->prev_scan_ssid = ssid;
	} else
		wpa_s->prev_scan_ssid = BROADCAST_SSID_SCAN;

	if (wpa_s->driver->scan(wpa_s->ifname, wpa_s,
				ssid ? ssid->ssid : NULL,
				ssid ? ssid->ssid_len : 0)) {
		wpa_printf(MSG_WARNING, "Failed to initiate AP scan.");
	}
}


static wpa_cipher cipher_suite2driver(int cipher)
{
	switch (cipher) {
	case WPA_CIPHER_NONE:
		return CIPHER_NONE;
	case WPA_CIPHER_WEP40:
		return CIPHER_WEP40;
	case WPA_CIPHER_WEP104:
		return CIPHER_WEP104;
	case WPA_CIPHER_CCMP:
		return CIPHER_CCMP;
	case WPA_CIPHER_TKIP:
	default:
		return CIPHER_TKIP;
	}
}


static wpa_key_mgmt key_mgmt2driver(int key_mgmt)
{
	switch (key_mgmt) {
	case WPA_KEY_MGMT_NONE:
	case WPA_KEY_MGMT_IEEE8021X_NO_WPA:
		return KEY_MGMT_NONE;
	case WPA_KEY_MGMT_IEEE8021X:
		return KEY_MGMT_802_1X;
	case WPA_KEY_MGMT_PSK:
	default:
		return KEY_MGMT_PSK;
	}
}


static int wpa_supplicant_set_suites(struct wpa_supplicant *wpa_s,
				     struct wpa_scan_result *bss,
				     struct wpa_ssid *ssid,
				     u8 *wpa_ie, int *wpa_ie_len)
{
	struct wpa_ie_data ie;
	int sel, proto;
	u8 *ap_ie;
	size_t ap_ie_len;

	if (bss->rsn_ie_len && (ssid->proto & WPA_PROTO_RSN)) {
		wpa_msg(wpa_s, MSG_DEBUG, "RSN: using IEEE 802.11i/D9.0");
		proto = WPA_PROTO_RSN;
		ap_ie = bss->rsn_ie;
		ap_ie_len = bss->rsn_ie_len;
	} else {
		wpa_msg(wpa_s, MSG_DEBUG, "WPA: using IEEE 802.11i/D3.0");
		proto = WPA_PROTO_WPA;
		ap_ie = bss->wpa_ie;
		ap_ie_len = bss->wpa_ie_len;
	}

	if (wpa_parse_wpa_ie(wpa_s, ap_ie, ap_ie_len, &ie)) {
		wpa_msg(wpa_s, MSG_WARNING, "WPA: Failed to parse WPA IE for "
			"the selected BSS.");
		return -1;
	}

	wpa_s->proto = proto;
	free(wpa_s->ap_wpa_ie);
	wpa_s->ap_wpa_ie = malloc(ap_ie_len);
	memcpy(wpa_s->ap_wpa_ie, ap_ie, ap_ie_len);
	wpa_s->ap_wpa_ie_len = ap_ie_len;

	sel = ie.group_cipher & ssid->group_cipher;
	if (sel & WPA_CIPHER_CCMP) {
		wpa_s->group_cipher = WPA_CIPHER_CCMP;
	} else if (sel & WPA_CIPHER_TKIP) {
		wpa_s->group_cipher = WPA_CIPHER_TKIP;
	} else if (sel & WPA_CIPHER_WEP104) {
		wpa_s->group_cipher = WPA_CIPHER_WEP104;
	} else if (sel & WPA_CIPHER_WEP40) {
		wpa_s->group_cipher = WPA_CIPHER_WEP40;
	} else {
		wpa_printf(MSG_WARNING, "WPA: Failed to select group cipher.");
		return -1;
	}

	sel = ie.pairwise_cipher & ssid->pairwise_cipher;
	if (sel & WPA_CIPHER_CCMP) {
		wpa_s->pairwise_cipher = WPA_CIPHER_CCMP;
	} else if (sel & WPA_CIPHER_TKIP) {
		wpa_s->pairwise_cipher = WPA_CIPHER_TKIP;
	} else if (sel & WPA_CIPHER_NONE) {
		wpa_s->pairwise_cipher = WPA_CIPHER_NONE;
	} else {
		wpa_printf(MSG_WARNING, "WPA: Failed to select pairwise "
			   "cipher.");
		return -1;
	}

	sel = ie.key_mgmt & ssid->key_mgmt;
	if (sel & WPA_KEY_MGMT_IEEE8021X) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_IEEE8021X;
	} else if (sel & WPA_KEY_MGMT_PSK) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_PSK;
	} else {
		wpa_printf(MSG_WARNING, "WPA: Failed to select authenticated "
			   "key management type.");
		return -1;
	}


	/* Starting new association, so clear the possibly used WPA IE from the
	 * previous association. */
	free(wpa_s->assoc_wpa_ie);
	wpa_s->assoc_wpa_ie = NULL;
	wpa_s->assoc_wpa_ie_len = 0;

	*wpa_ie_len = wpa_gen_wpa_ie(wpa_s, wpa_ie);
	if (*wpa_ie_len < 0) {
		wpa_printf(MSG_WARNING, "WPA: Failed to generate WPA IE.");
		return -1;
	}
	wpa_hexdump(MSG_DEBUG, "WPA: Own WPA IE", wpa_ie, *wpa_ie_len);

	if (ssid->key_mgmt & WPA_KEY_MGMT_PSK)
		memcpy(wpa_s->pmk, ssid->psk, PMK_LEN);
	else if (wpa_s->cur_pmksa)
		memcpy(wpa_s->pmk, wpa_s->cur_pmksa->pmk, PMK_LEN);
	else {
		memset(wpa_s->pmk, 0, PMK_LEN);
		wpa_s->ext_pmk_received = 0;
	}

	return 0;
}


static void wpa_supplicant_associate(struct wpa_supplicant *wpa_s,
				     struct wpa_scan_result *bss,
				     struct wpa_ssid *ssid)
{
	u8 wpa_ie[80];
	int wpa_ie_len;
	int use_crypt;
	int algs = AUTH_ALG_OPEN_SYSTEM;

	wpa_s->reassociate = 0;
	wpa_msg(wpa_s, MSG_INFO, "Trying to associate with " MACSTR
		" (SSID='%s' freq=%d MHz)", MAC2STR(bss->bssid),
		wpa_ssid_txt(ssid->ssid, ssid->ssid_len), bss->freq);
	wpa_supplicant_cancel_scan(wpa_s);

	if (ssid->key_mgmt & WPA_KEY_MGMT_IEEE8021X_NO_WPA) {
		if (ssid->leap) {
			if (ssid->non_leap == 0)
				algs = AUTH_ALG_LEAP;
			else
				algs |= AUTH_ALG_LEAP;
		}
	}
	if (wpa_s->driver->set_auth_alg)
		wpa_s->driver->set_auth_alg(wpa_s->ifname, algs);

	if ((bss->wpa_ie_len || bss->rsn_ie_len) &&
	    (ssid->key_mgmt & (WPA_KEY_MGMT_IEEE8021X | WPA_KEY_MGMT_PSK))) {
		wpa_s->cur_pmksa = pmksa_cache_get(wpa_s, bss->bssid, NULL);
		if (wpa_s->cur_pmksa) {
			wpa_hexdump(MSG_DEBUG, "RSN: PMKID",
				    wpa_s->cur_pmksa->pmkid, PMKID_LEN);
			eapol_sm_notify_pmkid_attempt(wpa_s->eapol);
		}
		if (wpa_supplicant_set_suites(wpa_s, bss, ssid,
					      wpa_ie, &wpa_ie_len)) {
			wpa_printf(MSG_WARNING, "WPA: Failed to set WPA key "
				   "management and encryption suites");
			return;
		}
	} else {
		wpa_supplicant_set_non_wpa_policy(wpa_s, ssid);
		wpa_ie_len = 0;
	}

	wpa_clear_keys(wpa_s, bss->bssid);
	use_crypt = 1;
	if (wpa_s->key_mgmt == WPA_KEY_MGMT_NONE) {
		int i;
		use_crypt = 0;
		for (i = 0; i < NUM_WEP_KEYS; i++) {
			if (ssid->wep_key_len[i]) {
				use_crypt = 1;
				wpa_eapol_set_wep_key(wpa_s,
						      i == ssid->wep_tx_keyidx,
						      i, ssid->wep_key[i],
						      ssid->wep_key_len[i]);
			}
		}
	} else if (wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X_NO_WPA) {
		if ((ssid->eapol_flags &
		     (EAPOL_FLAG_REQUIRE_KEY_UNICAST |
		      EAPOL_FLAG_REQUIRE_KEY_BROADCAST)) == 0)
			use_crypt = 0;
	}
	wpa_s->driver->set_drop_unencrypted(wpa_s->ifname, use_crypt);
	wpa_s->wpa_state = WPA_ASSOCIATING;
	wpa_s->driver->associate(wpa_s->ifname, bss->bssid,
				 bss->ssid, bss->ssid_len, bss->freq,
				 wpa_ie, wpa_ie_len,
				 cipher_suite2driver(wpa_s->pairwise_cipher),
				 cipher_suite2driver(wpa_s->group_cipher),
				 key_mgmt2driver(wpa_s->key_mgmt));

	/* Timeout for IEEE 802.11 authentication and association */
	wpa_supplicant_req_auth_timeout(wpa_s, 5, 0);

	wpa_s->current_ssid = ssid;
	wpa_supplicant_initiate_eapol(wpa_s);
}


void wpa_supplicant_disassociate(struct wpa_supplicant *wpa_s,
				 int reason_code)
{
	u8 *addr = NULL;
	wpa_s->wpa_state = WPA_DISCONNECTED;
	if (memcmp(wpa_s->bssid, "\x00\x00\x00\x00\x00\x00", ETH_ALEN) != 0) {
		wpa_s->driver->disassociate(wpa_s->ifname, wpa_s->bssid,
					    reason_code);
		addr = wpa_s->bssid;
	}
	wpa_clear_keys(wpa_s, addr);
	wpa_s->current_ssid = NULL;
	eapol_sm_notify_config(wpa_s->eapol, NULL, NULL);
	eapol_sm_notify_portEnabled(wpa_s->eapol, FALSE);
	eapol_sm_notify_portValid(wpa_s->eapol, FALSE);
}


void wpa_supplicant_deauthenticate(struct wpa_supplicant *wpa_s,
				   int reason_code)
{
	u8 *addr = NULL;
	wpa_s->wpa_state = WPA_DISCONNECTED;
	if (memcmp(wpa_s->bssid, "\x00\x00\x00\x00\x00\x00", ETH_ALEN) != 0) {
		wpa_s->driver->deauthenticate(wpa_s->ifname, wpa_s->bssid,
					      reason_code);
		addr = wpa_s->bssid;
	}
	wpa_clear_keys(wpa_s, addr);
	wpa_s->current_ssid = NULL;
	eapol_sm_notify_config(wpa_s->eapol, NULL, NULL);
	eapol_sm_notify_portEnabled(wpa_s->eapol, FALSE);
	eapol_sm_notify_portValid(wpa_s->eapol, FALSE);
}


static void wpa_supplicant_imsi_identity(struct wpa_supplicant *wpa_s,
					 struct wpa_ssid *ssid)
{
	if (ssid->identity == NULL && wpa_s->imsi) {
		ssid->identity = malloc(1 + wpa_s->imsi_len);
		if (ssid->identity) {
			ssid->identity[0] = '1';
			memcpy(ssid->identity + 1, wpa_s->imsi,
			       wpa_s->imsi_len);
			ssid->identity_len = 1 + wpa_s->imsi_len;
			wpa_hexdump_ascii(MSG_DEBUG, "permanent identity from "
					  "IMSI", ssid->identity,
					  ssid->identity_len);
		}
	}
}


static void wpa_supplicant_scard_init(struct wpa_supplicant *wpa_s,
				      struct wpa_ssid *ssid)
{
	char buf[100];
	size_t len;

	if (ssid->pcsc == NULL)
		return;
	if (wpa_s->scard != NULL) {
		wpa_supplicant_imsi_identity(wpa_s, ssid);
		return;
	}
	wpa_printf(MSG_DEBUG, "Selected network is configured to use SIM - "
		   "initialize PCSC");
	wpa_s->scard = scard_init(SCARD_TRY_BOTH, ssid->pin);
	if (wpa_s->scard == NULL) {
		wpa_printf(MSG_WARNING, "Failed to initialize SIM "
			   "(pcsc-lite)");
		/* TODO: what to do here? */
		return;
	}
	eapol_sm_register_scard_ctx(wpa_s->eapol, wpa_s->scard);

	len = sizeof(buf);
	if (scard_get_imsi(wpa_s->scard, buf, &len)) {
		wpa_printf(MSG_WARNING, "Failed to get IMSI from SIM");
		/* TODO: what to do here? */
		return;
	}

	wpa_hexdump_ascii(MSG_DEBUG, "IMSI", buf, len);
	free(wpa_s->imsi);
	wpa_s->imsi = malloc(len);
	if (wpa_s->imsi) {
		wpa_s->imsi = buf;
		wpa_s->imsi_len = len;
		wpa_supplicant_imsi_identity(wpa_s, ssid);
	}
}


static struct wpa_scan_result *
wpa_supplicant_select_bss(struct wpa_supplicant *wpa_s, struct wpa_ssid *group,
			  struct wpa_scan_result *results, int num,
			  struct wpa_ssid **selected_ssid)
{
	struct wpa_ssid *ssid;
	struct wpa_scan_result *bss, *selected = NULL;
	int i;

	wpa_printf(MSG_DEBUG, "Selecting BSS from priority group %d",
		   group->priority);

	bss = NULL;
	ssid = NULL;
	/* First, try to find WPA-enabled AP */
	for (i = 0; i < num && !selected; i++) {
		bss = &results[i];
		wpa_printf(MSG_DEBUG, "%d: " MACSTR " ssid='%s' "
			   "wpa_ie_len=%d rsn_ie_len=%d",
			   i, MAC2STR(bss->bssid),
			   wpa_ssid_txt(bss->ssid, bss->ssid_len),
			   bss->wpa_ie_len, bss->rsn_ie_len);
		if (bss->wpa_ie_len == 0 && bss->rsn_ie_len == 0) {
			wpa_printf(MSG_DEBUG, "   skip - no WPA/RSN IE");
			continue;
		}

		for (ssid = group; ssid; ssid = ssid->pnext) {
			struct wpa_ie_data ie;
			if (bss->ssid_len != ssid->ssid_len ||
			    memcmp(bss->ssid, ssid->ssid,
				   bss->ssid_len) != 0) {
				wpa_printf(MSG_DEBUG, "   skip - "
					   "SSID mismatch");
				continue;
			}
			if (ssid->bssid_set &&
			    memcmp(bss->bssid, ssid->bssid, ETH_ALEN) != 0) {
				wpa_printf(MSG_DEBUG, "   skip - "
					   "BSSID mismatch");
				continue;
			}
			if (!(((ssid->proto & WPA_PROTO_RSN) &&
			       wpa_parse_wpa_ie(wpa_s, bss->rsn_ie,
						bss->rsn_ie_len, &ie) == 0) ||
			      ((ssid->proto & WPA_PROTO_WPA) &&
			       wpa_parse_wpa_ie(wpa_s, bss->wpa_ie,
						bss->wpa_ie_len, &ie) == 0))) {
				wpa_printf(MSG_DEBUG, "   skip - "
					   "could not parse WPA/RSN IE");
				continue;
			}
			if (!(ie.proto & ssid->proto)) {
				wpa_printf(MSG_DEBUG, "   skip - "
					   "proto mismatch");
				continue;
			}
			if (!(ie.pairwise_cipher & ssid->pairwise_cipher)) {
				wpa_printf(MSG_DEBUG, "   skip - "
					   "PTK cipher mismatch");
				continue;
			}
			if (!(ie.group_cipher & ssid->group_cipher)) {
				wpa_printf(MSG_DEBUG, "   skip - "
					   "GTK cipher mismatch");
				continue;
			}
			if (!(ie.key_mgmt & ssid->key_mgmt)) {
				wpa_printf(MSG_DEBUG, "   skip - "
					   "key mgmt mismatch");
				continue;
			}

			selected = bss;
			*selected_ssid = ssid;
			wpa_printf(MSG_DEBUG, "   selected");
			break;
		}
	}

	/* If no WPA-enabled AP found, try to find non-WPA AP, if configuration
	 * allows this. */
	for (i = 0; i < num && !selected; i++) {
		bss = &results[i];
		for (ssid = group; ssid; ssid = ssid->pnext) {
			if (bss->ssid_len == ssid->ssid_len &&
			    memcmp(bss->ssid, ssid->ssid, bss->ssid_len) == 0
			    &&
			    (!ssid->bssid_set ||
			     memcmp(bss->bssid, ssid->bssid, ETH_ALEN) == 0) &&
			    ((ssid->key_mgmt & WPA_KEY_MGMT_NONE) ||
			     (ssid->key_mgmt & WPA_KEY_MGMT_IEEE8021X_NO_WPA)))
			{
				selected = bss;
				*selected_ssid = ssid;
				wpa_printf(MSG_DEBUG, "   selected non-WPA AP "
					   MACSTR " ssid='%s'",
					   MAC2STR(bss->bssid),
					   wpa_ssid_txt(bss->ssid,
							bss->ssid_len));
				break;
			}
		}
	}

	return selected;
}


static void wpa_supplicant_scan_results(struct wpa_supplicant *wpa_s)
{
#define SCAN_AP_LIMIT 50
	struct wpa_scan_result results[SCAN_AP_LIMIT];
	int num, prio;
	struct wpa_scan_result *selected = NULL;
	struct wpa_ssid *ssid;

	num = wpa_s->driver->get_scan_results(wpa_s->ifname, results,
					      SCAN_AP_LIMIT);
	wpa_printf(MSG_DEBUG, "Scan results: %d", num);
	if (num < 0)
		return;
	if (num > SCAN_AP_LIMIT) {
		wpa_printf(MSG_INFO, "Not enough room for all APs (%d < %d)",
			   num, SCAN_AP_LIMIT);
		num = SCAN_AP_LIMIT;
	}

	for (prio = 0; prio < wpa_s->conf->num_prio; prio++) {
		selected = wpa_supplicant_select_bss(wpa_s,
						     wpa_s->conf->pssid[prio],
						     results, num, &ssid);
		if (selected)
			break;
	}

	if (selected) {
		if (wpa_s->reassociate ||
		    memcmp(selected->bssid, wpa_s->bssid, ETH_ALEN) != 0) {
			wpa_supplicant_scard_init(wpa_s, ssid);
			wpa_supplicant_associate(wpa_s, selected, ssid);
		} else {
			wpa_printf(MSG_DEBUG, "Already associated with the "
				   "selected AP.");
		}
		rsn_preauth_scan_results(wpa_s, results, num);
	} else {
		wpa_printf(MSG_DEBUG, "No suitable AP found.");
		wpa_supplicant_req_scan(wpa_s, 5, 0);
	}
}


static void wpa_supplicant_dot1x_receive(int sock, void *eloop_ctx,
					 void *sock_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	u8 buf[128];
	int res;

	res = recv(sock, buf, sizeof(buf), 0);
	wpa_printf(MSG_DEBUG, "WPA: Receive from dot1x (Xsupplicant) socket "
		   "==> %d", res);
	if (res < 0) {
		perror("recv");
		return;
	}

	if (res != PMK_LEN) {
		wpa_printf(MSG_WARNING, "WPA: Invalid master key length (%d) "
			   "from dot1x", res);
		return;
	}

	wpa_hexdump(MSG_DEBUG, "WPA: Master key (dot1x)", buf, PMK_LEN);
	if (wpa_s->key_mgmt & WPA_KEY_MGMT_IEEE8021X) {
		memcpy(wpa_s->pmk, buf, PMK_LEN);
		wpa_s->ext_pmk_received = 1;
	} else {
		wpa_printf(MSG_INFO, "WPA: Not in IEEE 802.1X mode - dropping "
			   "dot1x PMK update (%d)", wpa_s->key_mgmt);
	}
}


static int wpa_supplicant_802_1x_init(struct wpa_supplicant *wpa_s)
{
	int s;
	struct sockaddr_un addr;

	s = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	addr.sun_path[0] = '\0';
	snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1,
		 "wpa_supplicant");
	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("bind");
		close(s);
		return -1;
	}

	wpa_s->dot1x_s = s;
	eloop_register_read_sock(s, wpa_supplicant_dot1x_receive, wpa_s,
				 NULL);
	return 0;
}


#ifdef CONFIG_DRIVER_HOSTAP
extern struct wpa_driver_ops wpa_driver_hostap_ops; /* driver_hostap.c */
#endif /* CONFIG_DRIVER_HOSTAP */
#ifdef CONFIG_DRIVER_PRISM54
extern struct wpa_driver_ops wpa_driver_prism54_ops; /* driver_prism54.c */
#endif /* CONFIG_DRIVER_PRISM54 */
#ifdef CONFIG_DRIVER_HERMES
extern struct wpa_driver_ops wpa_driver_hermes_ops; /* driver_hermes.c */
#endif /* CONFIG_DRIVER_HERMES */
#ifdef CONFIG_DRIVER_MADWIFI
extern struct wpa_driver_ops wpa_driver_madwifi_ops; /* driver_madwifi.c */
#endif /* CONFIG_DRIVER_MADWIFI */
#ifdef CONFIG_DRIVER_ATMEL
extern struct wpa_driver_ops wpa_driver_atmel_ops; /* driver_atmel.c */
#endif /* CONFIG_DRIVER_ATMEL */
#ifdef CONFIG_DRIVER_WEXT
extern struct wpa_driver_ops wpa_driver_wext_ops; /* driver_wext.c */
#endif /* CONFIG_DRIVER_WEXT */
#ifdef CONFIG_DRIVER_NDISWRAPPER
/* driver_ndiswrapper.c */
extern struct wpa_driver_ops wpa_driver_ndiswrapper_ops;
#endif /* CONFIG_DRIVER_NDISWRAPPER */

static int wpa_supplicant_set_driver(struct wpa_supplicant *wpa_s,
				     const char *name)
{
	struct wpa_driver_ops *def_drv;

	if (wpa_s == NULL)
		return -1;

#ifdef CONFIG_DRIVER_HOSTAP
	def_drv = &wpa_driver_hostap_ops;
#elif CONFIG_DRIVER_PRISM54
	def_drv = &wpa_driver_prism54_ops;
#elif CONFIG_DRIVER_HERMES
	def_drv = &wpa_driver_hermes_ops;
#elif CONFIG_DRIVER_MADWIFI
	def_drv = &wpa_driver_madwifi_ops;
#elif CONFIG_DRIVER_ATMEL
	def_drv = &wpa_driver_atmel_ops;
#elif CONFIG_DRIVER_WEXT
	def_drv = &wpa_driver_wext_ops;
#elif CONFIG_DRIVER_NDISWRAPPER
	def_drv = &wpa_driver_ndiswrapper_ops;
#else
#error No driver support included in .config.
#error See README for more information.
#endif

	if (name == NULL)
		wpa_s->driver = def_drv;
#ifdef CONFIG_DRIVER_HOSTAP
	else if (strcmp(name, "hostap") == 0)
		wpa_s->driver = &wpa_driver_hostap_ops;
#endif /* CONFIG_DRIVER_HOSTAP */
#ifdef CONFIG_DRIVER_PRISM54
	else if (strcmp(name, "prism54") == 0)
		wpa_s->driver = &wpa_driver_prism54_ops;
#endif /* CONFIG_DRIVER_PRISM54 */
#ifdef CONFIG_DRIVER_HERMES
	else if (strcmp(name, "hermes") == 0)
		wpa_s->driver = &wpa_driver_hermes_ops;
#endif /* CONFIG_DRIVER_HERMES */
#ifdef CONFIG_DRIVER_MADWIFI
	else if (strcmp(name, "madwifi") == 0)
		wpa_s->driver = &wpa_driver_madwifi_ops;
#endif /* CONFIG_DRIVER_MADWIFI */
#ifdef CONFIG_DRIVER_ATMEL
	else if (strcmp(name, "atmel") == 0)
		wpa_s->driver = &wpa_driver_atmel_ops;
#endif /* CONFIG_DRIVER_ATMEL */
#ifdef CONFIG_DRIVER_WEXT
	else if (strcmp(name, "wext") == 0)
		wpa_s->driver = &wpa_driver_wext_ops;
#endif /* CONFIG_DRIVER_WEXT */
#ifdef CONFIG_DRIVER_NDISWRAPPER
	else if (strcmp(name, "ndiswrapper") == 0)
		wpa_s->driver = &wpa_driver_ndiswrapper_ops;
#endif /* CONFIG_DRIVER_NDISWRAPPER */
	else {
		printf("Unsupported driver '%s'.\n", name);
		return -1;
	}
	return 0;
}


static void wpa_supplicant_fd_workaround(void)
{
	int s, i;
	/* When started from pcmcia-cs scripts, wpa_supplicant might start with
	 * fd 0, 1, and 2 closed. This will cause some issues because many
	 * places in wpa_supplicant are still printing out to stdout. As a
	 * workaround, make sure that fd's 0, 1, and 2 are not used for other
	 * sockets. */
	for (i = 0; i < 3; i++) {
		s = open("/dev/null", O_RDWR);
		if (s > 2) {
			close(s);
			break;
		}
	}
}


static int wpa_supplicant_driver_init(struct wpa_supplicant *wpa_s,
				      int wait_for_interface)
{
	for (;;) {
		wpa_s->l2 = l2_packet_init(wpa_s->ifname, ETH_P_EAPOL,
					   wpa_supplicant_rx_eapol, wpa_s);
		if (wpa_s->l2)
			break;
		else if (!wait_for_interface)
			return -1;
		printf("Waiting for interface..\n");
		sleep(5);
	}

	if (l2_packet_get_own_addr(wpa_s->l2, wpa_s->own_addr)) {
		fprintf(stderr, "Failed to get own L2 address\n");
		return -1;
	}

	if (wpa_s->driver->set_wpa(wpa_s->ifname, 1) < 0) {
		fprintf(stderr, "Failed to enable WPA in the driver.\n");
		return -1;
	}

	wpa_clear_keys(wpa_s, NULL);

	/* Make sure that TKIP countermeasures are not left enabled (could
	 * happen if wpa_supplicant is killed during countermeasures. */
	wpa_s->driver->set_countermeasures(wpa_s->ifname, 0);

	wpa_s->driver->set_drop_unencrypted(wpa_s->ifname, 1);

	wpa_s->prev_scan_ssid = BROADCAST_SSID_SCAN;
	wpa_supplicant_req_scan(wpa_s, 0, 100000);

	return 0;
}


static void usage(void)
{
	printf("%s\n\n%s\n"
	       "usage:\n"
	       "  wpa_supplicant [-BddehLqqvw] -i<ifname> -c<config file> "
	       "[-D<driver>]\n"
	       "\n"
	       "drivers:\n"
#ifdef CONFIG_DRIVER_HOSTAP
	       "  hostap = Host AP driver (Intersil Prism2/2.5/3)\n"
#endif  /* CONFIG_DRIVER_HOSTAP */
#ifdef CONFIG_DRIVER_PRISM54
	       "  prism54 = Prism54.org driver (Intersil Prism GT/Duette/"
	       "Indigo)\n"
#endif  /* CONFIG_DRIVER_PRISM54 */
#ifdef CONFIG_DRIVER_HERMES
	       "  hermes = Agere Systems Inc. driver (Hermes-I/Hermes-II)\n"
#endif  /* CONFIG_DRIVER_HERMES */
#ifdef CONFIG_DRIVER_MADWIFI
	       "  madwifi = MADWIFI 802.11 support (Atheros, etc.)\n"
#endif  /* CONFIG_DRIVER_MADWIFI */
#ifdef CONFIG_DRIVER_ATMEL
	       "  atmel = ATMEL AT76C5XXx (USB, PCMCIA)\n"
#endif  /* CONFIG_DRIVER_ATMEL */
#ifdef CONFIG_DRIVER_WEXT
	       "  wext = Linux wireless extensions (generic)\n"
#endif  /* CONFIG_DRIVER_WEXT */
#ifdef CONFIG_DRIVER_NDISWRAPPER
	       "  ndiswrapper = Linux ndiswrapper\n"
#endif  /* CONFIG_DRIVER_NDISWRAPER */
	       "options:\n"
	       "  -B = run daemon in the background\n"
	       "  -d = increase debugging verbosity (-dd even more)\n"
#ifdef IEEE8021X_EAPOL
	       "  -e = use external IEEE 802.1X Supplicant (e.g., "
	       "xsupplicant)\n"
	       "       (this disables the internal Supplicant)\n"
#endif /* IEEE8021X_EAPOL */
	       "  -h = show this help text\n"
	       "  -L = show license (GPL and BSD)\n"
	       "  -q = decrease debugging verbosity (-qq even less)\n"
	       "  -v = show version\n"
	       "  -w = wait for interface to be added, if needed\n",
	       wpa_supplicant_version, wpa_supplicant_license);
}


static void license(void)
{
	printf("%s\n\n%s\n",
	       wpa_supplicant_version, wpa_supplicant_full_license);
}


int main(int argc, char *argv[])
{
	struct wpa_supplicant wpa_s;
	char *ifname = NULL;
	int c;
	const char *confname = NULL, *driver = NULL;
	int daemonize = 0, wait_for_interface = 0, disable_eapol = 0, exitcode;

	memset(&wpa_s, 0, sizeof(wpa_s));
	wpa_s.dot1x_s = -1;

	for (;;) {
		c = getopt(argc, argv, "Bc:D:dehi:Lqvw");
		if (c < 0)
			break;
		switch (c) {
		case 'B':
			daemonize++;
			break;
		case 'c':
			confname = optarg;
			break;
		case 'D':
			driver = optarg;
			break;
		case 'd':
			wpa_debug_level--;
			break;
#ifdef IEEE8021X_EAPOL
		case 'e':
			disable_eapol++;
			break;
#endif /* IEEE8021X_EAPOL */
		case 'h':
			usage();
			return -1;
		case 'i':
			ifname = optarg;
			break;
		case 'L':
			license();
			return -1;
		case 'q':
			wpa_debug_level++;
			break;
		case 'v':
			printf("%s\n", wpa_supplicant_version);
			return -1;
		case 'w':
			wait_for_interface++;
			break;
		default:
			usage();
			return -1;
		}
	}

	wpa_supplicant_fd_workaround();
	eloop_init(&wpa_s);

	if (wpa_supplicant_set_driver(&wpa_s, driver) < 0) {
		return -1;
	}

	if (confname) {
		wpa_s.confname = rel2abs_path(confname);
		if (wpa_s.confname == NULL) {
			wpa_printf(MSG_ERROR, "Failed to get absolute path "
				   "for configuration file '%s'.", confname);
			return -1;
		}
		wpa_printf(MSG_DEBUG, "Configuration file '%s' -> '%s'",
			   confname, wpa_s.confname);
		wpa_s.conf = wpa_config_read(wpa_s.confname);
		if (wpa_s.conf == NULL) {
			printf("Failed to read configuration file '%s'.\n",
			       wpa_s.confname);
			return 1;
		}
	}

	if (wpa_s.conf == NULL || wpa_s.conf->ssid == NULL) {
		usage();
		printf("\nNo networks (SSID) configured.\n");
		return -1;
	}

	if (ifname == NULL) {
		usage();
		printf("\nInterface name is required.\n");
		return -1;
	}
	if (strlen(ifname) >= sizeof(wpa_s.ifname)) {
		printf("Too long interface name '%s'.\n", ifname);
		return -1;
	}
	strncpy(wpa_s.ifname, ifname, sizeof(wpa_s.ifname));

	if (wpa_supplicant_ctrl_iface_init(&wpa_s)) {
		printf("Failed to initialize control interface '%s'.\n"
		       "You may have another wpa_supplicant process already "
		       "running or the file was\n"
		       "left by an unclean termination of wpa_supplicant in "
		       "which case you will need\n"
		       "to manually remove this file before starting "
		       "wpa_supplicant again.\n",
		       wpa_s.conf->ctrl_interface);
		return -1;
	}

	exitcode = 0;

	if (wait_for_interface && daemonize) {
		wpa_printf(MSG_DEBUG, "Daemonize..");
		if (daemon(0, 0)) {
			perror("daemon");
			exitcode = -1;
			goto cleanup;
		}
	}

	if (!disable_eapol) {
		struct eapol_ctx *ctx;
		ctx = malloc(sizeof(*ctx));
		if (ctx == NULL) {
			printf("Failed to allocate EAPOL context.\n");
			exitcode = -1;
			goto cleanup;
		}
		memset(ctx, 0, sizeof(*ctx));
		ctx->ctx = &wpa_s;
		ctx->msg_ctx = &wpa_s;
		ctx->preauth = 0;
		ctx->eapol_done_cb = wpa_supplicant_notify_eapol_done;
		ctx->eapol_send = wpa_eapol_send;
		ctx->set_wep_key = wpa_eapol_set_wep_key;
		wpa_s.eapol = eapol_sm_init(ctx);
		if (wpa_s.eapol == NULL) {
			free(ctx);
			printf("Failed to initialize EAPOL state machines.\n");
			exitcode = -1;
			goto cleanup;
		}
	}

	/* RSNA Supplicant Key Management - INITIALIZE */
	eapol_sm_notify_portEnabled(wpa_s.eapol, FALSE);
	eapol_sm_notify_portValid(wpa_s.eapol, FALSE);

	/* Register driver event handler before L2 receive handler so that
	 * association events are processed before EAPOL-Key packets if both
	 * become available for the same select() call. */
	wpa_s.events_priv = wpa_s.driver->events_init(&wpa_s);
	if (wpa_s.events_priv == NULL) {
		fprintf(stderr, "Failed to initialize driver event "
			"processing\n");
		exitcode = -1;
		goto cleanup;
	}

	wpa_s.renew_snonce = 1;
	if (wpa_supplicant_driver_init(&wpa_s, wait_for_interface) < 0) {
		exitcode = -1;
		goto cleanup;
	}

	if (disable_eapol)
		wpa_supplicant_802_1x_init(&wpa_s);

	if (!wait_for_interface && daemonize) {
		wpa_printf(MSG_DEBUG, "Daemonize..");
		if (daemon(0, 0)) {
			perror("daemon");
			exitcode = -1;
			goto cleanup;
		}
	}

	eloop_register_signal(SIGINT, wpa_supplicant_terminate, NULL);
	eloop_register_signal(SIGTERM, wpa_supplicant_terminate, NULL);
	eloop_register_signal(SIGHUP, wpa_supplicant_reconfig, NULL);

	eloop_run();

	wpa_supplicant_deauthenticate(&wpa_s, REASON_DEAUTH_LEAVING);

cleanup:
	if (wpa_s.driver->set_wpa(wpa_s.ifname, 0) < 0) {
		fprintf(stderr, "Failed to disable WPA in the driver.\n");
	}

	if (wpa_s.events_priv)
		wpa_s.driver->events_deinit(&wpa_s, wpa_s.events_priv);

	wpa_s.driver->set_drop_unencrypted(wpa_s.ifname, 0);
	wpa_s.driver->set_countermeasures(wpa_s.ifname, 0);

	if (wpa_s.driver->cleanup)
		wpa_s.driver->cleanup(wpa_s.ifname);

	wpa_supplicant_cleanup(&wpa_s);

	eloop_destroy();

	return exitcode;
}
