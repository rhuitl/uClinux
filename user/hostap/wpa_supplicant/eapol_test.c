/*
 * WPA Supplicant - test code
 * Copyright (c) 2003-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * IEEE 802.1X Supplicant test code (to be used in place of wpa_supplicant.c.
 * Not used in production version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <signal.h>
#include <netinet/in.h>
#include <assert.h>
#include <arpa/inet.h>

#include "common.h"
#include "config.h"
#include "eapol_sm.h"
#include "eloop.h"
#include "wpa.h"
#include "eap.h"
#include "wpa_supplicant.h"
#include "wpa_supplicant_i.h"
#include "radius.h"
#include "radius_client.h"
#include "l2_packet.h"
#include "ctrl_iface.h"
#include "pcsc_funcs.h"


static int wpa_debug_level = 0;

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


void wpa_supplicant_event(struct wpa_supplicant *wpa_s, wpa_event_type event,
			  union wpa_event_data *data)
{
}


int rsn_preauth_init(struct wpa_supplicant *wpa_s, u8 *dst)
{
	return -1;
}


void rsn_preauth_deinit(struct wpa_supplicant *wpa_s)
{
}


int pmksa_cache_list(struct wpa_supplicant *wpa_s, char *buf, size_t len)
{
	return 0;
}


int wpa_get_mib(struct wpa_supplicant *wpa_s, char *buf, size_t buflen)
{
	return 0;
}


void wpa_supplicant_req_scan(struct wpa_supplicant *wpa_s, int sec, int usec)
{
}


const char * wpa_ssid_txt(u8 *ssid, size_t ssid_len)
{
	return NULL;
}


int wpa_supplicant_reload_configuration(struct wpa_supplicant *wpa_s)
{
	return -1;
}


static void ieee802_1x_encapsulate_radius(struct wpa_supplicant *wpa_s,
					  u8 *eap, size_t len)
{
	struct radius_msg *msg;
	char buf[128];
	struct wpa_ssid *ssid = wpa_s->current_ssid;
	u8 *identity;
	size_t identity_len;

	wpa_printf(MSG_DEBUG, "Encapsulating EAP message into a RADIUS "
		   "packet");

	wpa_s->radius_identifier = radius_client_get_id(wpa_s);
	msg = radius_msg_new(RADIUS_CODE_ACCESS_REQUEST,
			     wpa_s->radius_identifier);
	if (msg == NULL) {
		printf("Could not create net RADIUS packet\n");
		return;
	}

	radius_msg_make_authenticator(msg, (u8 *) wpa_s, sizeof(*wpa_s));

	if (ssid->anonymous_identity) {
		identity = ssid->anonymous_identity;
		identity_len = ssid->anonymous_identity_len;
	} else {
		identity = ssid->identity;
		identity_len = ssid->identity_len;
	}

	if (identity &&
	    !radius_msg_add_attr(msg, RADIUS_ATTR_USER_NAME,
				 identity, identity_len)) {
		printf("Could not add User-Name\n");
		goto fail;
	}

	if (!radius_msg_add_attr(msg, RADIUS_ATTR_NAS_IP_ADDRESS,
				 (u8 *) &wpa_s->own_ip_addr, 4)) {
		printf("Could not add NAS-IP-Address\n");
		goto fail;
	}

	snprintf(buf, sizeof(buf), RADIUS_802_1X_ADDR_FORMAT,
		 MAC2STR(wpa_s->own_addr));
	if (!radius_msg_add_attr(msg, RADIUS_ATTR_CALLING_STATION_ID,
				 buf, strlen(buf))) {
		printf("Could not add Calling-Station-Id\n");
		goto fail;
	}

	/* TODO: should probably check MTU from driver config; 2304 is max for
	 * IEEE 802.11, but use 1400 to avoid problems with too large packets
	 */
	if (!radius_msg_add_attr_int32(msg, RADIUS_ATTR_FRAMED_MTU, 1400)) {
		printf("Could not add Framed-MTU\n");
		goto fail;
	}

	if (!radius_msg_add_attr_int32(msg, RADIUS_ATTR_NAS_PORT_TYPE,
				       RADIUS_NAS_PORT_TYPE_IEEE_802_11)) {
		printf("Could not add NAS-Port-Type\n");
		goto fail;
	}

	snprintf(buf, sizeof(buf), "CONNECT 11Mbps 802.11b");
	if (!radius_msg_add_attr(msg, RADIUS_ATTR_CONNECT_INFO,
				 buf, strlen(buf))) {
		printf("Could not add Connect-Info\n");
		goto fail;
	}

	if (eap && !radius_msg_add_eap(msg, eap, len)) {
		printf("Could not add EAP-Message\n");
		goto fail;
	}

	/* State attribute must be copied if and only if this packet is
	 * Access-Request reply to the previous Access-Challenge */
	if (wpa_s->last_recv_radius && wpa_s->last_recv_radius->hdr->code ==
	    RADIUS_CODE_ACCESS_CHALLENGE) {
		int res = radius_msg_copy_attr(msg, wpa_s->last_recv_radius,
					       RADIUS_ATTR_STATE);
		if (res < 0) {
			printf("Could not copy State attribute from previous "
			       "Access-Challenge\n");
			goto fail;
		}
		if (res > 0) {
			wpa_printf(MSG_DEBUG, "  Copied RADIUS State "
				   "Attribute");
		}
	}

	radius_client_send(wpa_s, msg, RADIUS_AUTH, wpa_s->own_addr);
	return;

 fail:
	radius_msg_free(msg);
	free(msg);
}


static int eapol_test_eapol_send(void *ctx, int type, u8 *buf, size_t len)
{
	struct wpa_supplicant *wpa_s = ctx;
	printf("WPA: wpa_eapol_send(type=%d len=%d)\n", type, len);
	if (type == IEEE802_1X_TYPE_EAP_PACKET) {
		wpa_hexdump(MSG_DEBUG, "TX EAP -> RADIUS", buf, len);
		ieee802_1x_encapsulate_radius(wpa_s, buf, len);
	}
	return 0;
}


static void eapol_test_eapol_done_cb(void *ctx)
{
	printf("WPA: EAPOL processing complete\n");
}


static void eapol_sm_cb(struct eapol_sm *eapol, int success, void *ctx)
{
	printf("eapol_sm_cb: success=%d\n", success);
	eloop_terminate();
}


static int test_eapol(struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid)
{
	struct eapol_config eapol_conf;
	struct eapol_ctx *ctx;

	ctx = malloc(sizeof(*ctx));
	if (ctx == NULL) {
		printf("Failed to allocate EAPOL context.\n");
		return -1;
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->ctx = wpa_s;
	ctx->msg_ctx = wpa_s;
	ctx->scard_ctx = wpa_s->scard;
	ctx->cb = eapol_sm_cb;
	ctx->cb_ctx = wpa_s;
	ctx->preauth = 0;
	ctx->eapol_done_cb = eapol_test_eapol_done_cb;
	ctx->eapol_send = eapol_test_eapol_send;

	wpa_s->eapol = eapol_sm_init(ctx);
	if (wpa_s->eapol == NULL) {
		free(ctx);
		printf("Failed to initialize EAPOL state machines.\n");
		return -1;
	}

	wpa_s->current_ssid = ssid;
	memset(&eapol_conf, 0, sizeof(eapol_conf));
	eapol_conf.accept_802_1x_keys = 1;
	eapol_conf.required_keys = 0;
	eapol_sm_notify_config(wpa_s->eapol, ssid, &eapol_conf);


	eapol_sm_notify_portValid(wpa_s->eapol, FALSE);
	/* 802.1X::portControl = Auto */
	eapol_sm_notify_portEnabled(wpa_s->eapol, TRUE);

	return 0;
}


static void test_eapol_clean(struct wpa_supplicant *wpa_s)
{
	radius_client_deinit(wpa_s);
	free(wpa_s->last_eap_radius);
	if (wpa_s->last_recv_radius) {
		radius_msg_free(wpa_s->last_recv_radius);
		free(wpa_s->last_recv_radius);
	}
	eapol_sm_deinit(wpa_s->eapol);
	wpa_s->eapol = NULL;
	if (wpa_s->auth_server) {
		free(wpa_s->auth_server->shared_secret);
		free(wpa_s->auth_server);
	}
	scard_deinit(wpa_s->scard);
	wpa_supplicant_ctrl_iface_deinit(wpa_s);
	wpa_config_free(wpa_s->conf);
}


static void send_eap_request_identity(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	u8 buf[100], *pos;
	struct ieee802_1x_hdr *hdr;
	struct eap_hdr *eap;

	hdr = (struct ieee802_1x_hdr *) buf;
	hdr->version = EAPOL_VERSION;
	hdr->type = IEEE802_1X_TYPE_EAP_PACKET;
	hdr->length = htons(5);

	eap = (struct eap_hdr *) (hdr + 1);
	eap->code = EAP_CODE_REQUEST;
	eap->identifier = 0;
	eap->length = htons(5);
	pos = (u8 *) (eap + 1);
	*pos = EAP_TYPE_IDENTITY;

	printf("Sending fake EAP-Request-Identity\n");
	eapol_sm_rx_eapol(wpa_s->eapol, wpa_s->bssid, buf,
			  sizeof(*hdr) + 5);
}


static void eapol_test_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	printf("EAPOL test timed out\n");
	wpa_s->auth_timed_out = 1;
	eloop_terminate();
}


static char *eap_type_text(u8 type)
{
	switch (type) {
	case EAP_TYPE_IDENTITY: return "Identity";
	case EAP_TYPE_NOTIFICATION: return "Notification";
	case EAP_TYPE_NAK: return "Nak";
	case EAP_TYPE_TLS: return "TLS";
	case EAP_TYPE_TTLS: return "TTLS";
	case EAP_TYPE_PEAP: return "PEAP";
	case EAP_TYPE_SIM: return "SIM";
	case EAP_TYPE_GTC: return "GTC";
	case EAP_TYPE_MD5: return "MD5";
	case EAP_TYPE_OTP: return "OTP";
	default: return "Unknown";
	}
}


static void ieee802_1x_decapsulate_radius(struct wpa_supplicant *wpa_s)
{
	char *eap;
	size_t len;
	struct eap_hdr *hdr;
	int eap_type = -1;
	char buf[64];
	struct radius_msg *msg;

	if (wpa_s->last_recv_radius == NULL)
		return;

	msg = wpa_s->last_recv_radius;

	eap = radius_msg_get_eap(msg, &len);
	if (eap == NULL) {
		/* draft-aboba-radius-rfc2869bis-20.txt, Chap. 2.6.3:
		 * RADIUS server SHOULD NOT send Access-Reject/no EAP-Message
		 * attribute */
		wpa_printf(MSG_DEBUG, "could not extract "
			       "EAP-Message from RADIUS message");
		free(wpa_s->last_eap_radius);
		wpa_s->last_eap_radius = NULL;
		wpa_s->last_eap_radius_len = 0;
		return;
	}

	if (len < sizeof(*hdr)) {
		wpa_printf(MSG_DEBUG, "too short EAP packet "
			       "received from authentication server");
		free(eap);
		return;
	}

	if (len > sizeof(*hdr))
		eap_type = eap[sizeof(*hdr)];

	hdr = (struct eap_hdr *) eap;
	switch (hdr->code) {
	case EAP_CODE_REQUEST:
		snprintf(buf, sizeof(buf), "EAP-Request-%s (%d)",
			 eap_type >= 0 ? eap_type_text(eap_type) : "??",
			 eap_type);
		break;
	case EAP_CODE_RESPONSE:
		snprintf(buf, sizeof(buf), "EAP Response-%s (%d)",
			 eap_type >= 0 ? eap_type_text(eap_type) : "??",
			 eap_type);
		break;
	case EAP_CODE_SUCCESS:
		snprintf(buf, sizeof(buf), "EAP Success");
		/* LEAP uses EAP Success within an authentication, so must not
		 * stop here with eloop_terminate(); */
		break;
	case EAP_CODE_FAILURE:
		snprintf(buf, sizeof(buf), "EAP Failure");
		eloop_terminate();
		break;
	default:
		snprintf(buf, sizeof(buf), "unknown EAP code");
		wpa_hexdump(MSG_DEBUG, "Decapsulated EAP packet", eap, len);
		break;
	}
	wpa_printf(MSG_DEBUG, "decapsulated EAP packet (code=%d "
		       "id=%d len=%d) from RADIUS server: %s",
		      hdr->code, hdr->identifier, ntohs(hdr->length), buf);

	/* sta->eapol_sm->be_auth.idFromServer = hdr->identifier; */

	if (wpa_s->last_eap_radius)
		free(wpa_s->last_eap_radius);
	wpa_s->last_eap_radius = eap;
	wpa_s->last_eap_radius_len = len;

	{
		struct ieee802_1x_hdr *hdr;
		hdr = malloc(sizeof(*hdr) + len);
		assert(hdr != NULL);
		hdr->version = EAPOL_VERSION;
		hdr->type = IEEE802_1X_TYPE_EAP_PACKET;
		hdr->length = htons(len);
		memcpy((u8 *) (hdr + 1), eap, len);
		eapol_sm_rx_eapol(wpa_s->eapol, wpa_s->bssid,
				  (u8 *) hdr, sizeof(*hdr) + len);
		free(hdr);
	}
}


static void ieee802_1x_get_keys(struct wpa_supplicant *wpa_s,
				struct radius_msg *msg, struct radius_msg *req,
				u8 *shared_secret, size_t shared_secret_len)
{
	struct radius_ms_mppe_keys *keys;

	keys = radius_msg_get_ms_keys(msg, req, shared_secret,
				      shared_secret_len);
	if (keys && keys->send == NULL && keys->recv == NULL) {
		free(keys);
		keys = radius_msg_get_cisco_keys(msg, req, shared_secret,
						 shared_secret_len);
	}

	if (keys) {
		if (keys->send) {
			wpa_hexdump(MSG_DEBUG, "MS-MPPE-Send-Key (sign)",
				    keys->send, keys->send_len);
		}
		if (keys->recv) {
			wpa_hexdump(MSG_DEBUG, "MS-MPPE-Recv-Key (crypt)",
				    keys->recv, keys->recv_len);
			wpa_s->authenticator_pmk_len =
				keys->recv_len > PMK_LEN ? PMK_LEN :
				keys->recv_len;
			memcpy(wpa_s->authenticator_pmk, keys->recv,
			       wpa_s->authenticator_pmk_len);
		}

		free(keys->send);
		free(keys->recv);
		free(keys);
	}
}


/* Process the RADIUS frames from Authentication Server */
static RadiusRxResult
ieee802_1x_receive_auth(struct wpa_supplicant *wpa_s,
			struct radius_msg *msg, struct radius_msg *req,
			u8 *shared_secret, size_t shared_secret_len,
			void *data)
{
#if 0
	u32 session_timeout, termination_action;
	int session_timeout_set;
	int acct_interim_interval;
#endif

#if 0
	sta = ap_get_sta_radius_identifier(hapd, msg->hdr->identifier);
	if (sta == NULL) {
		wpa_printf(MSG_DEBUG, "IEEE 802.1X: Could not "
		      "find matching station for this RADIUS "
		      "message\n");
		return RADIUS_RX_UNKNOWN;
	}
#endif

	/* RFC 2869, Ch. 5.13: valid Message-Authenticator attribute MUST be
	 * present when packet contains an EAP-Message attribute */
	if (msg->hdr->code == RADIUS_CODE_ACCESS_REJECT &&
	    radius_msg_get_attr(msg, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, NULL,
				0) < 0 &&
	    radius_msg_get_attr(msg, RADIUS_ATTR_EAP_MESSAGE, NULL, 0) < 0) {
		wpa_printf(MSG_DEBUG, "Allowing RADIUS "
			      "Access-Reject without Message-Authenticator "
			      "since it does not include EAP-Message\n");
	} else if (radius_msg_verify(msg, shared_secret, shared_secret_len,
				     req)) {
		printf("Incoming RADIUS packet did not have correct "
		       "Message-Authenticator - dropped\n");
		return RADIUS_RX_UNKNOWN;
	}

	if (msg->hdr->code != RADIUS_CODE_ACCESS_ACCEPT &&
	    msg->hdr->code != RADIUS_CODE_ACCESS_REJECT &&
	    msg->hdr->code != RADIUS_CODE_ACCESS_CHALLENGE) {
		printf("Unknown RADIUS message code\n");
		return RADIUS_RX_UNKNOWN;
	}

	wpa_s->radius_identifier = -1;
	wpa_printf(MSG_DEBUG, "RADIUS packet matching with station");

	if (wpa_s->last_recv_radius) {
		radius_msg_free(wpa_s->last_recv_radius);
		free(wpa_s->last_recv_radius);
	}

	wpa_s->last_recv_radius = msg;

#if 0
	session_timeout_set =
		!radius_msg_get_attr_int32(msg, RADIUS_ATTR_SESSION_TIMEOUT,
					   &session_timeout);
	if (radius_msg_get_attr_int32(msg, RADIUS_ATTR_TERMINATION_ACTION,
				      &termination_action))
		termination_action = RADIUS_TERMINATION_ACTION_DEFAULT;

	if (hapd->conf->radius_acct_interim_interval == 0 &&
	    msg->hdr->code == RADIUS_CODE_ACCESS_ACCEPT &&
	    radius_msg_get_attr_int32(msg, RADIUS_ATTR_ACCT_INTERIM_INTERVAL,
				      &acct_interim_interval) == 0) {
		if (acct_interim_interval < 60) {
			hostapd_logger(hapd, sta->addr,
				       HOSTAPD_MODULE_IEEE8021X,
				       HOSTAPD_LEVEL_INFO,
				       "ignored too small "
				       "Acct-Interim-Interval %d",
				       acct_interim_interval);
		} else
			sta->acct_interim_interval = acct_interim_interval;
	}


	switch (msg->hdr->code) {
	case RADIUS_CODE_ACCESS_ACCEPT:
		/* draft-congdon-radius-8021x-22.txt, Ch. 3.17 */
		if (session_timeout_set &&
			termination_action ==
		    RADIUS_TERMINATION_ACTION_RADIUS_REQUEST) {
			sta->eapol_sm->reauth_timer.reAuthPeriod =
				session_timeout;
		} else if (session_timeout_set)
			ap_sta_session_timeout(hapd, sta, session_timeout);

		sta->eapol_sm->be_auth.aSuccess = TRUE;
		ieee802_1x_get_keys(hapd, sta, msg, req, shared_secret,
				    shared_secret_len);
		if (sta->eapol_sm->keyAvailable) {
			pmksa_cache_add(hapd, sta, sta->eapol_key_crypt,
					session_timeout_set ?
					session_timeout : -1);
		}
		break;
	case RADIUS_CODE_ACCESS_REJECT:
		sta->eapol_sm->be_auth.aFail = TRUE;
		break;
	case RADIUS_CODE_ACCESS_CHALLENGE:
		if (session_timeout_set) {
			/* RFC 2869, Ch. 2.3.2
			 * draft-congdon-radius-8021x-22.txt, Ch. 3.17 */
			sta->eapol_sm->be_auth.suppTimeout = session_timeout;
		}
		sta->eapol_sm->be_auth.aReq = TRUE;
		break;
	}
#else

	switch (msg->hdr->code) {
	case RADIUS_CODE_ACCESS_ACCEPT:
		wpa_s->radius_access_accept_received = 1;
		ieee802_1x_get_keys(wpa_s, msg, req, shared_secret,
				    shared_secret_len);
		break;
	case RADIUS_CODE_ACCESS_REJECT:
		wpa_s->radius_access_reject_received = 1;
		break;
	}
#endif

	ieee802_1x_decapsulate_radius(wpa_s);

	/* eapol_sm_step(sta->eapol_sm); */

	if (msg->hdr->code == RADIUS_CODE_ACCESS_ACCEPT ||
	    msg->hdr->code == RADIUS_CODE_ACCESS_REJECT) {
		eloop_terminate();
	}

	return RADIUS_RX_QUEUED;
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

	wpa_hexdump(MSG_DEBUG, "IMSI", buf, len);
	free(wpa_s->imsi);
	wpa_s->imsi = malloc(len);
	if (wpa_s->imsi) {
		wpa_s->imsi = buf;
		wpa_s->imsi_len = len;
		wpa_supplicant_imsi_identity(wpa_s, ssid);
	}
}


static void wpa_init_conf(struct wpa_supplicant *wpa_s, const char *authsrv,
			  const char *secret)
{
	struct hostapd_radius_server *as;
	int res;

	wpa_s->bssid[5] = 1;
	wpa_s->own_addr[5] = 2;
	wpa_s->own_ip_addr.s_addr = htonl((127 << 24) | 1);

	wpa_s->num_auth_servers = 1;
	as = malloc(sizeof(struct hostapd_radius_server));
	assert(as != NULL);
	inet_aton(authsrv, &as->addr);
	as->port = 1812;
	as->shared_secret = strdup(secret);
	as->shared_secret_len = strlen(secret);
	wpa_s->auth_server = wpa_s->auth_servers = as;


	res = radius_client_init(wpa_s);
	assert(res == 0);

	res = radius_client_register(wpa_s, RADIUS_AUTH,
				     ieee802_1x_receive_auth, NULL);
	assert(res == 0);
}


static int scard_test(void)
{
	struct scard_data *scard;
	size_t len;
	char imsi[20];
	unsigned char rand[16];
	unsigned char sres[4];
	unsigned char kc[8];
	const int num_triplets = 5;
	unsigned char rand_[num_triplets][16];
	unsigned char sres_[num_triplets][4];
	unsigned char kc_[num_triplets][8];
	int i, j;

	scard = scard_init(SCARD_TRY_BOTH, "1234");
	if (scard == NULL)
		return -1;

	len = sizeof(imsi);
	if (scard_get_imsi(scard, imsi, &len))
		goto failed;
	wpa_hexdump_ascii(MSG_DEBUG, "SCARD: IMSI", imsi, len);
	/* NOTE: Permanent Username: 1 | IMSI */

	memset(rand, 0, sizeof(rand));
	if (scard_gsm_auth(scard, rand, sres, kc))
		goto failed;

	memset(rand, 0xff, sizeof(rand));
	if (scard_gsm_auth(scard, rand, sres, kc))
		goto failed;

	for (i = 0; i < num_triplets; i++) {
		memset(rand_[i], i, sizeof(rand_[i]));
		if (scard_gsm_auth(scard, rand_[i], sres_[i], kc_[i]))
			goto failed;
	}

	for (i = 0; i < num_triplets; i++) {
		printf("1");
		for (j = 0; j < len; j++)
			printf("%c", imsi[j]);
		printf(",");
		for (j = 0; j < 16; j++)
			printf("%02X", rand_[i][j]);
		printf(",");
		for (j = 0; j < 4; j++)
			printf("%02X", sres_[i][j]);
		printf(",");
		for (j = 0; j < 8; j++)
			printf("%02X", kc_[i][j]);
		printf("\n");
	}

failed:
	scard_deinit(scard);

	return 0;
}


static void eapol_test_terminate(int sig, void *eloop_ctx,
				 void *signal_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	wpa_msg(wpa_s, MSG_INFO, "Signal %d received - terminating", sig);
	eloop_terminate();
}


int main(int argc, char *argv[])
{
	struct wpa_supplicant wpa_s;
	u8 pmk[PMK_LEN];
	int ret = 1;

	if (argc == 2 && strcmp(argv[1], "scard") == 0) {
		return scard_test();
	}

	if (argc < 4) {
		printf("usage: eapol_test <conf> <auth srv IP> <secret>\n");
		return -1;
	}

	eloop_init(&wpa_s);

	memset(&wpa_s, 0, sizeof(wpa_s));
	wpa_s.conf = wpa_config_read(argv[1]);
	if (wpa_s.conf == NULL) {
		printf("Failed to parse configuration file '%s'.\n", argv[1]);
		return -1;
	}
	if (wpa_s.conf->ssid == NULL) {
		printf("No networks defined.\n");
		return -1;
	}

	wpa_init_conf(&wpa_s, argv[2], argv[3]);
	if (wpa_supplicant_ctrl_iface_init(&wpa_s)) {
		printf("Failed to initialize control interface '%s'.\n"
		       "You may have another eapol_test process already "
		       "running or the file was\n"
		       "left by an unclean termination of eapol_test in "
		       "which case you will need\n"
		       "to manually remove this file before starting "
		       "eapol_test again.\n",
		       wpa_s.conf->ctrl_interface);
		return -1;
	}
	wpa_supplicant_scard_init(&wpa_s, wpa_s.conf->ssid);

	if (test_eapol(&wpa_s, wpa_s.conf->ssid))
		return -1;

	eloop_register_timeout(30, 0, eapol_test_timeout, &wpa_s, NULL);
	eloop_register_timeout(0, 0, send_eap_request_identity, &wpa_s, NULL);
	eloop_register_signal(SIGINT, eapol_test_terminate, NULL);
	eloop_register_signal(SIGTERM, eapol_test_terminate, NULL);
	eloop_register_signal(SIGHUP, eapol_test_terminate, NULL);
	eloop_run();

	if (eapol_sm_get_key(wpa_s.eapol, pmk, PMK_LEN) == 0) {
		wpa_hexdump(MSG_DEBUG, "PMK from EAPOL", pmk, PMK_LEN);
		if (memcmp(pmk, wpa_s.authenticator_pmk, PMK_LEN) != 0)
			printf("WARNING: PMK mismatch\n");
		else if (wpa_s.radius_access_accept_received)
			ret = 0;
	} else if (wpa_s.authenticator_pmk_len == 16 &&
		   eapol_sm_get_key(wpa_s.eapol, pmk, 16) == 0) {
		wpa_hexdump(MSG_DEBUG, "LEAP PMK from EAPOL", pmk, 16);
		if (memcmp(pmk, wpa_s.authenticator_pmk, 16) != 0)
			printf("WARNING: PMK mismatch\n");
		else if (wpa_s.radius_access_accept_received)
			ret = 0;
	} else if (wpa_s.radius_access_accept_received && argc > 4) {
		/* No keying material expected */
		ret = 0;
	}

	if (wpa_s.auth_timed_out)
		ret = -2;
	if (wpa_s.radius_access_reject_received)
		ret = -3;

	test_eapol_clean(&wpa_s);

	eloop_destroy();

	return ret;
}
