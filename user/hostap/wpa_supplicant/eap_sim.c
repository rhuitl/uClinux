/*
 * WPA Supplicant / EAP-SIM (draft-haverinen-pppext-eap-sim-12.txt)
 * Copyright (c) 2004, Jouni Malinen <jkmaline@cc.hut.fi>
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
#include <netinet/in.h>

#include "common.h"
#include "eapol_sm.h"
#include "eap.h"
#include "wpa_supplicant.h"
#include "config.h"
#include "sha1.h"
#include "pcsc_funcs.h"

#define EAP_SIM_VERSION 1

/* EAP-SIM Subtypes */
#define EAP_SIM_SUBTYPE_START 10
#define EAP_SIM_SUBTYPE_CHALLENGE 11
#define EAP_SIM_SUBTYPE_NOTIFICATION 12
#define EAP_SIM_SUBTYPE_RE_AUTHENTICATION 13
#define EAP_SIM_SUBTYPE_CLIENT_ERROR 14

/* EAP-SIM Attributes (0..127 non-skippable) */
#define EAP_SIM_AT_RAND 1
#define EAP_SIM_AT_PADDING 6
#define EAP_SIM_AT_NONCE_MT 7
#define EAP_SIM_AT_PERMANENT_ID_REQ 10
#define EAP_SIM_AT_MAC 11
#define EAP_SIM_AT_NOTIFICATION 12
#define EAP_SIM_AT_ANY_ID_REQ 13
#define EAP_SIM_AT_IDENTITY 14
#define EAP_SIM_AT_VERSION_LIST 15
#define EAP_SIM_AT_SELECTED_VERSION 16
#define EAP_SIM_AT_FULLAUTH_ID_REQ 17
#define EAP_SIM_AT_COUNTER 19
#define EAP_SIM_AT_COUNTER_TOO_SMALL 20
#define EAP_SIM_AT_NONCE_S 21
#define EAP_SIM_AT_CLIENT_ERROR_CODE 22
#define EAP_SIM_AT_IV 129
#define EAP_SIM_AT_ENCR_DATA 130
#define EAP_SIM_AT_NEXT_PSEUDONYM 132
#define EAP_SIM_AT_NEXT_REAUTH_ID 133

/* AT_NOTIFICATION notification code values */
#define EAP_SIM_TEMPORARILY_DENIED 1025
#define EAP_SIM_NOT_SUBSCRIBED 1031

/* AT_CLIENT_ERROR_CODE error codes */
#define EAP_SIM_UNABLE_TO_PROCESS_PACKET 0
#define EAP_SIM_UNSUPPORTED_VERSION 1
#define EAP_SIM_INSUFFICIENT_NUM_OF_CHAL 2
#define EAP_SIM_RAND_NOT_FRESH 3

#define GSM_RAND_LEN 16
#define NONCE_MT_LEN 16
#define EAP_SIM_MAC_LEN 16
#define MK_LEN 20
#define KC_LEN 8
#define SRES_LEN 4
#define K_AUT_LEN 16
#define K_ENCR_LEN 16
#define MSK_LEN 8
#define EMSK_LEN 8
#define EAP_SIM_KEYING_DATA_LEN 64

struct eap_sim_data {
	u8 *ver_list;
	size_t ver_list_len;
	int selected_version;

	u8 kc1[KC_LEN], kc2[KC_LEN], kc3[KC_LEN];
	u8 sres1[SRES_LEN], sres2[SRES_LEN], sres3[SRES_LEN];
	u8 nonce_mt[NONCE_MT_LEN];
	u8 mk[MK_LEN];
	u8 k_aut[K_AUT_LEN];
	u8 k_encr[K_ENCR_LEN];
	u8 msk[EAP_SIM_KEYING_DATA_LEN];
	u8 rand1[GSM_RAND_LEN], rand2[GSM_RAND_LEN], rand3[GSM_RAND_LEN];
};


static void * eap_sim_init(struct eap_sm *sm)
{
	struct eap_sim_data *data;
	data = malloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	memset(data, 0, sizeof(*data));

	if (hostapd_get_rand(data->nonce_mt, NONCE_MT_LEN)) {
		wpa_printf(MSG_WARNING, "EAP-SIM: Failed to get random data "
			   "for NONCE_MT");
		free(data);
		return NULL;
	}

	return data;
}


static void eap_sim_deinit(struct eap_sm *sm, void *priv)
{
	struct eap_sim_data *data = priv;
	if (data) {
		free(data->ver_list);
		free(data);
	}
}


static void eap_sim_gsm_auth(struct eap_sm *sm, struct eap_sim_data *data)
{
	wpa_printf(MSG_DEBUG, "EAP-SIM: GSM authentication algorithm");
#ifdef PCSC_FUNCS
	if (scard_gsm_auth(sm->eapol->ctx->scard_ctx, data->rand1,
			   data->sres1, data->kc1) ||
	    scard_gsm_auth(sm->eapol->ctx->scard_ctx, data->rand2,
			   data->sres2, data->kc2) ||
	    scard_gsm_auth(sm->eapol->ctx->scard_ctx, data->rand3,
			   data->sres3, data->kc3)) {
		wpa_printf(MSG_DEBUG, "EAP-SIM: GSM SIM authentication could "
			   "not be completed");
		/* TODO: what to do here? */
	}
#else /* PCSC_FUNCS */
	/* These hardcoded Kc and SRES values are used for testing.
	 * Could consider making them configurable. */
	memcpy(data->kc1, "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7", KC_LEN);
	memcpy(data->kc2, "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7", KC_LEN);
	memcpy(data->kc3, "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7", KC_LEN);
	memcpy(data->sres1, "\xd1\xd2\xd3\xd4", SRES_LEN);
	memcpy(data->sres2, "\xe1\xe2\xe3\xe4", SRES_LEN);
	memcpy(data->sres3, "\xf1\xf2\xf3\xf4", SRES_LEN);
#endif /* PCSC_FUNCS */
}


static int eap_sim_supported_ver(struct eap_sim_data *data, int version)
{
	return version == EAP_SIM_VERSION;
}


static void eap_sim_derive_mk(struct eap_sim_data *data,
			      u8 *identity, size_t identity_len)
{
	u8 sel_ver[2];
	SHA1_CTX context;

	sel_ver[0] = data->selected_version >> 8;
	sel_ver[1] = data->selected_version & 0xff;

	/* MK = SHA1(Identity|n*Kc|NONCE_MT|Version List|Selected Version) */

	SHA1Init(&context);
	SHA1Update(&context, identity, identity_len);
	SHA1Update(&context, data->kc1, KC_LEN);
	SHA1Update(&context, data->kc2, KC_LEN);
	SHA1Update(&context, data->kc3, KC_LEN);
	SHA1Update(&context, data->nonce_mt, NONCE_MT_LEN);
	SHA1Update(&context, data->ver_list, data->ver_list_len);
	SHA1Update(&context, sel_ver, 2);
	SHA1Final(data->mk, &context);
	wpa_hexdump(MSG_DEBUG, "EAP-SIM: MK", data->mk, MK_LEN);
}


static void eap_sim_prf(u8 *key, u8 *x, size_t xlen)
{
	u8 xkey[64];
	u32 t[5], _t[5];
	int i, j, m, k;
	u8 *xpos = x;
	u32 carry;

	/* FIPS 186-2 + change notice 1 */

	memcpy(xkey, key, MK_LEN);
	memset(xkey + MK_LEN, 0, 64 - MK_LEN);
	t[0] = 0x67452301;
	t[1] = 0xEFCDAB89;
	t[2] = 0x98BADCFE;
	t[3] = 0x10325476;
	t[4] = 0xC3D2E1F0;

	m = xlen / 40;
	for (j = 0; j < m; j++) {
		/* XSEED_j = 0 */
		for (i = 0; i < 2; i++) {
			/* XVAL = (XKEY + XSEED_j) mod 2^b */

			/* w_i = G(t, XVAL) */
			memcpy(_t, t, 20);
			sha1_transform((u8 *) _t, xkey);
			_t[0] = htonl(_t[0]);
			_t[1] = htonl(_t[1]);
			_t[2] = htonl(_t[2]);
			_t[3] = htonl(_t[3]);
			_t[4] = htonl(_t[4]);
			memcpy(xpos, _t, 20);

			/* XKEY = (1 + XKEY + w_i) mod 2^b */
			carry = 1;
			for (k = 19; k >= 0; k--) {
				carry += xkey[k] + xpos[k];
				xkey[k] = carry & 0xff;
				carry >>= 8;
			}

			xpos += SHA1_MAC_LEN;
		}
		/* x_j = w_0|w_1 */
	}
}


static void eap_sim_derive_keys(struct eap_sim_data *data)
{
	u8 buf[120], *pos;
	eap_sim_prf(data->mk, buf, 120);
	pos = buf;
	memcpy(data->k_encr, pos, K_ENCR_LEN);
	pos += K_ENCR_LEN;
	memcpy(data->k_aut, pos, K_AUT_LEN);
	pos += K_AUT_LEN;
	memcpy(data->msk, pos, EAP_SIM_KEYING_DATA_LEN);
	pos += MSK_LEN;

	wpa_hexdump(MSG_DEBUG, "EAP-SIM: K_encr", data->k_encr, K_ENCR_LEN);
	wpa_hexdump(MSG_DEBUG, "EAP-SIM: K_aut", data->k_aut, K_ENCR_LEN);
	wpa_hexdump(MSG_DEBUG, "EAP-SIM: MSK", data->msk, MSK_LEN);
	wpa_hexdump(MSG_DEBUG, "EAP-SIM: Ext. MSK",
		    data->msk + MSK_LEN, EMSK_LEN);
	wpa_hexdump(MSG_DEBUG, "EAP-SIM: keying material",
		    data->msk, EAP_SIM_KEYING_DATA_LEN);
}


static int eap_sim_verify_mac(struct eap_sm *sm, struct eap_sim_data *data,
			      u8 *req, size_t req_len, u8 *mac,
			      u8 *extra, size_t extra_len)
{
	unsigned char hmac[SHA1_MAC_LEN];
	unsigned char *addr[2] = { req, extra };
	unsigned int len[2] = { req_len, extra_len };
	u8 rx_mac[EAP_SIM_MAC_LEN];

	/* HMAC-SHA1-128 */
	memcpy(rx_mac, mac, EAP_SIM_MAC_LEN);
	memset(mac, 0, EAP_SIM_MAC_LEN);
	hmac_sha1_vector(data->k_aut, K_AUT_LEN, 2, addr, len, hmac);
	memcpy(mac, rx_mac, EAP_SIM_MAC_LEN);

	return (memcmp(hmac, mac, EAP_SIM_MAC_LEN) == 0) ? 0 : 1;
}


static void eap_sim_add_mac(struct eap_sm *sm, struct eap_sim_data *data,
			    u8 *msg, size_t msg_len, u8 *mac,
			    u8 *extra, size_t extra_len)
{
	unsigned char hmac[SHA1_MAC_LEN];
	unsigned char *addr[2] = { msg, extra };
	unsigned int len[2] = { msg_len, extra_len };

	/* HMAC-SHA1-128 */
	memset(mac, 0, EAP_SIM_MAC_LEN);
	hmac_sha1_vector(data->k_aut, K_AUT_LEN, 2, addr, len, hmac);
	memcpy(mac, hmac, EAP_SIM_MAC_LEN);
}


static u8 * eap_sim_client_error(struct eap_sm *sm, struct eap_sim_data *data,
				 struct eap_hdr *req,
				 size_t *respDataLen, int err)
{
	struct eap_hdr *resp;
	size_t len;
	u8 *pos;

	sm->decision = DECISION_FAIL;
	sm->methodState = METHOD_DONE;

	len = sizeof(struct eap_hdr) + 1 + 3 + 4;

	resp = malloc(len);
	if (resp == NULL)
		return NULL;
	memset(resp, 0, len);
	resp->code = EAP_CODE_RESPONSE;
	resp->identifier = req->identifier;
	resp->length = htons(len);
	pos = (u8 *) (resp + 1);

	*pos++ = EAP_TYPE_SIM;
	*pos++ = EAP_SIM_SUBTYPE_CLIENT_ERROR;
	*pos++ = 0; /* Reserved */
	*pos++ = 0; /* Reserved */

	*pos++ = EAP_SIM_AT_CLIENT_ERROR_CODE;
	*pos++ = 1; /* Length */
	*pos++ = err >> 8;
	*pos++ = err & 0xff;

	*respDataLen = len;
	return (u8 *) resp;
}


enum eap_sim_id_req {
	NO_ID_REQ, ANY_ID, FULLAUTH_ID, PERMANENT_ID
};

static u8 * eap_sim_response_start(struct eap_sm *sm,
				   struct eap_sim_data *data,
				   struct eap_hdr *req,
				   size_t *respDataLen,
				   enum eap_sim_id_req id_req)
{
	struct eap_hdr *resp;
	size_t len;
	u8 *pos;
	struct wpa_ssid *config = sm->eapol->config;
	u8 *identity = NULL;
	size_t identity_len = 0, id_pad = 0;

	len = sizeof(struct eap_hdr) + 1 + 3 + (4 + NONCE_MT_LEN) + 4;
	if (id_req != NO_ID_REQ && config && config->identity) {
		identity = config->identity;
		identity_len = config->identity_len;
		id_pad = 4 - identity_len % 4;
		if (id_pad == 4)
			id_pad = 0;
		len += 4 + identity_len + id_pad;
	}

	resp = malloc(len);
	if (resp == NULL)
		return NULL;
	memset(resp, 0, len);
	resp->code = EAP_CODE_RESPONSE;
	resp->identifier = req->identifier;
	resp->length = htons(len);
	pos = (u8 *) (resp + 1);

	*pos++ = EAP_TYPE_SIM;
	*pos++ = EAP_SIM_SUBTYPE_START;
	*pos++ = 0; /* Reserved */
	*pos++ = 0; /* Reserved */

	*pos++ = EAP_SIM_AT_NONCE_MT;
	*pos++ = 5; /* Length */
	*pos++ = 0; /* Reserved */
	*pos++ = 0; /* Reserved */
	wpa_hexdump(MSG_DEBUG, "EAP-SIM: NONCE_MT",
		    data->nonce_mt, NONCE_MT_LEN);
	memcpy(pos, data->nonce_mt, NONCE_MT_LEN);
	pos += NONCE_MT_LEN;

	*pos++ = EAP_SIM_AT_SELECTED_VERSION;
	*pos++ = 1; /* Length */
	*pos++ = data->selected_version >> 8;
	*pos++ = data->selected_version & 0xff;

	if (identity) {
		u8 alen = 4 + identity_len + id_pad;
		u8 *start = pos;
		*pos++ = EAP_SIM_AT_IDENTITY;
		*pos++ = alen / 4; /* Length */
		*pos++ = identity_len >> 8;
		*pos++ = identity_len & 0xff;
		memcpy(pos, identity, identity_len);
		pos += identity_len;
		memset(pos, 0, id_pad);
		pos += id_pad;
		wpa_hexdump(MSG_DEBUG, "EAP-SIM: AT_IDENTITY",
			    start, pos - start);
	}

	wpa_hexdump(MSG_DEBUG, "EAP-SIM: EAP-Response/SIM/Start",
		    (u8 *) resp, len);

	*respDataLen = len;
	return (u8 *) resp;
}


static u8 * eap_sim_response_challenge(struct eap_sm *sm,
				       struct eap_sim_data *data,
				       struct eap_hdr *req,
				       size_t *respDataLen)
{
	struct eap_hdr *resp;
	size_t len;
	u8 *pos;
	u8 sres[3 * SRES_LEN];

	len = sizeof(struct eap_hdr) + 1 + 3 + (4 + EAP_SIM_MAC_LEN);

	resp = malloc(len);
	if (resp == NULL)
		return NULL;
	memset(resp, 0, len);
	resp->code = EAP_CODE_RESPONSE;
	resp->identifier = req->identifier;
	resp->length = htons(len);
	pos = (u8 *) (resp + 1);

	*pos++ = EAP_TYPE_SIM;
	*pos++ = EAP_SIM_SUBTYPE_CHALLENGE;
	*pos++ = 0; /* Reserved */
	*pos++ = 0; /* Reserved */

	*pos++ = EAP_SIM_AT_MAC;
	*pos++ = 5; /* Length */
	*pos++ = 0; /* Reserved */
	*pos++ = 0; /* Reserved */
	memcpy(sres, data->sres1, SRES_LEN);
	memcpy(sres + SRES_LEN, data->sres2, SRES_LEN);
	memcpy(sres + 2 * SRES_LEN, data->sres3, SRES_LEN);
	eap_sim_add_mac(sm, data, (u8 *) resp, len, pos,
			sres, 3 * SRES_LEN);

	wpa_hexdump(MSG_DEBUG, "EAP-SIM: EAP-Response/SIM/Challenge",
		    (u8 *) resp, len);

	*respDataLen = len;
	return (u8 *) resp;
}


static u8 * eap_sim_process(struct eap_sm *sm, void *priv,
			    u8 *reqData, size_t reqDataLen,
			    size_t *respDataLen)
{
	struct eap_sim_data *data = priv;
	struct wpa_ssid *config = sm->eapol->config;
	struct eap_hdr *req;
	u8 *pos, subtype, *end, *apos;
	size_t alen;
	int i, selected_version = -1;
	u8 *rands = NULL, *mac = NULL;
	size_t num_chal = 0;
	enum eap_sim_id_req id_req = NO_ID_REQ;

	wpa_hexdump(MSG_DEBUG, "EAP-SIM: EAP data", reqData, reqDataLen);
	if (config == NULL || config->identity == NULL) {
		wpa_printf(MSG_INFO, "EAP-SIM: Identity not configured");
		eap_sm_request_identity(sm, config);
		sm->ignore = TRUE;
		return NULL;
	}

	req = (struct eap_hdr *) reqData;
	end = reqData + reqDataLen;
	pos = (u8 *) (req + 1);
	if (reqDataLen < sizeof(*req) + 4 || *pos != EAP_TYPE_SIM) {
		wpa_printf(MSG_INFO, "EAP-SIM: Invalid frame");
		sm->ignore = TRUE;
		return NULL;
	}

	sm->ignore = FALSE;
	sm->methodState = METHOD_CONT;
	sm->allowNotifications = TRUE;

	pos++;
	subtype = *pos++;
	wpa_printf(MSG_DEBUG, "EAP-SIM: Subtype=%d", subtype);
	pos += 2; /* Reserved */

	/* Parse EAP-SIM Attributes */
	while (pos < end) {
		if (pos + 2 > end) {
			wpa_printf(MSG_INFO, "EAP-SIM: Attribute overflow(1)");
			sm->ignore = TRUE;
			return NULL;
		}
		wpa_printf(MSG_DEBUG, "EAP-SIM: Attribute: Type=%d Len=%d",
			   pos[0], pos[1] * 4);
		if (pos + pos[1] * 4 > end) {
			wpa_printf(MSG_INFO, "EAP-SIM: Attribute overflow "
				   "(pos=%p len=%d end=%p)",
				   pos, pos[1] * 4, end);
			sm->ignore = TRUE;
			return NULL;
		}
		apos = pos + 2;
		alen = pos[1] * 4 - 2;
		wpa_hexdump(MSG_DEBUG, "EAP-SIM: Attribute data", apos, alen);

		switch (pos[0]) {
		case EAP_SIM_AT_VERSION_LIST:
		{ 
			int list_len = apos[0] * 256 + apos[1];
			wpa_printf(MSG_DEBUG, "EAP-SIM: AT_VERSION_LIST");
			if (list_len < 2 || list_len - 2 > alen) {
				wpa_printf(MSG_WARNING, "EAP-SIM: Invalid "
					   "AT_VERSION_LIST (list_len=%d "
					   "attr_len=%d)", list_len, alen);
				return eap_sim_client_error(
					sm, data, req, respDataLen,
					EAP_SIM_UNABLE_TO_PROCESS_PACKET);
			}
			apos += 2;
			free(data->ver_list);
			data->ver_list = malloc(list_len);
			if (data->ver_list == NULL) {
				wpa_printf(MSG_DEBUG, "EAP-SIM: Failed to "
					   "allocate memory for version list");
				return eap_sim_client_error(
					sm, data, req, respDataLen,
					EAP_SIM_UNABLE_TO_PROCESS_PACKET);
			}
			memcpy(data->ver_list, apos, list_len);
			data->ver_list_len = list_len;
			for (i = 0; i < list_len / 2; i++) {
				int ver = apos[0] * 256 + apos[1];
				apos += 2;
				if (eap_sim_supported_ver(data, ver)) {
					selected_version = ver;
					break;
				}
			}
			break;
		}
		case EAP_SIM_AT_PERMANENT_ID_REQ:
			wpa_printf(MSG_DEBUG, "EAP-SIM: AT_PERMANENT_ID_REQ");
			id_req = PERMANENT_ID;
			break;
		case EAP_SIM_AT_ANY_ID_REQ:
			wpa_printf(MSG_DEBUG, "EAP-SIM: AT_ANY_ID_REQ");
			id_req = ANY_ID;
			break;
		case EAP_SIM_AT_FULLAUTH_ID_REQ:
			wpa_printf(MSG_DEBUG, "EAP-SIM: AT_FULLAUTH_ID_REQ");
			id_req = FULLAUTH_ID;
			break;
		case EAP_SIM_AT_RAND:
		{
			wpa_printf(MSG_DEBUG, "EAP-SIM: AT_RAND");
			apos += 2;
			alen -= 2;
			if (alen % 16) {
				wpa_printf(MSG_INFO, "EAP-SIM: Invalid AT_RAND"
					   " (rand len %d)", alen);
				return eap_sim_client_error(
					sm, data, req, respDataLen,
					EAP_SIM_UNABLE_TO_PROCESS_PACKET);
			}
			rands = apos;
			num_chal = alen / 16;
			/* TODO: could also accept two challenges */
			if (num_chal < 3) {
				wpa_printf(MSG_INFO, "EAP-SIM: Insufficient "
					   "number of challenges (%d)",
					   num_chal);
				return eap_sim_client_error(
					sm, data, req, respDataLen,
					EAP_SIM_INSUFFICIENT_NUM_OF_CHAL);
			}
			if (num_chal > 3) {
				wpa_printf(MSG_INFO, "EAP-SIM: Too many "
					   "challenges (%d)", num_chal);
				return eap_sim_client_error(
					sm, data, req, respDataLen,
					EAP_SIM_UNABLE_TO_PROCESS_PACKET);
			}

			/* Verify that RANDs are different */
			if (memcmp(apos, apos + GSM_RAND_LEN,
				   GSM_RAND_LEN) == 0 ||
			    (num_chal > 2 &&
			     (memcmp(apos, apos + 2 * GSM_RAND_LEN,
				     GSM_RAND_LEN) == 0 ||
			      memcmp(apos + GSM_RAND_LEN,
				     apos + 2 * GSM_RAND_LEN,
				     GSM_RAND_LEN) == 0))) {
				wpa_printf(MSG_INFO, "EAP-SIM: Same RAND used "
					   "multiple times");
				return eap_sim_client_error(
					sm, data, req, respDataLen,
					EAP_SIM_RAND_NOT_FRESH);
			}

			break;
		}
		case EAP_SIM_AT_MAC:
			wpa_printf(MSG_DEBUG, "EAP-SIM: AT_MAC");
			if (alen != 2 + EAP_SIM_MAC_LEN) {
				wpa_printf(MSG_INFO, "EAP-SIM: Invalid AT_MAC "
					   "length");
				return eap_sim_client_error(
					sm, data, req, respDataLen,
					EAP_SIM_UNABLE_TO_PROCESS_PACKET);
			}
			mac = apos + 2;
			break;
		default:
			if (pos[0] < 128) {
				wpa_printf(MSG_INFO, "EAP-SIM: Unrecognized "
					   "non-skippable attribute %d",
					   pos[0]);
				return eap_sim_client_error(
					sm, data, req, respDataLen,
					EAP_SIM_UNABLE_TO_PROCESS_PACKET);
			}

			wpa_printf(MSG_DEBUG, "EAP-SIM: Unrecognized skippable"
				   " attribute %d ignored", pos[0]);
			break;
		}

		pos += pos[1] * 4;
	}

	switch (subtype) {
	case EAP_SIM_SUBTYPE_START:
		wpa_printf(MSG_DEBUG, "EAP-SIM: subtype Start");
		if (selected_version < 0) {
			wpa_printf(MSG_INFO, "EAP-SIM: Could not find "
				   "supported version");
			return eap_sim_client_error(
				sm, data, req, respDataLen,
				EAP_SIM_UNSUPPORTED_VERSION);
		}
		wpa_printf(MSG_DEBUG, "EAP-SIM: Selected Version %d",
			   selected_version);
		data->selected_version = selected_version;
		return eap_sim_response_start(sm, data, req, respDataLen,
					      id_req);
	case EAP_SIM_SUBTYPE_CHALLENGE:
		wpa_printf(MSG_DEBUG, "EAP-SIM: subtype Challenge");
		if (!mac) {
			wpa_printf(MSG_WARNING, "EAP-SIM: Challenge message "
				   "did not include AT_MAC");
			return eap_sim_client_error(
				sm, data, req, respDataLen,
				EAP_SIM_UNABLE_TO_PROCESS_PACKET);
		}
		if (!rands || num_chal != 3) {
			wpa_printf(MSG_WARNING, "EAP-SIM: Challenge message "
				   "did not include valid AT_RAND");
			return eap_sim_client_error(
				sm, data, req, respDataLen,
				EAP_SIM_UNABLE_TO_PROCESS_PACKET);
		}
		memcpy(data->rand1, rands, GSM_RAND_LEN);
		memcpy(data->rand2, rands + GSM_RAND_LEN, GSM_RAND_LEN);
		memcpy(data->rand3, rands + 2 * GSM_RAND_LEN, GSM_RAND_LEN);

		eap_sim_gsm_auth(sm, data);
		eap_sim_derive_mk(data,
				  config->identity, config->identity_len);
		eap_sim_derive_keys(data);
		if (eap_sim_verify_mac(sm, data, reqData, reqDataLen, mac,
				       data->nonce_mt, NONCE_MT_LEN)) {
			wpa_printf(MSG_WARNING, "EAP-SIM: Challenge message "
				   "used invalid AT_MAC");
			return eap_sim_client_error(
				sm, data, req, respDataLen,
				EAP_SIM_UNABLE_TO_PROCESS_PACKET);
		}

		sm->decision = DECISION_UNCOND_SUCC;
		sm->methodState = METHOD_DONE;
		free(sm->eapKeyData);
		sm->eapKeyData = malloc(EAP_SIM_KEYING_DATA_LEN);
		if (sm->eapKeyData) {
			sm->eapKeyDataLen = EAP_SIM_KEYING_DATA_LEN;
			memcpy(sm->eapKeyData, data->msk,
			       EAP_SIM_KEYING_DATA_LEN);
		}

		return eap_sim_response_challenge(sm, data, req, respDataLen);
	case EAP_SIM_SUBTYPE_NOTIFICATION:
		wpa_printf(MSG_DEBUG, "EAP-SIM: subtype Notification");
		break;
	case EAP_SIM_SUBTYPE_RE_AUTHENTICATION:
		wpa_printf(MSG_DEBUG, "EAP-SIM: subtype Re-authentication");
		break;
	case EAP_SIM_SUBTYPE_CLIENT_ERROR:
		wpa_printf(MSG_DEBUG, "EAP-SIM: subtype Client-Error");
		break;
	default:
		wpa_printf(MSG_DEBUG, "EAP-SIM: Unknown subtype=%d", subtype);
		break;
	}

	sm->ignore = TRUE;
	return NULL;
}


const struct eap_method eap_method_sim =
{
	.method = EAP_TYPE_SIM,
	.init = eap_sim_init,
	.deinit = eap_sim_deinit,
	.process = eap_sim_process,
};
