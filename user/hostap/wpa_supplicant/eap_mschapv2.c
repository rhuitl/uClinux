/*
 * WPA Supplicant / EAP-MSCHAPV2 (draft-kamath-pppext-eap-mschapv2-00.txt)
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
#include "ms_funcs.h"


struct eap_mschapv2_hdr {
	u8 code;
	u8 identifier;
	u16 length; /* including code, identifier, and length */
	u8 type; /* EAP_TYPE_MSCHAPV2 */
	u8 op_code; /* MSCHAPV2_OP_* */
	u8 mschapv2_id; /* usually same as identifier */
	u8 ms_length[2]; /* Note: misaligned; length - 5 */
	/* followed by data */
} __attribute__ ((packed));

#define MSCHAPV2_OP_CHALLENGE 1
#define MSCHAPV2_OP_RESPONSE 2
#define MSCHAPV2_OP_SUCCESS 3
#define MSCHAPV2_OP_FAILURE 4
#define MSCHAPV2_OP_CHANGE_PASSWORD 7

#define MSCHAPV2_RESP_LEN 49

#define ERROR_RESTRICTED_LOGON_HOURS 646
#define ERROR_ACCT_DISABLED 647
#define ERROR_PASSWD_EXPIRED 648
#define ERROR_NO_DIALIN_PERMISSION 649
#define ERROR_AUTHENTICATION_FAILURE 691
#define ERROR_CHANGING_PASSWORD 709

#define PASSWD_CHANGE_CHAL_LEN 16


struct eap_mschapv2_data {
	u8 auth_response[20];
	int auth_response_valid;

	int prev_error;
	u8 passwd_change_challenge[PASSWD_CHANGE_CHAL_LEN];
	int passwd_change_challenge_valid;
	int passwd_change_version;
};


static void * eap_mschapv2_init(struct eap_sm *sm)
{
	struct eap_mschapv2_data *data;
	data = malloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	memset(data, 0, sizeof(*data));
	return data;
}


static void eap_mschapv2_deinit(struct eap_sm *sm, void *priv)
{
	struct eap_mschapv2_data *data = priv;
	free(data);
}


static u8 * eap_mschapv2_challenge(struct eap_sm *sm,
				   struct eap_mschapv2_data *data,
				   struct eap_mschapv2_hdr *req,
				   size_t *respDataLen)
{
	struct wpa_ssid *config = sm->eapol->config;
	u8 *challenge, *peer_challenge, *username, *pos;
	int challenge_len, i, ms_len;
	size_t len, username_len;
	struct eap_mschapv2_hdr *resp;

	/* MSCHAPv2 does not include optional domain name in the
	 * challenge-response calculation, so remove domain prefix
	 * (if present). */
	username = config->identity;
	username_len = config->identity_len;
	pos = username;
	for (i = 0; i < username_len; i++) {
		if (username[i] == '\\') {
			username_len -= i + 1;
			username += i + 1;
			break;
		}
	}

	wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: Received challenge");
	len = ntohs(req->length);
	pos = (u8 *) (req + 1);
	challenge_len = *pos++;
	if (challenge_len != 16) {
		wpa_printf(MSG_INFO, "EAP-MSCHAPV2: Invalid challenge length "
			   "%d", challenge_len);
		sm->ignore = TRUE;
		return NULL;
	}

	if (len - challenge_len - 10 < 0) {
		wpa_printf(MSG_INFO, "EAP-MSCHAPV2: Too short challenge"
			   " packet: len=%d challenge_len=%d",
			   len, challenge_len);
	}

	challenge = pos;
	pos += challenge_len;
	wpa_hexdump_ascii(MSG_DEBUG, "EAP-MSCHAPV2: Authentication Servername",
		    pos, len - challenge_len - 10);

	sm->methodState = METHOD_CONT;
	sm->decision = DECISION_FAIL;
	sm->ignore = FALSE;
	sm->allowNotifications = TRUE;

	wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: Generating Challenge Response");

	*respDataLen = sizeof(*resp) + 1 + MSCHAPV2_RESP_LEN +
		config->identity_len;
	resp = malloc(*respDataLen);
	if (resp == NULL)
		return NULL;
	memset(resp, 0, *respDataLen);
	resp->code = EAP_CODE_RESPONSE;
	resp->identifier = req->identifier;
	resp->length = htons(*respDataLen);
	resp->type = EAP_TYPE_MSCHAPV2;
	resp->op_code = MSCHAPV2_OP_RESPONSE;
	resp->mschapv2_id = req->mschapv2_id;
	ms_len = *respDataLen - 5;
	resp->ms_length[0] = ms_len >> 8;
	resp->ms_length[1] = ms_len & 0xff;
	pos = (u8 *) (resp + 1);
	*pos++ = MSCHAPV2_RESP_LEN; /* Value-Size */

	/* Response */
	peer_challenge = pos;
	if (hostapd_get_rand(peer_challenge, 16)) {
		free(resp);
		return NULL;
	}
	pos += 16;
	pos += 8; /* Reserved, must be zero */
	wpa_hexdump(MSG_DEBUG, "EAP-MSCHAPV2: auth_challenge", challenge, 16);
	wpa_hexdump(MSG_DEBUG, "EAP-MSCHAPV2: peer_challenge",
		    peer_challenge, 16);
	wpa_hexdump_ascii(MSG_DEBUG, "EAP-MSCHAPV2: username",
			  username, username_len);
	wpa_hexdump_ascii(MSG_DEBUG, "EAP-MSCHAPV2: password",
			  config->password, config->password_len);
	generate_nt_response(challenge, peer_challenge,
			     username, username_len,
			     config->password, config->password_len,
			     pos);
	wpa_hexdump(MSG_DEBUG, "EAP-MSCHAPV2: response", pos, 24);
	/* Authenticator response is not really needed yet, but calculate it
	 * here so that challenges need not be saved. */
	generate_authenticator_response(config->password, config->password_len,
					peer_challenge, challenge,
					username, username_len, pos,
					data->auth_response);
	data->auth_response_valid = 1;
	pos += 24;
	pos++; /* Flag / reserved, must be zero */

	memcpy(pos, config->identity, config->identity_len);
	return (u8 *) resp;
}


static u8 * eap_mschapv2_success(struct eap_sm *sm,
				 struct eap_mschapv2_data *data,
				 struct eap_mschapv2_hdr *req,
				 size_t *respDataLen)
{
	struct eap_mschapv2_hdr *resp;
	u8 *pos, recv_response[20];
	int len, left;

	wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: Received success");
	len = ntohs(req->length);
	pos = (u8 *) (req + 1);
	if (!data->auth_response_valid || len < sizeof(*req) + 42 ||
	    pos[0] != 'S' || pos[1] != '=' ||
	    hexstr2bin(pos + 2, recv_response, 20) ||
	    memcmp(data->auth_response, recv_response, 20) != 0) {
		wpa_printf(MSG_WARNING, "EAP-MSCHAPV2: Invalid authenticator "
			   "response in success request");
		sm->methodState = METHOD_DONE;
		sm->decision = DECISION_FAIL;
		sm->ignore = TRUE;
		return NULL;
	}
	pos += 42;
	left = len - sizeof(*req) - 42;
	while (left > 0 && *pos == ' ') {
		pos++;
		left--;
	}
	wpa_hexdump(MSG_DEBUG, "EAP-MSCHAPV2: Success message", pos, left);
	wpa_printf(MSG_INFO, "EAP-MSCHAPV2: Authentication succeeded");
	*respDataLen = 6;
	resp = malloc(6);
	if (resp == NULL) {
		sm->ignore = TRUE;
		return NULL;
	}

	resp->code = EAP_CODE_RESPONSE;
	resp->identifier = req->identifier;
	resp->length = htons(6);
	resp->type = EAP_TYPE_MSCHAPV2;
	resp->op_code = MSCHAPV2_OP_SUCCESS;

	sm->methodState = METHOD_DONE;
	sm->decision = DECISION_UNCOND_SUCC;
	sm->ignore = FALSE;

	/* EAP-MSCHAPV2 can be used generate keying data. However, this is not
	 * used with EAP-PEAP, so no need to fill in sm->eapKeyData here. */

	return (u8 *) resp;
}


static int eap_mschapv2_failure_txt(struct eap_sm *sm,
				    struct eap_mschapv2_data *data, char *txt)
{
	char *pos, *msg = "";
	int retry = 1;
	struct wpa_ssid *config = sm->eapol->config;

	/* For example:
	 * E=691 R=1 C=<32 octets hex challenge> V=3 M=Authentication Failure
	 */

	pos = txt;

	if (pos && strncmp(pos, "E=", 2) == 0) {
		pos += 2;
		data->prev_error = atoi(pos);
		wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: error %d",
			   data->prev_error);
		pos = strchr(pos, ' ');
		if (pos)
			pos++;
	}

	if (pos && strncmp(pos, "R=", 2) == 0) {
		pos += 2;
		retry = atoi(pos);
		wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: retry is %sallowed",
			   retry == 1 ? "" : "not ");
		pos = strchr(pos, ' ');
		if (pos)
			pos++;
	}

	if (pos && strncmp(pos, "C=", 2) == 0) {
		int hex_len;
		pos += 2;
		hex_len = strchr(pos, ' ') - (char *) pos;
		if (hex_len == PASSWD_CHANGE_CHAL_LEN * 2) {
			if (hexstr2bin(pos, data->passwd_change_challenge,
				       PASSWD_CHANGE_CHAL_LEN)) {
				wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: invalid "
					   "failure challenge");
			} else {
				wpa_hexdump(MSG_DEBUG, "EAP-MSCHAPV2: failure "
					    "challenge",
					    data->passwd_change_challenge,
					    PASSWD_CHANGE_CHAL_LEN);
				data->passwd_change_challenge_valid = 1;
			}
		} else {
			wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: invalid failure "
				   "challenge len %d", hex_len);
		}
		pos = strchr(pos, ' ');
		if (pos)
			pos++;
	} else {
		wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: required challenge field "
			   "was not present in failure message");
	}

	if (pos && strncmp(pos, "V=", 2) == 0) {
		pos += 2;
		data->passwd_change_version = atoi(pos);
		wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: password changing "
			   "protocol version %d", data->passwd_change_version);
		pos = strchr(pos, ' ');
		if (pos)
			pos++;
	}

	if (pos && strncmp(pos, "M=", 2) == 0) {
		pos += 2;
		msg = pos;
	}
	wpa_msg(sm->eapol->ctx->msg_ctx, MSG_WARNING,
		"EAP-MSCHAPV2: failure message: '%s' (retry %sallowed, error "
		"%d)",
		msg, retry == 1 ? "" : "not ", data->prev_error);
	if (retry == 1 && config) {
		/* TODO: could prevent the current password from being used
		 * again at least for some period of time */
		eap_sm_request_identity(sm, config);
		eap_sm_request_password(sm, config);
	} else if (config) {
		/* TODO: prevent retries using same username/password */
	}

	return retry == 1;
}


static u8 * eap_mschapv2_failure(struct eap_sm *sm,
				 struct eap_mschapv2_data *data,
				 struct eap_mschapv2_hdr *req,
				 size_t *respDataLen)
{
	struct eap_mschapv2_hdr *resp;
	u8 *msdata = (u8 *) (req + 1);
	char *buf;
	int len = ntohs(req->length) - sizeof(*req);
	int retry = 0;

	wpa_printf(MSG_DEBUG, "EAP-MSCHAPV2: Received failure");
	wpa_hexdump_ascii(MSG_DEBUG, "EAP-MSCHAPV2: Failure data",
			  msdata, len);
	buf = malloc(len + 1);
	if (buf) {
		memcpy(buf, msdata, len);
		buf[len] = '\0';
		retry = eap_mschapv2_failure_txt(sm, data, buf);
		free(buf);
	}

	/* EAP-PEAP uses tunneled failure message, so do not marked method done
	 * here for PEAP. */
	if (sm->selectedMethod != EAP_TYPE_PEAP)
		sm->methodState = METHOD_DONE;
	sm->decision = DECISION_FAIL;
	sm->ignore = FALSE;

	if (retry) {
		/* TODO: could try to retry authentication, e.g, after having
		 * changed the username/password. In this case, EAP MS-CHAP-v2
		 * Failure Response would not be sent here. */
	}

	*respDataLen = 6;
	resp = malloc(6);
	if (resp == NULL) {
		sm->ignore = TRUE;
		return NULL;
	}

	resp->code = EAP_CODE_RESPONSE;
	resp->identifier = req->identifier;
	resp->length = htons(6);
	resp->type = EAP_TYPE_MSCHAPV2;
	resp->op_code = MSCHAPV2_OP_FAILURE;

	return (u8 *) resp;
}


static u8 * eap_mschapv2_process(struct eap_sm *sm, void *priv,
				 u8 *reqData, size_t reqDataLen,
				 size_t *respDataLen)
{
	struct eap_mschapv2_data *data = priv;
	struct wpa_ssid *config = sm->eapol->config;
	struct eap_mschapv2_hdr *req;
	int ms_len, len;

	if (config == NULL || config->identity == NULL) {
		wpa_printf(MSG_INFO, "EAP-MSCHAPV2: Identity not configured");
		eap_sm_request_identity(sm, config);
		sm->ignore = TRUE;
		return NULL;
	}

	if (config->password == NULL) {
		wpa_printf(MSG_INFO, "EAP-MSCHAPV2: Password not configured");
		eap_sm_request_password(sm, config);
		sm->ignore = TRUE;
		return NULL;
	}

	req = (struct eap_mschapv2_hdr *) reqData;
	len = ntohs(req->length);
	if (len < sizeof(*req) + 2 || req->type != EAP_TYPE_MSCHAPV2) {
		wpa_printf(MSG_INFO, "EAP-MSCHAPV2: Invalid frame");
		sm->ignore = TRUE;
		return NULL;
	}

	ms_len = ((int) req->ms_length[0] << 8) | req->ms_length[1];
	if (ms_len != len - 5) {
		wpa_printf(MSG_INFO, "EAP-MSCHAPV2: Invalid header: len=%d "
			   "ms_len=%d", len, ms_len);
		/* TODO: could make this workaround configurable */
		if (1 /* workaround */) {
			/* Some authentication servers use invalid ms_len,
			 * ignore it for interoperability. */
			wpa_printf(MSG_INFO, "EAP-MSCHAPV2: workaround, ignore"
				   " invalid ms_len");
		} else {
			sm->ignore = TRUE;
			return NULL;
		}
	}

	switch (req->op_code) {
	case MSCHAPV2_OP_CHALLENGE:
		return eap_mschapv2_challenge(sm, data, req, respDataLen);
	case MSCHAPV2_OP_SUCCESS:
		return eap_mschapv2_success(sm, data, req, respDataLen);
	case MSCHAPV2_OP_FAILURE:
		return eap_mschapv2_failure(sm, data, req, respDataLen);
	default:
		wpa_printf(MSG_INFO, "EAP-MSCHAPV2: Unknown op %d - ignored",
			   req->op_code);
		sm->ignore = TRUE;
		return NULL;
	}
}


const struct eap_method eap_method_mschapv2 =
{
	.method = EAP_TYPE_MSCHAPV2,
	.init = eap_mschapv2_init,
	.deinit = eap_mschapv2_deinit,
	.process = eap_mschapv2_process,
};
