/*
 * WPA Supplicant / EAP-TLS (RFC 2716)
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
#include "eap_tls_common.h"
#include "wpa_supplicant.h"
#include "config.h"


static void eap_tls_deinit(struct eap_sm *sm, void *priv);


struct eap_tls_data {
	struct eap_ssl_data ssl;
};


static void * eap_tls_init(struct eap_sm *sm)
{
	struct eap_tls_data *data;
	struct wpa_ssid *config = sm->eapol->config;
	if (config == NULL ||
	    (sm->init_phase2 ? config->client_cert2 : config->client_cert)
	    == NULL) {
		wpa_printf(MSG_INFO, "EAP-TLS: Client certificate not "
			   "configured");
		return NULL;
	}

	data = malloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	memset(data, 0, sizeof(*data));

	if (eap_tls_ssl_init(sm, &data->ssl, config)) {
		wpa_printf(MSG_INFO, "EAP-TLS: Failed to initialize SSL.");
		eap_tls_deinit(sm, data);
		return NULL;
	}

	return data;
}


static void eap_tls_deinit(struct eap_sm *sm, void *priv)
{
	struct eap_tls_data *data = priv;
	if (data == NULL)
		return;
	if (data->ssl.ssl)
		SSL_free(data->ssl.ssl);
	free(data);
}


static u8 * eap_tls_process(struct eap_sm *sm, void *priv,
			    u8 *reqData, size_t reqDataLen,
			    size_t *respDataLen)
{
	struct eap_hdr *req;
	unsigned long err;
	int left, res;
	unsigned int tls_msg_len;
	u8 flags, *pos, *resp, id;
	struct eap_tls_data *data = priv;

	err = ERR_get_error();
	if (err != 0) {
		do {
			wpa_printf(MSG_INFO, "EAP-TLS - SSL error: %s",
				   ERR_error_string(err, NULL));
			err = ERR_get_error();
		} while (err != 0);
		sm->ignore = TRUE;
		return NULL;
	}

	req = (struct eap_hdr *) reqData;
	pos = (u8 *) (req + 1);
	if (reqDataLen < sizeof(*req) + 2 || *pos != EAP_TYPE_TLS) {
		wpa_printf(MSG_INFO, "EAP-TLS: Invalid frame");
		sm->ignore = TRUE;
		return NULL;
	}
	id = req->identifier;
	pos++;
	flags = *pos++;
	left = htons(req->length) - sizeof(struct eap_hdr) - 2;
	wpa_printf(MSG_DEBUG, "EAP-TLS: Received packet(len=%d) - "
		   "Flags 0x%02x", reqDataLen, flags);
	if (flags & EAP_TLS_FLAGS_LENGTH_INCLUDED) {
		if (left < 4) {
			wpa_printf(MSG_INFO, "EAP-TLS: Short frame with TLS "
				   "length");
			sm->ignore = TRUE;
			return NULL;
		}
		tls_msg_len = (pos[0] << 24) | (pos[1] << 16) | (pos[2] << 8) |
			pos[3];
		wpa_printf(MSG_DEBUG, "EAP-TLS: TLS Message Length: %d",
			   tls_msg_len);
		if (data->ssl.tls_in_left == 0)
			data->ssl.tls_in_left = tls_msg_len;
		pos += 4;
		left -= 4;
	}

	sm->ignore = FALSE;

	sm->methodState = METHOD_CONT;
	sm->decision = DECISION_COND_SUCC;
	sm->allowNotifications = TRUE;

	if (flags & EAP_TLS_FLAGS_START) {
		wpa_printf(MSG_DEBUG, "EAP-TLS: Start");
		left = 0; /* make sure that this frame is empty, even though it
			   * should always be, anyway */
	}

	resp = NULL;
	res = eap_tls_process_helper(sm, &data->ssl, EAP_TYPE_TLS, 0, id, pos,
				     left, &resp, respDataLen);

	if (SSL_is_init_finished(data->ssl.ssl)) {
		wpa_printf(MSG_DEBUG, "EAP-TLS: Done");
		sm->methodState = METHOD_DONE;
		sm->decision = DECISION_UNCOND_SUCC;
		if (data->ssl.phase2) {
			u8 *key;
			/* TODO: clean this up.. Move key data to private
			 * method struct and fill sm->eapKey from eap.c using
			 * a new getKey func registered by the EAP method. */
			key = eap_tls_derive_key(
				data->ssl.ssl, "client EAP encryption");
			if (key) {
				wpa_hexdump(MSG_DEBUG, "EAP-TLS: Derived "
					    "Phase2 key",
					    key, EAP_TLS_KEY_LEN);
				free(key);
			} else {
				wpa_printf(MSG_DEBUG,
					   "EAP-TLS: Failed to derive Phase2 "
					   "key");
			}
		} else {
			free(sm->eapKeyData);
			sm->eapKeyData = eap_tls_derive_key(
				data->ssl.ssl, "client EAP encryption");
			if (sm->eapKeyData) {
				sm->eapKeyDataLen = EAP_TLS_KEY_LEN;
				wpa_hexdump(MSG_DEBUG, "EAP-TLS: Derived key",
					    sm->eapKeyData, sm->eapKeyDataLen);
			} else {
				wpa_printf(MSG_DEBUG,
					   "EAP-TLS: Failed to derive key");
			}
		}
	}

	if (res == 1)
		return eap_tls_build_ack(respDataLen, id, EAP_TYPE_TLS, 0);
	return resp;
}


const struct eap_method eap_method_tls =
{
	.method = EAP_TYPE_TLS,
	.init = eap_tls_init,
	.deinit = eap_tls_deinit,
	.process = eap_tls_process,
};
