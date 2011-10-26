/*
 * WPA Supplicant / EAP-MD5
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
#include <netinet/in.h>

#include "common.h"
#include "eapol_sm.h"
#include "eap.h"
#include "wpa_supplicant.h"
#include "config.h"
#include "md5.h"


static void * eap_md5_init(struct eap_sm *sm)
{
	return (void *) 1;
}


static void eap_md5_deinit(struct eap_sm *sm, void *priv)
{
}


static u8 * eap_md5_process(struct eap_sm *sm, void *priv,
			    u8 *reqData, size_t reqDataLen,
			    size_t *respDataLen)
{
	struct wpa_ssid *config = sm->eapol->config;
	struct eap_hdr *req, *resp;
	u8 *pos, *challenge;
	int challenge_len;
	MD5_CTX context;

	if (config == NULL || config->password == NULL) {
		wpa_printf(MSG_INFO, "EAP-MD5: Password not configured");
		eap_sm_request_password(sm, config);
		sm->ignore = TRUE;
		return NULL;
	}

	req = (struct eap_hdr *) reqData;
	pos = (u8 *) (req + 1);
	if (reqDataLen < sizeof(*req) + 2 || *pos != EAP_TYPE_MD5) {
		wpa_printf(MSG_INFO, "EAP-MD5: Invalid frame");
		sm->ignore = TRUE;
		return NULL;
	}
	pos++;
	challenge_len = *pos++;
	if (challenge_len == 0 ||
	    challenge_len > reqDataLen - sizeof(*req) - 1) {
		wpa_printf(MSG_INFO, "EAP-MD5: Invalid challenge "
			   "(challenge_len=%d reqDataLen=%d",
			   challenge_len, reqDataLen);
		sm->ignore = TRUE;
		return NULL;
	}
	sm->ignore = FALSE;
	challenge = pos;
	wpa_hexdump(MSG_MSGDUMP, "EAP-MD5: Challenge",
		    challenge, challenge_len);

	wpa_printf(MSG_DEBUG, "EAP-MD5: generating Challenge Response");
	sm->methodState = METHOD_DONE;
	sm->decision = DECISION_UNCOND_SUCC;
	sm->allowNotifications = TRUE;

	*respDataLen = sizeof(struct eap_hdr) + 1 + 1 + MD5_MAC_LEN;
	resp = malloc(*respDataLen);
	if (resp == NULL)
		return NULL;
	resp->code = EAP_CODE_RESPONSE;
	resp->identifier = req->identifier;
	resp->length = htons(*respDataLen);
	pos = (u8 *) (resp + 1);
	*pos++ = EAP_TYPE_MD5;
	*pos++ = MD5_MAC_LEN; /* Value-Size */

	MD5Init(&context);
	MD5Update(&context, &resp->identifier, 1);
	MD5Update(&context, config->password, config->password_len);
	MD5Update(&context, challenge, challenge_len);
	MD5Final(pos, &context);
	wpa_hexdump(MSG_MSGDUMP, "EAP-MD5: Response", pos, MD5_MAC_LEN);

	/* EAP-MD5 does not generate keying data, so eapKeyData is never filled
	 * here */

	return (u8 *) resp;
}


const struct eap_method eap_method_md5 =
{
	.method = EAP_TYPE_MD5,
	.init = eap_md5_init,
	.deinit = eap_md5_deinit,
	.process = eap_md5_process,
};
