/*
 * WPA Supplicant / EAP-TTLS (draft-ietf-pppext-eap-ttls-03.txt)
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
#include "ms_funcs.h"
#include "md5.h"

struct ttls_avp {
	u32 avp_code;
	u32 avp_length; /* 8-bit flags, 24-bit length;
			 * length includes AVP header */
	/* optional 32-bit Vendor-ID */
	/* Data */
};

struct ttls_avp_vendor {
	u32 avp_code;
	u32 avp_length; /* 8-bit flags, 24-bit length;
			 * length includes AVP header */
	u32 vendor_id;
	/* Data */
};

#define AVP_FLAGS_VENDOR 0x80
#define AVP_FLAGS_MANDATORY 0x40

#define AVP_PAD(start, pos) \
do { \
	int pad; \
	pad = (4 - (((pos) - (start)) & 3)) & 3; \
	memset((pos), 0, pad); \
	pos += pad; \
} while(0)


/* RFC 2865 */
#define RADIUS_ATTR_USER_NAME 1
#define RADIUS_ATTR_USER_PASSWORD 2
#define RADIUS_ATTR_CHAP_PASSWORD 3
#define RADIUS_ATTR_REPLY_MESSAGE 18
#define RADIUS_ATTR_CHAP_CHALLENGE 60
#define RADIUS_ATTR_EAP_MESSAGE 79

/* RFC 2548 */
#define RADIUS_VENDOR_ID_MICROSOFT 311
#define RADIUS_ATTR_MS_CHAP_RESPONSE 1
#define RADIUS_ATTR_MS_CHAP_NT_ENC_PW 6
#define RADIUS_ATTR_MS_CHAP_CHALLENGE 11
#define RADIUS_ATTR_MS_CHAP2_RESPONSE 25
#define RADIUS_ATTR_MS_CHAP2_SUCCESS 26
#define RADIUS_ATTR_MS_CHAP2_CPW 27

#define EAP_TTLS_MSCHAPV2_CHALLENGE_LEN 16
#define EAP_TTLS_MSCHAPV2_RESPONSE_LEN 50
#define EAP_TTLS_MSCHAP_CHALLENGE_LEN 8
#define EAP_TTLS_MSCHAP_RESPONSE_LEN 50
#define EAP_TTLS_CHAP_CHALLENGE_LEN 16
#define EAP_TTLS_CHAP_PASSWORD_LEN 16


static void eap_ttls_deinit(struct eap_sm *sm, void *priv);


struct eap_ttls_data {
	struct eap_ssl_data ssl;

	const struct eap_method *phase2_method;
	void *phase2_priv;
	int phase2_success;
	int phase2_start;

	enum {
		EAP_TTLS_PHASE2_EAP,
		EAP_TTLS_PHASE2_MSCHAPV2,
		EAP_TTLS_PHASE2_MSCHAP,
		EAP_TTLS_PHASE2_PAP,
		EAP_TTLS_PHASE2_CHAP,
	} phase2_type;
	u8 phase2_eap_type;

	u8 auth_response[20];
	int auth_response_valid;
	u8 ident;
};


static void * eap_ttls_init(struct eap_sm *sm)
{
	struct eap_ttls_data *data;
	struct wpa_ssid *config = sm->eapol->config;
	char *selected;

	data = malloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	memset(data, 0, sizeof(*data));
	selected = "EAP-MD5";
	data->phase2_type = EAP_TTLS_PHASE2_EAP;
	data->phase2_eap_type = EAP_TYPE_MD5;
	if (config && config->phase2) {
		if (strstr(config->phase2, "auth=MSCHAPV2")) {
			selected = "MSCHAPV2";
			data->phase2_type = EAP_TTLS_PHASE2_MSCHAPV2;
		} else if (strstr(config->phase2, "auth=MSCHAP")) {
			selected = "MSCHAP";
			data->phase2_type = EAP_TTLS_PHASE2_MSCHAP;
		} else if (strstr(config->phase2, "auth=PAP")) {
			selected = "PAP";
			data->phase2_type = EAP_TTLS_PHASE2_PAP;
		} else if (strstr(config->phase2, "auth=CHAP")) {
			selected = "CHAP";
			data->phase2_type = EAP_TTLS_PHASE2_CHAP;
		}
	}
	if (data->phase2_type == EAP_TTLS_PHASE2_EAP &&
	    config && config->phase2) {
		if (strstr(config->phase2, "autheap=MSCHAPV2")) {
			data->phase2_eap_type = EAP_TYPE_MSCHAPV2;
			selected = "EAP-MSCHAPV2";
		} else if (strstr(config->phase2, "autheap=GTC")) {
			data->phase2_eap_type = EAP_TYPE_GTC;
			selected = "EAP-GTC";
		} else if (strstr(config->phase2, "autheap=OTP")) {
			data->phase2_eap_type = EAP_TYPE_OTP;
			selected = "EAP-OTP";
		} else if (strstr(config->phase2, "autheap=TLS")) {
			data->phase2_eap_type = EAP_TYPE_TLS;
			selected = "EAP-TLS";
		}
	}
	wpa_printf(MSG_DEBUG, "EAP-TTLS: Phase2 type: %s", selected);

	if (eap_tls_ssl_init(sm, &data->ssl, config)) {
		wpa_printf(MSG_INFO, "EAP-TTLS: Failed to initialize SSL.");
		eap_ttls_deinit(sm, data);
		return NULL;
	}

	return data;
}


static void eap_ttls_deinit(struct eap_sm *sm, void *priv)
{
	struct eap_ttls_data *data = priv;
	if (data == NULL)
		return;
	if (data->phase2_priv && data->phase2_method)
		data->phase2_method->deinit(sm, data->phase2_priv);
	if (data->ssl.ssl)
		SSL_free(data->ssl.ssl);
	free(data);
}


static int eap_ttls_encrypt(struct eap_sm *sm, struct eap_ttls_data *data,
			    int id, u8 *plain, size_t plain_len,
			    u8 **out_data, size_t *out_len)
{
	int res;
	u8 *pos;
	struct eap_hdr *resp;

	BIO_reset(data->ssl.ssl_in);
	BIO_reset(data->ssl.ssl_out);
	res = SSL_write(data->ssl.ssl, plain, plain_len);
	if (res < 0) {
		int err = SSL_get_error(data->ssl.ssl, res);
		wpa_printf(MSG_INFO, "EAP-TTLS: SSL_write error %d", err);
		return 0;
	}

	/* TODO: add support for fragmentation, if needed. This will need to
	 * add TLS Message Length field, if the frame is fragmented. */
	resp = malloc(sizeof(struct eap_hdr) + 2 + data->ssl.tls_out_limit);
	if (resp == NULL)
		return 0;

	resp->code = EAP_CODE_RESPONSE;
	resp->identifier = id;

	pos = (u8 *) (resp + 1);
	*pos++ = EAP_TYPE_TTLS;
	*pos++ = 0;

	res = BIO_read(data->ssl.ssl_out, pos, data->ssl.tls_out_limit);
	if (res < 0) {
		free(resp);
		return 0;
	}

	*out_len = sizeof(struct eap_hdr) + 2 + res;
	resp->length = htons(*out_len);
	*out_data = (u8 *) resp;
	return 0;
}


static u8 * eap_ttls_avp_hdr(u8 *avphdr, u32 avp_code, u32 vendor_id,
			     int mandatory, size_t len)
{
	struct ttls_avp_vendor *avp;
	u8 flags;
	size_t hdrlen;

	avp = (struct ttls_avp_vendor *) avphdr;
	flags = mandatory ? AVP_FLAGS_MANDATORY : 0;
	if (vendor_id) {
		flags |= AVP_FLAGS_VENDOR;
		hdrlen = sizeof(*avp);
		avp->vendor_id = htonl(vendor_id);
	} else {
		hdrlen = sizeof(struct ttls_avp);
	}

	avp->avp_code = htonl(avp_code);
	avp->avp_length = htonl((flags << 24) | (hdrlen + len));

	return avphdr + hdrlen;
}


static u8 * eap_ttls_avp_add(u8 *start, u8 *avphdr, u32 avp_code,
			     u32 vendor_id, int mandatory,
			     u8 *data, size_t len)
{
	u8 *pos;
	pos = eap_ttls_avp_hdr(avphdr, avp_code, vendor_id, mandatory, len);
	memcpy(pos, data, len);
	pos += len;
	AVP_PAD(start, pos);
	return pos;
}


static int eap_ttls_avp_encapsulate(u8 **resp, size_t *resp_len, u32 avp_code,
				    int mandatory)
{
	u8 *avp, *pos;

	avp = malloc(sizeof(struct ttls_avp) + *resp_len + 4);
	if (avp == NULL) {
		free(*resp);
		*resp_len = 0;
		return -1;
	}

	pos = eap_ttls_avp_hdr(avp, avp_code, 0, mandatory, *resp_len);
	memcpy(pos, *resp, *resp_len);
	pos += *resp_len;
	AVP_PAD(avp, pos);
	free(*resp);
	*resp = avp;
	*resp_len = pos - avp;
	return 0;
}


static int eap_ttls_phase2_nak(struct eap_sm *sm,
			       struct eap_ttls_data *data,
			       struct eap_hdr *hdr,
			       u8 **resp, size_t *resp_len)
{
	struct eap_hdr *resp_hdr;
	u8 *pos = (u8 *) (hdr + 1);

	wpa_printf(MSG_DEBUG, "EAP-TTLS: Phase 2 EAP Request: Nak type=%d, "
		   "request %d", *pos, data->phase2_eap_type);
	*resp_len = sizeof(struct eap_hdr) + 2;
	*resp = malloc(*resp_len);
	if (*resp == NULL)
		return -1;

	resp_hdr = (struct eap_hdr *) (*resp);
	resp_hdr->code = EAP_CODE_RESPONSE;
	resp_hdr->identifier = hdr->identifier;
	resp_hdr->length = htons(*resp_len);
	pos = (u8 *) (resp_hdr + 1);
	*pos++ = EAP_TYPE_NAK;
	*pos++ = data->phase2_eap_type;

	return 0;
}


static int eap_ttls_phase2_request_eap(struct eap_sm *sm,
				       struct eap_ttls_data *data,
				       struct eap_hdr *req,
				       struct eap_hdr *hdr,
				       u8 **resp, size_t *resp_len)
{
	size_t len = ntohs(hdr->length);
	u8 *pos;

	if (len <= sizeof(struct eap_hdr)) {
		wpa_printf(MSG_INFO, "EAP-TTLS: too short "
			   "Phase 2 request (len=%d)", len);
		return -1;
	}
	pos = (u8 *) (hdr + 1);
	wpa_printf(MSG_DEBUG, "EAP-TTLS: Phase 2 EAP Request: type=%d", *pos);
	switch (*pos) {
	case EAP_TYPE_IDENTITY:
		*resp = eap_sm_buildIdentity(sm, req->identifier, resp_len, 1);
		break;
	case EAP_TYPE_MSCHAPV2:
	case EAP_TYPE_GTC:
	case EAP_TYPE_OTP:
	case EAP_TYPE_MD5:
	case EAP_TYPE_TLS:
		wpa_printf(MSG_DEBUG, "EAP-TTLS: Phase 2 EAP packet");
		if (*pos != data->phase2_eap_type) {
			if (eap_ttls_phase2_nak(sm, data, hdr, resp, resp_len))
				return -1;
			break;
		}

		if (data->phase2_priv == NULL) {
			data->phase2_method = eap_sm_get_eap_methods(*pos);
			if (data->phase2_method) {
				sm->init_phase2 = 1;
				data->phase2_priv =
					data->phase2_method->init(sm);
				sm->init_phase2 = 0;
			}
		}
		if (data->phase2_priv == NULL || data->phase2_method == NULL) {
			wpa_printf(MSG_INFO, "EAP-TTLS: failed to initialize "
				   "Phase 2 EAP method %d", *pos);
			sm->methodState = METHOD_DONE;
			sm->decision = DECISION_FAIL;
			sm->ignore = TRUE;
			return -1;
		}
		*resp = data->phase2_method->process(sm, data->phase2_priv,
						     (u8 *) hdr, len,
						     resp_len);
		break;
	default:
		if (eap_ttls_phase2_nak(sm, data, hdr, resp, resp_len))
			return -1;
		break;
	}

	if (*resp == NULL)
		return -1;

	wpa_hexdump(MSG_DEBUG, "EAP-TTLS: AVP encapsulate EAP Response",
		    *resp, *resp_len);
	return eap_ttls_avp_encapsulate(resp, resp_len,
					RADIUS_ATTR_EAP_MESSAGE, 1);
}


static int eap_ttls_phase2_request_mschapv2(struct eap_sm *sm,
					    struct eap_ttls_data *data,
					    struct eap_hdr *req,
					    struct eap_hdr *hdr,
					    u8 **resp, size_t *resp_len)
{
	struct wpa_ssid *config = sm->eapol->config;
	u8 *buf, *pos, *challenge, *username;
	size_t username_len;
	int i;

	wpa_printf(MSG_DEBUG, "EAP-TTLS: Phase 2 MSCHAPV2 Request");

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

	pos = buf = malloc(config->identity_len + 1000);
	if (buf == NULL) {
		wpa_printf(MSG_ERROR,
			   "EAP-TTLS/MSCHAPV2: Failed to allocate memory");
		sm->ignore = TRUE;
		return -1;
	}

	/* User-Name */
	pos = eap_ttls_avp_add(buf, pos, RADIUS_ATTR_USER_NAME, 0, 1,
			       config->identity, config->identity_len);

	/* MS-CHAP-Challenge */
	challenge = eap_tls_derive_key(data->ssl.ssl, "ttls challenge");
	if (challenge == NULL) {
		free(buf);
		wpa_printf(MSG_ERROR, "EAP-TTLS/MSCHAPV2: Failed to derive "
			   "implicit challenge");
		return -1;
	}

	pos = eap_ttls_avp_add(buf, pos, RADIUS_ATTR_MS_CHAP_CHALLENGE,
			       RADIUS_VENDOR_ID_MICROSOFT, 1,
			       challenge, EAP_TTLS_MSCHAPV2_CHALLENGE_LEN);

	/* MS-CHAP2-Response */
	pos = eap_ttls_avp_hdr(pos, RADIUS_ATTR_MS_CHAP2_RESPONSE,
			       RADIUS_VENDOR_ID_MICROSOFT, 1,
			       EAP_TTLS_MSCHAPV2_RESPONSE_LEN);
	data->ident = challenge[EAP_TTLS_MSCHAPV2_CHALLENGE_LEN];
	*pos++ = data->ident;
	*pos++ = 0; /* Flags */
	memcpy(pos, challenge, EAP_TTLS_MSCHAPV2_CHALLENGE_LEN);
	pos += EAP_TTLS_MSCHAPV2_CHALLENGE_LEN;
	memset(pos, 0, 8); /* Reserved, must be zero */
	pos += 8;
	wpa_hexdump(MSG_DEBUG, "EAP-TTLS: MSCHAPV2: implicit challenge",
		    challenge, EAP_TTLS_MSCHAPV2_CHALLENGE_LEN);
	wpa_hexdump_ascii(MSG_DEBUG, "EAP-TTLS: MSCHAPV2 username",
			  username, username_len);
	wpa_hexdump_ascii(MSG_DEBUG, "EAP-TTLS: MSCHAPV2 password",
			  config->password, config->password_len);
	generate_nt_response(challenge, challenge,
			     username, username_len,
			     config->password, config->password_len,
			     pos);
	wpa_hexdump(MSG_DEBUG, "EAP-TTLS: MSCHAPV2 response", pos, 24);
	generate_authenticator_response(config->password, config->password_len,
					challenge, challenge,
					username, username_len,
					pos, data->auth_response);
	data->auth_response_valid = 1;

	pos += 24;
	free(challenge);
	AVP_PAD(buf, pos);

	*resp = buf;
	*resp_len = pos - buf;
	return 0;
}


static int eap_ttls_phase2_request_mschap(struct eap_sm *sm,
					  struct eap_ttls_data *data,
					  struct eap_hdr *req,
					  struct eap_hdr *hdr,
					  u8 **resp, size_t *resp_len)
{
	struct wpa_ssid *config = sm->eapol->config;
	u8 *buf, *pos, *challenge, *username;
	size_t username_len;
	int i;

	wpa_printf(MSG_DEBUG, "EAP-TTLS: Phase 2 MSCHAP Request");

	/* MSCHAP does not include optional domain name in the
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

	pos = buf = malloc(config->identity_len + 1000);
	if (buf == NULL) {
		wpa_printf(MSG_ERROR,
			   "EAP-TTLS/MSCHAP: Failed to allocate memory");
		sm->ignore = TRUE;
		return -1;
	}

	/* User-Name */
	pos = eap_ttls_avp_add(buf, pos, RADIUS_ATTR_USER_NAME, 0, 1,
			       config->identity, config->identity_len);

	/* MS-CHAP-Challenge */
	challenge = eap_tls_derive_key(data->ssl.ssl, "ttls challenge");
	if (challenge == NULL) {
		free(buf);
		wpa_printf(MSG_ERROR, "EAP-TTLS/MSCHAP: Failed to derive "
			   "implicit challenge");
		return -1;
	}

	pos = eap_ttls_avp_add(buf, pos, RADIUS_ATTR_MS_CHAP_CHALLENGE,
			       RADIUS_VENDOR_ID_MICROSOFT, 1,
			       challenge, EAP_TTLS_MSCHAP_CHALLENGE_LEN);

	/* MS-CHAP-Response */
	pos = eap_ttls_avp_hdr(pos, RADIUS_ATTR_MS_CHAP_RESPONSE,
			       RADIUS_VENDOR_ID_MICROSOFT, 1,
			       EAP_TTLS_MSCHAP_RESPONSE_LEN);
	data->ident = challenge[EAP_TTLS_MSCHAP_CHALLENGE_LEN];
	*pos++ = data->ident;
	*pos++ = 1; /* Flags: Use NT style passwords */
	memset(pos, 0, 24); /* LM-Response */
	pos += 24;
	nt_challenge_response(challenge,
			      config->password, config->password_len,
			      pos); /* NT-Response */
	wpa_hexdump_ascii(MSG_DEBUG, "EAP-TTLS: MSCHAP username",
			  username, username_len);
	wpa_hexdump_ascii(MSG_DEBUG, "EAP-TTLS: MSCHAP password",
			  config->password, config->password_len);
	wpa_hexdump(MSG_DEBUG, "EAP-TTLS: MSCHAP implicit challenge",
		    challenge, EAP_TTLS_MSCHAP_CHALLENGE_LEN);
	wpa_hexdump(MSG_DEBUG, "EAP-TTLS: MSCHAP response", pos, 24);
	pos += 24;
	free(challenge);
	AVP_PAD(buf, pos);

	*resp = buf;
	*resp_len = pos - buf;
	return 0;
}


static int eap_ttls_phase2_request_pap(struct eap_sm *sm,
				       struct eap_ttls_data *data,
				       struct eap_hdr *req,
				       struct eap_hdr *hdr,
				       u8 **resp, size_t *resp_len)
{
	struct wpa_ssid *config = sm->eapol->config;
	u8 *buf, *pos;
	size_t pad;

	wpa_printf(MSG_DEBUG, "EAP-TTLS: Phase 2 PAP Request");

	pos = buf = malloc(config->identity_len + config->password_len + 100);
	if (buf == NULL) {
		wpa_printf(MSG_ERROR,
			   "EAP-TTLS/PAP: Failed to allocate memory");
		sm->ignore = TRUE;
		return -1;
	}

	/* User-Name */
	pos = eap_ttls_avp_add(buf, pos, RADIUS_ATTR_USER_NAME, 0, 1,
			       config->identity, config->identity_len);

	/* User-Password; in RADIUS, this is encrypted, but EAP-TTLS encrypts
	 * the data, so no separate encryption is used in the AVP itself.
	 * However, the password is padded to obfuscate its length. */
	pad = (16 - (config->password_len & 15)) & 15;
	pos = eap_ttls_avp_hdr(pos, RADIUS_ATTR_USER_PASSWORD, 0, 1,
			       config->password_len + pad);
	memcpy(pos, config->password, config->password_len);
	pos += config->password_len;
	memset(pos, 0, pad);
	pos += pad;
	AVP_PAD(buf, pos);

	*resp = buf;
	*resp_len = pos - buf;
	return 0;
}


static int eap_ttls_phase2_request_chap(struct eap_sm *sm,
					struct eap_ttls_data *data,
					struct eap_hdr *req,
					struct eap_hdr *hdr,
					u8 **resp, size_t *resp_len)
{
	struct wpa_ssid *config = sm->eapol->config;
	u8 *buf, *pos, *challenge;
	MD5_CTX context;

	wpa_printf(MSG_DEBUG, "EAP-TTLS: Phase 2 CHAP Request");

	pos = buf = malloc(config->identity_len + 1000);
	if (buf == NULL) {
		wpa_printf(MSG_ERROR,
			   "EAP-TTLS/CHAP: Failed to allocate memory");
		sm->ignore = TRUE;
		return -1;
	}

	/* User-Name */
	pos = eap_ttls_avp_add(buf, pos, RADIUS_ATTR_USER_NAME, 0, 1,
			       config->identity, config->identity_len);

	/* CHAP-Challenge */
	challenge = eap_tls_derive_key(data->ssl.ssl, "ttls challenge");
	if (challenge == NULL) {
		free(buf);
		wpa_printf(MSG_ERROR, "EAP-TTLS/CHAP: Failed to derive "
			   "implicit challenge");
		return -1;
	}

	pos = eap_ttls_avp_add(buf, pos, RADIUS_ATTR_CHAP_CHALLENGE, 0, 1,
			       challenge, EAP_TTLS_CHAP_CHALLENGE_LEN);

	/* CHAP-Password */
	pos = eap_ttls_avp_hdr(pos, RADIUS_ATTR_CHAP_PASSWORD, 0, 1,
			       1 + EAP_TTLS_CHAP_PASSWORD_LEN);
	data->ident = challenge[EAP_TTLS_CHAP_CHALLENGE_LEN];
	*pos++ = data->ident;

	/* MD5(Ident + Password + Challenge) */
	MD5Init(&context);
	MD5Update(&context, &data->ident, 1);
	MD5Update(&context, config->password, config->password_len);
	MD5Update(&context, challenge, EAP_TTLS_CHAP_CHALLENGE_LEN);
	MD5Final(pos, &context);

	wpa_hexdump_ascii(MSG_DEBUG, "EAP-TTLS: CHAP username",
			  config->identity, config->identity_len);
	wpa_hexdump_ascii(MSG_DEBUG, "EAP-TTLS: CHAP password",
			  config->password, config->password_len);
	wpa_hexdump(MSG_DEBUG, "EAP-TTLS: CHAP implicit challenge",
		    challenge, EAP_TTLS_CHAP_CHALLENGE_LEN);
	wpa_hexdump(MSG_DEBUG, "EAP-TTLS: CHAP password",
		    pos, EAP_TTLS_CHAP_PASSWORD_LEN);
	pos += EAP_TTLS_CHAP_PASSWORD_LEN;
	free(challenge);
	AVP_PAD(buf, pos);

	*resp = buf;
	*resp_len = pos - buf;
	return 0;
}


static int eap_ttls_phase2_request(struct eap_sm *sm,
				   struct eap_ttls_data *data,
				   struct eap_hdr *req,
				   struct eap_hdr *hdr,
				   u8 **resp, size_t *resp_len)
{
	struct wpa_ssid *config = sm->eapol->config;

	if (data->phase2_type == EAP_TTLS_PHASE2_MSCHAPV2 ||
	    data->phase2_type == EAP_TTLS_PHASE2_MSCHAP ||
	    data->phase2_type == EAP_TTLS_PHASE2_PAP ||
	    data->phase2_type == EAP_TTLS_PHASE2_CHAP) {
		if (config == NULL || config->identity == NULL) {
			wpa_printf(MSG_INFO,
				   "EAP-TTLS: Identity not configured");
			eap_sm_request_identity(sm, config);
			if (config->password == NULL)
				eap_sm_request_password(sm, config);
			sm->ignore = TRUE;
			return -1;
		}

		if (config->password == NULL) {
			wpa_printf(MSG_INFO,
				   "EAP-TTLS: Password not configured");
			eap_sm_request_password(sm, config);
			sm->ignore = TRUE;
			return -1;
		}
	}

	switch (data->phase2_type) {
	case EAP_TTLS_PHASE2_EAP:
		return eap_ttls_phase2_request_eap(sm, data, req, hdr, resp,
						   resp_len);
	case EAP_TTLS_PHASE2_MSCHAPV2:
		return eap_ttls_phase2_request_mschapv2(sm, data, req, hdr,
							resp, resp_len);
	case EAP_TTLS_PHASE2_MSCHAP:
		return eap_ttls_phase2_request_mschap(sm, data, req, hdr,
						      resp, resp_len);
	case EAP_TTLS_PHASE2_PAP:
		return eap_ttls_phase2_request_pap(sm, data, req, hdr,
						   resp, resp_len);
	case EAP_TTLS_PHASE2_CHAP:
		return eap_ttls_phase2_request_chap(sm, data, req, hdr,
						    resp, resp_len);
	default:
		wpa_printf(MSG_ERROR, "EAP-TTLS: Phase 2 - Unknown");
		return -1;
	}
}


static int eap_ttls_decrypt(struct eap_sm *sm,
			    struct eap_ttls_data *data, struct eap_hdr *req,
			    u8 *in_data, size_t in_len,
			    u8 **out_data, size_t *out_len)
{
	u8 *in_decrypted, *pos;
	int buf_len, len_decrypted, len, left, ret = 0;
	struct eap_hdr *hdr = NULL;
	u8 *resp = NULL, *mschapv2 = NULL, *eapdata = NULL;
	size_t resp_len, eap_len = 0;
	struct ttls_avp *avp;
	u8 recv_response[20];

	wpa_printf(MSG_DEBUG, "EAP-TTLS: received %d bytes encrypted data for "
		   "Phase 2", in_len);
	if (in_len == 0 && data->phase2_start) {
		data->phase2_start = 0;
		wpa_printf(MSG_DEBUG, "EAP-TTLS: empty data in beginning of "
			   "Phase 2 - use fake EAP-Request Identity");
		buf_len = sizeof(*hdr) + 1;
		in_decrypted = malloc(buf_len);
		if (in_decrypted == NULL) {
			wpa_printf(MSG_WARNING, "EAP-TTLS: failed to allocate "
				   "memory for fake EAP-Identity Request");
			goto done;
		}
		hdr = (struct eap_hdr *) in_decrypted;
		hdr->code = EAP_CODE_REQUEST;
		hdr->identifier = 0;
		hdr->length = htons(sizeof(*hdr) + 1);
		in_decrypted[sizeof(*hdr)] = EAP_TYPE_IDENTITY;
		goto process_eap;
	}

	BIO_write(data->ssl.ssl_in, in_data, in_len);

	if (data->ssl.tls_in_left > in_len) {
		data->ssl.tls_in_left -= in_len;
		wpa_printf(MSG_DEBUG, "EAP-TTLS: Need %d bytes more"
			   " input data", data->ssl.tls_in_left);
		return 1;
	} else
		data->ssl.tls_in_left = 0;

	BIO_reset(data->ssl.ssl_out);

	data->phase2_start = 0;
	buf_len = in_len;
	if (data->ssl.tls_in_total > buf_len)
		buf_len = data->ssl.tls_in_total;
	in_decrypted = malloc(buf_len);
	if (in_decrypted == NULL) {
		wpa_printf(MSG_WARNING, "EAP-TTLS: failed to allocate memory "
			   "for decryption");
		ret = -1;
		goto done;
	}

	len_decrypted = SSL_read(data->ssl.ssl, in_decrypted, buf_len);
	if (len_decrypted < 0) {
		int err = SSL_get_error(data->ssl.ssl, len_decrypted);
		wpa_printf(MSG_INFO, "EAP-TTLS: SSL_read error %d", err);
		goto done;
	}

	wpa_hexdump(MSG_DEBUG, "EAP-TTLS: Decrypted Phase 2 AVPs",
		    in_decrypted, len_decrypted);
	if (len_decrypted < sizeof(struct ttls_avp)) {
		wpa_printf(MSG_WARNING, "EAP-TTLS: Too short Phase 2 AVP frame"
			   " len=%d expected %d or more - dropped",
			   len_decrypted, sizeof(struct ttls_avp));
		goto done;
	}

	/* Parse AVPs */
	pos = in_decrypted;
	left = len_decrypted;
	mschapv2 = NULL;

	while (left > 0) {
		u32 avp_code, avp_length, vendor_id = 0;
		u8 avp_flags, *dpos;
		size_t pad, dlen;
		avp = (struct ttls_avp *) pos;
		avp_code = ntohl(avp->avp_code);
		avp_length = ntohl(avp->avp_length);
		avp_flags = (avp_length >> 24) & 0xff;
		avp_length &= 0xffffff;
		wpa_printf(MSG_DEBUG, "EAP-TTLS: AVP: code=%d flags=0x%02x "
			   "length=%d", avp_code, avp_flags, avp_length);
		if (avp_length > left) {
			wpa_printf(MSG_WARNING, "EAP-TTLS: AVP overflow "
				   "(len=%d, left=%d) - dropped",
				   avp_length, left);
			goto done;
		}
		dpos = (u8 *) (avp + 1);
		dlen = avp_length - sizeof(*avp);
		if (avp_flags & AVP_FLAGS_VENDOR) {
			if (dlen < 4) {
				wpa_printf(MSG_WARNING, "EAP-TTLS: vendor AVP "
					   "underflow");
				goto done;
			}
			vendor_id = ntohl(* (u32 *) dpos);
			wpa_printf(MSG_DEBUG, "EAP-TTLS: AVP vendor_id %d",
				   vendor_id);
			dpos += 4;
			dlen -= 4;
		}

		wpa_hexdump(MSG_DEBUG, "EAP-TTLS: AVP data", dpos, dlen);

		if (vendor_id == 0 && avp_code == RADIUS_ATTR_EAP_MESSAGE) {
			wpa_printf(MSG_DEBUG, "EAP-TTLS: AVP - EAP Message");
			if (eapdata == NULL) {
				eapdata = malloc(dlen);
				if (eapdata == NULL) {
					ret = -1;
					wpa_printf(MSG_WARNING, "EAP-TTLS: "
						   "failed to allocate memory "
						   "for Phase 2 EAP data");
					goto done;
				}
				memcpy(eapdata, dpos, dlen);
				eap_len = dlen;
			} else {
				u8 *neweap = realloc(eapdata, eap_len + dlen);
				if (neweap == NULL) {
					ret = -1;
					wpa_printf(MSG_WARNING, "EAP-TTLS: "
						   "failed to allocate memory "
						   "for Phase 2 EAP data");
					goto done;
				}
				memcpy(neweap + eap_len, dpos, dlen);
				eapdata = neweap;
				eap_len += dlen;
			}
		} else if (vendor_id == 0 &&
			   avp_code == RADIUS_ATTR_REPLY_MESSAGE) {
			/* This is an optional message that can be displayed to
			 * the user. */
			wpa_hexdump_ascii(MSG_DEBUG,
					  "EAP-TTLS: AVP - Reply-Message",
					  dpos, dlen);
		} else if (vendor_id == RADIUS_VENDOR_ID_MICROSOFT &&
			   avp_code == RADIUS_ATTR_MS_CHAP2_SUCCESS) {
			wpa_hexdump_ascii(MSG_DEBUG, "EAP-TTLS: "
					  "MS-CHAP2-Success", dpos, dlen);
			if (dlen != 43) {
				wpa_printf(MSG_WARNING, "EAP-TTLS: Unexpected "
					   "MS-CHAP2-Success length "
					   "(len=%d, expected 43)", dlen);
				break;
			}
			mschapv2 = dpos;
		} else if (avp_flags & AVP_FLAGS_MANDATORY) {
			wpa_printf(MSG_WARNING, "EAP-TTLS: Unsupported "
				   "mandatory AVP code %d vendor_id %d - "
				   "dropped", avp_code, vendor_id);
			goto done;
		} else {
			wpa_printf(MSG_DEBUG, "EAP-TTLS: Ignoring unsupported "
				   "AVP code %d vendor_id %d",
				   avp_code, vendor_id);
		}

		pad = (4 - (avp_length & 3)) & 3;
		pos += avp_length + pad;
		left -= avp_length + pad;
	}

	switch (data->phase2_type) {
	case EAP_TTLS_PHASE2_EAP:
		if (eapdata == NULL) {
			wpa_printf(MSG_WARNING, "EAP-TTLS: No EAP Message in "
				   "the packet - dropped");
			goto done;
		}

		wpa_hexdump(MSG_DEBUG, "EAP-TTLS: Phase 2 EAP",
			    eapdata, eap_len);
		hdr = (struct eap_hdr *) eapdata;

		if (eap_len < sizeof(*hdr)) {
			wpa_printf(MSG_WARNING, "EAP-TTLS: Too short Phase 2 "
				   "EAP frame (len=%d, expected %d or more) - "
				   "dropped", eap_len, sizeof(*hdr));
			goto done;
		}
		len = ntohs(hdr->length);
		if (len > eap_len) {
			wpa_printf(MSG_INFO, "EAP-TTLS: Length mismatch in "
				   "Phase 2 EAP frame (EAP hdr len=%d, EAP "
				   "data len in AVP=%d)", len, eap_len);
			goto done;
		}
		wpa_printf(MSG_DEBUG, "EAP-TTLS: received Phase 2: code=%d "
			   "identifier=%d length=%d",
			   hdr->code, hdr->identifier, len);
	process_eap:
		switch (hdr->code) {
		case EAP_CODE_REQUEST:
			if (eap_ttls_phase2_request(sm, data, req, hdr,
						    &resp, &resp_len)) {
				wpa_printf(MSG_INFO, "EAP-TTLS: Phase2 "
					   "Request processing failed");
				goto done;
			}
			break;
		default:
			wpa_printf(MSG_INFO, "EAP-TTLS: Unexpected code=%d in "
				   "Phase 2 EAP header", hdr->code);
			break;
		}
		break;
	case EAP_TTLS_PHASE2_MSCHAPV2:
		if (mschapv2 == NULL) {
			wpa_printf(MSG_WARNING, "EAP-TTLS: no MS-CHAP2-Success"
				   " AVP received for Phase2 MSCHAPV2");
			break;
		}
		if (mschapv2[0] != data->ident) {
			wpa_printf(MSG_WARNING, "EAP-TTLS: Ident mismatch "
				   "for Phase 2 MSCHAPV2 (received Ident "
				   "0x%02x, expected 0x%02x)",
				   mschapv2[0], data->ident);
			break;
		}
		if (!data->auth_response_valid ||
		    mschapv2[1] != 'S' || mschapv2[2] != '=' ||
		    hexstr2bin(mschapv2 + 3, recv_response, 20) ||
		    memcmp(data->auth_response, recv_response, 20) != 0) {
			wpa_printf(MSG_WARNING, "EAP-TTLS: Invalid "
				   "authenticator response in Phase 2 "
				   "MSCHAPV2 success request");
			sm->methodState = METHOD_DONE;
			sm->decision = DECISION_FAIL;
			sm->ignore = TRUE;
			break;
		}

		wpa_printf(MSG_INFO, "EAP-TTLS: Phase 2 MSCHAPV2 "
			   "authentication succeeded");
		sm->methodState = METHOD_DONE;
		sm->decision = DECISION_COND_SUCC;
		sm->ignore = FALSE;

		/* Reply with empty data; authentication server will reply
		 * with EAP-Success after this. */
		ret = 1;
		goto done;
	case EAP_TTLS_PHASE2_MSCHAP:
	case EAP_TTLS_PHASE2_PAP:
	case EAP_TTLS_PHASE2_CHAP:
		/* EAP-TTLS/{MSCHAP,PAP,CHAP} should not send any TLS tunneled
		 * requests to the supplicant */
		wpa_printf(MSG_INFO, "EAP-TTLS: Phase 2 received unexpected "
			   "tunneled data");
		break;
	}

	if (resp) {
		wpa_hexdump(MSG_DEBUG, "EAP-TTLS: Encrypting Phase 2 data",
			    resp, resp_len);

		if (eap_ttls_encrypt(sm, data, req->identifier,
				     resp, resp_len, out_data, out_len)) {
			wpa_printf(MSG_INFO, "EAP-TTLS: Failed to encrypt "
				   "a Phase 2 frame");
		}
		free(resp);
	}

done:
	free(in_decrypted);
	free(eapdata);
	return ret;
}


static u8 * eap_ttls_process(struct eap_sm *sm, void *priv,
			     u8 *reqData, size_t reqDataLen,
			     size_t *respDataLen)
{
	struct eap_hdr *req;
	unsigned long err;
	int left, res;
	unsigned int tls_msg_len;
	u8 flags, *pos, *resp, id;
	struct eap_ttls_data *data = priv;

	err = ERR_get_error();
	if (err != 0) {
		do {
			wpa_printf(MSG_INFO, "EAP-TTLS - SSL error: %s",
				   ERR_error_string(err, NULL));
			err = ERR_get_error();
		} while (err != 0);
		sm->ignore = TRUE;
		return NULL;
	}

	req = (struct eap_hdr *) reqData;
	pos = (u8 *) (req + 1);
	if (reqDataLen < sizeof(*req) + 2 || *pos != EAP_TYPE_TTLS ||
	    (left = htons(req->length)) > reqDataLen) {
		wpa_printf(MSG_INFO, "EAP-TTLS: Invalid frame");
		sm->ignore = TRUE;
		return NULL;
	}
	left -= sizeof(struct eap_hdr);
	id = req->identifier;
	pos++;
	flags = *pos++;
	left -= 2;
	wpa_printf(MSG_DEBUG, "EAP-TTLS: Received packet(len=%d) - "
		   "Flags 0x%02x", reqDataLen, flags);
	if (flags & EAP_TLS_FLAGS_LENGTH_INCLUDED) {
		if (left < 4) {
			wpa_printf(MSG_INFO, "EAP-TTLS: Short frame with TLS "
				   "length");
			sm->ignore = TRUE;
			return NULL;
		}
		tls_msg_len = (pos[0] << 24) | (pos[1] << 16) | (pos[2] << 8) |
			pos[3];
		wpa_printf(MSG_DEBUG, "EAP-TTLS: TLS Message Length: %d",
			   tls_msg_len);
		if (data->ssl.tls_in_left == 0) {
			data->ssl.tls_in_total = tls_msg_len;
			data->ssl.tls_in_left = tls_msg_len;
		}
		pos += 4;
		left -= 4;
	}

	sm->ignore = FALSE;

	sm->methodState = METHOD_CONT;
	sm->decision = DECISION_COND_SUCC;
	sm->allowNotifications = TRUE;

	if (flags & EAP_TLS_FLAGS_START) {
		wpa_printf(MSG_DEBUG, "EAP-TTLS: Start");
		/* draft-ietf-pppext-eap-ttls-03.txt, Ch. 8.1:
		 * EAP-TTLS Start packet may, in a future specification, be
		 * allowed to contain data. Client based on this draft version
		 * must ignore such data but must not reject the Start packet.
		 */
		left = 0;
	}

	resp = NULL;
	if (SSL_is_init_finished(data->ssl.ssl)) {
		res = eap_ttls_decrypt(sm, data, req, pos, left,
				       &resp, respDataLen);
	} else {
		res = eap_tls_process_helper(sm, &data->ssl, EAP_TYPE_TTLS, 0,
					     id, pos, left,
					     &resp, respDataLen);

		if (SSL_is_init_finished(data->ssl.ssl)) {
			wpa_printf(MSG_DEBUG,
				   "EAP-TTLS: TLS done, proceed to Phase 2");
			sm->methodState = METHOD_CONT;
			data->phase2_start = 1;
			free(sm->eapKeyData);
			sm->eapKeyData =
				eap_tls_derive_key(data->ssl.ssl,
						   "ttls keying material");
			if (sm->eapKeyData) {
				sm->eapKeyDataLen = EAP_TLS_KEY_LEN;
				wpa_hexdump(MSG_DEBUG, "EAP-TTLS: Derived key",
					    sm->eapKeyData, sm->eapKeyDataLen);
			} else {
				wpa_printf(MSG_DEBUG, "EAP-TTLS: Failed to "
					   "derive key");
			}

			if (eap_ttls_decrypt(sm, data, req, NULL, 0,
					     &resp, respDataLen)) {
				wpa_printf(MSG_WARNING, "EAP-TTLS: failed to "
					   "process early start for Phase 2");
			}
			res = 0;
		}
	}

	if (res == 1)
		return eap_tls_build_ack(respDataLen, id, EAP_TYPE_TTLS, 0);
	return resp;
}


const struct eap_method eap_method_ttls =
{
	.method = EAP_TYPE_TTLS,
	.init = eap_ttls_init,
	.deinit = eap_ttls_deinit,
	.process = eap_ttls_process,
};
