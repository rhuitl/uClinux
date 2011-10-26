/*
 * WPA Supplicant / EAP-PEAP (draft-josefsson-pppext-eap-tls-eap-07.txt)
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


/* Maximum supported PEAP version
 * 0 = Microsoft's PEAP version 0; draft-kamath-pppext-peapv0-00.txt
 * 1 = draft-josefsson-ppext-eap-tls-eap-05.txt
 * 2 = draft-josefsson-ppext-eap-tls-eap-07.txt
 */
#define EAP_PEAP_VERSION 1

/* EAP-TLV TLVs (draft-josefsson-ppext-eap-tls-eap-07.txt) */
#define EAP_TLV_RESULT_TLV 3 /* Acknowledged Result */
#define EAP_TLV_NAK_TLV 4
#define EAP_TLV_CRYPTO_BINDING_TLV 5
#define EAP_TLV_CONNECTION_BINDING_TLV 6
#define EAP_TLV_VENDOR_SPECIFIC_TLV 7
#define EAP_TLV_URI_TLV 8
#define EAP_TLV_EAP_PAYLOAD_TLV 9
#define EAP_TLV_INTERMEDIATE_RESULT_TLV 10

#define EAP_TLV_RESULT_SUCCESS 1
#define EAP_TLV_RESULT_FAILURE 2


static void eap_peap_deinit(struct eap_sm *sm, void *priv);


struct eap_peap_data {
	struct eap_ssl_data ssl;

	int peap_version, force_peap_version, force_new_label;

	const struct eap_method *phase2_method;
	void *phase2_priv;
	int phase2_success;

	u8 phase2_type;

	int peap_outer_success; /* 0 = PEAP terminated on Phase 2 inner
				 * EAP-Success
				 * 1 = reply with tunneled EAP-Success to inner
				 * EAP-Success and expect AS to send outer
				 * (unencrypted) EAP-Success after this
				 * 2 = reply with PEAP/TLS ACK to inner
				 * EAP-Success and expect AS to send outer
				 * (unencrypted) EAP-Success after this */
};


static void * eap_peap_init(struct eap_sm *sm)
{
	struct eap_peap_data *data;
	struct wpa_ssid *config = sm->eapol->config;
	char *selected;

	data = malloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	sm->peap_done = FALSE;
	memset(data, 0, sizeof(*data));
	data->peap_version = EAP_PEAP_VERSION;
	data->force_peap_version = -1;
	data->peap_outer_success = 2;
	selected = "MSCHAPV2";
	if (config && config->phase1) {
		u8 *pos = strstr(config->phase1, "peapver=");
		if (pos) {
			data->force_peap_version = atoi(pos + 8);
			data->peap_version = data->force_peap_version;
			wpa_printf(MSG_DEBUG, "EAP-PEAP: Forced PEAP version "
				   "%d", data->force_peap_version);
		}

		if (strstr(config->phase1, "peaplabel=1")) {
			data->force_new_label = 1;
			wpa_printf(MSG_DEBUG, "EAP-PEAP: Force new label for "
				   "key derivation");
		}

		if (strstr(config->phase1, "peap_outer_success=0")) {
			data->peap_outer_success = 0;
			wpa_printf(MSG_DEBUG, "EAP-PEAP: terminate "
				   "authentication on tunneled EAP-Success");
		} else if (strstr(config->phase1, "peap_outer_success=1")) {
			data->peap_outer_success = 1;
			wpa_printf(MSG_DEBUG, "EAP-PEAP: send tunneled "
				   "EAP-Success after receiving tunneled "
				   "EAP-Success");
		} else if (strstr(config->phase1, "peap_outer_success=2")) {
			data->peap_outer_success = 2;
			wpa_printf(MSG_DEBUG, "EAP-PEAP: send PEAP/TLS ACK "
				   "after receiving tunneled EAP-Success");
		}
	}
	data->phase2_type = EAP_TYPE_MSCHAPV2;
	if (config && config->phase2) {
		if (strstr(config->phase2, "auth=TLS")) {
			selected = "TLS";
			data->phase2_type = EAP_TYPE_TLS;
		} else if (strstr(config->phase2, "auth=GTC")) {
			selected = "GTC";
			data->phase2_type = EAP_TYPE_GTC;
		} else if (strstr(config->phase2, "auth=OTP")) {
			selected = "OTP";
			data->phase2_type = EAP_TYPE_OTP;
		} else if (strstr(config->phase2, "auth=MD5")) {
			selected = "MD5";
			data->phase2_type = EAP_TYPE_MD5;
		}
	}
	wpa_printf(MSG_DEBUG, "EAP-PEAP: Phase2 type: %s", selected);

	if (eap_tls_ssl_init(sm, &data->ssl, config)) {
		wpa_printf(MSG_INFO, "EAP-PEAP: Failed to initialize SSL.");
		eap_peap_deinit(sm, data);
		return NULL;
	}

	return data;
}


static void eap_peap_deinit(struct eap_sm *sm, void *priv)
{
	struct eap_peap_data *data = priv;
	if (data == NULL)
		return;
	if (data->phase2_priv && data->phase2_method)
		data->phase2_method->deinit(sm, data->phase2_priv);
	if (data->ssl.ssl)
		SSL_free(data->ssl.ssl);
	free(data);
}


static int eap_peap_encrypt(struct eap_sm *sm, struct eap_peap_data *data,
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
		wpa_printf(MSG_INFO, "EAP-PEAP: SSL_write error %d", err);
		return 0;
	}

	/* TODO: add support for fragmentation, if needed. This will need to
	 * add TLS Message Length field, if the frame is fragmented.
	 * Note: Microsoft IAS did not seem to like TLS Message Length with
	 * PEAP/MSCHAPv2. */
	resp = malloc(sizeof(struct eap_hdr) + 2 + data->ssl.tls_out_limit);
	if (resp == NULL)
		return 0;

	resp->code = EAP_CODE_RESPONSE;
	resp->identifier = id;

	pos = (u8 *) (resp + 1);
	*pos++ = EAP_TYPE_PEAP;
	*pos++ = data->peap_version;

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


static u8 * eap_peap_build_tlv_nak(int id, int nak_type, size_t *resp_len)
{
	struct eap_hdr *hdr;
	u8 *pos;

	*resp_len = sizeof(struct eap_hdr) + 1 + 10;
	hdr = malloc(*resp_len);
	if (hdr == NULL)
		return NULL;

	hdr->code = EAP_CODE_RESPONSE;
	hdr->identifier = id;
	hdr->length = htons(*resp_len);
	pos = (u8 *) (hdr + 1);
	*pos++ = EAP_TYPE_TLV;
	*pos++ = 0x80; /* Mandatory */
	*pos++ = EAP_TLV_NAK_TLV;
	/* Length */
	*pos++ = 0;
	*pos++ = 6;
	/* Vendor-Id */
	*pos++ = 0;
	*pos++ = 0;
	*pos++ = 0;
	*pos++ = 0;
	/* NAK-Type */
	*pos++ = nak_type >> 8;
	*pos++ = nak_type & 0xff;

	return (u8 *) hdr;
}


static u8 * eap_peap_build_tlv_result(int id, int status, size_t *resp_len)
{
	struct eap_hdr *hdr;
	u8 *pos;

	*resp_len = sizeof(struct eap_hdr) + 1 + 6;
	hdr = malloc(*resp_len);
	if (hdr == NULL)
		return NULL;

	hdr->code = EAP_CODE_RESPONSE;
	hdr->identifier = id;
	hdr->length = htons(*resp_len);
	pos = (u8 *) (hdr + 1);
	*pos++ = EAP_TYPE_TLV;
	*pos++ = 0x80; /* Mandatory */
	*pos++ = EAP_TLV_RESULT_TLV;
	/* Length */
	*pos++ = 0;
	*pos++ = 2;
	/* Status */
	*pos++ = status >> 8;
	*pos++ = status & 0xff;

	return (u8 *) hdr;
}


static int eap_peap_phase2_tlv(struct eap_sm *sm,
			       struct eap_peap_data *data,
			       struct eap_hdr *hdr,
			       u8 **resp, size_t *resp_len)
{
	size_t left;
	u8 *pos;
	u8 *result_tlv = NULL;
	size_t result_tlv_len = 0;
	int tlv_type, mandatory, tlv_len;

	/* Parse TLVs */
	left = ntohs(hdr->length) - sizeof(struct eap_hdr) - 1;
	pos = (u8 *) (hdr + 1);
	pos++;
	wpa_hexdump(MSG_DEBUG, "EAP-PEAP: Received TLVs", pos, left);
	while (left >= 4) {
		mandatory = !!(pos[0] & 0x80);
		tlv_type = pos[0] & 0x3f;
		tlv_type = (tlv_type << 8) | pos[1];
		tlv_len = ((int) pos[2] << 8) | pos[3];
		pos += 4;
		left -= 4;
		if (tlv_len > left) {
			wpa_printf(MSG_DEBUG, "EAP-PEAP: TLV underrun "
				   "(tlv_len=%d left=%d)", tlv_len, left);
			return -1;
		}
		switch (tlv_type) {
		case EAP_TLV_RESULT_TLV:
			result_tlv = pos;
			result_tlv_len = tlv_len;
			break;
		default:
			wpa_printf(MSG_DEBUG, "EAP-PEAP: Unsupported TLV Type "
				   "%d%s", tlv_type,
				   mandatory ? " (mandatory)" : "");
			if (mandatory) {
				/* NAK TLV and ignore all TLVs in this packet.
				 */
				*resp = eap_peap_build_tlv_nak(hdr->identifier,
							       tlv_type,
							       resp_len);
				return *resp == NULL ? -1 : 0;
			}
			/* Ignore this TLV, but process other TLVs */
			break;
		}

		pos += tlv_len;
		left -= tlv_len;
	}
	if (left) {
		wpa_printf(MSG_DEBUG, "EAP-PEAP: Last TLV too short in "
			   "Request (left=%d)", left);
		return -1;
	}

	/* Process supported TLVs */
	if (result_tlv) {
		int status, resp_status;
		wpa_hexdump(MSG_DEBUG, "EAP-PEAP: Result TLV",
			    result_tlv, result_tlv_len);
		if (result_tlv_len < 2) {
			wpa_printf(MSG_INFO, "EAP-PEAP: Too short Result TLV "
				   "(len=%d)", result_tlv_len);
			return -1;
		}
		status = ((int) result_tlv[0] << 8) | result_tlv[1];
		if (status == EAP_TLV_RESULT_SUCCESS) {
			wpa_printf(MSG_INFO, "EAP-PEAP: TLV Result - Success "
				   "- EAP-PEAP/Phase2 Completed");
			resp_status = EAP_TLV_RESULT_SUCCESS;
			sm->decision = DECISION_UNCOND_SUCC;
		} else if (status == EAP_TLV_RESULT_FAILURE) {
			wpa_printf(MSG_INFO, "EAP-PEAP: TLV Result - Failure");
			resp_status = EAP_TLV_RESULT_FAILURE;
			sm->decision = DECISION_FAIL;
		} else {
			wpa_printf(MSG_INFO, "EAP-PEAP: Unknown TLV Result "
				   "Status %d", status);
			resp_status = EAP_TLV_RESULT_FAILURE;
			sm->decision = DECISION_FAIL;
		}
		sm->methodState = METHOD_DONE;

		*resp = eap_peap_build_tlv_result(hdr->identifier, resp_status,
						  resp_len);
	}

	return 0;
}


static int eap_peap_phase2_nak(struct eap_sm *sm,
			       struct eap_peap_data *data,
			       struct eap_hdr *hdr,
			       u8 **resp, size_t *resp_len)
{
	struct eap_hdr *resp_hdr;
	u8 *pos = (u8 *) (hdr + 1);

	wpa_printf(MSG_DEBUG, "EAP-PEAP: Phase 2 Request: Nak type=%d, "
		   "request %d", *pos, data->phase2_type);
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
	*pos++ = data->phase2_type;

	return 0;
}


static int eap_peap_phase2_request(struct eap_sm *sm,
				   struct eap_peap_data *data,
				   struct eap_hdr *req,
				   struct eap_hdr *hdr,
				   u8 **resp, size_t *resp_len)
{
	size_t len = ntohs(hdr->length);
	u8 *pos;

	if (len <= sizeof(struct eap_hdr)) {
		wpa_printf(MSG_INFO, "EAP-PEAP: too short "
			   "Phase 2 request (len=%d)", len);
		return -1;
	}
	pos = (u8 *) (hdr + 1);
	wpa_printf(MSG_DEBUG, "EAP-PEAP: Phase 2 Request: type=%d", *pos);
	switch (*pos) {
	case EAP_TYPE_IDENTITY:
		*resp = eap_sm_buildIdentity(sm, req->identifier, resp_len, 1);
		break;
	case EAP_TYPE_MSCHAPV2:
	case EAP_TYPE_GTC:
	case EAP_TYPE_OTP:
	case EAP_TYPE_MD5:
	case EAP_TYPE_TLS:
		wpa_printf(MSG_DEBUG, "EAP-PEAP: Phase 2 EAP packet");
		if (*pos != data->phase2_type) {
			if (eap_peap_phase2_nak(sm, data, hdr, resp, resp_len))
				return -1;
			return 0;
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
			wpa_printf(MSG_INFO, "EAP-PEAP: failed to initialize "
				   "Phase 2 EAP method %d", *pos);
			sm->methodState = METHOD_DONE;
			sm->decision = DECISION_FAIL;
			sm->ignore = TRUE;
			return -1;
		}
		*resp = data->phase2_method->process(sm, data->phase2_priv,
						     (u8 *) hdr, len,
						     resp_len);
		/* Don't allow Phase 2 to mark negotiation completed,
		 * since Acknowledged Result is expected. */
		if (sm->methodState == METHOD_DONE &&
		    sm->decision == DECISION_UNCOND_SUCC) {
			data->phase2_success = 1;
			sm->methodState = METHOD_CONT;
			sm->decision = DECISION_COND_SUCC;
		}
		break;
	case EAP_TYPE_TLV:
		if (eap_peap_phase2_tlv(sm, data, hdr, resp, resp_len))
			return -1;
		break;
	default:
		if (eap_peap_phase2_nak(sm, data, hdr, resp, resp_len))
			return -1;
		break;
	}
	return 0;
}


static int eap_peap_decrypt(struct eap_sm *sm,
			    struct eap_peap_data *data, struct eap_hdr *req,
			    u8 *in_data, size_t in_len,
			    u8 **out_data, size_t *out_len)
{
	u8 *in_decrypted;
	int buf_len, len_decrypted, len, skip_change = 0;
	struct eap_hdr *hdr;
	u8 *resp = NULL;
	size_t resp_len;

	wpa_printf(MSG_DEBUG, "EAP-PEAP: received %d bytes encrypted data for "
		   "Phase 2", in_len);

	BIO_write(data->ssl.ssl_in, in_data, in_len);

	if (data->ssl.tls_in_left > in_len) {
		data->ssl.tls_in_left -= in_len;
		wpa_printf(MSG_DEBUG, "EAP-PEAP: Need %d bytes more"
			   " input data", data->ssl.tls_in_left);
		return 1;
	} else
		data->ssl.tls_in_left = 0;

	BIO_reset(data->ssl.ssl_out);

	buf_len = in_len;
	if (data->ssl.tls_in_total > buf_len)
		buf_len = data->ssl.tls_in_total;
	in_decrypted = malloc(buf_len);
	if (in_decrypted == NULL)
		return 0;

	len_decrypted = SSL_read(data->ssl.ssl, in_decrypted, buf_len);
	if (len_decrypted < 0) {
		int err = SSL_get_error(data->ssl.ssl, len_decrypted);
		wpa_printf(MSG_INFO, "EAP-PEAP: SSL_read error %d", err);
		free(in_decrypted);
		return 0;
	}

	wpa_hexdump(MSG_DEBUG, "EAP-PEAP: Decrypted Phase 2 EAP", in_decrypted,
		    len_decrypted);

	hdr = (struct eap_hdr *) in_decrypted;
	if (len_decrypted == 5 && hdr->code == EAP_CODE_REQUEST &&
	    ntohs(hdr->length) == 5 &&
	    in_decrypted[4] == EAP_TYPE_IDENTITY) {
		/* At least FreeRADIUS seems to send full EAP header with
		 * EAP Request Identity */
		skip_change = 1;
	}
	if (len_decrypted >= 5 && hdr->code == EAP_CODE_REQUEST &&
	    in_decrypted[4] == EAP_TYPE_TLV) {
		skip_change = 1;
	}

	if (data->peap_version == 0 && !skip_change) {
		struct eap_hdr *nhdr = malloc(sizeof(struct eap_hdr) +
					      len_decrypted);
		if (nhdr == NULL) {
			free(in_decrypted);
			return 0;
		}
		memcpy((u8 *) (nhdr + 1), in_decrypted, len_decrypted);
		free(in_decrypted);
		nhdr->code = req->code;
		nhdr->identifier = req->identifier;
		nhdr->length = htons(sizeof(struct eap_hdr) + len_decrypted);

		len_decrypted += sizeof(struct eap_hdr);
		in_decrypted = (u8 *) nhdr;
	}
	hdr = (struct eap_hdr *) in_decrypted;
	if (len_decrypted < sizeof(*hdr)) {
		free(in_decrypted);
		wpa_printf(MSG_INFO, "EAP-PEAP: Too short Phase 2 "
			   "EAP frame (len=%d)", len_decrypted);
		return 0;
	}
	len = ntohs(hdr->length);
	if (len > len_decrypted) {
		free(in_decrypted);
		wpa_printf(MSG_INFO, "EAP-PEAP: Length mismatch in "
			   "Phase 2 EAP frame (len=%d hdr->length=%d)",
			   len_decrypted, len);
		return 0;
	}
	if (len < len_decrypted) {
		wpa_printf(MSG_INFO, "EAP-PEAP: Odd.. Phase 2 EAP header has "
			   "shorter length than full decrypted data (%d < %d)",
			   len, len_decrypted);
		if (len == 4 && len_decrypted == 5 &&
		    in_decrypted[4] == EAP_TYPE_IDENTITY) {
			/* Radiator 3.9 seems to set Phase 2 EAP header to use
			 * incorrect length for the EAP-Request Identity
			 * packet, so fix the inner header to interoperate..
			 * This was fixed in 2004-06-23 patch for Radiator and
			 * this workaround can be removed at some point. */
			wpa_printf(MSG_INFO, "EAP-PEAP: workaround -> replace "
				   "Phase 2 EAP header len (%d) with real "
				   "decrypted len (%d)", len, len_decrypted);
			len = len_decrypted;
			hdr->length = htons(len);
		}
	}
	wpa_printf(MSG_DEBUG, "EAP-PEAP: received Phase 2: code=%d "
		   "identifier=%d length=%d", hdr->code, hdr->identifier, len);
	switch (hdr->code) {
	case EAP_CODE_REQUEST:
		if (eap_peap_phase2_request(sm, data, req, hdr,
					    &resp, &resp_len)) {
			free(in_decrypted);
			wpa_printf(MSG_INFO, "EAP-PEAP: Phase2 Request "
				   "processing failed");
			return 0;
		}
		break;
	case EAP_CODE_SUCCESS:
		wpa_printf(MSG_DEBUG, "EAP-PEAP: Phase 2 Success");
		if (data->peap_version == 1) {
			struct eap_hdr *rhdr;
			/* EAP-Success within TLS tunnel is used to indicate
			 * shutdown of the TLS channel. The authentication has
			 * been completed. */
			wpa_printf(MSG_DEBUG, "EAP-PEAP: Version 1 - "
				   "EAP-Success within TLS tunnel - "
				   "authentication completed");
			sm->decision = DECISION_UNCOND_SUCC;
			sm->methodState = METHOD_DONE;
			if (data->peap_outer_success == 2) {
				free(in_decrypted);
				wpa_printf(MSG_DEBUG, "EAP-PEAP: Use TLS ACK "
					   "to finish authentication");
				return 1;
			} else if (data->peap_outer_success == 1) {
				/* Reply with EAP-Success within the TLS
				 * channel to complete the authentication. */
				resp_len = sizeof(struct eap_hdr);
				resp = malloc(resp_len);
				if (resp) {
					memset(resp, 0, resp_len);
					rhdr = (struct eap_hdr *) resp;
					rhdr->code = EAP_CODE_SUCCESS;
					rhdr->identifier = hdr->identifier;
					rhdr->length = htons(resp_len);
				}
			} else {
				/* No EAP-Success expected for Phase 1 (outer,
				 * unencrypted auth), so force EAP state
				 * machine to SUCCESS state. */
				sm->peap_done = TRUE;
			}
		} else {
			/* FIX: ? */
		}
		break;
	case EAP_CODE_FAILURE:
		wpa_printf(MSG_DEBUG, "EAP-PEAP: Phase 2 Failure");
		/* FIX: ? */
		break;
	default:
		wpa_printf(MSG_INFO, "EAP-PEAP: Unexpected code=%d in "
			   "Phase 2 EAP header", hdr->code);
		break;
	}

	free(in_decrypted);

	if (resp) {
		u8 *resp_pos;
		size_t resp_send_len;
		int skip_change = 0;

		wpa_hexdump(MSG_DEBUG, "EAP-PEAP: Encrypting Phase 2 data",
			    resp, resp_len);
		/* PEAP version changes */
		if (resp_len >= 5 && resp[0] == EAP_CODE_RESPONSE &&
		    resp[4] == EAP_TYPE_TLV)
			skip_change = 1;
		if (data->peap_version == 0 && !skip_change) {
			resp_pos = resp + sizeof(struct eap_hdr);
			resp_send_len = resp_len - sizeof(struct eap_hdr);
		} else {
			resp_pos = resp;
			resp_send_len = resp_len;
		}

		if (eap_peap_encrypt(sm, data, req->identifier,
				     resp_pos, resp_send_len,
				     out_data, out_len)) {
			wpa_printf(MSG_INFO, "EAP-PEAP: Failed to encrypt "
				   "a Phase 2 frame");
		}
		free(resp);
	}

	return 0;
}


static u8 * eap_peap_process(struct eap_sm *sm, void *priv,
			     u8 *reqData, size_t reqDataLen,
			     size_t *respDataLen)
{
	struct eap_hdr *req;
	unsigned long err;
	int left, res;
	unsigned int tls_msg_len;
	u8 flags, *pos, *resp, id;
	struct eap_peap_data *data = priv;

	err = ERR_get_error();
	if (err != 0) {
		do {
			wpa_printf(MSG_INFO, "EAP-PEAP - SSL error: %s",
				   ERR_error_string(err, NULL));
			err = ERR_get_error();
		} while (err != 0);
		sm->ignore = TRUE;
		return NULL;
	}

	req = (struct eap_hdr *) reqData;
	pos = (u8 *) (req + 1);
	if (reqDataLen < sizeof(*req) + 2 || *pos != EAP_TYPE_PEAP ||
	    (left = htons(req->length)) > reqDataLen) {
		wpa_printf(MSG_INFO, "EAP-PEAP: Invalid frame");
		sm->ignore = TRUE;
		return NULL;
	}
	left -= sizeof(struct eap_hdr);
	id = req->identifier;
	pos++;
	flags = *pos++;
	left -= 2;
	wpa_printf(MSG_DEBUG, "EAP-PEAP: Received packet(len=%d) - "
		   "Flags 0x%02x", reqDataLen, flags);
	if (flags & EAP_TLS_FLAGS_LENGTH_INCLUDED) {
		if (left < 4) {
			wpa_printf(MSG_INFO, "EAP-PEAP: Short frame with TLS "
				   "length");
			sm->ignore = TRUE;
			return NULL;
		}
		tls_msg_len = (pos[0] << 24) | (pos[1] << 16) | (pos[2] << 8) |
			pos[3];
		wpa_printf(MSG_DEBUG, "EAP-PEAP: TLS Message Length: %d",
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
		wpa_printf(MSG_DEBUG, "EAP-PEAP: Start (server ver=%d, own "
			   "ver=%d)", flags & EAP_PEAP_VERSION_MASK,
			data->peap_version);
		if ((flags & EAP_PEAP_VERSION_MASK) < data->peap_version)
			data->peap_version = flags & EAP_PEAP_VERSION_MASK;
		if (data->force_peap_version >= 0 &&
		    data->force_peap_version != data->peap_version) {
			wpa_printf(MSG_WARNING, "EAP-PEAP: Failed to select "
				   "forced PEAP version %d",
				   data->force_peap_version);
			sm->methodState = METHOD_DONE;
			sm->decision = DECISION_FAIL;
			sm->ignore = TRUE;
			return NULL;
		}
		wpa_printf(MSG_DEBUG, "EAP-PEAP: Using PEAP version %d",
			   data->peap_version);
		left = 0; /* make sure that this frame is empty, even though it
			   * should always be, anyway */
	}

	resp = NULL;
	if (SSL_is_init_finished(data->ssl.ssl)) {
		res = eap_peap_decrypt(sm, data, req, pos, left,
				       &resp, respDataLen);
	} else {
		res = eap_tls_process_helper(sm, &data->ssl, EAP_TYPE_PEAP,
					     data->peap_version, id, pos, left,
					     &resp, respDataLen);

		if (SSL_is_init_finished(data->ssl.ssl)) {
			char *label;
			wpa_printf(MSG_DEBUG,
				   "EAP-PEAP: TLS done, proceed to Phase 2");
			sm->methodState = METHOD_CONT;
			free(sm->eapKeyData);
			/* draft-josefsson-ppext-eap-tls-eap-05.txt
			 * specifies that PEAPv1 would use "client PEAP
			 * encryption" as the label. However, most existing
			 * PEAPv1 implementations seem to be using the old
			 * label, "client EAP encryption", instead. Use the old
			 * label by default, but allow it to be configured with
			 * phase1 parameter peaplabel=1. */
			if (data->peap_version > 1 || data->force_new_label)
				label = "client PEAP encryption";
			else
				label = "client EAP encryption";
			wpa_printf(MSG_DEBUG, "EAP-PEAP: using label '%s' in "
				   "key derivation", label);
			sm->eapKeyData =
				eap_tls_derive_key(data->ssl.ssl, label);
			if (sm->eapKeyData) {
				sm->eapKeyDataLen = EAP_TLS_KEY_LEN;
				wpa_hexdump(MSG_DEBUG, "EAP-PEAP: Derived key",
					    sm->eapKeyData, sm->eapKeyDataLen);
			} else {
				wpa_printf(MSG_DEBUG, "EAP-PEAP: Failed to "
					   "derive key");
			}
		}
	}

	if (res == 1)
		return eap_tls_build_ack(respDataLen, id, EAP_TYPE_PEAP,
					 data->peap_version);
	return resp;
}


const struct eap_method eap_method_peap =
{
	.method = EAP_TYPE_PEAP,
	.init = eap_peap_init,
	.deinit = eap_peap_deinit,
	.process = eap_peap_process,
};
