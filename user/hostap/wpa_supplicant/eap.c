/*
 * WPA Supplicant / EAP state machines
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


#ifdef EAP_MD5
extern const struct eap_method eap_method_md5;
#endif
#ifdef EAP_TLS
extern const struct eap_method eap_method_tls;
#endif
#ifdef EAP_MSCHAPv2
extern const struct eap_method eap_method_mschapv2;
#endif
#ifdef EAP_PEAP
extern const struct eap_method eap_method_peap;
#endif
#ifdef EAP_TTLS
extern const struct eap_method eap_method_ttls;
#endif
#ifdef EAP_GTC
extern const struct eap_method eap_method_gtc;
#endif
#ifdef EAP_OTP
extern const struct eap_method eap_method_otp;
#endif
#ifdef EAP_SIM
extern const struct eap_method eap_method_sim;
#endif
#ifdef EAP_LEAP
extern const struct eap_method eap_method_leap;
#endif

static const struct eap_method *eap_methods[] =
{
#ifdef EAP_MD5
	&eap_method_md5,
#endif
#ifdef EAP_TLS
	&eap_method_tls,
#endif
#ifdef EAP_MSCHAPv2
	&eap_method_mschapv2,
#endif
#ifdef EAP_PEAP
	&eap_method_peap,
#endif
#ifdef EAP_TTLS
	&eap_method_ttls,
#endif
#ifdef EAP_GTC
	&eap_method_gtc,
#endif
#ifdef EAP_OTP
	&eap_method_otp,
#endif
#ifdef EAP_SIM
	&eap_method_sim,
#endif
#ifdef EAP_LEAP
	&eap_method_leap,
#endif
};
#define NUM_EAP_METHODS (sizeof(eap_methods) / sizeof(eap_methods[0]))


const struct eap_method * eap_sm_get_eap_methods(int method)
{
	int i;
	for (i = 0; i < NUM_EAP_METHODS; i++) {
		if (eap_methods[i]->method == method)
			return eap_methods[i];
	}
	return NULL;
}


static Boolean eap_sm_allowMethod(struct eap_sm *sm, EapType method);
static u8 * eap_sm_buildNak(struct eap_sm *sm, int id, size_t *len);
static void eap_sm_processIdentity(struct eap_sm *sm, u8 *req, size_t len);
static void eap_sm_processNotify(struct eap_sm *sm, u8 *req, size_t len);
static u8 * eap_sm_buildNotify(struct eap_sm *sm, int id, size_t *len);
static void eap_sm_parseEapReq(struct eap_sm *sm, u8 *req, size_t len);
static const struct eap_method * eap_sm_get_method(int method);


/* Definitions for clarifying state machine implementation */
#define SM_STATE(machine, state) \
static void sm_ ## machine ## _ ## state ## _Enter(struct eap_sm *sm, \
	int global)

#define SM_ENTRY(machine, state) \
if (!global || sm->machine ## _state != machine ## _ ## state) { \
	sm->changed = TRUE; \
	wpa_printf(MSG_DEBUG, "EAP: " #machine " entering state " #state); \
} \
sm->machine ## _state = machine ## _ ## state;

#define SM_ENTER(machine, state) \
sm_ ## machine ## _ ## state ## _Enter(sm, 0)
#define SM_ENTER_GLOBAL(machine, state) \
sm_ ## machine ## _ ## state ## _Enter(sm, 1)

#define SM_STEP(machine) \
static void sm_ ## machine ## _Step(struct eap_sm *sm)

#define SM_STEP_RUN(machine) sm_ ## machine ## _Step(sm)


SM_STATE(EAP, INITIALIZE)
{
	SM_ENTRY(EAP, INITIALIZE);
	if (sm->m && sm->eap_method_priv)
		sm->m->deinit(sm, sm->eap_method_priv);
	sm->eap_method_priv = NULL;
	sm->selectedMethod = EAP_TYPE_NONE;
	sm->m = NULL;
	sm->methodState = METHOD_NONE;
	sm->allowNotifications = TRUE;
	sm->decision = DECISION_FAIL;
	sm->eapol->idleWhile = sm->ClientTimeout;
	sm->eapol->eapSuccess = FALSE;
	sm->eapol->eapFail = FALSE;
	free(sm->eapKeyData);
	sm->eapKeyData = NULL;
	sm->eapKeyAvailable = FALSE;
	sm->eapol->eapRestart = FALSE;
	sm->lastId = -1; /* new session - make sure this does not match with
			  * the first EAP-Packet */
	/* draft-ietf-eap-statemachine-02.pdf does not reset eapResp and
	 * eapNoResp here. However, this seemed to be able to trigger cases
	 * where both were set and if EAPOL state machine uses eapNoResp first,
	 * it may end up not sending a real reply correctly. This occurred
	 * when the workaround in FAIL state set eapNoResp = TRUE.. Maybe that
	 * workaround needs to be fixed to do something else(?) */
	sm->eapol->eapResp = FALSE;
	sm->eapol->eapNoResp = FALSE;
}


SM_STATE(EAP, DISABLED)
{
	SM_ENTRY(EAP, DISABLED);
}


SM_STATE(EAP, IDLE)
{
	SM_ENTRY(EAP, IDLE);
}


SM_STATE(EAP, RECEIVED)
{
	SM_ENTRY(EAP, RECEIVED);
	/* parse rxReq, rxSuccess, rxFailure, reqId, reqMethod */
	eap_sm_parseEapReq(sm, sm->eapol->eapReqData,
			   sm->eapol->eapReqDataLen);
}


SM_STATE(EAP, GET_METHOD)
{
	SM_ENTRY(EAP, GET_METHOD);
	if (eap_sm_allowMethod(sm, sm->reqMethod)) {
		if (sm->m && sm->eap_method_priv)
			sm->m->deinit(sm, sm->eap_method_priv);
		sm->eap_method_priv = NULL;
		sm->selectedMethod = sm->reqMethod;
		sm->m = eap_sm_get_method(sm->selectedMethod);
		if (sm->m) {
			sm->eap_method_priv = sm->m->init(sm);
			if (sm->eap_method_priv == NULL) {
				wpa_printf(MSG_DEBUG, "EAP: Failed to "
					   "initialize EAP method %d",
					   sm->selectedMethod);
				sm->m = NULL;
				sm->methodState = METHOD_NONE;
			}
		}
		sm->methodState = METHOD_INIT;
	} else {
		free(sm->eapRespData);
		sm->eapRespData = eap_sm_buildNak(sm, sm->reqId,
						  &sm->eapRespDataLen);
	}
}


SM_STATE(EAP, METHOD)
{
	SM_ENTRY(EAP, METHOD);
	if (sm->m == NULL) {
		wpa_printf(MSG_WARNING, "EAP::METHOD - method not selected");
		return;
	}

	/* Get ignore, methodState, decision, allowNotifications, and
	 * eapRespData. This will also fill in eapKeyData, if keying material
	 * is available. */
	free(sm->eapRespData);
	sm->eapRespData = sm->m->process(sm, sm->eap_method_priv,
					 sm->eapol->eapReqData,
					 sm->eapol->eapReqDataLen,
					 &sm->eapRespDataLen);
}


SM_STATE(EAP, SEND_RESPONSE)
{
	SM_ENTRY(EAP, SEND_RESPONSE);
	free(sm->lastRespData);
	if (sm->eapRespData) {
		sm->lastId = sm->reqId;
		sm->lastRespData = malloc(sm->eapRespDataLen);
		if (sm->lastRespData) {
			memcpy(sm->lastRespData, sm->eapRespData,
			       sm->eapRespDataLen);
			sm->lastRespDataLen = sm->eapRespDataLen;
		}
		sm->eapol->eapResp = TRUE;
	} else
		sm->lastRespData = NULL;
	sm->eapol->eapReq = FALSE;
	sm->eapol->idleWhile = sm->ClientTimeout;
}


SM_STATE(EAP, DISCARD)
{
	SM_ENTRY(EAP, DISCARD);
	sm->eapol->eapReq = FALSE;
	sm->eapol->eapNoResp = TRUE;
}


SM_STATE(EAP, IDENTITY)
{
	SM_ENTRY(EAP, IDENTITY);
	eap_sm_processIdentity(sm, sm->eapol->eapReqData,
			       sm->eapol->eapReqDataLen);
	free(sm->eapRespData);
	sm->eapRespData = eap_sm_buildIdentity(sm, sm->reqId,
					       &sm->eapRespDataLen, 0);
}


SM_STATE(EAP, NOTIFICATION)
{
	SM_ENTRY(EAP, NOTIFICATION);
	eap_sm_processNotify(sm, sm->eapol->eapReqData,
			     sm->eapol->eapReqDataLen);
	free(sm->eapRespData);
	sm->eapRespData = eap_sm_buildNotify(sm, sm->reqId,
					     &sm->eapRespDataLen);
}


SM_STATE(EAP, RETRANSMIT)
{
	SM_ENTRY(EAP, RETRANSMIT);
	free(sm->eapRespData);
	if (sm->lastRespData) {
		sm->eapRespData = malloc(sm->lastRespDataLen);
		if (sm->eapRespData) {
			memcpy(sm->eapRespData, sm->lastRespData,
			       sm->lastRespDataLen);
			sm->eapRespDataLen = sm->lastRespDataLen;
		}
	} else
		sm->eapRespData = NULL;
}


SM_STATE(EAP, SUCCESS)
{
	SM_ENTRY(EAP, SUCCESS);
	if (sm->eapKeyData != NULL)
		sm->eapKeyAvailable = TRUE;
	sm->eapol->eapSuccess = TRUE;
	/* draft-ietf-eap-statemachine-02.pdf does not clear eapReq here, but
	 * this seems to be required to avoid processing the same request
	 * twice when state machine is initialized. */
	sm->eapol->eapReq = FALSE;
	/* draft-ietf-eap-statemachine-02.pdf does not set eapNoResp here, but
	 * this seems to be required to get EAPOL Supplicant backend state
	 * machine into SUCCESS state. In addition, either eapResp or eapNoResp
	 * is required to be set after processing the received EAP frame. */
	sm->eapol->eapNoResp = TRUE;
}


SM_STATE(EAP, FAILURE)
{
	SM_ENTRY(EAP, FAILURE);
	sm->eapol->eapFail = TRUE;
	/* draft-ietf-eap-statemachine-02.pdf does not clear eapReq here, but
	 * this seems to be required to avoid processing the same request
	 * twice when state machine is initialized. */
	sm->eapol->eapReq = FALSE;
	/* draft-ietf-eap-statemachine-02.pdf does not set eapNoResp here.
	 * However, either eapResp or eapNoResp is required to be set after
	 * processing the received EAP frame. */
	sm->eapol->eapNoResp = TRUE;
}


static int eap_success_workaround(int reqId, int lastId)
{
	const int workaround_enabled = 1; /* TODO: make this configurable(?) */
	/* At least Microsoft IAS seems to send EAP-Success with lastId + 1
	 * after EAP-PEAP/MSCHAPv2. EAP state machines,
	 * draft-ietf-eap-statemachine-02.pdf, require that reqId == lastId.
	 * Accept any reqId to interoperate with IAS. These are unauthenticated
	 * plaintext messages, so this should have no security implications.
	 * This could maybe just verify that reqId == lastId ||
	 * reqId == (lastId + 1) 0xff, since other values were not yet
	 * observed. */
	if (workaround_enabled) {
		wpa_printf(MSG_DEBUG, "EAP: Workaround for unexpected "
			   "identifier field in EAP Success: "
			   "reqId=%d lastId=%d (these are supposed to be "
			   "same)", reqId, lastId);
		return 1;
	}
	return 0;
}


SM_STEP(EAP)
{
	if (sm->eapol->eapRestart && sm->eapol->portEnabled)
		SM_ENTER_GLOBAL(EAP, INITIALIZE);
	else if (!sm->eapol->portEnabled)
		SM_ENTER_GLOBAL(EAP, DISABLED);
	else switch (sm->EAP_state) {
	case EAP_INITIALIZE:
		SM_ENTER(EAP, IDLE);
		break;
	case EAP_DISABLED:
		if (sm->eapol->portEnabled)
			SM_ENTER(EAP, INITIALIZE);
		break;
	case EAP_IDLE:
		if (sm->eapol->eapReq)
			SM_ENTER(EAP, RECEIVED);
		else if ((sm->eapol->altAccept &&
			  sm->decision != DECISION_FAIL) ||
			 (sm->eapol->idleWhile == 0 &&
			  sm->decision == DECISION_UNCOND_SUCC))
			SM_ENTER(EAP, SUCCESS);
		else if (sm->eapol->altReject ||
			 (sm->eapol->idleWhile == 0 &&
			  sm->decision != DECISION_UNCOND_SUCC) ||
			 (sm->eapol->altAccept &&
			  sm->methodState != METHOD_CONT &&
			  sm->decision == DECISION_FAIL))
			SM_ENTER(EAP, FAILURE);
		else if (sm->selectedMethod == EAP_TYPE_LEAP &&
			 sm->leap_done && sm->decision != DECISION_FAIL &&
			 sm->methodState == METHOD_DONE)
			SM_ENTER(EAP, SUCCESS);
		else if (sm->selectedMethod == EAP_TYPE_PEAP &&
			 sm->peap_done && sm->decision != DECISION_FAIL &&
			 sm->methodState == METHOD_DONE)
			SM_ENTER(EAP, SUCCESS);
		break;
	case EAP_RECEIVED:
		if (sm->rxSuccess &&
		    (sm->reqId == sm->lastId ||
		     eap_success_workaround(sm->reqId, sm->lastId)) &&
		    sm->decision != DECISION_FAIL)
			SM_ENTER(EAP, SUCCESS);
		else if (sm->methodState != METHOD_CONT &&
			 ((sm->rxFailure &&
			   sm->decision != DECISION_UNCOND_SUCC) ||
			  (sm->rxSuccess && sm->decision == DECISION_FAIL)) &&
			 sm->reqId == sm->lastId)
			SM_ENTER(EAP, FAILURE);
		else if (sm->rxReq && sm->reqId == sm->lastId)
			SM_ENTER(EAP, RETRANSMIT);
		else if (sm->rxReq && sm->reqId != sm->lastId &&
			 sm->reqMethod == EAP_TYPE_NOTIFICATION &&
			 sm->allowNotifications)
			SM_ENTER(EAP, NOTIFICATION);
		else if (sm->rxReq && sm->reqId != sm->lastId &&
			 sm->selectedMethod == EAP_TYPE_NONE &&
			 sm->reqMethod == EAP_TYPE_IDENTITY)
			SM_ENTER(EAP, IDENTITY);
		else if (sm->rxReq && sm->reqId != sm->lastId &&
			 sm->selectedMethod == EAP_TYPE_NONE &&
			 sm->reqMethod != EAP_TYPE_IDENTITY &&
			 sm->reqMethod != EAP_TYPE_NOTIFICATION)
			SM_ENTER(EAP, GET_METHOD);
		else if (sm->rxReq && sm->reqId != sm->lastId &&
			 sm->reqMethod == sm->selectedMethod &&
			 sm->methodState != METHOD_DONE)
			SM_ENTER(EAP, METHOD);
		else if (sm->selectedMethod == EAP_TYPE_LEAP &&
			 (sm->rxSuccess || sm->rxResp))
			SM_ENTER(EAP, METHOD);
		else
			SM_ENTER(EAP, DISCARD);
		break;
	case EAP_GET_METHOD:
		if (sm->selectedMethod == sm->reqMethod)
			SM_ENTER(EAP, METHOD);
		else
			SM_ENTER(EAP, SEND_RESPONSE);
		break;
	case EAP_METHOD:
		if (sm->ignore)
			SM_ENTER(EAP, DISCARD);
		else
			SM_ENTER(EAP, SEND_RESPONSE);
		break;
	case EAP_SEND_RESPONSE:
		SM_ENTER(EAP, IDLE);
		break;
	case EAP_DISCARD:
		SM_ENTER(EAP, IDLE);
		break;
	case EAP_IDENTITY:
		SM_ENTER(EAP, SEND_RESPONSE);
		break;
	case EAP_NOTIFICATION:
		SM_ENTER(EAP, SEND_RESPONSE);
		break;
	case EAP_RETRANSMIT:
		SM_ENTER(EAP, SEND_RESPONSE);
		break;
	case EAP_SUCCESS:
		break;
	case EAP_FAILURE:
		break;
	}
}


static Boolean eap_sm_allowMethod(struct eap_sm *sm, EapType method)
{
	struct wpa_ssid *config = sm->eapol->config;
	int i;

	if (!wpa_config_allowed_eap_method(config, method))
		return FALSE;
	for (i = 0; i < NUM_EAP_METHODS; i++) {
		if (eap_methods[i]->method == method)
			return TRUE;
	}
	return FALSE;
}


static u8 *eap_sm_buildNak(struct eap_sm *sm, int id, size_t *len)
{
	struct wpa_ssid *config = sm->eapol->config;
	struct eap_hdr *resp;
	u8 *pos;
	int i, found = 0;

	wpa_printf(MSG_DEBUG, "EAP: Building EAP-Nak (requested type %d not "
		   "allowed)", sm->reqMethod);
	*len = sizeof(struct eap_hdr) + 1;
	resp = malloc(*len + NUM_EAP_METHODS);
	if (resp == NULL)
		return NULL;

	resp->code = EAP_CODE_RESPONSE;
	resp->identifier = id;
	pos = (u8 *) (resp + 1);
	*pos++ = EAP_TYPE_NAK;

	for (i = 0; i < NUM_EAP_METHODS; i++) {
		if (wpa_config_allowed_eap_method(config,
						  eap_methods[i]->method)) {
			*pos++ = eap_methods[i]->method;
			(*len)++;
			found++;
		}
	}
	if (!found) {
		*pos = EAP_TYPE_NONE;
		(*len)++;
	}
	wpa_hexdump(MSG_DEBUG, "EAP: allowed methods",
		    ((u8 *) (resp + 1)) + 1, found);

	resp->length = htons(*len);

	return (u8 *) resp;
}


static void eap_sm_processIdentity(struct eap_sm *sm, u8 *req, size_t len)
{
	struct eap_hdr *hdr = (struct eap_hdr *) req;
	u8 *pos = (u8 *) (hdr + 1);
	pos++;
	/* TODO: could save displayable message so that it can be shown to the
	 * user in case of interaction is required */
	wpa_hexdump_ascii(MSG_DEBUG, "EAP: EAP-Request Identity data",
			  pos, ntohs(hdr->length) - 5);
}


u8 *eap_sm_buildIdentity(struct eap_sm *sm, int id, size_t *len,
			 int encrypted)
{
	struct wpa_ssid *config = sm->eapol->config;
	struct eap_hdr *resp;
	u8 *pos, *identity;
	size_t identity_len;

	if (config == NULL) {
		wpa_printf(MSG_WARNING, "EAP: buildIdentity: configuration "
			   "was not available");
		return NULL;
	}

	if (!encrypted && config->anonymous_identity) {
		identity = config->anonymous_identity;
		identity_len = config->anonymous_identity_len;
		wpa_hexdump_ascii(MSG_DEBUG, "EAP: using anonymous identity",
				  identity, identity_len);
	} else {
		identity = config->identity;
		identity_len = config->identity_len;
		wpa_hexdump_ascii(MSG_DEBUG, "EAP: using real identity",
				  identity, identity_len);
	}

	if (identity == NULL) {
		wpa_printf(MSG_WARNING, "EAP: buildIdentity: identity "
			   "configuration was not available");
		eap_sm_request_identity(sm, config);
		return NULL;
	}


	*len = sizeof(struct eap_hdr) + 1 + identity_len;
	resp = malloc(*len);
	if (resp == NULL)
		return NULL;

	resp->code = EAP_CODE_RESPONSE;
	resp->identifier = id;
	resp->length = htons(*len);
	pos = (u8 *) (resp + 1);
	*pos++ = EAP_TYPE_IDENTITY;
	memcpy(pos, identity, identity_len);

	return (u8 *) resp;
}


static void eap_sm_processNotify(struct eap_sm *sm, u8 *req, size_t len)
{
	struct eap_hdr *hdr = (struct eap_hdr *) req;
	u8 *pos = (u8 *) (hdr + 1);
	pos++;
	/* TODO: log the Notification Request and make it available for UI */
	wpa_hexdump_ascii(MSG_DEBUG, "EAP: EAP-Request Notification data",
			  pos, ntohs(hdr->length) - 5);
}


static u8 *eap_sm_buildNotify(struct eap_sm *sm, int id, size_t *len)
{
	struct eap_hdr *resp;
	u8 *pos;

	wpa_printf(MSG_DEBUG, "EAP: Generating EAP-Response Notification");
	*len = sizeof(struct eap_hdr) + 1;
	resp = malloc(*len);
	if (resp == NULL)
		return NULL;

	resp->code = EAP_CODE_RESPONSE;
	resp->identifier = id;
	resp->length = htons(*len);
	pos = (u8 *) (resp + 1);
	*pos = EAP_TYPE_NOTIFICATION;

	return (u8 *) resp;
}


static void eap_sm_parseEapReq(struct eap_sm *sm, u8 *req, size_t len)
{
	struct eap_hdr *hdr;
	int plen;

	sm->rxReq = sm->rxSuccess = sm->rxFailure = FALSE;
	sm->reqId = 0;
	sm->reqMethod = EAP_TYPE_NONE;

	if (req == NULL || len < sizeof(*hdr))
		return;

	hdr = (struct eap_hdr *) req;
	plen = ntohs(hdr->length);
	if (plen > len) {
		wpa_printf(MSG_DEBUG, "EAP: Ignored truncated EAP-Packet "
			   "(len=%d plen=%d)", len, plen);
		return;
	}
	sm->reqId = hdr->identifier;
	switch (hdr->code) {
	case EAP_CODE_REQUEST:
		sm->rxReq = TRUE;
		if (plen > sizeof(*hdr))
			sm->reqMethod = *((u8 *) (hdr + 1));
		wpa_printf(MSG_DEBUG, "EAP: Received EAP-Request method=%d "
			   "id=%d", sm->reqMethod, sm->reqId);
		break;
	case EAP_CODE_RESPONSE:
		if (sm->selectedMethod == EAP_TYPE_LEAP) {
			sm->rxResp = TRUE;
			if (plen > sizeof(*hdr))
				sm->reqMethod = *((u8 *) (hdr + 1));
			wpa_printf(MSG_DEBUG, "EAP: Received EAP-Response for "
				   "LEAP method=%d id=%d",
				   sm->reqMethod, sm->reqId);
			break;
		}
		wpa_printf(MSG_DEBUG, "EAP: Ignored EAP-Response");
		break;
	case EAP_CODE_SUCCESS:
		wpa_printf(MSG_DEBUG, "EAP: Received EAP-Success");
		sm->rxSuccess = TRUE;
		break;
	case EAP_CODE_FAILURE:
		wpa_printf(MSG_DEBUG, "EAP: Received EAP-Failure");
		sm->rxFailure = TRUE;
		break;
	default:
		wpa_printf(MSG_DEBUG, "EAP: Ignored EAP-Packet with unknown "
			   "code %d", hdr->code);
		break;
	}
}


static const struct eap_method * eap_sm_get_method(int method)
{
	int i;
	for (i = 0; i < NUM_EAP_METHODS; i++) {
		if (eap_methods[i]->method == method)
			return eap_methods[i];
	}
	return NULL;
}


#ifdef EAP_TLS_FUNCS
static void ssl_info_cb(const SSL *ssl, int where, int ret)
{
	const char *str;
	int w;

	wpa_printf(MSG_DEBUG, "SSL: (where=0x%x ret=0x%x)", where, ret);
	w = where & ~SSL_ST_MASK;
	if (w & SSL_ST_CONNECT)
		str = "SSL_connect";
	else if (w & SSL_ST_ACCEPT)
		str = "SSL_accept";
	else
		str = "undefined";

	if (where & SSL_CB_LOOP) {
		wpa_printf(MSG_DEBUG, "SSL: %s:%s",
			   str, SSL_state_string_long(ssl));
	} else if (where & SSL_CB_ALERT) {
		wpa_printf(MSG_DEBUG, "SSL: SSL3 alert: %s:%s:%s",
			   where & SSL_CB_READ ? "read" : "write",
			   SSL_alert_type_string_long(ret),
			   SSL_alert_desc_string_long(ret));
	} else if (where & SSL_CB_EXIT && ret <= 0) {
		wpa_printf(MSG_DEBUG, "SSL: %s:%s in %s",
			   str, ret == 0 ? "failed" : "error",
			   SSL_state_string_long(ssl));
	}
}
#endif /* EAP_TLS_FUNCS */


struct eap_sm *eap_sm_init(struct eapol_sm *eapol)
{
	struct eap_sm *sm;

	sm = malloc(sizeof(*sm));
	if (sm == NULL)
		return NULL;
	memset(sm, 0, sizeof(*sm));
	sm->eapol = eapol;
	sm->ClientTimeout = 60;

#ifdef EAP_TLS_FUNCS
	SSL_load_error_strings();
	SSL_library_init();
	/* TODO: if /dev/urandom is available, PRNG is seeded automatically.
	 * If this is not the case, random data should be added here. */

	sm->ssl_ctx = SSL_CTX_new(TLSv1_method());
	if (sm->ssl_ctx == NULL) {
		wpa_printf(MSG_WARNING, "SSL: Failed to initialize TLS "
			   "context.");
		free(sm);
		return NULL;
	}

	SSL_CTX_set_info_callback(sm->ssl_ctx, ssl_info_cb);
#endif /* EAP_TLS_FUNCS */

	return sm;
}


void eap_sm_deinit(struct eap_sm *sm)
{
	if (sm == NULL)
		return;
	if (sm->m && sm->eap_method_priv)
		sm->m->deinit(sm, sm->eap_method_priv);
	free(sm->lastRespData);
	free(sm->eapRespData);
	free(sm->eapKeyData);
#ifdef EAP_TLS_FUNCS
	SSL_CTX_free(sm->ssl_ctx);
	ERR_free_strings();
#endif /* EAP_TLS_FUNCS */
	free(sm);
}


int eap_sm_step(struct eap_sm *sm)
{
	int res = 0;
	do {
		sm->changed = FALSE;
		SM_STEP_RUN(EAP);
		if (sm->changed)
			res = 1;
	} while (sm->changed);
	return res;
}


void eap_sm_abort(struct eap_sm *sm)
{
	/* release system resources that may have been allocated for the
	 * authentication session */
	free(sm->eapRespData);
	sm->eapRespData = NULL;
	free(sm->eapKeyData);
	sm->eapKeyData = NULL;
}


static const char * eap_sm_state_txt(int state)
{
	switch (state) {
	case EAP_INITIALIZE:
		return "INITIALIZE";
	case EAP_DISABLED:
		return "DISABLED";
	case EAP_IDLE:
		return "IDLE";
	case EAP_RECEIVED:
		return "RECEIVED";
	case EAP_GET_METHOD:
		return "GET_METHOD";
	case EAP_METHOD:
		return "METHOD";
	case EAP_SEND_RESPONSE:
		return "SEND_RESPONSE";
	case EAP_DISCARD:
		return "DISCARD";
	case EAP_IDENTITY:
		return "IDENTITY";
	case EAP_NOTIFICATION:
		return "NOTIFICATION";
	case EAP_RETRANSMIT:
		return "RETRANSMIT";
	case EAP_SUCCESS:
		return "SUCCESS";
	case EAP_FAILURE:
		return "FAILURE";
	default:
		return "UNKNOWN";
	}
}


static const char * eap_sm_method_state_txt(int state)
{
	switch (state) {
	case METHOD_NONE:
		return "NONE";
	case METHOD_INIT:
		return "INIT";
	case METHOD_CONT:
		return "CONT";
	case METHOD_MAY_CONT:
		return "MAY_CONT";
	case METHOD_DONE:
		return "DONE";
	default:
		return "UNKNOWN";
	}
}


static const char * eap_sm_decision_txt(int decision)
{
	switch (decision) {
	case DECISION_FAIL:
		return "FAIL";
	case DECISION_COND_SUCC:
		return "COND_SUCC";
	case DECISION_UNCOND_SUCC:
		return "UNCOND_SUCC";
	default:
		return "UNKNOWN";
	}
}


int eap_sm_get_status(struct eap_sm *sm, char *buf, size_t buflen)
{
	int len;
	if (sm == NULL)
		return 0;
	len = snprintf(buf, buflen,
		       "EAP state=%s\n"
		       "reqMethod=%d\n"
		       "selectedMethod=%d\n"
		       "methodState=%s\n"
		       "decision=%s\n"
		       "ClientTimeout=%d\n",
		       eap_sm_state_txt(sm->EAP_state),
		       sm->reqMethod,
		       sm->selectedMethod,
		       eap_sm_method_state_txt(sm->methodState),
		       eap_sm_decision_txt(sm->decision),
		       sm->ClientTimeout);
	return len;
}


typedef enum { TYPE_IDENTITY, TYPE_PASSWORD, TYPE_OTP } eap_ctrl_req_type;

static void eap_sm_request(struct eap_sm *sm, struct wpa_ssid *config,
			   eap_ctrl_req_type type, char *msg, size_t msglen)
{
	char *buf;
	size_t buflen;
	int len;
	char *field;
	char *txt, *tmp;

	if (config == NULL || sm == NULL || sm->eapol == NULL ||
	    sm->eapol->ctx->msg_ctx == NULL)
		return;

	switch (type) {
	case TYPE_IDENTITY:
		field = "IDENTITY";
		txt = "Identity";
		config->pending_req_identity++;
		break;
	case TYPE_PASSWORD:
		field = "PASSWORD";
		txt = "Password";
		config->pending_req_password++;
		break;
	case TYPE_OTP:
		field = "OTP";
		if (msg) {
			tmp = malloc(msglen + 3);
			if (tmp == NULL)
				return;
			tmp[0] = '[';
			memcpy(tmp + 1, msg, msglen);
			tmp[msglen + 1] = ']';
			tmp[msglen + 2] = '\0';
			txt = tmp;
			free(config->pending_req_otp);
			config->pending_req_otp = tmp;
			config->pending_req_otp_len = msglen + 3;
		} else {
			if (config->pending_req_otp == NULL)
				return;
			txt = config->pending_req_otp;
		}
		break;
	default:
		return;
	}

	buflen = 100 + strlen(txt) + config->ssid_len;
	buf = malloc(buflen);
	if (buf == NULL)
		return;
	len = snprintf(buf, buflen, "CTRL-REQ-%s-%d:%s needed for SSID ",
		       field, config->id, txt);
	if (config->ssid && buflen > len + config->ssid_len) {
		memcpy(buf + len, config->ssid, config->ssid_len);
		len += config->ssid_len;
		buf[len] = '\0';
	}
	wpa_msg(sm->eapol->ctx->msg_ctx, MSG_INFO, buf);
	free(buf);
}


void eap_sm_request_identity(struct eap_sm *sm, struct wpa_ssid *config)
{
	eap_sm_request(sm, config, TYPE_IDENTITY, NULL, 0);
}


void eap_sm_request_password(struct eap_sm *sm, struct wpa_ssid *config)
{
	eap_sm_request(sm, config, TYPE_PASSWORD, NULL, 0);
}


void eap_sm_request_otp(struct eap_sm *sm, struct wpa_ssid *config,
			char *msg, size_t msg_len)
{
	eap_sm_request(sm, config, TYPE_OTP, msg, msg_len);
}


void eap_sm_notify_ctrl_attached(struct eap_sm *sm)
{
	struct wpa_ssid *config;

	if (sm == NULL || sm->eapol == NULL)
		return;
	config = sm->eapol->config;
	if (config == NULL)
		return;

	/* Re-send any pending requests for user data since a new control
	 * interface was added. This handles cases where the EAP authentication
	 * starts immediately after system startup when the user interface is
	 * not yet running. */
	if (config->pending_req_identity)
		eap_sm_request_identity(sm, config);
	if (config->pending_req_password)
		eap_sm_request_password(sm, config);
	if (config->pending_req_otp)
		eap_sm_request_otp(sm, config, NULL, 0);
}
