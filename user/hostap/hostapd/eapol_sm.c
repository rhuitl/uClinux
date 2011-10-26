/*
 * Host AP (software wireless LAN access point) user space daemon for
 * Host AP kernel driver / IEEE 802.1X Authenticator - EAPOL state machine
 * Copyright (c) 2002-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

#include "hostapd.h"
#include "ieee802_1x.h"
#include "eapol_sm.h"
#include "eloop.h"
#include "wpa.h"
#include "sta_info.h"

/* TODO:
 * implement state machines: Controlled Directions and Key Receive
 */


/* EAPOL state machines are described in IEEE Std 802.1X-2001, Chap. 8.5 */

#define setPortAuthorized() \
ieee802_1x_set_sta_authorized(sm->hapd, sm->sta, 1)
#define setPortUnauthorized() \
ieee802_1x_set_sta_authorized(sm->hapd, sm->sta, 0)

/* procedures */
#define txCannedFail(x) ieee802_1x_tx_canned_eap(sm->hapd, sm->sta, (x), 0)
#define txCannedSuccess(x) ieee802_1x_tx_canned_eap(sm->hapd, sm->sta, (x), 1)
/* TODO: IEEE 802.1aa/D4 replaces txReqId(x) with txInitialMsg(x); value of
 * initialEAPMsg should be used to select which type of EAP packet is sent;
 * Currently, hostapd only supports EAP Request/Identity, so this can be
 * hardcoded. */
#define txInitialMsg(x) ieee802_1x_request_identity(sm->hapd, sm->sta, (x))
#define txReq(x) ieee802_1x_tx_req(sm->hapd, sm->sta, (x))
#define sendRespToServer ieee802_1x_send_resp_to_server(sm->hapd, sm->sta)
/* TODO: check if abortAuth would be needed for something */
#define abortAuth do { } while (0)
#define txKey(x) ieee802_1x_tx_key(sm->hapd, sm->sta, (x))


/* Definitions for clarifying state machine implementation */
#define SM_STATE(machine, state) \
static void sm_ ## machine ## _ ## state ## _Enter(struct eapol_state_machine \
*sm)

#define SM_ENTRY(machine, _state, _data) \
sm->_data.state = machine ## _ ## _state; \
if (sm->hapd->conf->debug >= HOSTAPD_DEBUG_MINIMAL) \
	printf("IEEE 802.1X: " MACSTR " " #machine " entering state " #_state \
		"\n", MAC2STR(sm->addr));

#define SM_ENTER(machine, state) sm_ ## machine ## _ ## state ## _Enter(sm)

#define SM_STEP(machine) \
static void sm_ ## machine ## _Step(struct eapol_state_machine *sm)

#define SM_STEP_RUN(machine) sm_ ## machine ## _Step(sm)



/* Port Timers state machine - implemented as a function that will be called
 * once a second as a registered event loop timeout */

static void eapol_port_timers_tick(void *eloop_ctx, void *timeout_ctx)
{
	struct eapol_state_machine *state = timeout_ctx;

	if (state->aWhile > 0)
		state->aWhile--;
	if (state->quietWhile > 0)
		state->quietWhile--;
	if (state->reAuthWhen > 0)
		state->reAuthWhen--;
	if (state->txWhen > 0)
		state->txWhen--;

	if (state->hapd->conf->debug >= HOSTAPD_DEBUG_MSGDUMPS)
		printf("IEEE 802.1X: " MACSTR " Port Timers TICK "
		       "(timers: %d %d %d %d)\n", MAC2STR(state->addr),
		       state->aWhile, state->quietWhile, state->reAuthWhen,
		       state->txWhen);

	eapol_sm_step(state);

	eloop_register_timeout(1, 0, eapol_port_timers_tick, eloop_ctx, state);
}



/* Authenticator PAE state machine */

SM_STATE(AUTH_PAE, INITIALIZE)
{
	SM_ENTRY(AUTH_PAE, INITIALIZE, auth_pae);
	sm->currentId = 0;
	sm->auth_pae.portMode = Auto;
}


SM_STATE(AUTH_PAE, DISCONNECTED)
{
	int from_initialize = sm->auth_pae.state == AUTH_PAE_INITIALIZE;

	if (sm->auth_pae.state == AUTH_PAE_CONNECTING &&
	    sm->auth_pae.eapLogoff)
		sm->auth_pae.authEapLogoffsWhileConnecting++;

	SM_ENTRY(AUTH_PAE, DISCONNECTED, auth_pae);

	sm->portStatus = Unauthorized;
	setPortUnauthorized();
	sm->auth_pae.eapLogoff = FALSE;
	sm->auth_pae.reAuthCount = 0;
	/* IEEE 802.1X state machine uses txCannedFail() always in this state.
	 * However, sending EAP packet with failure code seems to cause WinXP
	 * Supplicant to deauthenticate, which will set portEnabled = FALSE and
	 * state machines end back to INITIALIZE and then back here to send
	 * canned failure, and so on.. Avoid this by not sending failure packet
	 * when DISCONNECTED state is entered from INITIALIZE state. */
	if (!from_initialize) {
		txCannedFail(sm->currentId);
		sm->currentId++;
		if (sm->flags & EAPOL_SM_PREAUTH)
			rsn_preauth_finished(sm->hapd, sm->sta, 0);
	}
}


SM_STATE(AUTH_PAE, CONNECTING)
{
	if (sm->auth_pae.state != AUTH_PAE_CONNECTING)
		sm->auth_pae.authEntersConnecting++;

	if (sm->auth_pae.state == AUTH_PAE_AUTHENTICATED) {
		if (sm->reAuthenticate)
			sm->auth_pae.authAuthReauthsWhileAuthenticated++;
		if (sm->auth_pae.eapStart)
			sm->auth_pae.authAuthEapStartsWhileAuthenticated++;
		if (sm->auth_pae.eapLogoff)
			sm->auth_pae.authAuthEapLogoffWhileAuthenticated++;
	}

	SM_ENTRY(AUTH_PAE, CONNECTING, auth_pae);

	sm->auth_pae.eapStart = FALSE;
	sm->reAuthenticate = FALSE;
	sm->txWhen = sm->auth_pae.txPeriod;
	sm->auth_pae.rxInitialRsp = FALSE;
	txInitialMsg(sm->currentId);
	sm->auth_pae.reAuthCount++;
}


SM_STATE(AUTH_PAE, HELD)
{
	if (sm->auth_pae.state == AUTH_PAE_AUTHENTICATING && sm->authFail)
		sm->auth_pae.authAuthFailWhileAuthenticating++;

	SM_ENTRY(AUTH_PAE, HELD, auth_pae);

	sm->portStatus = Unauthorized;
	setPortUnauthorized();
	sm->quietWhile = sm->auth_pae.quietPeriod;
	sm->auth_pae.eapLogoff = FALSE;
	sm->currentId++;

	hostapd_logger(sm->hapd, sm->addr, HOSTAPD_MODULE_IEEE8021X,
		       HOSTAPD_LEVEL_WARNING, "authentication failed");
	if (sm->flags & EAPOL_SM_PREAUTH)
		rsn_preauth_finished(sm->hapd, sm->sta, 0);
}


SM_STATE(AUTH_PAE, AUTHENTICATED)
{
	if (sm->auth_pae.state == AUTH_PAE_AUTHENTICATING && sm->authSuccess)
		sm->auth_pae.authAuthSuccessesWhileAuthenticating++;
							
	SM_ENTRY(AUTH_PAE, AUTHENTICATED, auth_pae);

	sm->portStatus = Authorized;
	setPortAuthorized();
	sm->auth_pae.reAuthCount = 0;
	sm->currentId++;
	hostapd_logger(sm->hapd, sm->addr, HOSTAPD_MODULE_IEEE8021X,
		       HOSTAPD_LEVEL_INFO, "authenticated");
	if (sm->flags & EAPOL_SM_PREAUTH)
		rsn_preauth_finished(sm->hapd, sm->sta, 1);
}


SM_STATE(AUTH_PAE, AUTHENTICATING)
{
	if (sm->auth_pae.state == AUTH_PAE_CONNECTING &&
	    sm->auth_pae.rxInitialRsp)
		sm->auth_pae.authEntersAuthenticating++;

	SM_ENTRY(AUTH_PAE, AUTHENTICATING, auth_pae);

	sm->authSuccess = FALSE;
	sm->authFail = FALSE;
	sm->authTimeout = FALSE;
	sm->authStart = TRUE;
	sm->keyRun = FALSE;
	sm->keyDone = FALSE;
}


SM_STATE(AUTH_PAE, ABORTING)
{
	if (sm->auth_pae.state == AUTH_PAE_AUTHENTICATING) {
		if (sm->authTimeout)
			sm->auth_pae.authAuthTimeoutsWhileAuthenticating++;
		if (sm->reAuthenticate)
			sm->auth_pae.authAuthReauthsWhileAuthenticating++;
		if (sm->auth_pae.eapStart)
			sm->auth_pae.authAuthEapStartsWhileAuthenticating++;
		if (sm->auth_pae.eapLogoff)
			sm->auth_pae.authAuthEapLogoffWhileAuthenticating++;
	}

	SM_ENTRY(AUTH_PAE, ABORTING, auth_pae);

	sm->authAbort = TRUE;
	sm->keyRun = FALSE;
	sm->keyDone = FALSE;
	sm->currentId++;
}


SM_STATE(AUTH_PAE, FORCE_AUTH)
{
	SM_ENTRY(AUTH_PAE, FORCE_AUTH, auth_pae);

	sm->portStatus = Authorized;
	setPortAuthorized();
	sm->auth_pae.portMode = ForceAuthorized;
	sm->auth_pae.eapStart = FALSE;
	txCannedSuccess(sm->currentId);
	sm->currentId++;
}


SM_STATE(AUTH_PAE, FORCE_UNAUTH)
{
	SM_ENTRY(AUTH_PAE, FORCE_UNAUTH, auth_pae);

	sm->portStatus = Unauthorized;
	setPortUnauthorized();
	sm->auth_pae.portMode = ForceUnauthorized;
	sm->auth_pae.eapStart = FALSE;
	txCannedFail(sm->currentId);
	sm->currentId++;
}


SM_STEP(AUTH_PAE)
{
	if ((sm->portControl == Auto &&
	     sm->auth_pae.portMode != sm->portControl) ||
	    sm->initialize || !sm->portEnabled)
		SM_ENTER(AUTH_PAE, INITIALIZE);
	else if (sm->portControl == ForceAuthorized &&
		 sm->auth_pae.portMode != sm->portControl &&
		 !(sm->initialize || !sm->portEnabled))
		SM_ENTER(AUTH_PAE, FORCE_AUTH);
	else if (sm->portControl == ForceUnauthorized &&
		 sm->auth_pae.portMode != sm->portControl &&
		 !(sm->initialize || !sm->portEnabled))
		SM_ENTER(AUTH_PAE, FORCE_UNAUTH);
	else {
		switch (sm->auth_pae.state) {
		case AUTH_PAE_INITIALIZE:
			SM_ENTER(AUTH_PAE, DISCONNECTED);
			break;
		case AUTH_PAE_DISCONNECTED:
			SM_ENTER(AUTH_PAE, CONNECTING);
			break;
		case AUTH_PAE_HELD:
			if (sm->quietWhile == 0)
				SM_ENTER(AUTH_PAE, CONNECTING);
			break;
		case AUTH_PAE_CONNECTING:
			if (sm->auth_pae.eapLogoff ||
			    sm->auth_pae.reAuthCount > sm->auth_pae.reAuthMax)
				SM_ENTER(AUTH_PAE, DISCONNECTED);
			else if (sm->auth_pae.rxInitialRsp &&
				 sm->auth_pae.reAuthCount <=
				 sm->auth_pae.reAuthMax)
				SM_ENTER(AUTH_PAE, AUTHENTICATING);
			else if ((sm->txWhen == 0 || sm->auth_pae.eapStart ||
				  sm->reAuthenticate) &&
				 sm->auth_pae.reAuthCount <=
				 sm->auth_pae.reAuthMax)
				SM_ENTER(AUTH_PAE, CONNECTING);
			break;
		case AUTH_PAE_AUTHENTICATED:
			if (sm->auth_pae.eapStart || sm->reAuthenticate)
				SM_ENTER(AUTH_PAE, CONNECTING);
			else if (sm->auth_pae.eapLogoff || !sm->portValid)
				SM_ENTER(AUTH_PAE, DISCONNECTED);
			break;
		case AUTH_PAE_AUTHENTICATING:
			if (sm->authSuccess && sm->portValid)
				SM_ENTER(AUTH_PAE, AUTHENTICATED);
			else if (sm->authFail ||
				 (sm->keyDone && !sm->portValid))
				SM_ENTER(AUTH_PAE, HELD);
			else if (sm->reAuthenticate || sm->auth_pae.eapStart ||
				 sm->auth_pae.eapLogoff ||
				 sm->authTimeout)
				SM_ENTER(AUTH_PAE, ABORTING);
			break;
		case AUTH_PAE_ABORTING:
			if (sm->auth_pae.eapLogoff && !sm->authAbort)
				SM_ENTER(AUTH_PAE, DISCONNECTED);
			else if (!sm->auth_pae.eapLogoff && !sm->authAbort)
				SM_ENTER(AUTH_PAE, CONNECTING);
			break;
		case AUTH_PAE_FORCE_AUTH:
			if (sm->auth_pae.eapStart)
				SM_ENTER(AUTH_PAE, FORCE_AUTH);
			break;
		case AUTH_PAE_FORCE_UNAUTH:
			if (sm->auth_pae.eapStart)
				SM_ENTER(AUTH_PAE, FORCE_UNAUTH);
			break;
		}
	}
}



/* Backend Authentication state machine */

SM_STATE(BE_AUTH, INITIALIZE)
{
	SM_ENTRY(BE_AUTH, INITIALIZE, be_auth);

	abortAuth;
	sm->authAbort = FALSE;
}


SM_STATE(BE_AUTH, REQUEST)
{
	SM_ENTRY(BE_AUTH, REQUEST, be_auth);

	sm->currentId = sm->be_auth.idFromServer;
	txReq(sm->currentId);
	sm->be_auth.backendOtherRequestsToSupplicant++;
	sm->aWhile = sm->be_auth.suppTimeout;
	sm->be_auth.reqCount++;
}


SM_STATE(BE_AUTH, RESPONSE)
{
	SM_ENTRY(BE_AUTH, RESPONSE, be_auth);

	sm->be_auth.aReq = sm->be_auth.aSuccess = FALSE;
	sm->authTimeout = FALSE;
	sm->be_auth.rxResp = sm->be_auth.aFail = FALSE;
	sm->aWhile = sm->be_auth.serverTimeout;
	sm->be_auth.reqCount = 0;
	sendRespToServer;
	sm->be_auth.backendResponses++;
}


SM_STATE(BE_AUTH, SUCCESS)
{
	SM_ENTRY(BE_AUTH, SUCCESS, be_auth);

	sm->currentId = sm->be_auth.idFromServer;
	txReq(sm->currentId);
	sm->authSuccess = TRUE;
	sm->keyRun = TRUE;
}


SM_STATE(BE_AUTH, FAIL)
{
	SM_ENTRY(BE_AUTH, FAIL, be_auth);

	sm->currentId = sm->be_auth.idFromServer;
	if (sm->last_eap_radius == NULL)
		txCannedFail(sm->currentId);
	else
		txReq(sm->currentId);
	sm->authFail = TRUE;
}


SM_STATE(BE_AUTH, TIMEOUT)
{
	SM_ENTRY(BE_AUTH, TIMEOUT, be_auth);

	if (sm->portStatus == Unauthorized)
		txCannedFail(sm->currentId);
	sm->authTimeout = TRUE;
}


SM_STATE(BE_AUTH, IDLE)
{
	SM_ENTRY(BE_AUTH, IDLE, be_auth);

	sm->authStart = FALSE;
	sm->be_auth.reqCount = 0;
}


SM_STEP(BE_AUTH)
{
	if (sm->portControl != Auto || sm->initialize || sm->authAbort) {
		SM_ENTER(BE_AUTH, INITIALIZE);
		return;
	}

	switch (sm->be_auth.state) {
	case BE_AUTH_INITIALIZE:
		SM_ENTER(BE_AUTH, IDLE);
		break;
	case BE_AUTH_REQUEST:
		if (sm->aWhile == 0 &&
		    sm->be_auth.reqCount != sm->be_auth.maxReq)
			SM_ENTER(BE_AUTH, REQUEST);
		else if (sm->be_auth.rxResp)
			SM_ENTER(BE_AUTH, RESPONSE);
		else if (sm->aWhile == 0 &&
			 sm->be_auth.reqCount >= sm->be_auth.maxReq)
			SM_ENTER(BE_AUTH, TIMEOUT);
		break;
	case BE_AUTH_RESPONSE:
		if (sm->be_auth.aReq) {
			sm->be_auth.backendAccessChallenges++;
			SM_ENTER(BE_AUTH, REQUEST);
		} else if (sm->aWhile == 0)
			SM_ENTER(BE_AUTH, TIMEOUT);
		else if (sm->be_auth.aFail) {
			sm->be_auth.backendAuthFails++;
			SM_ENTER(BE_AUTH, FAIL);
		} else if (sm->be_auth.aSuccess /* &&
			((sm->keyTxEnabled && !sm->keyAvailable) ||
			!sm->keyTxEnabled) */) {
			sm->be_auth.backendAuthSuccesses++;
			SM_ENTER(BE_AUTH, SUCCESS);
		}
		break;
	case BE_AUTH_SUCCESS:
		SM_ENTER(BE_AUTH, IDLE);
		break;
	case BE_AUTH_FAIL:
		SM_ENTER(BE_AUTH, IDLE);
		break;
	case BE_AUTH_TIMEOUT:
		SM_ENTER(BE_AUTH, IDLE);
		break;
	case BE_AUTH_IDLE:
		if (sm->authStart)
			SM_ENTER(BE_AUTH, RESPONSE);
		break;
	}
}



/* Reauthentication Timer state machine */

SM_STATE(REAUTH_TIMER, INITIALIZE)
{
	SM_ENTRY(REAUTH_TIMER, INITIALIZE, reauth_timer);

	sm->reAuthWhen = sm->reauth_timer.reAuthPeriod;
}


SM_STATE(REAUTH_TIMER, REAUTHENTICATE)
{
	SM_ENTRY(REAUTH_TIMER, REAUTHENTICATE, reauth_timer);

	sm->reAuthenticate = TRUE;
	wpa_sm_event(sm->hapd, sm->sta, WPA_REAUTH_EAPOL);
}


SM_STEP(REAUTH_TIMER)
{
	if (sm->portControl != Auto || sm->initialize ||
	    sm->portStatus == Unauthorized ||
	    !sm->reauth_timer.reAuthEnabled) {
		SM_ENTER(REAUTH_TIMER, INITIALIZE);
		return;
	}

	switch (sm->reauth_timer.state) {
	case REAUTH_TIMER_INITIALIZE:
		if (sm->reAuthWhen == 0)
			SM_ENTER(REAUTH_TIMER, REAUTHENTICATE);
		break;
	case REAUTH_TIMER_REAUTHENTICATE:
		SM_ENTER(REAUTH_TIMER, INITIALIZE);
		break;
	}
}



/* Authenticator Key Transmit state machine */

SM_STATE(AUTH_KEY_TX, NO_KEY_TRANSMIT)
{
	SM_ENTRY(AUTH_KEY_TX, NO_KEY_TRANSMIT, auth_key_tx);
}


SM_STATE(AUTH_KEY_TX, KEY_TRANSMIT)
{
	SM_ENTRY(AUTH_KEY_TX, KEY_TRANSMIT, auth_key_tx);

	txKey(sm->currentId);
	sm->keyAvailable = FALSE;
	sm->keyDone = TRUE;
}


SM_STEP(AUTH_KEY_TX)
{
	if (sm->initialize || sm->portControl != Auto) {
		SM_ENTER(AUTH_KEY_TX, NO_KEY_TRANSMIT);
		return;
	}

	switch (sm->auth_key_tx.state) {
	case AUTH_KEY_TX_NO_KEY_TRANSMIT:
		if (sm->keyTxEnabled && sm->keyAvailable && sm->keyRun &&
		    !sm->sta->wpa)
			SM_ENTER(AUTH_KEY_TX, KEY_TRANSMIT);
		break;
	case AUTH_KEY_TX_KEY_TRANSMIT:
		if (!sm->keyTxEnabled || !sm->keyRun)
			SM_ENTER(AUTH_KEY_TX, NO_KEY_TRANSMIT);
		else if (sm->keyAvailable)
			SM_ENTER(AUTH_KEY_TX, KEY_TRANSMIT);
		break;
	}
}



struct eapol_state_machine *
eapol_sm_alloc(hostapd *hapd, struct sta_info *sta)
{
	struct eapol_state_machine *sm;

	sm = (struct eapol_state_machine *) malloc(sizeof(*sm));
	if (sm == NULL) {
		printf("IEEE 802.1X port state allocation failed\n");
		return NULL;
	}
	memset(sm, 0, sizeof(*sm));
	sm->radius_identifier = -1;
	memcpy(sm->addr, sta->addr, ETH_ALEN);
	if (sta->flags & WLAN_STA_PREAUTH)
		sm->flags |= EAPOL_SM_PREAUTH;

	sm->hapd = hapd;
	sm->sta = sta;

	/* Set default values for state machine constants */
	sm->auth_pae.state = AUTH_PAE_INITIALIZE;
	sm->auth_pae.quietPeriod = AUTH_PAE_DEFAULT_quietPeriod;
	sm->auth_pae.initialEAPMsg = AUTH_PAE_DEFAULT_initialEAPMsg;
	sm->auth_pae.reAuthMax = AUTH_PAE_DEFAULT_reAuthMax;
	sm->auth_pae.txPeriod = AUTH_PAE_DEFAULT_txPeriod;

	sm->be_auth.state = BE_AUTH_INITIALIZE;
	sm->be_auth.suppTimeout = BE_AUTH_DEFAULT_suppTimeout;
	sm->be_auth.serverTimeout = BE_AUTH_DEFAULT_serverTimeout;
	sm->be_auth.maxReq = BE_AUTH_DEFAULT_maxReq;

	sm->reauth_timer.state = REAUTH_TIMER_INITIALIZE;
	sm->reauth_timer.reAuthPeriod = REAUTH_TIMER_DEFAULT_reAuthPeriod;
	sm->reauth_timer.reAuthEnabled = REAUTH_TIMER_DEFAULT_reAuthEnabled;

	sm->portEnabled = FALSE;
	sm->portControl = Auto;

	/* IEEE 802.1aa/D4 */
	sm->keyAvailable = FALSE;
	if (!hapd->conf->wpa &&
	    (hapd->default_wep_key || hapd->conf->individual_wep_key_len > 0))
		sm->keyTxEnabled = TRUE;
	else
		sm->keyTxEnabled = FALSE;
	if (hapd->conf->wpa)
		sm->portValid = FALSE;
	else
		sm->portValid = TRUE;

	eapol_sm_initialize(sm);

	return sm;
}


void eapol_sm_free(struct eapol_state_machine *sm)
{
	if (sm == NULL)
		return;

	eloop_cancel_timeout(eapol_port_timers_tick, sm->hapd, sm);

	free(sm);
}


static int eapol_sm_sta_entry_alive(struct hostapd_data *hapd, u8 *addr)
{
	struct sta_info *sta;
	sta = ap_get_sta(hapd, addr);
	if (sta == NULL || sta->eapol_sm == NULL)
		return 0;
	return 1;
}


void eapol_sm_step(struct eapol_state_machine *sm)
{
	struct hostapd_data *hapd = sm->hapd;
	u8 addr[6];
	int prev_auth_pae, prev_be_auth, prev_reauth_timer, prev_auth_key_tx;

	/* FIX: could re-run eapol_sm_step from registered timeout (after
	 * 0 sec) to make sure that other possible timeouts/events are
	 * processed */

	memcpy(addr, sm->sta->addr, 6);
	do {
		prev_auth_pae = sm->auth_pae.state;
		prev_be_auth = sm->be_auth.state;
		prev_reauth_timer = sm->reauth_timer.state;
		prev_auth_key_tx = sm->auth_key_tx.state;

		SM_STEP_RUN(AUTH_PAE);
		if (!eapol_sm_sta_entry_alive(hapd, addr))
			break;
		SM_STEP_RUN(BE_AUTH);
		if (!eapol_sm_sta_entry_alive(hapd, addr))
			break;
		SM_STEP_RUN(REAUTH_TIMER);
		if (!eapol_sm_sta_entry_alive(hapd, addr))
			break;
		SM_STEP_RUN(AUTH_KEY_TX);
		if (!eapol_sm_sta_entry_alive(hapd, addr))
			break;
	} while (prev_auth_pae != sm->auth_pae.state ||
		 prev_be_auth != sm->be_auth.state ||
		 prev_reauth_timer != sm->reauth_timer.state ||
		 prev_auth_key_tx != sm->auth_key_tx.state);

	if (eapol_sm_sta_entry_alive(hapd, addr))
		wpa_sm_notify(sm->hapd, sm->sta);
}


void eapol_sm_initialize(struct eapol_state_machine *sm)
{
	/* Initialize the state machines by asserting initialize and then
	 * deasserting it after one step */
	sm->initialize = TRUE;
	eapol_sm_step(sm);
	sm->initialize = FALSE;
	eapol_sm_step(sm);

	/* Start one second tick for port timers state machine */
	eloop_cancel_timeout(eapol_port_timers_tick, sm->hapd, sm);
	eloop_register_timeout(1, 0, eapol_port_timers_tick, sm->hapd, sm);
}


#ifdef HOSTAPD_DUMP_STATE
static inline const char * port_type_txt(PortTypes pt)
{
	switch (pt) {
	case ForceUnauthorized: return "ForceUnauthorized";
	case ForceAuthorized: return "ForceAuthorized";
	case Auto: return "Auto";
	default: return "Unknown";
	}
}


static inline const char * port_state_txt(PortState ps)
{
	switch (ps) {
	case Unauthorized: return "Unauthorized";
	case Authorized: return "Authorized";
	default: return "Unknown";
	}
}


static inline const char * auth_pae_state_txt(int s)
{
	switch (s) {
	case AUTH_PAE_INITIALIZE: return "INITIALIZE";
	case AUTH_PAE_DISCONNECTED: return "DISCONNECTED";
	case AUTH_PAE_CONNECTING: return "CONNECTING";
	case AUTH_PAE_AUTHENTICATING: return "AUTHENTICATING";
	case AUTH_PAE_AUTHENTICATED: return "AUTHENTICATED";
	case AUTH_PAE_ABORTING: return "ABORTING";
	case AUTH_PAE_HELD: return "HELD";
	case AUTH_PAE_FORCE_AUTH: return "FORCE_AUTH";
	case AUTH_PAE_FORCE_UNAUTH: return "FORCE_UNAUTH";
	default: return "Unknown";
	}
}


static inline const char * auth_pae_eaptype_txt(EAPMsgType t)
{
	switch (t) {
	case EAPRequestIdentity: return "EAP Request/Identity";
	default: return "Unknown";
	}
}


static inline const char * be_auth_state_txt(int s)
{
	switch (s) {
	case BE_AUTH_REQUEST: return "REQUEST";
	case BE_AUTH_RESPONSE: return "RESPONSE";
	case BE_AUTH_SUCCESS: return "SUCCESS";
	case BE_AUTH_FAIL: return "FAIL";
	case BE_AUTH_TIMEOUT: return "TIMEOUT";
	case BE_AUTH_IDLE: return "IDLE";
	case BE_AUTH_INITIALIZE: return "INITIALIZE";
	default: return "Unknown";
	}
}


static inline const char * reauth_timer_state_txt(int s)
{
	switch (s) {
	case REAUTH_TIMER_INITIALIZE: return "INITIALIZE";
	case REAUTH_TIMER_REAUTHENTICATE: return "REAUTHENTICATE";
	default: return "Unknown";
	}
}


static inline const char * auth_key_tx_state_txt(int s)
{
	switch (s) {
	case AUTH_KEY_TX_NO_KEY_TRANSMIT: return "NO_KEY_TRANSMIT";
	case AUTH_KEY_TX_KEY_TRANSMIT: return "KEY_TRANSMIT";
	default: return "Unknown";
	}
}


void eapol_sm_dump_state(FILE *f, const char *prefix,
			 struct eapol_state_machine *sm)
{
	fprintf(f, "%sEAPOL state machine:\n", prefix);
	fprintf(f, "%s  aWhile=%d quietWhile=%d reAuthWhen=%d "
		"txWhen=%d\n", prefix,
		sm->aWhile, sm->quietWhile, sm->reAuthWhen, sm->txWhen);
#define _SB(b) ((b) ? "TRUE" : "FALSE")
	fprintf(f, "%s  authAbort=%s authFail=%s authStart=%s "
		"authTimeout=%s\n", prefix,
		_SB(sm->authAbort), _SB(sm->authFail), _SB(sm->authStart),
		_SB(sm->authTimeout));
	fprintf(f, "%s  authSuccess=%s currentId=%d initialize=%s "
		"reAuthenticate=%s\n", prefix, _SB(sm->authSuccess),
		sm->currentId, _SB(sm->initialize), _SB(sm->reAuthenticate));
	fprintf(f, "%s  portControl=%s portEnabled=%s portStatus=%s\n", prefix,
		port_type_txt(sm->portControl), _SB(sm->portEnabled),
		port_state_txt(sm->portStatus));
	fprintf(f, "%s  keyAvailable=%s keyTxEnabled=%s portValid=%s\n",
		prefix, _SB(sm->keyAvailable), _SB(sm->keyTxEnabled),
		_SB(sm->portValid));
	fprintf(f, "%s  keyRun=%s keyDone=%s\n",
		prefix, _SB(sm->keyRun), _SB(sm->keyDone));

	fprintf(f, "%s  Authenticator PAE:\n"
		"%s    state=%s\n"
		"%s    eapLogoff=%s eapStart=%s portMode=%s\n"
		"%s    reAuthCount=%d rxInitialRsp=%s\n"
		"%s    quietPeriod=%d initialEAPMsg=%s\n"
		"%s    reAuthMax=%d txPeriod=%d\n"
		"%s    authEntersConnecting=%d\n"
		"%s    authEapLogoffsWhileConnecting=%d\n"
		"%s    authEntersAuthenticating=%d\n"
		"%s    authAuthSuccessesWhileAuthenticating=%d\n"
		"%s    authAuthTimeoutsWhileAuthenticating=%d\n"
		"%s    authAuthFailWhileAuthenticating=%d\n"
		"%s    authAuthReauthsWhileAuthenticating=%d\n"
		"%s    authAuthEapStartsWhileAuthenticating=%d\n"
		"%s    authAuthEapLogoffWhileAuthenticating=%d\n"
		"%s    authAuthReauthsWhileAuthenticated=%d\n"
		"%s    authAuthEapStartsWhileAuthenticated=%d\n"
		"%s    authAuthEapLogoffWhileAuthenticated=%d\n",
		prefix, prefix, auth_pae_state_txt(sm->auth_pae.state), prefix,
		_SB(sm->auth_pae.eapLogoff), _SB(sm->auth_pae.eapStart),
		port_type_txt(sm->auth_pae.portMode),
		prefix, sm->auth_pae.reAuthCount,
		_SB(sm->auth_pae.rxInitialRsp),
		prefix, sm->auth_pae.quietPeriod,
		auth_pae_eaptype_txt(sm->auth_pae.initialEAPMsg),
		prefix, sm->auth_pae.reAuthMax, sm->auth_pae.txPeriod,
		prefix, sm->auth_pae.authEntersConnecting,
		prefix, sm->auth_pae.authEapLogoffsWhileConnecting,
		prefix, sm->auth_pae.authEntersAuthenticating,
		prefix, sm->auth_pae.authAuthSuccessesWhileAuthenticating,
		prefix, sm->auth_pae.authAuthTimeoutsWhileAuthenticating,
		prefix, sm->auth_pae.authAuthFailWhileAuthenticating,
		prefix, sm->auth_pae.authAuthReauthsWhileAuthenticating,
		prefix, sm->auth_pae.authAuthEapStartsWhileAuthenticating,
		prefix, sm->auth_pae.authAuthEapLogoffWhileAuthenticating,
		prefix, sm->auth_pae.authAuthReauthsWhileAuthenticated,
		prefix, sm->auth_pae.authAuthEapStartsWhileAuthenticated,
		prefix, sm->auth_pae.authAuthEapLogoffWhileAuthenticated);

	fprintf(f, "%s  Backend Authentication:\n"
		"%s    state=%s\n"
		"%s    reqCount=%d rxResp=%s aSuccess=%s aFail=%s aReq=%s\n"
		"%s    idFromServer=%d\n"
		"%s    suppTimeout=%d serverTimeout=%d maxReq=%d\n"
		"%s    backendResponses=%d\n"
		"%s    backendAccessChallenges=%d\n"
		"%s    backendOtherRequestsToSupplicant=%d\n"
		"%s    backendNonNakResponsesFromSupplicant=%d\n"
		"%s    backendAuthSuccesses=%d\n"
		"%s    backendAuthFails=%d\n",
		prefix, prefix,
		be_auth_state_txt(sm->be_auth.state), prefix,
		sm->be_auth.reqCount,
		_SB(sm->be_auth.rxResp), _SB(sm->be_auth.aSuccess),
		_SB(sm->be_auth.aFail), _SB(sm->be_auth.aReq),
		prefix, sm->be_auth.idFromServer, prefix,
		sm->be_auth.suppTimeout, sm->be_auth.serverTimeout,
		sm->be_auth.maxReq,
		prefix, sm->be_auth.backendResponses,
		prefix, sm->be_auth.backendAccessChallenges,
		prefix, sm->be_auth.backendOtherRequestsToSupplicant,
		prefix, sm->be_auth.backendNonNakResponsesFromSupplicant,
		prefix, sm->be_auth.backendAuthSuccesses,
		prefix, sm->be_auth.backendAuthFails);

	fprintf(f, "%s  Reauthentication Timer:\n"
		"%s    state=%s\n"
		"%s    reAuthPeriod=%d reAuthEnabled=%s\n", prefix, prefix,
		reauth_timer_state_txt(sm->reauth_timer.state), prefix,
		sm->reauth_timer.reAuthPeriod,
		_SB(sm->reauth_timer.reAuthEnabled));

	fprintf(f, "%s  Authenticator Key Transmit:\n"
		"%s    state=%s\n", prefix, prefix,
		auth_key_tx_state_txt(sm->auth_key_tx.state));
#undef _SB
}
#endif /* HOSTAPD_DUMP_STATE */
