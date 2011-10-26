
/*
 * $Id: auth_ntlm.c,v 1.17.2.22 2005/04/22 20:29:31 hno Exp $
 *
 * DEBUG: section 29    NTLM Authenticator
 * AUTHOR: Robert Collins
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

/* The functions in this file handle authentication.
 * They DO NOT perform access control or auditing.
 * See acl.c for access control and client_side.c for auditing */


#include "squid.h"
#include "auth_ntlm.h"

extern AUTHSSETUP authSchemeSetup_ntlm;

static void
authenticateStateFree(authenticateStateData * r)
{
    authenticateAuthUserRequestUnlock(r->auth_user_request);
    r->auth_user_request = NULL;
    cbdataFree(r);
}

/* NTLM Scheme */
static HLPSCB authenticateNTLMHandleReply;
static HLPSCB authenticateNTLMHandleplaceholder;
static AUTHSACTIVE authenticateNTLMActive;
static AUTHSAUTHED authNTLMAuthenticated;
static AUTHSAUTHUSER authenticateNTLMAuthenticateUser;
static AUTHSCONFIGURED authNTLMConfigured;
static AUTHSFIXERR authenticateNTLMFixErrorHeader;
static AUTHSFREE authenticateNTLMFreeUser;
static AUTHSDIRECTION authenticateNTLMDirection;
static AUTHSDECODE authenticateDecodeNTLMAuth;
static AUTHSDUMP authNTLMCfgDump;
static AUTHSFREECONFIG authNTLMFreeConfig;
static AUTHSINIT authNTLMInit;
static AUTHSONCLOSEC authenticateNTLMOnCloseConnection;
static AUTHSCONNLASTHEADER NTLMLastHeader;
static AUTHSUSERNAME authenticateNTLMUsername;
static AUTHSREQFREE authNTLMAURequestFree;
static AUTHSPARSE authNTLMParse;
static AUTHSSTART authenticateNTLMStart;
static AUTHSSTATS authenticateNTLMStats;
static AUTHSSHUTDOWN authNTLMDone;

/* helper callbacks to handle per server state data */
static HLPSAVAIL authenticateNTLMHelperServerAvailable;
static HLPSRESET authenticateNTLMHelperServerReset;

static statefulhelper *ntlmauthenticators = NULL;

CBDATA_TYPE(authenticateStateData);

static int authntlm_initialised = 0;

static MemPool *ntlm_helper_state_pool = NULL;
static MemPool *ntlm_user_pool = NULL;
static MemPool *ntlm_request_pool = NULL;
static MemPool *ntlm_challenge_pool = NULL;
static auth_ntlm_config *ntlmConfig = NULL;

static hash_table *ntlm_challenge_cache = NULL;

static void authenticateNTLMReleaseServer(ntlm_request_t * ntlm_request);
/*
 *
 * Private Functions
 *
 */

static void
authNTLMDone(void)
{
    debug(29, 2) ("authNTLMDone: shutting down NTLM authentication.\n");
    if (ntlmauthenticators)
	helperStatefulShutdown(ntlmauthenticators);
    authntlm_initialised = 0;
    if (!shutting_down)
	return;
    if (ntlmauthenticators)
	helperStatefulFree(ntlmauthenticators);
    ntlmauthenticators = NULL;
    if (ntlm_helper_state_pool) {
	assert(memPoolInUseCount(ntlm_helper_state_pool) == 0);
	memPoolDestroy(ntlm_helper_state_pool);
	ntlm_helper_state_pool = NULL;
    }
    if (ntlm_request_pool) {
	assert(memPoolInUseCount(ntlm_request_pool) == 0);
	memPoolDestroy(ntlm_request_pool);
	ntlm_request_pool = NULL;
    }
    if (ntlm_user_pool) {
	assert(memPoolInUseCount(ntlm_user_pool) == 0);
	memPoolDestroy(ntlm_user_pool);
	ntlm_user_pool = NULL;
    }
    debug(29, 2) ("authNTLMDone: NTLM authentication Shutdown.\n");
}

/* free any allocated configuration details */
static void
authNTLMFreeConfig(authScheme * scheme)
{
    if (ntlmConfig == NULL)
	return;
    assert(ntlmConfig == scheme->scheme_data);
    if (ntlmConfig->authenticate)
	wordlistDestroy(&ntlmConfig->authenticate);
    xfree(ntlmConfig);
    ntlmConfig = NULL;
}

static void
authNTLMCfgDump(StoreEntry * entry, const char *name, authScheme * scheme)
{
    auth_ntlm_config *config = scheme->scheme_data;
    wordlist *list = config->authenticate;
    storeAppendPrintf(entry, "%s %s", name, "ntlm");
    while (list != NULL) {
	storeAppendPrintf(entry, " %s", list->key);
	list = list->next;
    }
    storeAppendPrintf(entry, "\n%s %s children %d\n%s %s max_challenge_reuses %d\n%s %s max_challenge_lifetime %d seconds\n%s %s use_ntlm_negotiate %s\n",
	name, "ntlm", config->authenticateChildren,
	name, "ntlm", config->challengeuses,
	name, "ntlm", (int) config->challengelifetime,
	name, "ntlm", config->use_ntlm_negotiate ? "on" : "off");

}

static void
authNTLMParse(authScheme * scheme, int n_configured, char *param_str)
{
    if (scheme->scheme_data == NULL) {
	assert(ntlmConfig == NULL);
	/* this is the first param to be found */
	scheme->scheme_data = xmalloc(sizeof(auth_ntlm_config));
	memset(scheme->scheme_data, 0, sizeof(auth_ntlm_config));
	ntlmConfig = scheme->scheme_data;
	ntlmConfig->authenticateChildren = 5;
	ntlmConfig->challengeuses = 0;
	ntlmConfig->challengelifetime = 60;
	ntlmConfig->use_ntlm_negotiate = 0;
    }
    ntlmConfig = scheme->scheme_data;
    if (strcasecmp(param_str, "program") == 0) {
	if (ntlmConfig->authenticate)
	    wordlistDestroy(&ntlmConfig->authenticate);
	parse_wordlist(&ntlmConfig->authenticate);
	requirePathnameExists("authparam ntlm program", ntlmConfig->authenticate->key);
    } else if (strcasecmp(param_str, "children") == 0) {
	parse_int(&ntlmConfig->authenticateChildren);
    } else if (strcasecmp(param_str, "max_challenge_reuses") == 0) {
	parse_int(&ntlmConfig->challengeuses);
    } else if (strcasecmp(param_str, "max_challenge_lifetime") == 0) {
	parse_time_t(&ntlmConfig->challengelifetime);
    } else if (strcasecmp(param_str, "use_ntlm_negotiate") == 0) {
	parse_onoff(&ntlmConfig->use_ntlm_negotiate);
    } else {
	debug(28, 0) ("unrecognised ntlm auth scheme parameter '%s'\n", param_str);
    }
    /*
     * disable client side request pipelining. There is a race with
     * NTLM when the client sends a second request on an NTLM
     * connection before the authenticate challenge is sent. With
     * this patch, the client may fail to authenticate, but squid's
     * state will be preserved.  Caveats: this should be a post-parse
     * test, but that can wait for the modular parser to be integrated.
     */
    if (ntlmConfig->authenticate && Config.onoff.pipeline_prefetch != 0)
	Config.onoff.pipeline_prefetch = 0;

    if (ntlmConfig->use_ntlm_negotiate && ntlmConfig->challengeuses > 0) {
	debug(28, 1) ("challenge reuses incompatible with use_ntlm_negotiate. Disabling challenge reuse\n");
	ntlmConfig->challengeuses = 0;
    }
}


void
authSchemeSetup_ntlm(authscheme_entry_t * authscheme)
{
    assert(!authntlm_initialised);
    authscheme->Active = authenticateNTLMActive;
    authscheme->configured = authNTLMConfigured;
    authscheme->parse = authNTLMParse;
    authscheme->dump = authNTLMCfgDump;
    authscheme->requestFree = authNTLMAURequestFree;
    authscheme->freeconfig = authNTLMFreeConfig;
    authscheme->init = authNTLMInit;
    authscheme->authAuthenticate = authenticateNTLMAuthenticateUser;
    authscheme->authenticated = authNTLMAuthenticated;
    authscheme->authFixHeader = authenticateNTLMFixErrorHeader;
    authscheme->FreeUser = authenticateNTLMFreeUser;
    authscheme->authStart = authenticateNTLMStart;
    authscheme->authStats = authenticateNTLMStats;
    authscheme->authUserUsername = authenticateNTLMUsername;
    authscheme->getdirection = authenticateNTLMDirection;
    authscheme->decodeauth = authenticateDecodeNTLMAuth;
    authscheme->donefunc = authNTLMDone;
    authscheme->oncloseconnection = authenticateNTLMOnCloseConnection;
    authscheme->authConnLastHeader = NTLMLastHeader;
}

/* Initialize helpers and the like for this auth scheme. Called AFTER parsing the
 * config file */
static void
authNTLMInit(authScheme * scheme)
{
    static int ntlminit = 0;
    if (ntlmConfig->authenticate) {
	if (!ntlm_helper_state_pool)
	    ntlm_helper_state_pool = memPoolCreate("NTLM Helper State data", sizeof(ntlm_helper_state_t));
	if (!ntlm_user_pool)
	    ntlm_user_pool = memPoolCreate("NTLM Scheme User Data", sizeof(ntlm_user_t));
	if (!ntlm_request_pool)
	    ntlm_request_pool = memPoolCreate("NTLM Scheme Request Data", sizeof(ntlm_request_t));
	authntlm_initialised = 1;
	if (ntlmauthenticators == NULL)
	    ntlmauthenticators = helperStatefulCreate("ntlmauthenticator");
	if (ntlmConfig->challengeuses) {
	    if (!ntlm_challenge_cache)
		ntlm_challenge_cache = hash_create((HASHCMP *) strcmp, 7921, hash_string);
	    if (!ntlm_challenge_pool)
		ntlm_challenge_pool = memPoolCreate("NTLM Challenge Cache", sizeof(ntlm_challenge_hash_pointer));
	}
	ntlmauthenticators->cmdline = ntlmConfig->authenticate;
	ntlmauthenticators->n_to_start = ntlmConfig->authenticateChildren;
	ntlmauthenticators->ipc_type = IPC_TCP_SOCKET;
	ntlmauthenticators->datapool = ntlm_helper_state_pool;
	ntlmauthenticators->IsAvailable = authenticateNTLMHelperServerAvailable;
	ntlmauthenticators->Reset = authenticateNTLMHelperServerReset;
	helperStatefulOpenServers(ntlmauthenticators);
	/*
	 * TODO: In here send the initial YR to preinitialise the
	 * challenge cache
	 */
	/*
	 * Think about this... currently we ask when the challenge
	 * is needed. Better?
	 */
	if (!ntlminit) {
	    cachemgrRegister("ntlmauthenticator",
		"NTLM User Authenticator Stats",
		authenticateNTLMStats, 0, 1);
	    ntlminit++;
	}
	CBDATA_INIT_TYPE(authenticateStateData);
    }
}

static int
authenticateNTLMActive()
{
    return (authntlm_initialised == 1) ? 1 : 0;
}


static int
authNTLMConfigured()
{
    if ((ntlmConfig != NULL) && (ntlmConfig->authenticate != NULL) && (ntlmConfig->authenticateChildren != 0) && (ntlmConfig->challengeuses > -1) && (ntlmConfig->challengelifetime > -1)) {
	debug(29, 9) ("authNTLMConfigured: returning configured\n");
	return 1;
    }
    debug(29, 9) ("authNTLMConfigured: returning unconfigured\n");
    return 0;
}

/* NTLM Scheme */

static int
authenticateNTLMDirection(auth_user_request_t * auth_user_request)
{
    ntlm_request_t *ntlm_request = auth_user_request->scheme_data;
    /* null auth_user is checked for by authenticateDirection */
    switch (ntlm_request->auth_state) {
    case AUTHENTICATE_STATE_NONE:	/* no progress at all. */
	debug(29, 1) ("authenticateNTLMDirection: called before NTLM Authenticate!. Report a bug to squid-dev. au %p\n", auth_user_request);
	/* fall thru */
    case AUTHENTICATE_STATE_FAILED:
	return -2;
    case AUTHENTICATE_STATE_NEGOTIATE:		/* send to helper */
    case AUTHENTICATE_STATE_RESPONSE:	/*send to helper */
	return -1;
    case AUTHENTICATE_STATE_CHALLENGE:		/* send to client */
	return 1;
    case AUTHENTICATE_STATE_DONE:	/* do nothing.. */
	return 0;
    }
    return -2;
}

/*
 * Send the authenticate error header(s). Note: IE has a bug and the NTLM header
 * must be first. To ensure that, the configure use --enable-auth=ntlm, anything
 * else.
 */
static void
authenticateNTLMFixErrorHeader(auth_user_request_t * auth_user_request, HttpReply * rep, http_hdr_type type, request_t * request)
{
    ntlm_request_t *ntlm_request;
    if (ntlmConfig->authenticate) {
	/* New request, no user details */
	if (auth_user_request == NULL) {
	    debug(29, 9) ("authenticateNTLMFixErrorHeader: Sending type:%d header: 'NTLM'\n", type);
	    httpHeaderPutStrf(&rep->header, type, "NTLM");
	    /* drop the connection */
	    httpHeaderDelByName(&rep->header, "keep-alive");
	    /* NTLM has problems if the initial connection is not dropped
	     * I haven't checked the RFC compliance of this hack - RBCollins */
	    request->flags.proxy_keepalive = 0;
	} else {
	    ntlm_request = auth_user_request->scheme_data;
	    switch (ntlm_request->auth_state) {
	    case AUTHENTICATE_STATE_NONE:
	    case AUTHENTICATE_STATE_FAILED:
		debug(29, 9) ("authenticateNTLMFixErrorHeader: Sending type:%d header: 'NTLM'\n", type);
		httpHeaderPutStrf(&rep->header, type, "NTLM");
		/* drop the connection */
		httpHeaderDelByName(&rep->header, "keep-alive");
		/* NTLM has problems if the initial connection is not dropped
		 * I haven't checked the RFC compliance of this hack - RBCollins */
		request->flags.proxy_keepalive = 0;
		break;
	    case AUTHENTICATE_STATE_CHALLENGE:
		/* we are 'waiting' for a response */
		/* pass the challenge to the client */
		debug(29, 9) ("authenticateNTLMFixErrorHeader: Sending type:%d header: 'NTLM %s'\n", type, ntlm_request->authchallenge);
		httpHeaderPutStrf(&rep->header, type, "NTLM %s", ntlm_request->authchallenge);
		break;
	    default:
		debug(29, 0) ("authenticateNTLMFixErrorHeader: state %d.\n", ntlm_request->auth_state);
		fatal("unexpected state in AuthenticateNTLMFixErrorHeader.\n");
	    }
	}
    }
}

static void
authNTLMRequestFree(ntlm_request_t * ntlm_request)
{
    if (!ntlm_request)
	return;
    if (ntlm_request->ntlmnegotiate)
	xfree(ntlm_request->ntlmnegotiate);
    if (ntlm_request->authchallenge)
	xfree(ntlm_request->authchallenge);
    if (ntlm_request->ntlmauthenticate)
	xfree(ntlm_request->ntlmauthenticate);
    if (ntlm_request->authserver != NULL) {
	debug(29, 9) ("authenticateNTLMRequestFree: releasing server '%p'\n", ntlm_request->authserver);
	authenticateNTLMReleaseServer(ntlm_request);
    }
    memPoolFree(ntlm_request_pool, ntlm_request);
}

static void
authNTLMAURequestFree(auth_user_request_t * auth_user_request)
{
    if (auth_user_request->scheme_data)
	authNTLMRequestFree((ntlm_request_t *) auth_user_request->scheme_data);
    auth_user_request->scheme_data = NULL;
}

static void authenticateNTLMChallengeCacheRemoveLink(ntlm_challenge_hash_pointer * challenge_hash);

static void
authenticateNTLMFreeUser(auth_user_t * auth_user)
{
    ntlm_user_t *ntlm_user = auth_user->scheme_data;

    debug(29, 5) ("authenticateNTLMFreeUser: Clearing NTLM scheme data\n");
    if (ntlm_user->username)
	xfree(ntlm_user->username);
    /* were they linked in by one or more proxy-authenticate headers */
    while (ntlm_user->challenge_list.head) {
	authenticateNTLMChallengeCacheRemoveLink(ntlm_user->challenge_list.head->data);
    }
    memPoolFree(ntlm_user_pool, ntlm_user);
    auth_user->scheme_data = NULL;
}

/* clear the NTLM helper of being reserved for future requests */
static void
authenticateNTLMReleaseServer(ntlm_request_t * ntlm_request)
{
    helper_stateful_server *server = ntlm_request->authserver;
    debug(29, 9) ("authenticateNTLMReleaseServer: releasing server '%p'\n", server);
    ntlm_request->authserver = NULL;
    if (!ntlmConfig->challengeuses) {
	ntlm_helper_state_t *helperstate = helperStatefulServerGetData(server);
	helperstate->starve = 1;
    }
    helperStatefulReleaseServer(server);
}

/* clear the NTLM helper of being reserved for future requests */
static void
authenticateNTLMResetServer(ntlm_request_t * ntlm_request)
{
    helper_stateful_server *server = ntlm_request->authserver;
    ntlm_helper_state_t *helperstate = helperStatefulServerGetData(server);
    debug(29, 9) ("authenticateNTLMResetServer: releasing server '%p'\n", server);
    ntlm_request->authserver = NULL;
    helperstate->starve = 1;
    helperStatefulReleaseServer(server);
}

static void
authenticateNTLMHandleplaceholder(void *data, void *srv, char *reply)
{
    authenticateStateData *r = data;
    int valid;
    /* we should only be called for placeholder requests - which have no reply string */
    assert(reply == NULL);
    assert(r->auth_user_request);
    /* standard callback stuff */
    valid = cbdataValid(r->data);
    if (!valid) {
	debug(29, 2) ("AuthenticateNTLMHandlePlacheholder: invalid callback data.\n");
	helperStatefulReleaseServer(srv);
	return;
    }
    /* call authenticateNTLMStart to retry this request */
    debug(29, 9) ("authenticateNTLMHandleplaceholder: calling authenticateNTLMStart\n");
    helperStatefulReleaseServer(srv);
    authenticateNTLMStart(r->auth_user_request, r->handler, r->data);
    cbdataUnlock(r->data);
    authenticateStateFree(r);
}

static void
authenticateNTLMHandleReply(void *data, void *srv, char *reply)
{
    authenticateStateData *r = data;
    ntlm_helper_state_t *helperstate;
    int valid;
    auth_user_request_t *auth_user_request;
    auth_user_t *auth_user;
    ntlm_user_t *ntlm_user;
    ntlm_request_t *ntlm_request;
    debug(29, 9) ("authenticateNTLMHandleReply: Helper: '%p' {%s}\n", srv, reply ? reply : "<NULL>");
    valid = cbdataValid(r->data);
    if (!valid) {
	debug(29, 2) ("AuthenticateNTLMHandleReply: invalid callback data. Releasing helper '%p'.\n", srv);
	cbdataUnlock(r->data);
	authenticateStateFree(r);
	return;
    }
    if (!reply) {
	/*
	 * TODO: this occurs when a helper crashes. We should clean
	 * up that helpers resources and queued requests.
	 */
	fatal("authenticateNTLMHandleReply: called with no result string\n");
    }
    assert(r->auth_user_request != NULL);
    assert(r->auth_user_request->auth_user->auth_type == AUTH_NTLM);
    auth_user_request = r->auth_user_request;
    ntlm_request = auth_user_request->scheme_data;
    assert(ntlm_request != NULL);
    if (!ntlm_request->authserver)
	ntlm_request->authserver = srv;
    else
	assert(ntlm_request->authserver == srv);

    /* seperate out the useful data */
    if (strncasecmp(reply, "TT ", 3) == 0) {
	reply += 3;
	/* we have been given a Challenge */
	/* we should check we weren't given an empty challenge */
	/* copy the challenge to the state data */
	helperstate = helperStatefulServerGetData(srv);
	if (helperstate == NULL)
	    fatal("lost NTLM helper state! quitting\n");
	helperstate->challenge = xstrdup(reply);
	helperstate->renewed = squid_curtime;
	/* and we satisfy the request that happended on the refresh boundary */
	/* note this code is now in two places FIXME */
	assert(ntlm_request->auth_state == AUTHENTICATE_STATE_NEGOTIATE);
	ntlm_request->authchallenge = xstrdup(reply);
	helperstate->challengeuses = 1;
    } else if (strncasecmp(reply, "AF ", 3) == 0) {
	/* we're finished, release the helper */
	reply += 3;
	auth_user = auth_user_request->auth_user;
	ntlm_user = auth_user_request->auth_user->scheme_data;
	assert(ntlm_user != NULL);
	/* we only expect OK when finishing the handshake */
	assert(ntlm_request->auth_state == AUTHENTICATE_STATE_RESPONSE);
	ntlm_user->username = xstrdup(reply);
#ifdef NTLM_FAIL_OPEN
    } else if (strncasecmp(reply, "LD ", 3) == 0) {
	/* This is a variant of BH, which rather than deny access
	 * allows the user through. The helper is starved and then refreshed
	 * via YR, all pending authentications are likely to fail also.
	 * It is meant for those helpers which occasionally fail for
	 * no reason at all (casus belli, NTLMSSP helper on NT domain,
	 * failing about 1 auth out of 1k.
	 * The code is a merge from the BH case with snippets of the AF
	 * case */
	/* AF code: mark user as authenticated */
	reply += 3;
	auth_user = auth_user_request->auth_user;
	ntlm_user = auth_user_request->auth_user->scheme_data;
	assert(ntlm_user != NULL);
	/* we only expect LD when finishing the handshake */
	assert(ntlm_request->auth_state == AUTHENTICATE_STATE_RESPONSE);
	ntlm_user->username = xstrdup(reply);
	/* BH code: mark helper as broken */
	authenticateNTLMResetServer(ntlm_request);
	debug(29, 4) ("authenticateNTLMHandleReply: Error validating user via NTLM. Error returned '%s'\n", reply);
#endif
    } else if (strncasecmp(reply, "NA ", 3) == 0) {
	/* todo: action of Negotiate state on error */
	ntlm_request->auth_state = AUTHENTICATE_STATE_FAILED;
	authenticateNTLMResetServer(ntlm_request);
	debug(29, 4) ("authenticateNTLMHandleReply: Error validating user via NTLM. Error returned '%s'\n", reply);
	reply += 3;
	safe_free(auth_user_request->message);
	if (*reply)
	    auth_user_request->message = xstrdup(reply);
    } else if (strncasecmp(reply, "BH ", 3) == 0) {
	/* TODO kick off a refresh process. This can occur after a YR or after
	 * a KK. If after a YR release the helper and resubmit the request via 
	 * Authenticate NTLM start. 
	 * If after a KK deny the user's request w/ 407 and mark the helper as 
	 * Needing YR. */
	assert(r->auth_user_request != NULL);
	assert(r->auth_user_request->auth_user->auth_type == AUTH_NTLM);
	auth_user_request = r->auth_user_request;
	auth_user = auth_user_request->auth_user;
	assert(auth_user != NULL);
	ntlm_user = auth_user->scheme_data;
	ntlm_request = auth_user_request->scheme_data;
	assert((ntlm_user != NULL) && (ntlm_request != NULL));
	authenticateNTLMResetServer(ntlm_request);
	if (ntlm_request->auth_state == AUTHENTICATE_STATE_NEGOTIATE) {
	    /* The helper broke on YR. It automatically
	     * resets */
	    debug(29, 1) ("authenticateNTLMHandleReply: Error obtaining challenge from helper: %p. Error returned '%s'\n", srv, reply);
	    /* resubmit the request. This helper is currently busy, so we will get
	     * a different one. Our auth state stays the same */
	    authenticateNTLMStart(auth_user_request, r->handler, r->data);
	    /* don't call the callback */
	    cbdataUnlock(r->data);
	    authenticateStateFree(r);
	    return;
	} else {
	    /* the helper broke on a KK */
	    debug(29, 1) ("authenticateNTLMHandleReply: Error validating user via NTLM. Error returned '%s'\n", reply);
	    ntlm_request->auth_state = AUTHENTICATE_STATE_FAILED;
	    reply += 3;
	    safe_free(auth_user_request->message);
	    if (*reply)
		auth_user_request->message = xstrdup(reply);
	}
    } else {
	fatalf("authenticateNTLMHandleReply: *** Unsupported helper response ***, '%s'\n", reply);
    }
    r->handler(r->data, NULL);
    cbdataUnlock(r->data);
    authenticateStateFree(r);
}

static void
authenticateNTLMStats(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "NTLM Authenticator Statistics:\n");
    helperStatefulStats(sentry, ntlmauthenticators);
}

/* is a particular challenge still valid ? */
static int
authenticateNTLMValidChallenge(ntlm_helper_state_t * helperstate)
{
    debug(29, 9) ("authenticateNTLMValidChallenge: Challenge is %s\n", helperstate->challenge ? "Valid" : "Invalid");
    if (helperstate->challenge == NULL)
	return 0;
    return 1;
}

/* does our policy call for changing the challenge now? */
static int
authenticateNTLMChangeChallenge_p(ntlm_helper_state_t * helperstate)
{
    /* don't check for invalid challenges just for expiry choices */
    /* this is needed because we have to starve the helper until all old
     * requests have been satisfied */
    if (!helperstate->renewed) {
	/* first use, no challenge has been set. Without this check, it will
	 * loop forever */
	debug(29, 5) ("authenticateNTLMChangeChallenge_p: first use\n");
	return 0;
    }
    if (helperstate->challengeuses > ntlmConfig->challengeuses) {
	debug(29, 4) ("authenticateNTLMChangeChallenge_p: Challenge uses (%d) exceeded max uses (%d)\n", helperstate->challengeuses, ntlmConfig->challengeuses);
	return 1;
    }
    if (helperstate->renewed + ntlmConfig->challengelifetime < squid_curtime) {
	debug(29, 4) ("authenticateNTLMChangeChallenge_p: Challenge exceeded max lifetime by %d seconds\n", (int) (squid_curtime - (helperstate->renewed + ntlmConfig->challengelifetime)));
	return 1;
    }
    debug(29, 9) ("Challenge is to be reused\n");
    return 0;
}

/* send the initial data to a stateful ntlm authenticator module */
static void
authenticateNTLMStart(auth_user_request_t * auth_user_request, RH * handler, void *data)
{
    authenticateStateData *r = NULL;
    helper_stateful_server *server;
    ntlm_helper_state_t *helperstate;
    char buf[8192];
    char *sent_string = NULL;
    ntlm_user_t *ntlm_user;
    ntlm_request_t *ntlm_request;
    auth_user_t *auth_user;

    assert(auth_user_request);
    auth_user = auth_user_request->auth_user;
    ntlm_user = auth_user->scheme_data;
    ntlm_request = auth_user_request->scheme_data;
    assert(ntlm_user);
    assert(ntlm_request);
    assert(handler);
    assert(data);
    assert(auth_user->auth_type == AUTH_NTLM);
    debug(29, 9) ("authenticateNTLMStart: auth state '%d'\n", ntlm_request->auth_state);
    switch (ntlm_request->auth_state) {
    case AUTHENTICATE_STATE_NEGOTIATE:
	sent_string = ntlm_request->ntlmnegotiate;
	break;
    case AUTHENTICATE_STATE_RESPONSE:
	sent_string = ntlm_request->ntlmauthenticate;
	assert(ntlm_request->authserver);
	debug(29, 9) ("authenticateNTLMStart: Asking NTLMauthenticator '%p'.\n", ntlm_request->authserver);
	break;
    default:
	fatal("Invalid authenticate state for NTLMStart");
    }

    while (xisgraph(*sent_string))	/*trim NTLM */
	sent_string++;

    while (xisspace(*sent_string))	/*trim leading spaces */
	sent_string++;

    debug(29, 9) ("authenticateNTLMStart: state '%d'\n", ntlm_request->auth_state);
    debug(29, 9) ("authenticateNTLMStart: '%s'\n", sent_string);
    if (ntlmConfig->authenticate == NULL) {
	debug(29, 0) ("authenticateNTLMStart: no NTLM program specified:'%s'\n", sent_string);
	handler(data, NULL);
	return;
    }
    /* this is ugly TODO: move the challenge generation routines to their own function and
     * tidy the logic up to make use of the efficiency we now have */
    switch (ntlm_request->auth_state) {
    case AUTHENTICATE_STATE_NEGOTIATE:
	/*  
	 * 1: get a helper server
	 * 2: does it have a challenge?
	 * 3: tell it to get a challenge, or give ntlmauthdone the challenge
	 */
	server = helperStatefulGetServer(ntlmauthenticators);
	helperstate = server ? helperStatefulServerGetData(server) : NULL;
	if (ntlmConfig->challengeuses) {
	    while ((server != NULL) && authenticateNTLMChangeChallenge_p(helperstate)) {
		/* flag this helper for challenge changing */
		helperstate->starve = 1;
		helperStatefulReleaseServer(server);
		/* Get another server */
		server = helperStatefulGetServer(ntlmauthenticators);
		helperstate = server ? helperStatefulServerGetData(server) : NULL;
	    }
	}
	ntlm_request->authserver = server;
	/* tell the log what helper we have been given */
	if (server == NULL)
	    debug(29, 9) ("authenticateNTLMStart: unable to get a ntlm helper... Queuing as a placeholder request.\n");
	else
	    debug(29, 9) ("authenticateNTLMStart: helper '%p' assigned\n", server);
	/* server and valid challenge? */
	if ((server == NULL) || ntlmConfig->challengeuses == 0 || !authenticateNTLMValidChallenge(helperstate)) {
	    /* No server, or server with invalid challenge */
	    r = cbdataAlloc(authenticateStateData);
	    r->handler = handler;
	    cbdataLock(data);
	    r->data = data;
	    r->auth_user_request = auth_user_request;
	    authenticateAuthUserRequestLock(r->auth_user_request);
	    if (server == NULL && ntlmConfig->challengeuses) {
		helperStatefulSubmit(ntlmauthenticators, NULL, authenticateNTLMHandleplaceholder, r, NULL);
	    } else {
		/* Server with invalid challenge */

		if (ntlmConfig->use_ntlm_negotiate) {
		    snprintf(buf, 8192, "YR %s\n", sent_string);
		} else {
		    snprintf(buf, 8192, "YR\n");
		}

		helperStatefulSubmit(ntlmauthenticators, buf, authenticateNTLMHandleReply, r, ntlm_request->authserver);
	    }
	} else {
	    if (!ntlmConfig->challengeuses)
		debug(29, 0) ("authenticateNTLMStart: Reused challenge in server %p even if challenge reuse is disabled!", server);
	    /* (server != NULL and we have a valid challenge) */
	    /* TODO: turn the below into a function and call from here and handlereply */
	    /* increment the challenge uses */
	    helperstate->challengeuses++;
	    /* assign the challenge */
	    ntlm_request->authchallenge = xstrdup(helperstate->challenge);
	    handler(data, NULL);
	}

	break;
    case AUTHENTICATE_STATE_RESPONSE:
	r = cbdataAlloc(authenticateStateData);
	r->handler = handler;
	cbdataLock(data);
	r->data = data;
	r->auth_user_request = auth_user_request;
	authenticateAuthUserRequestLock(r->auth_user_request);
	snprintf(buf, 8192, "KK %s\n", sent_string);
	helperStatefulSubmit(ntlmauthenticators, buf, authenticateNTLMHandleReply, r, ntlm_request->authserver);
	debug(29, 9) ("authenticateNTLMstart: finished\n");
	break;
    default:
	fatal("Invalid authenticate state for NTLMStart");
    }
}

/* callback used by stateful helper routines */
static int
authenticateNTLMHelperServerAvailable(void *data)
{
    ntlm_helper_state_t *statedata = data;
    if (statedata != NULL) {
	if (statedata->starve) {
	    debug(29, 4) ("authenticateNTLMHelperServerAvailable: starving - returning 0\n");
	    return 0;
	} else {
	    debug(29, 4) ("authenticateNTLMHelperServerAvailable: not starving - returning 1\n");
	    return 1;
	}
    }
    debug(29, 4) ("authenticateNTLMHelperServerAvailable: no state data - returning 0\n");
    return 0;
}

static void
authenticateNTLMHelperServerReset(void *data)
{
    ntlm_helper_state_t *statedata = data;
    if (statedata == NULL)
	return;
    if (statedata->starve) {
	/* we have been starving the helper */
	debug(29, 9) ("authenticateNTLMHelperServerReset: resetting challenge details\n");
	statedata->starve = 0;
	statedata->challengeuses = 0;
	statedata->renewed = 0;
	xfree(statedata->challenge);
	statedata->challenge = NULL;
	while (statedata->user_list.head) {
	    authenticateNTLMChallengeCacheRemoveLink(statedata->user_list.head->data);
	}
    }
}

/* clear any connection related authentication details */
static void
authenticateNTLMOnCloseConnection(ConnStateData * conn)
{
    ntlm_request_t *ntlm_request;
    assert(conn != NULL);
    if (conn->auth_user_request != NULL) {
	assert(conn->auth_user_request->scheme_data != NULL);
	ntlm_request = conn->auth_user_request->scheme_data;
	assert(ntlm_request->conn == conn);
	if (ntlm_request->authserver != NULL)
	    authenticateNTLMReleaseServer(ntlm_request);
	/* unlock the connection based lock */
	debug(29, 9) ("authenticateNTLMOnCloseConnection: Unlocking auth_user from the connection.\n");
	/* minor abstraction break here: FIXME */
	/* Ensure that the auth user request will be getting closed */
	/* IFF we start persisting the struct after the conn closes - say for logging
	 * then this test may become invalid
	 */
	assert(conn->auth_user_request->references == 1);
	authenticateAuthUserRequestUnlock(conn->auth_user_request);
	conn->auth_user_request = NULL;
    }
}

/* authenticateUserUsername: return a pointer to the username in the */
static char *
authenticateNTLMUsername(auth_user_t * auth_user)
{
    ntlm_user_t *ntlm_user = auth_user->scheme_data;
    if (ntlm_user)
	return ntlm_user->username;
    return NULL;
}

/* NTLMLastHeader: return a pointer to the last header used in authenticating
 * the request/conneciton
 */
static const char *
NTLMLastHeader(auth_user_request_t * auth_user_request)
{
    ntlm_request_t *ntlm_request;
    assert(auth_user_request != NULL);
    assert(auth_user_request->scheme_data != NULL);
    ntlm_request = auth_user_request->scheme_data;
    return ntlm_request->ntlmauthenticate;
}

/*
 * Decode an NTLM [Proxy-]Auth string, placing the results in the passed
 * Auth_user structure.
 */

static void
authenticateDecodeNTLMAuth(auth_user_request_t * auth_user_request, const char *proxy_auth)
{
    dlink_node *node;
    assert(auth_user_request->auth_user == NULL);
    auth_user_request->auth_user = authenticateAuthUserNew("ntlm");
    auth_user_request->auth_user->auth_type = AUTH_NTLM;
    auth_user_request->auth_user->scheme_data = memPoolAlloc(ntlm_user_pool);
    auth_user_request->scheme_data = memPoolAlloc(ntlm_request_pool);
    memset(auth_user_request->scheme_data, '\0', sizeof(ntlm_request_t));
    /* lock for the auth_user_request link */
    authenticateAuthUserLock(auth_user_request->auth_user);
    node = dlinkNodeNew();
    dlinkAdd(auth_user_request, node, &auth_user_request->auth_user->requests);

    /* all we have to do is identify that it's NTLM - the helper does the rest */
    debug(29, 9) ("authenticateDecodeNTLMAuth: NTLM authentication\n");
    return;
}

static int
authenticateNTLMcmpUsername(ntlm_user_t * u1, ntlm_user_t * u2)
{
    return strcmp(u1->username, u2->username);
}


/* there is a known race where a single client recieves the same challenge
 * and sends the same response to squid on a single select cycle.
 * Check for this and if found ignore the new link 
 */
static void
authenticateNTLMChallengeCacheAddLink(const char *key, auth_user_t * auth_user, helper_stateful_server * auth_server)
{
    ntlm_challenge_hash_pointer *challenge_hash;
    ntlm_user_t *ntlm_user;
    ntlm_helper_state_t *helperstate = helperStatefulServerGetData(auth_server);
    ntlm_user = auth_user->scheme_data;
    /* prevent duplicates */
    if (hash_lookup(ntlm_challenge_cache, key))
	return;
    challenge_hash = memPoolAlloc(ntlm_challenge_pool);
    challenge_hash->key = xstrdup(key);
    challenge_hash->user.auth_user = auth_user;
    dlinkAddTail(challenge_hash, &challenge_hash->user.link, &ntlm_user->challenge_list);
    challenge_hash->challenge.authserver = auth_server;
    dlinkAddTail(challenge_hash, &challenge_hash->challenge.link, &helperstate->user_list);
    hash_join(ntlm_challenge_cache, (hash_link *) challenge_hash);
}

static void
authenticateNTLMChallengeCacheRemoveLink(ntlm_challenge_hash_pointer * challenge_hash)
{
    ntlm_user_t *ntlm_user = challenge_hash->user.auth_user->scheme_data;
    ntlm_helper_state_t *helperstate = helperStatefulServerGetData(challenge_hash->challenge.authserver);
    hash_remove_link(ntlm_challenge_cache, (hash_link *) challenge_hash);
    dlinkDelete(&challenge_hash->user.link, &ntlm_user->challenge_list);
    dlinkDelete(&challenge_hash->challenge.link, &helperstate->user_list);
    xfree(challenge_hash->key);
    memPoolFree(ntlm_challenge_pool, challenge_hash);
}


static int
authNTLMAuthenticated(auth_user_request_t * auth_user_request)
{
    ntlm_request_t *ntlm_request = auth_user_request->scheme_data;
    if (ntlm_request->auth_state == AUTHENTICATE_STATE_DONE)
	return 1;
    debug(29, 9) ("User not fully authenticated.\n");
    return 0;
}

static void
authenticateNTLMAuthenticateUser(auth_user_request_t * auth_user_request, request_t * request, ConnStateData * conn, http_hdr_type type)
{
    const char *proxy_auth;
    auth_user_hash_pointer *usernamehash;
    ntlm_challenge_hash_pointer *challenge_hash = NULL;
    auth_user_t *auth_user;
    ntlm_request_t *ntlm_request;
    ntlm_user_t *ntlm_user;
    LOCAL_ARRAY(char, ntlmhash, NTLM_CHALLENGE_SZ * 2);
    /* get header */
    proxy_auth = httpHeaderGetStr(&request->header, type);

    auth_user = auth_user_request->auth_user;
    assert(auth_user);
    assert(auth_user->auth_type == AUTH_NTLM);
    assert(auth_user->scheme_data != NULL);
    assert(auth_user_request->scheme_data != NULL);
    ntlm_user = auth_user->scheme_data;
    ntlm_request = auth_user_request->scheme_data;
    /* Check that we are in the client side, where we can generate
     * auth challenges */
    if (!conn) {
	ntlm_request->auth_state = AUTHENTICATE_STATE_FAILED;
	debug(29, 1) ("authenticateNTLMAuthenticateUser: attempt to perform authentication without a connection!\n");
	return;
    }
    switch (ntlm_request->auth_state) {
    case AUTHENTICATE_STATE_NONE:
	/* we've recieved a negotiate request. pass to a helper */
	debug(29, 9) ("authenticateNTLMAuthenticateUser: auth state ntlm none. %s\n", proxy_auth);
	ntlm_request->auth_state = AUTHENTICATE_STATE_NEGOTIATE;
	ntlm_request->ntlmnegotiate = xstrdup(proxy_auth);
	conn->auth_type = AUTH_NTLM;
	conn->auth_user_request = auth_user_request;
	ntlm_request->conn = conn;
	/* and lock for the connection duration */
	debug(29, 9) ("authenticateNTLMAuthenticateUser: Locking auth_user from the connection.\n");
	authenticateAuthUserRequestLock(auth_user_request);
	return;
	break;
    case AUTHENTICATE_STATE_NEGOTIATE:
	ntlm_request->auth_state = AUTHENTICATE_STATE_CHALLENGE;
	/* We _MUST_ have the auth challenge by now */
	assert(ntlm_request->authchallenge);
	return;
	break;
    case AUTHENTICATE_STATE_CHALLENGE:
	/* we should have recieved a NTLM challenge. pass it to the same 
	 * helper process */
	debug(29, 9) ("authenticateNTLMAuthenticateUser: auth state challenge with header %s.\n", proxy_auth);
	/* do a cache lookup here. If it matches it's a successful ntlm 
	 * challenge - release the helper and use the existing auth_user 
	 * details. */
	if (strncmp("NTLM ", proxy_auth, 5) == 0) {
	    ntlm_request->ntlmauthenticate = xstrdup(proxy_auth);
	} else {
	    fatal("Incorrect scheme in auth header\n");
	    /* TODO: more fault tolerance.. reset the auth scheme here */
	}
	/* normal case with challenge reuses disabled */
	if (ntlmConfig->challengeuses == 0) {
	    /* verify with the ntlm helper */
	    ntlm_request->auth_state = AUTHENTICATE_STATE_RESPONSE;
	    return;
	}
	/* cache entries have authenticateauthheaderchallengestring */
	snprintf(ntlmhash, sizeof(ntlmhash) - 1, "%s%s",
	    ntlm_request->ntlmauthenticate,
	    ntlm_request->authchallenge);
	/* see if we already know this user's authenticate */
	debug(29, 9) ("aclMatchProxyAuth: cache lookup with key '%s'\n", ntlmhash);
	assert(ntlm_challenge_cache != NULL);
	challenge_hash = hash_lookup(ntlm_challenge_cache, ntlmhash);
	if (!challenge_hash) {	/* not in the hash table */
	    debug(29, 4) ("authenticateNTLMAuthenticateUser: proxy-auth cache miss.\n");
	    ntlm_request->auth_state = AUTHENTICATE_STATE_RESPONSE;
	    /* verify with the ntlm helper */
	} else {
	    debug(29, 4) ("authenticateNTLMAuthenticateUser: ntlm proxy-auth cache hit\n");
	    /* throw away the temporary entry */
	    ntlm_request->authserver_deferred = 0;
	    authenticateNTLMReleaseServer(ntlm_request);
	    authenticateAuthUserMerge(auth_user, challenge_hash->user.auth_user);
	    auth_user = challenge_hash->user.auth_user;
	    auth_user_request->auth_user = auth_user;
	    ntlm_request->auth_state = AUTHENTICATE_STATE_DONE;
	    /* we found one */
	    debug(29, 9) ("found matching cache entry\n");
	    assert(auth_user->auth_type == AUTH_NTLM);
	    /* get the existing entries details */
	    ntlm_user = auth_user->scheme_data;
	    debug(29, 9) ("Username to be used is %s\n", ntlm_user->username);
	    /* on ntlm auth we do not unlock the auth_user until the
	     * connection is dropped. Thank MS for this quirk */
	    auth_user->expiretime = current_time.tv_sec;
	}
	return;
	break;
    case AUTHENTICATE_STATE_RESPONSE:
	/* auth-challenge pair cache miss. We've just got the response from the helper */
	/*add to cache and let them through */
	ntlm_request->auth_state = AUTHENTICATE_STATE_DONE;
	/* this connection is authenticated */
	debug(29, 4) ("authenticated\nch    %s\nauth     %s\nauthuser %s\n",
	    ntlm_request->authchallenge,
	    ntlm_request->ntlmauthenticate,
	    ntlm_user->username);
	/* see if this is an existing user with a different proxy_auth 
	 * string */
	usernamehash = hash_lookup(proxy_auth_username_cache, ntlm_user->username);
	if (usernamehash) {
	    while (usernamehash && (usernamehash->auth_user->auth_type != auth_user->auth_type || authenticateNTLMcmpUsername(usernamehash->auth_user->scheme_data, ntlm_user) != 0))
		usernamehash = usernamehash->next;
	}
	if (usernamehash) {
	    /* we can't seamlessly recheck the username due to the 
	     * challenge nature of the protocol. Just free the 
	     * temporary auth_user */
	    authenticateAuthUserMerge(auth_user, usernamehash->auth_user);
	    auth_user = usernamehash->auth_user;
	    auth_user_request->auth_user = auth_user;
	} else {
	    /* store user in hash's */
	    authenticateUserNameCacheAdd(auth_user);
	}
	if (ntlmConfig->challengeuses) {
	    /* cache entries have authenticateauthheaderchallengestring */
	    snprintf(ntlmhash, sizeof(ntlmhash) - 1, "%s%s",
		ntlm_request->ntlmauthenticate,
		ntlm_request->authchallenge);
	    authenticateNTLMChallengeCacheAddLink(ntlmhash, auth_user, ntlm_request->authserver);
	}
	/* set these to now because this is either a new login from an 
	 * existing user or a new user */
	auth_user->expiretime = current_time.tv_sec;
	authenticateNTLMReleaseServer(ntlm_request);
	return;
    case AUTHENTICATE_STATE_DONE:
	fatal("authenticateNTLMAuthenticateUser: unexpect auth state DONE! Report a bug to the squid developers.\n");
	break;
    case AUTHENTICATE_STATE_FAILED:
	/* we've failed somewhere in authentication */
	debug(29, 9) ("authenticateNTLMAuthenticateUser: auth state ntlm failed. %s\n", proxy_auth);
	return;
    }
    return;
}
