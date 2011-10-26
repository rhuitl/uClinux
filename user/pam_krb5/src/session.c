/*
 * Copyright 2003,2004,2005,2006,2007,2008,2009 Red Hat, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of the
 * GNU Lesser General Public License, in which case the provisions of the
 * LGPL are required INSTEAD OF the above restrictions.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "../config.h"

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif

#ifdef HAVE_SECURITY_PAM_MODULES_H
#define PAM_SM_SESSION
#include <security/pam_modules.h>
#endif

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include KRB5_H
#ifdef USE_KRB4
#include KRB4_DES_H
#include KRB4_KRB_H
#ifdef KRB4_KRB_ERR_H
#include KRB4_KRB_ERR_H
#endif
#endif

#include "init.h"
#include "log.h"
#include "options.h"
#include "prompter.h"
#include "shmem.h"
#include "stash.h"
#include "tokens.h"
#include "userinfo.h"
#include "v5.h"
#include "v4.h"
#include "xstr.h"

int
pam_sm_open_session(pam_handle_t *pamh, int flags,
		    int argc, PAM_KRB5_MAYBE_CONST char **argv)
{
	PAM_KRB5_MAYBE_CONST char *user;
	char envstr[PATH_MAX + 20], *segname;
	const char *ccname;
	krb5_context ctx;
	struct _pam_krb5_options *options;
	struct _pam_krb5_user_info *userinfo;
	struct _pam_krb5_stash *stash;
	int i, retval;

	/* Initialize Kerberos. */
	if (_pam_krb5_init_ctx(&ctx, argc, argv) != 0) {
		warn("error initializing Kerberos");
		return PAM_SERVICE_ERR;
	}

	/* Get the user's name. */
	i = pam_get_user(pamh, &user, NULL);
	if ((i != PAM_SUCCESS) || (user == NULL)) {
		warn("could not identify user name");
		krb5_free_context(ctx);
		return i;
	}

	/* Read our options. */
	options = _pam_krb5_options_init(pamh, argc, argv, ctx);
	if (options == NULL) {
		warn("error parsing options (shouldn't happen)");
		krb5_free_context(ctx);
		return PAM_SERVICE_ERR;
	}

	/* Get information about the user and the user's principal name. */
	userinfo = _pam_krb5_user_info_init(ctx, user, options);
	if (userinfo == NULL) {
		if (options->debug) {
			debug("no user info for '%s'", user);
		}
		if (options->ignore_unknown_principals) {
			retval = PAM_IGNORE;
		} else {
			retval = PAM_USER_UNKNOWN;
		}
		if (options->debug) {
			debug("pam_open_session returning %d (%s)",
			      retval,
			      pam_strerror(pamh, retval));
		}
		_pam_krb5_options_free(pamh, ctx, options);
		krb5_free_context(ctx);
		return retval;
	}
	if ((options->user_check) &&
	    (options->minimum_uid != (uid_t)-1) &&
	    (userinfo->uid < options->minimum_uid)) {
		if (options->debug) {
			debug("ignoring '%s' -- uid below minimum = %lu", user,
			      (unsigned long) options->minimum_uid);
		}
		_pam_krb5_user_info_free(ctx, userinfo);
		if (options->debug) {
			debug("pam_open_session returning %d (%s)", PAM_IGNORE,
			      pam_strerror(pamh, PAM_IGNORE));
		}
		_pam_krb5_options_free(pamh, ctx, options);
		krb5_free_context(ctx);
		return PAM_IGNORE;
	}

	/* Get the stash for this user. */
	stash = _pam_krb5_stash_get(pamh, user, userinfo, options);
	if (stash == NULL) {
		warn("no stash for '%s' (shouldn't happen)", user);
		_pam_krb5_user_info_free(ctx, userinfo);
		if (options->debug) {
			debug("pam_open_session returning %d (%s)",
			      PAM_SERVICE_ERR,
			      pam_strerror(pamh, PAM_SERVICE_ERR));
		}
		_pam_krb5_options_free(pamh, ctx, options);
		krb5_free_context(ctx);
		return PAM_SERVICE_ERR;
	}

	/* We don't need the shared memory segments any more, so we can get rid
	 * of them now.  (Depending on the application, we may not get a chance
	 * to do it later.) */
	if (options->use_shmem) {
		if ((stash->v5shm != -1) && (stash->v5shm_owner != -1)) {
			if (options->debug) {
				debug("removing v5 shared memory segment %d"
				      " creator pid %ld",
				      stash->v5shm, (long) stash->v5shm_owner);
			}
			_pam_krb5_shm_remove(stash->v5shm_owner, stash->v5shm,
					     options->debug);
			stash->v5shm = -1;
			_pam_krb5_stash_shm5_name(options, user, &segname);
			if (segname != NULL) {
				pam_putenv(pamh, segname);
				free(segname);
			}
		}
#ifdef USE_KRB4
		if ((stash->v4shm != -1) && (stash->v4shm_owner != -1)) {
			if (options->debug) {
				debug("removing v4 shared memory segment %d"
				      " creator pid %ld",
				      stash->v4shm, (long) stash->v4shm_owner);
			}
			_pam_krb5_shm_remove(stash->v4shm_owner, stash->v4shm,
					     options->debug);
			stash->v4shm = -1;
			_pam_krb5_stash_shm4_name(options, user, &segname);
			if (segname != NULL) {
				pam_putenv(pamh, segname);
				free(segname);
			}
		}
#endif
	}

	/* If we don't have any credentials, then we're done. */
	if ((stash->v5attempted == 0) || (stash->v5result != 0)) {
		if (options->debug) {
			debug("no v5 creds for user '%s', "
			      "skipping session setup", user);
		}
		_pam_krb5_user_info_free(ctx, userinfo);
		if (options->debug) {
			debug("pam_open_session returning %d (%s)", PAM_SUCCESS,
			      pam_strerror(pamh, PAM_SUCCESS));
		}
		_pam_krb5_options_free(pamh, ctx, options);
		krb5_free_context(ctx);
		return PAM_SUCCESS;
	}

	/* Obtain tokens, if necessary. */
	if ((i == PAM_SUCCESS) &&
	    (options->ignore_afs == 0) &&
	    tokens_useful()) {
		v5_save_for_tokens(ctx, stash, user, userinfo, options, NULL);
		if (stash->v4present) {
			v4_save_for_tokens(ctx, stash, userinfo, options, NULL);
		}
		
		tokens_obtain(ctx, stash, options, userinfo, 1);

		if (stash->v4present) {
			v4_destroy(ctx, stash, options);
		}
		v5_destroy(ctx, stash, options);
	}

	/* Create the user's credential cache. */
	if (options->debug) {
#ifdef HAVE_LONG_LONG
		debug("creating v5 ccache for '%s', uid=%llu, gid=%llu", user,
		      options->user_check ?
		      (unsigned long long) userinfo->uid :
		      (unsigned long long) getuid(),
		      options->user_check ?
		      (unsigned long long) userinfo->gid :
		      (unsigned long long) getgid());
#else
		debug("creating v5 ccache for '%s', uid=%lu, gid=%lu",
		      user,
		      options->user_check ?
		      (unsigned long) userinfo->uid :
		      (unsigned long) getuid(),
		      options->user_check ?
		      (unsigned long) userinfo->gid :
		      (unsigned long) getgid());
#endif
	}
	i = v5_save_for_user(ctx, stash, user, userinfo, options, &ccname);
	if ((i == PAM_SUCCESS) && (strlen(ccname) > 0)) {
		if (options->debug) {
			debug("created v5 ccache '%s' for '%s'", ccname, user);
		}
		sprintf(envstr, "KRB5CCNAME=%s", ccname);
		pam_putenv(pamh, envstr);
		stash->v5setenv = 1;
	}

#ifdef USE_KRB4
	/* Keep track of where the v5 ccache is. */
	if ((ccname == NULL) || (strlen(ccname) == 0)) {
		ccname = pam_getenv(pamh, "KRB5CCNAME");
	}
	/* Only bother to create a v4 tktfile if there's a v5 ccache. */
	if ((i == PAM_SUCCESS) && (stash->v4present) &&
	    (ccname != NULL) && (strlen(ccname) > 0)) {
		if (options->debug) {
			debug("creating v4 ticket file for '%s'", user);
		}
		i = v4_save_for_user(ctx, stash, userinfo, options, &ccname);
		if (i == PAM_SUCCESS) {
			if (options->debug) {
				debug("created v4 ticket file '%s' for "
				      "'%s'", ccname, user);
			}
			sprintf(envstr, "KRBTKFILE=%s", ccname);
			pam_putenv(pamh, envstr);
			stash->v4setenv = 1;
		}
	}
#endif

	/* If we didn't create ccache files because we couldn't, just
	 * pretend everything's fine. */
	if ((i != PAM_SUCCESS) &&
	    (v5_creds_check_initialized(ctx, &stash->v5creds) != 0)) {
		i = PAM_SUCCESS;
	}

	/* Clean up. */
	if (options->debug) {
		debug("pam_open_session returning %d (%s)", i,
		      pam_strerror(pamh, i));
	}
	_pam_krb5_options_free(pamh, ctx, options);
	_pam_krb5_user_info_free(ctx, userinfo);


	krb5_free_context(ctx);
	return i;
}

int
pam_sm_close_session(pam_handle_t *pamh, int flags,
		     int argc, PAM_KRB5_MAYBE_CONST char **argv)
{
	PAM_KRB5_MAYBE_CONST char *user;
	krb5_context ctx;
	struct _pam_krb5_options *options;
	struct _pam_krb5_user_info *userinfo;
	struct _pam_krb5_stash *stash;
	int i, retval;

	/* Initialize Kerberos. */
	if (_pam_krb5_init_ctx(&ctx, argc, argv) != 0) {
		warn("error initializing Kerberos");
		return PAM_SERVICE_ERR;
	}

	/* Get the user's name. */
	i = pam_get_user(pamh, &user, NULL);
	if (i != PAM_SUCCESS) {
		warn("could not determine user name");
		krb5_free_context(ctx);
		return i;
	}

	/* Read our options. */
	options = _pam_krb5_options_init(pamh, argc, argv, ctx);
	if (options == NULL) {
		krb5_free_context(ctx);
		return PAM_SERVICE_ERR;
	}

	/* Get information about the user and the user's principal name. */
	userinfo = _pam_krb5_user_info_init(ctx, user, options);
	if (userinfo == NULL) {
		if (options->ignore_unknown_principals) {
			retval = PAM_IGNORE;
		} else {
			warn("no user info for %s (shouldn't happen)", user);
			retval = PAM_USER_UNKNOWN;
		}
		if (options->debug) {
			debug("pam_close_session returning %d (%s)",
			      retval,
			      pam_strerror(pamh, retval));
		}
		_pam_krb5_options_free(pamh, ctx, options);
		krb5_free_context(ctx);
		return retval;
	}

	/* Check the minimum UID argument. */
	if ((options->user_check) &&
	    (options->minimum_uid != (uid_t)-1) &&
	    (userinfo->uid < options->minimum_uid)) {
		if (options->debug) {
			debug("ignoring '%s' -- uid below minimum", user);
		}
		_pam_krb5_user_info_free(ctx, userinfo);
		if (options->debug) {
			debug("pam_close_session returning %d (%s)", PAM_IGNORE,
			      pam_strerror(pamh, PAM_IGNORE));
		}
		_pam_krb5_options_free(pamh, ctx, options);
		krb5_free_context(ctx);
		return PAM_IGNORE;
	}

	/* Get the stash for this user. */
	stash = _pam_krb5_stash_get(pamh, user, userinfo, options);
	if (stash == NULL) {
		warn("no stash for user %s (shouldn't happen)", user);
		_pam_krb5_user_info_free(ctx, userinfo);
		if (options->debug) {
			debug("pam_close_session returning %d (%s)",
			      PAM_SERVICE_ERR,
			      pam_strerror(pamh, PAM_SERVICE_ERR));
		}
		_pam_krb5_options_free(pamh, ctx, options);
		krb5_free_context(ctx);
		return PAM_SERVICE_ERR;
	}

	/* If we didn't obtain any credentials, then we're done. */
	if ((stash->v5attempted == 0) || (stash->v5result != 0)) {
		if (options->debug) {
			debug("no v5 creds for user '%s', "
			      "skipping session cleanup",
			      user);
		}
		_pam_krb5_user_info_free(ctx, userinfo);
		if (options->debug) {
			debug("pam_close_session returning %d (%s)",
			      PAM_SUCCESS,
			      pam_strerror(pamh, PAM_SUCCESS));
		}
		_pam_krb5_options_free(pamh, ctx, options);
		krb5_free_context(ctx);
		return PAM_SUCCESS;
	}

	if (options->ignore_afs == 0) {
		tokens_release(stash, options);
	}

	if (stash->v5ccnames != NULL) {
		v5_destroy(ctx, stash, options);
		if (stash->v5setenv) {
			pam_putenv(pamh, "KRB5CCNAME");
			stash->v5setenv = 0;
		}
		if (options->debug) {
			debug("destroyed v5 ccache for '%s'", user);
		}
	}

#ifdef USE_KRB4
	if (stash->v4tktfiles != NULL) {
		v4_destroy(ctx, stash, options);
		if (stash->v4setenv) {
			pam_putenv(pamh, "KRBTKFILE");
			stash->v4setenv = 0;
		}
		if (options->debug) {
			debug("destroyed v4 ticket file for '%s'", user);
		}
	}
#endif
	_pam_krb5_user_info_free(ctx, userinfo);
	if (options->debug) {
		debug("pam_close_session returning %d (%s)",
		      PAM_SUCCESS,
		      pam_strerror(pamh, PAM_SUCCESS));
	}
	_pam_krb5_options_free(pamh, ctx, options);
	krb5_free_context(ctx);
	return PAM_SUCCESS;
}
