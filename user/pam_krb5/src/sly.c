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

#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif

#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

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
#include "sly.h"
#include "stash.h"
#include "tokens.h"
#include "userinfo.h"
#include "v5.h"
#include "v4.h"

#ifdef USE_KRB4
/* Store the v4 TGT in $KRBTKFILE. */
static void
sly_v4(krb5_context ctx, const char *v4tktfile,
       struct _pam_krb5_user_info *userinfo, struct _pam_krb5_stash *stash)
{
	int i;
	char name[ANAME_SZ + 1], instance[INST_SZ + 1], realm[REALM_SZ + 1];

	i = krb5_524_conv_principal(ctx, userinfo->principal_name,
				    name, instance, realm);
	if (i != 0) {
		return;
	}

	tf_init((char *) v4tktfile, W_TKT_FIL);
	v4_in_tkt(name, instance, realm);
	v4_save_credentials(KRB5_TGS_NAME, realm, realm,
			    stash->v4creds.session,
			    stash->v4creds.lifetime,
			    stash->v4creds.kvno,
			    &stash->v4creds.ticket_st,
			    stash->v4creds.issue_date);
	tf_close();
}
#else
static void
sly_v4(krb5_context ctx, const char *v4tktfile,
       struct _pam_krb5_user_info *userinfo, struct _pam_krb5_stash *stash)
{
}
#endif

/* Store the v5 TGT in $KRB5CCNAME. */
static int
sly_v5(krb5_context ctx, const char *v5ccname,
       struct _pam_krb5_user_info *userinfo, struct _pam_krb5_stash *stash)
{
	krb5_ccache ccache;
	krb5_principal princ;
	int i;

	ccache = NULL;
	i = krb5_cc_resolve(ctx, v5ccname, &ccache);
	if (i == 0) {
		princ = NULL;
		if (krb5_cc_get_principal(ctx, ccache, &princ) == 0) {
			if (krb5_principal_compare(ctx, princ,
						   userinfo->principal_name) == FALSE) {
				krb5_free_principal(ctx, princ);
				krb5_cc_close(ctx, ccache);
				return PAM_SERVICE_ERR;
			}
			krb5_free_principal(ctx, princ);
		}
		i = krb5_cc_initialize(ctx, ccache, userinfo->principal_name);
		if (i == 0) {
			i = krb5_cc_store_cred(ctx, ccache, &stash->v5creds);
		}
		krb5_cc_close(ctx, ccache);
	}

	return PAM_SUCCESS;
}

/* Inexpensive checks. */
int
_pam_krb5_sly_looks_unsafe(void)
{
	if (getenv("SUDO_COMMAND") != NULL) {
		return 1;
	}
	if (getuid() != geteuid()) {
		return 2;
	}
	if (getgid() != getegid()) {
		return 3;
	}
	return 0;
}

int
_pam_krb5_sly_maybe_refresh(pam_handle_t *pamh, int flags,
			    int argc, PAM_KRB5_MAYBE_CONST char **argv)
{
	PAM_KRB5_MAYBE_CONST char *user;
	krb5_context ctx;
	struct _pam_krb5_options *options;
	struct _pam_krb5_user_info *userinfo;
	struct _pam_krb5_stash *stash;
	struct stat st;
	int i, retval, stored;
	uid_t uid;
	gid_t gid;
	const char *v5ccname, *v5filename, *v4tktfile;
#ifdef TKT_ROOT
	char v4tktfilebuf[PATH_MAX];
#endif

	/* Inexpensive checks. */
	switch (_pam_krb5_sly_looks_unsafe()) {
	case 0:
		/* nothing: everything's okay */
		break;
	case 1:
		warn("won't refresh credentials while running under sudo");
		return PAM_SERVICE_ERR;
		break;
	case 2:
		warn("won't refresh credentials while running setuid");
		return PAM_SERVICE_ERR;
		break;
	case 3:
		warn("won't refresh credentials while running setgid");
		return PAM_SERVICE_ERR;
		break;
	default:
		warn("not safe to refresh credentials");
		return PAM_SERVICE_ERR;
		break;
	}

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
	if (options->debug) {
		debug("called to update credentials for '%s'", user);
	}

	/* Get information about the user and the user's principal name. */
	userinfo = _pam_krb5_user_info_init(ctx, user, options);
	if (userinfo == NULL) {
		if (options->ignore_unknown_principals) {
			retval = PAM_IGNORE;
		} else {
			warn("error getting information about '%s' "
			     "(shouldn't happen)", user);
			retval = PAM_USER_UNKNOWN;
		}
		_pam_krb5_options_free(pamh, ctx, options);
		krb5_free_context(ctx);
		return retval;
	}

	if ((options->user_check) &&
	    (options->minimum_uid != (uid_t)-1) &&
	    (userinfo->uid < options->minimum_uid)) {
		if (options->debug) {
			debug("ignoring '%s' -- uid below minimum", user);
		}
		_pam_krb5_user_info_free(ctx, userinfo);
		_pam_krb5_options_free(pamh, ctx, options);
		krb5_free_context(ctx);
		return PAM_IGNORE;
	}

	/* Get the stash for this user. */
	stash = _pam_krb5_stash_get(pamh, user, userinfo, options);
	if (stash == NULL) {
		warn("error retrieving stash for '%s' (shouldn't happen)",
		     user);
		_pam_krb5_user_info_free(ctx, userinfo);
		_pam_krb5_options_free(pamh, ctx, options);
		krb5_free_context(ctx);
		return PAM_SERVICE_ERR;
	}

	retval = PAM_SERVICE_ERR;

	/* Save credentials in the right places. */
	v5ccname = krb5_cc_default_name(ctx);
	v5filename = NULL;
	if (v5ccname == NULL) {
		/* This should never happen, but all we can do is tell libpam
		 * to ignore us.  We have nothing to do. */
		if (options->debug) {
			debug("ignoring '%s' -- no default ccache name", user);
		}
		retval = PAM_IGNORE;
	} else {
		if (strncmp(v5ccname, "FILE:", 5) == 0) {
			v5filename = v5ccname + 5;
			if (options->debug) {
				debug("ccache is a file named '%s'",
				      v5filename);
			}
		} else {
			if (options->debug) {
				debug("ccache '%s' is not a file", v5ccname);
			}
		}
	}

	stored = 0;
	uid = options->user_check ? userinfo->uid : getuid();
	gid = options->user_check ? userinfo->gid : getgid();

	if (v5_creds_check_initialized(ctx, &stash->v5creds) == 0) {
		if (v5filename != NULL) {
			/* Check the permissions on the ccache file. */
			if ((access(v5filename, R_OK | W_OK) == 0) &&
			    (lstat(v5filename, &st) == 0)) {
				if (S_ISREG(st.st_mode) &&
				    ((st.st_mode & S_IRWXG) == 0) &&
				    ((st.st_mode & S_IRWXO) == 0) &&
				    (st.st_uid == uid) &&
				    (st.st_gid == gid)) {
					if (options->debug) {
						debug("updating ccache '%s' "
						      "for '%s'",
						      v5ccname, user);
					}
					retval = sly_v5(ctx, v5ccname,
							userinfo, stash);
					stored = (retval == PAM_SUCCESS);
				} else {
					if (options->debug) {
						debug("not updating '%s'",
						      v5ccname);
					}
					retval = PAM_SUCCESS;
				}
			} else {
				if (errno == ENOENT) {
					/* We have nothing to do. */
					retval = PAM_SUCCESS;
				}
			}
		} else {
			if (v5ccname != NULL) {
				/* Go ahead and update the current not-a-file
				 * ccache. */
				if (options->debug) {
					debug("updating ccache '%s' for '%s'",
					      v5ccname, user);
				}
				retval = sly_v5(ctx, v5ccname, userinfo, stash);
				stored = (retval == PAM_SUCCESS);
			}
		}
	} else {
		if (options->debug) {
			debug("no credentials available to store in '%s'",
			      v5ccname);
		}
		retval = PAM_SUCCESS;
	}

	v4tktfile = getenv("KRBTKFILE");
#ifdef TKT_ROOT
	if ((v4tktfile == NULL) && (options->user_check)) {
		snprintf(v4tktfilebuf, sizeof(v4tktfilebuf), "%s%ld",
			 TKT_ROOT, (long) uid);
		v4tktfile = v4tktfilebuf;
	}
#endif
	if ((stash->v4present) && (v4tktfile != NULL)) {
		if (access(v4tktfile, R_OK | W_OK) == 0) {
			if (lstat(v4tktfile, &st) == 0) {
				if (S_ISREG(st.st_mode) &&
				    ((st.st_mode & S_IRWXG) == 0) &&
				    ((st.st_mode & S_IRWXO) == 0) &&
				    (st.st_uid == uid) &&
				    (st.st_gid == gid)) {
					if (options->debug) {
						debug("updating ticket file "
						      "'%s' for '%s'",
						      v4tktfile, user);
					}
					sly_v4(ctx, v4tktfile, userinfo, stash);
					stored = 1;
				} else {
					if (options->debug) {
						debug("not updating '%s'",
						      v4tktfile);
					}
				}
			} else {
				if (errno == ENOENT) {
					/* We have nothing to do. */
					if (options->debug) {
						debug("no preexisting ticket "
						      "file found");
					}
					retval = PAM_SUCCESS;
				}
			}
		} else {
			/* Touch nothing. */
			if (options->debug) {
				debug("unable to access preexisting ticket "
				      "file");
			}
			retval = PAM_SUCCESS;
		}
	}

	if (stored && !options->ignore_afs) {
		tokens_obtain(ctx, stash, options, userinfo, 0);
	}

	if (options->debug) {
		debug("_pam_krb5_sly_refresh returning %d (%s)", retval,
		      pam_strerror(pamh, retval));
	}

	_pam_krb5_user_info_free(ctx, userinfo);
	_pam_krb5_options_free(pamh, ctx, options);
	krb5_free_context(ctx);

	return retval;
}
