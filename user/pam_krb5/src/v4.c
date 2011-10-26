/*
 * Copyright 2003,2004,2005,2006,2007 Red Hat, Inc.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <limits.h>
#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
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

#include "log.h"
#include "prompter.h"
#include "stash.h"
#include "userinfo.h"
#include "v4.h"
#include "v5.h"
#include "xstr.h"

#ifdef USE_KRB4

int
v4_in_tkt(const char *name, const char *instance, const char *realm)
{
	int i;
	char *vname, *vinstance, *vrealm;

	vname = xstrdup(name);
	if (vname == NULL) {
		return KRB5KRB_ERR_GENERIC;
	}
	vinstance = xstrdup(instance);
	if (vinstance == NULL) {
		xstrfree(vname);
		return KRB5KRB_ERR_GENERIC;
	}
	vrealm = xstrdup(realm);
	if (vrealm == NULL) {
		xstrfree(vinstance);
		xstrfree(vname);
		return KRB5KRB_ERR_GENERIC;
	}

#ifdef HAVE_KRB_IN_TKT
	i = krb_in_tkt(vname, vinstance, vrealm);
#elif defined(HAVE_IN_TKT)
	i = in_tkt(vname, vinstance);
#else
#error "Don't know how to initialize v4 TGT for your Kerberos IV implementation!"
#endif
	xstrfree(vrealm);
	xstrfree(vinstance);
	xstrfree(vname);

	return i;
}

int
v4_save_credentials(const char *sname,
		    const char *sinstance,
		    const char *srealm,
		    unsigned char *session,
		    int lifetime,
		    int kvno,
		    KTEXT ticket,
		    int32_t issue_date)
{
	int i;
	char *vname, *vinstance, *vrealm;

	vname = xstrdup(sname);
	if (vname == NULL) {
		return KRB5KRB_ERR_GENERIC;
	}
	vinstance = xstrdup(sinstance);
	if (vinstance == NULL) {
		xstrfree(vname);
		return KRB5KRB_ERR_GENERIC;
	}
	vrealm = xstrdup(srealm);
	if (vrealm == NULL) {
		xstrfree(vinstance);
		xstrfree(vname);
		return KRB5KRB_ERR_GENERIC;
	}

#ifdef HAVE_KRB_SAVE_CREDENTIALS
	i = krb_save_credentials(vname, vinstance, vrealm,
				 session, lifetime, kvno,
				 ticket, issue_date);
#elif defined(HAVE_SAVE_CREDENTIALS)
	i = save_credentials(vname, vinstance, vrealm,
			     session, lifetime, kvno,
			     ticket, issue_date);
#else
#error "Don't know how to save v4 credentials for your Kerberos IV implementation!"
#endif
	xstrfree(vrealm);
	xstrfree(vinstance);
	xstrfree(vname);

	return i;
}

static int
_pam_krb5_v4_init(krb5_context ctx,
		  struct _pam_krb5_stash *stash,
		  struct _pam_krb5_user_info *user,
		  struct _pam_krb5_options *options,
		  char *sname, char *sinstance,
		  char *password,
		  int *result) 
{
	char name[ANAME_SZ + 1], instance[INST_SZ + 1], realm[REALM_SZ + 1];
	char pname[ANAME_SZ + 1], pinstance[INST_SZ + 1];
	char tktfile[PATH_MAX];
	char *saved_tktstring;
	int life, i, fd;
	struct stat st;

	/* Convert the krb5 version of the principal's name to a v4 principal
	 * name.  This may involve changing "host" to "rcmd" and so on, so let
	 * libkrb5 handle it. */
	memset(name, '\0', sizeof(name));
	memset(instance, '\0', sizeof(instance));
	memset(realm, '\0', sizeof(realm));
	i = krb5_524_conv_principal(ctx, user->principal_name,
				    name, instance, realm);
	if (i != 0) {
		if (result) {
			*result = i;
		}
		return PAM_SERVICE_ERR;
	}
	if (options->debug) {
		debug("converted principal to '%s%s%s%s@'%s'", name,
		      strlen(instance) ? "'.'" : "'", instance,
		      strlen(instance) ? "'" : "", realm);
	}

#ifdef HAVE_KRB_TIME_TO_LIFE
	/* Convert the ticket lifetime of the v5 credentials into a v4
	 * lifetime, which is the X coordinate along a curve where Y is the
	 * actual length.  Again, this is magic. */
	life = krb_time_to_life(stash->v5creds.times.starttime,
				stash->v5creds.times.endtime); 
#else
	/* No life_to_time() function means that we have to estimate the
	 * intended lifetime, in 5-minute increments.  We also have a maximum
	 * value to contend with, because the lifetime is expressed in a single
	 * byte. */
	life = stash->v5creds.times.endtime -
	       stash->v5creds.times.starttime;
	life /= (60 * 5);
	if (life > 0xff) {
		life = 0xff;
	}
#endif

	/* Create the ticket file.  One of two things will happen here.  Either
	 * libkrb[4] will just use the file, and we're safer because it
	 * wouldn't have used O_EXCL to do so, or it will nuke the file and
	 * reopen it with O_EXCL.  In the latter case, the descriptor we have
	 * will become useless, so we don't actually use it for anything. */
#ifdef HAVE_LONG_LONG
	snprintf(tktfile, sizeof(tktfile), "%s/tkt%llu_XXXXXX",
		 options->ccache_dir,
		 options->user_check ?
		 (unsigned long long) user->uid :
		 (unsigned long long) getuid());
#else
	snprintf(tktfile, sizeof(tktfile), "%s/tkt%lu_XXXXXX",
		 options->ccache_dir,
		 options->user_check ?
		 (unsigned long) user->uid :
		 (unsigned long) getuid());
#endif
	fd = mkstemp(tktfile);
	if (fd == -1) {
		if (result) {
			*result = errno;
		}
		return PAM_SERVICE_ERR;
	}
	if (fchown(fd, getuid(), getgid()) != 0) {
		warn("error setting permissions on \"%s\" (%s), attempting "
		     "to continue", tktfile, strerror(errno));
	}
	if (options->debug) {
		debug("preparing to place v4 credentials in '%s'", tktfile);
	}
	/* Save the old default ticket file name, and set the default to use
	 * our just-created empty file. */
	saved_tktstring = xstrdup(tkt_string());
	krb_set_tkt_string(tktfile);
	/* Get the initial credentials. */
	i = krb_get_pw_in_tkt(name, instance, realm,
			      sname, sinstance ? sinstance : realm,
			      life, password);
	if (result) {
		*result = i;
	}
	/* Restore the original default ticket file name. */
	krb_set_tkt_string(saved_tktstring);
	xstrfree(saved_tktstring);
	saved_tktstring = NULL;
	/* If we got credentials, read them from the file, and then remove the
	 * file. */
	if (i == 0) {
		i = tf_init(tktfile, R_TKT_FIL);
		if (i == 0) {
			i = tf_get_pname(pname);
			if (i == 0) {
				i = tf_get_pinst(pinstance);
				if (i == 0) {
					i = tf_get_cred(&stash->v4creds);
					if (i == 0) {
						tf_close();
						unlink(tktfile);
						close(fd);
						return PAM_SUCCESS;
					} else {
						warn("error reading creds "
						     "from '%s': %d (%s)",
						     tktfile,
						     i, v5_error_message(i));
					}
				} else {
					warn("error reading instance from '%s'"
					     ": %d (%s)",
					     tktfile, i, v5_error_message(i));
				}
			} else {
				warn("error reading principal name from '%s'"
				     ": %d (%s)",
				     tktfile, i, v5_error_message(i));
			}
			tf_close();
		} else {
			const char *tferror;
			switch (i) {
			case NO_TKT_FIL:
				tferror = "no ticket file";
				break;
			case TKT_FIL_ACC:
				tferror = "ticket file had wrong permissions";
				break;
			case TKT_FIL_LCK:
				tferror = "error locking ticket file";
				break;
			default:
				tferror = strerror(errno);
				break;
			}
			warn("error opening '%s' for reading: %s",
			     tktfile, tferror);
			if ((i == TKT_FIL_ACC) && (options->debug)) {
				if (stat(tktfile, &st) == 0) {
					debug("file owner is %lu:%lu, "
					      "we are effective %lu:%lu, "
					      "real %lu:%lu",
					      (unsigned long) st.st_uid,
					      (unsigned long) st.st_gid,
					      (unsigned long) geteuid(),
					      (unsigned long) getegid(),
					      (unsigned long) getuid(),
					      (unsigned long) getgid());
				}
			}
		}
	}
	unlink(tktfile);
	close(fd);
	return PAM_AUTH_ERR;
}

static int
v4_save(krb5_context ctx,
	struct _pam_krb5_stash *stash,
	struct _pam_krb5_user_info *userinfo,
	struct _pam_krb5_options *options,
	uid_t uid, gid_t gid,
	const char **ccname,
	int clone_cc)
{
	char name[ANAME_SZ + 1], instance[INST_SZ + 1], realm[REALM_SZ + 1];
	char tktfile[PATH_MAX];
	char *saved_tktstring;
	int i, fd;
	struct stat st;

	if (ccname != NULL) {
		*ccname = NULL;
	}

	/* Convert the v5 principal name into v4 notation. */
	memset(name, '\0', sizeof(name));
	memset(instance, '\0', sizeof(instance));
	memset(realm, '\0', sizeof(realm));
	if (stash->v5creds.client != NULL) {
		/* Use the client principal of the creds we have, which we
		 * can assume are always correct, even if "external" somehow
		 * got us to the point where the principal name in "userinfo"
		 * is incorrect. */
		i = krb5_524_conv_principal(ctx, stash->v5creds.client,
					    name, instance, realm);
	} else {
		/* Use the parsed principal as a fallback.  We should never
		 * really get here, but just in case. */
		i = krb5_524_conv_principal(ctx, userinfo->principal_name,
					    name, instance, realm);
	}
	if (i != 0) {
		warn("error converting %s to a Kerberos IV principal "
		     "(shouldn't happen)", userinfo->unparsed_name);
		return PAM_SERVICE_ERR;
	}

	/* Create a new ticket file. */
#ifdef HAVE_LONG_LONG
	snprintf(tktfile, sizeof(tktfile), "%s/tkt%llu_XXXXXX",
		 options->ccache_dir,
		 options->user_check ?
		 (unsigned long long) userinfo->uid :
		 (unsigned long long) getuid());
#else
	snprintf(tktfile, sizeof(tktfile), "%s/tkt%lu_XXXXXX",
		 options->ccache_dir,
		 options->user_check ?
		 (unsigned long) userinfo->uid :
		 (unsigned long) getuid());
#endif
	fd = mkstemp(tktfile);
	if (fd == -1) {
		warn("error creating unique Kerberos IV ticket file "
		     "(shouldn't happen)");
		return PAM_SERVICE_ERR;
	}
	if (fchown(fd, getuid(), getgid()) != 0) {
		warn("error setting permissions on \"%s\" (%s), attempting "
		     "to continue", tktfile, strerror(errno));
	}
	if (options->debug) {
		debug("saving v4 tickets to '%s'", tktfile);
	}

	/* Open the ticket file. */
	saved_tktstring = xstrdup(tkt_string());
	krb_set_tkt_string(tktfile);
	i = tf_init(tktfile, W_TKT_FIL);
	if (i != 0) {
		const char *tferror;
		switch (i) {
		case NO_TKT_FIL:
			tferror = "no ticket file";
			break;
		case TKT_FIL_ACC:
			tferror = "ticket file had wrong permissions";
			break;
		case TKT_FIL_LCK:
			tferror = "error locking ticket file";
			break;
		default:
			tferror = strerror(errno);
			break;
		}
		warn("error opening ticket file '%s': %s",
		     tktfile, tferror);
		if ((i == TKT_FIL_ACC) && (options->debug)) {
			if (stat(tktfile, &st) == 0) {
				debug("file owner is %lu:%lu, "
				      "we are effective %lu:%lu, "
				      "real %lu:%lu",
				      (unsigned long) st.st_uid,
				      (unsigned long) st.st_gid,
				      (unsigned long) geteuid(),
				      (unsigned long) getegid(),
				      (unsigned long) getuid(),
				      (unsigned long) getgid());
			}
		}
		krb_set_tkt_string(saved_tktstring);
		xstrfree(saved_tktstring);
		unlink(tktfile);
		close(fd);
		return PAM_SERVICE_ERR;
	}

	/* Store the user's name. */
	if (v4_in_tkt(name, instance, realm) != 0) {
		warn("error initializing ticket file '%s'", tktfile);
		tf_close();
		krb_set_tkt_string(saved_tktstring);
		xstrfree(saved_tktstring);
		unlink(tktfile);
		close(fd);
		return PAM_SERVICE_ERR;
	}

	/* Store the v4 credentials. */
	if (v4_save_credentials(KRB5_TGS_NAME, realm, realm,
				stash->v4creds.session,
				stash->v4creds.lifetime,
				stash->v4creds.kvno,
				&stash->v4creds.ticket_st,
				stash->v4creds.issue_date) != 0) {
		warn("error saving tickets to '%s'", tktfile);
		tf_close();
		krb_set_tkt_string(saved_tktstring);
		xstrfree(saved_tktstring);
		unlink(tktfile);
		close(fd);
		return PAM_SERVICE_ERR;
	}

	/* Close the new file. */
	tf_close();
	xstrfree(saved_tktstring);
	close(fd);

	/* Save the new file's name in the stash, and optionally return it to
	 * the caller. */
	if (_pam_krb5_stash_push_v4(ctx, stash, tktfile) == 0) {
		/* Generate a *new* ticket file with the same contents as this
		 * one. */
		if (clone_cc) {
			_pam_krb5_stash_clone_v4(stash, uid, gid);
		}
		krb_set_tkt_string(stash->v4tktfiles->name);
		if (ccname != NULL) {
			*ccname = stash->v4tktfiles->name;
		}
	}

	return PAM_SUCCESS;
}

int
v4_save_for_user(krb5_context ctx,
		 struct _pam_krb5_stash *stash,
		 struct _pam_krb5_user_info *userinfo,
		 struct _pam_krb5_options *options,
		 const char **ccname)
{
	return v4_save(ctx, stash, userinfo, options,
		       options->user_check ? userinfo->uid : getuid(),
		       options->user_check ? userinfo->gid : getgid(),
		       ccname, 1);
}

int
v4_save_for_tokens(krb5_context ctx,
		   struct _pam_krb5_stash *stash,
		   struct _pam_krb5_user_info *userinfo,
		   struct _pam_krb5_options *options,
		   const char **ccname)
{
	return v4_save(ctx, stash, userinfo, options, -1, -1, ccname, 0);
}

void
v4_destroy(krb5_context ctx, struct _pam_krb5_stash *stash,
	   struct _pam_krb5_options *options)
{
	if (stash->v4tktfiles != NULL) {
		if (options->debug) {
			debug("removing ticket file '%s'",
			      stash->v4tktfiles->name);
		}
		if (_pam_krb5_stash_pop_v4(ctx, stash) != 0) {
			warn("error removing ticket file '%s'",
			     stash->v4tktfiles->name);
		}
	}
}

int
v4_get_creds(krb5_context ctx,
	     pam_handle_t *pamh,
	     struct _pam_krb5_stash *stash,
	     struct _pam_krb5_user_info *userinfo,
	     struct _pam_krb5_options *options,
	     char *password,
	     int *result)
{
	int i;
#if defined(HAVE_KRB5_524_CONVERT_CREDS) || \
    defined(HAVE_KRB524_CONVERT_CREDS_KDC)
	krb5_creds *v4_compat_creds, *in_creds;

	v4_compat_creds = NULL;

	if (options->v4_use_524) {
		if (options->debug) {
			debug("obtaining v4-compatible key");
		}
		/* We need a DES-CBC-CRC v5 credential to convert to a proper v4
		 * credential. */
		i = v5_get_creds_etype(ctx, userinfo, options, &stash->v5creds,
				       ENCTYPE_DES_CBC_CRC, &v4_compat_creds);
		if (i == 0) {
			if (options->debug) {
				debug("obtained des-cbc-crc v5 creds");
			}
			in_creds = v4_compat_creds;
		} else {
			if (options->debug) {
				debug("failed to obtain des-cbc-crc v5 creds: "
				      "%d (%s)", i, v5_error_message(i));
			}
			in_creds = NULL;
			if (v5_creds_check_initialized(ctx,
						       &stash->v5creds) == 0) {
				krb5_copy_creds(ctx, &stash->v5creds,
						&in_creds);
			}
		}
#ifdef HAVE_KRB5_524_CONVERT_CREDS
		if (options->debug) {
			debug("converting v5 creds to v4 creds (etype = %d)",
			      in_creds ? v5_creds_get_etype(in_creds) : 0);
		}
		if ((in_creds != NULL) &&
		    (v5_creds_check_initialized(ctx, in_creds) == 0)) {
			i = krb5_524_convert_creds(ctx, in_creds,
						   &stash->v4creds);
			if (i == 0) {
				if (options->debug) {
					debug("conversion succeeded");
				}
				stash->v4present = 1;
				if (result) {
					*result = i;
				}
				krb5_free_creds(ctx, in_creds);
				return PAM_SUCCESS;
			} else {
				if (options->debug) {
					debug("conversion failed: %d (%s)",
					      i, v5_error_message(i));
				}
			}
		}
#else
#ifdef HAVE_KRB524_CONVERT_CREDS_KDC
		if (options->debug) {
			debug("converting v5 creds to v4 creds (etype = %d)",
			      in_creds ? v5_creds_get_etype(in_creds) : 0);
		}
		if ((in_creds != NULL) &&
		    (v5_creds_check_initialized(ctx, in_creds) == 0)) {
			i = krb524_convert_creds_kdc(ctx, in_creds,
						     &stash->v4creds);
			if (i == 0) {
				if (options->debug) {
					debug("conversion succeeded");
				}
				stash->v4present = 1;
				if (result) {
					*result = i;
				}
				krb5_free_creds(ctx, in_creds);
				return PAM_SUCCESS;
			} else {
				if (options->debug) {
					debug("conversion failed: %d (%s)",
					      i, v5_error_message(i));
				}
			}
		}
#endif
#endif
		if ((in_creds != NULL) &&
		    (v5_creds_check_initialized(ctx, in_creds) == 0)) {
			krb5_free_creds(ctx, in_creds);
		}
	}
#endif
	if ((password != NULL) && (options->v4_use_as_req)) {
		if (options->debug) {
			debug("attempting to obtain initial v4 creds");
		}
		i = _pam_krb5_v4_init(ctx, stash, userinfo, options,
				      KRB5_TGS_NAME, NULL, password, result);
		if (i == PAM_SUCCESS) {
			if (options->debug) {
				debug("initial v4 creds obtained");
			}
			stash->v4present = 1;
			return PAM_SUCCESS;
		}
		if (options->debug) {
			debug("could not obtain initial v4 creds: %d (%s)",
			      i, v5_error_message(i));
		}
	}
	return PAM_AUTH_ERR;
}

#else

int
v4_get_creds(krb5_context ctx,
	     pam_handle_t *pamh,
	     struct _pam_krb5_stash *stash,
	     struct _pam_krb5_user_info *userinfo,
	     struct _pam_krb5_options *options,
	     char *password,
	     int *result)
{
	return -1;
}

int
v4_save_for_user(krb5_context ctx,
		 struct _pam_krb5_stash *stash,
		 struct _pam_krb5_user_info *userinfo,
		 struct _pam_krb5_options *options,
		 const char **ccname)
{
	if (ccname != NULL) {
		*ccname = NULL;
	}
	return PAM_SERVICE_ERR;
}

int
v4_save_for_tokens(krb5_context ctx,
		   struct _pam_krb5_stash *stash,
		   struct _pam_krb5_user_info *userinfo,
		   struct _pam_krb5_options *options,
		   const char **ccname)
{
	if (ccname != NULL) {
		*ccname = NULL;
	}
	return PAM_SERVICE_ERR;
}
void
v4_destroy(krb5_context ctx, struct _pam_krb5_stash *stash,
	   struct _pam_krb5_options *options)
{
	return;
}

#endif
