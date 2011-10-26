/*
 * Copyright 2003,2005,2006,2008,2009 Red Hat, Inc.
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

#ifndef pam_krb5_options_h
#define pam_krb5_options_h

struct _pam_krb5_options {
	int debug;
	int save_cred;
	int addressless;
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_CANONICALIZE
	int canonicalize;
#endif
	int debug_sensitive;
	int external;
	int existing_ticket;
	int forwardable;
	int ignore_afs;
	int ignore_unknown_principals;
	int null_afs_first;
	int permit_password_callback;
	int proxiable;
	int renewable;
	int tokens;
	int user_check;
	int use_authtok;
	int use_first_pass;
	int use_second_pass;
	int use_third_pass;
	int use_shmem;
	int validate;
	int v4;
	int v4_for_afs;
	int v4_use_524;
	int v4_use_as_req;
	int warn;

	krb5_deltat ticket_lifetime;
	krb5_deltat renew_lifetime;

	uid_t minimum_uid;

	char *banner;
	char *ccache_dir;
	char *ccname_template;
	char *keytab;
	char *pwhelp;
	char *realm;
	char *token_strategy;
	char **hosts;

#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_PKINIT
	char *pkinit_identity;
	int pkinit_flags;
#endif
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_PA
	char **preauth_options;
#endif

	struct afs_cell {
		char *cell, *principal_name;
	} *afs_cells;
	int n_afs_cells;

	char *mappings_s;
	struct name_mapping {
		char *pattern, *replacement;
	} *mappings;
	int n_mappings;
};

struct _pam_krb5_options *_pam_krb5_options_init(pam_handle_t *pamh,
						 int argc,
						 PAM_KRB5_MAYBE_CONST char **argv,
						 krb5_context ctx);
void _pam_krb5_options_free(pam_handle_t *pamh,
			    krb5_context ctx,
			    struct _pam_krb5_options *options);

#endif
