/*
 * Copyright 2003,2005,2006,2007 Red Hat, Inc.
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

#ifndef pam_krb5_v4_h
#define pam_krb5_v4_h

#include "options.h"
#include "prompter.h"
#include "stash.h"
#include "userinfo.h"

#ifndef USE_KRB4
typedef struct ktext_st *KTEXT;
#endif

int v4_get_creds(krb5_context ctx,
		 pam_handle_t *pamh,
		 struct _pam_krb5_stash *stash,
		 struct _pam_krb5_user_info *userinfo,
		 struct _pam_krb5_options *options,
		 char *password,
		 int *result);

int v4_save_for_user(krb5_context ctx,
		     struct _pam_krb5_stash *stash,
		     struct _pam_krb5_user_info *userinfo,
		     struct _pam_krb5_options *options,
		     const char **ccname);
int v4_save_for_tokens(krb5_context ctx,
		       struct _pam_krb5_stash *stash,
		       struct _pam_krb5_user_info *userinfo,
		       struct _pam_krb5_options *options,
		       const char **ccname);
void v4_destroy(krb5_context ctx, struct _pam_krb5_stash *stash,
	        struct _pam_krb5_options *options);
int v4_in_tkt(const char *name, const char *instance, const char *realm);
int v4_save_credentials(const char *sname,
			const char *sinstance,
			const char *srealm,
			unsigned char *session,
			int lifetime,
			int kvno,
			KTEXT ticket,
			int32_t issue_date);

#endif
