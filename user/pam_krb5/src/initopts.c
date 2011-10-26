/*
 * Copyright 2003,2004,2005,2006,2009 Red Hat, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif

#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#include KRB5_H
#include "initopts.h"
#include "log.h"
#include "options.h"

#if defined(HAVE_KRB5_OS_LOCALADDR) && \
    defined(HAVE_KRB5_OS_HOSTADDR) && \
    defined(HAVE_KRB5_COPY_ADDR)
static void
_pam_krb5_set_default_address_list(krb5_context ctx,
				   krb5_get_init_creds_opt *k5_options,
				   struct _pam_krb5_options *options)
{
	krb5_address **addresses;
	if (krb5_os_localaddr(ctx, &addresses) == 0) {
		krb5_get_init_creds_opt_set_address_list(k5_options, addresses);
		/* the options structure "adopts" the address array */
	}
}
static void
_pam_krb5_set_empty_address_list(krb5_context ctx,
				 krb5_get_init_creds_opt *k5_options)
{
	krb5_get_init_creds_opt_set_address_list(k5_options, NULL);
}
static void
_pam_krb5_set_extra_address_list(krb5_context ctx,
				 krb5_get_init_creds_opt *k5_options,
				 struct _pam_krb5_options *options)
{
	int n_hosts, total, i, j, k;
	krb5_address ***hosts, **locals, **complete;

	n_hosts = 0;
	for (i = 0;
	     (options->hosts != NULL) && (options->hosts[i] != NULL);
	     i++) {
		n_hosts++;
	}

	hosts = malloc(n_hosts * sizeof(krb5_address **));
	if (hosts == NULL) {
		warn("not enough memory to set up extra hosts list");
		return;
	}
	memset(hosts, 0, n_hosts * sizeof(krb5_address **));

	total = 0;
	for (i = 0; i < n_hosts; i++) {
		if (krb5_os_hostaddr(ctx, options->hosts[i], &hosts[i]) != 0) {
			hosts[i] = NULL;
			warn("error resolving host \"%s\"", options->hosts[i]);
		}
		for (j = 0; (hosts[i] != NULL) && (hosts[i][j] != NULL); j++) {
			total++;
		}
	}

	locals = NULL;
	if (krb5_os_localaddr(ctx, &locals) != 0) {
		warn("error retrieving local address list");
		for (i = 0; i < n_hosts; i++) {
			if (hosts[i] != NULL) {
				krb5_free_addresses(ctx, hosts[i]);
			}
		}
		free(hosts);
		return;
	}

	for (i = 0; (locals != NULL) && (locals[i] != NULL); i++) {
		total++;
	}

	complete = malloc((total + 1) * sizeof(krb5_address *));
	if (complete == NULL) {
		warn("not enough memory to set up extra hosts list");
		return;
	}
	memset(complete, 0, (total + 1) * sizeof(krb5_address *));

	k = 0;
	for (i = 0; (locals != NULL) && (locals[i] != NULL); i++) {
		krb5_copy_addr(ctx, locals[i], &complete[k++]);
	}
	for (i = 0; i < n_hosts; i++) {
		for (j = 0; (hosts[i] != NULL) && (hosts[i][j] != NULL); j++) {
			krb5_copy_addr(ctx, hosts[i][j], &complete[k++]);
		}
	}

	krb5_get_init_creds_opt_set_address_list(k5_options, complete);

	for (i = 0; i < n_hosts; i++) {
		if (hosts[i] != NULL) {
			krb5_free_addresses(ctx, hosts[i]);
		}
	}
	free(hosts);
}
#elif defined(HAVE_KRB5_GET_ALL_CLIENT_ADDRS)
static void
_pam_krb5_set_default_address_list(krb5_context ctx,
				   krb5_get_init_creds_opt *k5_options,
				   struct _pam_krb5_options *options)
{
	krb5_addresses addresses, *tmp;
	if (krb5_get_all_client_addrs(ctx, &addresses) == 0) {
		tmp = malloc(sizeof(krb5_addresses));
		if (tmp != NULL) {
			*tmp = addresses;
			krb5_get_init_creds_opt_set_address_list(k5_options,
								 tmp);
			/* the options structure "adopts" the address list */
		}
	}
}
static void
_pam_krb5_set_empty_address_list(krb5_context ctx,
				 krb5_get_init_creds_opt *k5_options)
{
	krb5_addresses *tmp;
	tmp = malloc(sizeof(krb5_addresses));
	if (tmp == NULL) {
		warn("not enough memory to set up extra hosts list");
		return;
	}
	memset(tmp, 0, sizeof(krb5_addresses));
	tmp->len = 0;
	tmp->val = NULL;
	krb5_get_init_creds_opt_set_address_list(k5_options, tmp);
}
static void
_pam_krb5_set_extra_address_list(krb5_context ctx,
				 krb5_get_init_creds_opt *k5_options,
				 struct _pam_krb5_options *options)
{
	int i;
	krb5_addresses addresses, *list;

	list = malloc(sizeof(krb5_addresses));
	if (list == NULL) {
		warn("out of memory setting extra address list");
		return;
	}
	memset(list, 0, sizeof(krb5_addresses));
	list->len = 0;
	list->val = NULL;

	if (krb5_get_all_client_addrs(ctx, &addresses) == 0) {
		krb5_append_addresses(ctx, list, &addresses);
		krb5_free_addresses(ctx, &addresses);
	}
	for (i = 0;
	     (options->hosts != NULL) && (options->hosts[i] != NULL);
	     i++) {
		if (krb5_parse_address(ctx, options->hosts[i],
				       &addresses) == 0) {
			krb5_append_addresses(ctx, list, &addresses);
			krb5_free_addresses(ctx, &addresses);
		} else {
			warn("error resolving host \"%s\"", options->hosts[i]);
		}
	}

	krb5_get_init_creds_opt_set_address_list(k5_options, list);
}
#else
static void
_pam_krb5_set_default_address_list(krb5_context ctx,
				   krb5_get_init_creds_opt *k5_options,
				   struct _pam_krb5_options *options)
{
#ifdef HAVE_KRB5_OS_LOCALADDR
	krb5_address **addresses;
	if (krb5_os_localaddr(ctx, &addresses) == 0) {
		krb5_get_init_creds_opt_set_address_list(k5_options, addresses);
		/* the options structure "adopts" the address array */
	}
#endif
}
static void
_pam_krb5_set_empty_address_list(krb5_context ctx,
				 krb5_get_init_creds_opt *k5_options)
{
	/* this *may* work */
	krb5_get_init_creds_opt_set_address_list(k5_options, NULL);
}
static void
_pam_krb5_set_extra_address_list(krb5_context ctx,
				 krb5_get_init_creds_opt *k5_options,
				 struct _pam_krb5_options *options)
{
	warn("The \"hosts\" configuration directive is not supported "
	     "with your release of Kerberos.  Please check if your "
	     "release supports an `extra_addresses' directive instead.");
}
#endif

void
_pam_krb5_set_init_opts(krb5_context ctx, krb5_get_init_creds_opt *k5_options,
			struct _pam_krb5_options *options)
{
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_CHANGE_PASSWORD_PROMPT
	/* We want to handle password expiration ourselves, if we can. */
	krb5_get_init_creds_opt_set_change_password_prompt(k5_options, 0);
#endif
	/* Only enable or disable these flags if we were told one way or
	 * another, to avoid stepping on library-wide configuration. */
	if (options->forwardable != -1) {
		krb5_get_init_creds_opt_set_forwardable(k5_options,
							options->forwardable);
	}
	if (options->proxiable != -1) {
		krb5_get_init_creds_opt_set_proxiable(k5_options,
						      options->proxiable);
	}
	if ((options->ticket_lifetime != -1) &&
	    (options->ticket_lifetime > 0)) {
		krb5_get_init_creds_opt_set_tkt_life(k5_options,
						     options->ticket_lifetime);
	}
	if ((options->renewable != -1) &&
	    (options->renew_lifetime != -1) &&
	    (options->renew_lifetime > 0)) {
		krb5_get_init_creds_opt_set_renew_life(k5_options,
						       options->renewable ?
						       options->renew_lifetime :
						       0);
	}
	if (options->addressless == 1) {
		krb5_get_init_creds_opt_set_address_list(k5_options, NULL);
		_pam_krb5_set_empty_address_list(ctx, k5_options);
	}
	if (options->addressless == 0) {
		_pam_krb5_set_default_address_list(ctx, k5_options, options);
		if ((options->hosts != NULL) &&
		    (options->hosts[0] != NULL)) {
			_pam_krb5_set_extra_address_list(ctx, k5_options,
							 options);
		}
	}
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_CANONICALIZE
	if (options->canonicalize != -1) {
#ifdef KRB5_GET_INIT_CREDS_OPT_SET_CANONICALIZE_TAKES_3_ARGS
		krb5_get_init_creds_opt_set_canonicalize(ctx,
							 k5_options,
							 options->canonicalize);
#else
		krb5_get_init_creds_opt_set_canonicalize(k5_options,
							 options->canonicalize);
#endif
	}
#endif
}

void
_pam_krb5_set_init_opts_for_pwchange(krb5_context ctx,
				     krb5_get_init_creds_opt *k5_options,
				     struct _pam_krb5_options *options)
{
	krb5_get_init_creds_opt_set_tkt_life(k5_options, 5 * 60);
	krb5_get_init_creds_opt_set_renew_life(k5_options, 0);
	krb5_get_init_creds_opt_set_forwardable(k5_options, 0);
	krb5_get_init_creds_opt_set_proxiable(k5_options, 0);
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_CANONICALIZE
	if (options->canonicalize != -1) {
#ifdef KRB5_GET_INIT_CREDS_OPT_SET_CANONICALIZE_TAKES_3_ARGS
		krb5_get_init_creds_opt_set_canonicalize(ctx,
							 k5_options,
							 options->canonicalize);
#else
		krb5_get_init_creds_opt_set_canonicalize(k5_options,
							 options->canonicalize);
#endif
	}
#endif
}
