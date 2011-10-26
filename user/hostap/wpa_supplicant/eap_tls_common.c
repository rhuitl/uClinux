/*
 * WPA Supplicant / EAP-TLS/PEAP common functions
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
#include "md5.h"
#include "sha1.h"


int eap_tls_passwd_cb(char *buf, int size, int rwflag, void *password)
{
	strncpy(buf, (char *) password, size);
	buf[size - 1] = '\0';
	return strlen(buf);
}


int eap_tls_verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
	char buf[256];
	X509 *err_cert;
	int err, depth;
	SSL *ssl;

	err_cert = X509_STORE_CTX_get_current_cert(x509_ctx);
	err = X509_STORE_CTX_get_error(x509_ctx);
	depth = X509_STORE_CTX_get_error_depth(x509_ctx);
	ssl = X509_STORE_CTX_get_ex_data(x509_ctx,
					 SSL_get_ex_data_X509_STORE_CTX_idx());
	X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

	if (!preverify_ok) {
		wpa_printf(MSG_WARNING, "SSL: Certificate verification failed,"
			   " error %d (%s) depth %d for '%s'", err,
			   X509_verify_cert_error_string(err), depth, buf);
	} else {
		wpa_printf(MSG_DEBUG, "SSL: eap_tls_verify_cb - "
			   "preverify_ok=%d err=%d (%s) depth=%d buf='%s'",
			   preverify_ok, err,
			   X509_verify_cert_error_string(err), depth, buf);
	}

	return preverify_ok;
}


int eap_tls_ssl_init(struct eap_sm *sm, struct eap_ssl_data *data,
		     struct wpa_ssid *config)
{
	int ret = -1, err;
	u8 *ca_cert, *client_cert, *private_key, *private_key_passwd;
	data->phase2 = sm->init_phase2;
	if (config == NULL) {
		ca_cert = NULL;
		client_cert = NULL;
		private_key = NULL;
		private_key_passwd = NULL;
	} else if (data->phase2) {
		ca_cert = config->ca_cert2;
		client_cert = config->client_cert2;
		private_key = config->private_key2;
		private_key_passwd = config->private_key2_passwd;
	} else {
		ca_cert = config->ca_cert;
		client_cert = config->client_cert;
		private_key = config->private_key;
		private_key_passwd = config->private_key_passwd;
	}
	data->ssl = SSL_new(sm->ssl_ctx);
	if (data->ssl == NULL) {
		wpa_printf(MSG_INFO, "SSL: Failed to initialize new SSL "
			   "structure: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		goto done;
	}

	if (ca_cert) {
		if (SSL_CTX_load_verify_locations(sm->ssl_ctx,
						  ca_cert, NULL) != 1) {
			wpa_printf(MSG_WARNING, "SSL: Failed to load root "
				   "certificates: %s",
				   ERR_error_string(ERR_get_error(), NULL));
			goto done;
		} else {
			wpa_printf(MSG_DEBUG, "SSL: Trusted root "
				   "certificate(s) loaded");
		}
		SSL_set_verify(data->ssl, SSL_VERIFY_PEER, eap_tls_verify_cb);
	} else {
		/* No ca_cert configured - do not try to verify server
		 * certificate */
		SSL_set_verify(data->ssl, SSL_VERIFY_NONE, NULL);
	}

	if (client_cert) {
		if (SSL_use_certificate_file(data->ssl, client_cert,
					     SSL_FILETYPE_ASN1) != 1 &&
		    SSL_use_certificate_file(data->ssl, client_cert,
					     SSL_FILETYPE_PEM) != 1) {
			wpa_printf(MSG_INFO, "SSL: Failed to load client "
				   "certificate: %s",
				   ERR_error_string(ERR_get_error(), NULL));
			goto done;
		}
	}

	if (private_key) {
		SSL_CTX_set_default_passwd_cb(sm->ssl_ctx, eap_tls_passwd_cb);
		SSL_CTX_set_default_passwd_cb_userdata(
			sm->ssl_ctx, private_key_passwd);
		if (SSL_use_PrivateKey_file(data->ssl, private_key,
					    SSL_FILETYPE_ASN1) != 1 &&
		    SSL_use_PrivateKey_file(data->ssl, private_key,
					    SSL_FILETYPE_PEM) != 1) {
			wpa_printf(MSG_INFO, "SSL: Failed to load private "
				   "key: %s",
				   ERR_error_string(ERR_get_error(), NULL));
			goto done;
		}
		SSL_CTX_set_default_passwd_cb(sm->ssl_ctx, NULL);

		if (!SSL_check_private_key(data->ssl)) {
			wpa_printf(MSG_INFO, "SSL: Private key failed "
				   "verification: %s",
				   ERR_error_string(ERR_get_error(), NULL));
			goto done;
		}
	}

	SSL_set_options(data->ssl,
			SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
			SSL_OP_SINGLE_DH_USE);

	data->ssl_in = BIO_new(BIO_s_mem());
	if (!data->ssl_in) {
		wpa_printf(MSG_INFO, "SSL: Failed to create a new BIO for "
			   "ssl_in: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		goto done;
	}

	data->ssl_out = BIO_new(BIO_s_mem());
	if (!data->ssl_out) {
		wpa_printf(MSG_INFO, "SSL: Failed to create a new BIO for "
			   "ssl_out: %s",
			   ERR_error_string(ERR_get_error(), NULL));
		goto done;
	}

	SSL_set_bio(data->ssl, data->ssl_in, data->ssl_out);

	/* TODO: make this configurable */
	data->tls_out_limit = 1398;
	if (data->phase2) {
		/* Limit the fragment size in the inner TLS authentication
		 * since the outer authentication with EAP-PEAP does not yet
		 * support fragmentation */
		if (data->tls_out_limit > 100)
			data->tls_out_limit -= 100;
	}
	ret = 0;

done:
	while ((err = ERR_get_error()) != 0) {
		wpa_printf(MSG_DEBUG, "SSL - SSL error: %s",
			   ERR_error_string(err, NULL));
	}
	return ret;
}


static int tls_prf(u8 *secret, size_t secret_len, char *label,
		   u8 *seed, size_t seed_len, u8 *out, size_t outlen)
{
	size_t L_S1, L_S2;
	u8 *S1, *S2;
	u8 A_MD5[MD5_MAC_LEN], A_SHA1[SHA1_MAC_LEN];
	u8 P_MD5[MD5_MAC_LEN], P_SHA1[SHA1_MAC_LEN];
	int i, MD5_pos, SHA1_pos;
	u8 *MD5_addr[3] = { A_MD5, label, seed };
	size_t MD5_len[3] = { MD5_MAC_LEN, strlen(label), seed_len };
	unsigned char *SHA1_addr[3] = { A_SHA1, label, seed };
	unsigned int SHA1_len[3] = { SHA1_MAC_LEN, strlen(label), seed_len };

	if (secret_len & 1) {
		/* This should never happen with EAP-TLS */
		wpa_printf(MSG_DEBUG, "SSL: tls_prf - odd secret_len=%d not "
			   "supported", secret_len);
		return -1;
	}

	/* RFC 2246, Chapter 5
	 * A(0) = seed, A(i) = HMAC(secret, A(i-1))
	 * P_hash = HMAC(secret, A(1) + seed) + HMAC(secret, A(2) + seed) + ..
	 * PRF = P_MD5(S1, label + seed) XOR P_SHA-1(S2, label + seed)
	 */

	L_S1 = L_S2 = (secret_len + 1) / 2;
	S1 = secret;
	S2 = secret + L_S1;

	hmac_md5_vector(S1, L_S1, 2, &MD5_addr[1], &MD5_len[1], A_MD5);
	hmac_sha1_vector(S2, L_S2, 2, &SHA1_addr[1], &SHA1_len[1], A_SHA1);

	MD5_pos = MD5_MAC_LEN;
	SHA1_pos = SHA1_MAC_LEN;
	for (i = 0; i < outlen; i++) {
		if (MD5_pos == MD5_MAC_LEN) {
			hmac_md5_vector(S1, L_S1, 3, MD5_addr, MD5_len, P_MD5);
			MD5_pos = 0;
			hmac_md5(S1, L_S1, A_MD5, MD5_MAC_LEN, A_MD5);
		}
		if (SHA1_pos == SHA1_MAC_LEN) {
			hmac_sha1_vector(S2, L_S2, 3, SHA1_addr, SHA1_len,
					 P_SHA1);
			SHA1_pos = 0;
			hmac_sha1(S2, L_S2, A_SHA1, SHA1_MAC_LEN, A_SHA1);
		}

		out[i] = P_MD5[MD5_pos] ^ P_SHA1[SHA1_pos];

		MD5_pos++;
		SHA1_pos++;
	}

	return 0;
}


u8 * eap_tls_derive_key(SSL *ssl, char *label)
{
	u8 random[2 * SSL3_RANDOM_SIZE];
	u8 *out;

	out = malloc(EAP_TLS_KEY_LEN);
	if (ssl == NULL || ssl->s3 == NULL || ssl->session == NULL ||
	    out == NULL) {
		free(out);
		return NULL;
	}
	memcpy(random, ssl->s3->client_random, SSL3_RANDOM_SIZE);
	memcpy(random + SSL3_RANDOM_SIZE, ssl->s3->server_random,
	       SSL3_RANDOM_SIZE);

	if (tls_prf(ssl->session->master_key,
		    ssl->session->master_key_length,
		    label, random, 2 * SSL3_RANDOM_SIZE,
		    out, EAP_TLS_KEY_LEN)) {
		free(out);
		return NULL;
	}
	return out;
}


int eap_tls_process_helper(struct eap_sm *sm, struct eap_ssl_data *data,
			   int eap_type, int peap_version,
			   u8 id, u8 *in_data, size_t in_len,
			   u8 **out_data, size_t *out_len)
{
	BUF_MEM *buf;
	int res;
	size_t len;
	u8 *pos, *flags;
	struct eap_hdr *resp;

	if (data->tls_out_len == 0) {
		if (in_data) {
			BIO_write(data->ssl_in, in_data, in_len);
			if (data->tls_in_left > in_len) {
				data->tls_in_left -= in_len;
				wpa_printf(MSG_DEBUG, "SSL: Need %d bytes more"
					   " input data", data->tls_in_left);
				return 1;
			} else
				data->tls_in_left = 0;
		}
	}
	res = SSL_connect(data->ssl);
	if (res != 1) {
		int err = SSL_get_error(data->ssl, res);
		if (err == SSL_ERROR_WANT_READ)
			wpa_printf(MSG_DEBUG, "SSL: SSL_connect - want "
				   "more data");
		else if (err == SSL_ERROR_WANT_WRITE)
			wpa_printf(MSG_DEBUG, "SSL: SSL_connect - want to "
				   "write");
		else
			wpa_printf(MSG_INFO, "SSL: SSL_connect: %s",
				   ERR_error_string(ERR_get_error(), NULL));
	}
	BIO_get_mem_ptr(data->ssl_out, &buf);
	data->tls_out = buf->data;
	data->tls_out_len = buf->length;
	if (data->tls_out_len == 0) {
		/* TLS negotiation should now be complete since all other cases
		 * needing more that should have been catched above based on
		 * the TLS Message Length field. */
		wpa_printf(MSG_DEBUG, "SSL: No data to be sent out");
		return 1;
	}

	wpa_printf(MSG_DEBUG, "SSL: %d bytes left to be sent out (of total %d "
		   "bytes)",
		   data->tls_out_len - data->tls_out_pos, data->tls_out_len);
	resp = malloc(sizeof(struct eap_hdr) + 2 + 4 + data->tls_out_limit);
	if (resp == NULL) {
		*out_data = NULL;
		return -1;
	}
	resp->code = EAP_CODE_RESPONSE;
	resp->identifier = id;
	pos = (u8 *) (resp + 1);
	*pos++ = eap_type;
	flags = pos++;
	*flags = peap_version;
	if (data->tls_out_pos == 0 &&
	    data->tls_out_len > data->tls_out_limit) {
		*flags |= EAP_TLS_FLAGS_LENGTH_INCLUDED;
		*pos++ = (data->tls_out_len >> 24) & 0xff;
		*pos++ = (data->tls_out_len >> 16) & 0xff;
		*pos++ = (data->tls_out_len >> 8) & 0xff;
		*pos++ = data->tls_out_len & 0xff;
	}

	len = data->tls_out_len - data->tls_out_pos;
	if (len > data->tls_out_limit) {
		*flags |= EAP_TLS_FLAGS_MORE_FRAGMENTS;
		len = data->tls_out_limit;
		wpa_printf(MSG_DEBUG, "SSL: sending %d bytes, more fragments "
			   "will follow", len);
	}
	memcpy(pos, &data->tls_out[data->tls_out_pos], len);
	data->tls_out_pos += len;
	*out_len = (pos - (u8 *) resp) + len;
	resp->length = htons(*out_len);
	*out_data = (u8 *) resp;

	if (!(*flags & EAP_TLS_FLAGS_MORE_FRAGMENTS)) {
		data->tls_out_len = 0;
		data->tls_out_pos = 0;
		BIO_reset(data->ssl_out);
	}

	return 0;
}


u8 * eap_tls_build_ack(size_t *respDataLen, u8 id, int eap_type,
		       int peap_version)
{
	struct eap_hdr *resp;
	u8 *pos;

	*respDataLen = sizeof(struct eap_hdr) + 2;
	resp = malloc(*respDataLen);
	if (resp == NULL)
		return NULL;
	wpa_printf(MSG_DEBUG, "SSL: Building ACK");
	resp->code = EAP_CODE_RESPONSE;
	resp->identifier = id;
	resp->length = htons(*respDataLen);
	pos = (u8 *) (resp + 1);
	*pos++ = eap_type; /* Type */
	*pos = peap_version; /* Flags */
	return (u8 *) resp;
}
