#ifndef EAP_TLS_COMMON_H
#define EAP_TLS_COMMON_H

struct eap_ssl_data {
	SSL *ssl;
	BIO *ssl_in, *ssl_out;

	u8 *tls_out;
	size_t tls_out_len;
	size_t tls_out_pos;
	size_t tls_out_limit;
	size_t tls_in_left;
	size_t tls_in_total;

	int phase2;
};


/* EAP TLS Flags */
#define EAP_TLS_FLAGS_LENGTH_INCLUDED 0x80
#define EAP_TLS_FLAGS_MORE_FRAGMENTS 0x40
#define EAP_TLS_FLAGS_START 0x20
#define EAP_PEAP_VERSION_MASK 0x07

 /* could be up to 128 bytes, but only the first 64 bytes are used */
#define EAP_TLS_KEY_LEN 64


int eap_tls_passwd_cb(char *buf, int size, int rwflag, void *password);
int eap_tls_verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx);
int eap_tls_ssl_init(struct eap_sm *sm, struct eap_ssl_data *data,
		     struct wpa_ssid *config);
u8 * eap_tls_derive_key(SSL *ssl, char *label);
int eap_tls_process_helper(struct eap_sm *sm, struct eap_ssl_data *data,
			   int eap_type, int peap_version,
			   u8 id, u8 *in_data, size_t in_len,
			   u8 **out_data, size_t *out_len);
u8 * eap_tls_build_ack(size_t *respDataLen, u8 id, int eap_type,
		       int peap_version);



#endif /* EAP_TLS_COMMON_H */
