/* mechanisms for preshared keys (public, private, and preshared secrets)
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * RCSID $Id: preshared.h,v 1.22 2002/03/22 04:13:53 dhr Exp $
 */

#include <gmp.h>    /* GNU MP library */

#ifndef SHARED_SECRETS_FILE
# define SHARED_SECRETS_FILE  "/etc/ipsec.secrets"
#endif

extern const char *shared_secrets_file;

extern void load_preshared_secrets(void);
extern void free_preshared_secrets(void);

struct state;	/* forward declaration */

enum PrivateKeyKind {
    PPK_PSK,
    /* PPK_DSS, */	/* not implemented */
    PPK_RSA
};

extern const chunk_t *get_preshared_secret(struct connection *c);

struct RSA_public_key
{
    char keyid[KEYID_BUF];	/* see ipsec_keyblobtoid(3) */

    /* length of modulus n in octets: [RSA_MIN_OCTETS, RSA_MAX_OCTETS] */
    unsigned k;

    /* public: */
    MP_INT
	n,	/* modulus: p * q */
	e;	/* exponent: relatively prime to (p-1) * (q-1) [probably small] */
};

struct RSA_private_key {
    struct RSA_public_key pub;	/* must be at start for RSA_show_public_key */

    MP_INT
	d,	/* private exponent: (e^-1) mod ((p-1) * (q-1)) */
	/* help for Chinese Remainder Theorem speedup: */
	p,	/* first secret prime */
	q,	/* second secret prime */
	dP,	/* first factor's exponent: (e^-1) mod (p-1) == d mod (p-1) */
	dQ,	/* second factor's exponent: (e^-1) mod (q-1) == d mod (q-1) */
	qInv;	/* (q^-1) mod p */
};

extern void free_RSA_public_content(struct RSA_public_key *rsa);

extern err_t unpack_RSA_public_key(struct RSA_public_key *rsa, chunk_t *pubkey);

extern const struct RSA_private_key *get_RSA_private_key(struct connection *c);

/* public key machinery  */

struct pubkeyrec {
    struct id id;
    time_t installed;
    time_t until;
    enum dns_auth_level dns_auth_level;
    enum pubkey_alg alg;
    union {
	struct RSA_public_key rsa;
    } u;
    struct pubkeyrec *next;
};

extern struct pubkeyrec *pubkeys;	/* keys from ipsec.conf */

extern struct pubkeyrec *public_key_from_rsa(const struct RSA_public_key *k);
extern struct pubkeyrec *free_public_key(struct pubkeyrec *p);
extern void free_public_keys(struct pubkeyrec **keys);
extern void free_remembered_public_keys(void);
extern void delete_public_keys(const struct id *id, enum pubkey_alg alg);

extern err_t add_public_key(const struct id *id
    , enum dns_auth_level dns_auth_level
    , enum pubkey_alg alg
    , chunk_t *key
    , struct pubkeyrec **head);

extern void add_x509_public_key(const x509cert_t *cert
    , enum dns_auth_level dns_auth_level);

extern void remove_x509_public_key(const x509cert_t *cert);
extern void remember_public_keys(struct pubkeyrec **keys);
extern void list_public_keys(bool utc);

extern bool same_RSA_public_key(const struct RSA_public_key *a
    , const struct RSA_public_key *b);
