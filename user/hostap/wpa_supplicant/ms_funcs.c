/*
 * WPA Supplicant / shared MSCHAPV2 helper functions / RFC 2433 / RFC 2759
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
#include <openssl/md4.h>
#include <openssl/des.h>

#include "common.h"
#include "eapol_sm.h"
#include "eap.h"
#include "sha1.h"
#include "ms_funcs.h"


#if OPENSSL_VERSION_NUMBER < 0x00907000
#define DES_key_schedule des_key_schedule
#define DES_cblock des_cblock
#define DES_set_key(key, schedule) des_set_key((key), *(schedule))
#define DES_ecb_encrypt(input, output, ks, enc) \
	des_ecb_encrypt((input), (output), *(ks), (enc))
#endif /* openssl < 0.9.7 */


static void challenge_hash(u8 *peer_challenge, u8 *auth_challenge,
			   u8 *username, size_t username_len,
			   u8 *challenge)
{
	SHA1_CTX context;
	u8 hash[SHA1_MAC_LEN];
	SHA1Init(&context);
	SHA1Update(&context, peer_challenge, 16);
	SHA1Update(&context, auth_challenge, 16);
	SHA1Update(&context, username, username_len);
	SHA1Final(hash, &context);
	memcpy(challenge, hash, 8);
}


void nt_password_hash(u8 *password, size_t password_len, u8 *password_hash)
{
	u8 *buf;
	int i;
	MD4_CTX ctx;

	/* Convert password into unicode */
	buf = malloc(password_len * 2);
	if (buf == NULL)
		return;
	memset(buf, 0, password_len * 2);
	for (i = 0; i < password_len; i++)
		buf[2 * i] = password[i];

	MD4_Init(&ctx);
	MD4_Update(&ctx, buf, password_len * 2);
	free(buf);
	MD4_Final(password_hash, &ctx);
}


void hash_nt_password_hash(u8 *password_hash, u8 *password_hash_hash)
{
	MD4_CTX ctx;
	MD4_Init(&ctx);
	MD4_Update(&ctx, password_hash, 16);
	MD4_Final(password_hash_hash, &ctx);
}


/**
 * @clear: 8 octets (in)
 * @key: 7 octets (in) (no parity bits included)
 * @cypher: 8 octets (out)
 */
static void des_encrypt(u8 *clear, u8 *key, u8 *cypher)
{
	u8 pkey[8], next, tmp;
	int i;
	DES_key_schedule ks;

	/* Add parity bits to the key */
	next = 0;
	for (i = 0; i < 7; i++) {
		tmp = key[i];
		pkey[i] = (tmp >> i) | next | 1;
		next = tmp << (7 - i);
	}
	pkey[i] = next | 1;

	DES_set_key(&pkey, &ks);
	DES_ecb_encrypt((DES_cblock *) clear, (DES_cblock *) cypher, &ks,
			DES_ENCRYPT);
}


void challenge_response(u8 *challenge, u8 *password_hash, u8 *response)
{
	u8 zpwd[7];
	des_encrypt(challenge, password_hash, response);
	des_encrypt(challenge, password_hash + 7, response + 8);
	zpwd[0] = password_hash[14];
	zpwd[1] = password_hash[15];
	memset(zpwd + 2, 0, 5);
	des_encrypt(challenge, zpwd, response + 16);
}


void generate_nt_response(u8 *auth_challenge, u8 *peer_challenge,
			  u8 *username, size_t username_len,
			  u8 *password, size_t password_len,
			  u8 *response)
{
	u8 challenge[8];
	u8 password_hash[16];

	challenge_hash(peer_challenge, auth_challenge, username, username_len,
		       challenge);
	nt_password_hash(password, password_len, password_hash);
	challenge_response(challenge, password_hash, response);
}


void generate_authenticator_response(u8 *password, size_t password_len,
				     u8 *peer_challenge,
				     u8 *auth_challenge,
				     u8 *username, size_t username_len,
				     u8 *nt_response, u8 *response)
{
	static const u8 magic1[39] = {
		0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
		0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
		0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
		0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74
	};
	static const u8 magic2[41] = {
		0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
		0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
		0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
		0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
		0x6E
	};

	u8 password_hash[16], password_hash_hash[16], challenge[8];
	SHA1_CTX context;

	nt_password_hash(password, password_len, password_hash);
	hash_nt_password_hash(password_hash, password_hash_hash);
	SHA1Init(&context);
	SHA1Update(&context, password_hash_hash, 16);
	SHA1Update(&context, nt_response, 24);
	SHA1Update(&context, (u8 *) magic1, sizeof(magic1));
	SHA1Final(response, &context);

	challenge_hash(peer_challenge, auth_challenge, username, username_len,
		       challenge);

	SHA1Init(&context);
	SHA1Update(&context, response, SHA1_MAC_LEN);
	SHA1Update(&context, challenge, 8);
	SHA1Update(&context, (u8 *) magic2, sizeof(magic2));
	SHA1Final(response, &context);
}


void nt_challenge_response(u8 *challenge, u8 *password, size_t password_len,
			   u8 *response)
{
	u8 password_hash[16];
	nt_password_hash(password, password_len, password_hash);
	challenge_response(challenge, password_hash, response);
}
