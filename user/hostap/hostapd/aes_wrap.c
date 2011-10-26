/*
 * AES Key Wrap Algorithm (128-bit KEK) (RFC3394)
 * Copyright (c) 2003-2004, Jouni Malinen <jkmaline@cc.hut.fi>
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

#include <stdio.h>
#include <string.h>
#include "common.h"
#include "aes_wrap.h"

#ifdef EAP_TLS_FUNCS

#include <openssl/aes.h>

#else /* EAP_TLS_FUNCS */

#include "aes.c"

struct aes_key_st {
	u32 rk[44];
};
typedef struct aes_key_st AES_KEY;

#define AES_set_encrypt_key(userKey, bits, key) \
	rijndaelKeySetupEnc((key)->rk, (userKey))
#define AES_set_decrypt_key(userKey, bits, key) \
	rijndaelKeySetupDec((key)->rk, (userKey))
#define AES_encrypt(in, out, key) \
	rijndaelEncrypt((key)->rk, in, out)
#define AES_decrypt(in, out, key) \
	rijndaelDecrypt((key)->rk, in, out)

#endif /* EAP_TLS_FUNCS */


/*
 * @kek: key encryption key (KEK)
 * @n: length of the wrapped key in 64-bit units; e.g., 2 = 128-bit = 16 bytes
 * @plain: plaintext key to be wrapped, n * 64 bit
 * @cipher: wrapped key, (n + 1) * 64 bit
 */
void aes_wrap(u8 *kek, int n, u8 *plain, u8 *cipher)
{
	u8 *a, *r, b[16];
	int i, j;
	AES_KEY key;

	a = cipher;
	r = cipher + 8;

	/* 1) Initialize variables. */
	memset(a, 0xa6, 8);
	memcpy(r, plain, 8 * n);

	AES_set_encrypt_key(kek, 128, &key);

	/* 2) Calculate intermediate values.
	 * For j = 0 to 5
	 *     For i=1 to n
	 *         B = AES(K, A | R[i])
	 *         A = MSB(64, B) ^ t where t = (n*j)+i
	 *         R[i] = LSB(64, B)
	 */
	for (j = 0; j <= 5; j++) {
		r = cipher + 8;
		for (i = 1; i <= n; i++) {
			memcpy(b, a, 8);
			memcpy(b + 8, r, 8);
			AES_encrypt(b, b, &key);
			memcpy(a, b, 8);
			a[7] ^= n * j + i;
			memcpy(r, b + 8, 8);
			r += 8;
		}
	}

	/* 3) Output the results.
	 *
	 * These are already in @cipher due to the location of temporary
	 * variables.
	 */
}


/*
 * @kek: key encryption key (KEK)
 * @n: length of the wrapped key in 64-bit units; e.g., 2 = 128-bit = 16 bytes
 * @cipher: wrapped key to be unwrapped, (n + 1) * 64 bit
 * @plain: plaintext key, n * 64 bit
 */
int aes_unwrap(u8 *kek, int n, u8 *cipher, u8 *plain)
{
	u8 a[8], *r, b[16];
	int i, j;
	AES_KEY key;

	/* 1) Initialize variables. */
	memcpy(a, cipher, 8);
	r = plain;
	memcpy(r, cipher + 8, 8 * n);

	AES_set_decrypt_key(kek, 128, &key);

	/* 2) Compute intermediate values.
	 * For j = 5 to 0
	 *     For i = n to 1
	 *         B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
	 *         A = MSB(64, B)
	 *         R[i] = LSB(64, B)
	 */
	for (j = 5; j >= 0; j--) {
		r = plain + (n - 1) * 8;
		for (i = n; i >= 1; i--) {
			memcpy(b, a, 8);
			b[7] ^= n * j + i;

			memcpy(b + 8, r, 8);
			AES_decrypt(b, b, &key);
			memcpy(a, b, 8);
			memcpy(r, b + 8, 8);
			r -= 8;
		}
	}

	/* 3) Output results.
	 *
	 * These are already in @plain due to the location of temporary
	 * variables. Just verify that the IV matches with the expected value.
	 */
	for (i = 0; i < 8; i++) {
		if (a[i] != 0xa6)
			return -1;
	}

	return 0;
}


#ifdef TEST_MAIN

#ifdef __i386__
#define rdtscll(val) \
     __asm__ __volatile__("rdtsc" : "=A" (val))

static void test_aes_perf(void)
{
	const int num_iters = 10;
	int i;
	unsigned int start, end;
	AES_KEY akey;
	u8 key[16], pt[16], ct[16];

	printf("keySetupEnc:");
	for (i = 0; i < num_iters; i++) {
		rdtscll(start);
		AES_set_encrypt_key(key, 128, &akey);
		rdtscll(end);
		printf(" %d", end - start);
	}
	printf("\n");

	printf("Encrypt:");
	for (i = 0; i < num_iters; i++) {
		rdtscll(start);
		AES_encrypt(pt, ct, &akey);
		rdtscll(end);
		printf(" %d", end - start);
	}
	printf("\n");
}
#endif /* __i386__ */

int main(int argc, char *argv[])
{
	u8 kek[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};
	u8 plain[] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	};
	u8 crypt[] = {
		0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
		0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
		0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5
	};
	u8 result[24];
	int ret = 0;

	aes_wrap(kek, 2, plain, result);
	if (memcmp(result, crypt, 24) != 0) {
		printf("AES-WRAP-128-128 failed\n");
		ret++;
	}
	if (aes_unwrap(kek, 2, crypt, result)) {
		printf("AES-UNWRAP-128-128 reported failure\n");
		ret++;
	}
	if (memcmp(result, plain, 16) != 0) {
		int i;
		printf("AES-UNWRAP-128-128 failed\n");
		ret++;
		for (i = 0; i < 16; i++)
			printf(" %02x", result[i]);
		printf("\n");
	}

#ifdef __i386__
	test_aes_perf();
#endif /* __i386__ */

	return ret;
}
#endif /* TEST_MAIN */
