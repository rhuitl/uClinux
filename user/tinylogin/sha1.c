/* vi: set sw=4 ts=4: */
/* 
   Implements the Secure Hash Algorithm (SHA1)

   Copyright (C) 1999 Scott G. Miller

   Released under the terms of the GNU General Public License v2
   see file COPYING for details

   Credits: 
      Robert Klep <robert@ilse.nl>  -- Expansion function fix 
   ---
   FIXME: This source takes int to be a 32 bit integer.  This
   may vary from system to system.  I'd use autoconf if I was familiar
   with it.  Anyone want to help me out?
*/

void sha_hash(int *, int *);
void sha_init(int *);
char *sprint_hash(int *);
void do_sha_hash(int *, int *);

/*
  added 3 functions for sha passowrd stuff (mainly inspired from stuff seen in main.c from shasum-1.3 package)
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <endian.h>
/* On big endian machines, we need to reverse the input to process
   the blocks correctly */

#define switch_endianness(x) (x<<24 & 0xff000000) | \
                             (x<<8  & 0x00ff0000) | \
                             (x>>8  & 0x0000ff00) | \
                             (x>>24 & 0x000000ff)

/* Initial hash values */
#define Ai 0x67452301
#define Bi 0xefcdab89
#define Ci 0x98badcfe
#define Di 0x10325476
#define Ei 0xc3d2e1f0

/* SHA1 round constants */
#define K1 0x5a827999
#define K2 0x6ed9eba1
#define K3 0x8f1bbcdc
#define K4 0xca62c1d6

/* Round functions.  Note that f2() is used in both rounds 2 and 4 */
#define f1(B,C,D) ((B & C) | ((~B) & D))
#define f2(B,C,D) (B ^ C ^ D)
#define f3(B,C,D) ((B & C) | (B & D) | (C & D))

/* left circular shift functions (rotate left) */
#define rol1(x) ((x<<1) | ((x>>31) & 1))
#define rol5(A) ((A<<5) | ((A>>27) & 0x1f))
#define rol30(B) ((B<<30) | ((B>>2) & 0x3fffffff))

/*
  Hashes 'data', which should be a pointer to 512 bits of data (sixteen
  32 bit ints), into the ongoing 160 bit hash value (five 32 bit ints)
  'hash'
*/
void sha_hash(int *data, int *hash)
{
	int W[80];
	unsigned int A = hash[0], B = hash[1], C = hash[2], D = hash[3], E =
		hash[4];
	unsigned int t, x, TEMP;

	for (t = 0; t < 16; t++) {
#ifdef BIG_ENDIAN
		W[t] = switch_endianness(data[t]);
#else
		W[t] = data[t];
#endif
	}


	/* SHA1 Data expansion */
	for (t = 16; t < 80; t++) {
		x = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16];
		W[t] = rol1(x);
	}

	/* SHA1 main loop (t=0 to 79) 
	   This is broken down into four subloops in order to use
	   the correct round function and constant */
	for (t = 0; t < 20; t++) {
		TEMP = rol5(A) + f1(B, C, D) + E + W[t] + K1;
		E = D;
		D = C;
		C = rol30(B);
		B = A;
		A = TEMP;
	}
	for (; t < 40; t++) {
		TEMP = rol5(A) + f2(B, C, D) + E + W[t] + K2;
		E = D;
		D = C;
		C = rol30(B);
		B = A;
		A = TEMP;
	}
	for (; t < 60; t++) {
		TEMP = rol5(A) + f3(B, C, D) + E + W[t] + K3;
		E = D;
		D = C;
		C = rol30(B);
		B = A;
		A = TEMP;
	}
	for (; t < 80; t++) {
		TEMP = rol5(A) + f2(B, C, D) + E + W[t] + K4;
		E = D;
		D = C;
		C = rol30(B);
		B = A;
		A = TEMP;
	}
	hash[0] += A;
	hash[1] += B;
	hash[2] += C;
	hash[3] += D;
	hash[4] += E;
}

/*
  Takes a pointer to a 160 bit block of data (five 32 bit ints) and
  intializes it to the start constants of the SHA1 algorithm.  This
  must be called before using hash in the call to sha_hash
*/
void sha_init(int *hash)
{
	hash[0] = Ai;
	hash[1] = Bi;
	hash[2] = Ci;
	hash[3] = Di;
	hash[4] = Ei;
}


/*
 * write the hash to a string
 */
char *sprint_sha1_hash(int *hashval)
{
	int x = 0;
	char *out = NULL;

	if ((out = malloc(43)) == NULL)
		return NULL;
	memset(out, 0x00, 43);
	strcpy(out, "$2$");
	for (x = 0; x < 5; x++) {
		sprintf(out + (x * 8) + 3, "%08x", hashval[x]);
	}
	out[43] = 0;
	return out;
}


/*
 * hash the password
 */
void do_sha_hash(int *hashval, int *pw)
{
	sha_init(hashval);
	sha_hash(pw, hashval);
}


/*
 * hash a charakter string and return the 160bit integer in hex as a character string
 */
char *sha1_crypt(const char *pw)
{
	int hashval[20];

	memset(hashval, 0x00, sizeof(hashval));
	do_sha_hash(hashval, (int *) ((char *) pw + 3));

	return sprint_sha1_hash(hashval);
}
