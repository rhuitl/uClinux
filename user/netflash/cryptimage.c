/*
 * cryptimage.c: make signed netflash images
 *
 * Copyright (C) 2008-2009,  SnapGear (www.snapgear.com)
 * Written by Paul Dale
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/aes.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdarg.h>

#include <linux/autoconf.h>
#include <linux/version.h>
#include <config/autoconf.h>

#include "crypto.h"

#define PRIVFILE "xxx.pem"

unsigned char verbose;
unsigned char tagp;
char *pname;

#define START_POSN	(tagp?512:0)

static void error(const char *, ...) __attribute__ ((noreturn, format (printf, 1, 2)));
void error(const char *msg, ...) {
	va_list ap;

	fprintf(stderr, "%s error: ", pname);
	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(1);
}


static void usage(void) __attribute__ ((noreturn));
void usage(void) {
	fprintf(stderr, "usage: %s [-envt] [-f image] [-k priv.pem]\n", pname);
	fprintf(stderr, "\t-v\tverbose output\n"
			"\t-n\trun without overwriting image\n"
			"\t-e\tAES encrypt image\n"
			"\t-t\tprocess a tagged image instead of a raw image\n"
			"\t-f\tprocess specified file instead of imagez.bin\n"
			"\t-k\tspecify private key to sign image with\n"
		);
	exit(1);
}

static void getkey(unsigned char seed[AESKEYSIZE]) {
	int f2;

	f2 = open("/dev/random", O_RDONLY);
	if (f2 == -1)
		error("unable to open random stream");
	if (read(f2, seed, AESKEYSIZE) != AESKEYSIZE)
		error("unable to read random key");
	close(f2);
	if (verbose) {
		printf("Random key is:\n");
		for (f2=0; f2<AESKEYSIZE; f2++) {
			printf("%02x%c", seed[f2], (f2&0xf) == 0xf?'\n':' ');
		}
	}
}


static inline int sz(unsigned char c) {
	return (c & 0xf) * 4 + (c & 0xf0) / 4;
}

static void doctor_image(const struct header *hdr, int chlen, void *img, int imglen) {
	if (tagp) {
		unsigned char *sa;
		int esz= chlen + hdr->padsize + sizeof(struct little_header);
	
		sa = ((unsigned char *)img) + sz(((unsigned char *)img)[4]);
		while (!(sa[3] & 4))
			sa += sz(*sa);
		sa[3] -= 4;
		sa += sz(*sa);
		sa[0] = 4;
		sa[1] = 0;
		sa[2] = 0;
		sa[3] = 4;
		sa[4] = 0;	sa[5] = 0;	sa[6] = 0xa9;	sa[7] = 0;
		sa[8] = sa[12] = esz & 0xff;
		sa[9] = sa[13] = (esz >> 8) & 0xff;
		sa[10] = sa[14] = (esz >> 16) & 0xff;
		sa[11] = sa[15] = (esz >> 24) & 0xff;
	}
}


int main(int argc, char *argv[]) {
	char *fname = "imagez.bin";
	int f;
	struct stat st;
	unsigned char *fmem;
	unsigned char buf[5000];
	unsigned char tmp[AES_BLOCK_SIZE];
  	EVP_PKEY *pkey;
	int len;
	FILE *fp;
	unsigned long dsize;
	unsigned long s;
	int opt;
	char *privf = PRIVFILE;
	int encp = 0;
	struct header hdr;
	struct little_header lhdr;
	int i;
	int nop = 0;
	int forcep = 0;

	bzero(&hdr, sizeof(struct header));
	pname = argv[0];
	while ((opt = getopt(argc, argv, "Fnvetf:k:")) > 0) {
		switch (opt) {
		case 'F':	forcep = 1;	break;
		case 'e':	encp = 1;	break;
		case 'f':	fname = optarg;	break;
		case 'k':	privf = optarg;	break;
		case 'n':	nop = 1;	break;
		case 't':	tagp = 1;	break;
		case 'v':	verbose++;	break;
		default:
			usage();
			break;
		}
	}
	if (optind != argc)
		usage();

	ERR_load_crypto_strings();

	/* Load private key */
	fp = fopen(privf, "r");
	if (fp == NULL)
		error("unable to open key file %s", privf);
	pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	if (pkey == NULL)
		error("unable to read key from %s", privf);
	fclose(fp);

	/* Load file contents */
	f = open(fname, O_RDONLY);
	if (f == -1)
		error("unable to open %s", fname);
	if (fstat(f, &st) == -1)
		error("unable to stat %s", fname);
	if (encp) {
		/* AES requires blocks to encrypt so we'll pad if needed */
		hdr.padsize = AES_BLOCK_SIZE - (st.st_size % AES_BLOCK_SIZE);
		if (hdr.padsize == AES_BLOCK_SIZE)
			hdr.padsize = 0;
		if (verbose)
			printf("%s requires %d bytes padding\n",
					fname, hdr.padsize);
	}
 	dsize = st.st_size + hdr.padsize;
	fmem = malloc(dsize);
	if (fmem == NULL)
		error("unable to allocate memory for %s", fname);
	if (read(f, fmem, st.st_size) != st.st_size)
		error("unable to read %s", fname);
	close(f);

	/* Test to see if we've already processed the image */
	if (!forcep) {
		memcpy(&lhdr, fmem + st.st_size - sizeof(struct little_header),
				sizeof(struct little_header));
		if (lhdr.magic == htons(LITTLE_CRYPTO_MAGIC))
			error("image %s seems to be signed already "
					"use -F to force processing", fname);
	}

#ifdef CONFIG_USER_NETFLASH_CRYPTO_V2
	/* SHA256 sum the entire image */
	SHA256(fmem + START_POSN, st.st_size - START_POSN, hdr.hash);
	if (verbose) {
		printf("SHA256 checksum of %scontents is:\n\t",
				encp ? "unencrypted " : "");
		for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
			printf ("%02x", hdr.hash[i]);
		printf ("  %s\n", fname);
	}
#else
	/* MD5 sum the entire image */
	MD5(fmem + START_POSN, st.st_size - START_POSN, hdr.md5);
	if (verbose) {
		printf("MD5 checksum of %scontents is:\n\t",
				encp?"unencrypted ":"");
		for (i = 0; i < 16; i++)
			printf ("%02x", hdr.md5[i]);
		printf ("  %s\n", fname);
	}
#endif

	/* Encrypt in place if requested */
	if (encp) {
		AES_KEY key;
		hdr.flags |= FLAG_ENCRYPTED;
		getkey(hdr.aeskey);
		AES_set_encrypt_key(hdr.aeskey, AESKEYSIZE * 8, &key);
		for (s=START_POSN; s < dsize; s += AES_BLOCK_SIZE) {
			AES_encrypt(fmem+s, tmp, &key);
			memcpy(fmem+s, tmp, AES_BLOCK_SIZE);
		}
	}

	/* Now to public key encrypt the header and commit that too */
	hdr.magic = htonl(CRYPTO_MAGIC);
	len = RSA_private_encrypt(sizeof(struct header), (void *)&hdr, buf,
			pkey->pkey.rsa, RSA_PKCS1_PADDING);
	if (len == -1) {
		char err[120];
		ERR_error_string(ERR_get_error(), err);
		error("private encrypt failed: %s", err);
	}

	/* Fix up anything that needs fixing */
	doctor_image(&hdr, len, fmem, dsize);

	/* Write the image out */
	f = open("temp", O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (f == -1)
		error("unable to create output file");
	if (write(f, fmem, dsize) != dsize)
		error("write failed, image unchanged");
	free(fmem);
	if (write(f, buf, len) != len)
		error("key write failed, image unchanged");
	lhdr.hlen = htons((unsigned short)len);
	lhdr.magic = htons(LITTLE_CRYPTO_MAGIC);
	if (write(f, &lhdr, sizeof(struct little_header)) != sizeof(struct little_header))
		error("header size write failed, image unchanged");
	close(f);
	EVP_PKEY_free(pkey);
	if (nop)	unlink("temp");
	else		rename("temp", fname);
	return 0;
}
