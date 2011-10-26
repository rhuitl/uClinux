/*
 * decryptimage.c: extract signed netflash images
 *
 * Copyright (C) 2008-2009,  SnapGear (www.snapgear.com)
 * Written by Philip Craig
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
	fprintf(stderr, "usage: %s [-envt] [-f image] [-k pub.pem]\n", pname);
	fprintf(stderr, "\t-v\tverbose output\n"
			"\t-n\trun without overwriting image\n"
			"\t-t\tprocess a tagged image instead of a raw image\n"
			"\t-f\tprocess specified file instead of imagez.bin\n"
			"\t-k\tspecify public key to verify image with\n"
		);
	exit(1);
}

int main(int argc, char *argv[]) {
	char *fname = "imagez.bin";
	int f;
	struct stat st;
	unsigned char *fmem;
	unsigned char tmp[AES_BLOCK_SIZE];
	RSA *pkey;
	unsigned long dsize;
	unsigned long s;
	int opt;
	char *pubf = PUBLIC_KEY_FILE;
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
		case 'f':	fname = optarg;	break;
		case 'k':	pubf = optarg;	break;
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

	/* Load public key */
	{
		BIO *in;
		struct stat st;

		if (stat(pubf, &st) == -1)
			error("no public key file found, %s", pubf);
		in = BIO_new(BIO_s_file());
		if (in == NULL)
			error("cannot allocate a bio structure");
		if (BIO_read_filename(in, pubf) <= 0)
			error("cannot open public key file");
		pkey = PEM_read_bio_RSA_PUBKEY(in, NULL, NULL, NULL);
		if (pkey == NULL)
			error("cannot read public key");
	}

	/* Load file contents */
	f = open(fname, O_RDONLY);
	if (f == -1)
		error("unable to open %s", fname);
	if (fstat(f, &st) == -1)
		error("unable to stat %s", fname);
	dsize = st.st_size;
	fmem = malloc(dsize);
	if (fmem == NULL)
		error("unable to allocate memory for %s", fname);
	if (read(f, fmem, st.st_size) != st.st_size)
		error("unable to read %s", fname);
	close(f);

	/* Decode header information */
	memcpy(&lhdr, fmem + dsize - sizeof(lhdr), sizeof(lhdr));
	dsize -= sizeof(lhdr);
	if (lhdr.magic != htons(LITTLE_CRYPTO_MAGIC))
		error("image %s is not signed", fname);

	{
		unsigned short hlen = ntohs(lhdr.hlen);
		unsigned char tmp[hlen];
		unsigned char t2[hlen];
		int len;

		memcpy(&tmp, fmem + dsize - hlen, hlen);
		dsize -= hlen;
		len = RSA_public_decrypt(hlen, tmp, t2,
				pkey, RSA_PKCS1_PADDING);
		if (len == -1)
			error("public decrypt failed");
		if (len != sizeof(hdr))
			error("Length mismatch %d %d", (int)sizeof(hdr), len);
		memcpy(&hdr, t2, sizeof(struct header));
	}
	RSA_free(pkey);
	if (hdr.magic != htonl(CRYPTO_MAGIC))
		error("image not cryptographically enabled");

	/* Decrypt image if needed */
	if (hdr.flags & FLAG_ENCRYPTED) {
		if ((dsize % AES_BLOCK_SIZE) != 0)
			error("image size not miscable with cryptography");
		AES_KEY key;
		AES_set_decrypt_key(hdr.aeskey, AESKEYSIZE * 8, &key);
		/* Convert the body of the file */
		for (s = 0; s<dsize; s += AES_BLOCK_SIZE) {
			AES_decrypt(fmem + s, tmp, &key);
			memcpy(fmem + s, tmp, AES_BLOCK_SIZE);
		}
	}

	/* Remove padding */
	dsize -= hdr.padsize;

#ifdef CONFIG_USER_NETFLASH_CRYPTO_V2
	/* Check SHA256 sum if required */
	{
		unsigned char hash[SHA256_DIGEST_LENGTH];

		SHA256(fmem + START_POSN, dsize - START_POSN, hash);
		printf("SHA256 checksum of %scontents is:\n\t",
			(hdr.flags & FLAG_ENCRYPTED) ? "unencrypted " : "");
		for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
			printf ("%02x", hdr.hash[i]);
		printf ("  %s\n", fname);
		if (memcmp(hdr.hash, hash, SHA256_DIGEST_LENGTH) != 0)
			error("bad SHA256 signature");
	}
#else
	/* Check MD5 sum if required */
	{
		unsigned char hash[16];

		MD5(fmem + START_POSN, dsize - START_POSN, hash);
		printf("MD5 checksum of %scontents is:\n\t",
				(hdr.flags & FLAG_ENCRYPTED)?"unencrypted ":"");
		for (i = 0; i < 16; i++)
			printf ("%02x", hdr.md5[i]);
		printf ("  %s\n", fname);
		if (memcmp(hdr.md5, hash, MD5_DIGEST_LENGTH) != 0)
			error("bad MD5 signature");
	}
#endif

	/* Write the image out */
	f = open("temp", O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (f == -1)
		error("unable to create output file");
	if (write(f, fmem, dsize) != dsize)
		error("write failed, image unchanged");
	free(fmem);
	close(f);
	if (nop)	unlink("temp");
	else		rename("temp", fname);
	return 0;
}
