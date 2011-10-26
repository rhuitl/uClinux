/*
 * flashkey.c: put a raw public key somewhere a bootloader may find it.
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
#include <stdarg.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/bio.h>

#include <linux/autoconf.h>
#include <linux/version.h>
#include <config/autoconf.h>

#include "crypto.h"

char *pname;
int nop = 0;

/****************************************************************************/

void error(const char *, ...) __attribute__ ((noreturn, format (printf, 1, 2)));
void error(const char *msg, ...) {
	va_list ap;

	fprintf(stderr, "%s error: ", pname);
	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(1);
}

/****************************************************************************/

void usage(void) __attribute__ ((noreturn));
void usage(void) {
	fprintf(stderr, "usage: %s [-np] [-k key.pem]\n", pname);
	fprintf(stderr, "\t-k\tprocess specified key file\n"
			"\t-n\trun without committing anything to flash\n"
			"\t-e\terase crypto configuration\n"
		);
	exit(1);
}

/****************************************************************************/

static inline char *copy(const BIGNUM *x, char *c, unsigned char *t) {
	int i, n;

	n = BN_bn2mpi(x, t);
	for (i=0; i<n; c += sprintf(c, "%d,", t[i++]));
	return c;
}

/****************************************************************************/

int main(int argc, char *argv[]) {
	char *keyf = PUBLIC_KEY_FILE;
  	RSA *rsa;
	int opt;
	BIO *in;
	int se, sn;
	unsigned char *tbuf;
	char *cbuf;
	int erasep = 0;

	pname = argv[0];
	while ((opt = getopt(argc, argv, "enk:")) > 0) {
		switch (opt) {
		case 'e':	erasep = 1;	break;
		case 'k':	keyf = optarg;	break;
		case 'n':	nop = 1;	break;
		default:
			usage();
			break;
		}
	}
	if (optind != argc)
		usage();

	if (erasep) {
		cbuf = malloc(sn = 1050 * 4);
		for (se=0; se<sn; se++)
			cbuf[se] = (se&0x3)?((se&3)==3?((se == sn-1)?0:','):'5'):'2';
	} else {
		/* Load key into memory */
		in = BIO_new(BIO_s_file());
		if (in == NULL)
			error("cannot allocate a bio structure");
		if (BIO_read_filename(in, keyf) <= 0)
			error("cannot open public key file");
		rsa = PEM_read_bio_RSA_PUBKEY(in, NULL, NULL, NULL);
		if (rsa == NULL)
			error("cannot read public key");
		if (rsa->e->neg || rsa->n->neg)
			error("cannot deal with negative numbers");

		se = BN_bn2mpi(rsa->e, NULL);
		sn = BN_bn2mpi(rsa->n, NULL);
		tbuf = malloc(se>sn?se:sn);
		cbuf = malloc((se+sn) * 4 + 1);
		if (tbuf == NULL || cbuf == NULL)
			error("unable to allocate temporary memory");

		copy(rsa->n, copy(rsa->e, cbuf, tbuf), tbuf)[-1] = '\0';
		free(tbuf);
	}
	if (!nop) {
		execl("/bin/flash", "ckey", cbuf, NULL);
//		if (errno = E2BIG) {
//		}
		return 1;
	}
	printf("/bin/flash ckey %s\n", cbuf);
	return 0;
}
