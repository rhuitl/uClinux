/*
 *	sha256sum.c -- simple SHA256 sum code (to get a binary output)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include "sha256.h"

void usage(void)
{
	printf("usage: sha256sum [-hvb]\n");
}

int main(int argc, char *argv[])
{
	struct sha256_ctx ctx;
	unsigned char buf[64];
	unsigned char hash[32];
	int c;
	int dobinary = 0;

	while ((c = getopt(argc, argv, "?hvb")) > 0) {
		switch (c) {
		case 'b':
			dobinary = 1;
			break;
		case 'v':
			printf("Version: 1.0.0\n");
			return 0;
		case '?':
		case 'h':
			usage();
			return 0;
		default:
			usage();
			return 1;
		}
	}

	sha256_init_ctx(&ctx);
	do {
		c = fread(buf, 1, 64, stdin);
		sha256_process_bytes(buf, c, &ctx);
	} while (c == 64);
	sha256_finish_ctx(&ctx, hash);

	if (dobinary) {
		fwrite(hash, 1, 32, stdout);
	} else {
		for (c = 0; (c < 32); c++)
			printf("%02x", hash[c]);
		printf("\n");
	}

	return 0;
}

