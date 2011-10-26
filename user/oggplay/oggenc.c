#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <config/autoconf.h>

#ifdef CONFIG_USER_SETKEY_SETKEY
#include <key/key.h>
#endif

static int	crypto_keylen = 0;
static char	*crypto_key = NULL;

static void usage(int rc) {
	printf("usage: oggenc -c key files...\n");
	exit(rc);
}

static void process_file(char *fname) {
	const int fl = strlen(fname);
	char src[fl + 5];
	char dst[fl + 5];
	char *p;
	FILE *fs, *fd;
	int i = 0;
	int c;
	char bin[64000];
	char bout[64000];

	p = strrchr(fname, '.');
	if (p != NULL && strcasecmp(p, ".enc") == 0) {
		*p = '\0';
		strcpy(dst, fname);
		*p = '.';
		strcpy(src, fname);
	} else {
		strcpy(src, fname);
		sprintf(dst, "%s.enc", fname);
	}
	unlink(dst);

	fs = fopen(src, "r");
	if (fs == NULL) {
		fprintf(stderr, "unable to open %s for read\n", src);
		exit(1);
	}
	fd = fopen(dst, "w");
	if (fd == NULL) {
		fclose(fs);
		fprintf(stderr, "unable to create %s\n", dst);
		exit(1);
	}

	setbuffer(fs, bin, sizeof(bin));
	setbuffer(fd, bout, sizeof(bout));

	while ((c = getc(fs)) != EOF) {
		c ^= crypto_key[i++];
		if (i >= crypto_keylen)
			i = 0;
		putc(c, fd);
	}
	fclose(fs);
	fclose(fd);
}

int main(int argc, char *argv[]) {
	int c;

	while ((c = getopt(argc, argv, "?hc:")) >= 0) {
		switch (c) {
		case 'c':
			crypto_key = strdup(optarg);
			crypto_keylen = strlen(crypto_key);
			{	char *p = optarg;
				while (*p != '\0')
					*p++ = '\0';
			}
			break;
		case 'h':
		case '?':
			usage(0);
			break;
		default:
			usage(1);
			break;
		}
	}

#ifdef CONFIG_USER_SETKEY_SETKEY
	/* If we've got the crypto key driver installed and the user hasn't
	 * specified a crypto key already, we load it from the driver.
	 */
	if (crypto_key == NULL) {
		static unsigned char key[128];
		int i;

		if ((i = getdriverkey(key, sizeof(key))) > 0) {
			crypto_key = (char *) key;
			crypto_keylen = i;
		}
	}
#endif

	if (crypto_keylen == 0)
		usage(1);
	if (optind >= argc)
		usage(1);
	while (optind < argc)
		process_file(argv[optind++]);
	return 0;
}
