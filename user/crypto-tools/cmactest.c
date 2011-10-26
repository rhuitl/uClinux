
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <paths.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <err.h>

#include <string.h>
#include <err.h>

#include <sys/sysctl.h>
#include <time.h>
#include <sys/time.h>
#include <crypto/cryptodev.h>

#define	CHUNK	64	/* how much to display */
#define	N(a)		(sizeof (a) / sizeof (a[0]))
#define	streq(a,b)	(strcasecmp(a,b) == 0)

void	hexdump(char *, int);

static int
devcrypto(void)
{
	static int fd = -1;

	if (fd < 0) {
		fd = open(_PATH_DEV "crypto", O_RDWR, 0);
		if (fd < 0)
			err(1, _PATH_DEV "crypto");
		if (fcntl(fd, F_SETFD, 1) == -1)
			err(1, "fcntl(F_SETFD) (devcrypto)");
	}
	return fd;
}


void
des_md5_hmac()
{
	int i, fd = devcrypto();
	char *cleartext = NULL, *ciphertext = NULL, *originaltext = NULL;
	struct session2_op sop;
	struct crypt_op cop;
	char iv[64];
	char mac[MD5_HASH_LEN];

	bzero(&sop, sizeof(sop));
	bzero(&iv, sizeof(iv));
	bzero(&mac, sizeof(mac));

	sop.keylen = DES_MIN_KEY_LEN;
	sop.key = (char *) malloc(sop.keylen);
	for (i = 0; i < sop.keylen; i++)
		sop.key[i] = i;
	sop.cipher = CRYPTO_DES_CBC;

	sop.mackeylen = 16; /* MD5 size */
	sop.mackey = (char *) malloc(sop.mackeylen);
	for (i = 0; i < sop.mackeylen; i++)
		sop.mackey[i] = i;
	sop.mac = CRYPTO_MD5_HMAC;

	sop.crid = CRYPTO_FLAG_HARDWARE | CRYPTO_FLAG_SOFTWARE;

	if (ioctl(fd, CIOCGSESSION2, &sop) < 0) {
		perror("CIOCGSESSION2");
		exit(1);
	}

#undef size
#define size 32
	originaltext = (char *)malloc(size * 3);
	cleartext = originaltext+size;
	ciphertext = cleartext+size;
	for (i = 0; i < size; i++)
		cleartext[i] = i;
	memcpy(originaltext, cleartext, size);
	for (i = 0; i < N(iv); i++)
		iv[i] = i;

	printf("cleartext:");
	hexdump(cleartext, MIN(size, CHUNK));

	cop.ses = sop.ses;
	cop.op = COP_ENCRYPT;
	cop.flags = 0;
	cop.len = size;
	cop.src = cleartext;
	cop.dst = ciphertext;
	cop.mac = mac;
	cop.iv = iv;

	if (ioctl(fd, CIOCCRYPT, &cop) < 0)
		err(1, "line %d:ioctl(CIOCCRYPT)", __LINE__);

	if (bcmp(ciphertext, cleartext, size) == 0) {
		printf("cipher text unchanged:");
		hexdump(ciphertext, size);
	}

	printf("ciphertext:");
	hexdump(ciphertext, MIN(size, CHUNK));
	printf("cipheriv:");
	hexdump(iv, MIN(sizeof(iv), CHUNK));
	printf("mac:");
	hexdump(mac, MIN(sizeof(mac), CHUNK));

	memset(cleartext, 'x', MIN(size, CHUNK));
	cop.ses = sop.ses;
	cop.op = COP_DECRYPT;
	cop.flags = 0;
	cop.len = size;
	cop.src = ciphertext;
	cop.dst = cleartext;
	cop.mac = mac;
	cop.iv = iv;

	if (ioctl(fd, CIOCCRYPT, &cop) < 0)
		err(1, "line %d:ioctl(CIOCCRYPT)", __LINE__);

	if (bcmp(cleartext, originaltext, size) != 0) {
		printf("decrypt mismatch:\n");
		printf("original:");
		hexdump(originaltext, size);
		printf("cleartext:");
		hexdump(cleartext, size);
	}
 
	if (ioctl(fd, CIOCFSESSION, &sop.ses) < 0)
		perror("ioctl(CIOCFSESSION)");

	printf("cleartext:");
	hexdump(cleartext, MIN(size, CHUNK));
}

void
md5_hmac()
{
	int i, fd = devcrypto();
	char *cleartext = NULL, *ciphertext = NULL, *originaltext = NULL;
	struct session2_op sop;
	struct crypt_op cop;
	char mac[MD5_HASH_LEN];

	bzero(&sop, sizeof(sop));
	bzero(&mac, sizeof(mac));
	bzero(&cop, sizeof(cop));

	sop.mackeylen = 16; /* MD5 size */
	sop.mackey = (char *) malloc(sop.mackeylen);
	for (i = 0; i < sop.mackeylen; i++)
		sop.mackey[i] = i;
	sop.mac = CRYPTO_MD5_HMAC;

	sop.crid = CRYPTO_FLAG_HARDWARE | CRYPTO_FLAG_SOFTWARE;

	if (ioctl(fd, CIOCGSESSION2, &sop) < 0) {
		perror("CIOCGSESSION2");
		exit(1);
	}

#undef size
#define size 32
	originaltext = (char *)malloc(size * 3);
	cleartext = originaltext+size;
	ciphertext = cleartext+size;
	for (i = 0; i < size; i++)
		cleartext[i] = i;
	memcpy(originaltext, cleartext, size);

	printf("cleartext:");
	hexdump(cleartext, MIN(size, CHUNK));

	cop.ses = sop.ses;
	cop.op = COP_ENCRYPT;
	cop.len = size;
	cop.src = cleartext;
	cop.dst = ciphertext;
	cop.mac = mac;

	if (ioctl(fd, CIOCCRYPT, &cop) < 0)
		err(1, "line %d:ioctl(CIOCCRYPT)", __LINE__);

	printf("mac:");
	hexdump(mac, MIN(sizeof(mac), CHUNK));

	if (ioctl(fd, CIOCFSESSION, &sop.ses) < 0)
		perror("ioctl(CIOCFSESSION)");
}


void
hexdump(char *p, int n)
{
	int i, off;

	for (off = 0; n > 0; off += 16, n -= 16) {
		printf("%s%04x:", off == 0 ? "\n" : "", off);
		i = (n >= 16 ? 16 : n);
		do {
			printf(" %02x", *p++ & 0xff);
		} while (--i);
		printf("\n");
	}
}

int
main(int argc, char **argv)
{
	des_md5_hmac();
	md5_hmac();
}
