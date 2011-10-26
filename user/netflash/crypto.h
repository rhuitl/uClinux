#ifndef __NETFLASH_CRYPTO_H__
#define __NETFLASH_CRYPTO_H__

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/md5.h>
#include <openssl/aes.h>

#define CRYPTO_MAGIC		0xb9b1e546
#define LITTLE_CRYPTO_MAGIC	0x2ad6

#define AESKEYSIZE		(256/8)

#define FLAG_ENCRYPTED		0x01

/*
 * Have to pack this structure. It has been known to change size from
 * host to target system which causes a few problems!
 */
struct header {
	unsigned int magic;
#ifdef CONFIG_USER_NETFLASH_CRYPTO_V2
	unsigned char hash[SHA256_DIGEST_LENGTH];
#else
	unsigned char md5[MD5_DIGEST_LENGTH];
#endif
	unsigned char aeskey[AESKEYSIZE];
	unsigned char flags;
	unsigned char padsize;
} __attribute__ ((packed));

struct little_header {
	unsigned short hlen;	/* Length of encrypted header block */
	unsigned short magic;	/* Magic number for identification purposes */
};

#endif
