#include "config.h"
#include "jpegsign.h"
#include "profiling.h"

#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>

/*
 * First, you need to create a private/public keypair:
 * $ openssl genrsa -out private.pem 1024
 * $ openssl rsa -in private.pem -out public.pem -outform PEM -pubout
 */

int load_private_key(const char* keyfilename, RSA** rsa_key)
{
	FILE* keyfile = fopen(keyfilename, "r");
	if(!keyfile) {
		perror("Cannot open keyfile");
		return 1;
	}

	int ret = 0;
	if(!PEM_read_RSAPrivateKey(keyfile, rsa_key, NULL, NULL)) {
		printf("Cannot read private key\n");
		ret = 1;
	}
	fclose(keyfile);
	return ret;
}

void encode_sig(void* sig, int sig_sz)
{
	BIO* b64 = BIO_new(BIO_f_base64());
	BIO* bout = BIO_new(BIO_s_mem());

	BIO_push(b64, bout);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	BIO_write(b64, sig, sig_sz);
	BIO_flush(b64);

	BUF_MEM* b64_data;
	BIO_get_mem_ptr(bout, &b64_data);

	printf("Base64 hash (%d bytes): %*s\n", b64_data->length, b64_data->length, b64_data->data);

	BIO_set_close(bout, BIO_CLOSE);     // free underlying BUF_MEM
	BIO_free_all(b64);
	BIO_free_all(bout);
}

int sign_data(void* jpeg_data, size_t jpeg_sz, RSA* rsa_key)
{
	// Create a message digest and sign it
	unsigned char md[SHA_DIGEST_LENGTH];
	PROFILE_BEGIN(sha1)
	SHA1(jpeg_data, jpeg_sz, md);
	PROFILE_END(sha1)

	unsigned char sig[RSA_size(rsa_key)];
	unsigned int sig_sz;

	printf("Signing %lu bytes, digest size: %d, sig size is %lu\n",
	       sizeof(md), SHA_DIGEST_LENGTH, sizeof(sig));

	PROFILE_BEGIN(rsa_sign)
	int ret = RSA_sign(NID_sha1, md, sizeof(md), sig, &sig_sz, rsa_key);
	PROFILE_END(rsa_sign)

	if(!ret) {
		printf("RSA_sign failed\n");
	} else {
		printf("Got %d sig bytes\n", sig_sz);
		/*PROFILE_BEGIN(encode_sig)
		encode_sig(sig, sig_sz);
		PROFILE_END(encode_sig)*/
	}
	return 0;
}
