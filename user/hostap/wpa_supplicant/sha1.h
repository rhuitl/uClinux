#ifndef SHA1_H
#define SHA1_H

#ifdef EAP_TLS_FUNCS

#include <openssl/sha.h>

#define SHA1_CTX SHA_CTX
#define SHA1Init SHA1_Init
#define SHA1Update SHA1_Update
#define SHA1Final SHA1_Final
#define SHA1Transform SHA1_Transform
#define SHA1_MAC_LEN SHA_DIGEST_LENGTH

#else /* EAP_TLS_FUNCS */

#define SHA1_MAC_LEN 20

typedef struct {
	u32 state[5];
	u32 count[2];
    unsigned char buffer[64];
} SHA1_CTX;

void SHA1Init(SHA1_CTX *context);
void SHA1Update(SHA1_CTX *context, unsigned char *data, u32 len);
void SHA1Final(unsigned char digest[20], SHA1_CTX* context);
void SHA1Transform(u32 state[5], unsigned char buffer[64]);

#endif /* EAP_TLS_FUNCS */

void sha1_mac(unsigned char *key, unsigned int key_len,
	      unsigned char *data, unsigned int data_len,
	      unsigned char *mac);
void hmac_sha1_vector(unsigned char *key, unsigned int key_len,
		      size_t num_elem, unsigned char *addr[],
		      unsigned int *len, unsigned char *mac);
void hmac_sha1(unsigned char *key, unsigned int key_len,
	       unsigned char *data, unsigned int data_len,
	       unsigned char *mac);
void sha1_prf(unsigned char *key, unsigned int key_len,
	      char *label, unsigned char *data, unsigned int data_len,
	      unsigned char *buf, size_t buf_len);
void pbkdf2_sha1(char *passphrase, char *ssid, size_t ssid_len, int iterations,
		 unsigned char *buf, size_t buflen);
void sha1_transform(u8 *state, u8 data[64]);

#endif /* SHA1_H */
