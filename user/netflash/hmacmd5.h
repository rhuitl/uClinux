#ifndef _HMACMD5_H
#define _HMACMD5_H

#include "md5.h"

typedef struct {
    unsigned char ipad[64];
    unsigned char opad[64];
    MD5_CTX md5ctx;
} HMACMD5_CTX;

void HMACMD5Init(HMACMD5_CTX *ctx, unsigned char* key, int key_len);
void HMACMD5Update(HMACMD5_CTX *ctx, unsigned char *text, int text_len);
void HMACMD5Final(unsigned char hash[], HMACMD5_CTX *ctx);

#endif /* HMACMD5_H */
