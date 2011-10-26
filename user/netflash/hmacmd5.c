#include "hmacmd5.h"

void
HMACMD5Init(HMACMD5_CTX *ctx, unsigned char* key, int key_len)
{
    unsigned char tk[16];
    int i;

    /* if key is longer than 64 bytes reset it to key=MD5(key) */
    if (key_len > 64) {

	MD5_CTX      tctx;

	MD5Init(&tctx);
	MD5Update(&tctx, key, key_len);
	MD5Final(tk, &tctx);

	key = tk;
	key_len = 16;
    }

    /*
     * the HMAC_MD5 transform looks like:
     *
     * MD5(K XOR opad, MD5(K XOR ipad, text))
     *
     * where K is an n byte key
     * ipad is the byte 0x36 repeated 64 times

     * opad is the byte 0x5c repeated 64 times
     * and text is the data being protected
     */

    /* start out by storing key in pads */
    bzero(ctx->ipad, sizeof(ctx->ipad));
    bzero(ctx->opad, sizeof(ctx->opad));
    bcopy(key, ctx->ipad, key_len);
    bcopy(key, ctx->opad, key_len);

    /* XOR key with ipad and opad values */
    for (i=0; i<64; i++) {
	ctx->ipad[i] ^= 0x36;
	ctx->opad[i] ^= 0x5c;
    }

    /*
     * start the inner MD5
     */
    MD5Init(&ctx->md5ctx);                   /* init context for 1st pass */
    MD5Update(&ctx->md5ctx, ctx->ipad, 64);  /* start with inner pad */
}

void HMACMD5Update(HMACMD5_CTX *ctx, unsigned char *text, int text_len)
{
    MD5Update(&ctx->md5ctx, text, text_len); /* then text of datagram */
}

void HMACMD5Final(unsigned char hash[], HMACMD5_CTX *ctx)
{
    MD5Final(hash, &ctx->md5ctx);            /* finish up 1st pass */

    /*
     * perform outer MD5
     */
    MD5Init(&ctx->md5ctx);                   /* init context for 2nd pass */
    MD5Update(&ctx->md5ctx, ctx->opad, 64);  /* start with outer pad */
    MD5Update(&ctx->md5ctx, hash, 16);       /* then results of 1st hash */
    MD5Final(hash, &ctx->md5ctx);            /* finish up 2nd pass */
}
