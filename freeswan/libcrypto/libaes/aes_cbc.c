#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <sys/types.h>
#endif
#include "aes_cbc.h"
#include "cbc_generic.h"
/* returns bool success */
int AES_set_key(aes_context *aes_ctx, const u_int8_t *key, int keysize) {
	aes_set_key(aes_ctx, key, keysize, 0);
	return 1;	
}
#if HW_ASSIST
#include "hw_assist.h"
CBC_IMPL_BLK16(_AES_cbc_encrypt, aes_context, u_int8_t *, aes_encrypt, aes_decrypt);
int AES_cbc_encrypt(aes_context *ctx, const u_int8_t * in, u_int8_t * out, int ilen, const u_int8_t * iv, int encrypt) {
	if (hw_aes_assist()) {
		return hw_aes_cbc_encrypt(ctx, in, out, ilen, iv, encrypt);
	} else {
		return _AES_cbc_encrypt(ctx, in, out, ilen, iv, encrypt);
	}
}
#else
CBC_IMPL_BLK16(AES_cbc_encrypt, aes_context, u_int8_t *, aes_encrypt, aes_decrypt);
#endif
