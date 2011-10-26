/*
 * Host AP crypt: host-based WEP encryption implementation for Host AP driver
 *
 * Copyright (c) 2002-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */

#include <linux/autoconf.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/random.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,44))
#include <linux/tqueue.h>
#else
#include <linux/workqueue.h>
#endif
#include <linux/skbuff.h>
#include <asm/string.h>

#include "hostap_crypt.h"
#include "hostap_compat.h"
#include "hostap_config.h"

#ifdef CONFIG_CRYPTO
#ifdef HOSTAP_USE_CRYPTO_API
#include <linux/crypto.h>
#include <asm/scatterlist.h>
#include <linux/crc32.h>
#endif /* HOSTAP_USE_CRYPTO_API */
#else /* CONFIG_CRYPTO */
#undef HOSTAP_USE_CRYPTO_API
#endif /* CONFIG_CRYPTO */

MODULE_AUTHOR("Jouni Malinen");
MODULE_DESCRIPTION("Host AP crypt: WEP");
MODULE_LICENSE("GPL");


struct prism2_wep_data {
	u32 iv;
#define WEP_KEY_LEN 13
	u8 key[WEP_KEY_LEN + 1];
	u8 key_len;
	u8 key_idx;
#ifdef HOSTAP_USE_CRYPTO_API
	struct crypto_tfm *tfm;
#endif /* HOSTAP_USE_CRYPTO_API */
};

#ifndef HOSTAP_USE_CRYPTO_API
static const __u32 crc32_table[256] = {
	0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L,
	0x706af48fL, 0xe963a535L, 0x9e6495a3L, 0x0edb8832L, 0x79dcb8a4L,
	0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L,
	0x90bf1d91L, 0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
	0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L, 0x136c9856L,
	0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L,
	0xfa0f3d63L, 0x8d080df5L, 0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L,
	0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
	0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L,
	0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L, 0x26d930acL, 0x51de003aL,
	0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L,
	0xb8bda50fL, 0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
	0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL, 0x76dc4190L,
	0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL,
	0x9fbfe4a5L, 0xe8b8d433L, 0x7807c9a2L, 0x0f00f934L, 0x9609a88eL,
	0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
	0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL,
	0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L, 0x65b0d9c6L, 0x12b7e950L,
	0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L,
	0xfbd44c65L, 0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
	0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL, 0x4369e96aL,
	0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L,
	0xaa0a4c5fL, 0xdd0d7cc9L, 0x5005713cL, 0x270241aaL, 0xbe0b1010L,
	0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
	0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L,
	0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL, 0xedb88320L, 0x9abfb3b6L,
	0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L,
	0x73dc1683L, 0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
	0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L, 0xf00f9344L,
	0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL,
	0x196c3671L, 0x6e6b06e7L, 0xfed41b76L, 0x89d32be0L, 0x10da7a5aL,
	0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
	0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L,
	0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL, 0xd80d2bdaL, 0xaf0a1b4cL,
	0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL,
	0x4669be79L, 0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
	0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL, 0xc5ba3bbeL,
	0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L,
	0x2cd99e8bL, 0x5bdeae1dL, 0x9b64c2b0L, 0xec63f226L, 0x756aa39cL,
	0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
	0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL,
	0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L, 0x86d3d2d4L, 0xf1d4e242L,
	0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L,
	0x18b74777L, 0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
	0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L, 0xa00ae278L,
	0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L,
	0x4969474dL, 0x3e6e77dbL, 0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L,
	0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
	0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L,
	0xcdd70693L, 0x54de5729L, 0x23d967bfL, 0xb3667a2eL, 0xc4614ab8L,
	0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL,
	0x2d02ef8dL
};
#endif /* HOSTAP_USE_CRYPTO_API */


static void * prism2_wep_init(int keyidx)
{
	struct prism2_wep_data *priv;

#ifdef NEW_MODULE_CODE
	if (!try_module_get(THIS_MODULE))
		return NULL;
#else
	MOD_INC_USE_COUNT;
#endif

	priv = (struct prism2_wep_data *) kmalloc(sizeof(*priv), GFP_ATOMIC);
	if (priv == NULL) {
#ifdef NEW_MODULE_CODE
		module_put(THIS_MODULE);
#else
		MOD_DEC_USE_COUNT;
#endif
		goto fail;
	}
	memset(priv, 0, sizeof(*priv));
	priv->key_idx = keyidx;

#ifdef HOSTAP_USE_CRYPTO_API
	priv->tfm = crypto_alloc_tfm("arc4", 0);
	if (priv->tfm == NULL) {
		printk(KERN_DEBUG "hostap_crypt_wep: could not allocate "
		       "crypto API arc4\n");
		goto fail;
	}
#endif /* HOSTAP_USE_CRYPTO_API */

	/* start WEP IV from a random value */
	get_random_bytes(&priv->iv, 4);

	return priv;

fail:
	if (priv) {
#ifdef HOSTAP_USE_CRYPTO_API
		if (priv->tfm)
			crypto_free_tfm(priv->tfm);
#endif /* HOSTAP_USE_CRYPTO_API */
		kfree(priv);
	}
#ifdef NEW_MODULE_CODE
	module_put(THIS_MODULE);
#else
	MOD_DEC_USE_COUNT;
#endif
	return NULL;
}


static void prism2_wep_deinit(void *priv)
{
#ifdef HOSTAP_USE_CRYPTO_API
	struct prism2_wep_data *_priv = priv;
	if (_priv && _priv->tfm)
		crypto_free_tfm(_priv->tfm);
#endif /* HOSTAP_USE_CRYPTO_API */
	kfree(priv);
#ifdef NEW_MODULE_CODE
	module_put(THIS_MODULE);
#else
	MOD_DEC_USE_COUNT;
#endif
}


/* Perform WEP encryption on given skb that has at least 4 bytes of headroom
 * for IV and 4 bytes of tailroom for ICV. Both IV and ICV will be transmitted,
 * so the payload length increases with 8 bytes.
 *
 * WEP frame payload: IV + TX key idx, RC4(data), ICV = RC4(CRC32(data))
 */
static int prism2_wep_encrypt(struct sk_buff *skb, int hdr_len, void *priv)
{
	struct prism2_wep_data *wep = priv;
	u32 crc, klen, len;
	u8 key[WEP_KEY_LEN + 3];
#ifdef HOSTAP_USE_CRYPTO_API
	u8 *pos, *icv;
	struct scatterlist sg;
#else /* HOSTAP_USE_CRYPTO_API */
	u32 i, j, k;
	u8 S[256];
	u8 kpos, *pos;
#define S_SWAP(a,b) do { u8 t = S[a]; S[a] = S[b]; S[b] = t; } while(0)
#endif /* HOSTAP_USE_CRYPTO_API */

	if (skb_headroom(skb) < 4 || skb_tailroom(skb) < 4 ||
	    skb->len < hdr_len)
		return -1;

	len = skb->len - hdr_len;
	pos = skb_push(skb, 4);
	memmove(pos, pos + 4, hdr_len);
	pos += hdr_len;

	klen = 3 + wep->key_len;

	wep->iv++;

	/* Fluhrer, Mantin, and Shamir have reported weaknesses in the key
	 * scheduling algorithm of RC4. At least IVs (KeyByte + 3, 0xff, N)
	 * can be used to speedup attacks, so avoid using them. */
	if ((wep->iv & 0xff00) == 0xff00) {
		u8 B = (wep->iv >> 16) & 0xff;
		if (B >= 3 && B < klen)
			wep->iv += 0x0100;
	}

	/* Prepend 24-bit IV to RC4 key and TX frame */
	*pos++ = key[0] = (wep->iv >> 16) & 0xff;
	*pos++ = key[1] = (wep->iv >> 8) & 0xff;
	*pos++ = key[2] = wep->iv & 0xff;
	*pos++ = wep->key_idx << 6;

	/* Copy rest of the WEP key (the secret part) */
	memcpy(key + 3, wep->key, wep->key_len);

#ifdef HOSTAP_USE_CRYPTO_API

	/* Append little-endian CRC32 and encrypt it to produce ICV */
	crc = ~crc32_le(~0, pos, len);
	icv = skb_put(skb, 4);
	icv[0] = crc;
	icv[1] = crc >> 8;
	icv[2] = crc >> 16;
	icv[3] = crc >> 24;

	crypto_cipher_setkey(wep->tfm, key, klen);
	sg.page = virt_to_page(pos);
	sg.offset = offset_in_page(pos);
	sg.length = len + 4;
	crypto_cipher_encrypt(wep->tfm, &sg, &sg, len + 4);

#else /* HOSTAP_USE_CRYPTO_API */

	/* Setup RC4 state */
	for (i = 0; i < 256; i++)
		S[i] = i;
	j = 0;
	kpos = 0;
	for (i = 0; i < 256; i++) {
		j = (j + S[i] + key[kpos]) & 0xff;
		kpos++;
		if (kpos >= klen)
			kpos = 0;
		S_SWAP(i, j);
	}

	/* Compute CRC32 over unencrypted data and apply RC4 to data */
	crc = ~0;
	i = j = 0;
	for (k = 0; k < len; k++) {
		crc = crc32_table[(crc ^ *pos) & 0xff] ^ (crc >> 8);
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		S_SWAP(i, j);
		*pos++ ^= S[(S[i] + S[j]) & 0xff];
	}
	crc = ~crc;

	/* Append little-endian CRC32 and encrypt it to produce ICV */
	pos = skb_put(skb, 4);
	pos[0] = crc;
	pos[1] = crc >> 8;
	pos[2] = crc >> 16;
	pos[3] = crc >> 24;
	for (k = 0; k < 4; k++) {
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		S_SWAP(i, j);
		*pos++ ^= S[(S[i] + S[j]) & 0xff];
	}

#endif /* HOSTAP_USE_CRYPTO_API */

	return 0;
}


/* Perform WEP decryption on given buffer. Buffer includes whole WEP part of
 * the frame: IV (4 bytes), encrypted payload (including SNAP header),
 * ICV (4 bytes). len includes both IV and ICV.
 *
 * Returns 0 if frame was decrypted successfully and ICV was correct and -1 on
 * failure. If frame is OK, IV and ICV will be removed.
 */
static int prism2_wep_decrypt(struct sk_buff *skb, int hdr_len, void *priv)
{
	struct prism2_wep_data *wep = priv;
	u32 crc, klen, plen;
	u8 key[WEP_KEY_LEN + 3];
	u8 keyidx, *pos, icv[4];
#ifdef HOSTAP_USE_CRYPTO_API
	struct scatterlist sg;
#else /* HOSTAP_USE_CRYPTO_API */
	u32 i, j, k;
	u8 S[256], kpos;
#endif /* HOSTAP_USE_CRYPTO_API */

	if (skb->len < hdr_len + 8)
		return -1;

	pos = skb->data + hdr_len;
	key[0] = *pos++;
	key[1] = *pos++;
	key[2] = *pos++;
	keyidx = *pos++ >> 6;
	if (keyidx != wep->key_idx)
		return -1;

	klen = 3 + wep->key_len;

	/* Copy rest of the WEP key (the secret part) */
	memcpy(key + 3, wep->key, wep->key_len);

#ifdef HOSTAP_USE_CRYPTO_API

	/* Apply RC4 to data and compute CRC32 over decrypted data */
	plen = skb->len - hdr_len - 8;

	crypto_cipher_setkey(wep->tfm, key, klen);
	sg.page = virt_to_page(pos);
	sg.offset = offset_in_page(pos);
	sg.length = plen + 4;
	crypto_cipher_decrypt(wep->tfm, &sg, &sg, plen + 4);

	crc = ~crc32_le(~0, pos, plen);
	icv[0] = crc;
	icv[1] = crc >> 8;
	icv[2] = crc >> 16;
	icv[3] = crc >> 24;
	if (memcmp(icv, pos + plen, 4) != 0) {
		/* ICV mismatch - drop frame */
		return -2;
	}

#else /* HOSTAP_USE_CRYPTO_API */

	/* Setup RC4 state */
	for (i = 0; i < 256; i++)
		S[i] = i;
	j = 0;
	kpos = 0;
	for (i = 0; i < 256; i++) {
		j = (j + S[i] + key[kpos]) & 0xff;
		kpos++;
		if (kpos >= klen)
			kpos = 0;
		S_SWAP(i, j);
	}

	/* Apply RC4 to data and compute CRC32 over decrypted data */
	plen = skb->len - hdr_len - 8;
	crc = ~0;
	i = j = 0;
	for (k = 0; k < plen; k++) {
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		S_SWAP(i, j);
		*pos ^= S[(S[i] + S[j]) & 0xff];
		crc = crc32_table[(crc ^ *pos) & 0xff] ^ (crc >> 8);
		pos++;
	}
	crc = ~crc;

	/* Encrypt little-endian CRC32 and verify that it matches with the
	 * received ICV */
	icv[0] = crc;
	icv[1] = crc >> 8;
	icv[2] = crc >> 16;
	icv[3] = crc >> 24;
	for (k = 0; k < 4; k++) {
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		S_SWAP(i, j);
		if ((icv[k] ^ S[(S[i] + S[j]) & 0xff]) != *pos++) {
			/* ICV mismatch - drop frame */
			return -2;
		}
	}

#endif /* HOSTAP_USE_CRYPTO_API */

	/* Remove IV and ICV */
	memmove(skb->data + 4, skb->data, hdr_len);
	skb_pull(skb, 4);
	skb_trim(skb, skb->len - 4);

	return 0;
}


static int prism2_wep_set_key(void *key, int len, u8 *seq, void *priv)
{
	struct prism2_wep_data *wep = priv;

	if (len < 0 || len > WEP_KEY_LEN)
		return -1;

	memcpy(wep->key, key, len);
	wep->key_len = len;

	return 0;
}


static int prism2_wep_get_key(void *key, int len, u8 *seq, void *priv)
{
	struct prism2_wep_data *wep = priv;

	if (len < wep->key_len)
		return -1;

	memcpy(key, wep->key, wep->key_len);

	return wep->key_len;
}


static char * prism2_wep_print_stats(char *p, void *priv)
{
	struct prism2_wep_data *wep = priv;
	p += sprintf(p, "key[%d] alg=WEP len=%d\n",
		     wep->key_idx, wep->key_len);
	return p;
}


static struct hostap_crypto_ops hostap_crypt_wep = {
	.name			= "WEP",
	.init			= prism2_wep_init,
	.deinit			= prism2_wep_deinit,
	.encrypt_mpdu		= prism2_wep_encrypt,
	.decrypt_mpdu		= prism2_wep_decrypt,
	.encrypt_msdu		= NULL,
	.decrypt_msdu		= NULL,
	.set_key		= prism2_wep_set_key,
	.get_key		= prism2_wep_get_key,
	.print_stats		= prism2_wep_print_stats,
	.extra_prefix_len	= 4 /* IV */,
	.extra_postfix_len	= 4 /* ICV */
};


static int __init hostap_crypto_wep_init(void)
{
	if (hostap_register_crypto_ops(&hostap_crypt_wep) < 0)
		return -1;

	return 0;
}


static void __exit hostap_crypto_wep_exit(void)
{
	hostap_unregister_crypto_ops(&hostap_crypt_wep);
}


module_init(hostap_crypto_wep_init);
module_exit(hostap_crypto_wep_exit);
