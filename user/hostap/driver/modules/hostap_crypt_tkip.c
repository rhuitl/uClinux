/*
 * Host AP crypt: host-based TKIP encryption implementation for Host AP driver
 *
 * Copyright (c) 2003-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */

#include <linux/config.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <asm/string.h>

#include "hostap_crypt.h"
#include "hostap_compat.h"
#include "hostap_wext.h"
#include "hostap_wlan.h"
#include "hostap_80211.h"
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
MODULE_DESCRIPTION("Host AP crypt: TKIP");
MODULE_LICENSE("GPL");


struct hostap_tkip_data {
#define TKIP_KEY_LEN 32
	u8 key[TKIP_KEY_LEN];
	int key_set;

	u32 tx_iv32;
	u16 tx_iv16;
	u16 tx_ttak[5];
	int tx_phase1_done;

	u32 rx_iv32;
	u16 rx_iv16;
	u16 rx_ttak[5];
	int rx_phase1_done;
	u32 rx_iv32_new;
	u16 rx_iv16_new;

	u32 dot11RSNAStatsTKIPReplays;
	u32 dot11RSNAStatsTKIPICVErrors;
	u32 dot11RSNAStatsTKIPLocalMICFailures;

	int key_idx;

#ifdef HOSTAP_USE_CRYPTO_API
	struct crypto_tfm *tfm_arc4;
	struct crypto_tfm *tfm_michael;
#endif /* HOSTAP_USE_CRYPTO_API */

	/* scratch buffers for virt_to_page() (crypto API) */
	u8 rx_hdr[16], tx_hdr[16];
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


static void * hostap_tkip_init(int key_idx)
{
	struct hostap_tkip_data *priv;

#ifdef NEW_MODULE_CODE
	if (!try_module_get(THIS_MODULE))
		return NULL;
#else
	MOD_INC_USE_COUNT;
#endif

	priv = (struct hostap_tkip_data *) kmalloc(sizeof(*priv), GFP_ATOMIC);
	if (priv == NULL)
		goto fail;
	memset(priv, 0, sizeof(*priv));
	priv->key_idx = key_idx;

#ifdef HOSTAP_USE_CRYPTO_API
	priv->tfm_arc4 = crypto_alloc_tfm("arc4", 0);
	if (priv->tfm_arc4 == NULL) {
		printk(KERN_DEBUG "hostap_crypt_tkip: could not allocate "
		       "crypto API arc4\n");
		goto fail;
	}

	priv->tfm_michael = crypto_alloc_tfm("michael_mic", 0);
	if (priv->tfm_michael == NULL) {
		printk(KERN_DEBUG "hostap_crypt_tkip: could not allocate "
		       "crypto API michael_mic\n");
		goto fail;
	}
#endif /* HOSTAP_USE_CRYPTO_API */

	return priv;

fail:
	if (priv) {
#ifdef HOSTAP_USE_CRYPTO_API
		if (priv->tfm_michael)
			crypto_free_tfm(priv->tfm_michael);
		if (priv->tfm_arc4)
			crypto_free_tfm(priv->tfm_arc4);
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


static void hostap_tkip_deinit(void *priv)
{
#ifdef HOSTAP_USE_CRYPTO_API
	struct hostap_tkip_data *_priv = priv;
	if (_priv && _priv->tfm_michael)
		crypto_free_tfm(_priv->tfm_michael);
	if (_priv && _priv->tfm_arc4)
		crypto_free_tfm(_priv->tfm_arc4);
#endif /* HOSTAP_USE_CRYPTO_API */
	kfree(priv);
#ifdef NEW_MODULE_CODE
	module_put(THIS_MODULE);
#else
	MOD_DEC_USE_COUNT;
#endif
}


static inline u16 RotR1(u16 val)
{
	return (val >> 1) | (val << 15);
}


static inline u8 Lo8(u16 val)
{
	return val & 0xff;
}


static inline u8 Hi8(u16 val)
{
	return val >> 8;
}


static inline u16 Lo16(u32 val)
{
	return val & 0xffff;
}


static inline u16 Hi16(u32 val)
{
	return val >> 16;
}


static inline u16 Mk16(u8 hi, u8 lo)
{
	return lo | (((u16) hi) << 8);
}


static inline u16 Mk16_le(u16 *v)
{
	return le16_to_cpu(*v);
}


static const u16 Sbox[256] =
{
	0xC6A5, 0xF884, 0xEE99, 0xF68D, 0xFF0D, 0xD6BD, 0xDEB1, 0x9154,
	0x6050, 0x0203, 0xCEA9, 0x567D, 0xE719, 0xB562, 0x4DE6, 0xEC9A,
	0x8F45, 0x1F9D, 0x8940, 0xFA87, 0xEF15, 0xB2EB, 0x8EC9, 0xFB0B,
	0x41EC, 0xB367, 0x5FFD, 0x45EA, 0x23BF, 0x53F7, 0xE496, 0x9B5B,
	0x75C2, 0xE11C, 0x3DAE, 0x4C6A, 0x6C5A, 0x7E41, 0xF502, 0x834F,
	0x685C, 0x51F4, 0xD134, 0xF908, 0xE293, 0xAB73, 0x6253, 0x2A3F,
	0x080C, 0x9552, 0x4665, 0x9D5E, 0x3028, 0x37A1, 0x0A0F, 0x2FB5,
	0x0E09, 0x2436, 0x1B9B, 0xDF3D, 0xCD26, 0x4E69, 0x7FCD, 0xEA9F,
	0x121B, 0x1D9E, 0x5874, 0x342E, 0x362D, 0xDCB2, 0xB4EE, 0x5BFB,
	0xA4F6, 0x764D, 0xB761, 0x7DCE, 0x527B, 0xDD3E, 0x5E71, 0x1397,
	0xA6F5, 0xB968, 0x0000, 0xC12C, 0x4060, 0xE31F, 0x79C8, 0xB6ED,
	0xD4BE, 0x8D46, 0x67D9, 0x724B, 0x94DE, 0x98D4, 0xB0E8, 0x854A,
	0xBB6B, 0xC52A, 0x4FE5, 0xED16, 0x86C5, 0x9AD7, 0x6655, 0x1194,
	0x8ACF, 0xE910, 0x0406, 0xFE81, 0xA0F0, 0x7844, 0x25BA, 0x4BE3,
	0xA2F3, 0x5DFE, 0x80C0, 0x058A, 0x3FAD, 0x21BC, 0x7048, 0xF104,
	0x63DF, 0x77C1, 0xAF75, 0x4263, 0x2030, 0xE51A, 0xFD0E, 0xBF6D,
	0x814C, 0x1814, 0x2635, 0xC32F, 0xBEE1, 0x35A2, 0x88CC, 0x2E39,
	0x9357, 0x55F2, 0xFC82, 0x7A47, 0xC8AC, 0xBAE7, 0x322B, 0xE695,
	0xC0A0, 0x1998, 0x9ED1, 0xA37F, 0x4466, 0x547E, 0x3BAB, 0x0B83,
	0x8CCA, 0xC729, 0x6BD3, 0x283C, 0xA779, 0xBCE2, 0x161D, 0xAD76,
	0xDB3B, 0x6456, 0x744E, 0x141E, 0x92DB, 0x0C0A, 0x486C, 0xB8E4,
	0x9F5D, 0xBD6E, 0x43EF, 0xC4A6, 0x39A8, 0x31A4, 0xD337, 0xF28B,
	0xD532, 0x8B43, 0x6E59, 0xDAB7, 0x018C, 0xB164, 0x9CD2, 0x49E0,
	0xD8B4, 0xACFA, 0xF307, 0xCF25, 0xCAAF, 0xF48E, 0x47E9, 0x1018,
	0x6FD5, 0xF088, 0x4A6F, 0x5C72, 0x3824, 0x57F1, 0x73C7, 0x9751,
	0xCB23, 0xA17C, 0xE89C, 0x3E21, 0x96DD, 0x61DC, 0x0D86, 0x0F85,
	0xE090, 0x7C42, 0x71C4, 0xCCAA, 0x90D8, 0x0605, 0xF701, 0x1C12,
	0xC2A3, 0x6A5F, 0xAEF9, 0x69D0, 0x1791, 0x9958, 0x3A27, 0x27B9,
	0xD938, 0xEB13, 0x2BB3, 0x2233, 0xD2BB, 0xA970, 0x0789, 0x33A7,
	0x2DB6, 0x3C22, 0x1592, 0xC920, 0x8749, 0xAAFF, 0x5078, 0xA57A,
	0x038F, 0x59F8, 0x0980, 0x1A17, 0x65DA, 0xD731, 0x84C6, 0xD0B8,
	0x82C3, 0x29B0, 0x5A77, 0x1E11, 0x7BCB, 0xA8FC, 0x6DD6, 0x2C3A,
};


static inline u16 _S_(u16 v)
{
	u16 t = Sbox[Hi8(v)];
	return Sbox[Lo8(v)] ^ ((t << 8) | (t >> 8));
}


#define PHASE1_LOOP_COUNT 8

static void tkip_mixing_phase1(u16 *TTAK, const u8 *TK, const u8 *TA, u32 IV32)
{
	int i, j;

	/* Initialize the 80-bit TTAK from TSC (IV32) and TA[0..5] */
	TTAK[0] = Lo16(IV32);
	TTAK[1] = Hi16(IV32);
	TTAK[2] = Mk16(TA[1], TA[0]);
	TTAK[3] = Mk16(TA[3], TA[2]);
	TTAK[4] = Mk16(TA[5], TA[4]);

	for (i = 0; i < PHASE1_LOOP_COUNT; i++) {
		j = 2 * (i & 1);
		TTAK[0] += _S_(TTAK[4] ^ Mk16(TK[1 + j], TK[0 + j]));
		TTAK[1] += _S_(TTAK[0] ^ Mk16(TK[5 + j], TK[4 + j]));
		TTAK[2] += _S_(TTAK[1] ^ Mk16(TK[9 + j], TK[8 + j]));
		TTAK[3] += _S_(TTAK[2] ^ Mk16(TK[13 + j], TK[12 + j]));
		TTAK[4] += _S_(TTAK[3] ^ Mk16(TK[1 + j], TK[0 + j])) + i;
	}
}


static void tkip_mixing_phase2(u8 *WEPSeed, const u8 *TK, const u16 *TTAK,
			       u16 IV16)
{
	/* Make temporary area overlap WEP seed so that the final copy can be
	 * avoided on little endian hosts. */
	u16 *PPK = (u16 *) &WEPSeed[4];

	/* Step 1 - make copy of TTAK and bring in TSC */
	PPK[0] = TTAK[0];
	PPK[1] = TTAK[1];
	PPK[2] = TTAK[2];
	PPK[3] = TTAK[3];
	PPK[4] = TTAK[4];
	PPK[5] = TTAK[4] + IV16;

	/* Step 2 - 96-bit bijective mixing using S-box */
	PPK[0] += _S_(PPK[5] ^ Mk16_le((u16 *) &TK[0]));
	PPK[1] += _S_(PPK[0] ^ Mk16_le((u16 *) &TK[2]));
	PPK[2] += _S_(PPK[1] ^ Mk16_le((u16 *) &TK[4]));
	PPK[3] += _S_(PPK[2] ^ Mk16_le((u16 *) &TK[6]));
	PPK[4] += _S_(PPK[3] ^ Mk16_le((u16 *) &TK[8]));
	PPK[5] += _S_(PPK[4] ^ Mk16_le((u16 *) &TK[10]));

	PPK[0] += RotR1(PPK[5] ^ Mk16_le((u16 *) &TK[12]));
	PPK[1] += RotR1(PPK[0] ^ Mk16_le((u16 *) &TK[14]));
	PPK[2] += RotR1(PPK[1]);
	PPK[3] += RotR1(PPK[2]);
	PPK[4] += RotR1(PPK[3]);
	PPK[5] += RotR1(PPK[4]);

	/* Step 3 - bring in last of TK bits, assign 24-bit WEP IV value
	 * WEPSeed[0..2] is transmitted as WEP IV */
	WEPSeed[0] = Hi8(IV16);
	WEPSeed[1] = (Hi8(IV16) | 0x20) & 0x7F;
	WEPSeed[2] = Lo8(IV16);
	WEPSeed[3] = Lo8((PPK[5] ^ Mk16_le((u16 *) &TK[0])) >> 1);

#ifdef __BIG_ENDIAN
	{
		int i;
		for (i = 0; i < 6; i++)
			PPK[i] = (PPK[i] << 8) | (PPK[i] >> 8);
	}
#endif
}


#ifndef HOSTAP_USE_CRYPTO_API
static void hostap_wep_encrypt(u8 *key, u8 *buf, size_t buflen, u8 *icv)
{
	u32 i, j, k, crc;
	u8 S[256];
	u8 *pos;
#define S_SWAP(a,b) do { u8 t = S[a]; S[a] = S[b]; S[b] = t; } while(0)

	/* Setup RC4 state */
	for (i = 0; i < 256; i++)
		S[i] = i;
	j = 0;
	for (i = 0; i < 256; i++) {
		j = (j + S[i] + key[i & 0x0f]) & 0xff;
		S_SWAP(i, j);
	}

	/* Compute CRC32 over unencrypted data and apply RC4 to data */
	crc = ~0;
	i = j = 0;
	pos = buf;
	for (k = 0; k < buflen; k++) {
		crc = crc32_table[(crc ^ *pos) & 0xff] ^ (crc >> 8);
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		S_SWAP(i, j);
		*pos++ ^= S[(S[i] + S[j]) & 0xff];
	}
	crc = ~crc;

	/* Append little-endian CRC32 and encrypt it to produce ICV */
	pos = icv;
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
}
#endif /* HOSTAP_USE_CRYPTO_API */


static int hostap_tkip_encrypt(struct sk_buff *skb, int hdr_len, void *priv)
{
	struct hostap_tkip_data *tkey = priv;
	int len;
	u8 rc4key[16], *pos, *icv;
	struct hostap_ieee80211_hdr *hdr;
#ifdef HOSTAP_USE_CRYPTO_API
	u32 crc;
	struct scatterlist sg;
#endif /* HOSTAP_USE_CRYPTO_API */

	if (skb_headroom(skb) < 8 || skb_tailroom(skb) < 4 ||
	    skb->len < hdr_len)
		return -1;

	hdr = (struct hostap_ieee80211_hdr *) skb->data;
	if (!tkey->tx_phase1_done) {
		tkip_mixing_phase1(tkey->tx_ttak, tkey->key, hdr->addr2,
				   tkey->tx_iv32);
		tkey->tx_phase1_done = 1;
	}
	tkip_mixing_phase2(rc4key, tkey->key, tkey->tx_ttak, tkey->tx_iv16);

	len = skb->len - hdr_len;
	pos = skb_push(skb, 8);
	memmove(pos, pos + 8, hdr_len);
	pos += hdr_len;
	icv = skb_put(skb, 4);

	*pos++ = rc4key[0];
	*pos++ = rc4key[1];
	*pos++ = rc4key[2];
	*pos++ = (tkey->key_idx << 6) | (1 << 5) /* Ext IV included */;
	*pos++ = tkey->tx_iv32 & 0xff;
	*pos++ = (tkey->tx_iv32 >> 8) & 0xff;
	*pos++ = (tkey->tx_iv32 >> 16) & 0xff;
	*pos++ = (tkey->tx_iv32 >> 24) & 0xff;

#ifdef HOSTAP_USE_CRYPTO_API
	crc = ~crc32_le(~0, pos, len);
	icv[0] = crc;
	icv[1] = crc >> 8;
	icv[2] = crc >> 16;
	icv[3] = crc >> 24;

	crypto_cipher_setkey(tkey->tfm_arc4, rc4key, 16);
	sg.page = virt_to_page(pos);
	sg.offset = offset_in_page(pos);
	sg.length = len + 4;
	crypto_cipher_encrypt(tkey->tfm_arc4, &sg, &sg, len + 4);
#else /* HOSTAP_USE_CRYPTO_API */
	hostap_wep_encrypt(rc4key, pos, len, icv);
#endif /* HOSTAP_USE_CRYPTO_API */

	tkey->tx_iv16++;
	if (tkey->tx_iv16 == 0) {
		tkey->tx_phase1_done = 0;
		tkey->tx_iv32++;
	}

	return 0;
}


#ifndef HOSTAP_USE_CRYPTO_API
static int hostap_wep_decrypt(u8 *key, u8 *buf, size_t plen)
{
	u32 i, j, k, crc;
	u8 S[256];
	u8 *pos, icv[4];

	/* Setup RC4 state */
	for (i = 0; i < 256; i++)
		S[i] = i;
	j = 0;
	for (i = 0; i < 256; i++) {
		j = (j + S[i] + key[i & 0x0f]) & 0xff;
		S_SWAP(i, j);
	}

	/* Apply RC4 to data and compute CRC32 over decrypted data */
	pos = buf;
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
			return -1;
		}
	}

	return 0;
}
#endif /* HOSTAP_USE_CRYPTO_API */


static int hostap_tkip_decrypt(struct sk_buff *skb, int hdr_len, void *priv)
{
	struct hostap_tkip_data *tkey = priv;
	u8 rc4key[16];
	u8 keyidx, *pos;
	u32 iv32;
	u16 iv16;
	struct hostap_ieee80211_hdr *hdr;
#ifdef HOSTAP_USE_CRYPTO_API
	u8 icv[4];
	u32 crc;
	struct scatterlist sg;
	int plen;
#endif /* HOSTAP_USE_CRYPTO_API */

	if (skb->len < hdr_len + 8 + 4)
		return -1;

	hdr = (struct hostap_ieee80211_hdr *) skb->data;
	pos = skb->data + hdr_len;
	keyidx = pos[3];
	if (!(keyidx & (1 << 5))) {
		if (net_ratelimit()) {
			printk(KERN_DEBUG "TKIP: received packet without ExtIV"
			       " flag from " MACSTR "\n", MAC2STR(hdr->addr2));
		}
		return -2;
	}
	keyidx >>= 6;
	if (tkey->key_idx != keyidx) {
		printk(KERN_DEBUG "TKIP: RX tkey->key_idx=%d frame "
		       "keyidx=%d priv=%p\n", tkey->key_idx, keyidx, priv);
		return -6;
	}
	if (!tkey->key_set) {
		if (net_ratelimit()) {
			printk(KERN_DEBUG "TKIP: received packet from " MACSTR
			       " with keyid=%d that does not have a configured"
			       " key\n", MAC2STR(hdr->addr2), keyidx);
		}
		return -3;
	}
	iv16 = (pos[0] << 8) | pos[2];
	iv32 = pos[4] | (pos[5] << 8) | (pos[6] << 16) | (pos[7] << 24);
	pos += 8;

	if (iv32 < tkey->rx_iv32 ||
	    (iv32 == tkey->rx_iv32 && iv16 <= tkey->rx_iv16)) {
		if (net_ratelimit()) {
			printk(KERN_DEBUG "TKIP: replay detected: STA=" MACSTR
			       " previous TSC %08x%04x received TSC "
			       "%08x%04x\n", MAC2STR(hdr->addr2),
			       tkey->rx_iv32, tkey->rx_iv16, iv32, iv16);
		}
		tkey->dot11RSNAStatsTKIPReplays++;
		return -4;
	}

	if (iv32 != tkey->rx_iv32 || !tkey->rx_phase1_done) {
		tkip_mixing_phase1(tkey->rx_ttak, tkey->key, hdr->addr2, iv32);
		tkey->rx_phase1_done = 1;
	}
	tkip_mixing_phase2(rc4key, tkey->key, tkey->rx_ttak, iv16);

#ifdef HOSTAP_USE_CRYPTO_API
	plen = skb->len - hdr_len - 12;

	crypto_cipher_setkey(tkey->tfm_arc4, rc4key, 16);
	sg.page = virt_to_page(pos);
	sg.offset = offset_in_page(pos);
	sg.length = plen + 4;
	crypto_cipher_decrypt(tkey->tfm_arc4, &sg, &sg, plen + 4);

	crc = ~crc32_le(~0, pos, plen);
	icv[0] = crc;
	icv[1] = crc >> 8;
	icv[2] = crc >> 16;
	icv[3] = crc >> 24;
	if (memcmp(icv, pos + plen, 4) != 0) {
#else /* HOSTAP_USE_CRYPTO_API */
	if (hostap_wep_decrypt(rc4key, pos, skb->len - hdr_len - 12)) {
#endif /* HOSTAP_USE_CRYPTO_API */
		if (iv32 != tkey->rx_iv32) {
			/* Previously cached Phase1 result was already lost, so
			 * it needs to be recalculated for the next packet. */
			tkey->rx_phase1_done = 0;
		}
		if (net_ratelimit()) {
			printk(KERN_DEBUG "TKIP: ICV error detected: STA="
			       MACSTR "\n", MAC2STR(hdr->addr2));
		}
		tkey->dot11RSNAStatsTKIPICVErrors++;
		return -5;
	}

	/* Update real counters only after Michael MIC verification has
	 * completed */
	tkey->rx_iv32_new = iv32;
	tkey->rx_iv16_new = iv16;

	/* Remove IV and ICV */
	memmove(skb->data + 8, skb->data, hdr_len);
	skb_pull(skb, 8);
	skb_trim(skb, skb->len - 4);

	return keyidx;
}


#ifdef HOSTAP_USE_CRYPTO_API
static int michael_mic(struct hostap_tkip_data *tkey, u8 *key, u8 *hdr,
		       u8 *data, size_t data_len, u8 *mic)
{
	struct scatterlist sg[2];

	if (tkey->tfm_michael == NULL) {
		printk(KERN_WARNING "michael_mic: tfm_michael == NULL\n");
		return -1;
	}
	sg[0].page = virt_to_page(hdr);
	sg[0].offset = offset_in_page(hdr);
	sg[0].length = 16;

	sg[1].page = virt_to_page(data);
	sg[1].offset = offset_in_page(data);
	sg[1].length = data_len;

	crypto_digest_init(tkey->tfm_michael);
	crypto_digest_setkey(tkey->tfm_michael, key, 8);
	crypto_digest_update(tkey->tfm_michael, sg, 2);
	crypto_digest_final(tkey->tfm_michael, mic);

	return 0;
}

#else /* HOSTAP_USE_CRYPTO_API */

static inline u32 rotl(u32 val, int bits)
{
	return (val << bits) | (val >> (32 - bits));
}


static inline u32 rotr(u32 val, int bits)
{
	return (val >> bits) | (val << (32 - bits));
}


static inline u32 xswap(u32 val)
{
	return ((val & 0x00ff00ff) << 8) | ((val & 0xff00ff00) >> 8);
}


#define michael_block(l, r)	\
do {				\
	r ^= rotl(l, 17);	\
	l += r;			\
	r ^= xswap(l);		\
	l += r;			\
	r ^= rotl(l, 3);	\
	l += r;			\
	r ^= rotr(l, 2);	\
	l += r;			\
} while (0)


static inline u32 get_le32(u8 *p)
{
	return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}


static inline void put_le32(u8 *p, u32 v)
{
	p[0] = v;
	p[1] = v >> 8;
	p[2] = v >> 16;
	p[3] = v >> 24;
}


static int michael_mic(struct hostap_tkip_data *tkey, u8 *key, u8 *hdr,
		       u8 *data, size_t data_len, u8 *mic)
{
	u32 l, r;
	int i, blocks, last;

	l = get_le32(key);
	r = get_le32(key + 4);

	/* Michael MIC pseudo header: DA, SA, 3 x 0, Priority */
	l ^= get_le32(hdr);
	michael_block(l, r);
	l ^= get_le32(&hdr[4]);
	michael_block(l, r);
	l ^= get_le32(&hdr[8]);
	michael_block(l, r);
	l ^= get_le32(&hdr[12]);
	michael_block(l, r);

	/* 32-bit blocks of data */
	blocks = data_len / 4;
	last = data_len % 4;
	for (i = 0; i < blocks; i++) {
		l ^= get_le32(&data[4 * i]);
		michael_block(l, r);
	}

	/* Last block and padding (0x5a, 4..7 x 0) */
	switch (last) {
	case 0:
		l ^= 0x5a;
		break;
	case 1:
		l ^= data[4 * i] | 0x5a00;
		break;
	case 2:
		l ^= data[4 * i] | (data[4 * i + 1] << 8) | 0x5a0000;
		break;
	case 3:
		l ^= data[4 * i] | (data[4 * i + 1] << 8) |
			(data[4 * i + 2] << 16) | 0x5a000000;
		break;
	}
	michael_block(l, r);
	/* l ^= 0; */
	michael_block(l, r);

	put_le32(mic, l);
	put_le32(mic + 4, r);
	return 0;
}
#endif /* HOSTAP_USE_CRYPTO_API */


static void michael_mic_hdr(struct sk_buff *skb, u8 *hdr)
{
	struct hostap_ieee80211_hdr *hdr11;

	hdr11 = (struct hostap_ieee80211_hdr *) skb->data;
	switch (le16_to_cpu(hdr11->frame_control) &
		(WLAN_FC_FROMDS | WLAN_FC_TODS)) {
	case WLAN_FC_TODS:
		memcpy(hdr, hdr11->addr3, ETH_ALEN); /* DA */
		memcpy(hdr + ETH_ALEN, hdr11->addr2, ETH_ALEN); /* SA */
		break;
	case WLAN_FC_FROMDS:
		memcpy(hdr, hdr11->addr1, ETH_ALEN); /* DA */
		memcpy(hdr + ETH_ALEN, hdr11->addr3, ETH_ALEN); /* SA */
		break;
	case WLAN_FC_FROMDS | WLAN_FC_TODS:
		memcpy(hdr, hdr11->addr3, ETH_ALEN); /* DA */
		memcpy(hdr + ETH_ALEN, hdr11->addr4, ETH_ALEN); /* SA */
		break;
	case 0:
		memcpy(hdr, hdr11->addr1, ETH_ALEN); /* DA */
		memcpy(hdr + ETH_ALEN, hdr11->addr2, ETH_ALEN); /* SA */
		break;
	}

	hdr[12] = 0; /* priority */
	hdr[13] = hdr[14] = hdr[15] = 0; /* reserved */
}


static int hostap_michael_mic_add(struct sk_buff *skb, int hdr_len, void *priv)
{
	struct hostap_tkip_data *tkey = priv;
	u8 *pos;

	if (skb_tailroom(skb) < 8 || skb->len < hdr_len) {
		printk(KERN_DEBUG "Invalid packet for Michael MIC add "
		       "(tailroom=%d hdr_len=%d skb->len=%d)\n",
		       skb_tailroom(skb), hdr_len, skb->len);
		return -1;
	}

	michael_mic_hdr(skb, tkey->tx_hdr);
	pos = skb_put(skb, 8);
	if (michael_mic(tkey, &tkey->key[16], tkey->tx_hdr,
			skb->data + hdr_len, skb->len - 8 - hdr_len, pos))
		return -1;

	return 0;
}


#if WIRELESS_EXT >= 15
static void hostap_michael_mic_failure(struct net_device *dev,
				       struct hostap_ieee80211_hdr *hdr,
				       int keyidx)
{
	union iwreq_data wrqu;
	char buf[128];

	/* TODO: needed parameters: count, keyid, key type, src address, TSC */
	sprintf(buf, "MLME-MICHAELMICFAILURE.indication(keyid=%d %scast addr="
		MACSTR ")", keyidx, hdr->addr1[0] & 0x01 ? "broad" : "uni",
		MAC2STR(hdr->addr2));
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.data.length = strlen(buf);
	wireless_send_event(dev, IWEVCUSTOM, &wrqu, buf);
}
#else /* WIRELESS_EXT >= 15 */
static inline void hostap_michael_mic_failure(struct net_device *dev,
					      struct hostap_ieee80211_hdr *hdr,
					      int keyidx)
{
}
#endif /* WIRELESS_EXT >= 15 */


static int hostap_michael_mic_verify(struct sk_buff *skb, int keyidx,
				     int hdr_len, void *priv)
{
	struct hostap_tkip_data *tkey = priv;
	u8 mic[8];

	if (!tkey->key_set)
		return -1;

	michael_mic_hdr(skb, tkey->rx_hdr);
	if (michael_mic(tkey, &tkey->key[24], tkey->rx_hdr,
			skb->data + hdr_len, skb->len - 8 - hdr_len, mic))
		return -1;
	if (memcmp(mic, skb->data + skb->len - 8, 8) != 0) {
		struct hostap_ieee80211_hdr *hdr;
		hdr = (struct hostap_ieee80211_hdr *) skb->data;
		printk(KERN_DEBUG "%s: Michael MIC verification failed for "
		       "MSDU from " MACSTR " keyidx=%d\n",
		       skb->dev ? skb->dev->name : "N/A", MAC2STR(hdr->addr2),
		       keyidx);
		if (skb->dev)
			hostap_michael_mic_failure(skb->dev, hdr, keyidx);
		tkey->dot11RSNAStatsTKIPLocalMICFailures++;
		return -1;
	}

	/* Update TSC counters for RX now that the packet verification has
	 * completed. */
	tkey->rx_iv32 = tkey->rx_iv32_new;
	tkey->rx_iv16 = tkey->rx_iv16_new;

	skb_trim(skb, skb->len - 8);

	return 0;
}


static int hostap_tkip_set_key(void *key, int len, u8 *seq, void *priv)
{
	struct hostap_tkip_data *tkey = priv;
	int keyidx;
#ifdef HOSTAP_USE_CRYPTO_API
	struct crypto_tfm *tfm = tkey->tfm_michael;
	struct crypto_tfm *tfm2 = tkey->tfm_arc4;
#endif /* HOSTAP_USE_CRYPTO_API */

	keyidx = tkey->key_idx;
	memset(tkey, 0, sizeof(*tkey));
	tkey->key_idx = keyidx;
#ifdef HOSTAP_USE_CRYPTO_API
	tkey->tfm_michael = tfm;
	tkey->tfm_arc4 = tfm2;
#endif /* HOSTAP_USE_CRYPTO_API */
	if (len == TKIP_KEY_LEN) {
		memcpy(tkey->key, key, TKIP_KEY_LEN);
		tkey->key_set = 1;
		tkey->tx_iv16 = 1; /* TSC is initialized to 1 */
		if (seq) {
			tkey->rx_iv32 = (seq[5] << 24) | (seq[4] << 16) |
				(seq[3] << 8) | seq[2];
			tkey->rx_iv16 = (seq[1] << 8) | seq[0];
		}
	} else if (len == 0) {
		tkey->key_set = 0;
	} else
		return -1;

	return 0;
}


static int hostap_tkip_get_key(void *key, int len, u8 *seq, void *priv)
{
	struct hostap_tkip_data *tkey = priv;

	if (len < TKIP_KEY_LEN)
		return -1;

	if (!tkey->key_set)
		return 0;
	memcpy(key, tkey->key, TKIP_KEY_LEN);

	if (seq) {
		/* Return the sequence number of the last transmitted frame. */
		u16 iv16 = tkey->tx_iv16;
		u32 iv32 = tkey->tx_iv32;
		if (iv16 == 0)
			iv32--;
		iv16--;
		seq[0] = tkey->tx_iv16;
		seq[1] = tkey->tx_iv16 >> 8;
		seq[2] = tkey->tx_iv32;
		seq[3] = tkey->tx_iv32 >> 8;
		seq[4] = tkey->tx_iv32 >> 16;
		seq[5] = tkey->tx_iv32 >> 24;
	}

	return TKIP_KEY_LEN;
}


static char * hostap_tkip_print_stats(char *p, void *priv)
{
	struct hostap_tkip_data *tkip = priv;
	p += sprintf(p, "key[%d] alg=TKIP key_set=%d "
		     "tx_pn=%02x%02x%02x%02x%02x%02x "
		     "rx_pn=%02x%02x%02x%02x%02x%02x "
		     "replays=%d icv_errors=%d local_mic_failures=%d\n",
		     tkip->key_idx, tkip->key_set,
		     (tkip->tx_iv32 >> 24) & 0xff,
		     (tkip->tx_iv32 >> 16) & 0xff,
		     (tkip->tx_iv32 >> 8) & 0xff,
		     tkip->tx_iv32 & 0xff,
		     (tkip->tx_iv16 >> 8) & 0xff,
		     tkip->tx_iv16 & 0xff,
		     (tkip->rx_iv32 >> 24) & 0xff,
		     (tkip->rx_iv32 >> 16) & 0xff,
		     (tkip->rx_iv32 >> 8) & 0xff,
		     tkip->rx_iv32 & 0xff,
		     (tkip->rx_iv16 >> 8) & 0xff,
		     tkip->rx_iv16 & 0xff,
		     tkip->dot11RSNAStatsTKIPReplays,
		     tkip->dot11RSNAStatsTKIPICVErrors,
		     tkip->dot11RSNAStatsTKIPLocalMICFailures);
	return p;
}


static struct hostap_crypto_ops hostap_crypt_tkip = {
	.name			= "TKIP",
	.init			= hostap_tkip_init,
	.deinit			= hostap_tkip_deinit,
	.encrypt_mpdu		= hostap_tkip_encrypt,
	.decrypt_mpdu		= hostap_tkip_decrypt,
	.encrypt_msdu		= hostap_michael_mic_add,
	.decrypt_msdu		= hostap_michael_mic_verify,
	.set_key		= hostap_tkip_set_key,
	.get_key		= hostap_tkip_get_key,
	.print_stats		= hostap_tkip_print_stats,
	.extra_prefix_len	= 4 + 4 /* IV + ExtIV */,
	.extra_postfix_len	= 8 + 4 /* MIC + ICV */
};


static int __init hostap_crypto_tkip_init(void)
{
	if (hostap_register_crypto_ops(&hostap_crypt_tkip) < 0)
		return -1;

	return 0;
}


static void __exit hostap_crypto_tkip_exit(void)
{
	hostap_unregister_crypto_ops(&hostap_crypt_tkip);
}


module_init(hostap_crypto_tkip_init);
module_exit(hostap_crypto_tkip_exit);
