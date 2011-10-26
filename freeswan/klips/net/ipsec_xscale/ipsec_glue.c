/*
 * IPSEC_GLUE interface code.
 * Copyright 2002 Intel Corporation All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */


/* To do: Note to myself try to compile these file first see to see if it's work */

char ipsec_sa_glue_c_version[] = "RCSID $Id: ipsec_glue.c,v 1.1 2004/05/11 00:38:42 danield Exp $";

#include <linux/config.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h> /* printk() */
#include <linux/spinlock.h>

#include "ipsec_param.h"

#ifdef MALLOC_SLAB
# include <linux/slab.h> /* kmalloc() */
#else /* MALLOC_SLAB */
# include <linux/malloc.h> /* kmalloc() */
#endif /* MALLOC_SLAB */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */

#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/ip.h>          /* struct iphdr */
#include <linux/in.h>          /* struct sockaddr_in */
#include <linux/skbuff.h>

#ifdef NET_21
# include <asm/uaccess.h>
# include <linux/in6.h>
#endif /* NET_21 */

#include <asm/checksum.h>
#include <net/ip.h>

#include "ipsec_glue_mbuf.h" 	/* The interface to glue mbuf 				*/
#include "ipsec_glue.h"		/* The interface to glue sa 				*/
#include "ipsec_glue_desc.h" 	/* The interface to glue desc 				*/

#include <freeswan.h>
#include "ipsec_netlink.h"
#include "ipsec_xform.h"	/* The interface to ipsec transform		 	*/
#include "ipsec_ah.h"
#include "ipsec_esp.h"
#include "ipsec_sa.h"
#include <pfkeyv2.h>
#include <pfkey.h>

#define AES_KEY_E_OFFSET_IN_TDB     8

extern spinlock_t tdb_lock;

extern int debug_xform;
	
/* Perform the encrytion for hardware accelaration funtion */
extern void ipsec_tunnel_start_xmit_cb( UINT32, IX_MBUF *, IX_MBUF *, IxCryptoAccStatus);

/* Perform the dencrytion for hardware accelaration funtion */
extern void ipsec_rcv_cb( UINT32, IX_MBUF *, IX_MBUF *, IxCryptoAccStatus);

/* Callback funtion for crypto context registration */
static IxCryptoAccPerformCompleteCallback PerformCallbk = NULL; 

/* Forward declaration of the show funtion */
#ifdef SA_GLUE_DEBUG
  void print_show_algo(void);
#endif /* SA_GLUE_DEBUG */

/* Crypto context 	*/
IxCryptoAccCtx cryptoAccCtx;

/* To do need to allocate this mbuf */
IX_MBUF *callbackmbuf = NULL;
IX_MBUF *pMbufPrimaryChainVar = NULL;
IX_MBUF *pMbufSecondaryChainVar = NULL;


void ipsec_glue_crypto_ctx_init(void)
{
    cryptoAccCtx.operation = IX_CRYPTO_ACC_OP_TYPE_OF_OPERATION;
    cryptoAccCtx.cipherCtx.cipherAlgo = IX_CRYPTO_ACC_CIPHER_NULL;
    cryptoAccCtx.cipherCtx.cipherMode = IX_CRYPTO_ACC_MODE_NULL ;
    cryptoAccCtx.cipherCtx.cipherKeyLen = 0;
    cryptoAccCtx.cipherCtx.cipherBlockLen = 0;
    cryptoAccCtx.cipherCtx.cipherInitialVectorLen = 0;
    cryptoAccCtx.authCtx.authAlgo =IX_CRYPTO_ACC_AUTH_NULL;
    cryptoAccCtx.authCtx.authDigestLen = 0;
    cryptoAccCtx.authCtx.authKeyLen = 0;
    cryptoAccCtx.authCtx.key.authKey[0] =  0;
    cryptoAccCtx.useDifferentSrcAndDestMbufs = FALSE;
}

void ipsec_glue_update_state(struct ipsec_sa *ips,
			     IxCryptoAccStatus state)
{
    if (state == IX_SUCCESS)
    {
        KLIPS_PRINT(debug_xform,
		    "klips_glue:update_state: "
		    "Changing State to Mature.!");
        /* update tdb to MATURE state */
        ips->ips_state = SADB_SASTATE_MATURE;
    }
    else if (state ==IX_CRYPTO_ACC_STATUS_WAIT)
    {
	    KLIPS_PRINT(debug_xform,
		    "klips_glue:update_state: "
		    "Registration not complete yet; wait for next completion indication.!");
	    /* update tdb to LARVA state */
        ips->ips_state = SADB_SASTATE_LARVAL;
    }
    else if (state == IX_FAIL)
    {
        KLIPS_PRINT(debug_xform,
            "klips_glue:update_state: "
            "Changing State to Dead.!");
        /* update tdb to DEAD state */
        ips->ips_state = SADB_SASTATE_DEAD;
    }
    else
    {
	    KLIPS_PRINT(debug_xform,
		    "klips_glue:update_state: "
		    "Error in status message.!");
        /* update tdb to DEAD state */
        ips->ips_state = SADB_SASTATE_DEAD;
    }
}

UINT32 ipsec_glue_create_cipher(struct ipsec_sa *ips)
{
    UINT32 status = IPSEC_GLUE_STATUS_SUCCESS;

    switch(ips->ips_encalg)
    {
#ifdef CONFIG_IPSEC_ENC_DES
	case ESP_DES:
	    /* The cipher algorith, DES */
	    cryptoAccCtx.cipherCtx.cipherAlgo = IX_CRYPTO_ACC_CIPHER_DES;

	    /* The cipher key length	 		*/
	    /* check the cipher length, 3DES = 24 bytes	*/
	    if (EMT_ESPDES_KEY_SZ == (DIVUP(ips->ips_key_bits_e, IPSEC_GLUE_BITS)))
	    {
            cryptoAccCtx.cipherCtx.cipherKeyLen = IX_CRYPTO_ACC_DES_KEY_64;
	    }
	    else
	    {
            status = IPSEC_GLUE_STATUS_FAIL;
            KLIPS_PRINT(debug_xform,
                    "klips_error:ipsec_glue_create_cipher: "
                    "Invalid DES length!\n");
            break;
	    }

	    /* The cipher key  */
	    memcpy (cryptoAccCtx.cipherCtx.key.cipherKey, (UINT8 *)(ips->ips_key_e),
		    cryptoAccCtx.cipherCtx.cipherKeyLen);

	    /* The cipher block length */
	    cryptoAccCtx.cipherCtx.cipherBlockLen = IX_CRYPTO_ACC_DES_BLOCK_64;

        /* The cipher IV length */
        if (EMT_ESPDES_IV_SZ == (DIVUP(ips->ips_iv_bits, IPSEC_GLUE_BITS)))
        {
            cryptoAccCtx.cipherCtx.cipherInitialVectorLen = IX_CRYPTO_ACC_DES_IV_64;
        }
        else
        {
            status = IPSEC_GLUE_STATUS_FAIL;
            KLIPS_PRINT(debug_xform,
                "klips_error:ipsec_glue_create_cipher: "
                "Invalid IV length!\n");
        }

	    break;
#endif /* CONFIG_IPSEC_ENC_DES */
    
#ifdef CONFIG_IPSEC_ENC_3DES
	case ESP_3DES:
	    /* The cipher algorith, 3DES */
	    cryptoAccCtx.cipherCtx.cipherAlgo = IX_CRYPTO_ACC_CIPHER_3DES;

	    /* The cipher key length	 		*/
	    /* check the cipher length, 3DES = 24 bytes	*/
	    if (EMT_ESP3DES_KEY_SZ == (DIVUP(ips->ips_key_bits_e, IPSEC_GLUE_BITS)))
	    {
            cryptoAccCtx.cipherCtx.cipherKeyLen = IX_CRYPTO_ACC_3DES_KEY_192;
	    }
	    else
	    {
            status = IPSEC_GLUE_STATUS_FAIL;
            KLIPS_PRINT(debug_xform,
                    "klips_error:ipsec_glue_create_cipher: "
                    "Invalid 3DES length!\n");
            break;
	    }

	    /* The cipher key  */
	    memcpy (cryptoAccCtx.cipherCtx.key.cipherKey, (UINT8 *)(ips->ips_key_e),
		    cryptoAccCtx.cipherCtx.cipherKeyLen);

	    /* The cipher block length */
	    cryptoAccCtx.cipherCtx.cipherBlockLen = IX_CRYPTO_ACC_DES_BLOCK_64;

        /* The cipher IV length */
        if (EMT_ESPDES_IV_SZ == (DIVUP(ips->ips_iv_bits, IPSEC_GLUE_BITS)))
        {
            cryptoAccCtx.cipherCtx.cipherInitialVectorLen = IX_CRYPTO_ACC_DES_IV_64;
        }
        else
        {
            status = IPSEC_GLUE_STATUS_FAIL;
            KLIPS_PRINT(debug_xform,
                "klips_error:ipsec_glue_create_cipher: "
                "Invalid IV length!\n");
        }

	    break;
#endif /* CONFIG_IPSEC_ENC_3DES */


#ifdef CONFIG_IPSEC_ALG
        case ESP_AES:
            /* The cipher algorith, AES */
            cryptoAccCtx.cipherCtx.cipherAlgo = IX_CRYPTO_ACC_CIPHER_AES;

            /* The cipher key length	 		*/
            switch (DIVUP(ips->ips_key_bits_e, IPSEC_GLUE_BITS))
            {
                case EMT_ESPAES128_KEY_SZ :
                    cryptoAccCtx.cipherCtx.cipherKeyLen = IX_CRYPTO_ACC_AES_KEY_128;
                    break;

                case EMT_ESPAES192_KEY_SZ :
                    cryptoAccCtx.cipherCtx.cipherKeyLen = IX_CRYPTO_ACC_AES_KEY_192;
                    break;

                case EMT_ESPAES256_KEY_SZ :
                    cryptoAccCtx.cipherCtx.cipherKeyLen = IX_CRYPTO_ACC_AES_KEY_256;
                    break;

                default :
                    status = IPSEC_GLUE_STATUS_FAIL;
                    KLIPS_PRINT(debug_xform,
                        "klips_error:ipsec_glue_create_cipher: "
                        "Invalid AES key length!\n");
                    break;
            }
            /* The cipher key  */
            memcpy (cryptoAccCtx.cipherCtx.key.cipherKey,
                (UINT8 *)((ips->ips_key_e) + AES_KEY_E_OFFSET_IN_TDB),
                cryptoAccCtx.cipherCtx.cipherKeyLen);

            /* The cipher block length */
            cryptoAccCtx.cipherCtx.cipherBlockLen = IX_CRYPTO_ACC_AES_BLOCK_128;

            /* The cipher IV length */
            if (EMT_ESPAES_CBC_IV_SZ == (DIVUP(ips->ips_iv_bits, IPSEC_GLUE_BITS)))
            {
                cryptoAccCtx.cipherCtx.cipherInitialVectorLen = IX_CRYPTO_ACC_AES_CBC_IV_128;
            }
            else
            {
                status = IPSEC_GLUE_STATUS_FAIL;
                KLIPS_PRINT(debug_xform,
                    "klips_error:ipsec_glue_create_cipher: "
                    "Invalid IV length!\n");
                break;
            }

            break;
#endif /* CONFIG_IPSEC_ALG */

	default:
	    /* Encryption not supported */
	    status = IPSEC_GLUE_STATUS_FAIL;
	    KLIPS_PRINT(debug_xform,
			"klips_error:ipsec_glue_create_cipher: "
			"Encap. Algorithm not supported!\n");
	    return status;
    }


    /* The cipher mode, supported cipher mode: CBC	*/
    cryptoAccCtx.cipherCtx.cipherMode = IX_CRYPTO_ACC_MODE_CBC;

  
    

    return status;
}


UINT32 ipsec_glue_create_auth(struct ipsec_sa *ips)
{
    UINT32 status = IPSEC_GLUE_STATUS_SUCCESS;

    switch(ips->ips_authalg) {
#ifdef CONFIG_IPSEC_AUTH_HMAC_MD5
	case AH_MD5:
	    /* Tne the authentication algorithm - MD5*/
	    cryptoAccCtx.authCtx.authAlgo = IX_CRYPTO_ACC_AUTH_MD5;

	    /* The digest length, in bytes */
	    cryptoAccCtx.authCtx.authDigestLen = AHHMAC_HASHLEN;

	    /* The authentication key length */
	    if (AHMD596_KLEN == (DIVUP(ips->ips_key_bits_a, IPSEC_GLUE_BITS)))
	    {
		    cryptoAccCtx.authCtx.authKeyLen = IX_CRYPTO_ACC_MD5_KEY_128;
	    }
	    else
	    {
            status = IPSEC_GLUE_STATUS_FAIL;
            KLIPS_PRINT(debug_xform,
			    "klips_error:glue_create_auth: "
			    "Invalid MD5 length!\n");
		    break;
	    }

	    /* The authentication key */
	    memcpy(cryptoAccCtx.authCtx.key.authKey, (UINT8 *)(ips->ips_key_a),
		    cryptoAccCtx.authCtx.authKeyLen);
	    break;
#endif /* CONFIG_IPSEC_AUTH_HMAC_MD5 */

#ifdef CONFIG_IPSEC_AUTH_HMAC_SHA1
	case AH_SHA:
	    cryptoAccCtx.authCtx.authAlgo = IX_CRYPTO_ACC_AUTH_SHA1;

	    /* The digest length, in bytes */
	    cryptoAccCtx.authCtx.authDigestLen = AHHMAC_HASHLEN;

	    /* The authentication key length */
	    if (AHSHA196_KLEN == (DIVUP(ips->ips_key_bits_a, IPSEC_GLUE_BITS)))
	    {
    		cryptoAccCtx.authCtx.authKeyLen = IX_CRYPTO_ACC_SHA1_KEY_160;
	    }
	    else
	    {
	    	status = IPSEC_GLUE_STATUS_FAIL;
		    KLIPS_PRINT(debug_xform,
			    "klips_error:glue_create_auth: "
			    "Invalid SHA1 length!\n");
		    break;
	    }

	    /* The authentication key, SHA1 */
	    memcpy(cryptoAccCtx.authCtx.key.authKey, (UINT8 *)(ips->ips_key_a),
		    cryptoAccCtx.authCtx.authKeyLen);

	    break;
#endif /* CONFIG_IPSEC_AUTH_HMAC_SHA1 */

	case AH_NONE:
	    break;

	default:
	    /* Authentication algo. not supported */
	    status = IPSEC_GLUE_STATUS_FAIL;
	    KLIPS_PRINT(debug_xform,
			"klips_error:ipsec_glue_create_auth: "
			"Authen. Algorithm not supported!\n");
    }
    return status;
}


UINT32 ipsec_compose_context(struct ipsec_sa *ips)
{
    UINT32 status = IPSEC_GLUE_STATUS_SUCCESS;

    /*
       Temporary structure to store the crypto context. Hardware
       accelarator will copy the data into its own structure
    */
    ipsec_glue_crypto_ctx_init();

    switch(ips->ips_said.proto)
    {
	    case IPPROTO_AH:
            /* fill only in cryto authentication context */
            if (IPSEC_GLUE_STATUS_FAIL == ipsec_glue_create_auth(ips))
            {
                status = IPSEC_GLUE_STATUS_FAIL;
                KLIPS_PRINT(debug_xform,
                    "klips_error:glue_compose_context: "
                    "Encapsulation Algo error!\n");
		        return (IPSEC_GLUE_STATUS_FAIL);
	        }
            /* Determine the direction of the transformation */
            if (ips->ips_flags & EMT_INBOUND)
    	    {	/* Incoming direction */
	        	cryptoAccCtx.operation = IX_CRYPTO_ACC_OP_AUTH_CHECK;
		        PerformCallbk = &ipsec_rcv_cb;
	        }
	        else
	        {	/* Outgoing direction */
               cryptoAccCtx.operation = IX_CRYPTO_ACC_OP_AUTH_CALC;
                PerformCallbk = &ipsec_tunnel_start_xmit_cb;
            }
	        break;

	    case IPPROTO_ESP:
	        if (IPSEC_GLUE_STATUS_FAIL == ipsec_glue_create_cipher(ips))
	        {
                status = IPSEC_GLUE_STATUS_FAIL;
		        KLIPS_PRINT(debug_xform,
                    "klips_error:glue_compose_context: "
                    "Encapsulation Algo error!\n");
        		return (IPSEC_GLUE_STATUS_FAIL);
	        }

            /* fill only in cryto authentication context */
            if (IPSEC_GLUE_STATUS_FAIL == ipsec_glue_create_auth(ips))
            {
                status = IPSEC_GLUE_STATUS_FAIL;
        		KLIPS_PRINT(debug_xform,
		    	    "klips_error:glue_compose_context: "
			        "Encapsulation Algo error!\n");
		        return (IPSEC_GLUE_STATUS_FAIL);
	        }

	        /* Determine the direction of the transformation */
	        if (ips->ips_flags & EMT_INBOUND)
	        {	/* Incoming direction */
                if (AH_NONE == ips->ips_authalg)
                {
                    cryptoAccCtx.operation = IX_CRYPTO_ACC_OP_DECRYPT;
                }
                else
                {
                    cryptoAccCtx.operation = IX_CRYPTO_ACC_OP_AUTH_DECRYPT;
                }
                PerformCallbk = &ipsec_rcv_cb;
	        }
	        else
	        {	/* Outgoing direction */
                if (AH_NONE == ips->ips_authalg)
                {
                    cryptoAccCtx.operation = IX_CRYPTO_ACC_OP_ENCRYPT;
                }
                else
                {
                    cryptoAccCtx.operation = IX_CRYPTO_ACC_OP_ENCRYPT_AUTH;
                }
                PerformCallbk = &ipsec_tunnel_start_xmit_cb;
            }
    	    break;

	/* Glue code is to create the crypto context from the freeswan security association
		which means it only maps the applicable freeswan SA to the crypto context. In
		other words IPPROTO_IPIP, IPPROTO_COMP, IPPROTO_INT, and case 0 do not relate
		to the IXDP425 crypto context and only applicable to IPSEC/Freeswan. */ 
	case IPPROTO_IPIP:
	    status = IPSEC_GLUE_STATUS_NOT_SUPPORTED;
	    break;

#ifdef CONFIG_IPSEC_IPCOMP
	case IPPROTO_COMP:
	    status = IPSEC_GLUE_STATUS_NOT_SUPPORTED;
	    break;
#endif /* CONFIG_IPSEC_IPCOMP */

	case IPPROTO_INT:
	    status = IPSEC_GLUE_STATUS_NOT_SUPPORTED;
	    break;

	case 0: /* Security association with no authentication algorithm and encryption algorithm */
	    status = IPSEC_GLUE_STATUS_NOT_SUPPORTED;
	    break;

	default:
	    KLIPS_PRINT(debug_xform,
			"klips_error:compose_context: "
			"unknown proto=%d.\n",
			ips->ips_said.proto);
	    status = IPSEC_GLUE_STATUS_FAIL;
	    break;
    }

    /* The data is read and write to the source */
    cryptoAccCtx.useDifferentSrcAndDestMbufs = FALSE;

#ifdef SA_GLUE_DEBUG
    printk ("Context compose status:  %d\n", status);
    print_show_algo();
#endif /* SA_GLUE_DEBUG */

    return status;
}

#ifdef IX_OSAL_MBUF_PRIV
/*
 * emulate some changes we made to older CSR libs so
 * we don;t need to keep modding them
 */

static struct CTXREG {
	UINT32 cryptoCtxId;
	struct ipsec_sa *ips;
	struct CTXREG *next;
} *ipsec_ctxips_list = NULL;

static int
ixCryptoAccSetUserCtx(UINT32 cryptoCtxId, struct ipsec_sa *ips)
{
    struct CTXREG *n = (struct CTXREG *) kmalloc(sizeof(*n), GFP_ATOMIC);
    if (!n)
	return IX_CRYPTO_ACC_STATUS_FAIL;
    n->cryptoCtxId = cryptoCtxId;
    n->ips = ips;
    n->next = ipsec_ctxips_list;
	ipsec_ctxips_list = n;
    return IX_CRYPTO_ACC_STATUS_SUCCESS;
}

static int
ixCryptoAccGetUserCtx(UINT32 cryptoCtxId, struct ipsec_sa **ips)
{
    struct CTXREG *p;

    for (p = ipsec_ctxips_list; p; p = p->next) {
	if (p->cryptoCtxId == cryptoCtxId) {
	    *ips = p->ips;
	    return IX_CRYPTO_ACC_STATUS_SUCCESS;
	}
    }
    return IX_CRYPTO_ACC_STATUS_FAIL;
}

#define ixCryptoAccDelUserCtx _ixCryptoAccDelUserCtx
static void
_ixCryptoAccDelUserCtx(UINT32 cryptoCtxId)
{
    struct CTXREG *p, *last = NULL;

    for (p = ipsec_ctxips_list; p; last = p, p = p->next) {
	if (p->cryptoCtxId == cryptoCtxId) {
	    if (last)
		last->next = p->next;
	    else
		ipsec_ctxips_list = p->next;
	    kfree(p);
		break;
	}
    }
}

#endif /* IX_OSAL_MBUF_PRIV */

UINT32
ipsec_glue_crypto_context_put(struct ipsec_sa *ips)
{
    UINT32 status = IPSEC_GLUE_STATUS_SUCCESS;
    UINT32 ret_status;
    IxCryptoAccStatus reg_status;
    IxCryptoAccStatus cb_status;
    unsigned long flags;
    UINT32 cryptoCtxId;

    pMbufPrimaryChainVar = NULL;
    pMbufSecondaryChainVar = NULL;

    /* Contruct the crypto context	*/
    ret_status = ipsec_compose_context(ips);

    if (IPSEC_GLUE_STATUS_FAIL == ret_status)
    {
    	KLIPS_PRINT(debug_xform,
		    "klips_error:context_put: "
		    "Composed crypto context failed \n");
        return (IPSEC_GLUE_STATUS_FAIL);
    }
    else if (IPSEC_GLUE_STATUS_NOT_SUPPORTED == ret_status)
    {
    	KLIPS_PRINT(debug_xform,
            "klips_debug:context_put: "
		    "Composed crypto context not supported \n");
	
	spin_lock_bh(&tdb_lock);
        ips->ips_crypto_state = IPSEC_GLUE_UNSUPPORTED_CTXID;
        spin_unlock_bh(&tdb_lock);

    	return status;
     }

    if (PerformCallbk == NULL)
    {
        KLIPS_PRINT(debug_xform,
            "klips_error:context_put: "
            "PerformCallbk is NULL.\n");
        return IPSEC_GLUE_STATUS_FAIL;
    }

    /*  allocate Mbuf for crypto registration */
    /* ESP with authentication or AH */
    if ((IX_CRYPTO_ACC_OP_ENCRYPT != cryptoAccCtx.operation) ||
	    (IX_CRYPTO_ACC_OP_DECRYPT != cryptoAccCtx.operation))
    {
        if (IPSEC_GLUE_STATUS_FAIL == ipsec_glue_mbuf_get (&pMbufPrimaryChainVar))
        {
            KLIPS_PRINT(debug_xform,
                "klips_error:context_put: "
                "Unable to allocate MBUF.\n");
            return (IPSEC_GLUE_STATUS_FAIL);
        }

        if (IPSEC_GLUE_STATUS_FAIL == ipsec_glue_mbuf_get (&pMbufSecondaryChainVar))
        {
            if (pMbufPrimaryChainVar)
                ipsec_glue_mbuf_rel (pMbufPrimaryChainVar);

            KLIPS_PRINT(debug_xform,
                "klips_error:context_put: "
                "Unable to allocate MBUF.\n");
            return (IPSEC_GLUE_STATUS_FAIL);
        }
    }


    /*  The tdb table better *NOT* be locked before it is handed in,
	or SMP locks will happen */
    spin_lock_bh(&tdb_lock);
    ips->ips_state = SADB_SASTATE_LARVAL;
    spin_unlock_bh(&tdb_lock);

    /* Register crypto context	*/
    spin_lock_irqsave(&tdb_lock, flags);
    reg_status = ixCryptoAccCtxRegister (&cryptoAccCtx,
                    pMbufPrimaryChainVar,
                    pMbufSecondaryChainVar,
                    register_crypto_cb,
                    PerformCallbk,
                    &cryptoCtxId);

    if (IX_CRYPTO_ACC_STATUS_SUCCESS == reg_status)
    {
        ixCryptoAccSetUserCtx(cryptoCtxId, ips);
        ips->ips_crypto_state = IPSEC_GLUE_VALID_CTXID;
        ips->ips_crypto_context_id = cryptoCtxId;
	spin_unlock_irqrestore(&tdb_lock, flags);
    }
    else
    {
	spin_unlock_irqrestore(&tdb_lock, flags);
        spin_lock_bh(&tdb_lock);
        ips->ips_state = SADB_SASTATE_DEAD;
        spin_unlock_bh(&tdb_lock);

        if (pMbufPrimaryChainVar)
            ipsec_glue_mbuf_rel (pMbufPrimaryChainVar);
        if (pMbufSecondaryChainVar)
            ipsec_glue_mbuf_rel (pMbufSecondaryChainVar);

        if (IX_CRYPTO_ACC_STATUS_FAIL == reg_status)
        {
            KLIPS_PRINT(debug_xform,
                "klips_error:glue_crypto_context_put: "
                "Registration failed for some unspecified internal reasons!");
        } else if (IX_CRYPTO_ACC_STATUS_EXCEED_MAX_TUNNELS == reg_status)
		{
            KLIPS_PRINT(debug_xform,
                "klips_error:glue_crypto_context_put: "
                "Registration failed as we have exceeded max active tunnels");
        } else if (IX_CRYPTO_ACC_STATUS_OPERATION_NOT_SUPPORTED == reg_status)
		{
            KLIPS_PRINT(debug_xform,
                "klips_error:glue_crypto_context_put: "
                "Registration failed as the requested operation is not suppored");
        } else {
            KLIPS_PRINT(debug_xform,
                "klips_error:glue_crypto_context_put: "
                "Registration failed - Invalid parameters!");
        }

        status = IPSEC_GLUE_STATUS_FAIL;
    }
#ifdef SA_GLUE_DEBUG
    printk ("Context Put: Status: %d\n", status);
	ixCryptoAccShowWithId(cryptoCtxId);
#endif /* SA_GLUE_DEBUG */
    return status;
}

void register_crypto_cb(UINT32 cryptoCtxId,IX_MBUF *empty_mbuf, IxCryptoAccStatus state)
{
    unsigned long flags;
    struct ipsec_sa *sa;
    IxCryptoAccStatus status;

    if (empty_mbuf != NULL)
    {
        /* free the mbuf */
        ipsec_glue_mbuf_rel (empty_mbuf);
    }

    /* prints the returned pointer to cryptoCtxId*/
    KLIPS_PRINT(debug_xform,
		"klips_glue:crypto_cb: "
		"cryptoCtxId is %d\n",
		cryptoCtxId);

	spin_lock_irqsave(&tdb_lock, flags);
    status = ixCryptoAccGetUserCtx(cryptoCtxId, (void **)&sa);
    if (IX_CRYPTO_ACC_STATUS_SUCCESS == status)
		ipsec_glue_update_state(sa, state);
	spin_unlock_irqrestore(&tdb_lock, flags);
}


UINT32
ipsec_glue_crypto_context_del (UINT32 crypto_context_id)
{
    UINT32 status = IPSEC_GLUE_STATUS_SUCCESS;
    IxCryptoAccStatus unregister_status;
    UINT32 tries = 0;

#ifdef ixCryptoAccDelUserCtx
{
	unsigned long flags;
	spin_lock_irqsave(&tdb_lock, flags);
    ixCryptoAccDelUserCtx(crypto_context_id);
	spin_unlock_irqrestore(&tdb_lock, flags);
}
#endif

    do
    {
    	unregister_status = ixCryptoAccCtxUnregister (crypto_context_id);
	if(100 == tries++)
	{
		printk("ERROR: Crypto unregistration failure\n");
		break;
	}
    } while (IX_CRYPTO_ACC_STATUS_RETRY == unregister_status);

    if (IX_CRYPTO_ACC_STATUS_SUCCESS == unregister_status)
    {
    }
    else
    {
        if (IX_CRYPTO_ACC_STATUS_FAIL == unregister_status)
        {
            KLIPS_PRINT(debug_xform,
                "klips_error:glue_crypto_context_del: "
                "Cannot unregister crypto context!");
        }
        else if (IX_CRYPTO_ACC_STATUS_CRYPTO_CTX_NOT_VALID == unregister_status)
	    {	KLIPS_PRINT(debug_xform,
			    "klips_error:glue_crypto_context_del: "
			    "invalid cryptoCtxId.!\n");
	    }
	    else
	    {
		KLIPS_PRINT(debug_xform,
			    "klips_error:glue_crypto_context_del: "
			    "retry the unregister operation.!");
	    }

	    status = IPSEC_GLUE_STATUS_FAIL;
    }

#ifdef SA_GLUE_DEBUG
        printk ("Context Del: Status: %d\n", status);
	ixCryptoAccShowWithId(crypto_context_id);
#endif /* SA_GLUE_DEBUG */
    return status;
}

#ifdef SA_GLUE_DEBUG
void print_show_algo()
{
    printk("Cipher Operation : %d\n", cryptoAccCtx.operation);
    printk("Cipher Algo: %d\n", cryptoAccCtx.cipherCtx.cipherAlgo);
    printk("Cipher Mode: %d\n", cryptoAccCtx.cipherCtx.cipherMode);
    printk("Cipher Key Length: %d\n", cryptoAccCtx.cipherCtx.cipherKeyLen);
    printk("Cipher key : 0x%x\n", (*(((UINT32 *)(cryptoAccCtx.cipherCtx.key.desKey)) + 0)));
    printk("Cipher key : 0x%x\n", (*(((UINT32 *)(cryptoAccCtx.cipherCtx.key.desKey)) + 1))); 
    printk("Cipher key : 0x%x\n", (*(((UINT32 *)(cryptoAccCtx.cipherCtx.key.desKey)) + 2))); 
    printk("Cipher key : 0x%x\n", (*(((UINT32 *)(cryptoAccCtx.cipherCtx.key.desKey)) + 3))); 
    printk("Cipher key : 0x%x\n", (*(((UINT32 *)(cryptoAccCtx.cipherCtx.key.desKey)) + 4))); 
    printk("Cipher key : 0x%x\n", (*(((UINT32 *)(cryptoAccCtx.cipherCtx.key.desKey)) + 5))); 
    printk("Cipher Block Len: %d\n", cryptoAccCtx.cipherCtx.cipherBlockLen);
    printk("Cipher IV Length: %d\n", cryptoAccCtx.cipherCtx.cipherInitialVectorLen);

     
    printk("Auth Algo: %d\n", cryptoAccCtx.authCtx.authAlgo);
    printk("Auth Digetst Len: %d\n", cryptoAccCtx.authCtx.authDigestLen);
    printk("Auth key Len: %d\n", cryptoAccCtx.authCtx.authKeyLen);
    printk("Auth Key: 0x%x\n", (*(((UINT32 *)(cryptoAccCtx.authCtx.key.authKey)) + 0)));
    printk("Auth Key: 0x%x\n", (*(((UINT32 *)(cryptoAccCtx.authCtx.key.authKey)) + 1)));
    printk("Auth Key: 0x%x\n", (*(((UINT32 *)(cryptoAccCtx.authCtx.key.authKey)) + 2)));
    printk("Auth Key: 0x%x\n", (*(((UINT32 *)(cryptoAccCtx.authCtx.key.authKey)) + 3)));
}
#endif /* SA_GLUE_DEBUG */ 

void addRcvDesc_to_salist(struct ipsec_sa *tdbp, IpsecRcvDesc *pRcvDesc) {
	if (tdbp->RcvDesc_head == NULL) {
		tdbp->RcvDesc_head = pRcvDesc;
	} else {
		if (tdbp->RcvDesc_tail != NULL)
			tdbp->RcvDesc_tail->RcvDesc_next = pRcvDesc;
	}
	tdbp->RcvDesc_tail = pRcvDesc;
	pRcvDesc->RcvDesc_next = NULL;
}

void delRcvDesc_from_salist(struct ipsec_sa *tdbp, IpsecRcvDesc *pRcvDesc) {
	struct _IpsecRcvDesc *p = NULL;
	struct _IpsecRcvDesc *q = NULL;

	for (p = tdbp->RcvDesc_head; p != NULL; p = p->RcvDesc_next) {
		if (p == pRcvDesc) {
			if (p == tdbp->RcvDesc_head) {
				/* pRcvDesc is at the head of the list */
				tdbp->RcvDesc_head = p->RcvDesc_next;
				if (p == tdbp->RcvDesc_tail) {
					tdbp->RcvDesc_tail = NULL;
				}
			} else {
				q->RcvDesc_next = p->RcvDesc_next;
				if (p == tdbp->RcvDesc_tail) {
					tdbp->RcvDesc_tail = q;
				}
			}
			p->RcvDesc_next = NULL;
			break;
		}
		q = p;
	}
}

void addXmitDesc_to_salist(struct ipsec_sa *tdbp, IpsecXmitDesc *pXmitDesc) {
	if (tdbp->XmitDesc_head == NULL) {
		tdbp->XmitDesc_head = pXmitDesc;
	} else {
		if (tdbp->XmitDesc_tail != NULL)
			tdbp->XmitDesc_tail->XmitDesc_next = pXmitDesc;
	}
	tdbp->XmitDesc_tail = pXmitDesc;
	pXmitDesc->XmitDesc_next = NULL;
}

void delXmitDesc_from_salist(struct ipsec_sa *tdbp, IpsecXmitDesc *pXmitDesc) {
	struct _IpsecXmitDesc *p = NULL;
	struct _IpsecXmitDesc *q = NULL;

	for (p = tdbp->XmitDesc_head; p != NULL; p = p->XmitDesc_next) {
		if (p == pXmitDesc) {
			if (p == tdbp->XmitDesc_head) {
				/* pRcvDesc is at the head of the list */
				tdbp->XmitDesc_head = p->XmitDesc_next;
				if (p == tdbp->XmitDesc_tail) {
					tdbp->XmitDesc_tail = NULL;
				}
			} else {
				q->XmitDesc_next = p->XmitDesc_next;
				if (p == tdbp->XmitDesc_tail) {
					tdbp->XmitDesc_tail = q;
					break;
				}
			}
			p->XmitDesc_next = NULL;
			break;
		}
		q = p;
	}
}
