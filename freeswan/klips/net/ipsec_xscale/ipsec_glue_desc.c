/*
 * IPSEC_GLUE_DESC interface code.
 * Copyright 2003 Intel Corporation All Rights Reserved.
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

 RCSID $Id: ipsec_glue_desc.c,v 1.0 2003/04/27 05:08:18 rgb Exp $

 */
 
/*
 * Put the user defined include files required.
 */
#include "IxTypes.h"
#include "IxOsCacheMMU.h"
#include "IxOsServices.h"
#include <linux/in.h>
#include <linux/slab.h>
#include "ipsec_glue_desc.h"
#include "ipsec_glue.h"

/*
 * Variable declarations global to this file only.  Externs are followed by
 * static variables.
 */
static kmem_cache_t *ipsec_rcv_desc_cachep;
static kmem_cache_t *ipsec_xmit_desc_cachep;



/**
 * ipsec_glue_rcv_desc_init
 *
 * Initialize ipsec_rcv descriptor management module. 
 *
 * Returns: IPSEC_GLUE_STATUS_SUCCESS - Initialization is successful
 *			IPSEC_GLUE_STATUS_FAIL - Initialization failure
 */
int
ipsec_glue_rcv_desc_init (void)
{
    ipsec_rcv_desc_cachep = kmem_cache_create("ipsec_rcv_desc",
	    IPSEC_RCV_DESC_SIZE, 0, 0, NULL, NULL);
    if (!ipsec_rcv_desc_cachep)
        return IPSEC_GLUE_STATUS_FAIL;

    return IPSEC_GLUE_STATUS_SUCCESS;

} /* end of ipsec_glue_rcv_desc_init () function */


/**
 * ipsec_glue_rcv_desc_get
 *
 * Get descriptor from the ipsec_rcv descriptor pool.
 *
 * Param : pIpsecRcvDescPtr [out] - Pointer to ipsec_rcv descriptor pointer
 *
 * Return : IPSEC_GLUE_STATUS_SUCCESS
 *          IPSEC_GLUE_STATUS_FAIL
 *
 */
int
ipsec_glue_rcv_desc_get (IpsecRcvDesc **pIpsecRcvDescPtr)
{
    if (!ipsec_rcv_desc_cachep)
        return IPSEC_GLUE_STATUS_FAIL;

    *pIpsecRcvDescPtr = kmem_cache_alloc(ipsec_rcv_desc_cachep, GFP_ATOMIC);
    if (!*pIpsecRcvDescPtr)
        return IPSEC_GLUE_STATUS_FAIL;

    (*pIpsecRcvDescPtr)->stats = NULL;
    return IPSEC_GLUE_STATUS_SUCCESS;
}


/**
 * ipsec_glue_rcv_desc_release
 *
 * Release descriptor previously allocated back to the ipsec_rcv
 * descriptor pool
 *
 * Return : IPSEC_GLUE_STATUS_SUCCESS
 *          IPSEC_GLUE_STATUS_FAIL
 */
int
ipsec_glue_rcv_desc_release (IpsecRcvDesc *pIpsecRcvDesc)
{
    if (!ipsec_rcv_desc_cachep)
        return IPSEC_GLUE_STATUS_FAIL;

    kmem_cache_free(ipsec_rcv_desc_cachep, pIpsecRcvDesc);
    return IPSEC_GLUE_STATUS_SUCCESS;
}




/**
 * ipsec_rcv_desc_pool_free
 *
 * To free the memory allocated to descriptor pool through malloc
 *        function.
 *
 * Param : None
 * Return :  None
 *
 */
void
ipsec_rcv_desc_pool_free (void)
{
    if (ipsec_rcv_desc_cachep && kmem_cache_destroy(ipsec_rcv_desc_cachep))
	ipsec_rcv_desc_cachep = NULL;
}



/**
 * ipsec_glue_xmit_desc_init
 *
 * Initialize ipsec_xmit descriptor management module.
 *
 * Return:  IPSEC_GLUE_STATUS_SUCCESS
 *          IPSEC_GLUE_STATUS_FAIL
 **/
int
ipsec_glue_xmit_desc_init (void)
{
    ipsec_xmit_desc_cachep = kmem_cache_create("ipsec_xmit_desc",
	    IPSEC_XMIT_DESC_SIZE, 0, 0, NULL, NULL);
    if (!ipsec_xmit_desc_cachep)
        return IPSEC_GLUE_STATUS_FAIL;

    return IPSEC_GLUE_STATUS_SUCCESS;
}



/**
 * ipsec_glue_xmit_desc_get
 *
 * Get descriptor from the ipsec_xmit descriptor pool.
 *
 * Param : pIpsecXmitDescPtr [out] - Pointer to ipsec_xmit descriptor pointer
 *
 * Return:  IPSEC_GLUE_STATUS_SUCCESS
 *          IPSEC_GLUE_STATUS_FAIL
 **/
int
ipsec_glue_xmit_desc_get (IpsecXmitDesc **pIpsecXmitDescPtr)
{
    if (!ipsec_xmit_desc_cachep)
        return IPSEC_GLUE_STATUS_FAIL;

    *pIpsecXmitDescPtr = kmem_cache_alloc(ipsec_xmit_desc_cachep, GFP_ATOMIC);
    if (!*pIpsecXmitDescPtr)
        return IPSEC_GLUE_STATUS_FAIL;

    (*pIpsecXmitDescPtr)->tot_headroom = 0;
    (*pIpsecXmitDescPtr)->tot_tailroom = 0;
    (*pIpsecXmitDescPtr)->saved_header = NULL;
    (*pIpsecXmitDescPtr)->oskb = NULL;
    (*pIpsecXmitDescPtr)->pass = 0;
    memset((char*)&((*pIpsecXmitDescPtr)->tdb), 0, sizeof(struct ipsec_sa));
    return IPSEC_GLUE_STATUS_SUCCESS;
}



/**
 * ipsec_glue_xmit_desc_release
 *
 * Release descriptor previously allocated back to the ipsec_xmit
 * descriptor pool
 *
 * pIpsecXmitDesc [in] - Pointer to ipsec_xmit descriptor
 *
 * Return:  IPSEC_GLUE_STATUS_SUCCESS
 *          IPSEC_GLUE_STATUS_FAIL
 *
 */
int
ipsec_glue_xmit_desc_release (IpsecXmitDesc *pIpsecXmitDesc)
{
    if (!ipsec_xmit_desc_cachep)
        return IPSEC_GLUE_STATUS_FAIL;

    kmem_cache_free(ipsec_xmit_desc_cachep, pIpsecXmitDesc);
    return IPSEC_GLUE_STATUS_SUCCESS;
}



/**
 * ipsec_xmit_desc_pool_free
 *
 * To free the memory allocated to descriptor pool through malloc
 *        function.
 *
 * Param : None
 * Return :  None
 *
 */
void
ipsec_xmit_desc_pool_free (void)
{
    if (ipsec_xmit_desc_cachep && kmem_cache_destroy(ipsec_xmit_desc_cachep))
	ipsec_xmit_desc_cachep = NULL;
}
