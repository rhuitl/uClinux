/*
 * IPSEC_GLUE_MBUF interface code.
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

 RCSID $Id: ipsec_glue_mbuf.c,v 1.0 2003/04/22 05:40:47 rgb Exp $

 */

#include "ipsec_glue_mbuf.h"

IX_MBUF_POOL *pIpsecMbufHdrPool; /* mbuf header pool pointer */
IX_MBUF       *pIpsecMbufHdr;
UINT32 	      mbufHdrAreaMemSize;

IX_MBUF_POOL *pIpsecMbufPool;   /* Mbuf pool pointer */



/* Initialize mbuf header pool */
void ipsec_glue_mbuf_header_init (void)
{
    pIpsecMbufHdr = IX_MBUF_POOL_MBUF_AREA_ALLOC(IPSEC_GLUE_MBUF_HEADER_COUNT, mbufHdrAreaMemSize);

    /* initialize mbuf header pool */
    IX_MBUF_POOL_INIT_NO_ALLOC(
        &pIpsecMbufHdrPool,
        pIpsecMbufHdr,
        NULL,
	    IPSEC_GLUE_MBUF_HEADER_COUNT,
        0,
        "IXP425 IPSec driver Mbuf Header Pool");
}


/* Get mbuf from mbuf header pool */
int ipsec_glue_mbuf_header_get (IX_MBUF **pMbufPtr)
{
    if ((IX_MBUF_POOL_GET(pIpsecMbufHdrPool, pMbufPtr)) == IX_SUCCESS)
    {
        IX_MBUF_MDATA (*pMbufPtr) = NULL;
        IX_MBUF_NEXT_PKT_IN_CHAIN_PTR (*pMbufPtr) = NULL;
        return 0;
    }
    else
        return 1;
}


/* Release mbuf back into mbuf header pool */
void ipsec_glue_mbuf_header_rel (IX_MBUF *pMbuf)
{
    IX_MBUF_POOL_PUT (pMbuf);
}


/* Initialize mbuf pool */
void ipsec_glue_mbuf_init (void)
{

    /* initialize mbuf pool */
    IX_MBUF_POOL_INIT(
        &pIpsecMbufPool,
	    IPSEC_GLUE_MBUF_COUNT,
        IPSEC_GLUE_MBUF_DATA_SIZE,
        "IXP425 IPSec driver Mbuf Pool");
}


/* Get mbuf from mbuf pool */
int ipsec_glue_mbuf_get (IX_MBUF **pMbufPtr)
{
    if ((IX_MBUF_POOL_GET(pIpsecMbufPool, pMbufPtr)) == IX_SUCCESS)
        return 0;
    else
        return 1;
}


/* Release mbuf back into mbuf pool */
void ipsec_glue_mbuf_rel (IX_MBUF *pMbuf)
{
    IX_MBUF_POOL_PUT (pMbuf);
}
