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

 RCSID $Id: ipsec_glue_mbuf.h,v 1.0 2003/04/22 05:40:47 rgb Exp $

 */

#ifndef _IPSEC_GLUE_MBUF_H
#define _IPSEC_GLUE_MBUF_H

#include "IxOsBuffMgt.h"
#include "IxOsBuffPoolMgt.h"

/* Maximum mbuf header allocate for IPSec driver */
#define IPSEC_GLUE_MBUF_HEADER_COUNT    384

/* Maximum mbufs allocate for IPSec driver */
#define IPSEC_GLUE_MBUF_COUNT           256

/* Size of mdata in mbuf */
#define IPSEC_GLUE_MBUF_DATA_SIZE       128

/*
 * Initialize mbufs header pool
 * The mbuf pool will have maximum IPSEC_GLUE_MBUF_HEADER_COUNT of mbufs. The mbuf header do not have
 * the mdata pointer attached to it.
 *
 * Param: None
 *
 * Return:None
 *
 */
void ipsec_glue_mbuf_header_init (void);


/*
 * Get mbuf header from mbuf pool
 *
 * Param: pMbufPtr [out] pointer to the mbuf pointer
 *
 * Return: IPSEC_GLUE_STATUS_SUCCESS
 *         IPSEC_GLUE_STATUS_FAIL
 *
 */
int ipsec_glue_mbuf_header_get (IX_MBUF **pMbufPtr);


/*
 * Release mbuf header back into mbuf pool
 *
 * Param: pMbuf [in] mbuf pointer to be release back to the pool
 *
 * Return: None
 *
 */
void ipsec_glue_mbuf_header_rel (IX_MBUF *pMbuf);


/*
 * Initialize mbufs pool
 * The mbuf pool will have maximum IPSEC_GLUE_MBUF_COUNT of mbufs with mdata pointer attached to it.
 *
 * Param: None
 *
 * Return:None
 *
 */
void ipsec_glue_mbuf_init (void);


/*
 * Get mbuf header from mbuf pool
 *
 * Param: pMbufPtr [out] pointer to the mbuf pointer
 *
 * Return: IPSEC_GLUE_STATUS_SUCCESS
 *         IPSEC_GLUE_STATUS_FAIL
 *
 */
int ipsec_glue_mbuf_get (IX_MBUF **pMbufPtr);


/*
 * Release mbuf back into mbuf pool
 *
 * Param: pMbuf [in] mbuf pointer to be release back to the pool
 *
 * Return: None
 *
 */
void ipsec_glue_mbuf_rel (IX_MBUF *pMbuf);


#ifdef IX_OSAL_MBUF_PRIV
/**
 * mbuf_swap_skb : links/unlinks mbuf to skb
 */
static inline struct sk_buff *mbuf_swap_skb(IX_OSAL_MBUF *mbuf, struct sk_buff *skb)
{
    struct sk_buff *res = IX_OSAL_MBUF_PRIV(mbuf);

    IX_OSAL_MBUF_PRIV(mbuf) = skb;

    if (!skb)
	return res;
    
    IX_OSAL_MBUF_MDATA(mbuf) = skb->data;
    IX_OSAL_MBUF_MLEN(mbuf) = IX_OSAL_MBUF_PKT_LEN(mbuf) = skb->len;

    return res;
}
#endif /* IX_OSAL_MBUF_PRIV */

#endif /*_IPSEC_GLUE_MBUF_H */
