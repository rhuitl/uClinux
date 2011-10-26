#ifndef _BOUNDS_H
#define _BOUNDS_H
/*
** Copyright (C) 2003, Sourcefire, Inc.
**               Chris Green <cmg@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef OSF1
#include <sys/bitypes.h>
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <assert.h>
#include <unistd.h>

#define SAFEMEM_ERROR 0
#define SAFEMEM_SUCCESS 1

/* This INLINE is conflicting with the INLINE defined in bitop.h.
 * So, let's just add a little sanity check here.
 */
#ifndef DEBUG
    #ifndef INLINE
        #define INLINE inline
    #endif
    #define ERRORRET return SAFEMEM_ERROR;
#else
    #ifdef INLINE
        #undef INLINE
    #endif
    #define INLINE   
    #define ERRORRET assert(0==1)
#endif /* DEBUG */


/*
 * Check to make sure that p is less than or equal to the ptr range
 * pointers
 *
 * 1 means it's in bounds, 0 means it's not
 */
static INLINE int inBounds(u_int8_t *start, u_int8_t *end, u_int8_t *p)
{
    if(p >= start && p < end)
    {
        return 1;
    }
    
    return 0;
}

/** 
 * A Safer Memcpy
 * 
 * @param dst where to copy to
 * @param src where to copy from
 * @param n number of bytes to copy
 * @param start start of the dest buffer
 * @param end end of the dst buffer
 * 
 * @return 0 on failure, 1 on success
 */
static INLINE int SafeMemcpy(void *dst, void *src, size_t n, void *start, void *end)
{
    void *tmp;

    if(n < 1)
    {
        ERRORRET;
    }

    if (!dst || !src)
    {
        ERRORRET;
    }

    tmp = ((u_int8_t*)dst) + (n-1);
    if (tmp < dst)
    {
        ERRORRET;
    }

    if(!inBounds(start,end, dst) || !inBounds(start,end,tmp))
    {
        ERRORRET;
    }

    memcpy(dst, src, n);

    return SAFEMEM_SUCCESS;
}

/** 
 * A Safer *a = *b
 * 
 * @param start start of the dst buffer
 * @param end end of the dst buffer
 * @param dst the location to write to
 * @param src the source to read from
 * 
 * @return 0 on failure, 1 on success
 */
static INLINE int SafeWrite(u_int8_t *start, u_int8_t *end, u_int8_t *dst, u_int8_t *src)
{
    if(!inBounds(start, end, dst))
    {
        ERRORRET;
    }
     
    *dst = *src;        
    return 1;
}

static inline int SafeRead(u_int8_t *start, u_int8_t *end, u_int8_t *src, u_int8_t *read)
{
    if(!inBounds(start,end, src))
    {
        ERRORRET;
    }
    
    *read = *start;
    return 1;
}

#endif /* _BOUNDS_H */
