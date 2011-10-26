/*
 * dcerpc_util.c
 *
 * Copyright (C) 2006 Sourcefire,Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Description:
 *
 * Contains utility functions.
 *
 */

#include <stdio.h>
#include <ctype.h>

#include "snort_dcerpc.h"
#include "dcerpc_util.h"
#include "bounds.h"

extern u_int32_t   _memcap;
extern u_int8_t    _alert_memcap;
extern u_int16_t   _max_frag_size;

u_int32_t _total_memory = 0;

void *DCERPC_FragAlloc(void *p, u_int16_t old_size, u_int16_t *new_size)
{
    u_int16_t add_size;
    void *new_buf = NULL;

    if (old_size >= *new_size)
    {
        *new_size = old_size;
        return p;
    }

    add_size = *new_size - old_size;

    if ( (((u_int32_t) add_size) + _total_memory) > _memcap )
    {
        /* Raise alert */
        if ( _alert_memcap )
        {
            DCERPC_GenerateAlert(DCERPC_EVENT_MEMORY_OVERFLOW, 
                                    DCERPC_EVENT_MEMORY_OVERFLOW_STR);
        }
        add_size = (u_int16_t) (_memcap - _total_memory);
    }

    *new_size = old_size + add_size;

    if (*new_size == old_size)
        return p;

    new_buf = calloc(*new_size, 1);

    if (new_buf == NULL)
    {
        if (p != NULL)
        {
            DCERPC_FragFree(p, old_size);
        }

        return NULL;
    }

    if (p != NULL)
    {
        int ret;

        ret = SafeMemcpy(new_buf, p, old_size, new_buf, (u_int8_t *)new_buf + *new_size);

        if (ret == 0)
        {
            *new_size = old_size;
            free(new_buf);
            return p;
        }

        DCERPC_FragFree(p, old_size);
    }

    /* DCERPC_FragFree will decrement old_size from _total_memory so
     * we add the *new_size */
    _total_memory += *new_size;

    return new_buf;
}


int DCERPC_FragFree(void *p, u_int16_t size)
{
    if ( p )
    {
        if ( _total_memory > size )
            _total_memory -= size;
        else
            _total_memory = 0;
        
        free(p);
        return 1;
    }
    
    return 0;
}

void DCERPC_GenerateAlert(dcerpc_event_e event, char *msg)
{
    _dpd.alertAdd(GENERATOR_DCERPC, event, 1, 0, 3, msg, 0);
}


/* Print out given buffer in hex and ascii, for debugging */
void PrintBuffer(char * title, u_int8_t *buf, u_int16_t buf_len)
{
    u_int16_t i, j = 0;

    printf("%s\n", title);

    for ( i = 0; i < buf_len; i+=16 )
    {
        printf("%.4x  ", i);
        for ( j = 0; j < (buf_len-i) && j < 16; j++ )
        {
            printf("%.2x ", *(buf+i+j));
            if ( (j+1)%8 == 0 )
                printf(" ");
        }
        if ( j != 16 )
            printf(" ");
        for ( ; j < 16; j++ )
            printf("   ");
        printf(" ");
        for ( j = 0; j < (buf_len-i) && j < 16; j++ )
        {
            if ( isprint(*(buf+i+j)) )
                printf("%c", *(buf+i+j));
            else
                printf(".");
            if ( (j+1)%8 == 0 )
                printf(" ");
            if ( (j+1)%16 == 0 )
                printf("\n");
        }
    }
    if ( j != 16 )
        printf("\n");
}

