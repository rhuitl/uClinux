/*
 * dcerpc_util.h
 *
 * Copyright (C) 2006 Sourcefire,Inc
 * Andrew Mullican
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
 * Declares routines for utility functions.
 *
 *
 */
#ifndef _DCERPC_UTIL_H_
#define _DCERPC_UTIL_H_

/* Needs to match what is in generators.h */
#define  GENERATOR_DCERPC    130


/* Events for DCERPC */
typedef enum _dcerpc_event_e 
{
    DCERPC_EVENT_MEMORY_OVERFLOW       = 1

} dcerpc_event_e;

#define     DCERPC_EVENT_MEMORY_OVERFLOW_STR  "(dcerpc) Maximum memory usage reached"


void *DCERPC_FragAlloc(void *p, u_int16_t old_size, u_int16_t *new_size);
int DCERPC_FragFree(void *p, u_int16_t size);
void DCERPC_GenerateAlert(dcerpc_event_e event, char *msg);
void PrintBuffer(char * title, u_int8_t *buf, u_int16_t buf_len);

#endif  /*  _DCERPC_UTIL_H_  */
