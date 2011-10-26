/* $Id$ */
/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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
*/

/*  D E F I N E S  ************************************************************/
#ifndef __EVENT_H__
#define __EVENT_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef OSF1
#include <sys/bitypes.h>
#endif

#include <sys/types.h>
#ifndef WIN32
#include <sys/time.h>
#endif

#include "snort_packet_header.h"

typedef struct _Event
{
    u_int32_t sig_generator;   /* which part of snort generated the alert? */
    u_int32_t sig_id;          /* sig id for this generator */
    u_int32_t sig_rev;         /* sig revision for this id */
    u_int32_t classification;  /* event classification */
    u_int32_t priority;        /* event priority */
    u_int32_t event_id;        /* event ID */
    u_int32_t event_reference; /* reference to other events that have gone off,
                                * such as in the case of tagged packets...
                                */
    struct pcap_timeval ref_time;   /* reference time for the event reference */

    /* Don't add to this structure because this is the serialized data
     * struct for unified logging.
     */
} Event;

#if 0
typedef struct _EventID
{
    u_int32_t sequence;
    u_int32_t seconds;
} EventID;

typedef struct _Event
{
    EventID id;
    u_int32_t uSeconds;
    SigInfo sigInfo;
} Event;

#endif


#endif /* __EVENT_H__ */
