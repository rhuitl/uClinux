/* $Id$ */
/*
 ** Copyright (C) 1998-2006 Sourcefire, Inc.
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
/**
 * @file   event_wrapper.c
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Wed Jun 18 10:49:59 2003
 * 
 * @brief  generate a snort event
 * 
 * This is a wrapper around SetEvent,CallLogFuncs,CallEventFuncs 
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "util.h"
#include "event_wrapper.h"

u_int32_t GenerateSnortEvent(Packet *p,
                            u_int32_t gen_id,
                            u_int32_t sig_id,
                            u_int32_t sig_rev,
                            u_int32_t classification,
                            u_int32_t priority,
                            char *msg)
{
    Event event;

    if(!msg)
    {
        return 0;
    }
    
    SetEvent(&event, gen_id, sig_id, sig_rev, classification, priority, 0);
    CallAlertFuncs(p, msg, NULL, &event);

    if(p)
    {
        /*
        **  This logic is for if we eventually decide to flush streams on
        **  events that aren't rules.  Right now we don't flush because
        **  the rules are what are the most important and not generic
        **  preprocessor events, so we don't want to flush a stream that
        **  might have alerted on a rule, but instead "all you got was
        **  this lousy preprocessor event".  But here's the logic if we 
        **  want to add it sometime.
        */
        /*
        if(p->ssnptr != NULL)
        {
            if(stream_api->alert_flush_stream(p) == 0)
                CallLogFuncs(p, msg, NULL, &event);
        }
        else
        {
            CallLogFuncs(p, msg, NULL, &event);
        }
        */

        CallLogFuncs(p, msg, NULL, &event);
    }

    /* 0 is never used as an event id in snort unless things wrap around... */
    return event.event_id;
}

/** 
 * Log additional packet data using the same kinda mechanism tagging does.
 * 
 * @param p Packet to log
 * @param gen_id generator id
 * @param sig_id signature id
 * @param sig_rev revision is
 * @param classification classification id
 * @param priority priority level
 * @param event_ref reference of a previous event
 * @param ref_sec the tv_sec of that previous event
 * @param msg The message data txt
 * 
 * @return 1 on success, 0 on FAILURE ( note this is to stay the same as GenerateSnortEvent() )
 */
int LogTagData(Packet *p,
               u_int32_t gen_id,
               u_int32_t sig_id,
               u_int32_t sig_rev,
               u_int32_t classification,
               u_int32_t priority,
               u_int32_t event_ref,
               time_t ref_sec,
               char *msg)
   
{
    Event event;
    
    if(!event_ref || !ref_sec)
        return 0;

    SetEvent(&event, gen_id, sig_id, sig_rev, classification, priority, event_ref);

    event.ref_time.tv_sec = ref_sec;
    
    if(p)
        CallLogFuncs(p, msg, NULL, &event);

    return 1;
}
                     
