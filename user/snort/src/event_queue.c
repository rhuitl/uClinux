/* $Id$ */
/*
 ** Copyright (C) 2004-2006 Sourcefire, Inc.
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
**  @file       event_queue.c
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      Snort wrapper to sfeventq library.
**
**  Copyright (C) 2004, Daniel Roelker and Sourcefire, Inc.
**
**  These functions wrap the sfeventq API and provide the priority
**  functions for ordering incoming events.
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fpcreate.h"
#include "fpdetect.h"
#include "util.h"
#include "sfeventq.h"
#include "event_wrapper.h"
#include "event_queue.h"
#include "sfthreshold.h"

/*
**  Set default values
*/
SNORT_EVENT_QUEUE g_event_queue = {8,3,SNORT_EVENTQ_CONTENT_LEN,0};

/*
 *  Changed so events are inserted in action config order 'drop alert ...',
 *  and sub sorted in each action group by priority or content length.
 *  The sub sorting is done in fpFinalSelect inf fpdetect.c.  Once the
 *  events are inserted they can all be logged, as we only insert
 *  g_event_queue.log_events into the queue.
 *  ... Jan '06
 */
int SnortEventqAdd(unsigned int gid, 
                   unsigned int sid, 
                   unsigned int rev, 
                   unsigned int classification, 
                   unsigned int pri,
                   char        *msg,
                   void        *rule_info)
{
    EventNode *en;

    en = (EventNode *)sfeventq_event_alloc();
    if(!en)
        return -1;

    en->gid = gid;
    en->sid = sid;
    en->rev = rev;
    en->classification = classification;
    en->priority = pri;
    en->msg = msg;
    en->rule_info = rule_info;

    if(sfeventq_add((void *)en))
        return -1;

    return 0;
}
#ifdef OLD_RULE_ORDER
static int OrderPriority(void *event1, void *event2)
{
    EventNode *e1;
    EventNode *e2;

    if(!event1 || !event2)
        return 0;

    e1 = (EventNode *)event1;
    e2 = (EventNode *)event2;

    if(e1->priority < e2->priority)
        return 1;

    return 0;
}

static int OrderContentLength(void *event1, void *event2)
{
    EventNode *e1;
    EventNode *e2;
    OTNX      *o1;
    OTNX      *o2;

    if(!event1 || !event2)
        return 0;

    e1 = (EventNode *)event1;
    e2 = (EventNode *)event2;

    if(!e1->rule_info && e2->rule_info)
    {
        /*
        **  incoming event is not a rule, keep
        **  looking.
        */
        return 0;
    }
    else if(e1->rule_info && !e2->rule_info)
    {
        /*
        **  incoming event is a rule, event in queue
        **  is not.  Put incoming here.
        */
        return 1;
    }
    else if(!e1->rule_info && !e2->rule_info)
    {
        /*
        **  Neither event is a rule.  Use incoming as
        **  priority.  Last one in goes at the end to 
        **  preserve rule order.
        */
        return 0;
    }

    /*
    **  We already know that these pointers aren't NULL by
    **  the previous logic.
    */
    o1 = (OTNX *)e1->rule_info;
    o2 = (OTNX *)e2->rule_info;

    if(o1->content_length > o2->content_length)
        return 1;

    return 0;
}
#endif

int SnortEventqInit(void)
{
    int (*sort)(void *, void*) = NULL;
#ifdef OLD_RULE_ORDER
    if(g_event_queue.order == SNORT_EVENTQ_PRIORITY)
    {
        sort = OrderPriority;
    }
    else if(g_event_queue.order == SNORT_EVENTQ_CONTENT_LEN)
    {
        sort = OrderContentLength;
    }
    else
    {
        FatalError("Order function for event queue is invalid.\n");
    }
#else
    sort = 0;
#endif
    if(sfeventq_init(g_event_queue.max_events, g_event_queue.log_events,
                    sizeof(EventNode), sort))
    {
        FatalError("Failed to initialize Snort event queue.\n");
    }

    return 0;
}
            
static int LogSnortEvents(void *event, void *user)
{
    Packet    *p;
    EventNode *en;
    OTNX      *otnx;
    SNORT_EVENTQ_USER *snort_user;

    if(!event || !user)
        return 0;

    en         = (EventNode *)event;
    snort_user = (SNORT_EVENTQ_USER *)user;
    p  = (Packet *)snort_user->pkt;

    /*
    **  Log rule events differently because we have to.
    */
    if(en->rule_info)
    {
        otnx = (OTNX *)en->rule_info;
        if(!otnx->rtn || !otnx->otn)
            return 0;
#if 0
        LogMessage("LogSnortEvents: calling fpLogEvent( sid: %u,gid: %u, p ) \n",
           otnx->otn->sigInfo.id,
           otnx->otn->sigInfo.generator );
#endif
        snort_user->rule_alert = 1;

        fpLogEvent(otnx->rtn, otnx->otn, p);
    }
    else
    {
        GenerateSnortEvent(p, en->gid, en->sid, en->rev,
                           en->classification, en->priority, en->msg);
    }

    sfthreshold_reset();

    return 0;
}

/*
**  NAME
**    SnortEventqLog::
*/
/**
**  We return whether we logged events or not.  We've add a eventq user
**  structure so we can track whether the events logged we're rule events
**  or preprocessor/decoder events.  The reason being that we don't want
**  to flush a TCP stream for preprocessor/decoder events, and cause
**  early flushing of the stream.
**
**  @return 1 logged events
**  @return 0 did not log events or logged only decoder/preprocessor events
*/
int SnortEventqLog(Packet *p)
{
    static SNORT_EVENTQ_USER user;

    user.rule_alert = 0x00;
    user.pkt = (void *)p;

    if(sfeventq_action(LogSnortEvents, (void *)&user) > 0)
    {
        if(user.rule_alert)
            return 1;
    }

    return 0;
}

void SnortEventqReset(void)
{
    sfeventq_reset();
    return;
}
