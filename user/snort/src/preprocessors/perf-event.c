/*
**  $Id$
**
**  perf-event.c
**
**  Copyright (C) 2002 Sourcefire,Inc
**  Marc Norton <mnorton@sourcefire.com>
**  Dan Roelker <droelker@sourcefire.com>
**
**  NOTES
**  5.28.02 - Initial Source Code. Norton/Roelker
**
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/

#include "snort.h"
#include "util.h"

int DisplayEventPerfStats(SFEVENT_STATS *sfEventStats);

SFEVENT *GetEventPtr() { return &sfPerf.sfEvent; }

int InitEventStats(SFEVENT *sfEvent)
{
    sfEvent->NQEvents = 0;
    sfEvent->QEvents  = 0;

    return 0;
}

int UpdateNQEvents()
{
    SFEVENT *sfEvent = GetEventPtr();

    if(!(sfPerf.iPerfFlags & SFPERF_EVENT))
    {
        return 0;
    }

    sfEvent->NQEvents++;
    sfEvent->TotalEvents++;

    return 0;
}

int UpdateQEvents()
{
    SFEVENT *sfEvent = GetEventPtr();

    if(!(sfPerf.iPerfFlags & SFPERF_EVENT))
    {
        return 0;
    }

    sfEvent->QEvents++;
    sfEvent->TotalEvents++;

    return 0;
}

int ProcessEventStats(SFEVENT *sfEvent)
{
    SFEVENT_STATS sfEventStats;

    sfEventStats.NQEvents = sfEvent->NQEvents;
    sfEventStats.QEvents = sfEvent->QEvents;
    sfEventStats.TotalEvents = sfEvent->TotalEvents;

    if(sfEvent->TotalEvents)
    {
        sfEventStats.NQPercent = 100.0 * (double)sfEvent->NQEvents / 
                                 (double)sfEvent->TotalEvents;
        sfEventStats.QPercent  = 100.0 * (double)sfEvent->QEvents / 
                                 (double)sfEvent->TotalEvents;
    }
    else
    {
        sfEventStats.NQPercent = 0;
        sfEventStats.QPercent = 0;
    }

    sfEvent->NQEvents    = 0;
    sfEvent->QEvents     = 0;
    sfEvent->TotalEvents = 0;

    DisplayEventPerfStats(&sfEventStats);

    return 0;
}

int DisplayEventPerfStats(SFEVENT_STATS *sfEventStats)
{
    LogMessage("\n\nSnort Setwise Event Stats\n");
    LogMessage(    "-------------------------\n");

    LogMessage( "Total Events:           %llu\n", sfEventStats->TotalEvents);
    LogMessage( "Qualified Events:       %llu\n", sfEventStats->QEvents);
    LogMessage( "Non-Qualified Events:   %llu\n", sfEventStats->NQEvents);

    LogMessage("%%Qualified Events:      %.4f%%\n", sfEventStats->QPercent);
    LogMessage("%%Non-Qualified Events:  %.4f%%\n", sfEventStats->NQPercent);

    return 0;
}
    

