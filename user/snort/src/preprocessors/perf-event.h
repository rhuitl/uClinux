/*
**  $Id$
**
**  perf-event.h
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

#ifndef __PERF_EVENT__
#define __PERF_EVENT__

#include "perf.h"

typedef struct _SFEVENT {

    UINT64 NQEvents;
    UINT64 QEvents;

    UINT64 TotalEvents;

} SFEVENT;

typedef struct _SFEVENT_STATS {

    UINT64 NQEvents;
    UINT64 QEvents;

    UINT64 TotalEvents;

    double NQPercent;
    double QPercent;

}  SFEVENT_STATS;

/*
**  These functions are for interfacing with the main
**  perf module.
*/ 
int InitEventStats(SFEVENT *sfEvent);
int ProcessEventStats(SFEVENT *sfEvent);

/*
**  These functions are external for updating the
**  SFEVENT structure.
*/
int UpdateNQEvents();
int UpdateQEvents();

#endif
