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
/* $Id$ */

/* spo_log_null
 * 
 * Purpose:
 *
 * This module is a NULL placeholder for people that want to turn off 
 * logging for whatever reason.  Please note that logging is separate from
 * alerting, they are completely separate output facilities within Snort.
 *
 * Arguments:
 *   
 * None.
 *
 * Effect:
 *
 * None.
 *
 * Comments:
 *
 */

#include <sys/types.h>

#include "decode.h"
#include "event.h"
#include "plugbase.h"
#include "spo_plugbase.h"
#include "parser.h"
#include "debug.h"

#include "snort.h"

/* list of function prototypes for this output plugin */
void LogNullInit(u_char *);
void LogNull(Packet *, char *, void *, Event *);
void LogNullCleanExitFunc(int, void *);
void LogNullRestartFunc(int, void *);

void LogNullSetup()
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterOutputPlugin("log_null", NT_OUTPUT_LOG, LogNullInit);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Output plugin: LogNull is setup...\n"););
}


void LogNullInit(u_char *args)
{
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Output: LogNull Initialized\n"););

    pv.log_plugin_active = 1;

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(LogNull, NT_OUTPUT_LOG, NULL);
    AddFuncToCleanExitList(LogNullCleanExitFunc, NULL);
    AddFuncToRestartList(LogNullRestartFunc, NULL);
}



void LogNull(Packet *p, char *msg, void *arg, Event *event)
{
    return;
}


void LogNullCleanExitFunc(int signal, void *arg)
{
    return;
}

void LogNullRestartFunc(int signal, void *arg)
{
    return;
}
