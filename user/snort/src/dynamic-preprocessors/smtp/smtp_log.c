/*
 * smtp_log.c
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
 * Copyright (C) 2005 Sourcefire Inc.
 *
 * Author: Andy  Mullican
 *
 * Description:
 *
 * This file handles SMTP alerts.
 *
 * Entry point functions:
 *
 *    SMTP_GenerateAlert()
 *
 *
 */

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>

#include "debug.h"
#include "preprocids.h"

#include "snort_smtp.h"
#include "smtp_log.h"

/* Array of static event buffers */
#define EVENT_STR_LEN      256
char _smtp_event[SMTP_EVENT_MAX][EVENT_STR_LEN];

extern SMTP_CONFIG  _smtp_config;


void SMTP_GenerateAlert(smtp_event_e event, char *format, ...)
{
    va_list ap;

    if ( _smtp_config.no_alerts )
    {
        DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "Ignoring alert %d\n", event););
        return;
    }

    va_start(ap, format);

    vsnprintf(_smtp_event[event], EVENT_STR_LEN, format, ap);
    _smtp_event[event][EVENT_STR_LEN-1] = '\0';

    _dpd.alertAdd(GENERATOR_SMTP, event, 1, 0, 3, _smtp_event[event], 0);

#ifdef DEBUG
    {
        //int len = strlen(_smtp_event[event]);
        char debugstr[EVENT_STR_LEN];
        strncpy(debugstr, _smtp_event[event], EVENT_STR_LEN);
        debugstr[EVENT_STR_LEN - 2] = '\n';
        debugstr[EVENT_STR_LEN - 1] = '\0';
        
        DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, debugstr););
    }
#endif
    va_end(ap);

}

