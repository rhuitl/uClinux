
/*
 * smtp_log.h
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
 */

#ifndef __SMTP_LOG_H__
#define __SMTP_LOG_H__


/* Events for SMTP */
typedef enum _smtp_event_e 
{
    SMTP_EVENT_COMMAND_OVERFLOW       = 1,
    SMTP_EVENT_DATA_HDR_OVERFLOW      = 2,
    SMTP_EVENT_RESPONSE_OVERFLOW      = 3,
    SMTP_EVENT_SPECIFIC_CMD_OVERFLOW  = 4,
    SMTP_EVENT_UNKNOWN_CMD            = 5,
    SMTP_EVENT_ILLEGAL_CMD            = 6,
    
    SMTP_EVENT_MAX                    = 10

} smtp_event_e;

/* Messages for each event */
#define     SMTP_COMMAND_OVERFLOW_STR                  "(smtp) Attempted command buffer overflow"
#define     SMTP_DATA_HDR_OVERFLOW_STR                 "(smtp) Attempted data header buffer overflow"
#define     SMTP_RESPONSE_OVERFLOW_STR                 "(smtp) Attempted response buffer overflow"
#define     SMTP_SPECIFIC_CMD_OVERFLOW_STR             "(smtp) Attempted specific command buffer overflow"
#define     SMTP_UNKNOWN_CMD_STR                       "(smtp) Unknown command"
#define     SMTP_ILLEGAL_CMD_STR                       "(smtp) Illegal command"
 


/* Function prototypes  */
void SMTP_GenerateAlert(smtp_event_e event, char *format, ...);


#endif  /*  __SMTP_LOG_H__  */
