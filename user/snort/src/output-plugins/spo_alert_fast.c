/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 2000,2001 Andrew R. Baker <andrewb@uab.edu>
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

/* spo_alert_fast
 * 
 * Purpose:  output plugin for fast alerting
 *
 * Arguments:  alert file
 *   
 * Effect:
 *
 * Alerts are written to a file in the snort fast alert format
 *
 * Comments:   Allows use of fast alerts with other output plugin types
 *
 */

/* output plugin header file */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "event.h"
#include "decode.h"
#include "debug.h"
#include "plugbase.h"
#include "spo_plugbase.h"
#include "parser.h"
#include "util.h"
#include "log.h"
#include "mstring.h"

#include "snort.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* !WIN32 */

#include <sys/types.h>

typedef struct _SpoAlertFastData
{
    FILE *file;
    u_int8_t packet_flag;
} SpoAlertFastData;

void AlertFastInit(u_char *);
SpoAlertFastData *ParseAlertFastArgs(char *);
void AlertFastCleanExitFunc(int, void *);
void AlertFastRestartFunc(int, void *);
void AlertFast(Packet *, char *, void *, Event *);



/*
 * Function: SetupAlertFast()
 *
 * Purpose: Registers the output plugin keyword and initialization 
 *          function into the output plugin list.  This is the function that
 *          gets called from InitOutputPlugins() in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void AlertFastSetup(void)
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterOutputPlugin("alert_fast", NT_OUTPUT_ALERT, AlertFastInit);
    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Output plugin: AlertFast is setup...\n"););
}


/*
 * Function: AlertFastInit(u_char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
void AlertFastInit(u_char *args)
{
    SpoAlertFastData *data;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Output: AlertFast Initialized\n"););

    pv.alert_plugin_active = 1;

    /* parse the argument list from the rules file */
    data = ParseAlertFastArgs(args);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Linking AlertFast functions to call lists...\n"););
    
    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(AlertFast, NT_OUTPUT_ALERT, data);
    AddFuncToCleanExitList(AlertFastCleanExitFunc, data);
    AddFuncToRestartList(AlertFastRestartFunc, data);
}

void AlertFast(Packet *p, char *msg, void *arg, Event *event)
{
    char timestamp[TIMEBUF_SIZE];
    SpoAlertFastData *data = (SpoAlertFastData *)arg;

    bzero((char *) timestamp, TIMEBUF_SIZE);
    ts_print(p == NULL ? NULL : (struct timeval *) & p->pkth->ts, timestamp);

    /* dump the timestamp */
    fwrite(timestamp, strlen(timestamp), 1, data->file);

    if( p && (p->packet_flags & PKT_INLINE_DROP) ) fputs(" [Drop]",data->file);

    if(msg != NULL)
    {
#ifdef MARK_TAGGED
        char c=' ';
        if (p && (p->packet_flags & PKT_REBUILT_STREAM))
            c = 'R';
        else if (p && (p->packet_flags & PKT_REBUILT_FRAG))
            c = 'F';
        fprintf(data->file, " [**] %c ", c);
#else
        fwrite(" [**] ", 6, 1, data->file);
#endif

        if(event != NULL)
        {
            fprintf(data->file, "[%lu:%lu:%lu] ",
                    (unsigned long) event->sig_generator,
                    (unsigned long) event->sig_id,
                    (unsigned long) event->sig_rev);
        }

        if(pv.alert_interface_flag)
        {
            fprintf(data->file, " <%s> ", PRINT_INTERFACE(pv.interface));
            fwrite(msg, strlen(msg), 1, data->file);
        }
        else
        {
            fwrite(msg, strlen(msg), 1, data->file);
        }

        fwrite(" [**] ", 6, 1, data->file);
    }

    /* print the packet header to the alert file */
    if(p && p->iph)
    {
        PrintPriorityData(data->file, 0);

        fprintf(data->file, "{%s} ", protocol_names[p->iph->ip_proto]);

        if(p->frag_flag)
        {
            /* just print the straight IP header */
            fputs(inet_ntoa(p->iph->ip_src), data->file);
            fwrite(" -> ", 4, 1, data->file);
            fputs(inet_ntoa(p->iph->ip_dst), data->file);
        }
        else
        {
            switch(p->iph->ip_proto)
            {
                case IPPROTO_UDP:
                case IPPROTO_TCP:
                    /* print the header complete with port information */
                    fputs(inet_ntoa(p->iph->ip_src), data->file);
                    fprintf(data->file, ":%d -> ", p->sp);
                    fputs(inet_ntoa(p->iph->ip_dst), data->file);
                    fprintf(data->file, ":%d", p->dp);
                    break;
                case IPPROTO_ICMP:
                default:
                    /* just print the straight IP header */
                    fputs(inet_ntoa(p->iph->ip_src), data->file);
                    fwrite(" -> ", 4, 1, data->file);
                    fputs(inet_ntoa(p->iph->ip_dst), data->file);
            }
        }
    }               /* end of if (p) */
    if(p && data->packet_flag)
    {
        fputc('\n', data->file);

        if(p->iph)
            PrintIPPkt(data->file, p->iph->ip_proto, p);
        else if(p->ah)
            PrintArpHeader(data->file, p);
    }

    fputc('\n', data->file);

    fflush(data->file);
    return;
}

/*
 * Function: ParseAlertFastArgs(char *)
 *
 * Purpose: Process the preprocessor arguements from the rules file and 
 *          initialize the preprocessor's data struct.  This function doesn't
 *          have to exist if it makes sense to parse the args in the init 
 *          function.
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 *
 */
SpoAlertFastData *ParseAlertFastArgs(char *args)
{
    char **toks;
    int num_toks;
    char *filename;
    SpoAlertFastData *data;

    data = (SpoAlertFastData *)SnortAlloc(sizeof(SpoAlertFastData));

    if(args == NULL)
    {
        data->file = OpenAlertFile(NULL);
        return data;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "ParseAlertFastArgs: %s\n", args););

    toks = mSplit(args, " ", 2, &num_toks, 0);
    if(strcasecmp("stdout", toks[0]) == 0)
        data->file = stdout;
    else
    {
        filename = ProcessFileOption(toks[0]);
        data->file = OpenAlertFile(filename);
        free(filename);
    }
    if(num_toks > 1)
    {
        if(strcasecmp(toks[1], "packet") == 0)
        {
            data->packet_flag = 1;
        }
        else
        {
            FatalError("Unrecognized alert_fast option: %s\n", toks[1]);
        }
    }
    /* free toks */
    mSplitFree(&toks, num_toks);

    return data;
}

void AlertFastCleanExitFunc(int signal, void *arg)
{
    SpoAlertFastData *data = (SpoAlertFastData *)arg;
    /* close alert file */
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"AlertFastCleanExitFunc\n"););
    fclose(data->file);
    /*free memory from SpoAlertFastData */
    free(data);
}

void AlertFastRestartFunc(int signal, void *arg)
{
    SpoAlertFastData *data = (SpoAlertFastData *)arg;
    /* close alert file */
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"AlertFastRestartFunc\n"););
    fclose(data->file);
    /*free memory from SpoAlertFastData */
    free(data);
}

