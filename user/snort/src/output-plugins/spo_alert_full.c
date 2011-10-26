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

/* spo_alert_full
 * 
 * Purpose:  output plugin for full alerting
 *
 * Arguments:  alert file (eventually)
 *   
 * Effect:
 *
 * Alerts are written to a file in the snort full alert format
 *
 * Comments:   Allows use of full alerts with other output plugin types
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "event.h"
#include "decode.h"
#include "plugbase.h"
#include "spo_plugbase.h"
#include "debug.h"
#include "parser.h"
#include "util.h"
#include "log.h"
#include "mstring.h"

#include "snort.h"

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <stdio.h>
#include <stdlib.h>


typedef struct _SpoAlertFullData
{
    FILE *file;
} SpoAlertFullData;

void AlertFullInit(u_char *);
SpoAlertFullData *ParseAlertFullArgs(char *);
void AlertFull(Packet *, char *, void *, Event *);
void AlertFullCleanExit(int, void *);
void AlertFullRestart(int, void *);


/*
 * Function: SetupAlertFull()
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
void AlertFullSetup(void)
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterOutputPlugin("alert_full", NT_OUTPUT_ALERT, AlertFullInit);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Output plugin: AlertFull is setup...\n"););
}


/*
 * Function: AlertFullInit(u_char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
void AlertFullInit(u_char *args)
{
    SpoAlertFullData *data;
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output: AlertFull Initialized\n"););
    
    pv.alert_plugin_active = 1;

    /* parse the argument list from the rules file */
    data = ParseAlertFullArgs(args);
    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Linking AlertFull functions to call lists...\n"););

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(AlertFull, NT_OUTPUT_ALERT, data);
    AddFuncToCleanExitList(AlertFullCleanExit, data);
    AddFuncToRestartList(AlertFullRestart, data);
}

void AlertFull(Packet *p, char *msg, void *arg, Event *event)
{
    char timestamp[TIMEBUF_SIZE];
    SpoAlertFullData *data = (SpoAlertFullData *)arg;

    if(msg != NULL)
    {
        fwrite("[**] ", 5, 1, data->file);

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
            fwrite(" [**]\n", 6, 1, data->file);
        }
        else
        {
            fwrite(msg, strlen(msg), 1, data->file);
            fwrite(" [**]\n", 6, 1, data->file);
        }
    }
    else
    {
        fwrite("[**] Snort Alert! [**]\n", 23, 1, data->file);
    }

    if(p && p->iph)
    {
        PrintPriorityData(data->file, 1);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "Logging Alert data!\n"););

    bzero((char *) timestamp, TIMEBUF_SIZE);
    ts_print(p == NULL ? NULL : (struct timeval *) & p->pkth->ts, timestamp);

    /* dump the timestamp */
    fwrite(timestamp, strlen(timestamp), 1, data->file);
    if(p && p->iph)
    {
        /* print the packet header to the alert file */

        if(pv.show2hdr_flag)
        {
            Print2ndHeader(data->file, p);
        }

        PrintIPHeader(data->file, p);

        /* if this isn't a fragment, print the other header info */
        if(!p->frag_flag)
        {
            switch(p->iph->ip_proto)
            {
                case IPPROTO_TCP:
                    PrintTCPHeader(data->file, p);
                    break;

                case IPPROTO_UDP:
                    PrintUDPHeader(data->file, p);
                    break;

                case IPPROTO_ICMP:
                    PrintICMPHeader(data->file, p);
                    break;

                default:
                    break;
            }

            PrintXrefs(data->file, 1);
        }

        fputc('\n', data->file);
    } /* End of if(p) */
    else
    {
        fputs("\n\n", data->file);
    }

    fflush(data->file);
    return;
 


}


/*
 * Function: ParseAlertFullArgs(char *)
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
SpoAlertFullData *ParseAlertFullArgs(char *args)
{
    char **toks;
    int num_toks;
    char *filename;
    SpoAlertFullData *data;

    data = (SpoAlertFullData *)SnortAlloc(sizeof(SpoAlertFullData));
    if(args == NULL)
    {
        data->file = OpenAlertFile(NULL);
        return data;
    }
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"ParseAlertFullArgs: %s\n", args););

    toks = mSplit(args, " ", 2, &num_toks, 0);
    if(strcasecmp("stdout", toks[0]) == 0)
        data->file = stdout;
    else
    {
        filename = ProcessFileOption(toks[0]);
        data->file = OpenAlertFile(filename);
        free(filename);
    }
    mSplitFree(&toks, num_toks);
    return data;
}

void AlertFullCleanExit(int signal, void *arg)
{
    SpoAlertFullData *data = (SpoAlertFullData *)arg;
    /* close alert file */
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"AlertFullCleanExit\n"););
    fclose(data->file);
    /* free memory from SpoAlertFullData */
    free(data);
}

void AlertFullRestart(int signal, void *arg)
{
    SpoAlertFullData *data = (SpoAlertFullData *)arg;
    /* close alert file */
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"AlertFullRestart\n"););
    fclose(data->file);
    /* free memory from SpoAlertFullData */
    free(data);
}

