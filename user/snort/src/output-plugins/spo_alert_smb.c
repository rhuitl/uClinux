/* $Id: spo_alert_smb.c,v 1.27 2003/05/19 18:08:04 chrisgreen Exp $ */
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

/* spo_alert_smb
 * 
 * Purpose:  output plugin for smb alerting
 *
 * Arguments:  workstations file
 *   
 * Effect:
 *
 * Alerts are sent to each workstation in the workstations file via WinPopup
 *
 * Comments:  Requires smbclient to be in PATH
 *
 */
#ifdef ENABLE_SMB_ALERTS

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "decode.h"
#include "event.h"
#include "rules.h"
#include "plugbase.h"
#include "spo_plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"

#include "snort.h"


typedef struct _SpoAlertSmbData
{
    char *filename;
} SpoAlertSmbData;

void AlertSmbInit(u_char *);
void AlertSmb(Packet *, char *, void *, Event *);
SpoAlertSmbData *ParseAlertSmbArgs(char *);
void AlertSmbCleanExit(int, void *);
void AlertSmbRestart(int, void *);



/* external globals from rules.c */
extern OptTreeNode *otn_tmp;

/*
 * Function: SetupAlertSmb()
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
void AlertSmbSetup()
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterOutputPlugin("alert_smb", NT_OUTPUT_ALERT, AlertSmbInit);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Output plugin: AlertSmb is setup...\n"););
}


/*
 * Function: AlertSmbInit(u_char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
void AlertSmbInit(u_char *args)
{
    SpoAlertSmbData *data;

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Output: AlertSmb Initialized\n"););

    pv.alert_plugin_active = 1;

    /* parse the argument list from the rules file */
    data = ParseAlertSmbArgs(args);


    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Linking SmbAlert functions to call lists...\n"););

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(AlertSmb, NT_OUTPUT_ALERT, data);
    AddFuncToCleanExitList(AlertSmbCleanExit, data);
    AddFuncToRestartList(AlertSmbRestart, data);
}


/*
 * Function: ParseAlertSmbArgs(char *)
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
 * Notes:	code adapted from ParseTcpdumpArgs in spo_log_tcpdump.c
 */
SpoAlertSmbData *ParseAlertSmbArgs(char *args)
{
    SpoAlertSmbData *data;

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "ParseAlertSmbArgs: %s\n", args););

    data = (SpoAlertSmbData *) malloc(sizeof(SpoAlertSmbData));

    if(args != NULL)
    {
        while(isspace((int)*args)) args++;
        data->filename = (char *) calloc(strlen(args) + 1, sizeof(char));
        if(data->filename == NULL)
        {
            FatalError("ParseAlertSmbArgs() filename calloc failed: %s\n",
                       strerror(errno));
        }

        strncpy(data->filename, args, strlen(args)+1);
    }
    else
    {
        FatalError("%s(%d): No filename for AlertSmb\n",
                   file_name, file_line);
    }

    return data;
}

/****************************************************************************
 *
 * Function: SmbAlert(Packet *, char *)
 *
 * Purpose: Send the current alert to a waiting WinPopup client
 *
 * Arguments: p => pointer to the packet data struct
 *            msg => the message to print in the alert
 *
 * Returns: void function
 *
 ***************************************************************************/
void AlertSmb(Packet *p, char *msg, void *arg, Event *event)
{
    char command_line[2048];
#ifndef WIN32
    FILE *output;
#endif
    FILE *workstations;
    char *tempmsg;
    char tempwork[STD_BUF];
    char timestamp[TIMEBUF_SIZE];
    char sip[16];
    char dip[16];
    int msg_str_size;
    SpoAlertSmbData *data = (SpoAlertSmbData *)arg;
    char pri_data[STD_BUF];

    pri_data[0] = '\0';
    if(otn_tmp)
    {
        if(otn_tmp->sigInfo.classType)
        {
            snprintf(pri_data, STD_BUF-1, " [Classification: %s] "
                    "[Priority: %d]:", otn_tmp->sigInfo.classType->name,
                    otn_tmp->sigInfo.priority); 
        }
        else if(otn_tmp->sigInfo.priority != 0)
        {
            snprintf(pri_data, STD_BUF-1, "[Priority: %d]:", 
                    otn_tmp->sigInfo.priority); 
        }
    }

    bzero((char *)timestamp, TIMEBUF_SIZE);

    ts_print(p==NULL?NULL:(struct timeval *)&p->pkth->ts, timestamp);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Generating SMB alert!\n"););

    /* message size + IP addrs + ports + pad space */  
    msg_str_size = strlen(msg) + 32 + 10 + 150;

    if((tempmsg = (char *) calloc(msg_str_size, sizeof(char))) == NULL)
    {
        FatalError("[!] ERROR: SmbAlert() unable to allocate space for"
                " tempmsg: %s\n", strerror(errno));
    }

    /* open the message file and the workstation names file */
    if((workstations = fopen(data->filename,"r")) != NULL)
    {
        if(p != NULL)
        {
            strncpy(sip, inet_ntoa(p->iph->ip_src), 16);
            strncpy(dip, inet_ntoa(p->iph->ip_dst), 16);

            if(p->frag_flag || (!p->udph && !p->tcph))
            {
                /* write the alert message into the buffer */
                snprintf(tempmsg, msg_str_size-1, 
                        "[**] %s [**]%s%s %s->%s", msg, 
                        pri_data, timestamp, sip, dip);
            }
            else
            {
                /* write the alert message into the buffer */
                snprintf(tempmsg, msg_str_size-1, 
                        "[**] %s [**]%s%s %s:%d->%s:%d", msg, 
                        pri_data, timestamp, 
                        sip, p->sp, dip, p->dp);
            }
        }
        else
        {
            /* write the alert message into the buffer - this part 
             * is for alerts with NULL packets (like portscans)
             */
            snprintf(tempmsg, msg_str_size-1, "[**] %s [**]\n", msg);
        }

        bzero((char *)tempwork, STD_BUF);
        bzero((char *)command_line, 2048);

        /* read in the name of each workstation to send the message to */
        while((fgets(tempwork, STD_BUF-1, workstations)) != NULL)
        {
            /* if the line isn't blank */
            if(tempwork[0] != 0x0A)
            {
                /* chop the <CR> */
                strip(tempwork);

#ifdef WIN32
                snprintf(command_line, 2047, 
                        "start /min net send %s %s", tempwork, tempmsg);

                WinExec(command_line,SW_SHOWMINNOACTIVE);
#else
                /* build the command line */
                snprintf(command_line, 2047, 
                        "echo \"%s\" | smbclient -U Snort -M %s", 
                        tempmsg, tempwork);

                /* run the command */
                output = popen(command_line,"r");

                pclose(output);
#endif

                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Sending WinPopup alert to: %s\n", 
                            tempwork););
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Command Line: %s\n", command_line););

                bzero((char *)tempwork, STD_BUF);
                bzero((char *)command_line, 2048);
            }
        }

        fclose(workstations);
    }

    free(tempmsg);
}

void AlertSmbCleanExit(int signal, void *arg)
{
    SpoAlertSmbData *data = (SpoAlertSmbData *)arg;

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "SpoAlertSmbCleanExitFunc\n"););

    /* free memory from SpoAlertSmbData */
    free(data->filename);
    free(data);
}

void AlertSmbRestart(int signal, void *arg)
{
    SpoAlertSmbData *data = (SpoAlertSmbData *)arg;

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "SpoAlertSmbRestartFunc\n"););

    /* free memory from SpoAlertSmbData */
    free(data->filename);
    free(data);
}

#endif
