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

/* spo_log_tcpdump 
 * 
 * Purpose:
 *
 * This plugin generates tcpdump formatted binary log files
 *
 * Arguments:
 *   
 * filename of the output log (default: snort.log)
 *
 * Effect:
 *
 * Packet logs are written (quickly) to a tcpdump formatted output
 * file
 *
 * Comments:
 *
 * First logger...
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <sys/types.h>
#include <pcap.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#include "decode.h"
#include "event.h"
#include "plugbase.h"
#include "spo_plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"

#include "snort.h"

/* For the traversal of reassembled packets */
#include "stream_api.h"

typedef struct _LogTcpdumpData
{
    char *filename;
    int log_written;
    pcap_dumper_t *dumpd;

} LogTcpdumpData;

/* list of function prototypes for this preprocessor */
void LogTcpdumpInit(u_char *);
LogTcpdumpData *ParseTcpdumpArgs(char *);
void LogTcpdump(Packet *, char *, void *, Event *);
void TcpdumpInitLogFileFinalize(int unused, void *arg);
void TcpdumpInitLogFile(LogTcpdumpData *);
void SpoLogTcpdumpCleanExitFunc(int, void *);
void SpoLogTcpdumpRestartFunc(int, void *);
void DirectLogTcpdump(struct pcap_pkthdr *, u_int8_t *);
void LogTcpdumpSingle(Packet *, char *, void *, Event *);
void LogTcpdumpStream(Packet *, char *, void *, Event *);



/* external globals from rules.c */
extern pcap_dumper_t *dumpd;  /* ptr to pcap packet dump facility */
extern PV pv;              /* program variables struct */

/* If you need to instantiate the plugin's data structure, do it here */
LogTcpdumpData *log_tcpdump_ptr;

/*
 * Function: SetupLogTcpdump()
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
void LogTcpdumpSetup()
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterOutputPlugin("log_tcpdump", NT_OUTPUT_LOG, LogTcpdumpInit);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Output plugin: Log-Tcpdump is setup...\n"););
}


/*
 * Function: LogTcpdumpInit(u_char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
void LogTcpdumpInit(u_char *args)
{
    LogTcpdumpData *data;
    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Output: Log-Tcpdump Initialized\n"););

    /* tell command line loggers to go away */
    pv.log_plugin_active = 1;

    /* parse the argument list from the rules file */
    data = ParseTcpdumpArgs(args);
    log_tcpdump_ptr = data;

    //TcpdumpInitLogFile(data);
    AddFuncToPostConfigList(TcpdumpInitLogFileFinalize, data);

    pv.log_bitmap |= LOG_TCPDUMP;

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(LogTcpdump, NT_OUTPUT_LOG, data);
    AddFuncToCleanExitList(SpoLogTcpdumpCleanExitFunc, data);
    AddFuncToRestartList(SpoLogTcpdumpRestartFunc, data);
}



/*
 * Function: ParseTcpdumpArgs(char *)
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
LogTcpdumpData *ParseTcpdumpArgs(char *args)
{
    LogTcpdumpData *data;

    data = (LogTcpdumpData *) SnortAlloc(sizeof(LogTcpdumpData));

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"Args: %s<>\n", args););

    if(args != NULL)
    {
        while(isspace((int)*args)) args++;
        if(strcmp(args, "") != 0)
            data->filename = strdup(args);
        else
            data->filename = strdup("snort.log");
    }
    else
    {
        data->filename = strdup("snort.log");
    }

    if (!data->filename)
    {
        FatalError("Unable to allocate memory for tcpdump log filename\n");
    }

    return data;
}


/*
 * Function: PreprocFunction(Packet *)
 *
 * Purpose: Perform the preprocessor's intended function.  This can be
 *          simple (statistics collection) or complex (IP defragmentation)
 *          as you like.  Try not to destroy the performance of the whole
 *          system by trying to do too much....
 *
 * Arguments: p => pointer to the current packet data struct 
 *
 * Returns: void function
 */
void LogTcpdump(Packet *p, char *msg, void *arg, Event *event)
{

    if(p)
    {
        if(p->packet_flags & PKT_REBUILT_STREAM)
        {
            LogTcpdumpStream(p, msg, arg, event);
        }
        else
        {
            LogTcpdumpSingle(p, msg, arg, event);
        }
    }
}

void LogTcpdumpSingle(Packet *p, char *msg, void *arg, Event *event)
{
    LogTcpdumpData *data = (LogTcpdumpData *)arg;

    data->log_written = 1;

    /* sizeof(struct pcap_pkthdr) = 16 bytes */
    pcap_dump((u_char *)data->dumpd,p->pkth,p->pkt);

    if(!pv.line_buffer_flag)
    { 
#ifdef WIN32
        fflush( NULL );  /* flush all open output streams */
#else
        /* we happen to know that pcap_dumper_t* is really just a FILE* */
        fflush( (FILE*) data->dumpd );
#endif
    }
}

int LogTcpdumpStreamCallback(SnortPktHeader *pkth, u_int8_t *packet_data,
        void *userdata)
{
    LogTcpdumpData *data = (LogTcpdumpData *)userdata;

    pcap_dump((u_char *)data->dumpd, 
              (struct pcap_pkthdr *) pkth, 
              (u_char *) packet_data);

    return 0;
}

void LogTcpdumpStream(Packet *p, char *msg, void *arg, Event *event)
{
    LogTcpdumpData *data = (LogTcpdumpData *)arg;

    data->log_written = 1;

    if (stream_api)
        stream_api->traverse_reassembled(p, LogTcpdumpStreamCallback, data);

    if(!pv.line_buffer_flag)
    { 
#ifdef WIN32
        fflush( NULL );  /* flush all open output streams */
#else
        /* we happen to know that pcap_dumper_t* is really just a FILE* */
        fflush( (FILE*) data->dumpd );
#endif
    }
}

void TcpdumpInitLogFileFinalize(int unused, void *arg)
{
    TcpdumpInitLogFile((LogTcpdumpData *)arg);
}

/*
 * Function: TcpdumpInitLogFile()
 *
 * Purpose: Initialize the tcpdump log file header
 *
 * Arguments: data => pointer to the plugin's reference data struct 
 *
 * Returns: void function
 */
void TcpdumpInitLogFile(LogTcpdumpData *data)
{
    time_t curr_time;      /* place to stick the clock data */
    //struct tm *loc_time;   /* place to stick the adjusted clock data */
    //char timebuf[10];
    char logdir[STD_BUF];
    int value;

    bzero(logdir, STD_BUF);
    //bzero(timebuf, 10);
    curr_time = time(NULL);
    //loc_time = localtime(&curr_time);
    //strftime(timebuf,9,"%m%d@%H%M",loc_time);

    if(data->filename[0] == '/')
        value = SnortSnprintf(logdir, STD_BUF, "%s.%lu", data->filename, 
                              (unsigned long)curr_time);
    else
        value = SnortSnprintf(logdir, STD_BUF, "%s/%s.%lu", pv.log_dir, 
                              data->filename, (unsigned long)curr_time);

    if(value != SNORT_SNPRINTF_SUCCESS)
        FatalError("log file logging path and file name are too long\n");

    DEBUG_WRAP(DebugMessage(DEBUG_LOG, "Opening %s\n", logdir););

    if(!pv.test_mode_flag)
    {
        data->dumpd = pcap_dump_open(pd,logdir);
        if(data->dumpd == NULL)
        {
            FatalError("log_tcpdump TcpdumpInitLogFile(): %s\n", strerror(errno));
        }

        /* keep a copy of the filename for later reference */
        if(data->filename != NULL)
        {
            bzero( data->filename, strlen(data->filename) );
            free(data->filename);
            data->filename = strdup(logdir);
        }
    }

    return;
}



/*
 * Function: SpoLogTcpdumpCleanExitFunc()
 *
 * Purpose: Cleanup at exit time
 *
 * Arguments: signal => signal that caused this event
 *            arg => data ptr to reference this plugin's data
 *
 * Returns: void function
 */
void SpoLogTcpdumpCleanExitFunc(int signal, void *arg)
{
    /* cast the arg pointer to the proper type */
    LogTcpdumpData *data = (LogTcpdumpData *) arg;

    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"SpoLogTcpdumpCleanExitFunc\n"););

    /* close the output file */
    if( data->dumpd != NULL )
    {
        pcap_dump_close(data->dumpd);
        data->dumpd = NULL;
    }

    /* 
     * if we haven't written any data, dump the output file so there aren't
     * fragments all over the disk 
     */
    if(data->filename!=NULL && pc.alert_pkts==0 && pc.log_pkts==0)
    {
        unlink(data->filename);
    }

    /* free up initialized memory */
    if( data->filename != NULL )
    {
        bzero(data->filename, strlen(data->filename));
        free(data->filename);
    }
    bzero(data, sizeof(LogTcpdumpData));
    free(data);
}



/*
 * Function: SpoLogTcpdumpRestartFunc()
 *
 * Purpose: For restarts (SIGHUP usually) clean up structs that need it
 *
 * Arguments: signal => signal that caused this event
 *            arg => data ptr to reference this plugin's data
 *
 * Returns: void function
 */
void SpoLogTcpdumpRestartFunc(int signal, void *arg)
{

    LogTcpdumpData *data = (LogTcpdumpData *)arg;

    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"SpoLogTcpdumpRestartFunc\n"););

    if( data->dumpd != NULL )
    {
        pcap_dump_close(data->dumpd); 
        data->dumpd = NULL;
    }

    /* 
     * if we haven't written any data, dump the output file so there aren't
     * fragments all over the disk 
     */
    if(data->filename!=NULL && pc.alert_pkts==0 && pc.log_pkts==0)
    {
        unlink(data->filename);
    }

    if( data->filename != NULL )
    {
        bzero(data->filename, strlen(data->filename));
        free(data->filename);
    }
    bzero(data, sizeof(LogTcpdumpData));
    free(data);
}



void DirectLogTcpdump(struct pcap_pkthdr *ph, u_int8_t *pkt)
{
    pc.log_pkts++;
    pcap_dump((u_char *)log_tcpdump_ptr->dumpd, ph, pkt);
    return;
}
        
