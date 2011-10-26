/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 2001 Brian Caswell <bmc@mitre.org>
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

/* spo_csv
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

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* !WIN32 */

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "event.h"
#include "decode.h"
#include "plugbase.h"
#include "spo_plugbase.h"
#include "parser.h"
#include "debug.h"
#include "mstring.h"
#include "util.h"
#include "log.h"

#include "snort.h"

#define DEFAULT_CSV "timestamp,sig_generator,sig_id,sig_rev,msg,proto,src,srcport,dst,dstport,ethsrc,ethdst,ethlen,tcpflags,tcpseq,tcpack,tcpln,tcpwindow,ttl,tos,id,dgmlen,iplen,icmptype,icmpcode,icmpid,icmpseq"

typedef struct _AlertCSVConfig
{
    char *type;
    struct _AlertCSVConfig *next;
} AlertCSVConfig;

typedef struct _AlertCSVData
{
    FILE *file;
    char * csvargs;
    char ** args;
    int numargs;
    AlertCSVConfig *config;
} AlertCSVData;


/* list of function prototypes for this preprocessor */
void AlertCSVInit(u_char *);
AlertCSVData *AlertCSVParseArgs(char *);
void AlertCSV(Packet *, char *, void *, Event *);
void AlertCSVCleanExit(int, void *);
void AlertCSVRestart(int, void *);
void RealAlertCSV(Packet * p, char *msg, FILE * file, char **args, 
        int numargs, Event *event);
static char *CSVEscape(char *input);

/*
 * Function: SetupCSV()
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
void AlertCSVSetup(void)
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterOutputPlugin("alert_CSV", NT_OUTPUT_ALERT, AlertCSVInit);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output plugin: alert_CSV is setup...\n"););
}


/*
 * Function: CSVInit(u_char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
void AlertCSVInit(u_char *args)
{
    AlertCSVData *data;
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output: CSV Initialized\n"););

    pv.alert_plugin_active = 1;

    /* parse the argument list from the rules file */
    data = AlertCSVParseArgs(args);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Linking CSV functions to call lists...\n"););

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(AlertCSV, NT_OUTPUT_ALERT, data);
    AddFuncToCleanExitList(AlertCSVCleanExit, data);
    AddFuncToRestartList(AlertCSVRestart, data);
}

/*
 * Function: ParseCSVArgs(char *)
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
AlertCSVData *AlertCSVParseArgs(char *args)
{
    char **toks;
    int num_toks; 
    char *filename;
    AlertCSVData *data;
    /*    SpoCSVConfig *config; */

    data = (AlertCSVData *)SnortAlloc(sizeof(AlertCSVData));
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "ParseCSVArgs: %s\n", args););

    toks = mSplit(args, " ", 2, &num_toks, 0);

    if(num_toks <= 1)
    {
        FatalError("You must supply at least TWO arguments for "
                   "the CSV plugin...\n"
                   "\t ... arguements of \"/path/to/output/file default\" "
                   "as a minimum.\n");
    }
 
    filename = ProcessFileOption(toks[0]);
    data->file = OpenAlertFile(filename);
    free(filename);
    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"AlertCSV Got filename\n"););

    if(!strncasecmp("default", toks[1], 7))
    {
	    data->csvargs = strdup(DEFAULT_CSV);
    }
    else
    {
	    data->csvargs = strdup(toks[1]); 
    } 

    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"AlertCSV Got Config ARGS\n"););
    
    mSplitFree(&toks, num_toks);
    toks = mSplit(data->csvargs, ",", 128, &num_toks, 0);

    data->args = toks;
    data->numargs = num_toks;

    return data;
}

void AlertCSVCleanExit(int signal, void *arg)
{
    AlertCSVData *data = (AlertCSVData *)arg;
    /* close alert file */
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"CSVCleanExitFunc\n"););
    
    if(data) 
    {
        mSplitFree(&data->args, data->numargs);
        fclose(data->file);
        free(data->csvargs);
        /* free memory from SpoCSVData */
        free(data);
    }
    
}

void AlertCSVRestart(int signal, void *arg)
{
    AlertCSVData *data = (AlertCSVData *)arg;
    /* close alert file */
    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"CSVRestartFunc\n"););

    if(data) 
    {
        mSplitFree(&data->args, data->numargs);
        fclose(data->file);
        free(data->csvargs);
        /* free memory from SpoCSVData */
        free(data);
    }
}


void AlertCSV(Packet *p, char *msg, void *arg, Event *event)
{
    AlertCSVData *data = (AlertCSVData *)arg;
    RealAlertCSV(p, msg, data->file, data->args, data->numargs, event); 
    return;
}



/*
 *
 * Function: AlertCSV(Packet *, char *, FILE *, char *, numargs const int)
 *
 * Purpose: Write a user defined CSV message
 *
 * Arguments:     p => packet. (could be NULL)
 *              msg => the message to send
 *             file => file pointer to print data to
 *             args => CSV output arguements 
 *          numargs => number of arguements
 * Returns: void function
 *
 */
void RealAlertCSV(Packet * p, char *msg, FILE * file, char **args, 
        int numargs, Event *event)
{
    char timestamp[TIMEBUF_SIZE];
    int num; 
    char *type;
    char tcpFlags[9];

    if(p == NULL)
	return;

    bzero((char *) timestamp, TIMEBUF_SIZE);
    ts_print(p == NULL ? NULL : (struct timeval *) & p->pkth->ts, timestamp);

    DEBUG_WRAP(DebugMessage(DEBUG_LOG,"Logging CSV Alert data\n");); 

    for (num = 0; num < numargs; num++)
    {
	type = args[num];

	DEBUG_WRAP(DebugMessage(DEBUG_LOG, "CSV Got type %s %d\n", type, num);); 

	if(!strncasecmp("timestamp", type, 9))
	{
	    fwrite(timestamp, strlen(timestamp), 1, file);
	}
	else if(!strncasecmp("sig_generator",type,13))
	{
	   if(event != NULL)
	   {
	       fprintf(file, "%lu",  (unsigned long) event->sig_generator);
	   }
	}
	else if(!strncasecmp("sig_id",type,6))
	{
	   if(event != NULL)
	   {
	      fprintf(file, "%lu",  (unsigned long) event->sig_id);
	   }
	}
	else if(!strncasecmp("sig_rev",type,7))
	{
	   if(event != NULL)
	   {
	      fprintf(file, "%lu",  (unsigned long) event->sig_rev);
 	   }
	}
	else if(!strncasecmp("msg", type, 3))
	{
        /* Escape the msg */
        char *escaped_msg;
        if(!(escaped_msg = CSVEscape(msg)))
        {
            FatalError("Out of memory escaping msg string");
        }
	    fwrite(escaped_msg, strlen(escaped_msg),1,file);
        free(escaped_msg);
	}
	else if(!strncasecmp("proto", type, 5))
	{
        if(p->iph)
        {
            switch (p->iph->ip_proto)
            {
                case IPPROTO_UDP:
                    fwrite("UDP", 3,1,file);
                    break;
                case IPPROTO_TCP:
                    fwrite("TCP", 3,1,file);
                    break;
                case IPPROTO_ICMP:
                    fwrite("ICMP", 4,1,file);
                    break;
            }
        }
	}
	else if(!strncasecmp("ethsrc", type, 6))
	{
	    if(p->eh)
	    {
            fprintf(file, "%X:%X:%X:%X:%X:%X", p->eh->ether_src[0],
            p->eh->ether_src[1], p->eh->ether_src[2], p->eh->ether_src[3],
            p->eh->ether_src[4], p->eh->ether_src[5]);
	    }
	} 
	else if(!strncasecmp("ethdst", type, 6))
	{
	    if(p->eh)
	    {
            fprintf(file, "%X:%X:%X:%X:%X:%X", p->eh->ether_dst[0],
            p->eh->ether_dst[1], p->eh->ether_dst[2], p->eh->ether_dst[3],
            p->eh->ether_dst[4], p->eh->ether_dst[5]);
	    }
	}
	else if(!strncasecmp("ethtype", type, 7))
	{
	    if(p->eh)
	    {
            fprintf(file,"0x%X",ntohs(p->eh->ether_type));
	    }
	}
	else if(!strncasecmp("udplength", type, 9))
	{
	    if(p->udph)
		fprintf(file,"%d",ntohs(p->udph->uh_len));
	}
	else if(!strncasecmp("ethlen", type, 6))
	{
	    if(p->eh)
            fprintf(file,"0x%X",p->pkth->len);
	}
	else if(!strncasecmp("trheader", type, 8))
	{
	    if(p->trh)
            PrintTrHeader(file, p);
	}
	else if(!strncasecmp("srcport", type, 7))
	{
        if(p->iph)
        {
	        switch(p->iph->ip_proto)
	        {
	            case IPPROTO_UDP:
	            case IPPROTO_TCP:
		            fprintf(file, "%d", p->sp);
		            break;
	        }    
        }
	}
	else if(!strncasecmp("dstport", type, 7))
	{
        if(p->iph)
        {
	        switch(p->iph->ip_proto)
	        {
	            case IPPROTO_UDP:
	            case IPPROTO_TCP:
		            fprintf(file, "%d", p->dp);
		            break;
	        }    
        }
	}
	else if(!strncasecmp("src", type, 3))
	{
        if(p->iph)
            fputs(inet_ntoa(p->iph->ip_src), file);
	}
	else if(!strncasecmp("dst", type, 3))
	{
        if(p->iph)
            fputs(inet_ntoa(p->iph->ip_dst), file); 
	}
	else if(!strncasecmp("icmptype",type,8))
	{
	    if(p->icmph)
	    {
		fprintf(file,"%d",p->icmph->type);
	    }
	}
	else if(!strncasecmp("icmpcode",type,8))
	{
	    if(p->icmph)
	    {
		fprintf(file,"%d",p->icmph->code);
	    }
	}
	else if(!strncasecmp("icmpid",type,6))
	{
	    if(p->icmph)
            fprintf(file,"%d",ntohs(p->icmph->s_icmp_id));	   
	}
	else if(!strncasecmp("icmpseq",type,7))
	{
	    if(p->icmph)
		    fprintf(file,"%d",ntohs(p->icmph->s_icmp_seq));
	}
	else if(!strncasecmp("ttl",type,3))
	{
	    if(p->iph)
		fprintf(file,"%d",p->iph->ip_ttl);
	}
	else if(!strncasecmp("tos",type,3))
	{
	    if(p->iph)
		fprintf(file,"%d",p->iph->ip_tos);
	}
	else if(!strncasecmp("id",type,2))
	{
	    if(p->iph)
		fprintf(file,"%d",ntohs(p->iph->ip_id));
	}
	else if(!strncasecmp("iplen",type,5))
	{
	    if(p->iph)
		fprintf(file,"%d",IP_HLEN(p->iph) << 2);
	}
	else if(!strncasecmp("dgmlen",type,6))
	{
	    if(p->iph)
		fprintf(file,"%d",ntohs(p->iph->ip_len));
	}
	else if(!strncasecmp("tcpseq",type,6))
	{
	    if(p->tcph)
		fprintf(file,"0x%lX",(u_long) ntohl(p->tcph->th_seq));
	}
	else if(!strncasecmp("tcpack",type,6))
	{
	    if(p->tcph)
		fprintf(file,"0x%lX",(u_long) ntohl(p->tcph->th_ack));
	}
	else if(!strncasecmp("tcplen",type,6))
	{
	    if(p->tcph)
		fprintf(file,"%d",TCP_OFFSET(p->tcph) << 2);
	}
	else if(!strncasecmp("tcpwindow",type,9))
	{
	    if(p->tcph)
		fprintf(file,"0x%X",ntohs(p->tcph->th_win));
	}
	else if(!strncasecmp("tcpflags",type,8))
	{
	    if(p->tcph)
	    {   
		CreateTCPFlagString(p, tcpFlags);
		fprintf(file,"%s", tcpFlags);
	    }
	}

	if (num < numargs - 1) 
	    fwrite(",",1,1,file);
    }
    fputc('\n', file);
   

    return;
}


char *CSVEscape(char *input)
{
    size_t strLen;
    char *buffer;
    char *current;
    if((strchr(input, ',') == NULL) && (strchr(input, '"') == NULL))
        return strdup(input);
    /* max size of escaped string is 2*size + 3, so we allocate that much */
    strLen = strlen(input);
    buffer = (char *)SnortAlloc((strLen * 2) + 3);
    current = buffer;
    *current = '"';
    ++current;
    while(*input != '\0')
    {
        switch(*input)
        {
            case '"':
                *current = '\\';
                ++current;
                *current = '"';
                ++current;
                break;
            case '\\':
                *current = '\\';
                ++current;
                *current = '\\';
                ++current;
                break;
            default:
                *current = *input;
                ++current;
                break;
        }
        ++input;
    }
    *current = '"';
    return buffer;
}

