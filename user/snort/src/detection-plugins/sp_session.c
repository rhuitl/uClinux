/* $Id$ */

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

/* Snort Session Logging Plugin */

/* sp_session 
 * 
 * Purpose:
 *
 * Drops data (printable or otherwise) into a SESSION file.  Useful for 
 * logging user sessions (telnet, http, ftp, etc).
 *
 * Arguments:
 *   
 * This plugin can take two arguments:
 *    printable => only log the "printable" ASCII characters.
 *    all       => log all traffic in the session, logging non-printable
 *                 chars in "\xNN" hexidecimal format
 *
 * Effect:
 *
 * Warning, this plugin may slow Snort *way* down!
 *
 */

/* put the name of your pluging header file here */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include <sys/types.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* !WIN32 */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <errno.h>
#include <sys/stat.h>

#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "plugin_enum.h"
#include "snort.h"


#define SESSION_PRINTABLE  1
#define SESSION_ALL        2
#define SESSION_BINARY     3

typedef struct _SessionData
{
    int session_flag;
} SessionData;

void SessionInit(char *, OptTreeNode *, int);
void ParseSession(char *, OptTreeNode *);
int LogSessionData(Packet *, struct _OptTreeNode *, OptFpList *);
void DumpSessionData(FILE *, Packet *, struct _OptTreeNode *);
FILE *OpenSessionFile(Packet *);


/****************************************************************************
 * 
 * Function: SetupSession()
 *
 * Purpose: Init the session plugin module.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupSession(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("session", SessionInit);
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: Session Setup\n"););
}


/**************************************************************************
 * 
 * Function: SessionInit(char *, OptTreeNode *)
 *
 * Purpose: Initialize the sesion plugin, parsing the rule parameters and
 *          setting up any necessary data structures.
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 *************************************************************************/
void SessionInit(char *data, OptTreeNode *otn, int protocol)
{

    /*
     * Theoretically we should only all this plugin to be used when there's a 
     * possibility of a session happening (i.e. TCP), but I get enough 
     * requests that I'm going to pull the verifier so that things should work
     * for everyone
     */
/*    if(protocol != IPPROTO_TCP)
    {
        FatalError("%(%d): Session keyword can not be used in non-TCP rule\n",
                file_name, file_line);
    }*/

    /* multiple declaration check */ 
    if(otn->ds_list[PLUGIN_SESSION])
    {
        FatalError("%s(%d): Multiple session options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_SESSION] = (SessionData *)
        SnortAlloc(sizeof(SessionData));

    /* be sure to check that the protocol that is passed in matches the
       transport layer protocol that you're using for this rule! */

    /* this is where the keyword arguments are processed and placed into 
       the rule option's data structure */
    ParseSession(data, otn);

    /* finally, attach the option's detection function to the rule's 
       detect function pointer list */
    AddOptFuncToList(LogSessionData, otn);
}



/****************************************************************************
 * 
 * Function: ParseSession(char *, OptTreeNode *)
 *
 * Purpose: Figure out how much of the session data we're collecting
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseSession(char *data, OptTreeNode *otn)
{
    SessionData *ds_ptr;  /* data struct pointer */

    /* set the ds pointer to make it easier to reference the option's
       particular data struct */
    ds_ptr = otn->ds_list[PLUGIN_SESSION];

    /* manipulate the option arguments here */
    while(isspace((int)*data))
        data++;

    if(!strncasecmp(data, "printable", 9))
    {
        ds_ptr->session_flag = SESSION_PRINTABLE;
        return;
    }

    if(!strncasecmp(data, "binary", 6))
    {
        ds_ptr->session_flag = SESSION_BINARY;
        return;
    }

    if(!strncasecmp(data, "all", 3))
    {
        ds_ptr->session_flag = SESSION_ALL;
        return;
    }

    FatalError("%s(%d): invalid session modifier: %s\n", file_name, file_line, data);

}



/****************************************************************************
 * 
 * Function: LogSessionData(char *, OptTreeNode *)
 *
 * Purpose: Dumps the session data to the log file.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: Always calls the next function (this one doesn't test the data,
 *          it just logs it....)
 *
 ****************************************************************************/
int LogSessionData(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    FILE *session;         /* session file ptr */

    /* if there's data in this packet */
    if(p != NULL) 
    { 
        if((p->dsize != 0 && p->data != NULL) || p->frag_flag != 1)
        {
             session = OpenSessionFile(p);

             if(session == NULL)
             {
                 return fp_list->next->OptTestFunc(p, otn, fp_list->next);
             }

             DumpSessionData(session, p, otn);

             fclose(session);
        }
    }

    return fp_list->next->OptTestFunc(p, otn, fp_list->next);
}



void DumpSessionData(FILE *fp, Packet *p, struct _OptTreeNode *otn)
{
    u_char *idx;
    u_char *end;
    char conv[] = "0123456789ABCDEF"; /* xlation lookup table */

    if(p->dsize == 0 || p->data == NULL || p->frag_flag)
        return;

    idx = p->data;
    end = idx + p->dsize;

    if(((SessionData *) otn->ds_list[PLUGIN_SESSION])->session_flag == SESSION_PRINTABLE)
    {
        while(idx != end)
        {
            if((*idx > 0x1f && *idx < 0x7f) || *idx == 0x0a || *idx == 0x0d)
            {
                fputc(*idx, fp);
            }
            idx++;
        }
    }
    else if(((SessionData *) otn->ds_list[PLUGIN_SESSION])->session_flag == SESSION_BINARY)
    {
        fwrite(p->data, p->dsize, sizeof(char), fp);
    }
    else
    {
        while(idx != end)
        {
            if((*idx > 0x1f && *idx < 0x7f) || *idx == 0x0a || *idx == 0x0d)
            {
                /* Escape all occurences of '\' */
                if(*idx == '\\')
                    fputc('\\', fp);
                fputc(*idx, fp);
            }
            else
            {
                fputc('\\', fp);
                fputc(conv[((*idx&0xFF) >> 4)], fp);
                fputc(conv[((*idx&0xFF)&0x0F)], fp);
            }

            idx++;
        }
    }
}



FILE *OpenSessionFile(Packet *p)
{
    char filename[STD_BUF];
    char log_path[STD_BUF];
    char session_file[STD_BUF]; /* name of session file */
    FILE *ret;

    if(p->frag_flag)  
    {
        return NULL;
    }

    bzero((char *)session_file, STD_BUF);
    bzero((char *)log_path, STD_BUF);

    /* figure out which way this packet is headed in relation to the homenet */
    if((p->iph->ip_dst.s_addr & pv.netmask) == pv.homenet)
    {
        if((p->iph->ip_src.s_addr & pv.netmask) != pv.homenet)
        {
            SnortSnprintf(log_path, STD_BUF, "%s/%s", pv.log_dir, inet_ntoa(p->iph->ip_src));
        }
        else
        {
            if(p->sp >= p->dp)
            {
                SnortSnprintf(log_path, STD_BUF, "%s/%s", pv.log_dir, inet_ntoa(p->iph->ip_src));
            }
            else
            {
                SnortSnprintf(log_path, STD_BUF, "%s/%s", pv.log_dir, inet_ntoa(p->iph->ip_dst));
            }
        }
    }
    else
    {
        if((p->iph->ip_src.s_addr & pv.netmask) == pv.homenet)
        {
            SnortSnprintf(log_path, STD_BUF, "%s/%s", pv.log_dir, inet_ntoa(p->iph->ip_dst));
        }
        else
        {
            if(p->sp >= p->dp)
            {
                SnortSnprintf(log_path, STD_BUF, "%s/%s", pv.log_dir, inet_ntoa(p->iph->ip_src));
            }
            else
            {
                SnortSnprintf(log_path, STD_BUF, "%s/%s", pv.log_dir, inet_ntoa(p->iph->ip_dst));
            }
        }
    }

    /* build the log directory */
    if(mkdir(log_path,S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH))
    {
        if(errno != EEXIST)
        {
            FatalError("Problem creating directory %s: %s\n",
                       log_path,strerror(errno));
        }
    }

    if(p->sp >= p->dp)
    {
#ifdef WIN32
        SnortSnprintf(session_file, STD_BUF, "%s/SESSION_%d-%d", log_path, p->sp, p->dp);
#else
        SnortSnprintf(session_file, STD_BUF, "%s/SESSION:%d-%d", log_path, p->sp, p->dp);
#endif
    }
    else
    {
#ifdef WIN32
        SnortSnprintf(session_file, STD_BUF, "%s/SESSION_%d-%d", log_path, p->dp, p->sp);
#else
        SnortSnprintf(session_file, STD_BUF, "%s/SESSION:%d-%d", log_path, p->dp, p->sp);
#endif
    }

    
    strncpy(filename, session_file, STD_BUF - 1);
    filename[STD_BUF - 1] = '\0';

    ret = fopen(session_file, "a");

    if(ret == NULL)
    {
        FatalError("OpenSessionFile() => fopen(%s) session file: %s\n",
                   session_file, strerror(errno));
    }

    return ret;

}




