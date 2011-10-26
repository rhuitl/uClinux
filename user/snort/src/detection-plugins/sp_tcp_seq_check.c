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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>

#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "util.h"
#include "debug.h"
#include "plugin_enum.h"



typedef struct _TcpSeqCheckData
{
    u_long tcp_seq;

} TcpSeqCheckData;

void TcpSeqCheckInit(char *, OptTreeNode *, int);
void ParseTcpSeq(char *, OptTreeNode *);
int CheckTcpSeqEq(Packet *, struct _OptTreeNode *, OptFpList *);



/****************************************************************************
 * 
 * Function: SetupTcpSeqCheck()
 *
 * Purpose: Link the seq keyword to the initialization function
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupTcpSeqCheck(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("seq", TcpSeqCheckInit);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Plugin: TcpSeqCheck Initialized\n"););
}


/****************************************************************************
 * 
 * Function: TcpSeqCheckInit(char *, OptTreeNode *)
 *
 * Purpose: Attach the option data to the rule data struct and link in the
 *          detection function to the function pointer list.
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void TcpSeqCheckInit(char *data, OptTreeNode *otn, int protocol)
{
    if(protocol != IPPROTO_TCP)
    {
        FatalError("Line %s (%d): TCP Options on non-TCP rule\n", file_name, file_line);
    }

    /* multiple declaration check */ 
    if(otn->ds_list[PLUGIN_TCP_SEQ_CHECK])
    {
        FatalError("%s(%d): Multiple TCP seq options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_TCP_SEQ_CHECK] = (TcpSeqCheckData *)
            SnortAlloc(sizeof(TcpSeqCheckData));

    /* this is where the keyword arguments are processed and placed into the 
       rule option's data structure */
    ParseTcpSeq(data, otn);

    /* finally, attach the option's detection function to the rule's 
       detect function pointer list */
    AddOptFuncToList(CheckTcpSeqEq, otn);
}



/****************************************************************************
 * 
 * Function: ParseTcpSeq(char *, OptTreeNode *)
 *
 * Purpose: Attach the option rule's argument to the data struct.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseTcpSeq(char *data, OptTreeNode *otn)
{
    char **ep = NULL;
    TcpSeqCheckData *ds_ptr;  /* data struct pointer */

    /* set the ds pointer to make it easier to reference the option's
       particular data struct */
    ds_ptr = otn->ds_list[PLUGIN_TCP_SEQ_CHECK];

    ds_ptr->tcp_seq = strtoul(data, ep, 0);
    ds_ptr->tcp_seq = htonl(ds_ptr->tcp_seq);
 
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Seq set to %lX\n", ds_ptr->tcp_seq););

}


/****************************************************************************
 * 
 * Function: CheckTcpSeqEq(char *, OptTreeNode *)
 *
 * Purpose: Check to see if the packet's TCP ack field is equal to the rule
 *          ack value.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
int CheckTcpSeqEq(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    if(!p->tcph)
        return 0; /* if error appeared when tcp header was processed,
               * test fails automagically */

    if(((TcpSeqCheckData *)otn->ds_list[PLUGIN_TCP_SEQ_CHECK])->tcp_seq == 
       p->tcph->th_seq)
    {
        /* call the next function in the function list recursively */
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
#ifdef DEBUG
    else
    {
        /* you can put debug comments here or not */
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"No match\n"););
    }
#endif

    /* if the test isn't successful, return 0 */
    return 0;
}
