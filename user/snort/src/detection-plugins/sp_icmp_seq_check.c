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
/* sp_icmp_seq_check 
 * 
 * Purpose:
 *
 * Test the Sequence number field of ICMP ECHO and ECHO_REPLY packets for 
 * specified values.  This is useful for detecting TFN attacks, amongst others.
 *
 * Arguments:
 *   
 * The ICMP Seq plugin takes a number as an option argument.
 *
 * Effect:
 *
 * Tests ICMP ECHO and ECHO_REPLY packet Seq field values and returns a 
 * "positive" detection result (i.e. passthrough) upon a value match.
 *
 * Comments:
 *
 * This plugin was developed to detect TFN distributed attacks.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <ctype.h>

#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "plugin_enum.h"


typedef struct _IcmpSeqData
{
    unsigned short icmpseq;

} IcmpSeqData; 

void IcmpSeqCheckInit(char *, OptTreeNode *, int);
void ParseIcmpSeq(char *, OptTreeNode *);
int IcmpSeqCheck(Packet *, struct _OptTreeNode *, OptFpList *);




/****************************************************************************
 * 
 * Function: SetupIcmpSeqCheck()
 *
 * Purpose: Registers the configuration function and links it to a rule
 *          keyword.  This is the function that gets called from InitPlugins
 *          in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupIcmpSeqCheck(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("icmp_seq", IcmpSeqCheckInit);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: IcmpSeqCheck Setup\n"););
}


/****************************************************************************
 * 
 * Function: IcmpSeqCheckInit(char *, OptTreeNode *)
 *
 * Purpose: Handles parsing the rule information and attaching the associated
 *          detection function to the OTN.
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void IcmpSeqCheckInit(char *data, OptTreeNode *otn, int protocol)
{
    if(protocol != IPPROTO_ICMP)
    {
        FatalError("%s(%d): ICMP Options on non-ICMP rule\n", file_name, file_line);
    }

    /* multiple declaration check */ 
    if(otn->ds_list[PLUGIN_ICMP_SEQ_CHECK])
    {
        FatalError("%s(%d): Multiple ICMP seq options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_ICMP_SEQ_CHECK] = (IcmpSeqData *)
        SnortAlloc(sizeof(IcmpSeqData));

    /* this is where the keyword arguments are processed and placed into the 
       rule option's data structure */
    ParseIcmpSeq(data, otn);

    /* finally, attach the option's detection function to the rule's 
       detect function pointer list */
    AddOptFuncToList(IcmpSeqCheck, otn);
}



/****************************************************************************
 * 
 * Function: ParseIcmpSeq(char *, OptTreeNode *)
 *
 * Purpose: Convert the rule option argument to program data.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseIcmpSeq(char *data, OptTreeNode *otn)
{
    IcmpSeqData *ds_ptr;  /* data struct pointer */

    /* set the ds pointer to make it easier to reference the option's
       particular data struct */
    ds_ptr = otn->ds_list[PLUGIN_ICMP_SEQ_CHECK];

    /* advance past whitespace */
    while(isspace((int)*data)) data++;

    ds_ptr->icmpseq = atoi(data);
    ds_ptr->icmpseq = htons(ds_ptr->icmpseq);
    
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Set ICMP Seq test value to %d\n", ds_ptr->icmpseq););
}


/****************************************************************************
 * 
 * Function: IcmpSeqCheck(char *, OptTreeNode *)
 *
 * Purpose: Compare the ICMP Sequence field to the rule value.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: If the detection test fails, this function *must* return a zero!
 *          On success, it calls the next function in the detection list 
 *
 ****************************************************************************/
int IcmpSeqCheck(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    if(!p->icmph)
        return 0; /* if error occured while icmp header
                   * was processed, return 0 automagically.
               */
    if(p->icmph->type == ICMP_ECHO || p->icmph->type == ICMP_ECHOREPLY)
    {
        /* test the rule ID value against the ICMP extension ID field */
        if(((IcmpSeqData *) otn->ds_list[PLUGIN_ICMP_SEQ_CHECK])->icmpseq == 
           p->icmph->s_icmp_seq)
        {
            /* call the next function in the function list recursively */
            return fp_list->next->OptTestFunc(p, otn, fp_list->next);
        }
        else
        {
            /* you can put debug comments here or not */
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"ICMP Seq check failed\n"););
        }
    }

    /* if the test isn't successful, this function *must* return 0 */
    return 0;
}
