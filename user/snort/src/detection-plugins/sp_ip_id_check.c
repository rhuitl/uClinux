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
#include "parser.h"
#include "plugbase.h"
#include "debug.h"
#include "plugin_enum.h"
#include "util.h"

typedef struct _IpIdData
{
    u_long ip_id;

} IpIdData;

void IpIdCheckInit(char *, OptTreeNode *, int);
void ParseIpId(char *, OptTreeNode *);
int IpIdCheckEq(Packet *, struct _OptTreeNode *, OptFpList *);


/****************************************************************************
 * 
 * Function: SetupIpIdCheck()
 *
 * Purpose: Associate the id keyword with IpIdCheckInit
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupIpIdCheck(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("id", IpIdCheckInit);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Plugin: IpIdCheck Initialized\n"););
}


/****************************************************************************
 * 
 * Function: IpIdCheckInit(char *, OptTreeNode *)
 *
 * Purpose: Setup the id data struct and link the function into option
 *          function pointer list
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void IpIdCheckInit(char *data, OptTreeNode *otn, int protocol)
{
    /* multiple declaration check */ 
    if(otn->ds_list[PLUGIN_IP_ID_CHECK])
    {
        FatalError("%s(%d): Multiple IP id options in rule\n", file_name,
                file_line);
    }
        
    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_IP_ID_CHECK] = (IpIdData *)
            SnortAlloc(sizeof(IpIdData));

    /* this is where the keyword arguments are processed and placed into the 
       rule option's data structure */
    ParseIpId(data, otn);

    /* finally, attach the option's detection function to the rule's 
       detect function pointer list */
    AddOptFuncToList(IpIdCheckEq, otn);
}



/****************************************************************************
 * 
 * Function: ParseIpId(char *, OptTreeNode *)
 *
 * Purpose: Convert the id option argument to data and plug it into the 
 *          data structure
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseIpId(char *data, OptTreeNode *otn)
{
    IpIdData *ds_ptr;  /* data struct pointer */

    /* set the ds pointer to make it easier to reference the option's
       particular data struct */
    ds_ptr = otn->ds_list[PLUGIN_IP_ID_CHECK];

    /* get rid of any whitespace */
    while(isspace((int)*data))
    {
        data++;
    }

    ds_ptr->ip_id = htons( (u_short) atoi(data));

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"ID set to %ld\n", ds_ptr->ip_id););
}


/****************************************************************************
 * 
 * Function: IpIdCheckEq(char *, OptTreeNode *)
 *
 * Purpose: Test the ip header's id field to see if its value is equal to the
 *          value in the rule.  This is useful to detect things like "elite"
 *          numbers, oddly repeating numbers, etc.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
int IpIdCheckEq(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    if(!p->iph)
        return 0; /* if error occured while ip header
                   * was processed, return 0 automagically.
               */
    if(((IpIdData *)otn->ds_list[PLUGIN_IP_ID_CHECK])->ip_id == p->iph->ip_id)
    {
        /* call the next function in the function list recursively */
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
    else
    {
        /* you can put debug comments here or not */
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "No match for sp_ip_id_check\n"););
    }

    /* if the test isn't successful, return 0 */
    return 0;
}
