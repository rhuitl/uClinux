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
#include <string.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "plugin_enum.h"
#include "util.h"

typedef struct _IpTosData
{
    u_int8_t ip_tos;
    u_int8_t not_flag;

} IpTosData;

void IpTosCheckInit(char *, OptTreeNode *, int);
void ParseIpTos(char *, OptTreeNode *);
int IpTosCheckEq(Packet *, struct _OptTreeNode *, OptFpList *);



/****************************************************************************
 * 
 * Function: SetupIpTosCheck()
 *
 * Purpose: Associate the tos keyword with IpTosCheckInit
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupIpTosCheck(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("tos", IpTosCheckInit);
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: IpTosCheck Initialized\n"););
}


/****************************************************************************
 * 
 * Function: IpTosCheckInit(char *, OptTreeNode *)
 *
 * Purpose: Setup the tos data struct and link the function into option
 *          function pointer list
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void IpTosCheckInit(char *data, OptTreeNode *otn, int protocol)
{
    /* multiple declaration check */ 
    if(otn->ds_list[PLUGIN_IP_TOS_CHECK])
    {
        FatalError("%s(%d): Multiple IP tos options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_IP_TOS_CHECK] = (IpTosData *)
            SnortAlloc(sizeof(IpTosData));

    /* this is where the keyword arguments are processed and placed into the 
       rule option's data structure */
    ParseIpTos(data, otn);

    /* finally, attach the option's detection function to the rule's 
       detect function pointer list */
    AddOptFuncToList(IpTosCheckEq, otn);
}



/****************************************************************************
 * 
 * Function: ParseIpTos(char *, OptTreeNode *)
 *
 * Purpose: Convert the tos option argument to data and plug it into the 
 *          data structure
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseIpTos(char *data, OptTreeNode *otn)
{
    IpTosData *ds_ptr;  /* data struct pointer */

    /* set the ds pointer to make it easier to reference the option's
       particular data struct */
    ds_ptr = otn->ds_list[PLUGIN_IP_TOS_CHECK];

    /* get rid of any whitespace */
    while(isspace((int)*data))
    {
        data++;
    }

    if(data[0] == '!')
    {
        ds_ptr->not_flag = 1;
    }

    if(index(data, (int) 'x') == NULL && index(data, (int)'X') == NULL)
    {
        ds_ptr->ip_tos = atoi(data);
    }
    else
    {
        if(index(data,(int)'x'))
        {
            ds_ptr->ip_tos = (u_char) strtol((index(data, (int)'x')+1), NULL, 16);
        }
        else
        {
            ds_ptr->ip_tos = (u_char) strtol((index(data, (int)'X')+1), NULL, 16);
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"TOS set to %d\n", ds_ptr->ip_tos););
}


/****************************************************************************
 * 
 * Function: IpTosCheckEq(char *, OptTreeNode *)
 *
 * Purpose: Test the ip header's tos field to see if its value is equal to the
 *          value in the rule.  This is useful to detect things like the
 *	    "bubonic" DoS tool.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
int IpTosCheckEq(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    if(!p->iph)
        return 0; /* if error occured while ip header
                   * was processed, return 0 automagically.
                   */

    if((((IpTosData *)otn->ds_list[PLUGIN_IP_TOS_CHECK])->ip_tos == p->iph->ip_tos) ^ (((IpTosData *)otn->ds_list[PLUGIN_IP_TOS_CHECK])->not_flag))
    {
        /* call the next function in the function list recursively */
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
    else
    {
        /* you can put debug comments here or not */
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"No match\n"););
    }
    
    /* if the test isn't successful, return 0 */
    return 0;
}
