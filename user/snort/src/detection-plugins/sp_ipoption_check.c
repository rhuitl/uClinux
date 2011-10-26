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

#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "plugin_enum.h"


typedef struct _IpOptionData
{
    u_char ip_option;
    u_char any_flag;

} IpOptionData;

void IpOptionInit(char *, OptTreeNode *, int);
void ParseIpOptionData(char *, OptTreeNode *);
int CheckIpOptions(Packet *, struct _OptTreeNode *, OptFpList *);

/****************************************************************************
 * 
 * Function: SetupTemplate()
 *
 * Purpose: Generic detection engine plugin template.  Registers the
 *          configuration function and links it to a rule keyword.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupIpOptionCheck(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("ipopts", IpOptionInit);
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Plugin: IpOptionCheck Initialized\n"););
}


/****************************************************************************
 * 
 * Function: TemplateInit(char *, OptTreeNode *)
 *
 * Purpose: Generic rule configuration function.  Handles parsing the rule 
 *          information and attaching the associated detection function to
 *          the OTN.
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void IpOptionInit(char *data, OptTreeNode *otn, int protocol)
{
    /* multiple declaration check */ 
    if(otn->ds_list[PLUGIN_IPOPTION_CHECK])
    {
        FatalError("%s(%d): Multiple ipopts options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_IPOPTION_CHECK] = (IpOptionData *)
            SnortAlloc(sizeof(IpOptionData));

    /* this is where the keyword arguments are processed and placed into the 
       rule option's data structure */
    ParseIpOptionData(data, otn);

    /* finally, attach the option's detection function to the rule's 
       detect function pointer list */
    AddOptFuncToList(CheckIpOptions, otn);
}



/****************************************************************************
 * 
 * Function: TemplateRuleParseFunction(char *, OptTreeNode *)
 *
 * Purpose: This is the function that is used to process the option keyword's
 *          arguments and attach them to the rule's data structures.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseIpOptionData(char *data, OptTreeNode *otn)
{
    IpOptionData *ds_ptr;  /* data struct pointer */

    /* set the ds pointer to make it easier to reference the option's
       particular data struct */
    ds_ptr = otn->ds_list[PLUGIN_IPOPTION_CHECK];

    if(data == NULL)
    {
        FatalError("%s(%d): IP Option keyword missing argument!\n", file_name, file_line);
    }

    while(isspace((u_char)*data))
        data++; 


    if(!strncasecmp(data, "rr", 2))
    {
        ds_ptr->ip_option = IPOPT_RR;
        return;
    }
    else if(!strncasecmp(data, "eol", 3))
    {
        ds_ptr->ip_option = IPOPT_EOL;
        return;
    }
    else if(!strncasecmp(data, "nop", 3))
    {
        ds_ptr->ip_option = IPOPT_NOP;
        return;
    }
    else if(!strncasecmp(data, "ts", 2))
    {
        ds_ptr->ip_option = IPOPT_TS;
        return;
    }
    else if(!strncasecmp(data, "sec", 3))
    {
        ds_ptr->ip_option = IPOPT_SECURITY;
        return;
    }
    else if(!strncasecmp(data, "lsrr", 4))
    {
        ds_ptr->ip_option = IPOPT_LSRR;
        return;
    }
    else if(!strncasecmp(data, "lsrre", 5))
    {
        ds_ptr->ip_option = IPOPT_LSRR_E;
        return;
    }
    else if(!strncasecmp(data, "satid", 5))
    {
        ds_ptr->ip_option = IPOPT_SATID;
        return;
    }
    else if(!strncasecmp(data, "ssrr", 4))
    {
        ds_ptr->ip_option = IPOPT_SSRR;
        return;
    }
    else if(!strncasecmp(data, "any", 3))
    {
        ds_ptr->ip_option = 0;
        ds_ptr->any_flag = 1;
        return;
    }
    else
    {
        FatalError("%s(%d) => Unknown IP option argument: %s!\n",
                   file_name, file_line, data);
    }
}


/****************************************************************************
 * 
 * Function: TemplateDetectorFunction(char *, OptTreeNode *)
 *
 * Purpose: Use this function to perform the particular detection routine
 *          that this rule keyword is supposed to encompass.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
int CheckIpOptions(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    int i;
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "CheckIpOptions:"););
    if(!p->iph)
        return 0; /* if error occured while ip header
                   * was processed, return 0 automagically.
               */

    if((((IpOptionData *)otn->ds_list[PLUGIN_IPOPTION_CHECK])->any_flag == 1) 
       && (p->ip_option_count > 0))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Matched any ip options!\n"););
        /* call the next function in the function list recursively */
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }

    for(i=0; i< (int) p->ip_option_count; i++)
    {
	DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "testing pkt(%d):rule(%d)\n",
				((IpOptionData *)otn->ds_list[PLUGIN_IPOPTION_CHECK])->ip_option,
				p->ip_options[i].code); );

        if(((IpOptionData *)otn->ds_list[PLUGIN_IPOPTION_CHECK])->ip_option == p->ip_options[i].code)
        {
            /* call the next function in the function list recursively */
            return fp_list->next->OptTestFunc(p, otn, fp_list->next);
        }
    }

    /* if the test isn't successful, return 0 */
    return 0;
}
