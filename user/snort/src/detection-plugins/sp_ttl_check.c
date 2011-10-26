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

#include <stdlib.h>
#include <ctype.h>

#include "rules.h"
#include "decode.h"
#include "debug.h"
#include "plugbase.h"
#include "parser.h"
#include "plugin_enum.h"
#include "util.h"


typedef struct _TtlCheckData
{
    int ttl;
    int h_ttl;

} TtlCheckData;

void TtlCheckInit(char *, OptTreeNode *, int);
void ParseTtl(char *, OptTreeNode *);
int CheckTtlEq(Packet *, struct _OptTreeNode *, OptFpList *);
int CheckTtlGT(Packet *, struct _OptTreeNode *, OptFpList *);
int CheckTtlLT(Packet *, struct _OptTreeNode *, OptFpList *);
int CheckTtlRG(Packet *, struct _OptTreeNode *, OptFpList *);



/****************************************************************************
 * 
 * Function: SetupTtlCheck()
 *
 * Purpose: Register the ttl option keyword with its setup function
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupTtlCheck(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("ttl", TtlCheckInit);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: TTLCheck Initialized\n"););
}


/****************************************************************************
 * 
 * Function: TtlCheckInit(char *, OptTreeNode *)
 *
 * Purpose: Parse the ttl keyword arguments and link the detection module
 *          into the function list
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void TtlCheckInit(char *data, OptTreeNode *otn, int protocol)
{
    /* multiple declaration check */ 
    if(otn->ds_list[PLUGIN_TTL_CHECK])
    {
        FatalError("%s(%d): Multiple IP ttl options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_TTL_CHECK] = (TtlCheckData *)
            SnortAlloc(sizeof(TtlCheckData));

    /* this is where the keyword arguments are processed and placed into the 
       rule option's data structure */
    ParseTtl(data, otn);

    /* NOTE: the AddOptFuncToList call is moved to the parsing function since
       the linking is best determined within that function */
}



/****************************************************************************
 * 
 * Function: ParseTtl(char *, OptTreeNode *)
 *
 * Purpose: Parse the TTL keyword's arguments
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseTtl(char *data, OptTreeNode *otn)
{
    TtlCheckData *ds_ptr;  /* data struct pointer */
    char ttlrel;

    /* set the ds pointer to make it easier to reference the option's
       particular data struct */
    ds_ptr = (TtlCheckData *)otn->ds_list[PLUGIN_TTL_CHECK];

    while(isspace((int)*data)) data++;

    ttlrel = *data;

    switch (ttlrel) {
        case '-':
            ds_ptr->h_ttl = -1; /* leading dash flag */
        case '>':
        case '<':
        case '=':
            data++;
            break;
       default:     
            ttlrel = '=';
    }
    while(isspace((int)*data)) data++;

    ds_ptr->ttl = atoi(data);

    /* skip digit */
    while(isdigit((int)*data)) data++;
    /* and spaces.. if any */ 
    while(isspace((int)*data)) data++;
    if (*data == '-')
    {
        data++;
        ttlrel = '-';
    }
    switch (ttlrel) {
        case '>':
            AddOptFuncToList(CheckTtlGT, otn);
            break;
        case '<':     
            AddOptFuncToList(CheckTtlLT, otn);
            break;
        case '=':
            AddOptFuncToList(CheckTtlEq, otn);
            break;
        case '-':
            while(isspace((int)*data)) data++;
            if (ds_ptr->h_ttl != -1 && atoi(data) == 0)
            {
                ds_ptr->h_ttl = 255;
            }
            else
            {
                ds_ptr->h_ttl = atoi(data);
            }
            /* sanity check.. */
            if (ds_ptr->h_ttl < ds_ptr->ttl) 
            {
                ds_ptr->h_ttl = ds_ptr->ttl;
                ds_ptr->ttl   = atoi(data);
            }
            AddOptFuncToList(CheckTtlRG, otn);
            break;
        default:
            /* wtf? */
            /* we need at least one statement after "default" or else Visual C++ issues a warning */
            break;
    }
             

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Set TTL check value to %c%d (%d)\n", ttlrel, ds_ptr->ttl, ds_ptr->h_ttl););

}


/****************************************************************************
 * 
 * Function: CheckTtlEq(char *, OptTreeNode *)
 *
 * Purpose: Test if the packet TTL equals the rule option's ttl
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns:  0 on failure, return value of next list function on success
 *
 ****************************************************************************/
int CheckTtlEq(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    if(p->iph &&
        ((TtlCheckData *)otn->ds_list[PLUGIN_TTL_CHECK])->ttl == p->iph->ip_ttl)
    {
        /* call the next function in the function list recursively */
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
#ifdef DEBUG
    else
    {
        /* you can put debug comments here or not */
        DebugMessage(DEBUG_PLUGIN, "CheckTtlEq: Not equal to %d\n",
        ((TtlCheckData *)otn->ds_list[PLUGIN_TTL_CHECK])->ttl);
    }
#endif

    /* if the test isn't successful, return 0 */
    return 0;
}



/****************************************************************************
 * 
 * Function: CheckTtlGT(char *, OptTreeNode *)
 *
 * Purpose: Test the packet's payload size against the rule payload size 
 *          value.  This test determines if the packet payload size is 
 *          greater than the rule ttl.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns:  0 on failure, return value of next list function on success
 *
 ****************************************************************************/
int CheckTtlGT(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    if(p->iph &&
         ((TtlCheckData *)otn->ds_list[PLUGIN_TTL_CHECK])->ttl < p->iph->ip_ttl)
    {
        /* call the next function in the function list recursively */
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
#ifdef DEBUG
    else
    {
        /* you can put debug comments here or not */
        DebugMessage(DEBUG_PLUGIN, "CheckTtlGt: Not greater than %d\n",
        ((TtlCheckData *)otn->ds_list[PLUGIN_TTL_CHECK])->ttl);
    }
#endif

    /* if the test isn't successful, return 0 */
    return 0;
}




/****************************************************************************
 * 
 * Function: CheckTtlLT(char *, OptTreeNode *)
 *
 * Purpose: Test the packet's payload size against the rule payload size 
 *          value.  This test determines if the packet payload size is 
 *          less than the rule ttl.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns:  0 on failure, return value of next list function on success
 *
 ****************************************************************************/
int CheckTtlLT(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    if(p->iph &&
         ((TtlCheckData *)otn->ds_list[PLUGIN_TTL_CHECK])->ttl > p->iph->ip_ttl)
    {
        /* call the next function in the function list recursively */
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
#ifdef DEBUG
    else
    {
        /* you can put debug comments here or not */
        DebugMessage(DEBUG_PLUGIN, "CheckTtlLT: Not Less than %d\n",
        ((TtlCheckData *)otn->ds_list[PLUGIN_TTL_CHECK])->ttl);
    }
#endif

    /* if the test isn't successful, return 0 */
    return 0;
}





/****************************************************************************
 * 
 * Function: CheckTtlRG(char *, OptTreeNode *)
 *
 * Purpose: Test the packet's payload size against the rule payload size 
 *          value.  This test determines if the packet payload size is 
 *          within the rule ttl.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns:  0 on failure, return value of next list function on success
 *
 ****************************************************************************/
int CheckTtlRG(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    if(p->iph &&
         ((TtlCheckData *)otn->ds_list[PLUGIN_TTL_CHECK])->ttl <= p->iph->ip_ttl &&
         ((TtlCheckData *)otn->ds_list[PLUGIN_TTL_CHECK])->h_ttl >= p->iph->ip_ttl)
    {
        /* call the next function in the function list recursively */
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
#ifdef DEBUG
    else if (p->iph != NULL)
    {
        /* you can put debug comments here or not */
        DebugMessage(DEBUG_PLUGIN, "CheckTtlLT: Not Within the range %d - %d (%d)\n", 
                     ((TtlCheckData *)otn->ds_list[PLUGIN_TTL_CHECK])->ttl,
                     ((TtlCheckData *)otn->ds_list[PLUGIN_TTL_CHECK])->h_ttl,
                     p->iph->ip_ttl);
    }
#endif

    /* if the test isn't successful, return 0 */
    return 0;
}
