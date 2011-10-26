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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "debug.h"
#include "parser.h"
#include "plugin_enum.h"
#include "util.h"

#define EQ                   0
#define GT                   1
#define LT                   2

typedef struct _DsizeCheckData
{
    int dsize;
    int dsize2;

} DsizeCheckData;

void DsizeCheckInit(char *, OptTreeNode *, int);
void ParseDsize(char *, OptTreeNode *);
int CheckDsizeEq(Packet *, struct _OptTreeNode *, OptFpList *);
int CheckDsizeGT(Packet *, struct _OptTreeNode *, OptFpList *);
int CheckDsizeLT(Packet *, struct _OptTreeNode *, OptFpList *);
int CheckDsizeRange(Packet *, struct _OptTreeNode *, OptFpList *);

/****************************************************************************
 * 
 * Function: SetupDsizeCheck()
 *
 * Purpose: Attach the dsize keyword to the rule parse function
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupDsizeCheck(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("dsize", DsizeCheckInit);
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: DsizeCheck Initialized\n"););
}


/****************************************************************************
 * 
 * Function: DsizeCheckInit(char *, OptTreeNode *)
 *
 * Purpose: Parse the rule argument and attach it to the rule data struct, 
 *          then attach the detection function to the function list
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void DsizeCheckInit(char *data, OptTreeNode *otn, int protocol)
{
    /* multiple declaration check */
    if(otn->ds_list[PLUGIN_DSIZE_CHECK])
    {
        FatalError("%s(%d): Multiple dsize options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */

    otn->ds_list[PLUGIN_DSIZE_CHECK] = (DsizeCheckData *)
        SnortAlloc(sizeof(DsizeCheckData));

    /* this is where the keyword arguments are processed and placed into the 
       rule option's data structure */
    ParseDsize(data, otn);

    /* NOTE: I moved the AddOptFuncToList call to the parsing function since
       the linking is best determined within that function */
}



/****************************************************************************
 * 
 * Function: ParseDsize(char *, OptTreeNode *)
 *
 * Purpose: Parse the dsize function argument and attach the detection
 *          function to the rule list as well.  
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseDsize(char *data, OptTreeNode *otn)
{
    DsizeCheckData *ds_ptr;  /* data struct pointer */
    char *pcEnd;
    char *pcTok;
    int  iDsize = 0;

    /* set the ds pointer to make it easier to reference the option's
       particular data struct */
    ds_ptr = (DsizeCheckData *)otn->ds_list[PLUGIN_DSIZE_CHECK];

    while(isspace((int)*data)) data++;

    /* If a range is specified, put min in ds_ptr->dsize and max in
       ds_ptr->dsize2 */
    
    if(isdigit((int)*data) && strchr(data, '<') && strchr(data, '>'))
    {
        pcTok = strtok(data, " <>");
        if(!pcTok)
        {
            /*
            **  Fatal
            */
            FatalError("%s(%d): Invalid 'dsize' argument.\n",
                       file_name, file_line);
        }

        iDsize = strtol(pcTok, &pcEnd, 10);
        if(iDsize < 0 || *pcEnd)
        {
            FatalError("%s(%d): Invalid 'dsize' argument.\n",
                       file_name, file_line);
        }

        ds_ptr->dsize = (unsigned short)iDsize;

        pcTok = strtok(NULL, " <>");
        if(!pcTok)
        {
            FatalError("%s(%d): Invalid 'dsize' argument.\n",
                       file_name, file_line);
        }

        iDsize = strtol(pcTok, &pcEnd, 10);
        if(iDsize < 0 || *pcEnd)
        {
            FatalError("%s(%d): Invalid 'dsize' argument.\n",
                       file_name, file_line);
        }

        ds_ptr->dsize2 = (unsigned short)iDsize;

#ifdef DEBUG
        printf("min dsize: %d\n", ds_ptr->dsize);
        printf("max dsize: %d\n", ds_ptr->dsize2);
#endif
        AddOptFuncToList(CheckDsizeRange, otn);
        return;
    }
    else if(*data == '>')
    {
        data++;
        AddOptFuncToList(CheckDsizeGT, otn);
    }
    else if(*data == '<')
    {
        data++;
        AddOptFuncToList(CheckDsizeLT, otn);
    }
    else
    {
        AddOptFuncToList(CheckDsizeEq, otn);
    }

    while(isspace((int)*data)) data++;

    iDsize = strtol(data, &pcEnd, 10);
    if(iDsize < 0 || *pcEnd)
    {
        FatalError("%s(%d): Invalid 'dsize' argument.\n",
                   file_name, file_line);
    }

    ds_ptr->dsize = (unsigned short)iDsize;

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Payload length = %d\n", ds_ptr->dsize););

}


/****************************************************************************
 * 
 * Function: CheckDsizeEq(char *, OptTreeNode *)
 *
 * Purpose: Test the packet's payload size against the rule payload size value
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns:  0 on failure, return value of next list function on success
 *
 ****************************************************************************/
int CheckDsizeEq(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{

    /* fake packet dsizes are always wrong */
    if(p->packet_flags & PKT_REBUILT_STREAM)
    {
        return 0;
    }
    
    if(((DsizeCheckData *)otn->ds_list[PLUGIN_DSIZE_CHECK])->dsize == p->dsize)
    {
        /* call the next function in the function list recursively */
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
    else
    {
        /* you can put debug comments here or not */
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Not equal\n"););
    }

    /* if the test isn't successful, return 0 */
    return 0;
}



/****************************************************************************
 * 
 * Function: CheckDsizeGT(char *, OptTreeNode *)
 *
 * Purpose: Test the packet's payload size against the rule payload size 
 *          value.  This test determines if the packet payload size is 
 *          greater than the rule dsize.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns:  0 on failure, return value of next list function on success
 *
 ****************************************************************************/
int CheckDsizeGT(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    /* fake packet dsizes are always wrong */
    if(p->packet_flags & PKT_REBUILT_STREAM)
    {
        return 0;
    }

    if(((DsizeCheckData *)otn->ds_list[PLUGIN_DSIZE_CHECK])->dsize < p->dsize)
    {
        /* call the next function in the function list recursively */
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
    else
    {
        /* you can put debug comments here or not */
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Not equal\n"););
    }

    /* if the test isn't successful, return 0 */
    return 0;
}




/****************************************************************************
 * 
 * Function: CheckDsizeLT(char *, OptTreeNode *)
 *
 * Purpose: Test the packet's payload size against the rule payload size 
 *          value.  This test determines if the packet payload size is 
 *          less than the rule dsize.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns:  0 on failure, return value of next list function on success
 *
 ****************************************************************************/
int CheckDsizeLT(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    /* fake packet dsizes are always wrong */
    if(p->packet_flags & PKT_REBUILT_STREAM)
    {
        return 0;
    }
    
    if(((DsizeCheckData *)otn->ds_list[PLUGIN_DSIZE_CHECK])->dsize > p->dsize)
    {
        /* call the next function in the function list recursively */
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
    else
    {
        /* you can put debug comments here or not */
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Not equal\n"););
    }

    /* if the test isn't successful, return 0 */
    return 0;
}


/****************************************************************************
 *
 * Function: CheckDsizeRange(char *, OptTreeNode *)
 *
 * Purpose: Test the packet's payload size against the rule payload size
 *          values.  This test determines if the packet payload size is
 *          in the range of the rule dsize min and max.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns:  0 on failure, return value of next list function on success
 *
 ****************************************************************************/
int CheckDsizeRange(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    /* fake packet dsizes are always wrong */
    if(p->packet_flags & PKT_REBUILT_STREAM)
    {
        return 0;
    }

    if(((DsizeCheckData *)otn->ds_list[PLUGIN_DSIZE_CHECK])->dsize <= p->dsize &&
     ((DsizeCheckData *)otn->ds_list[PLUGIN_DSIZE_CHECK])->dsize2 >= p->dsize)
    {
        /* call the next function in the function list recursively */
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,
                                "CheckDsizeRange(): not in range\n"););
    }

    return 0;
}
