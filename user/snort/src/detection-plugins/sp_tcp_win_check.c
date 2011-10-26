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
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <ctype.h>

#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "util.h"
#include "debug.h"
#include "plugin_enum.h"


typedef struct _TcpWinData
{
    u_int16_t tcp_win;
    u_int8_t not_flag;

} TcpWinData;

void TcpWinCheckInit(char *, OptTreeNode *, int);
void ParseTcpWin(char *, OptTreeNode *);
int TcpWinCheckEq(Packet *, struct _OptTreeNode *, OptFpList *);




/****************************************************************************
 * 
 * Function: SetupTcpWinCheck()
 *
 * Purpose: Associate the window keyword with TcpWinCheckInit
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupTcpWinCheck(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("window", TcpWinCheckInit);
}


/****************************************************************************
 * 
 * Function: TcpWinCheckInit(char *, OptTreeNode *)
 *
 * Purpose: Setup the window data struct and link the function into option
 *          function pointer list
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void TcpWinCheckInit(char *data, OptTreeNode *otn, int protocol)
{
    if(protocol != IPPROTO_TCP)
    {
        FatalError("%s(%d): TCP Options on non-TCP rule\n", 
                   file_name, file_line);
    }

    /* multiple declaration check */ 
    if(otn->ds_list[PLUGIN_TCP_WIN_CHECK])
    {
        FatalError("%s(%d): Multiple TCP window options in rule\n", file_name,
                file_line);
    }
        
    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_TCP_WIN_CHECK] = (TcpWinData *)
            SnortAlloc(sizeof(TcpWinData));

    /* this is where the keyword arguments are processed and placed into the 
       rule option's data structure */
    ParseTcpWin(data, otn);

    /* finally, attach the option's detection function to the rule's 
       detect function pointer list */
    AddOptFuncToList(TcpWinCheckEq, otn);
}



/****************************************************************************
 * 
 * Function: ParseTcpWin(char *, OptTreeNode *)
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
void ParseTcpWin(char *data, OptTreeNode *otn)
{
    TcpWinData *ds_ptr;  /* data struct pointer */
    u_int16_t win_size;

    /* set the ds pointer to make it easier to reference the option's
       particular data struct */
    ds_ptr = otn->ds_list[PLUGIN_TCP_WIN_CHECK];

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
        win_size = atoi(data);
    }
    else
    {
        if(index(data,(int)'x'))
        {
            win_size = (u_int16_t) strtol((index(data, (int)'x')+1), NULL, 16);
        }
        else
        {
            win_size = (u_int16_t) strtol((index(data, (int)'X')+1), NULL, 16);
        }
    }

    ds_ptr->tcp_win = htons(win_size);

#ifdef DEBUG
    printf("TCP Window set to 0x%X\n", ds_ptr->tcp_win);
#endif

}


/****************************************************************************
 * 
 * Function: TcpWinCheckEq(char *, OptTreeNode *)
 *
 * Purpose: Test the TCP header's window to see if its value is equal to the
 *          value in the rule.  
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
int TcpWinCheckEq(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    if(!p->tcph)
        return 0; /* if error occured while ip header
                   * was processed, return 0 automagically.
                   */

    if((((TcpWinData *)otn->ds_list[PLUGIN_TCP_WIN_CHECK])->tcp_win == p->tcph->th_win) ^ (((TcpWinData *)otn->ds_list[PLUGIN_TCP_WIN_CHECK])->not_flag))
    {
        /* call the next function in the function list recursively */
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
#ifdef DEBUG
    else
    {
        /* you can put debug comments here or not */
        DebugMessage(DEBUG_PLUGIN,"No match\n");
    }
#endif

    /* if the test isn't successful, return 0 */
    return 0;
}
