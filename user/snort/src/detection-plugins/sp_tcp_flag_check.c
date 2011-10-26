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
#include <ctype.h>

#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "plugin_enum.h"

#define M_NORMAL  0
#define M_ALL     1
#define M_ANY     2
#define M_NOT     3

typedef struct _TCPFlagCheckData
{
    u_char mode;
    u_char tcp_flags; 
    u_char tcp_mask; /* Mask to take away from the flags check */

} TCPFlagCheckData;

void TCPFlagCheckInit(char *, OptTreeNode *, int);
void ParseTCPFlags(char *, OptTreeNode *);
int CheckTcpFlags(Packet *, struct _OptTreeNode *, OptFpList *);



void SetupTCPFlagCheck(void)
{
    RegisterPlugin("flags", TCPFlagCheckInit);
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: TCPFlagCheck Initialized!\n"););
}



void TCPFlagCheckInit(char *data, OptTreeNode *otn, int protocol)
{
    if(protocol != IPPROTO_TCP)
    {
        FatalError("Line %s (%d): TCP Options on non-TCP rule\n", file_name, file_line);
    }

    /* multiple declaration check */ 
    if(otn->ds_list[PLUGIN_TCP_FLAG_CHECK])
    {
        FatalError("%s(%d): Multiple TCP flags options in rule\n", file_name,
                file_line);
    }

    otn->ds_list[PLUGIN_TCP_FLAG_CHECK] = (TCPFlagCheckData *)
            SnortAlloc(sizeof(TCPFlagCheckData));

    /* set up the pattern buffer */
    ParseTCPFlags(data, otn);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Adding TCP flag check function (%p) to list\n",
			    CheckTcpFlags););

    /* link the plugin function in to the current OTN */
    AddOptFuncToList(CheckTcpFlags, otn);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "OTN function CheckTcpFlags added to rule!\n"););
}



/****************************************************************************
 *
 * Function: ParseTCPflags(char *)
 *
 * Purpose: Figure out which TCP flags the current rule is interested in
 *
 * Arguments: rule => the rule string 
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseTCPFlags(char *rule, OptTreeNode *otn)
{
    char *fptr;
    char *fend;
    int comma_set = 0;
    TCPFlagCheckData *idx;

    idx = otn->ds_list[PLUGIN_TCP_FLAG_CHECK];

    fptr = rule;

    /* make sure there is atleast a split pointer */
    if(fptr == NULL) 
    {
        FatalError("[!] ERROR Line %s (%d): Flags missing in TCP flag rule\n", file_name, file_line);
    }

    while(isspace((u_char) *fptr))
        fptr++;

    if(strlen(fptr) == 0)
    {
        FatalError("[!] ERROR Line %s (%d): Flags missing in TCP flag rule\n", file_name, file_line);
    }

    /* find the end of the alert string */
    fend = fptr + strlen(fptr); 

    idx->mode = M_NORMAL; /* this is the default, unless overridden */

    while(fptr < fend && comma_set == 0)
    {
        switch(*fptr)
        {
            case 'f':
            case 'F':
                idx->tcp_flags |= R_FIN;
                break;

            case 's':
            case 'S':
                idx->tcp_flags |= R_SYN;
                break;

            case 'r':
            case 'R':
                idx->tcp_flags |= R_RST;
                break;

            case 'p':
            case 'P':
                idx->tcp_flags |= R_PSH;
                break;

            case 'a':
            case 'A':
                idx->tcp_flags |= R_ACK;
                break;

            case 'u':
            case 'U':
                idx->tcp_flags |= R_URG;
                break;

            case '0':
                idx->tcp_flags = 0;
                break;

            case '1': /* reserved bit flags */
                idx->tcp_flags |= R_RES1;
                break;

            case '2': /* reserved bit flags */
                idx->tcp_flags |= R_RES2;
                break;

            case '!': /* not, fire if all flags specified are not present,
                         other are don't care */
                idx->mode = M_NOT;
                break;
            case '*': /* star or any, fire if any flags specified are 
                         present, other are don't care */
                idx->mode = M_ANY;
                break;
            case '+': /* plus or all, fire if all flags specified are
                         present, other are don't care */
                idx->mode = M_ALL;
                break;
            case ',':
                comma_set = 1;
                break;
            default:
                FatalError("%s(%d): bad TCP flag = \"%c\"\n"
                           "Valid otions: UAPRSF12 or 0 for NO flags (e.g. NULL scan),"
                           " and !, + or * for modifiers\n",
                           file_name, file_line, *fptr);
        }

        fptr++;
    }

    while(isspace((u_char) *fptr))
        fptr++;

    
    /* create the mask portion now */
    while(fptr < fend && comma_set == 1)
    {
        switch(*fptr)
        {
            case 'f':
            case 'F':
                idx->tcp_mask |= R_FIN;
                break;

            case 's':
            case 'S':
                idx->tcp_mask |= R_SYN;
                break;

            case 'r':
            case 'R':
                idx->tcp_mask |= R_RST;
                break;

            case 'p':
            case 'P':
                idx->tcp_mask |= R_PSH;
                break;
                
            case 'a':
            case 'A':
                idx->tcp_mask |= R_ACK;
                break;
                
            case 'u':
            case 'U':
                idx->tcp_mask |= R_URG;
                break;
                
            case '1': /* reserved bit flags */
                idx->tcp_mask |= R_RES1;
                break;

            case '2': /* reserved bit flags */
                idx->tcp_mask |= R_RES2;
                break;
            default:
                FatalError(" Line %s (%d): bad TCP flag = \"%c\"\n  Valid otions: UAPRS12 \n",
                           file_name, file_line, *fptr);
        }

        fptr++;
    }
}


int CheckTcpFlags(Packet *p, struct _OptTreeNode *otn_idx, OptFpList *fp_list)
{
    TCPFlagCheckData *flagptr;
    u_char tcp_flags;

    
    flagptr = otn_idx->ds_list[PLUGIN_TCP_FLAG_CHECK];

    if(!p->tcph)
    {
        /* if error appeared when tcp header was processed,
         * test fails automagically */
        return 0; 
    }

    /* the flags we really want to check are all the ones
     */

    tcp_flags = p->tcph->th_flags & (0xFF ^ flagptr->tcp_mask);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "           <!!> CheckTcpFlags: "););

    switch((flagptr->mode))
    {
        case M_NORMAL:
            if(flagptr->tcp_flags == tcp_flags) /* only these set */
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Got TCP [default] flag match!\n"););
                return fp_list->next->OptTestFunc(p, otn_idx, fp_list->next);
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"No match\n"););
            }
            break;

        case M_ALL:
            /* all set */
            if((flagptr->tcp_flags & tcp_flags) == flagptr->tcp_flags)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Got TCP [ALL] flag match!\n"););
                return fp_list->next->OptTestFunc(p, otn_idx, fp_list->next);
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"No match\n"););
            }
            break;

        case M_NOT:
            if((flagptr->tcp_flags & tcp_flags) == 0)  /* none set */
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Got TCP [NOT] flag match!\n"););
                return fp_list->next->OptTestFunc(p, otn_idx, fp_list->next);
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "No match\n"););
            }
            break;

        case M_ANY:
            if((flagptr->tcp_flags & tcp_flags) != 0)  /* something set */
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Got TCP [ANY] flag match!\n"););
                return fp_list->next->OptTestFunc(p, otn_idx, fp_list->next);
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"No match\n"););
            }
            break;

        default:  /* Should never see this */
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "TCP flag check went to default case"
				    " for some silly reason\n"););
            break;
    }

    return 0;
}

