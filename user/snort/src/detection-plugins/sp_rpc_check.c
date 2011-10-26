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
#ifndef WIN32
#include <rpc/rpc.h>
#endif /* !WIN32 */

#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "plugin_enum.h"

/*
 * This is driven by 64-bit Solaris which doesn't
 * define _LONG
 * 
 */

#ifndef IXDR_GET_LONG
    #define IXDR_GET_LONG IXDR_GET_INT32
#endif

typedef struct _RpcCheckData
{
    u_long program; /* RPC program number */
    u_long vers; /* RPC program version */
    u_long proc; /* RPC procedure number */
    int flags; /* Which of the above fields have been specified */

} RpcCheckData;

#define RPC_CHECK_PROG 1
#define RPC_CHECK_VERS 2
#define RPC_CHECK_PROC 4

void RpcCheckInit(char *, OptTreeNode *, int);
void ParseRpc(char *, OptTreeNode *);
int CheckRpc(Packet *, struct _OptTreeNode *, OptFpList *);



/****************************************************************************
 * 
 * Function: SetupRpcCheck()
 *
 * Purpose: Register the rpc option keyword with its setup function
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupRpcCheck(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("rpc", RpcCheckInit);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: RPCCheck Initialized\n"););
}


/****************************************************************************
 * 
 * Function: RpcCheckInit(char *, OptTreeNode *)
 *
 * Purpose: Parse the rpc keyword arguments and link the detection module
 *          into the function list
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void RpcCheckInit(char *data, OptTreeNode *otn, int protocol)
{
    if(protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
    {
        FatalError("%s(%d) => Bad protocol in RPC Check rule...\n",
                   file_name, file_line);
    }

    /* multiple declaration check */ 
    if(otn->ds_list[PLUGIN_RPC_CHECK])
    {
        FatalError("%s(%d): Multiple rpc options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_RPC_CHECK] = (RpcCheckData *)
            SnortAlloc(sizeof(RpcCheckData));

    /* this is where the keyword arguments are processed and placed into the 
       rule option's data structure */
    ParseRpc(data, otn);

    /* finally, attach the option's detection function to the rule's 
       detect function pointer list */
    AddOptFuncToList(CheckRpc, otn);
}



/****************************************************************************
 * 
 * Function: ParseRpc(char *, OptTreeNode *)
 *
 * Purpose: Parse the RPC keyword's arguments
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseRpc(char *data, OptTreeNode *otn)
{
    RpcCheckData *ds_ptr;  /* data struct pointer */
    char *tmp = NULL;

    /* set the ds pointer to make it easier to reference the option's
       particular data struct */
    ds_ptr = otn->ds_list[PLUGIN_RPC_CHECK];
    ds_ptr->flags=0;

    /* advance past whitespace */
    while(isspace((int)*data)) data++;

    if(*data != '*')
    {
        ds_ptr->program = strtoul(data,&tmp,0);
        ds_ptr->flags|=RPC_CHECK_PROG;
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Set RPC program to %lu\n", ds_ptr->program););
    }
    else
    {
        FatalError("%s(%d): Invalid applicaion number in rpc rule option\n",file_name,file_line);
    }

    if(*tmp == '\0') return;

    data=++tmp;
    if(*data != '*')
    {
        ds_ptr->vers = strtoul(data,&tmp,0);
        ds_ptr->flags|=RPC_CHECK_VERS;
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Set RPC vers to %lu\n", ds_ptr->vers););
    }
    else
    {
        tmp++;
    }
    if(*tmp == '\0') return;
    data=++tmp;
    if(*data != '*')
    {
        ds_ptr->proc = strtoul(data,&tmp,0);
        ds_ptr->flags|=RPC_CHECK_PROC;
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Set RPC proc to %lu\n", ds_ptr->proc););
    }
}


/****************************************************************************
 * 
 * Function: CheckRpc(char *, OptTreeNode *)
 *
 * Purpose: Test if the packet RPC equals the rule option's rpc
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: 0 on failure, return value of next list function on success
 *
 ****************************************************************************/
int CheckRpc(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    RpcCheckData *ds_ptr;  /* data struct pointer */
    unsigned char* c=(unsigned char*)p->data;
    u_long xid, rpcvers, prog, vers, proc;
    enum msg_type direction;
#ifdef DEBUG
    int i;
#endif
    if(!p->iph || (p->iph->ip_proto == IPPROTO_TCP && !p->tcph)
       || (p->iph->ip_proto == IPPROTO_UDP && !p->udph))
        return 0; /* if error occured while ip header
                   * was processed, return 0 automagically.
               */

    if(p->iph->ip_proto == IPPROTO_TCP)
    {
        /* offset to rpc_msg */
        c+=4;
        /* Fail if the packet is too short to match */
        if(p->dsize<28)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "RPC packet too small"););
            return 0;
        }
    }
    else
    { /* must be UDP */
        /* Fail if the packet is too short to match */
        if(p->dsize<24)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "RPC packet too small"););
            return 0;
        }
    }

#ifdef DEBUG
    DebugMessage(DEBUG_PLUGIN,"<---xid---> <---dir---> <---rpc--->"
		 " <---prog--> <---vers--> <---proc-->\n");
    for(i=0; i<24; i++)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "%02X ",c[i]););
    }
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"\n"););
#endif

    /* Read xid */
    xid = IXDR_GET_LONG (c);

    /* Read direction : CALL or REPLY */
    direction = IXDR_GET_ENUM (c, enum msg_type);

    /* We only look at calls */
    if(direction != CALL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "RPC packet not a call"););
        return 0;
    }

    /* Read the RPC message version */
    rpcvers = IXDR_GET_LONG (c);

    /* Fail if it is not right */
    if(rpcvers != RPC_MSG_VERSION)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"RPC msg version invalid"););
        return 0;
    }

    /* Read the program number, version, and procedure */
    prog = IXDR_GET_LONG (c);
    vers = IXDR_GET_LONG (c);
    proc = IXDR_GET_LONG (c);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"RPC decoded to: %lu %lu %lu\n",
			    prog,vers,proc););

    ds_ptr=(RpcCheckData *)otn->ds_list[PLUGIN_RPC_CHECK];

    DEBUG_WRAP(
	       DebugMessage(DEBUG_PLUGIN, "RPC matching on: %d %d %d\n",
			    ds_ptr->flags & RPC_CHECK_PROG,ds_ptr->flags & RPC_CHECK_VERS,
			    ds_ptr->flags & RPC_CHECK_PROC););
    if(!(ds_ptr->flags & RPC_CHECK_PROG) ||
       ds_ptr->program == prog)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"RPC program matches"););
        if(!(ds_ptr->flags & RPC_CHECK_VERS) ||
           ds_ptr->vers == vers)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"RPC version matches"););
            if(!(ds_ptr->flags & RPC_CHECK_PROC) ||
               ds_ptr->proc == proc)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"RPC proc matches"););
		DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Yippee! Found one!"););
                /* call the next function in the function list recursively */
                return fp_list->next->OptTestFunc(p, otn, fp_list->next);
            }
        }
    }
    else
    {
        /* you can put debug comments here or not */
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"RPC not equal\n"););
    }

    /* if the test isn't successful, return 0 */
    return 0;
}
