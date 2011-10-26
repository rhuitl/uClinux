/* $Id$ */
/*
 ** Copyright (C) 2002-2006 Sourcefire, Inc.
 ** Author: Martin Roesch
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

/* sp_clientserver 
 * 
 * Purpose:
 *
 * Wouldn't be nice if we could tell a TCP rule to only apply if it's going 
 * to or from the client or server side of a connection?  Think of all the 
 * false alarms we could elminate!  That's what we're doing with this one,
 * it allows you to write rules that only apply to client or server packets.
 * One thing though, you *must* have stream4 enabled for it to work!
 *
 * Arguments:
 *   
 *   None.
 *
 * Effect:
 *
 * Test the packet to see if it's coming from the client or the server side
 * of a connection.
 *
 * Comments:
 *
 * None.
 *
 */

/* put the name of your pluging header file here */

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
#include "snort.h"



typedef struct _ClientServerData
{
    u_int8_t from_server;
    u_int8_t from_client;    
    u_int8_t ignore_reassembled; /* ignore reassembled sessions */
    u_int8_t only_reassembled; /* ignore reassembled sessions */
} ClientServerData;

void FlowInit(char *, OptTreeNode *, int);
void ParseFlowArgs(char *, OptTreeNode *);
void InitFlowData(OptTreeNode *);
int CheckFromClient(Packet *, struct _OptTreeNode *, OptFpList *);
int CheckFromServer(Packet *, struct _OptTreeNode *, OptFpList *);
int CheckForReassembled(Packet *, struct _OptTreeNode *, OptFpList *);
int CheckForNonReassembled(Packet *p, struct _OptTreeNode *, OptFpList *);


/****************************************************************************
 * 
 * Function: SetupClientServer()
 *
 * Purpose: Generic detection engine plugin template.  Registers the
 *          configuration function and links it to a rule keyword.  This is
 *          the function that gets called from InitPlugins in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupClientServer(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("flow", FlowInit);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
                            "Plugin: ClientServerName(Flow) Setup\n"););
}


/****************************************************************************
 * 
 * Function: FlowInit(char *, OptTreeNode *)
 *
 * Purpose: Configure the flow init option to register the appropriate checks
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void FlowInit(char *data, OptTreeNode *otn, int protocol)
{
#ifdef STREAM4_UDP
    if ((protocol != IPPROTO_TCP) && (protocol != IPPROTO_UDP))
    {
        FatalError("%s(%d): Cannot check flow connection "
                   "for non-TCP and non-UDP traffic\n", file_name, file_line);
    }
#else
    if(protocol != IPPROTO_TCP)
    {
        FatalError("%s(%d): Cannot check flow connection "
                   "for non-TCP traffic\n", file_name, file_line);
    }
#endif

    /* multiple declaration check */
    if(otn->ds_list[PLUGIN_CLIENTSERVER])
    {
        FatalError("%s(%d): Multiple flow options in rule\n", file_name, 
                file_line);
    }
        

    InitFlowData(otn);
    ParseFlowArgs(data, otn);
}



/****************************************************************************
 * 
 * Function: ParseFlowArgs(char *, OptTreeNode *)
 *
 * Purpose: parse the arguments to the flow plugin and alter the otn
 *          accordingly
 *
 * Arguments: otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseFlowArgs(char *data, OptTreeNode *otn)
{
    char *token, *str, *p;
    ClientServerData *csd;

    csd = (ClientServerData *)otn->ds_list[PLUGIN_CLIENTSERVER];

    str = strdup(data);

    if(str == NULL)
    {
        FatalError("ParseFlowArgs: Can't strdup data\n");
    }

    p = str;

    /* nuke leading whitespace */
    while(isspace((int)*p)) p++;

    token = strtok(p, ",");

    while(token) 
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
                    "parsed %s,(%d)\n", token,strlen(token)););

        while(isspace((int)*token))
            token++;

        if(!strcasecmp(token, "to_server"))
        {
            csd->from_client = 1;
        }
        else if(!strcasecmp(token, "to_client"))
        {
            csd->from_server = 1;
        } 
        else if(!strcasecmp(token, "from_server"))
        {
            csd->from_server = 1;
        } 
        else if(!strcasecmp(token, "from_client"))
        {
            csd->from_client = 1;
        }
        else if(!strcasecmp(token, "stateless"))
        {
            otn->stateless = 1;
        }
        else if(!strcasecmp(token, "established"))
        {
            otn->established = 1;
        }
        else if(!strcasecmp(token, "not_established"))
        {
            otn->unestablished = 1;
        }
        else if(!strcasecmp(token, "no_stream"))
        {
            csd->ignore_reassembled = 1;
        }
        else if(!strcasecmp(token, "only_stream"))
        {
            csd->only_reassembled = 1;
        }
        else
        {
            FatalError("%s:%d: Unknown Flow Option: '%s'\n",
                       file_name,file_line,token);

        }


        token = strtok(NULL, ",");
    }

    if(csd->from_client && csd->from_server)
    {
        FatalError("%s:%d: Can't use both from_client"
                   "and flow_from server", file_name, file_line);
    }

    if(csd->ignore_reassembled && csd->only_reassembled)
    {
        FatalError("%s:%d: Can't use no_stream and"
                   " only_stream", file_name,file_line);
    }

    if(otn->stateless && (csd->from_client || csd->from_server)) 
    {
        FatalError("%s:%d: Can't use flow: stateless option with"
                   " other options", file_name, file_line);
    }

    if(otn->stateless && otn->established)
    {
        FatalError("%s:%d: Can't specify established and stateless "
                   "options in same rule\n", file_name, file_line);
    }

    if(otn->stateless && otn->unestablished)
    {
        FatalError("%s:%d: Can't specify unestablished and stateless "
                   "options in same rule\n", file_name, file_line);
    }

    if(otn->established && otn->unestablished)
    {
        FatalError("%s:%d: Can't specify unestablished and established "
                   "options in same rule\n", file_name, file_line);
    }

    if(csd->from_client) 
    {
        AddOptFuncToList(CheckFromClient, otn);
    } 

    if(csd->from_server) 
    {
        AddOptFuncToList(CheckFromServer, otn);
    }

    if(csd->ignore_reassembled) 
    {
        AddOptFuncToList(CheckForNonReassembled, otn);
    }

    if(csd->only_reassembled) 
    {
        AddOptFuncToList(CheckForReassembled, otn);
    }

    
    free(str);
}

/****************************************************************************
 * 
 * Function: InitFlowData(OptTreeNode *)
 *
 * Purpose: calloc the clientserver data node
 *
 * Arguments: otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void InitFlowData(OptTreeNode * otn)
{

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_CLIENTSERVER] = (ClientServerData *) 
        calloc(sizeof(ClientServerData), sizeof(char));

    if(otn->ds_list[PLUGIN_CLIENTSERVER] == NULL) 
    {
        FatalError("FlowData calloc Failed!\n");
    }
}

/****************************************************************************
 * 
 * Function: CheckFromClient(Packet *, struct _OptTreeNode *, OptFpList *)
 *
 * Purpose: Check to see if this packet came from the client side of the 
 *          connection.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: 0 on failure
 *
 ****************************************************************************/
int CheckFromClient(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
#ifdef DEBUG_CS
    DebugMessage(DEBUG_STREAM, "CheckFromClient: entering\n");
    if(p->packet_flags & PKT_REBUILT_STREAM)
    {
        DebugMessage(DEBUG_STREAM, "=> rebuilt!\n");
    }
#endif /* DEBUG_CS */    

    if(!pv.stateful)
    {
        /* if we're not in stateful mode we ignore this plugin */
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }

    if(p->packet_flags & PKT_FROM_CLIENT || 
            !(p->packet_flags & PKT_FROM_SERVER))
    {
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }

    /* if the test isn't successful, this function *must* return 0 */
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "CheckFromClient: returning 0\n"););
    return 0;
}


/****************************************************************************
 * 
 * Function: CheckFromServer(Packet *, struct _OptTreeNode *, OptFpList *)
 *
 * Purpose: Check to see if this packet came from the client side of the 
 *          connection.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: 0 on failure
 *
 ****************************************************************************/
int CheckFromServer(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    if(!pv.stateful)
    {
        /* if we're not in stateful mode we ignore this plugin */
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
    
    if(p->packet_flags & PKT_FROM_SERVER || 
            !(p->packet_flags & PKT_FROM_CLIENT))
    {
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }

    /* if the test isn't successful, this function *must* return 0 */
    return 0;
}


/****************************************************************************
 * 
 * Function: int CheckForReassembled(Packet *p, struct _OptTreeNode *otn,
                                    OptFpList *fp_list)
 *
 * Purpose: Check to see if this packet came from a reassembled connection
 *          connection.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: 0 on failure
 *
 ****************************************************************************/
int CheckForReassembled(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    /* is this a reassembled stream? */
    if(p->packet_flags & PKT_REBUILT_STREAM)
    {
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }

    /* if the test isn't successful, this function *must* return 0 */
    return 0;
}


/* 
 * Function: int CheckForNonReassembled(Packet *p, struct _OptTreeNode *otn,
                                    OptFpList *fp_list)
 *
 * Purpose: Check to see if this packet came from a reassembled connection
 *          connection.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: 0 on failure
 *
 ****************************************************************************/
int CheckForNonReassembled(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    /* is this a reassembled stream? */
    if(p->packet_flags & PKT_REBUILT_STREAM)
    {
        return 0;
    }

    /* if the test isn't successful, this function *must* return 0 */
    return fp_list->next->OptTestFunc(p, otn, fp_list->next);
}
