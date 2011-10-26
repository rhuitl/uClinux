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

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* !WIN32 */
#include <time.h>
#include <errno.h>


#include "plugbase.h"
#include "spo_plugbase.h"
#include "snort.h"
#include "debug.h"
#include "util.h"
#include "log.h"
#include "detect.h"

/* built-in preprocessors */
#include "preprocessors/spp_rpc_decode.h"
#include "preprocessors/spp_bo.h"
#include "preprocessors/spp_telnet_negotiation.h"
#include "preprocessors/spp_stream4.h"
#include "preprocessors/spp_stream5.h"
#include "preprocessors/spp_frag2.h"
#include "preprocessors/spp_arpspoof.h"
#include "preprocessors/spp_perfmonitor.h"
#include "preprocessors/spp_httpinspect.h"
#include "preprocessors/spp_flow.h"
#include "preprocessors/spp_sfportscan.h"
#include "preprocessors/spp_frag3.h"

/* built-in detection plugins */
#include "detection-plugins/sp_pattern_match.h"
#include "detection-plugins/sp_tcp_flag_check.h"
#include "detection-plugins/sp_icmp_type_check.h"
#include "detection-plugins/sp_icmp_code_check.h"
#include "detection-plugins/sp_ttl_check.h"
#include "detection-plugins/sp_ip_id_check.h"
#include "detection-plugins/sp_tcp_ack_check.h"
#include "detection-plugins/sp_tcp_seq_check.h"
#include "detection-plugins/sp_dsize_check.h"
#include "detection-plugins/sp_ipoption_check.h"
#include "detection-plugins/sp_rpc_check.h"
#include "detection-plugins/sp_icmp_id_check.h"
#include "detection-plugins/sp_icmp_seq_check.h"
#include "detection-plugins/sp_session.h"
#include "detection-plugins/sp_ip_tos_check.h"
#include "detection-plugins/sp_ip_fragbits.h"
#include "detection-plugins/sp_tcp_win_check.h"
#include "detection-plugins/sp_ip_same_check.h"
#include "detection-plugins/sp_ip_proto.h"
#include "detection-plugins/sp_ip_same_check.h"
#include "detection-plugins/sp_clientserver.h"
#include "detection-plugins/sp_byte_check.h"
#include "detection-plugins/sp_byte_jump.h"
#include "detection-plugins/sp_isdataat.h"
#include "detection-plugins/sp_pcre.h"
#include "detection-plugins/sp_flowbits.h"
#include "detection-plugins/sp_asn1.h"
#if defined(ENABLE_RESPONSE) && !defined(ENABLE_RESPONSE2)
#include "detection-plugins/sp_react.h"
#include "detection-plugins/sp_respond.h"
#elif defined(ENABLE_RESPONSE2) && !defined(ENABLE_RESPONSE)
#include "detection-plugins/sp_respond2.h"
#endif
#if defined(ENABLE_REACT) && !defined(ENABLE_RESPONSE)
#include "detection-plugins/sp_react.h"
#endif
#include "detection-plugins/sp_ftpbounce.h"
#include "detection-plugins/sp_urilen_check.h"

/* built-in output plugins */
#include "output-plugins/spo_alert_syslog.h"
#include "output-plugins/spo_log_tcpdump.h"
#include "output-plugins/spo_database.h"
#include "output-plugins/spo_alert_fast.h"
#include "output-plugins/spo_alert_full.h"
#include "output-plugins/spo_alert_unixsock.h"
#include "output-plugins/spo_csv.h"
#include "output-plugins/spo_unified.h"
#include "output-plugins/spo_log_null.h"
#include "output-plugins/spo_log_ascii.h"

#ifdef ARUBA
#include "output-plugins/spo_alert_arubaaction.h"
#endif

#ifdef HAVE_LIBPRELUDE
#include "output-plugins/spo_alert_prelude.h"
#endif

#ifdef LINUX
#include "output-plugins/spo_alert_sf_socket.h"
#endif

PluginSignalFuncNode *PluginShutdownList;
PluginSignalFuncNode *PluginCleanExitList;
PluginSignalFuncNode *PluginRestartList;
PluginSignalFuncNode *PluginPostConfigList;

PreprocSignalFuncNode *PreprocShutdownList;
PreprocSignalFuncNode *PreprocCleanExitList;
PreprocSignalFuncNode *PreprocRestartList;

extern int file_line;
extern char *file_name;




/**************************** Detection Plugin API ****************************/
KeywordXlateList *KeywordList;

void InitPlugIns()
{
    if(!pv.quiet_flag)
    {
        LogMessage("Initializing Plug-ins!\n");
    }
    SetupPatternMatch();
    SetupTCPFlagCheck();
    SetupIcmpTypeCheck();
    SetupIcmpCodeCheck();
    SetupTtlCheck();
    SetupIpIdCheck();
    SetupTcpAckCheck();
    SetupTcpSeqCheck();
    SetupDsizeCheck();
    SetupIpOptionCheck();
    SetupRpcCheck();
    SetupIcmpIdCheck();
    SetupIcmpSeqCheck();
    SetupSession();
    SetupIpTosCheck();
    SetupFragBits();
    SetupFragOffset();
    SetupTcpWinCheck();
    SetupIpProto();
    SetupIpSameCheck();
    SetupClientServer();
    SetupByteTest();
    SetupByteJump();
    SetupIsDataAt();
    SetupPcre();
    SetupFlowBits();
    SetupAsn1();
#if defined(ENABLE_RESPONSE) && !defined(ENABLE_RESPONSE2)
    SetupReact();
    SetupRespond();
#elif defined(ENABLE_RESPONSE2) && !defined(ENABLE_RESPONSE)
    SetupRespond2();
#endif
#if defined(ENABLE_REACT) && !defined(ENABLE_RESPONSE)
    SetupReact();
#endif
    SetupFTPBounce();
    SetupUriLenCheck();
}

/****************************************************************************
 *
 * Function: RegisterPlugin(char *, void (*func)())
 *
 * Purpose:  Associates a rule option keyword with an option setup/linking
 *           function.
 *
 * Arguments: keyword => The option keyword to associate with the option
 *                       handler
 *            *func => function pointer to the handler
 *
 * Returns: void function
 *
 ***************************************************************************/
void RegisterPlugin(char *keyword, void (*func) (char *, OptTreeNode *, int))
{
    KeywordXlateList *idx;

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Registering keyword:func => %s:%p\n",
               keyword, func););

    idx = KeywordList;

    if(idx == NULL)
    {
        KeywordList = (KeywordXlateList *)SnortAlloc(sizeof(KeywordXlateList));

        KeywordList->entry.keyword = (char *)SnortAlloc((strlen(keyword) + 1) * sizeof(char));

        SnortStrncpy(KeywordList->entry.keyword, keyword, strlen(keyword) + 1);
        KeywordList->entry.func = func;
    }
    else
    {
        /* go to the end of the list */
        while(idx->next != NULL)
        {
            if(!strcasecmp(idx->entry.keyword, keyword))
            {
                FatalError("RegisterPlugin: Duplicate detection plugin keyword:"
                        " (%s) (%s)!\n", idx->entry.keyword, keyword);
            }
            idx = idx->next;
        }

        idx->next = (KeywordXlateList *)SnortAlloc(sizeof(KeywordXlateList));

        idx = idx->next;

        idx->entry.keyword = (char *)SnortAlloc((strlen(keyword) + 1) * sizeof(char));
        SnortStrncpy(idx->entry.keyword, keyword, strlen(keyword) + 1);
        idx->entry.func = func;
    }
}




/****************************************************************************
 *
 * Function: DumpPlugIns()
 *
 * Purpose:  Prints the keyword->function list
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ***************************************************************************/
void DumpPlugIns()
{
    KeywordXlateList *idx;

    if(pv.quiet_flag)
        return;

    idx = KeywordList;

    printf("-------------------------------------------------\n");
    printf(" Keyword     |      Plugin Registered @\n");
    printf("-------------------------------------------------\n");
    while(idx != NULL)
    {
        printf("%-13s:      %p\n", idx->entry.keyword, idx->entry.func);
        idx = idx->next;
    }
    printf("-------------------------------------------------\n\n");
}


/****************************************************************************
 * 
 * Function: AddOptFuncToList(int (*func)(), OptTreeNode *)
 *
 * Purpose: Links the option detection module to the OTN
 *
 * Arguments: (*func)() => function pointer to the detection module
 *            otn =>  pointer to the current OptTreeNode
 *
 * Returns: void function
 *
 ***************************************************************************/
OptFpList *AddOptFuncToList(int (*func) (Packet *, struct _OptTreeNode *, 
            struct _OptFpList *), OptTreeNode * otn)
{
    OptFpList *idx;     /* index pointer */

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Adding new rule to list\n"););

    /* set the index pointer to the start of this OTN's function list */
    idx = otn->opt_func;

    /* if there are no nodes on the function list... */
    if(idx == NULL)
    {
        /* calloc the list head */
        otn->opt_func = (OptFpList *)calloc(1, sizeof(OptFpList));

        if(otn->opt_func == NULL)
        {
            FatalError("new node calloc failed: %s\n",
                       strerror(errno));
        }

        /* set the head function */
        otn->opt_func->OptTestFunc = func;

        idx = otn->opt_func;
    }
    else
    {
        /* walk to the end of the list */
        while(idx->next != NULL)
        {
            idx = idx->next;
        }

        /* allocate a new node on the end of the list */
        idx->next = (OptFpList *)calloc(1, sizeof(OptFpList));

        if(idx->next == NULL)
        {
            FatalError("AddOptFuncToList new node calloc failed: %s\n",
                       strerror(errno));
        }

        /* move up to the new node */
        idx = idx->next;

        /* link the function to the new node */
        idx->OptTestFunc = func;

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Set OptTestFunc to %p\n", 
                    func););
    }

    return idx;
}

/****************************************************************************
 *
 * Function: AddRspFuncToList(int (*func)(), OptTreeNode *)
 *
 * Purpose: Adds Response function to OTN
 *
 * Arguments: (*func)() => function pointer to the response module
 *            otn =>  pointer to the current OptTreeNode
 *
 * Returns: void function
 *
 ***************************************************************************/
void AddRspFuncToList(int (*func) (Packet *, struct _RspFpList *), OptTreeNode * otn, void *params)
{
    RspFpList *idx;     /* index pointer */

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Adding response to list\n"););

    /* set the index pointer to the start of this OTN's function list */
    idx = otn->rsp_func;

    /* if there are no nodes on the function list... */
    if(idx == NULL)
    {
        /* calloc the list head */
        otn->rsp_func = (RspFpList *)calloc(1, sizeof(RspFpList));

        if(otn->rsp_func == NULL)
        {
            FatalError("AddRspFuncToList new node calloc failed: %s\n", strerror(errno));
        }
        /* set the head function */
        otn->rsp_func->ResponseFunc = func;
        otn->rsp_func->params = params;
    }
    else
    {
        /* walk to the end of the list */
        while(idx->next != NULL)
        {
            idx = idx->next;
        }

        /* allocate a new node on the end of the list */
        idx->next = (RspFpList *)calloc(1, sizeof(RspFpList));

        if(idx->next == NULL)
        {
            FatalError("AddRspFuncToList new node calloc failed: %s\n", strerror(errno));
        }
        /* link the function to the new node */
        idx->next->ResponseFunc = func;
        idx->next->params = params;

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Set ResponseFunc to %p\n", func););
    }
}


/************************* End Detection Plugin API ***************************/


/************************** Preprocessor Plugin API ***************************/
PreprocessKeywordList *PreprocessKeywords = NULL;
PreprocessFuncNode *PreprocessList = NULL;
PreprocessCheckConfigNode *PreprocessConfigCheckList = NULL;

void InitPreprocessors()
{
    if(!pv.quiet_flag)
    {
        LogMessage("Initializing Preprocessors!\n");
    }
    SetupRpcDecode();
    SetupBo();
    SetupTelNeg();
    SetupStream4();
    SetupFrag2();
    SetupARPspoof();
    SetupHttpInspect();
    SetupPerfMonitor();
    SetupFlow();
    SetupPsng();
    SetupFrag3();
    SetupStream5();
}

void CheckPreprocessorsConfig()
{
    PreprocessCheckConfigNode *idx;

    idx = PreprocessConfigCheckList;

    if(!pv.quiet_flag)
    {
        LogMessage("Verifying Preprocessor Configurations!\n");
    }

    while(idx != NULL)
    {
        idx->func();
        idx = idx->next;
    }
}

void PostConfigInitPlugins()
{
    PluginSignalFuncNode *idx;

    idx = PluginPostConfigList;

    while (idx != NULL)
    {
        idx->func(0, idx->arg);
        idx = idx->next;
    }
}

/****************************************************************************
 *
 * Function: RegisterPreprocessor(char *, void (*func)(u_char *))
 *
 * Purpose:  Associates a preprocessor statement with its function.
 *
 * Arguments: keyword => The option keyword to associate with the
 *                       preprocessor
 *            *func => function pointer to the handler
 *
 * Returns: void function
 *
 ***************************************************************************/
void RegisterPreprocessor(char *keyword, void (*func) (u_char *))
{
    PreprocessKeywordList *idx;

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Registering keyword:preproc => %s:%p\n", keyword, func););

    idx = PreprocessKeywords;

    if(idx == NULL)
    {
        /* alloc the node */
        PreprocessKeywords = (PreprocessKeywordList *)SnortAlloc(sizeof(PreprocessKeywordList));

        /* alloc space for the keyword */
        PreprocessKeywords->entry.keyword = (char *)SnortAlloc((strlen(keyword) + 1) * sizeof(char));

        /* copy the keyword into the struct */
        SnortStrncpy(PreprocessKeywords->entry.keyword, keyword, strlen(keyword) + 1);

        /* set the function pointer to the keyword handler function */
        PreprocessKeywords->entry.func = (void *) func;
    }
    else
    {
        /* loop to the end of the list */
        while(idx->next != NULL)
        {
            if(!strcasecmp(idx->entry.keyword, keyword))
            {
                FatalError("%s(%d) => Duplicate preprocessor keyword!\n",
                           file_name, file_line);
            }
            idx = idx->next;
        }

        idx->next = (PreprocessKeywordList *)SnortAlloc(sizeof(PreprocessKeywordList));

        idx = idx->next;

        /* alloc space for the keyword */
        idx->entry.keyword = (char *)SnortAlloc((strlen(keyword) + 1) * sizeof(char));

        /* copy the keyword into the struct */
        SnortStrncpy(idx->entry.keyword, keyword, strlen(keyword) + 1);

        /* set the function pointer to the keyword handler function */
        idx->entry.func = (void *) func;
    }
}




/****************************************************************************
 *
 * Function: DumpPreprocessors()
 *
 * Purpose:  Prints the keyword->preprocess list
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ***************************************************************************/
void DumpPreprocessors()
{
    PreprocessKeywordList *idx;

    if(pv.quiet_flag)
        return;
    idx = PreprocessKeywords;

    printf("-------------------------------------------------\n");
    printf(" Keyword     |       Preprocessor @ \n");
    printf("-------------------------------------------------\n");
    while(idx != NULL)
    {
        printf("%-13s:       %p\n", idx->entry.keyword, idx->entry.func);
        idx = idx->next;
    }
    printf("-------------------------------------------------\n\n");
}

static SFGHASH *preprocIdTable = NULL;
unsigned int num_preprocs = 0;
int IsPreprocBitSet(Packet *p, unsigned int preproc_bit)
{
#if 0
    int preproc_bit;
    PreprocessFuncNode *idx = sfghash_find(preprocIdTable, &preproc_id);
    if (idx)
    {
        preproc_bit = idx->preproc_bit;
        return boIsBitSet(p->preprocessor_bits, preproc_bit);
    }
    return 0;
#endif
    return boIsBitSet(p->preprocessor_bits, preproc_bit);
}

int SetPreprocBit(Packet *p, unsigned int preproc_id)
{
    int preproc_bit;
    PreprocessFuncNode *idx = sfghash_find(preprocIdTable, &preproc_id);
    if (idx)
    {
        preproc_bit = idx->preproc_bit;
        return boSetBit(p->preprocessor_bits, preproc_bit);
    }
    return 0;
}

PreprocessFuncNode *AddFuncToPreprocList(void (*func) (Packet *, void *),
        unsigned short priority,
        unsigned int preproc_id)
{
    PreprocessFuncNode *idx;
    PreprocessFuncNode *tmpNext;
    PreprocessFuncNode *insertAfter = NULL;

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,
        "Adding preprocessor function ID %d/bit %d/pri %d to list\n",
         preproc_id, num_preprocs, priority););
    idx = PreprocessList;

    if(idx == NULL)
    {
        PreprocessList = (PreprocessFuncNode *)SnortAlloc(sizeof(PreprocessFuncNode));

        PreprocessList->func = func;
        PreprocessList->priority = priority;
        PreprocessList->preproc_id = preproc_id;
        PreprocessList->preproc_bit = num_preprocs++;

        idx = PreprocessList;
    }
    else
    {
        do
        {
            if (idx->preproc_id == preproc_id)
            {
                FatalError("Preprocessor already registered with ID %d\n",
                        preproc_id);
                return NULL;
            }
            
            if (idx->priority > priority)
                break;
            insertAfter = idx;
            idx = idx->next;
        }
        while (idx);

        idx = (PreprocessFuncNode *)SnortAlloc(sizeof(PreprocessFuncNode));
        if (insertAfter)
        {
            tmpNext = insertAfter->next;
            insertAfter->next = idx;
            idx->next = tmpNext;
        }
        else
        {
            idx->next = PreprocessList;
            PreprocessList = idx;
        }

        idx->func = func;
        idx->priority = priority;
        idx->preproc_id = preproc_id;
        idx->preproc_bit = num_preprocs++;
    }

    return idx;
}

void MapPreprocessorIds()
{
    PreprocessFuncNode *idx;
    if (preprocIdTable || !num_preprocs)
        return;

    preprocIdTable = sfghash_new(num_preprocs, 4, 1, NULL);

    idx = PreprocessList;

    while (idx)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,
                   "Adding preprocessor ID %d/bit %d/pri %d to hash table\n",
                   idx->preproc_id, idx->preproc_bit, idx->priority););
        sfghash_add(preprocIdTable, &(idx->preproc_id), idx);
        idx = idx->next;
    }
}

PreprocessCheckConfigNode *AddFuncToConfigCheckList(void (*func)(void))
{
    PreprocessCheckConfigNode *idx;

    idx = PreprocessConfigCheckList;

    if(idx == NULL)
    {
        PreprocessConfigCheckList = (PreprocessCheckConfigNode *)SnortAlloc(sizeof(PreprocessCheckConfigNode));

        PreprocessConfigCheckList->func = func;

        idx = PreprocessConfigCheckList;
    }
    else
    {
        while(idx->next != NULL)
            idx = idx->next;

        idx->next = (PreprocessCheckConfigNode *)SnortAlloc(sizeof(PreprocessCheckConfigNode));

        idx = idx->next;
        idx->func = func;
    }

    return idx;
}

/* functions to aid in cleaning up aftre plugins */
void AddFuncToPreprocRestartList(void (*func) (int, void *), void *arg,
        unsigned short priority, unsigned int preproc_id)
{
    PreprocRestartList = AddFuncToPreprocSignalList(func, arg, PreprocRestartList, priority, preproc_id);
}

void AddFuncToPreprocCleanExitList(void (*func) (int, void *), void *arg,
        unsigned short priority, unsigned int preproc_id)
{
    PreprocCleanExitList = AddFuncToPreprocSignalList(func, arg, PreprocCleanExitList, priority, preproc_id);
}

void AddFuncToPreprocShutdownList(void (*func) (int, void *), void *arg,
        unsigned short priority, unsigned int preproc_id)
{
    PreprocShutdownList = AddFuncToPreprocSignalList(func, arg, PreprocShutdownList, priority, preproc_id);
}

PreprocSignalFuncNode *AddFuncToPreprocSignalList(void (*func) (int, void *), void *arg,
                                          PreprocSignalFuncNode * list, unsigned short priority, unsigned int preproc_id)
{
    PreprocSignalFuncNode *idx;
    PreprocSignalFuncNode *insertAfter = NULL;
    PreprocSignalFuncNode *tmpNext;

    idx = list;

    if(idx == NULL)
    {
        idx = (PreprocSignalFuncNode *)SnortAlloc(sizeof(PreprocSignalFuncNode));

        idx->func = func;
        idx->arg = arg;
        idx->preproc_id = preproc_id;
        idx->priority = priority;
        list = idx;
    }
    else
    {
        do
        {
            if (idx->priority > priority)
                break;

            insertAfter = idx;
            idx = idx->next;
        }
        while(idx);

        idx = (PreprocSignalFuncNode *)SnortAlloc(sizeof(PreprocSignalFuncNode));
        if (insertAfter)
        {
            tmpNext = insertAfter->next;
            insertAfter->next = idx;
            idx->next = tmpNext;
        }
        else
        {
            idx->next = list;
            list = idx;
        }

        idx->func = func;
        idx->arg = arg;
        idx->priority = priority;
        idx->preproc_id = preproc_id;
    }

    return list;
}

/************************ End Preprocessor Plugin API  ************************/

/***************************** Output Plugin API  *****************************/
OutputKeywordList *OutputKeywords;
OutputFuncNode *AlertList;
OutputFuncNode *LogList;
OutputFuncNode *AppendOutputFuncList(void (*) (Packet *,char *,void *,Event*),
                void *, OutputFuncNode *);

void InitOutputPlugins()
{
    if(!pv.quiet_flag)
    {
        LogMessage("Initializing Output Plugins!\n");
    }
    AlertSyslogSetup();
    LogTcpdumpSetup();
    DatabaseSetup();
    AlertFastSetup();
    AlertFullSetup();
#ifndef WIN32
    /* Win32 doesn't support AF_UNIX sockets */
    AlertUnixSockSetup();
#endif /* !WIN32 */
    AlertCSVSetup();
    LogNullSetup();
    UnifiedSetup();
    LogAsciiSetup();

#ifdef ARUBA
    AlertArubaActionSetup();
#endif

#ifdef LINUX
    /* This uses linux only capabilities */
    AlertSFSocket_Setup();
#endif

#ifdef HAVE_LIBPRELUDE
    AlertPreludeSetup();
#endif
}

int ActivateOutputPlugin(char *plugin_name, char *plugin_options)
{
    OutputKeywordNode *plugin;
    
    if(!plugin_name)
        return -1;
    
    /* get the output plugin node */
    if(!(plugin = GetOutputPlugin(plugin_name)))
        return -1;

    switch(plugin->node_type)
    {
        case NT_OUTPUT_SPECIAL: /* both alert & logging in one plugin */
            plugin->func(plugin_options);
            break;
        case NT_OUTPUT_ALERT:
            plugin->func(plugin_options);
            break;
        case NT_OUTPUT_LOG:
            plugin->func(plugin_options);
            break;
    }

    return 0;
}

OutputKeywordNode *GetOutputPlugin(char *plugin_name)
{
    OutputKeywordList *list_node;

    if(!plugin_name)
        return NULL;

    list_node = OutputKeywords;

    while(list_node)
    {
        if(strcasecmp(plugin_name, list_node->entry.keyword) == 0)
            return &(list_node->entry);
        list_node = list_node->next;
    }
    FatalError("unknown output plugin: '%s'", 
               plugin_name);

    return NULL;
}


/****************************************************************************
 *
 * Function: RegisterOutputPlugin(char *, void (*func)(Packet *, u_char *))
 *
 * Purpose:  Associates an output statement with its function.
 *
 * Arguments: keyword => The output keyword to associate with the
 *                       output processor
 *            type => alert or log types
 *            *func => function pointer to the handler
 *
 * Returns: void function
 *
 ***************************************************************************/
void RegisterOutputPlugin(char *keyword, int type, void (*func) (u_char *))
{
    OutputKeywordList *idx;

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Registering keyword:output => %s:%p\n", 
                keyword, func););

    idx = OutputKeywords;

    if(idx == NULL)
    {
        /* alloc the node */
        OutputKeywords = (OutputKeywordList *)SnortAlloc(sizeof(OutputKeywordList));

        idx = OutputKeywords;
    }
    else
    {
        /* loop to the end of the list */
        while(idx->next != NULL)
        {
            if(!strcasecmp(idx->entry.keyword, keyword))
            {
                FatalError("%s(%d) => Duplicate output keyword!\n", 
                        file_name, file_line);
            }
            idx = idx->next;
        }

        idx->next = (OutputKeywordList *)SnortAlloc(sizeof(OutputKeywordList));

        idx = idx->next;
    }

    /* alloc space for the keyword */
    idx->entry.keyword = (char *)SnortAlloc((strlen(keyword) + 1) * sizeof(char));

    /* copy the keyword into the struct */
    SnortStrncpy(idx->entry.keyword, keyword, strlen(keyword) + 1);

    /*
     * set the plugin type, needed to determine whether an overriding command
     * line arg has been specified
     */
    idx->entry.node_type = (char) type;

    /* set the function pointer to the keyword handler function */
    idx->entry.func = (void *) func;
}


/****************************************************************************
 *
 * Function: DumpOutputPlugins()
 *
 * Purpose:  Prints the keyword->preprocess list
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ***************************************************************************/
void DumpOutputPlugins()
{
    OutputKeywordList *idx;

    if(pv.quiet_flag)
        return;

    idx = OutputKeywords;

    printf("-------------------------------------------------\n");
    printf(" Keyword     |          Output @ \n");
    printf("-------------------------------------------------\n");
    while(idx != NULL)
    {
        printf("%-13s:       %p\n", idx->entry.keyword, idx->entry.func);
        idx = idx->next;
    }
    printf("-------------------------------------------------\n\n");
}

extern ListHead *head_tmp;

void AddFuncToOutputList(void (*func) (Packet *, char *, void *, Event *),
        char node_type, void *arg)
{
    switch(node_type)
    {
        case NT_OUTPUT_ALERT:
            if(head_tmp != NULL)
                head_tmp->AlertList = AppendOutputFuncList(func, arg,
                        head_tmp->AlertList);
            else
                AlertList = AppendOutputFuncList(func, arg, AlertList);
            break;

        case NT_OUTPUT_LOG:
            if(head_tmp != NULL)
                head_tmp->LogList = AppendOutputFuncList(func, arg,
                        head_tmp->LogList);
            else
                LogList = AppendOutputFuncList(func, arg, LogList);
            break;

        default:
            /* just to be error-prone */
            FatalError("Unknown nodetype: %i. Possible bug, please report\n",
                    node_type);
    }

    return;
}


OutputFuncNode *AppendOutputFuncList(
        void (*func) (Packet *, char *, void *, Event *),
        void *arg, OutputFuncNode * list)
{
    OutputFuncNode *idx = list;

    if(idx == NULL)
    {
        idx = (OutputFuncNode *)SnortAlloc(sizeof(OutputFuncNode));
        idx->func = func;
        idx->arg = arg;
        list = idx;
    }
    else
    {
        while(idx->next != NULL)
            idx = idx->next;

        idx->next = (OutputFuncNode *)SnortAlloc(sizeof(OutputFuncNode));
        idx = idx->next;
        idx->func = func;
        idx->arg = arg;
    }

    idx->next = NULL;

    return list;
}

/*
 * frees the existing OutputList ands sets it a single node for the
 * function argument
 */
void SetOutputList(void (*func) (Packet *, char *, void *, Event *),
        char node_type, void *arg)
{
    OutputFuncNode *idx;
    OutputFuncNode *prev;

    switch(node_type)
    {
        case NT_OUTPUT_ALERT:
            prev = AlertList;
            break;

        case NT_OUTPUT_LOG:
            prev = LogList;
            break;

        default:
            return;
    }

    while(prev != NULL)
    {
        idx = prev->next;
        free(prev);
        prev = idx;
    }

    switch(node_type)
    {
        case NT_OUTPUT_ALERT:
            AlertList = prev;
            break;

        case NT_OUTPUT_LOG:
            LogList = prev;
            break;

        default:
            return;
    }

    AddFuncToOutputList(func, node_type, arg);

    return;
}



/*************************** End Output Plugin API  ***************************/


/************************** Miscellaneous Functions  **************************/

int PacketIsIP(Packet * p)
{
    if(p->iph != NULL)
        return 1;

    return 0;
}



int PacketIsTCP(Packet * p)
{
    if(p->iph != NULL && p->tcph != NULL)
        return 1;

    return 0;
}



int PacketIsUDP(Packet * p)
{
    if(p->iph != NULL && p->udph != NULL)
        return 1;

    return 0;
}



int PacketIsICMP(Packet * p)
{
    if(p->iph != NULL && p->icmph != NULL)
        return 1;

    return 0;
}



int DestinationIpIsHomenet(Packet * p)
{
    if((p->iph->ip_dst.s_addr & pv.netmask) == pv.homenet)
    {
        return 1;
    }
    return 0;
}



int SourceIpIsHomenet(Packet * p)
{
    if((p->iph->ip_src.s_addr & pv.netmask) == pv.homenet)
    {
        return 1;
    }
    return 0;
}

int CheckNet(struct in_addr * compare, struct in_addr * compare2)
{
    if(compare->s_addr == compare2->s_addr)
    {
        return 1;
    }
    return 0;
}

/* functions to aid in cleaning up aftre plugins */
void AddFuncToRestartList(void (*func) (int, void *), void *arg)
{
    PluginRestartList = AddFuncToSignalList(func, arg, PluginRestartList);
}

void AddFuncToCleanExitList(void (*func) (int, void *), void *arg)
{
    PluginCleanExitList = AddFuncToSignalList(func, arg, PluginCleanExitList);
}

void AddFuncToShutdownList(void (*func) (int, void *), void *arg)
{
    PluginShutdownList = AddFuncToSignalList(func, arg, PluginShutdownList);
}

void AddFuncToPostConfigList(void (*func)(int, void *), void *arg)
{
    PluginPostConfigList = AddFuncToSignalList(func, arg, PluginPostConfigList);
}

PluginSignalFuncNode *AddFuncToSignalList(void (*func) (int, void *), void *arg,
                                          PluginSignalFuncNode * list)
{
    PluginSignalFuncNode *idx;

    idx = list;

    if(idx == NULL)
    {
        idx = (PluginSignalFuncNode *)SnortAlloc(sizeof(PluginSignalFuncNode));

        idx->func = func;
        idx->arg = arg;
        list = idx;
    }
    else
    {
        while(idx->next != NULL)
            idx = idx->next;

        idx->next = (PluginSignalFuncNode *)SnortAlloc(sizeof(PluginSignalFuncNode));

        idx = idx->next;
        idx->func = func;
        idx->arg = arg;
    }
    idx->next = NULL;

    return list;
}


/****************************************************************************
 *
 * Function: GetUniqueName(char * iface)
 *
 * Purpose: To return a string that has a high probability of being unique
 *          for a given sensor.
 *
 * Arguments: char * iface - The network interface you are sniffing
 *
 * Returns: A char * -- its a static char * so you should not free it
 *
 ***************************************************************************/
char *GetUniqueName(char * iface)
{
    char * rptr;
    static char uniq_name[256];

    if (iface == NULL) LogMessage("Interface is NULL. Name may not be unique for the host\n");
#ifndef WIN32
    rptr = GetIP(iface); 
    if(rptr == NULL || !strcmp(rptr, "unknown"))
#endif
    {
        SnortSnprintf(uniq_name, 255, "%s:%s\n",GetHostname(),iface);
        rptr = uniq_name; 
    }
    if (pv.verbose_flag) LogMessage("Node unique name is: %s\n", rptr);
    return rptr;
}    

/****************************************************************************
 *
 * Function: GetIP(char * iface)
 *
 * Purpose: To return a string representing the IP address for an interface
 *
 * Arguments: char * iface - The network interface you want to find an IP
 *            address for.
 *
 * Returns: A char * -- make sure you call free on this when you are done
 *          with it.
 *
 ***************************************************************************/
char *GetIP(char * iface)
{
    struct ifreq ifr;
    struct sockaddr_in *addr;
    int s;

    if(iface)
    {
        /* Set up a dummy socket just so we can use ioctl to find the
           ip address of the interface */
        s = socket(PF_INET, SOCK_DGRAM, 0);
        if(s == -1)
        {
            FatalError("Problem establishing socket to find IP address for interface: %s\n", iface);
        }

        SnortStrncpy(ifr.ifr_name, iface, strlen(iface) + 1);

#ifndef WIN32
        if(ioctl(s, SIOCGIFADDR, &ifr) < 0) return NULL;
        else
#endif
        {
            addr = (struct sockaddr_in *) &ifr.ifr_broadaddr;
        }
        close(s);

        return strdup(inet_ntoa(addr->sin_addr));
    }
    else
    {
        return "unknown";
    }
}

/****************************************************************************
 *
 * Function: GetHostname()
 *
 * Purpose: To return a string representing the hostname
 *
 * Arguments: None
 *
 * Returns: A static char * representing the hostname. 
 *
 ***************************************************************************/
char *GetHostname()
{
#ifdef WIN32
    DWORD bufflen = 256;
    static char buff[256];
    GetComputerName(buff, &bufflen);
    return buff;
#else
    char * error = "unknown";
    if(getenv("HOSTNAME")) return getenv("HOSTNAME");
    else if(getenv("HOST")) return getenv("HOST");
    else return error;
#endif
}

/****************************************************************************
 *
 * Function: GetTimestamp(register const struct timeval *tvp, int tz)
 *
 * Purpose: Get an ISO-8601 formatted timestamp for tvp within the tz
 *          timezone. 
 *
 * Arguments: tvp is a timeval pointer. tz is a timezone. 
 *
 * Returns: char * -- You must free this char * when you are done with it.
 *
 ***************************************************************************/
char *GetTimestamp(register const struct timeval *tvp, int tz)
{
    struct tm *lt;  /* localtime */
    char * buf;
    int msec;

    buf = (char *)SnortAlloc(SMALLBUFFER * sizeof(char));

    msec = tvp->tv_usec / 1000;

    if(pv.use_utc == 1)
    {
        lt = gmtime((time_t *)&tvp->tv_sec);
        SnortSnprintf(buf, SMALLBUFFER, "%04i-%02i-%02i %02i:%02i:%02i.%03i",
                      1900 + lt->tm_year, lt->tm_mon + 1, lt->tm_mday,
                      lt->tm_hour, lt->tm_min, lt->tm_sec, msec);
    }
    else
    {
        lt = localtime((time_t *)&tvp->tv_sec);
        SnortSnprintf(buf, SMALLBUFFER,
                      "%04i-%02i-%02i %02i:%02i:%02i.%03i+%03i",
                      1900 + lt->tm_year, lt->tm_mon + 1, lt->tm_mday,
                      lt->tm_hour, lt->tm_min, lt->tm_sec, msec, tz);
    }

    return buf;
}

/****************************************************************************
 *
 * Function: GetLocalTimezone()
 *
 * Purpose: Find the offset from GMT for current host
 *
 * Arguments: none 
 *
 * Returns: int representing the offset from GMT
 *
 ***************************************************************************/
int GetLocalTimezone()
{
    time_t      ut;
    struct tm * ltm;
    long        seconds_away_from_utc;

    time(&ut);
    ltm = localtime(&ut);

#if defined(WIN32) || defined(SOLARIS) || defined(AIX)
    /* localtime() sets the global timezone variable,
       which is defined in <time.h> */
    seconds_away_from_utc = timezone;
#else
    seconds_away_from_utc = ltm->tm_gmtoff;
#endif

    return  seconds_away_from_utc/3600;
}

/****************************************************************************
 *
 * Function: GetCurrentTimestamp()
 *
 * Purpose: Generate an ISO-8601 formatted timestamp for the current time.
 *
 * Arguments: none 
 *
 * Returns: char * -- You must free this char * when you are done with it.
 *
 ***************************************************************************/
char *GetCurrentTimestamp()
{
    struct tm *lt;
    struct timezone tz;
    struct timeval tv;
    struct timeval *tvp;
    char * buf;
    int tzone;
    int msec;

    buf = (char *)SnortAlloc(SMALLBUFFER * sizeof(char));

    bzero((char *)&tz,sizeof(tz));
    gettimeofday(&tv,&tz);
    tvp = &tv;

    msec = tvp->tv_usec/1000;

    if(pv.use_utc == 1)
    {
        lt = gmtime((time_t *)&tvp->tv_sec);
        SnortSnprintf(buf, SMALLBUFFER, "%04i-%02i-%02i %02i:%02i:%02i.%03i",
                      1900 + lt->tm_year, lt->tm_mon + 1, lt->tm_mday,
                      lt->tm_hour, lt->tm_min, lt->tm_sec, msec);
    }
    else
    {
        lt = localtime((time_t *)&tvp->tv_sec);

        tzone = GetLocalTimezone();

        SnortSnprintf(buf, SMALLBUFFER,
                      "%04i-%02i-%02i %02i:%02i:%02i.%03i+%03i",
                      1900 + lt->tm_year, lt->tm_mon + 1, lt->tm_mday,
                      lt->tm_hour, lt->tm_min, lt->tm_sec, msec, tzone);
    }

    return buf;
}

/****************************************************************************
 * Function: base64(char * xdata, int length)
 *
 * Purpose: Insert data into the database
 *
 * Arguments: xdata  => pointer to data to base64 encode
 *            length => how much data to encode 
 *
 * Make sure you allocate memory for the output before you pass
 * the output pointer into this function. You should allocate 
 * (1.5 * length) bytes to be safe.
 *
 * Returns: data base64 encoded as a char *
 *
 ***************************************************************************/
char * base64(u_char * xdata, int length)
{
    int count, cols, bits, c, char_count;
    unsigned char alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char * payloadptr;
    char * output;
    char_count = 0;
    bits = 0;
    cols = 0;

    output = (char *)SnortAlloc( ((unsigned int) (length * 1.5 + 4)) * sizeof(char) );

    payloadptr = output;

    for(count = 0; count < length; count++)
    {
        c = xdata[count];

        if(c > 255)
        {
            ErrorMessage("plugbase.c->base64(): encountered char > 255 (decimal %d)\n If you see this error message a char is more than one byte on your machine\n This means your base64 results can not be trusted", c);
        }

        bits += c;
        char_count++;

        if(char_count == 3)
        {
            *output = alpha[bits >> 18]; output++;
            *output = alpha[(bits >> 12) & 0x3f]; output++;
            *output = alpha[(bits >> 6) & 0x3f]; output++;
            *output = alpha[bits & 0x3f]; output++; 
            cols += 4;
            if(cols == 72)
            {
                *output = '\n'; output++;
                cols = 0;
            }
            bits = 0;
            char_count = 0;
        }
        else
        {
            bits <<= 8;
        }
    }

    if(char_count != 0)
    {
        bits <<= 16 - (8 * char_count);
        *output = alpha[bits >> 18]; output++;
        *output = alpha[(bits >> 12) & 0x3f]; output++;
        if(char_count == 1)
        {
            *output = '='; output++;
            *output = '='; output++;
        }
        else
        {
            *output = alpha[(bits >> 6) & 0x3f]; 
            output++; *output = '='; 
            output++;
        }
    }
    *output = '\0';
    return payloadptr;
} 

/****************************************************************************
 *
 * Function: ascii(u_char *xdata, int length)
 *
 * Purpose: This function takes takes a buffer "xdata" and its length then
 *          returns a string of only the printible ASCII characters.
 *
 * Arguments: xdata is the buffer, length is the length of the buffer in
 *            bytes
 *
 * Returns: char * -- You must free this char * when you are done with it.
 *
 ***************************************************************************/
char *ascii(u_char *xdata, int length)
{
     char *d_ptr, *ret_val;
     int i,count = 0;
     int size;
     
     if(xdata == NULL)
     {
         return NULL;         
     }
     
     for(i=0;i<length;i++)
     {
         if(xdata[i] == '<')
             count+=4;              /* &lt; */
         else if(xdata[i] == '&')
             count+=5;              /* &amp; */
         else if(xdata[i] == '>')   /* &gt;  */
             count += 4;
     }

     size = length + count + 1;
     ret_val = (char *) malloc(size);
     
     if(ret_val == NULL)
     {
         LogMessage("plugbase.c: ascii(): Out of memory, can't log anything!\n");
         return NULL;
     }
     
     memset(ret_val, '\0',(length + count + 1));
     
     d_ptr = ret_val; 
     
     for(i=0;i<length;i++)
     {
         if((xdata[i] > 0x1F) && (xdata[i] < 0x7F))
         {
             if(xdata[i] == '<')
             {
                 SnortStrncpy(d_ptr, "&lt;", size - (d_ptr - ret_val));
                 d_ptr+=4;
             }
             else if(xdata[i] == '&')
             {
                 SnortStrncpy(d_ptr, "&amp;", size - (d_ptr - ret_val));
                 d_ptr += 5;
             }
             else if(xdata[i] == '>')
             {
                 SnortStrncpy(d_ptr, "&gt;", size - (d_ptr - ret_val));
                 d_ptr += 4;
             }
             else
             {
                 *d_ptr++ = xdata[i];
             }
         }
         else
         {
             *d_ptr++ = '.';
         }        
     }
     
     *d_ptr++ = '\0';
     
     return ret_val;
}

/****************************************************************************
 *
 * Function: hex(u_char *xdata, int length)
 *
 * Purpose: This function takes takes a buffer "xdata" and its length then
 *          returns a string of hex with no spaces
 *
 * Arguments: xdata is the buffer, length is the length of the buffer in
 *            bytes
 *
 * Returns: char * -- You must free this char * when you are done with it.
 *
 ***************************************************************************/
char *hex(u_char *xdata, int length)
{
    int x;
    char *rval;
    char *buf;

    buf = (char *)SnortAlloc(length * 2 + 1);
    rval = buf;

    for(x=0; x < length; x++)
    {
        SnortSnprintf(buf, 3, "%02X", xdata[x]);
        buf += 2;
    } 

    rval[length * 2] = '\0';

    return rval;
}



char *fasthex(u_char *xdata, int length)
{
    char conv[] = "0123456789ABCDEF";
    char *retbuf = NULL; 
    char *index;
    char *end;
    char *ridx;

    index = xdata;
    end = xdata + length;
    retbuf = (char *)SnortAlloc(((length * 2) + 1) * sizeof(char));
    ridx = retbuf;

    while(index < end)
    {
        *ridx++ = conv[((*index & 0xFF)>>4)];
        *ridx++ = conv[((*index & 0xFF)&0x0F)];
        index++;
    }

    return retbuf;
}

