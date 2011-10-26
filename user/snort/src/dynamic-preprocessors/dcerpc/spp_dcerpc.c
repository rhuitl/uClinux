/*
 * spp_dcerpc.c
 *
 * Copyright (C) 2004-2006 Sourcefire,Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Description:
 *
 * This file initializes DCERPC as a Snort preprocessor.
 *
 * This file registers the DCERPC initialization function,
 * adds the DCERPC function into the preprocessor list, reads
 * the user configuration in the snort.conf file, and prints out
 * the configuration that is read.
 *
 * In general, this file is a wrapper to DCERPC preproc functionality,
 * by interfacing with the Snort preprocessor functions.  The rest
 * of DCERPC should be separate from the preprocessor hooks.
 *
 * The DCERPC preprocessor parses DCERPC requests from remote machines by
 * layering SMB and DCERPC data structures over the data stream and extracting
 * various pieces of information.
 *
 * Arguments:
 *   
 * This plugin takes port list(s) representing the TCP ports that the
 * user is interested in having decoded.  It is of the format
 *
 * ports nbt { port1 [port2 ...] }
 * ports raw { port1 [port2 ...] }
 *
 * where nbt & raw are used to specify the ports for SMB over NetBios/TCP
 * and raw SMB, respectively.
 *
 * Effect:
 *
 * None
 *
 * NOTES:
 * - 08.12.04:  Initial Development.  SAS
 *
 */

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#ifdef HAVE_STRINGS_H	 
#include <strings.h>	 
#endif

#include "debug.h"

#include "preprocids.h"
#include "sf_snort_packet.h"

#include "profiler.h"

#include "snort_dcerpc.h"

#ifdef PERF_PROFILING
PreprocStats dcerpcPerfStats;
PreprocStats dcerpcDetectPerfStats;
int dcerpcDetectCalled = 0;
#endif

/*
 * The length of the error string buffer.
 */
#define ERRSTRLEN 1000

/*
 * The definition of the configuration separators in the snort.conf
 * configure line.
 */
#define CONF_SEPARATORS " \t\n\r"
 
void DCERPCInit(u_char *);
void ProcessDCERPCPacket(void *, void *);
void DCERPCCleanExitFunction(int signal, void *data);


/*
 * Function: SetupDCERPC()
 *
 * Purpose: Registers the preprocessor keyword and initialization 
 *          function into the preprocessor list.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void SetupDCERPC()
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    _dpd.registerPreproc("dcerpc", DCERPCInit);

    DEBUG_WRAP(_dpd.debugMsg(DEBUG_DCERPC,"Preprocessor: DCERPC in setup...\n"););
}


/*
 * Function: DCERPCInit(u_char *)
 *
 * Purpose: Processes the args sent to the preprocessor, sets up the
 *          port list, links the processing function into the preproc
 *          function list
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
void DCERPCInit(u_char *args)
{
    char ErrorString[ERRSTRLEN];
    int  iErrStrLen = ERRSTRLEN - 1;

    /* Initialize the tokenizer */
    char *token = strtok(args, CONF_SEPARATORS);

    ErrorString[ERRSTRLEN - 1] = '\0';

    DEBUG_WRAP(_dpd.debugMsg(DEBUG_DCERPC,"Preprocessor: DCERPC Initialized\n"););

    /* parse the argument list into a list of ports to normalize */
    
    if (DCERPCProcessConf(token, ErrorString, iErrStrLen))
    {
        /*
         * Fatal Error, log error and exit.
         */
        DynamicPreprocessorFatalMessage("%s(%d) => %s\n", *_dpd.config_file, *_dpd.config_line, ErrorString);
    }

    /* Set the preprocessor function into the function list */
	_dpd.addPreproc(ProcessDCERPCPacket, PRIORITY_APPLICATION, PP_DCERPC);
	_dpd.addPreprocExit(DCERPCCleanExitFunction, NULL, PRIORITY_LAST, PP_DCERPC);

#ifdef PERF_PROFILING
    _dpd.addPreprocProfileFunc("dcerpc", &dcerpcPerfStats, 0, _dpd.totalPerfStats);
#endif
}


static void DCERPC_DisableDetect(SFSnortPacket *p)
{
    _dpd.disableAllDetect(p);

    _dpd.setPreprocBit(p, PP_SFPORTSCAN);
    _dpd.setPreprocBit(p, PP_PERFMONITOR);
    _dpd.setPreprocBit(p, PP_STREAM4);
}


/*
 * Function: ProcessDCERPCPacket(void *)
 *
 * Purpose: Inspects the packet's payload for fragment records and 
 *          converts them into one infragmented record.
 *
 * Arguments: p => pointer to the current packet data struct 
 *
 * Returns: void function
 *
 */
void ProcessDCERPCPacket(void *pkt, void *context)
{
	SFSnortPacket *p = (SFSnortPacket *)pkt;
    int            detected = 0;
    u_int32_t      session_flags = 0;
    PROFILE_VARS;

    DEBUG_WRAP(_dpd.debugMsg(DEBUG_DCERPC,"DCERPC packet with %d bytes\n", p->payload_size););

    /* no data to inspect */
    if (p->payload_size == 0)
        return;

    /* check to make sure we're talking TCP and that the TWH has already
       completed before processing anything */
    if(!IsTCP(p))
    {
        DEBUG_WRAP(_dpd.debugMsg(DEBUG_DCERPC,"It isn't TCP session traffic\n"););
        return;
    }

    if(p->flags & FLAG_FROM_SERVER)
    {
        DEBUG_WRAP(_dpd.debugMsg(DEBUG_DCERPC,"This is from a server\n"););
        return;
    }

    /*
     * Check for valid packet
     * if neither header or data is good, then we just abort.
     */
    if(!p->ip4_header || !p->tcp_header || !p->payload || !p->payload_size)
    {
        return;
    }

    if ( !_dpd.streamAPI )
	{
		DEBUG_WRAP(_dpd.debugMsg(DEBUG_DCERPC, "Error: Failed to get Stream API - Stream not enabled?\n"););
        return;
	}

    if (p->stream_session_ptr == NULL)
        return;

    session_flags = _dpd.streamAPI->get_session_flags(p->stream_session_ptr);

    if (session_flags & SSNFLAG_MIDSTREAM)
        return;

    if (!(session_flags & SSNFLAG_ESTABLISHED))
        return;

    PREPROC_PROFILE_START(dcerpcPerfStats);

    /* Okay, do something with it... */
    if (DCERPCDecode(p) == 0)
    {
        PREPROC_PROFILE_END(dcerpcPerfStats);
        return;
    }

    PREPROC_PROFILE_START(dcerpcDetectPerfStats);

    detected = _dpd.detect(p);

#ifdef PERF_PROFILING
    dcerpcDetectCalled = 1;
#endif

    PREPROC_PROFILE_END(dcerpcDetectPerfStats);

    /* Turn off detection since we've already done it. */
    DCERPC_DisableDetect(p);
     
    PREPROC_PROFILE_END(dcerpcPerfStats);

#ifdef PERF_PROFILING
    if (dcerpcDetectCalled)
    {
        dcerpcPerfStats.ticks -= dcerpcDetectPerfStats.ticks;
        /* And Reset ticks to 0 */
        dcerpcDetectPerfStats.ticks = 0;
        dcerpcDetectCalled = 0;
    }
#endif

    if ( detected )
    {
        DEBUG_WRAP(_dpd.debugMsg(DEBUG_DCERPC, "DCE/RPC vulnerability detected\n"););
    }

    return;
}

/* 
 * Function: DCERPCCleanExitFunction(int, void *)
 *
 * Purpose: This function gets called when Snort is exiting, if there's
 *          any cleanup that needs to be performed (e.g. closing files)
 *          it should be done here.
 *
 * Arguments: signal => the code of the signal that was issued to Snort
 *            data => any arguments or data structs linked to this 
 *                    function when it was registered, may be
 *                    needed to properly exit
 *       
 * Returns: void function
 */                   
void DCERPCCleanExitFunction(int signal, void *data)
{    
    DCERPC_Exit();
}

