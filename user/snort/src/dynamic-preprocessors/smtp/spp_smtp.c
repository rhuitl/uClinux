
/*
 * spp_smtp.c
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
 * Copyright (C) 2005 Sourcefire Inc.
 *
 * Author: Andy  Mullican
 *
 * Description:
 *
 * This file initializes SMTP as a Snort preprocessor.
 *
 * This file registers the SMTP initialization function,
 * adds the SMTP function into the preprocessor list.
 *
 * In general, this file is a wrapper to SMTP functionality,
 * by interfacing with the Snort preprocessor functions.  The rest
 * of SMTP should be separate from the preprocessor hooks.
 *
 */

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>

#include "preprocids.h"
#include "sf_snort_packet.h"

#include "spp_smtp.h"
#include "snort_smtp.h"
#include "smtp_config.h"
#include "smtp_log.h"

#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats smtpPerfStats;
PreprocStats smtpDetectPerfStats;
int smtpDetectCalled = 0;
#endif


static void SMTPInit(u_char *);
static void SMTP_XLINK_Init(u_char *);
static void SMTPDetect(void *, void *context);
static void SMTPCleanExitFunction(int, void *);
static void SMTPRestartFunction(int, void *);


/*
 * Function: SetupSMTP()
 *
 * Purpose: Registers the preprocessor keyword and initialization 
 *          function into the preprocessor list.  This is the function that
 *          gets called from InitPreprocessors() in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void SetupSMTP()
{
    /* 
     * link the preprocessor keyword to the init function in
     * the preproc list
     */
    _dpd.registerPreproc("smtp", SMTPInit);
    _dpd.registerPreproc("xlink2state", SMTP_XLINK_Init);
}


/*
 * Function: SMTPInit(u_char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
static void SMTPInit(u_char *args)
{
    static int bFirstConfig = 1;

    /* 
     * Parse the argument list from the rules file 
     */
    SMTP_ParseArgs(args);

    /* 
     * Perform any other initialization functions that are required here
     */
    SMTP_Init();

    /* 
     * Put the preprocessor function into the function list 
     */
    if ( bFirstConfig )
    {
        _dpd.addPreproc(SMTPDetect, PRIORITY_APPLICATION, PP_SMTP);
        _dpd.addPreprocExit(SMTPCleanExitFunction, NULL, PRIORITY_LAST, PP_SMTP);
        _dpd.addPreprocRestart(SMTPRestartFunction, NULL, PRIORITY_LAST, PP_SMTP);
        bFirstConfig = 0;

#ifdef PERF_PROFILING
        _dpd.addPreprocProfileFunc("smtp", (void*)&smtpPerfStats, 0, _dpd.totalPerfStats);        
#endif
    }
}


/*
 * Function: SMTP_XLINK_Init(u_char *)
 *
 * Purpose: Dummy function to make upgrade easier.  If preprocessor
 *           xlink2state is configured in snort.conf, just ignore it.
  *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
static void SMTP_XLINK_Init(u_char *args)
{
    return;
}


/*
 * Function: SMTPFunction(Packet *)
 *
 * Purpose: Perform the preprocessor's intended function.  This can be
 *          simple (statistics collection) or complex (IP defragmentation)
 *          as you like.  Try not to destroy the performance of the whole
 *          system by trying to do too much....
 *
 * Arguments: p => pointer to the current packet data struct 
 *
 * Returns: void function
 *
 */
static void SMTPDetect(void *pkt, void *context)
{
    SFSnortPacket *p = (SFSnortPacket *)pkt;
    PROFILE_VARS;

    if(!IsTCP(p))
    {
        return;
    }

    PREPROC_PROFILE_START(smtpPerfStats);

    SnortSMTP(p);

    PREPROC_PROFILE_END(smtpPerfStats);
#ifdef PERF_PROFILING
    if (smtpDetectCalled)
    {
        smtpPerfStats.ticks -= smtpDetectPerfStats.ticks;
        /* And Reset ticks to 0 */
        smtpDetectPerfStats.ticks = 0;
        smtpDetectCalled = 0;
    }
#endif

    /* 
     * if you need to issue an alert from your preprocessor, check out 
     * event_wrapper.h, there are some useful helper functions there
     */
}


/* 
 * Function: SMTPCleanExitFunction(int, void *)
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
static void SMTPCleanExitFunction(int signal, void *data)
{    
    SMTP_ConfigFree();
    SMTP_Free();
}


/* 
 * Function: SMTPRestartFunction(int, void *)
 *
 * Purpose: This function gets called when Snort is restarting on a SIGHUP,
 *          if there's any initialization or cleanup that needs to happen
 *          it should be done here.
 *
 * Arguments: signal => the code of the signal that was issued to Snort
 *            data => any arguments or data structs linked to this 
 *                    functioin when it was registered, may be
 *                    needed to properly exit
 *       
 * Returns: void function
 */                   
static void SMTPRestartFunction(int signal, void *foo)
{
       /* restart code goes here */
}
