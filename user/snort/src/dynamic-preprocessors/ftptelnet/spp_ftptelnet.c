/*
 * spp_ftptelnet.c
 *
 * Copyright (C) 2004 Sourcefire,Inc
 * Steven A. Sturges <ssturges@sourcefire.com>
 * Daniel J. Roelker <droelker@sourcefire.com>
 * Marc A. Norton <mnorton@sourcefire.com>
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
 * This file initializes FTPTelnet as a Snort preprocessor.
 *
 * This file registers the FTPTelnet initialization function,
 * adds the FTPTelnet function into the preprocessor list, reads
 * the user configuration in the snort.conf file, and prints out
 * the configuration that is read.
 *
 * In general, this file is a wrapper to FTPTelnet functionality,
 * by interfacing with the Snort preprocessor functions.  The rest
 * of FTPTelnet should be separate from the preprocessor hooks.
 *
 * NOTES:
 * - 16.09.04:  Initial Development.  SAS
 *
 */

#include <string.h>
#include <stdio.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

//#include "decode.h"
//#include "plugbase.h"
#include "debug.h"
//#include "util.h"

#include "ftpp_ui_config.h"
#ifdef CLIENT_READY
#include "ftp_client.h"
#include "ftp_norm.h"
#endif
#include "snort_ftptelnet.h"

#include "profiler.h"

#ifdef DYNAMIC_PLUGIN
//#include "dynamic-plugins/sp_preprocopt.h"
#endif

/*
 * Defines for preprocessor initialization
 */
/*
 * snort.conf preprocessor keyword
 */
#define GLOBAL_KEYWORD   "ftp_telnet"
#define PROTOCOL_KEYWORD "ftp_telnet_protocol"

/*
 * The length of the error string buffer.
 */
#define ERRSTRLEN 1000

/*
 * External Global Variables
 * Variables that we need from Snort to log errors correctly and such.
 */
//extern char *file_name;
//extern int file_line;
#ifdef PERF_PROFILING
PreprocStats ftpPerfStats;
PreprocStats telnetPerfStats;
#endif

/*
 * Global Variables
 * This is the only way to work with Snort preprocessors because
 * the user configuration must be kept between the Init function
 * the actual preprocessor.  There is no interaction between the
 * two except through global variable usage.
 */
FTPTELNET_GLOBAL_CONF FTPTelnetGlobalConf;

/*
 * Function: FTPTelnetChecks(Packet *p)
 *
 * Purpose: This function wraps the functionality in the generic FTPTelnet
 *          processing.  We get a Packet structure and pass this into the
 *          FTPTelnet module where the first stage in FTPTelnet is the
 *          Normalization stage where most of the other Snortisms are
 *          taken care of.  After that, the modules are generic.
 *
 * Arguments: p         => pointer to a Packet structure that contains
 *                         Snort info about the packet.
 *
 * Returns: None
 *
 */
static void FTPTelnetChecks(void *pkt, void *context)
{
    /*
     * IMPORTANT:
     * This is where we initialize any variables that can impact other
     * aspects of detection/processing.
     *
     */
    SFSnortPacket *p = (SFSnortPacket*)pkt;

    /*
     * Check for valid packet
     * if neither header or data is good, then we just abort.
     */
    if(!p->ip4_header || !p->tcp_header || !p->payload || !p->payload_size)
    {
        return;
    }

    /*
     * Pass in the configuration and the packet.
     */
    SnortFTPTelnet(&FTPTelnetGlobalConf, p);

    return;
}

/*
 * Function: FTPTelnetInit(u_char *args)
 *
 * Purpose: This function initializes FTPTelnetInit with a user configuration.
 *          The function is called when FTPTelnet is configured in snort.conf.
 *          It gets passed a string of arguments, which gets parsed into
 *          configuration constructs that FTPTelnet understands.
 *
 *          This function gets called for every FTPTelnet configure line.  We
 *          use this characteristic to split up the configuration, so each
 *          line is a configuration construct.  We need to keep track of what
 *          part of the configuration has been configured, so we don't
 *          configure one part, then configure it again.
 *
 *          Any upfront memory is allocated here (if necessary).
 *
 * Arguments: args      => pointer to a string to the preprocessor arguments.
 *
 * Returns: None
 *
 */
static void FTPTelnetInit(u_char *args)
{
    char ErrorString[ERRSTRLEN];
    int  iErrStrLen = ERRSTRLEN;
    int  iRet;
    static int siFirstConfig = 1;

    if(siFirstConfig)
    {
        if((iRet = ftpp_ui_config_init_global_conf(&FTPTelnetGlobalConf)))
        {
            snprintf(ErrorString, iErrStrLen,
                    "Error initializing Global Configuration.");
            DynamicPreprocessorFatalMessage("%s(%d) => %s\n", *(_dpd.config_file), *(_dpd.config_line), ErrorString);

            return;
        }

        if((iRet = ftpp_ui_config_default(&FTPTelnetGlobalConf)))
        {
            snprintf(ErrorString, iErrStrLen,
                    "Error configuring default global configuration.");
            DynamicPreprocessorFatalMessage("%s(%d) => %s\n", *(_dpd.config_file), *(_dpd.config_line), ErrorString);

            return;
        }

#ifdef CLIENT_READY
        if((iRet = ftpp_client_init(&FTPTelnetGlobalConf)))
        {
            snprintf(ErrorString, iErrStrLen,
                    "Error initializing client module.");
            DynamicPreprocessorFatalMessage("%s(%d) => %s\n", *(_dpd.config_file), *(_dpd.config_line), ErrorString);

            return;
        }

        if((iRet = ftpp_norm_init(&FTPTelnetGlobalConf)))
        {
            snprintf(ErrorString, iErrStrLen,
                     "Error initializing normalization module.");
            DynamicPreprocessorFatalMessage("%s(%d) => %s\n", *(_dpd.config_file), *(_dpd.config_line), ErrorString);

            return;
        }
#endif

    }
    
    if((iRet = FTPTelnetSnortConf(&FTPTelnetGlobalConf, args,
                    ErrorString, iErrStrLen)))
    {
        if(iRet > 0)
        {
            /*
             * Non-fatal Error
             */
            if(ErrorString)
            {
                _dpd.errMsg("WARNING: %s(%d) => %s\n", 
                        *(_dpd.config_file), *(_dpd.config_line), ErrorString);
            }
        }
        else
        {
            /*
             * Fatal Error, log error and exit.
             */
            if(ErrorString)
            {
                DynamicPreprocessorFatalMessage("%s(%d) => %s\n", 
                                                *(_dpd.config_file), *(_dpd.config_line), ErrorString);
            }
            else
            {
                /*
                 * Check if ErrorString is undefined.
                 */
                if(iRet == -2)
                {
                    DynamicPreprocessorFatalMessage("%s(%d) => ErrorString is undefined.\n", 
                                                    *(_dpd.config_file), *(_dpd.config_line));
                }
                else
                {
                    DynamicPreprocessorFatalMessage("%s(%d) => Undefined Error.\n", 
                                                    *(_dpd.config_file), *(_dpd.config_line));
                }
            }
        }
    }

    /*
     * Only add the functions one time to the preproc list.
     */
    if(siFirstConfig)
    {
        /*
         * Add FTPTelnet into the preprocessor list
         */
        _dpd.addPreproc(FTPTelnetChecks, PRIORITY_APPLICATION, PP_FTPTELNET);

        /*
         * Remember to add any cleanup functions into the appropriate
         * lists.
         */

        siFirstConfig = 0;

#ifdef PERF_PROFILING
        _dpd.addPreprocProfileFunc("ftptelnet_ftp", (void*)&ftpPerfStats, 0, _dpd.totalPerfStats);
        _dpd.addPreprocProfileFunc("ftptelnet_telnet", (void*)&telnetPerfStats, 0, _dpd.totalPerfStats);
#endif
    }
    
    return;
}

/*
 * Function: SetupFTPTelnet()
 *
 * Purpose: This function initializes FTPTelnet as a Snort preprocessor.
 *
 *          It registers the preprocessor keyword for use in the snort.conf
 *          and sets up the initialization module for the preprocessor, in
 *          case it is configured.
 *
 *          This function must be called in InitPreprocessors() in plugbase.c
 *          in order to be recognized by Snort.
 *
 * Arguments: None
 *
 * Returns: None
 *
 */
void SetupFTPTelnet()
{
    _dpd.registerPreproc(GLOBAL_KEYWORD, FTPTelnetInit);
    _dpd.registerPreproc(PROTOCOL_KEYWORD, FTPTelnetInit);
    _dpd.addPreprocConfCheck(FTPConfigCheck);

#ifdef DYNAMIC_PLUGIN
    /* Cleanup func is NULL -- free() will be used as necessary */
    _dpd.preprocOptRegister("ftp.bounce", &FTPPBounceInit, &FTPPBounceEval, NULL);
#endif

    DEBUG_WRAP(_dpd.debugMsg(DEBUG_FTPTELNET, "Preprocessor: FTPTelnet is "
                "setup . . .\n"););
}
