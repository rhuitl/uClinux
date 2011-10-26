/*
 * dcerpc_config.c
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
 * Parses the configuration data.
 *
 * Arguments:
 *   
 * This plugin takes port list(s) representing the TCP ports that the
 * user is interested in having decoded.  It is of the format
 *
 * ports smb { port1 [port2 ...] }
 * ports dcerpc { port1 [port2 ...] }
 *
 * where smb is used to specify the ports for SMB over NetBios/TCP
 * or raw SMB, and dcerpc is used to specify raw DCE/RPC.
 *
 */

#include <string.h>
#include <ctype.h>
#include <stdio.h>

#include "sf_snort_plugin_api.h"
#include "snort_dcerpc.h"
#include "smb_structs.h"
#include "smb_andx_decode.h"
#include "smb_file_decode.h"

#include "profiler.h"

/*
 * The definition of the configuration separators in the snort.conf
 * configure line.
 */
#define CONF_SEPARATORS " \t\n\r"
 

/*
 * Port list delimiters
 */
#define START_PORT_LIST "{"
#define END_PORT_LIST   "}"

/*
 * Configuration options
 */
#define OPT_PORTS               "ports"
#define OPT_SMB_PORTS           "smb"
#define OPT_RPC_PORTS           "dcerpc"
#define OPT_AUTODETECT          "autodetect"
#define OPT_DISABLE_SMB_FRAG    "disable_smb_frag"
#define OPT_DISABLE_DCERPC_FRAG "disable_dcerpc_frag"
#define OPT_PRINT_DEBUG         "debug_print"
#define OPT_MAX_FRAG_SIZE       "max_frag_size"
#define OPT_MEMCAP              "memcap"
#define OPT_ALERT_MEMCAP        "alert_memcap"

#define PORT_STR_LEN	        512

char SMBPorts[MAX_PORT_INDEX];
char DCERPCPorts[MAX_PORT_INDEX];

u_int16_t   _max_frag_size = DEFAULT_MAX_FRAG_SIZE;
u_int32_t   _memcap = DEFAULT_MEMCAP*1024;
u_int8_t    _debug_print = 0;
u_int8_t    _alert_memcap = 0;

enum e_transport_type
{
    TRANS_SMB = 1,
    TRANS_RPC = 2
};

u_int8_t _autodetect = 0;
u_int8_t _disable_smb_fragmentation = 0;
u_int8_t _disable_dcerpc_fragmentation = 0;

/*
 * Function: InitializeDefaultSMBConfig()
 *
 * Purpose: Sets the default configuration for the SMB preprocessor.
 *
 * Arguments: None
 *
 * Returns: void
 *
 */
void InitializeDefaultSMBConfig()
{
    memset(&SMBPorts[0], 0, sizeof(SMBPorts));
    memset(&DCERPCPorts[0], 0, sizeof(DCERPCPorts));

    SMBPorts[PORT_INDEX(139)] |= CONV_PORT(139);
    SMBPorts[PORT_INDEX(445)] |= CONV_PORT(445);
    DCERPCPorts[PORT_INDEX(135)] |= CONV_PORT(135);

}

/*
 * Function: SmbSetPorts(int type)
 *
 * Purpose: Reads the list of port numbers from the argument string and
 *          parses them into the port list data struct
 *
 * Arguments: portlist => argument list
 *
 * Returns: int indicating error
 *
 */
int SMBSetPorts(int type, char *ErrorString, int ErrStrLen)
{
    int isReset = 0;
    char *token = strtok(NULL, CONF_SEPARATORS);
    char *transportType = "SMB";
    char *ports = NULL;
    int portsSize = 0;
    char portstr[PORT_STR_LEN];

    portstr[PORT_STR_LEN - 1] = '\0';

    if (token == NULL)
    {
        snprintf(ErrorString, ErrStrLen, "DCE/RPC - invalid port list\n");
        return -1;
    }

    switch (type)
    {
        case TRANS_SMB:
            ports = &SMBPorts[0];
            portsSize = sizeof(SMBPorts);
            transportType = "SMB";
            break;
        case TRANS_RPC:
            ports = &DCERPCPorts[0];
            portsSize = sizeof(DCERPCPorts);
            transportType = "DCE/RPC";
            break;
        default:
            snprintf(ErrorString, ErrStrLen, "Invalid type %d.", type);
            return -1;
    }
    
    if (strcmp(token , START_PORT_LIST))
    {
        snprintf(ErrorString, ErrStrLen, "Invalid token %s."
            "Missing port list delimiter, expecting '{'.\n", token);
        return -1;
    }

    token = strtok(NULL, CONF_SEPARATORS);

    if (token == NULL)
    {
        snprintf(ErrorString, ErrStrLen, "DCE/RPC - invalid port list\n");
        return -1;
    }

    if ( !strcmp(token,END_PORT_LIST) )
    {
        DynamicPreprocessorFatalMessage("ERROR %s(%d) => Empty port list.\n",
                                        *_dpd.config_file, *_dpd.config_line);
    }

    while (token && strcmp(token,END_PORT_LIST))
    {
        if(isdigit((int)token[0]))
        {
            char *num_p = NULL; /* used to determine last position in string */
            long t_num;

            t_num = strtol(token, &num_p, 10);

            if(*num_p != '\0')
            {
                DynamicPreprocessorFatalMessage("ERROR %s(%d) => Port Number invalid format: %s\n",
                                                *_dpd.config_file, *_dpd.config_line, token);
            }
            else if(t_num < 0 || t_num > 65535)
            {
                DynamicPreprocessorFatalMessage("ERROR %s(%d) => Port Number out of range: %ld\n",
                                                *_dpd.config_file, *_dpd.config_line, t_num);
            }

            /* user specified a legal port number and it should override the default
               port list, so reset it unless already done */
            if(!isReset)
            {
                bzero(ports, portsSize);
                portstr[0] = '\0';
                isReset = 1;
            }

            /* mark this port as being interesting using some portscan2-type voodoo,
               and also add it to the port list string while we're at it so we can
               later print out all the ports with a single LogMessage() */
            ports[PORT_INDEX(t_num)] |= CONV_PORT(t_num);

            snprintf(portstr + strlen(portstr), PORT_STR_LEN - strlen(portstr), "%s ", token);

            if (portstr[PORT_STR_LEN - 1] != '\0')
            {
                DynamicPreprocessorFatalMessage("%s(%d) => Too many ports as of port %ld.\n",
                                                *_dpd.config_file, *_dpd.config_line, t_num);
            }
        }
        else
        {
            DynamicPreprocessorFatalMessage("ERROR %s(%d) => Non-numeric port number: %s\n",
                                            *_dpd.config_file, *_dpd.config_line, token);
        }
        token = strtok(NULL, CONF_SEPARATORS);
    }

    /* print out final port list */
    _dpd.logMsg("    Ports to decode %s: %s\n", transportType, portstr);

    return 0;
}                                                                               
 

/*
 * Function: DCERPCProcessConf(char *)
 *
 * Purpose: Reads the list of port numbers from the argument string and
 *          parses them into the port list data struct
 *
 * Arguments: portlist => argument list
 *
 * Returns: int indicating error
 *
 */
int DCERPCProcessConf(char *pcToken, char *ErrorString, int ErrStrLen)
{
    int  iRet = 0;
    int  iTokens = 0;

    /* Initialize the defaults */
    InitializeDefaultSMBConfig();

    _dpd.logMsg("\nDCE/RPC Decoder config:\n");

    while(pcToken != NULL)
    {
        /*
         * Show that we at least got one token
         */
        iTokens = 1;

        /*
         * Search for configuration keywords
         */
        if ( !strcmp(pcToken, OPT_PORTS) )
        {
            /* Next should be smb or dcerpc, then the actual ports.
             * ie, ports smb { 139 }
             * ie, ports dcerpc { 135 }
             */
            pcToken = strtok(NULL, CONF_SEPARATORS);
            if (!pcToken)
            {
                snprintf(ErrorString, ErrStrLen, "Missing tokens from port list\n");
                return -1;
            }

            if ( !strcmp(pcToken, OPT_SMB_PORTS) )
            {
                iRet = SMBSetPorts(TRANS_SMB, ErrorString, ErrStrLen);
            }
            else if (!strcmp(pcToken, OPT_RPC_PORTS))
            {
                iRet = SMBSetPorts(TRANS_RPC, ErrorString, ErrStrLen);
            }
            else
            {
                snprintf(ErrorString, ErrStrLen,
                    "Invalid SMB transport specification: %s.  "
                    "Should be 'smb' or 'dcerpc'\n", pcToken);
                return -1;
            }

            if (iRet)
                return iRet;
        }
        else if ( !strcmp(pcToken, OPT_DISABLE_SMB_FRAG) )
        {
            _disable_smb_fragmentation = 1;
        }
        else if ( !strcmp(pcToken, OPT_DISABLE_DCERPC_FRAG) )
        {
            _disable_dcerpc_fragmentation = 1;
        }
        else if ( !strcmp(pcToken, OPT_AUTODETECT) )
        {
            _autodetect = 1;
        }
        else if ( !strcmp(pcToken, OPT_PRINT_DEBUG) )
        {
            _debug_print = 1;
        }
        else if ( !strcmp(pcToken, OPT_MAX_FRAG_SIZE) )
        {
             int max_frag_size;
 
             pcToken = strtok(NULL, CONF_SEPARATORS);
 
             if (pcToken == NULL || !isdigit((int)pcToken[0]))
             {
                 snprintf(ErrorString, ErrStrLen,
                          "Frag size must be an integer between 0 and 65535\n");
                 return -1;
             }
 
             max_frag_size = atoi(pcToken);
 
             if (max_frag_size < 0 || max_frag_size > 65535)
             {
                 snprintf(ErrorString, ErrStrLen,
                          "Frag size must be an integer between 0 and 65535\n");
                 return -1;
             }
 
             _max_frag_size = max_frag_size;
 
            if ( _max_frag_size == 0 )
            {
                _max_frag_size = DEFAULT_MAX_FRAG_SIZE;
                _dpd.logMsg("    WARNING: Invalid max frag size - setting to default.\n");
            }
            else if ( _max_frag_size > MAX_MAX_FRAG_SIZE )
            {
                _max_frag_size = MAX_MAX_FRAG_SIZE;
                _dpd.logMsg("    WARNING: Max frag size exceeded - setting to maximum.\n");
            }
        }
        else if ( !strcmp(pcToken, OPT_MEMCAP) )
        {
            int memcap;

            pcToken = strtok(NULL, CONF_SEPARATORS);

            if (pcToken == NULL || !isdigit((int)pcToken[0]))
            {
                snprintf(ErrorString, ErrStrLen,
                         "Frag size must be an integer between 0 and 4194303\n");
                return -1;
            }

            memcap = atoi(pcToken);

            if (memcap < 0 || memcap > 4194303)
            {
                snprintf(ErrorString, ErrStrLen,
                         "Frag size must be an integer between 0 and 4194303\n");
                return -1;
            }

            _memcap = memcap;
            
            if ( _memcap == 0 )
            {
                _memcap = DEFAULT_MEMCAP;
                _dpd.logMsg("    WARNING: Invalid memcap - setting to default.\n");
            }
            else if ( _memcap > DEFAULT_MEMCAP )
            {
                _memcap = DEFAULT_MEMCAP;
                _dpd.logMsg("    WARNING: Memcap exceeded - setting to maximum.\n");
            }

            _memcap *= 1024;
        }
        else if ( !strcmp(pcToken, OPT_ALERT_MEMCAP) )
        {
            _alert_memcap = 1;
        }
        /*
         * Invalid configuration keyword
         */
        else
        {
            snprintf(ErrorString, ErrStrLen,
                    "Invalid configuration token '%s'.\n", pcToken);
    
            return -1;
        }

        pcToken = strtok(NULL, CONF_SEPARATORS);
    }

    /*
     * If there are not any tokens to the configuration, then
     * we let the user know and log the error.  return non-fatal
     * error.
     */
    if(!iTokens)
    {
        snprintf(ErrorString, ErrStrLen,
                "No tokens to 'dcerpc' configuration.");

        return -1;
    }

    _dpd.logMsg("    Autodetect ports %s\n", _autodetect ? "ENABLED" : "DISABLED");
    _dpd.logMsg("    SMB fragmentation %s\n", _disable_smb_fragmentation ? "DISABLED" : "ENABLED");
    _dpd.logMsg("    DCE/RPC fragmentation %s\n", _disable_dcerpc_fragmentation ? "DISABLED" : "ENABLED");
    _dpd.logMsg("    Max Frag Size: %u bytes\n", _max_frag_size);
    _dpd.logMsg("    Memcap: %lu KB\n", _memcap/1024);
    _dpd.logMsg("    Alert if memcap exceeded %s\n", _alert_memcap ? "ENABLED" : "DISABLED");

    _dpd.logMsg("\n");

    return 0;
}
