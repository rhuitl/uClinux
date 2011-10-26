
/* smtp 
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
 * Handle configuration of the SMTP preprocessor
 *
 * Entry point functions:
 *
 *    SMTP_ParseArgs()
 *    SMTP_ConfigFree()
 *
 */

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_smtp.h"
#include "bounds.h"

#define CONF_SEPARATORS             " \t\n\r"
#define PORTS                       "ports"
#define INSPECTION_TYPE             "inspection_type"
#define NORMALIZE                   "normalize"
#define NORMALIZE_CMDS              "normalize_cmds"
#define IGNORE_DATA                 "ignore_data"
#define IGNORE_TLS_DATA             "ignore_tls_data"
#define MAX_COMMAND_LINE_LEN        "max_command_line_len"
#define MAX_HEADER_LINE_LEN         "max_header_line_len"
#define MAX_RESPONSE_LINE_LEN       "max_response_line_len"
#define ALT_MAX_COMMAND_LINE_LEN    "alt_max_command_line_len"
#define NO_ALERTS                   "no_alerts"
#define VALID_CMDS                  "valid_cmds"
#define INVALID_CMDS                "invalid_cmds"
#define PRINT_CMDS                  "print_cmds"
#define ALERT_UNKNOWN_CMDS          "alert_unknown_cmds"
#define XLINK2STATE                 "xlink2state"
#define ENABLE                      "enable"
#define DISABLE                     "disable"
#define INLINE_DROP                 "drop"


#define STATEFUL                    "stateful"
#define STATELESS                   "stateless"
#define YES                         "yes"
#define ALL                         "all"
#define NONE                        "none"
#define CMDS                        "cmds"

#define DEFAULT_MAX_COMMAND_LINE_LEN    0
#define DEFAULT_MAX_HEADER_LINE_LEN     0
#define DEFAULT_MAX_RESPONSE_LINE_LEN   0

#define ERRSTRLEN   512

/*
**  Port list delimiters
*/
#define START_LIST "{"
#define END_LIST   "}"


/*  Global variable to hold configuration */
SMTP_CONFIG   _smtp_config;



/* Private functions */
static int PrintConfig(void);
static int ProcessPorts(char *ErrorString, int ErrStrLen);
static int ProcessCmds(char *ErrorString, int ErrStrLen, u_int alert);
static u_int GetCmdId(char *name);
static int AddAlertCmd(char *name, u_int id, u_int alert);
static int AddNormalizeCmd(char *name);
static int ProcessAltMaxCmdLen(char *ErrorString, int ErrStrLen);
static int SetCmdLen(char *name, u_int max_len);
static int ProcessXlink2State(char *ErrorString, int ErrStrLen);


static SMTP_cmd _smtp_known_cmds[] =
{
	{"HELO",         CMD_HELO,},       
	{"EHLO",         CMD_HELO,},
	{"MAIL FROM:",   CMD_MAIL,},      
	{"RCPT TO:",     CMD_RCPT,},       
	{"DATA",         CMD_DATA,},       
	{"QUIT",         CMD_QUIT,},       

	{"BDAT",         CMD_BDAT,},       
	{"RSET",         CMD_RSET,},       
	{"VRFY",         CMD_VRFY,},       
	{"EXPN",         CMD_EXPN,},       
	{"HELP",         CMD_HELP,},       
	{"STARTTLS",     CMD_STARTTLS,},  
    
	{"Content-Type:",CMD_TYPE,},

	{"XEXCH50",      CMD_XEXCH50,},
	{"X-LINK2STATE", CMD_XLINK2STATE,},
        
	{"ATRN",         CMD_OTHER,},      
	{"AUTH",         CMD_OTHER,},      
	{"DEBUG",        CMD_OTHER,},
	{"EMAL",         CMD_OTHER,},
	{"ESAM",         CMD_OTHER,},
	{"ESND",         CMD_OTHER,},
	{"ESOM",         CMD_OTHER,},
	{"ETRN",         CMD_OTHER,},      
	{"EVFY",         CMD_OTHER,},
	{"IDENT",        CMD_OTHER,},
	{"NOOP",         CMD_OTHER,},      
	{"ONEX",         CMD_OTHER,},
	{"QUEU",         CMD_OTHER,},
	{"SAML",         CMD_OTHER,},      
	{"SEND",         CMD_OTHER,},      
	{"SOML",         CMD_OTHER,},      
	{"TICK",         CMD_OTHER,},
	{"TIME",         CMD_OTHER,},
	{"TURN",         CMD_OTHER,},      
	{"TURNME",       CMD_OTHER,},
	{"SIZE",         CMD_OTHER,},      
	{"VERB",         CMD_OTHER,},
	{"X-EXPS",       CMD_OTHER,},
	{"XADR",         CMD_OTHER,},
	{"XAUTH",        CMD_OTHER,},
	{"XCIR",         CMD_OTHER,},
	{"XGEN",         CMD_OTHER,},
	{"XLICENSE",     CMD_OTHER,},
	{"XQUE",         CMD_OTHER,},
	{"XSTA",         CMD_OTHER,},
	{"XTRN",         CMD_OTHER,},
	{"XUSR",         CMD_OTHER,},

	{NULL,           0}
};

/*
 * Function: SMTP_ParseArgs(char *)
 *
 * Purpose: Process the preprocessor arguments from the rules file and 
 *          initialize the preprocessor's data struct.  This function doesn't
 *          have to exist if it makes sense to parse the args in the init 
 *          function.
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 *
 */
void SMTP_ParseArgs(u_char *args)
{
    int   ret = 0;
    char *arg;
    char *value;
    char errStr[ERRSTRLEN];
    int  errStrLen = ERRSTRLEN;
    SMTP_cmd *smtp_cmd;

    if ((!_dpd.streamAPI) || (_dpd.streamAPI->version < STREAM_API_VERSION4))
        DynamicPreprocessorFatalMessage("SMTP_ParseArgs(): Streaming & reassembly must be enabled\n");

    if ( args == NULL )
    {
        return;
    }

    /*  Set config to defaults */
    memset(&_smtp_config, 0, sizeof(SMTP_CONFIG));

    _smtp_config.ports[SMTP_DEFAULT_SERVER_PORT/8] |= 1 << (SMTP_DEFAULT_SERVER_PORT%8);
    _smtp_config.ports[XLINK2STATE_DEFAULT_PORT/8] |= 1 << (XLINK2STATE_DEFAULT_PORT%8);
    _smtp_config.inspection_type = SMTP_STATELESS;
    _smtp_config.normalize = 0;
    _smtp_config.ignore_data = 0;
    _smtp_config.ignore_tls_data = 0;
    _smtp_config.max_command_line_len = DEFAULT_MAX_COMMAND_LINE_LEN;
    _smtp_config.max_header_line_len = DEFAULT_MAX_HEADER_LINE_LEN;
    _smtp_config.max_response_line_len = DEFAULT_MAX_RESPONSE_LINE_LEN;
    _smtp_config.no_alerts = 0;
    _smtp_config.cmd_size = 0;
    _smtp_config.alert_xlink2state = 1;
    _smtp_config.drop_xlink2state = 0;

    /*
     *  Build configured list of commands we do not alert on.
     */
    smtp_cmd = _smtp_known_cmds;
    while ( smtp_cmd->name != NULL )
    {
        /* Do not alert on the valid commands */
        ret = AddAlertCmd(smtp_cmd->name, smtp_cmd->id, 0);
        if ( ret == -1 )
        {
            DynamicPreprocessorFatalMessage("%s(%d) => Error setting alert for cmd %s.\n", 
                                            *(_dpd.config_file), *(_dpd.config_line), smtp_cmd->name);
            return;
        }
        smtp_cmd++;
    }

    *errStr = '\0';

    arg = strtok(args, CONF_SEPARATORS);
    
    while ( arg != NULL )
    {
        if ( !strcasecmp(PORTS, arg) )
        {
            ret = ProcessPorts(errStr, errStrLen);
            if ( ret == -1 )
                break;
        }
        else if ( !strcasecmp(INSPECTION_TYPE, arg) )
        {
            value = strtok(NULL, CONF_SEPARATORS);
            if ( value == NULL )
            {
                return;
            }
            if ( !strcasecmp(STATEFUL, value) )
            {
                _smtp_config.inspection_type = SMTP_STATEFUL;
            }
            else
            {
                _smtp_config.inspection_type = SMTP_STATELESS;
            }
        }
        else if ( !strcasecmp(NORMALIZE, arg) )
        {
            value = strtok(NULL, CONF_SEPARATORS);
            if ( value == NULL )
            {
                return;
            }
            if ( !strcasecmp(NONE, value) )
            {
                _smtp_config.normalize = normalize_none;
            }
            else if ( !strcasecmp(ALL, value) )
            {
                _smtp_config.normalize = normalize_all;
            }
            else
            {
                _smtp_config.normalize = normalize_cmds;
            }
        }
        else if ( !strcasecmp(IGNORE_DATA, arg) )
        {                    
             _smtp_config.ignore_data = 1;            
        }
        else if ( !strcasecmp(IGNORE_TLS_DATA, arg) )
        {
            _smtp_config.ignore_tls_data = 1;            
        }
        else if ( !strcasecmp(MAX_COMMAND_LINE_LEN, arg) )
        {
            char *endptr;

            value = strtok(NULL, CONF_SEPARATORS);
            if ( value == NULL )
            {
                return;
            }
            
            _smtp_config.max_command_line_len = strtol(value, &endptr, 10);
        }
        else if ( !strcasecmp(MAX_HEADER_LINE_LEN, arg) )
        {
            char *endptr;

            value = strtok(NULL, CONF_SEPARATORS);
            if ( value == NULL )
            {
                return;
            }
            
            _smtp_config.max_header_line_len = strtol(value, &endptr, 10);
        }
        else if ( !strcasecmp(MAX_RESPONSE_LINE_LEN, arg) )
        {
            char *endptr;

            value = strtok(NULL, CONF_SEPARATORS);
            if ( value == NULL )
            {
                return;
            }
            
            _smtp_config.max_response_line_len = strtol(value, &endptr, 10);
        }
        else if ( !strcasecmp(NO_ALERTS, arg) )
        {     
            _smtp_config.no_alerts = 1;
        }
        else if ( !strcasecmp(ALERT_UNKNOWN_CMDS, arg) )
        {
            _smtp_config.alert_unknown_cmds = 1;
        }
        else if ( !strcasecmp(INVALID_CMDS, arg) )
        {
            /* Parse disallowed commands */
            ret = ProcessCmds(errStr, errStrLen, 1);

        }
        else if ( !strcasecmp(VALID_CMDS, arg) )
        {
            /* Parse allowed commands */
            ret = ProcessCmds(errStr, errStrLen, 2);   
        }
        else if ( !strcasecmp(NORMALIZE_CMDS, arg) )
        {
            /* Parse normalized commands */
            ret = ProcessCmds(errStr, errStrLen, 0);
        }
        else if ( !strcasecmp(ALT_MAX_COMMAND_LINE_LEN, arg) )
        {
            /* Parse normalized commands */
            ret = ProcessAltMaxCmdLen(errStr, errStrLen);
        }
        else if ( !strcasecmp(XLINK2STATE, arg) )
        {
            ret = ProcessXlink2State(errStr, errStrLen);
        }

        else if ( !strcasecmp(PRINT_CMDS, arg) )
        {
            _smtp_config.print_cmds = 1;
        }
        else
        {
            DynamicPreprocessorFatalMessage("%s(%d) => Unknown SMTP configuration option %s\n", 
                                            *(_dpd.config_file), *(_dpd.config_line), arg);
        }        

        /*  Get next token */
        arg = strtok(NULL, CONF_SEPARATORS);
    }

    if ( ret < 0 )
    {
        /*
        **  Fatal Error, log error and exit.
        */
        if(*errStr)
        {
            DynamicPreprocessorFatalMessage("%s(%d) => %s\n", 
                                            *(_dpd.config_file), *(_dpd.config_line), errStr);
        }
        else
        {
            DynamicPreprocessorFatalMessage("%s(%d) => Undefined Error.\n", 
                                            *(_dpd.config_file), *(_dpd.config_line));
        }
    }

    PrintConfig();
}



/*
 *  Clean up memory allocated in this module
 */
void SMTP_ConfigFree()
{
    int i;

    if ( _smtp_config.cmd_size != 0 )
    {
        for ( i = 0; i < _smtp_config.cmd_size; i++ )
        {
            if (_smtp_config.cmd[i].name)
            {
                free(_smtp_config.cmd[i].name);
            }
        }
        free(_smtp_config.cmd);
    }
}


static int PrintConfig(void)
{
    int i;

    _dpd.logMsg("SMTP Config:\n");
    
    _dpd.logMsg("      Ports: ");
    for(i = 0; i < 65536; i++)
    {
        if( (_smtp_config.ports[i/8] & (1 << i%8)) )
        {
            _dpd.logMsg("%d ", i);
        }
   }
    _dpd.logMsg("\n");

    _dpd.logMsg("      Inspection Type:            %s\n",
               _smtp_config.inspection_type ? "STATEFUL" : "STATELESS");
    _dpd.logMsg("      Normalize Spaces:           %s\n", 
               _smtp_config.normalize ? "YES" : "NO");
    _dpd.logMsg("      Ignore Data:                %s\n", 
               _smtp_config.ignore_data ? "YES" : "NO");
    _dpd.logMsg("      Ignore TLS Data:            %s\n", 
               _smtp_config.ignore_tls_data ? "YES" : "NO");
    _dpd.logMsg("      Ignore Alerts:              %s\n",
               _smtp_config.no_alerts ? "YES" : "NO");
    _dpd.logMsg("      Max Command Length:         %d\n",
               _smtp_config.max_command_line_len);
    _dpd.logMsg("      Max Header Line Length:     %d\n",
               _smtp_config.max_header_line_len);
    _dpd.logMsg("      Max Response Line Length:   %d\n",
               _smtp_config.max_response_line_len);
    _dpd.logMsg("      X-Link2State Alert:         %s\n",
               _smtp_config.alert_xlink2state ? "YES" : "NO");
    _dpd.logMsg("      Drop on X-Link2State Alert: %s\n",
               _smtp_config.drop_xlink2state ? "YES" : "NO");

    if ( _smtp_config.print_cmds )
    {
        SMTP_token *cmd;
        
        _dpd.logMsg("      SMTP Alert on Command:\n");

        cmd = _smtp_config.cmd;
        while ( cmd->name != NULL )
        {
            /*  Ignore non-command strings */
            if ( strstr(cmd->name, "\n") == NULL )
            {
                _dpd.logMsg("          %s  -  %s\n",
                        cmd->name, cmd->alert ? "YES" : "NO");
            }
            cmd++;
        }
    }
    return 0;
}

/*
**  NAME
**    ProcessPorts::
*/
/**
**  Process the port list.
**
**  This configuration is a list of valid ports and is ended by a 
**  delimiter.
**
**  @param ErrorString error string buffer
**  @param ErrStrLen   the length of the error string buffer
**
**  @return an error code integer 
**          (0 = success, >0 = non-fatal error, <0 = fatal error)
**
**  @retval  0 successs
**  @retval -1 generic fatal error
**  @retval  1 generic non-fatal error
*/
static int ProcessPorts(char *ErrorString, int ErrStrLen)
{
    char *pcToken;
    char *pcEnd;
    int  iPort;
    int  iEndPorts = 0;

    pcToken = strtok(NULL, CONF_SEPARATORS);
    if(!pcToken)
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid port list format.");

        return -1;
    }

    if(strcmp(START_LIST, pcToken))
    {
        snprintf(ErrorString, ErrStrLen,
                "Must start a port list with the '%s' token.",
                START_LIST);

        return -1;
    }

    /* Since ports are specified, clear default ports */
    _smtp_config.ports[SMTP_DEFAULT_SERVER_PORT/8] &= ~(1 << SMTP_DEFAULT_SERVER_PORT%8);
    _smtp_config.ports[XLINK2STATE_DEFAULT_PORT/8] &= ~(1 << XLINK2STATE_DEFAULT_PORT%8);

    while((pcToken = strtok(NULL, CONF_SEPARATORS)))
    {
        if(!strcmp(END_LIST, pcToken))
        {
            iEndPorts = 1;
            break;
        }

        iPort = strtol(pcToken, &pcEnd, 10);

        /*
        **  Validity check for port
        */
        if(*pcEnd)
        {
            snprintf(ErrorString, ErrStrLen,
                    "Invalid port number.");

            return -1;
        }

        if(iPort < 0 || iPort > 65535)
        {
            snprintf(ErrorString, ErrStrLen,
                    "Invalid port number.  Must be between 0 and "
                    "65535.");

            return -1;
        }

        _smtp_config.ports[iPort/8] |= (1 << iPort%8);
    }

    if(!iEndPorts)
    {
        snprintf(ErrorString, ErrStrLen,
                "Must end '%s' configuration with '%s'.",
                PORTS, END_LIST);

        return -1;
    }

    return 0;
}

/*
**  NAME
**    ProcessCmds::
*/
/**
**  Process the command list.
**
**  This configuration is a list of valid ports and is ended by a 
**  delimiter.
**
**  @param ErrorString error string buffer
**  @param ErrStrLen   the length of the error string buffer
**
**  @return an error code integer 
**          (0 = success, >0 = non-fatal error, <0 = fatal error)
**
**  @retval  0 successs
**  @retval -1 generic fatal error
*/
static int ProcessCmds(char *ErrorString, int ErrStrLen, u_int alert)
{
    char *pcToken;
    int   iEndCmds = 0;
    int   ret;
    
    pcToken = strtok(NULL, CONF_SEPARATORS);
    if(!pcToken)
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid command list format.");

        return -1;
    }

    if(strcmp(START_LIST, pcToken))
    {
        snprintf(ErrorString, ErrStrLen,
                "Must start a command list with the '%s' token.",
                START_LIST);

        return -1;
    }
    
    while((pcToken = strtok(NULL, CONF_SEPARATORS)))
    {
        if(!strcmp(END_LIST, pcToken))
        {
            iEndCmds = 1;
            break;
        }
        if ( alert )
        {
            u_int id = GetCmdId(pcToken);

            ret = AddAlertCmd(pcToken, id, alert == 1 ? 1 : 0);   
            if ( ret == -1 )
            {
                snprintf(ErrorString, ErrStrLen,
                                "Error setting alert for cmd %s.", pcToken);
                return -1;
            }
        }
        else
        {
            ret = AddNormalizeCmd(pcToken);
            if ( ret == -1 )
            {
                snprintf(ErrorString, ErrStrLen,
                                "Error setting normalization for cmd %s.", pcToken);
                return -1;
            }
        }
    }

    if(!iEndCmds)
    {
        if ( alert )
        {
            snprintf(ErrorString, ErrStrLen,
                    "Must end '%s' configuration with '%s'.",
                    alert == 1 ? INVALID_CMDS : VALID_CMDS, END_LIST);
        }
        else
        {
             snprintf(ErrorString, ErrStrLen,
                    "Must end '%s' configuration with '%s'.",
                    NORMALIZE_CMDS, END_LIST);
        }
        return -1;
    }

    return 0;
}

/* Return id associated with a given command string */
static u_int GetCmdId(char *name)
{
    SMTP_cmd *smtp_cmd;

    /*
     *  Build configured list of commands we do not alert on.
     */
    smtp_cmd = _smtp_known_cmds;
    while ( smtp_cmd->name != NULL )
    {
        if ( strcmp(smtp_cmd->name, name) == 0 )
        {
            return smtp_cmd->id;
        }
        smtp_cmd++;
    }
    
    return CMD_OTHER;
}

/* Return -1 on error */
static int AddAlertCmd(char *name, u_int id, u_int alert)
{
    int found = 0;
    int i;
    int ret;

    /* Only add if name valid command name */
    if ( name == NULL )
        return 0;  /* Not necessarily an error */

    /* See if command already in list */
    for ( i = 0; i < _smtp_config.cmd_size; i++ )
    {
        if ( !_smtp_config.cmd[i].name )
        {
            /* No name... try next one */
            continue;
        }

        if ( strcmp(_smtp_config.cmd[i].name, name) == 0 )
        {
            found = 1;
            break;
        }
    }

    if ( found )
    {
        _smtp_config.cmd[i].alert = alert;
        return 0;
    }

    if ( _smtp_config.cmd_size == 0 )
    {
        _smtp_config.cmd = (SMTP_token *) calloc(2, sizeof(SMTP_token));
         
        if ( _smtp_config.cmd == NULL )
            return -1;

        _smtp_config.cmd_size++;
    }
    else
    {
        SMTP_token *tmp;
        u_int8_t *tmp_start, *tmp_end;

        _smtp_config.cmd_size++;
        tmp = (SMTP_token *) calloc((1 + _smtp_config.cmd_size), sizeof(SMTP_token));
        if ( tmp == NULL )
        {
            /* failed to allocate, decrement size that was incremented above */
            _smtp_config.cmd_size--;
            return -1;
        }
        else
        {
            /* Copy in the existing data... */
            tmp_start = (u_int8_t*)tmp;
            tmp_end = tmp_start + ((_smtp_config.cmd_size+1) * sizeof(SMTP_token));
            ret = SafeMemcpy(tmp, _smtp_config.cmd, _smtp_config.cmd_size * sizeof(SMTP_token),
                             tmp_start, tmp_end);

            if (ret == SAFEMEM_ERROR)
            {
                _dpd.fatalMsg("%s(%d) => SafeMemcpy failed\n",
                              *(_dpd.config_file), *(_dpd.config_line));
            }

            free(_smtp_config.cmd);
            _smtp_config.cmd = tmp;
        }
    }
    _smtp_config.cmd[_smtp_config.cmd_size-1].name  = strdup(name);
    if ( _smtp_config.cmd[_smtp_config.cmd_size-1].name == NULL )
        return -1;
    _smtp_config.cmd[_smtp_config.cmd_size-1].name_len = 0;
    _smtp_config.cmd[_smtp_config.cmd_size-1].id    = id;
    _smtp_config.cmd[_smtp_config.cmd_size-1].alert = alert;
    _smtp_config.cmd[_smtp_config.cmd_size-1].normalize = 0;
    _smtp_config.cmd[_smtp_config.cmd_size-1].max_len = 0;
    _smtp_config.cmd[_smtp_config.cmd_size].name    = NULL;
    _smtp_config.cmd[_smtp_config.cmd_size].name_len = 0;
    _smtp_config.cmd[_smtp_config.cmd_size].id      = 0;
    _smtp_config.cmd[_smtp_config.cmd_size].alert   = 0;
    _smtp_config.cmd[_smtp_config.cmd_size].normalize   = 0;
    _smtp_config.cmd[_smtp_config.cmd_size].max_len = 0;
   
    return 0;
}




/* Return -1 on error */
static int AddNormalizeCmd(char *name)
{
    SMTP_token *cmd;

    /* Only add if name valid command name */
    if ( name == NULL )
        return 0;  /* Not necessarily an error */

    /*  Find command */
    for ( cmd = _smtp_config.cmd; cmd->name != NULL; cmd++ )
    {
        if ( !strncasecmp(name, cmd->name, strlen(name)) )
        {
            cmd->normalize = 1;
            return 0;
        }
    }

    return -1;
}



/*
**  NAME
**    ProcessAltMaxCmdLen::
*/
/**
**
**   alt_max_command_line_len <int> { <cmd> [<cmd>] }
**
**  @param ErrorString error string buffer
**  @param ErrStrLen   the length of the error string buffer
**
**  @return an error code integer 
**          (0 = success, >0 = non-fatal error, <0 = fatal error)
**
**  @retval  0 successs
**  @retval -1 generic fatal error
*/
static int ProcessAltMaxCmdLen(char *ErrorString, int ErrStrLen)
{
    char *pcToken;
    char *pcLen;
    int   iEndCmds = 0;
    int   ret;
    int   cmd_len;
    char *pcLenEnd;
    
    /* Find number */
    pcLen = strtok(NULL, CONF_SEPARATORS);
    if(!pcLen)
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid format for alt_max_command_line_len.");

        return -1;
    }

    pcToken = strtok(NULL, CONF_SEPARATORS);
    if(!pcLen)
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid format for alt_max_command_line_len.");

        return -1;
    }
    
    cmd_len = strtoul(pcLen, &pcLenEnd, 10);
    if (pcLenEnd == pcLen)
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid format for alt_max_command_line_len (non-numeric).");

        return -1;
    }

    if(strcmp(START_LIST, pcToken))
    {
        snprintf(ErrorString, ErrStrLen,
                "Must start alt_max_command_line_len list with the '%s' token.",
                START_LIST);

        return -1;
    }
    
    while((pcToken = strtok(NULL, CONF_SEPARATORS)))
    {
        if(!strcmp(END_LIST, pcToken))
        {
            iEndCmds = 1;
            break;
        }
        
        ret = SetCmdLen(pcToken, cmd_len);   
        if ( ret == -1 )
        {
            snprintf(ErrorString, ErrStrLen,
                            "Error setting alert for cmd %s.", pcToken);
            return -1;
        }        
    }

    if(!iEndCmds)
    {
        snprintf(ErrorString, ErrStrLen,
                "Must end alt_max_command_line_len configuration with '%s'.", END_LIST);
     
        return -1;
    }

    return cmd_len;
}


/* Return -1 on error */
static int SetCmdLen(char *name, u_int max_len)
{
    SMTP_token *cmd;

    /* Only add if name valid command name */
    if ( name == NULL )
        return 0;  /* Not necessarily an error */

    /*  Find command */
    for ( cmd = _smtp_config.cmd; cmd->name != NULL; cmd++ )
    {
        if ( !strncasecmp(name, cmd->name, strlen(name)) )
        {
            cmd->max_len = max_len;
            return 0;
        }
    }

    return -1;
}

/*
**  NAME
**    ProcessXlink2State::
*/
/**
**
**   xlink2state { <enable/disable> <drop> }
**
**  @param ErrorString error string buffer
**  @param ErrStrLen   the length of the error string buffer
**
**  @return an error code integer 
**          (0 = success, >0 = non-fatal error, <0 = fatal error)
**
**  @retval  0 successs
**  @retval -1 generic fatal error
*/
static int ProcessXlink2State(char *ErrorString, int ErrStrLen)
{
    char *pcToken;
    int  iEnd = 0;

    pcToken = strtok(NULL, CONF_SEPARATORS);
    if(!pcToken)
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid xlink2state argument format.");

        return -1;
    }

    if(strcmp(START_LIST, pcToken))
    {
        snprintf(ErrorString, ErrStrLen,
                "Must start xlink2state arguments with the '%s' token.",
                START_LIST);

        return -1;
    }
    
    while((pcToken = strtok(NULL, CONF_SEPARATORS)))
    {
        if(!strcmp(END_LIST, pcToken))
        {
            iEnd = 1;
            break;
        }

        if ( !strcasecmp(DISABLE, pcToken) )
        {
            _smtp_config.alert_xlink2state = 0;
        }
        else if ( !strcasecmp(ENABLE, pcToken) )
        {
            _smtp_config.alert_xlink2state = 1;
        }
        else if ( !strcasecmp(INLINE_DROP, pcToken) )
        {
            if (_dpd.inlineMode())
            {
                _smtp_config.drop_xlink2state = 1;
            }
            else
            {
                _dpd.logMsg("%s(%d) WARNING: drop keyword ignored."
                           "snort is not in inline mode\n",
                           *(_dpd.config_file), *(_dpd.config_line));
            }
        }
    }

    if(!iEnd)
    {
        snprintf(ErrorString, ErrStrLen,
                "Must end '%s' configuration with '%s'.",
                PORTS, END_LIST);

        return -1;
    }

    return 0;
}    
