
/*
 * snort_smtp.c
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
 * This file handles SMTP protocol checking and normalization.
 *
 * Entry point functions:
 *
 *     SnortSMTP()
 *     SMTP_Init()
 *     SMTP_Free()
 *
 *
 */
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "sf_snort_packet.h"
#include "stream_api.h"

#include "debug.h"

#include "snort_smtp.h"
#include "smtp_util.h"
#include "smtp_log.h"
#include "smtp_xlink2state.h"
#include "smtp_normalize.h"

#include "bounds.h"

#include "profiler.h"
#ifdef PERF_PROFILING
extern PreprocStats smtpDetectPerfStats;
extern int smtpDetectCalled;
#endif


/* Function callbacks */
int SMTP_CmdStrFound(void * id, int index, void *data);
int SMTP_RespStrFound(void * id, int index, void *data);
int SMTP_DataStrFound(void * id, int index, void *data);

/* Private functions */
static void SMTP_Setup(SFSnortPacket *p);
static void SMTP_ResetState(SMTP *x);
static void SMTP_SessionFree(void *);
static int  IsServer(unsigned short port);
static void GetPacketDirection(SFSnortPacket *p);
static void SMTP_ProcessClientPacket(SFSnortPacket *p);
static int  SMTP_ProcessServerPacket(SFSnortPacket *p);
static void SMTP_DataInit(SMTP *smtp);
static void SMTP_DisableDetect(SFSnortPacket *p);

#define CMD_SEARCH      0
#define RESP_SEARCH     1
#define DATA_SEARCH     2
#define NUM_SEARCHES    3



/* 
 * Instantiate global preprocessor structure
 */
SMTP *_smtp = NULL;

SMTP smtp_default;

t_bm bm;

/* List of commands to alert on */
extern SMTP_CONFIG  _smtp_config;
extern char         _smtp_event[SMTP_EVENT_MAX][256];



SMTP_token _smtp_resp[] =
{
	{"354",      0,  RESP_354,   0,  0,  0,},  /* Data response */
	{"250",      0,  RESP_250,   0,  0,  0,},  /* OK */
	{"421:",     0,  RESP_421,   0,  0,  0,},  /* Service not available */

	{NULL,       0,  0,          0,  0,  0}
};

static SMTP_token _smtp_data[] =
{
	{"BOUNDARY", 0,  DATA_BOUNDARY,      0,  0,  0,},
	{".\n",      0,  DATA_BODY_END,      0,  0,  0,},  
	{".\r\n",    0,  DATA_BODY_END,      0,  0,  0,}, 
	{"\n\n",     0,  DATA_HEADER_END,    0,  0,  0,},
	{"\r\n\r\n", 0,  DATA_HEADER_END,    0,  0,  0,},
    
	{NULL,       0,  0,                  0,  0,  0}
};


/*
 * Initialize SMTP preprocessor
 *
 * @param  none
 *
 * @return none
 */
void SMTP_Init(void)
{
    int   i = 0;
    
    /* Set up commands we will watch for */
    _dpd.searchAPI->search_init(NUM_SEARCHES);
    for ( i = 0; i < _smtp_config.cmd_size ; i++ )
    {
        if (_smtp_config.cmd[i].name == NULL)
        {
            /* Save length of this command for future use */
            _smtp_config.cmd[i].name_len = 0;
        }
        else
        {
            /* Save length of this command for future use */
            _smtp_config.cmd[i].name_len = strlen(_smtp_config.cmd[i].name);
            _dpd.searchAPI->search_add(CMD_SEARCH, _smtp_config.cmd[i].name, _smtp_config.cmd[i].name_len, i);
        }
    }
    _dpd.searchAPI->search_prep(CMD_SEARCH);

    for ( i = 0; _smtp_resp[i].name != NULL; i++ )
    {
        /* Save length of this response for future use */
        _smtp_resp[i].name_len = strlen(_smtp_resp[i].name);
        _dpd.searchAPI->search_add(RESP_SEARCH, _smtp_resp[i].name, _smtp_resp[i].name_len, i);
    }
    _dpd.searchAPI->search_prep(RESP_SEARCH);

    make_boyer_moore(&bm, "boundary=", 9);
}

/* Set up data body searches, per session */
static void SMTP_DataInit(SMTP *smtp)
{
    int i;

    if ( !smtp )
    {
        return;
    }

    if ( smtp->data_search )
    {
        _dpd.searchAPI->search_instance_free(smtp->data_search);
    }
    
    smtp->data_search = _dpd.searchAPI->search_instance_new();
    
    if ( !smtp->data_search )
    {
        return;
    }

    /* Add search for end of data body */
    for ( i = 0; _smtp_data[i].name != NULL; i++ )
    {
        /* Save length of the data for future use */
        if ( _smtp_data[i].id == DATA_BOUNDARY )
        {
            /* If we have a boundary, add it; otherwise, ignore. */
            if ( smtp && smtp->boundary_len > 0 )
            {
                _smtp_data[i].name = smtp->boundary;
                _smtp_data[i].name_len = smtp->boundary_len;
                _dpd.searchAPI->search_instance_add(_smtp->data_search, _smtp_data[i].name, _smtp_data[i].name_len, i);
            }
        }   
        else
        {
            _smtp_data[i].name_len = strlen(_smtp_data[i].name);
            _dpd.searchAPI->search_instance_add(smtp->data_search, _smtp_data[i].name, _smtp_data[i].name_len, i);
        }
    }

    _dpd.searchAPI->search_instance_prep(smtp->data_search);
}


/*
 * Reset SMTP session state
 *
 * @param  none
 *
 * @return none
 */
static void SMTP_ResetState(SMTP *smtp)
{
    smtp->state = COMMAND;
    smtp->message_number = 0;
    smtp->pkt_direction = SMTP_PKT_FROM_UNKNOWN;
    smtp->got_data_cmd = 0;
    smtp->got_data_resp = 0;
    smtp->got_starttls = 0;
    smtp->got_server_tls = 0;
    smtp->last_byte = 0;
    smtp->cur_client_line_len = 0;
    smtp->cur_server_line_len = 0;
    smtp->last_byte_is_lf = 0;
    smtp->normalizing = 0 ;        
    smtp->token_id = 0;           
    smtp->token_iid = 0;           
    smtp->token_index = 0;         
    smtp->token_length = 0;        
    smtp->xlink2state_gotfirstchunk = 0;
    smtp->xlink2state_alerted = 0;
    smtp->boundary_len = 0;

    SMTP_DataInit(smtp);
}


/*
 * Given a server configuration and a port number, we decide if the port is
 *  in the SMTP server port list.
 *
 *  @param  port       the port number to compare with the configuration
 *
 *  @return integer
 *  @retval  0 means that the port is not a server port
 *  @retval !0 means that the port is a server port
 */
static int IsServer(unsigned short port)
{
    if( (_smtp_config.ports[port/8] & (1 << port%8)) )
    {
        return 1;
    }

    return 0;
}


/*
 * Do first-packet setup
 *
 * @param   p   standard Packet structure
 *
 * @return  none
 */
static void SMTP_Setup(SFSnortPacket *p)
{   
    /* Get session pointer */
    SMTP *smtp = NULL;
    
    if ( !p->stream_session_ptr )
    {
        _smtp = &smtp_default;
        memset(_smtp, 0, sizeof(SMTP));
        return;
    }

    smtp = _dpd.streamAPI->get_application_data(p->stream_session_ptr, PP_SMTP);

    if ( smtp == NULL )
    {
        smtp = (SMTP *) malloc(sizeof(SMTP));
        if ( smtp == NULL )
        {
            DynamicPreprocessorFatalMessage("%s(%d) => Failed to allocate for SMTP session data\n");
            return;
        }
        else
        {      
            _dpd.streamAPI->set_application_data(p->stream_session_ptr, PP_SMTP,
                                                    smtp, &SMTP_SessionFree);   
        }
        
        /* Initialize state for first packet */
        memset(smtp, 0, sizeof(SMTP));

        /* Set up searches for data portion of mail messages */
        SMTP_DataInit(smtp);
    }
    
    _smtp = smtp;
}

/*
 * Determine packet direction
 *
 * @param   p   standard Packet structure
 *
 * @return  none
 */
static void GetPacketDirection(SFSnortPacket *p)
{    
    /*
     *  We now set the packet direction
     */
    if (_dpd.streamAPI->get_session_flags(p->stream_session_ptr) & SSNFLAG_MIDSTREAM)
    {
        /* We can't be sure what state we are in, in this case. */
        SMTP_ResetState(_smtp);

        if ( IsServer(p->src_port) )
        {
            if ( !IsServer(p->dst_port) )
            {
                _smtp->pkt_direction = SMTP_PKT_FROM_SERVER;
            }
            else
            {
                _smtp->pkt_direction = SMTP_PKT_FROM_UNKNOWN;
            }
        }
        else if ( IsServer(p->dst_port) )
        {
            _smtp->pkt_direction = SMTP_PKT_FROM_CLIENT;
        }
    }
    else if (p->flags & FLAG_FROM_SERVER)
    {
        _smtp->pkt_direction = SMTP_PKT_FROM_SERVER;
    }
    else if (p->flags & FLAG_FROM_CLIENT)
    {
        _smtp->pkt_direction = SMTP_PKT_FROM_CLIENT;
    }
    else
    {
        _smtp->pkt_direction = SMTP_PKT_FROM_UNKNOWN;
    }
}


/*
 * Free SMTP-specific related to this session
 *
 * @param   v   pointer to SMTP session structure
 *
 * @return  none
 */
static void SMTP_SessionFree(void * v)
{
    SMTP *smtp = (SMTP *) v;

    if ( smtp )
    {
        if ( smtp->data_search )
        {
            _dpd.searchAPI->search_instance_free(smtp->data_search);
        }

        free(smtp);
    }
    return;
}


/*
 * Free anything that needs it before shutting down preprocessor
 *
 * @param   none
 *
 * @return  none
 */
void SMTP_Free(void)
{
    _dpd.searchAPI->search_free();
}


/*
 * Callback function for string search
 *
 * @param   id      id in array of search strings from _smtp_config.cmds
 * @param   index   index in array of search strings from _smtp_config.cmds
 * @param   data    buffer passed in to search function
 *
 * @return response
 * @retval 1        commands caller to stop searching
 */
int SMTP_CmdStrFound(void *id, int index, void *data)
{
    int  iid = (int) id;
    SMTP_token smtp_token;

    DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "StrFound: %d, %d, %c\n", iid, index,
											((char *)data)[0]););

    smtp_token = _smtp_config.cmd[iid];

    _smtp->token_id = smtp_token.id;
    _smtp->token_iid = iid;
    _smtp->token_index = index;
    _smtp->token_length = smtp_token.name_len;

    DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "Found!  %s, id = %x\n",
							smtp_token.name, _smtp->token_id););

    /* Returning non-zero stops search, which is okay since we only look for one at a time */
    return 1;
}


/*
 * Callback function for string search
 *
 * @param   id      id in array of search strings
 * @param   index   index in array of search strings
 * @param   data    buffer passed in to search function
 *
 * @return response
 * @retval 1        commands caller to stop searching
 */
int SMTP_RespStrFound(void *id, int index, void *data)
{
    int  iid = (int) id;
    SMTP_token smtp_token;

    DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "StrFound: %d, %d, %c\n", iid, index,
											((char *)data)[0]););

    smtp_token = _smtp_resp[iid];

    _smtp->token_id = smtp_token.id;
    _smtp->token_iid = iid;
    _smtp->token_index = index;
    _smtp->token_length = smtp_token.name_len;
    
    DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "Found!  %s, id = %x\n",
							smtp_token.name, _smtp->token_id););

    /* Returning non-zero stops search, which is okay since we only look for one at a time */
    return 1;
}

/*
 * Callback function for string search
 *
 * @param   id      id in array of search strings
 * @param   index   index in array of search strings
 * @param   data    buffer passed in to search function
 *
 * @return response
 * @retval 1        commands caller to stop searching
 */
int SMTP_DataStrFound(void *id, int index, void *data)
{
    int  iid = (int) id;
    SMTP_token smtp_token;

    DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "StrFound: %d, %d, %c\n", iid, index,
											((char *)data)[0]););

    smtp_token = _smtp_data[iid];

    _smtp->token_id = smtp_token.id;
    _smtp->token_iid = iid;
    _smtp->token_index = index;
    _smtp->token_length = smtp_token.name_len;

    DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "Found!  %s, id = %x\n",
							smtp_token.name, _smtp->token_id););

    /* Returning non-zero stops search, which is okay since we only look for one at a time */
    return 1;
}


/*
 * Function to extract boundary string from given text
 *
 * @param   searchStr   current data, may contain "boundary="
 *
 * @return response
 * @retval 1            success, found boundary string
 * @retval 0            failure
 *
 * @note   this whole routing could probably be optimized
 */
static int GetBoundaryString(char *data, u_int data_len)
{
    char *b;
    char *end;
    u_int blen = 0;
    u_int boundary_len = 9;  /* strlen("boundary=") */
    u_int multipart_len = 9; /* strlen("multipart") */
    int ret;

    /* We've got Content-Type:, look for "multipart" following */
    while ( data_len > 0 && isspace(*data) )
    {
        data++;
        data_len--;
    }

    /* If not multipart, bail */
    if ( data_len > multipart_len && memcmp(data, "multipart", multipart_len) != 0 )
        return 0;

    /* We've got Content-Type, look for boundary string */
    b = bm_search(data, data_len, &bm);
    if ( !b )
        return 0;

    /* since b > data and b < data + data_len, this subtraction will
     * not yield a negative number
     * b will be somewhere between data and data + data_len */
    blen = data_len - (b - data);

    b += boundary_len;  
    blen -= boundary_len;

    if (b >= data + data_len)
        return 0;

    if ( *b == '\"' )
    {
        b++;
        blen--;
        end = safe_strchr(b, '\"', blen);
        if ( !end )
            return 0;
    }
    else
    {
        end = safe_strchr(b, '\r', blen);
        if ( !end )
            end = safe_strchr(b, '\n', blen);
        if ( !end )
            return 0;
    }

    /* recalculate blen based on where end is */
    blen = end - b;

    ret = SafeMemcpy(_smtp->boundary, "--", 2, _smtp->boundary, _smtp->boundary + MAX_BOUNDARY_LEN);
    if (ret == SAFEMEM_ERROR)
        return 0;

    ret = SafeMemcpy(_smtp->boundary+2, b, blen, _smtp->boundary+2, _smtp->boundary + MAX_BOUNDARY_LEN);
    if (ret == SAFEMEM_ERROR)
        return 0;

    blen += 2;
    if (blen >= MAX_BOUNDARY_LEN)
        return 0;
    _smtp->boundary[blen] = '\0';
    _smtp->boundary_len = blen;

    return 1;
}

/*
 * Handle COMMAND state
 *
 * @param   packet  standard Packet structure
 *
 * @param   i       index into p->payload buffer to start looking at data
 *
 * @return  i       index into p->payload where we stopped looking at data
 */
static u_int16_t SMTP_HandleCommandState(SFSnortPacket *p, u_int16_t i)
{
    u_int16_t count = 0;
    u_int8_t  c;
    int       cmdFound;
    char     *searchStr;
    int       nbytes;
    int       ret;

    /* Loop through packet, counting chars.  Notice if one is LF. */
    for ( ; i < p->payload_size; i++ )
    {
        /* If at beginning of line */
        if ( count == 0 )
        {
            /* Search starting at current character */
            searchStr = p->payload + i;

            /* Check for command verb or data header end */
            cmdFound = _dpd.searchAPI->search_find(CMD_SEARCH, searchStr, p->payload_size - i, 1, SMTP_CmdStrFound);

            DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "Match found: %s\n", cmdFound ? "YES" : "NO"););

            /* See if we found a command at the beginning of the line */
            if ( cmdFound && _smtp->token_index == 0 )
                cmdFound = 1;
            else
                cmdFound = 0;

            if ( (_smtp->state == COMMAND) && cmdFound )
            {     
                if ( (_smtp->token_id & CMD_DATA) || (_smtp->token_id & CMD_BDAT) )
                {
                    /* Got client DATA or BDAT and server 354, now we know we are in data section */
                    _smtp->got_data_cmd = 1;
                    if ( _smtp->got_data_resp )
                    {
                        _smtp->state = DATA;                      
                    }
                    else
                    {
                        _smtp->state = DATA_PEND;
                    }     
                    i += _smtp->token_length;
                    if ( *(p->payload + i) == '\r' )
                        i++;
                    if ( *(p->payload + i) == '\n' )
                        i++;
                    return i;
                }
                else if ( _smtp->token_id & CMD_STARTTLS )
                {
                    _smtp->got_starttls = 1;
                    if ( _smtp->got_server_tls )
                    {
                        _smtp->state = TLS_DATA;
                        /* Done, since now data is encrypted */
                        p->payload_size = i + _smtp->token_length;
                        return p->payload_size;
                    }
                }
                else if ( _smtp->token_id & CMD_XLINK2STATE )
                {
                    ParseXLink2State(p, (searchStr + _smtp->token_index));
                }
                
                if ( _smtp_config.cmd[_smtp->token_iid].alert )
                {
                    SMTP_GenerateAlert(SMTP_EVENT_ILLEGAL_CMD, "%s: %s",
                            SMTP_ILLEGAL_CMD_STR, _smtp_config.cmd[_smtp->token_iid].name);
                }                    
                
                if ( _smtp_config.normalize )
                {
                    if ( _smtp_config.normalize == normalize_all
                            || _smtp_config.cmd[_smtp->token_iid].normalize )
                    {
                        if ( !_smtp->normalizing )
                        {
                            if ( SMTP_NeedNormalize(p->payload + i + _smtp->token_length, p->payload + p->payload_size) )
                            {
                                _smtp->normalizing = 1;
                                ret = SafeMemcpy(_dpd.altBuffer, p->payload, i,
                                                 _dpd.altBuffer, _dpd.altBuffer+_dpd.altBufferLen);

                                //if (ret == SAFEMEM_ERROR)
                                //{
                                //    DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "SMTP_HandleCommandState() => SafeMemcpy failed\n"););
                                //    return -1;
                                //}

                                p->normalized_payload_size = i;

                                nbytes = SMTP_Normalize(p, i, _smtp->token_length);
                                //if (nbytes == -1)
                                //{
                                //    DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "SMTP_HandleCommandState() => SMTP_Normalize failed\n"););
                                //    return -1;
                                //}

                                i+= nbytes;
                                count += nbytes;
                                p->flags |= FLAG_ALT_DECODE;
                            }
                        }
                        else  /* Already normalizing */
                        {
                            nbytes = SMTP_Normalize(p, i, _smtp->token_length);
                            //if (nbytes == -1)
                            //{
                            //    DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "SMTP_HandleCommandState() => SMTP_Normalize failed\n"););
                            //    p->flags &= ~FLAG_ALT_DECODE;
                            //    return -1;
                            //}

                            i += nbytes;
                            count += nbytes;
                        }
                    }                        
                }
            }
            else if ( (_smtp->state == COMMAND) && !cmdFound )
            {
                if ( _smtp_config.alert_unknown_cmds )
                {
                    SMTP_GenerateAlert(SMTP_EVENT_UNKNOWN_CMD, "%s", SMTP_UNKNOWN_CMD_STR);
                }
            }
        }
        
        count++;
        c = *(p->payload + i);

        if ( _smtp->normalizing )
        {
            _dpd.altBuffer[p->normalized_payload_size] = c;
            p->normalized_payload_size++;
        }

        if ( c == '\n' )
        {
            if ( _smtp->token_id && _smtp_config.cmd[_smtp->token_iid].max_len != 0
                        && count > _smtp_config.cmd[_smtp->token_iid].max_len )
            {
                SMTP_GenerateAlert(SMTP_EVENT_SPECIFIC_CMD_OVERFLOW,
                        "%s: %s, %d chars", SMTP_SPECIFIC_CMD_OVERFLOW_STR,
                        _smtp_config.cmd[_smtp->token_iid].name, count);
            }
            else if ( _smtp_config.max_command_line_len != 0
                        && count > _smtp_config.max_command_line_len )
            {
                SMTP_GenerateAlert(SMTP_EVENT_COMMAND_OVERFLOW,
                            "%s: more than %d chars", SMTP_COMMAND_OVERFLOW_STR,
                            _smtp_config.max_command_line_len);
            }                        
            count = 0;            
            /* Reset found string */
            _smtp->token_id = 0;
        }        
    }

    if (count != 0)
    {
        if ( _smtp->token_id && _smtp_config.cmd[_smtp->token_iid].max_len != 0
                    && count > _smtp_config.cmd[_smtp->token_iid].max_len )
        {
            SMTP_GenerateAlert(SMTP_EVENT_SPECIFIC_CMD_OVERFLOW,
                    "%s: %s, %d chars", SMTP_SPECIFIC_CMD_OVERFLOW_STR,
                    _smtp_config.cmd[_smtp->token_iid].name, count);
        }
        else if ( _smtp_config.max_command_line_len != 0
                    && count > _smtp_config.max_command_line_len )
        {
            SMTP_GenerateAlert(SMTP_EVENT_COMMAND_OVERFLOW,
                        "%s: more than %d chars", SMTP_COMMAND_OVERFLOW_STR,
                        _smtp_config.max_command_line_len);
        }                        
    }                        
    return i;
}

/*
 * Handle DATA state
 *
 * @param   packet  standard Packet structure
 *
 * @param   i       index into p->payload buffer to start looking at data
 *
 * @return  i       index into p->payload where we stopped looking at data
 */
static u_int16_t SMTP_HandleDataState(SFSnortPacket *p, u_int16_t i)
{
    u_int16_t count = 0;
    u_int8_t  c;
    int       cmdFound;
    char     *searchStr;

    /* Loop through packet, counting chars.  Notice if one is LF. */
    for ( ; i < p->payload_size; i++ )
    {
        /* If at beginning of line */
        if ( count == 0 )
        {
            /* Search starting at current character */
            searchStr = p->payload + i;

            /* Check for command verb or data header end */
            cmdFound = _dpd.searchAPI->search_find(CMD_SEARCH, searchStr, p->payload_size - i, 1, SMTP_CmdStrFound);

            DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "Match found: %s\n", cmdFound ? "YES" : "NO"););

            /* See if we found a command at the beginning of the line */
            if ( cmdFound && _smtp->token_index == 0 )
                cmdFound = 1;
            else
                cmdFound = 0;

            if ( _smtp->state == DATA )
            {
                if ( (searchStr[0] == '\n')
                        || ( (i < p->payload_size-1) && searchStr[0] == '\r' && searchStr[1] == '\n' ) )
                {
                    DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "End DATA HEADER section"););
                    _smtp->state = DATA_BODY;
                }
                else if ( cmdFound && (_smtp->token_id & CMD_TYPE) )
                {
                    /*  Find Boundary string */
                    i += _smtp->token_length;
                    GetBoundaryString(p->payload + i, p->payload_size - i);
                    SMTP_DataInit(_smtp);
                }
            }
        }

        count++;
        c = *(p->payload + i);

        if ( _smtp->normalizing )
        {
            _dpd.altBuffer[p->normalized_payload_size] = c;
            p->normalized_payload_size++;
        }

        if ( c == '\n' )
        {
            if ( _smtp_config.max_header_line_len != 0 && count > _smtp_config.max_header_line_len )
            {
                SMTP_GenerateAlert(SMTP_EVENT_DATA_HDR_OVERFLOW,
                            "%s: %d chars", SMTP_DATA_HDR_OVERFLOW_STR, count);
            }
            count = 0;
        }

        if ( _smtp->state == DATA_BODY )
        {
            return i + 1;
        }
    }
    return i;
}


/*
 * Handle DATA_BODY state
 *
 * @param   packet  standard Packet structure
 *
 * @param   i       index into p->payload buffer to start looking at data
 *
 * @return  i       index into p->payload where we stopped looking at data
 */
static u_int16_t SMTP_HandleDataBodyState(SFSnortPacket *p, u_int16_t i)
{
    char *searchStr;
    int   cmdFound = 0;
    u_int16_t next_index = i;

    if ( !_smtp->data_search )
    {
        /* Nothing to do, so skip packet */
        return p->payload_size;
    }

    /* Search starting at current character */
    searchStr = p->payload + i;

    /* Check for command verb or data header end */
    cmdFound = _dpd.searchAPI->search_instance_find(_smtp->data_search, searchStr, 
                                    p->payload_size - i, 0, SMTP_DataStrFound);

    if ( cmdFound )
    {
        /* If found MIME boundary */
        if ( _smtp->token_id & DATA_BOUNDARY )
        {
            _smtp->state = MIME_HEADER;
        }
        /* If found end of mail, drop back into command state */
        else if ( _smtp->token_id & DATA_BODY_END )
        {
            /* Make sure the period is on a line by itself */
            if ( _smtp->token_index == 0 || searchStr[_smtp->token_index-1] == '\n' )
            {
                /* Handle multiple mail messages */
                _smtp->state = COMMAND;
                _smtp->message_number++;
                
                DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "Message number: %d", _smtp->message_number););
            }
        }

        next_index += _smtp->token_index + _smtp->token_length;
    }
    else if ( _smtp_config.ignore_data )
    {
        /* Ignore data */
        DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "In DATA_BODY section; ignore data\n"););
        if ( _smtp->normalizing )
        {
            p->normalized_payload_size = i;
        }
        else
        {
            p->payload_size = i;
        }
    }
   
    if ( !cmdFound )
    {
        /* Done looking at this packet */
        return p->payload_size;
    }

    return next_index;
}

/*
 * Handle COMMAND state
 *
 * @param   packet  standard Packet structure
 *
 * @param   i       index into p->payload buffer to start looking at data
 *
 * @return  i       index into p->payload where we stopped looking at data
 */
static u_int16_t SMTP_HandleMimeHeaderState(SFSnortPacket *p, u_int16_t i)
{
    char *searchStr;
    int   cmdFound = 0;
    
    if ( !_smtp->data_search )
    {
        /* Nothing to do, so skip packet */
        return p->payload_size;
    }

    /* Search starting at current character */
    searchStr = p->payload + i;

    /* Check for MIME header end */
    cmdFound = _dpd.searchAPI->search_instance_find(_smtp->data_search, searchStr, 
                                    p->payload_size - i, 0, SMTP_DataStrFound);

    /* If found LFLF, or CRLFCRLF, or (LF or CRLF) at the beginning of a line */
    if ( (i == 0 && ((p->payload_size > 0 && searchStr[0] == '\n')
            || (p->payload_size > 1 && searchStr[0] == '\r' && searchStr[1] == '\n')))
            || (cmdFound && _smtp->token_id & DATA_HEADER_END) )
    {
        /* Drop back to normal body search */
        _smtp->state = DATA_BODY;

        return i + _smtp->token_index + _smtp->token_length;
    }

    return p->payload_size;
}

/*
 * Handle COMMAND state
 *
 * @param   packet  standard Packet structure
 *
 * @param   i       index into p->payload buffer to start looking at data
 *
 * @return  i       index into p->payload where we stopped looking at data
 */
static u_int16_t SMTP_HandleTlsDataState(SFSnortPacket *p, u_int16_t i)
{
    if ( _smtp_config.ignore_tls_data )
    {
        DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "In TLS_DATA section; ignore encrypted data\n"););
        /* Make rules ignore TLS encoded data */
        p->payload_size = i;
    }

    return p->payload_size;  /* Skip over all data */
}

  

/*
 * Process client packet
 *
 * @param   packet  standard Packet structure
 *
 * @return  none
 */
static void SMTP_ProcessClientPacket(SFSnortPacket *p)
{
    u_int16_t i = 0;

#ifdef DEBUG
    p->payload[p->payload_size - 1] = '\0';
    DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "In SMTP_ProcessClientPacket(), %d: %s\n", p->payload_size, p->payload););
#endif    
    if ( p->flags & FLAG_REBUILT_STREAM )
    {
        DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "FLAG_REBUILT_STREAM: yes\n"););
    }
    if ( p->flags & FLAG_STREAM_INSERT )
    {
        DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "FLAG_STREAM_INSERT: yes\n"););
    }
    if ( p->flags & FLAG_STREAM_EST )
    {
        DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "FLAG_STREAM_EST: yes\n"););
    }

    _smtp->token_id = 0;
    _smtp->normalizing = 0;

    while ( i < p->payload_size )
    {
        switch ( _smtp->state )
        {
            case COMMAND:
                i = SMTP_HandleCommandState(p, i);
                //if (i < 0)
                //    return;
                break;
            case DATA:
            case DATA_PEND:
                i = SMTP_HandleDataState(p, i);
                break;
            case DATA_BODY:
                i = SMTP_HandleDataBodyState(p, i);
                break;
            case MIME_HEADER:
                i = SMTP_HandleMimeHeaderState(p, i);
                break;
            case TLS_DATA:
                i = SMTP_HandleTlsDataState(p, i);
                break;
            default:
                DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "Unknown SMTP state\n"););
                return;
        }
    }

    return;
}



/*
 * Check to see if this is a TLS handshake
 *
 * @param   p       packet we are examining
 * @param   index   index into buffer where new line starts
 *
 * @retval 1        if TLS server handshake
 * @retval 0        if not TLS server handshake
 */
static int SMTP_IsTLSServerHandshake(SFSnortPacket *p, u_int16_t index)
{
    if ( (index+2) < p->payload_size && *(p->payload + index) == 0x16
        && *(p->payload + index+1) == 0x03 && *(p->payload + index+2) == 0x01 )
    {
        return 1;
    }

    return 0;
}


/*
 * Process server packet
 *
 * @param   packet  standard Packet structure
 *
 * @return  do_flush
 * @retval  1           flush queued packets on client side
 * @retval  0           do not flush queued packets on client side
 */
static int SMTP_ProcessServerPacket(SFSnortPacket *p)
{
    u_int16_t i, count = 0;
    u_int8_t  c;
    int       numFound;
    int       do_flush = 0; 

    if ( _smtp->state == TLS_DATA && _smtp_config.ignore_tls_data )
    {
        /* Ignore data */
        DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "In TLS_DATA section; ignore encrypted data\n"););
        p->payload_size = 0;
        return 0;
    }

    _smtp->token_id = 0;

    /* Loop through packet, counting chars.  Notice if one is LF. */
    for ( i = 0; i < p->payload_size; i++ )
    {
        /* If at beginning of line */
        if ( count == 0 )
        {
            /* Check for response code */
            numFound = _dpd.searchAPI->search_find(RESP_SEARCH, p->payload + i, p->payload_size - i, 1, SMTP_RespStrFound);
            DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "Number of matches found: %d\n", numFound););

            if ( numFound && (_smtp->token_id & RESP_354) )
            {
                DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "354 flag set, dsize = %d\n", p->payload_size););
  
                /* Got client DATA and server 354, now we know we are in data section */
                if ( _smtp->got_data_cmd )
                {
                    _smtp->state = DATA;
                }                        
                 _smtp->got_data_resp = 1;
                 do_flush = 1;
            }

            /* Check for TLS encoding */
            if ( SMTP_IsTLSServerHandshake(p, i) )
            {
                _smtp->got_server_tls = 1;
                if ( _smtp->got_starttls )
                    _smtp->state = TLS_DATA;                    
            }            
        }
        count++;
        c = *(p->payload + i);
        if ( c == '\n' )
        {
            if ( _smtp_config.max_response_line_len != 0 && count > _smtp_config.max_response_line_len )
            {
                SMTP_GenerateAlert(SMTP_EVENT_RESPONSE_OVERFLOW,
                            "%s: %d chars", SMTP_RESPONSE_OVERFLOW_STR, count);
            }
            count = 0;
        }
    }

    return do_flush;
}


/*
 * Entry point to snort preprocessor for each packet
 *
 * @param   packet  standard Packet structure
 *
 * @return  none
 */
void SnortSMTP(SFSnortPacket *p)
{
    int        detected = 0;
    int        do_flush = 0;
    PROFILE_VARS;

    /* Make sure it's traffic we're interested in */
    if ( !IsServer(p->src_port) && !IsServer(p->dst_port) )
        return;

    /* Ignore if no data */
    if (p->payload_size == 0)
        return;
    
    SMTP_Setup(p);

    if(_smtp_config.inspection_type == SMTP_STATELESS)
    {
        SMTP_ResetState(_smtp);
    }

    /* Figure out direction of packet */
    GetPacketDirection(p);

    if ( p->payload[p->payload_size-1] == '\n' )
        _smtp->last_byte_is_lf = 1;

    if ( _smtp->pkt_direction == SMTP_PKT_FROM_SERVER )
    {
        DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, " <SMTP packet from server>\n"););

        /* Process as a server packet */
        do_flush = SMTP_ProcessServerPacket(p);

        if ( do_flush )
        {
            _dpd.streamAPI->response_flush_stream(p);
        }
    }
    else if ( _smtp->pkt_direction == SMTP_PKT_FROM_CLIENT )
    {
        DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, " <SMTP packet from client>\n"););

        if (p->flags & FLAG_STREAM_INSERT)
        {
            /* Packet will be rebuilt, so wait for it */
            DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "Client packet will be reassembled\n"));
            /* Turn off detection until we get the rebuilt packet. */
            SMTP_DisableDetect(p);
            return;
        }
        /* Interesting to see how often packets are rebuilt */
        DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "Client packet: rebuilt %s: %.*s\n",
                (p->flags & FLAG_REBUILT_STREAM) ? "yes" : "no", p->payload_size, p->payload));

        /* Process as a client packet */
        SMTP_ProcessClientPacket(p);
    }
    else
    {
        DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "SMTP packet NOT from client or server!\n"););

        /* Attempt to process as if it is a client packet */
        SMTP_ProcessClientPacket(p);
    }

    PREPROC_PROFILE_START(smtpDetectPerfStats);

    detected = _dpd.detect(p);

#ifdef PERF_PROFILING
    smtpDetectCalled = 1;
#endif

    PREPROC_PROFILE_END(smtpDetectPerfStats);

    /* Turn off detection since we've already done it. */
    SMTP_DisableDetect(p);
     
    if ( detected )
    {
        DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "SMTP vulnerability detected\n"););
    }
}

static void SMTP_DisableDetect(SFSnortPacket *p)
{
    _dpd.disableAllDetect(p);

    _dpd.setPreprocBit(p, PP_SFPORTSCAN);
    _dpd.setPreprocBit(p, PP_PERFMONITOR);
    _dpd.setPreprocBit(p, PP_STREAM4);
}


