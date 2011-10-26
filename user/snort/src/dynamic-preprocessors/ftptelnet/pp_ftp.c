/* $Id$ */
/*
 ** Copyright (C) 2004-2006 Sourcefire, Inc
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

/* pp_ftp.c 
 * 
 * Purpose:  FTP sessions contain commands and responses.  Certain
 *           commands are vectors of attack.  This module checks
 *           those FTP client commands and their parameter values, as
 *           well as the server responses per the configuration.
 *
 * Arguments:  None
 *   
 * Effect:  Alerts may be raised
 *
 * Comments:
 *
 */

/* your preprocessor header file goes here */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#else
#include <windows.h>
#endif

#include "ftpp_eo_log.h"
#include "pp_ftp.h"
#include "pp_telnet.h"
#include "ftpp_return_codes.h"
#include "ftp_cmd_lookup.h"
#include "ftp_bounce_lookup.h"
//#include "decode.h"
#include "debug.h"
#include "stream_api.h"
//#include "plugbase.h"

#ifndef MAXHOSTNAMELEN /* Why doesn't Windows define this? */
#define MAXHOSTNAMELEN 256
#endif

//extern u_int8_t DecodeBuffer[DECODE_BLEN]; /* decode.c */

/*
 * Used to keep track of pipelined commands and the last one
 * that resulted in a 
 */
static int ftp_cmd_pipe_index = 0;

/*
 * Function: getIP(char **ip_start,
 *                 char *last_char,
 *                 char term_char,
 *                 u_int32_t *ipRet,
 *                 u_int16_t *portRet)
 *
 * Purpose: Returns a 32bit IP address and port from an FTP-style
 *          string -- ie, a,b,c,d,p1,p2.  Stops checking when term_char
 *          is seen.  Used to get address and port information from FTP
 *          PORT command and server response to PASV command.
 *
 * Arguments ip_start        => Pointer to pointer to the start of string.
 *                              Updated to end of IP address if successful.
 *           last_char       => End of string
 *           term_char       => Character delimiting the end of the address.
 *           ipRet           => Return pointer to 32bit address on success
 *           portRet         => Return pointer to 16bit port on success
 *
 * Returns: int => return code indicating error or success
 *
 */
int getIP(char **ip_start, char *last_char, char term_char,
          u_int32_t *ipRet, u_int16_t *portRet)
{
    u_int32_t ip=0;
    u_int16_t port=0;
    int octet=0;
    char *this_param = *ip_start;
    do
    {
        int value = 0;
        do
        {
            if (!isdigit(*this_param))
            {
                return FTPP_NON_DIGIT;
            }
            value = value * 10 + (*this_param - '0');
            this_param++;
        } while ((this_param < last_char) &&
                 (*this_param != ',') &&
                 (*this_param != term_char));
        if (value > 0xFF)
        {
            return FTPP_INVALID_ARG;
        }
        if (octet  < 4)
        {
            ip = (ip << 8) + value;
        }
        else
        {
            port = (port << 8) + value;
        }

        if (*this_param != term_char)
            this_param++;
        octet++;
    } while ((this_param < last_char) && (*this_param != term_char) );

    if (octet != 6)
    {
        return FTPP_MALFORMED_IP_PORT;
    }

    *ipRet = ip;
    *portRet = port;
    *ip_start = this_param;

    return FTPP_SUCCESS;
}

/*
 * Function: validate_date_format(
 *                            FTP_DATE_FMT *ThisFmt,
 *                            char **this_param)
 *
 * Purpose: Recursively determines whether a date matches the
 *          a valid format.
 *
 * Arguments: ThisFmt        => Pointer to the current format
 *            this_param     => Pointer to start of the portion to validate.
 *                              Updated to end of valid section if valid.
 *
 * Returns: int => return code indicating error or success
 *
 */
int validate_date_format(FTP_DATE_FMT *ThisFmt, char **this_param)
{
    int valid_string = 0;
    int checked_something_else = 0;
    int checked_next = 0;
    int iRet = FTPP_ALERT;
    char *curr_ch;
    if (!ThisFmt)
        return FTPP_INVALID_ARG;

    if (!this_param || !(*this_param))
        return FTPP_INVALID_ARG;

    curr_ch = *this_param;
    if (!ThisFmt->empty)
    {
        char *format_char = ThisFmt->format_string;

        do
        {
            switch (*format_char)
            {
            case 'n':
                if (!isdigit(*curr_ch))
                {
                    /* Return for non-digit */
                    return FTPP_INVALID_DATE;
                }
                curr_ch++;
                format_char++;
                break;
            case 'C':
                if (!isalpha(*curr_ch))
                {
                    /* Return for non-char */
                    return FTPP_INVALID_DATE;
                }
                curr_ch++;
                format_char++;
                break;
            default:
                if (*curr_ch != *format_char)
                {
                    /* Return for non-matching char */
                    return FTPP_INVALID_DATE;
                }
                curr_ch++;
                format_char++;
                break;
            }
            valid_string = 1;
        }
        while ((*format_char != '\0') && !isspace(*curr_ch) );

        if ((*format_char != '\0') && isspace(*curr_ch))
        {
            /* Didn't have enough chars to complete this format */
            return FTPP_INVALID_DATE;
        }
    }

    if ((ThisFmt->optional) && !isspace(*curr_ch) )
    {
        char *tmp_ch = curr_ch;
        iRet = validate_date_format(ThisFmt->optional, &tmp_ch);
        if (iRet == FTPP_SUCCESS)
            curr_ch = tmp_ch;
    }
    if ((ThisFmt->next_a) && !isspace(*curr_ch) )
    {
        char *tmp_ch = curr_ch;
        checked_something_else = 1;
        iRet = validate_date_format(ThisFmt->next_a, &tmp_ch);
        if (iRet == FTPP_SUCCESS)
        {
            curr_ch = tmp_ch;
        }
        else if (ThisFmt->next_b)
        {
            iRet = validate_date_format(ThisFmt->next_b, &tmp_ch);
            if (iRet == FTPP_SUCCESS)
                curr_ch = tmp_ch;
        }
        if (ThisFmt->next)
        {
            iRet = validate_date_format(ThisFmt->next, &tmp_ch);
            if (iRet == FTPP_SUCCESS)
            {
                curr_ch = tmp_ch;
                checked_next = 1;
            }
        }
        if (iRet == FTPP_SUCCESS)
        {
            *this_param = curr_ch;
            return iRet;
        }
    }
    if ((!checked_next) && (ThisFmt->next))
    {
        char *tmp_ch = curr_ch;
        checked_something_else = 1;
        iRet = validate_date_format(ThisFmt->next, &tmp_ch);
        if (iRet == FTPP_SUCCESS)
        {
            curr_ch = tmp_ch;
            checked_next = 1;
        }
    }

    if ((isspace(*curr_ch)) && ((!ThisFmt->next) || checked_next))
    {
        *this_param = curr_ch;
        return FTPP_SUCCESS;
    }

    if (valid_string)
    {
        int all_okay = 0;
        if (checked_something_else)
        {
            if (iRet == FTPP_SUCCESS)
                all_okay = 1;
        }
        else
        {
            all_okay = 1;
        }

        if (all_okay)
        {
            *this_param = curr_ch;
            return FTPP_SUCCESS;
        }
    }

    return FTPP_INVALID_DATE;
}

/*
 * Function: validate_param(
 *                            Packet *p
 *                            char *param
 *                            char *end
 *                            FTP_PARAM_FMT *param_format,
 *                            FTP_SESSION *Session)
 *
 * Purpose: Validates the current parameter against the format
 *          specified.
 *
 * Arguments: p              => Pointer to the current packet
 *            params_begin   => Pointer to beginning of parameters
 *            params_end     => End of params buffer
 *            param_format   => Parameter format specifier for this command
 *            Session        => Pointer to the session info
 *
 * Returns: int => return code indicating error or success
 *
 */
int validate_param(SFSnortPacket *p,
                char *param,
                char *end,
                FTP_PARAM_FMT *ThisFmt,
                FTP_SESSION *Session)
{
    int iRet;
    char *this_param = param;

    if (param > end)
        return FTPP_ALERT;

    switch (ThisFmt->type)
    {
    case e_head:
        /* shouldn't get here, but just in case */
        break;
    case e_unrestricted:
        /* strings/filenames only occur as the last param,
         * so move to the end of the param buffer. */
        {
            do
            {
                this_param++;
            }
            while (this_param < end);
        }
        break;
    case e_strformat:
        /* Check for 2 % signs within the parameter for an FTP command
         * 2 % signs is the magic number per existing rules (24 Sep 2004)
         */
#define MAX_PERCENT_SIGNS 2
        {
            int numPercents = 0;
            do
            {
                if (*this_param == '%')
                {
                    numPercents++;
                    if (numPercents >= MAX_PERCENT_SIGNS)
                    {
                        break;
                    }
                }
                this_param++;
            }
            while ((this_param < end) &&
                   (*this_param != ' '));

            if (numPercents >= MAX_PERCENT_SIGNS)
            {
                /* Alert on string format attack in parameter */
                ftp_eo_event_log(Session, FTP_EO_PARAMETER_STR_FORMAT,
                    NULL, NULL);
                return FTPP_ALERTED;
            }
        }
        break;
    case e_int:
        /* check that this_param is all digits up to next space */
        {
            do
            {
                if (!isdigit(*this_param))
                {
                    /* Alert on non-digit */
                    return FTPP_INVALID_PARAM;
                }
                this_param++;
            }
            while ((this_param < end) && (*this_param != ' ') );
        }
        break;
    case e_number:
        /* check that this_param is all digits up to next space
         * and value is between 1 & 255 */
        {
            int iValue = 0;
            do
            {
                if (!isdigit(*this_param))
                {
                    /* Alert on non-digit */
                    return FTPP_INVALID_PARAM;
                }
                iValue = iValue * 10 + (*this_param - '0');
                this_param++;
            }
            while ((this_param < end) && (*this_param != ' ') );

            if ((iValue > 255) || (iValue == 0))
                return FTPP_INVALID_PARAM;
        }
        break;
    case e_char:
        /* check that this_param is one of chars specified */
        {
            int bitNum = (*this_param & 0x1f);
            if (!isalpha(*this_param))
            {
                /* Alert on non-char */
                return FTPP_INVALID_PARAM;
            }
            else
            {
                if (!(ThisFmt->format.chars_allowed & (1 << (bitNum-1))) )
                {
                    /* Alert on unexpected char */
                    return FTPP_INVALID_PARAM;
                }
            }
            this_param++; /* should be a space */
        }
        break;
    case e_date:
        /* check that this_param conforms to date specified */
        {
            char *tmp_ch = this_param;
            iRet = validate_date_format(ThisFmt->format.date_fmt, &tmp_ch);
            if (iRet != FTPP_SUCCESS)
            {
                /* Alert invalid date */
                return FTPP_INVALID_PARAM;
            }
            if (!isspace(*tmp_ch))
            {
                /* Alert invalid date -- didn't make it to end of parameter.
                Overflow attempt? */
                return FTPP_INVALID_PARAM;
            }
            this_param = tmp_ch;
        }
        break;
    case e_host_port:
        /* check that this_param is #,#,#,#,#,# */
        {
            u_int32_t ip;
            u_int16_t port=0;
            int iRet;
            iRet = getIP(&this_param, end, ' ', &ip, &port);
            switch (iRet)
            {
            case FTPP_NON_DIGIT:
                /* Alert on non-digit */
                return FTPP_INVALID_PARAM;
                break;
            case FTPP_INVALID_ARG:
                /* Alert on number > 255 */
                return FTPP_INVALID_PARAM;
                break;
            case FTPP_MALFORMED_IP_PORT:
                /* Alert on malformed host-port */
                return FTPP_INVALID_PARAM;
                break;
            }

            if ((Session->client_conf->bounce.on) &&
                (Session->client_conf->bounce.alert))
            {
                if (ip != ntohl(p->ip4_header->source.s_addr))
                {
                    int alert = 1;
                    char *ipPtr = (char *)&ip;
                    FTP_BOUNCE_TO *BounceTo = ftp_bounce_lookup_find(
                        Session->client_conf->bounce_lookup, ipPtr, 4, &iRet);
                    if (BounceTo)
                    {
                        if (BounceTo->portlo)
                        {
                            if (BounceTo->porthi)
                            {
                                if ((port >= BounceTo->portlo) &&
                                    (port <= BounceTo->porthi))
                                    alert = 0;
                            }
                            else
                            {
                                if (port == BounceTo->portlo)
                                    alert = 0;
                            }
                        }
                    }
                    
                    /* Alert on invalid IP address for PORT */
                    if (alert)
                    {
                        ftp_eo_event_log(Session, FTP_EO_BOUNCE, NULL, NULL);
                        /* Return here -- because we will likely want to
                         * inspect the data traffic over a bounced data
                         * connection */
                        return FTPP_PORT_ATTACK;
                    }
                }
            }

            Session->clientIP = htonl(ip);
            Session->clientPort = port;
            Session->data_chan_state |= DATA_CHAN_PORT_CMD_ISSUED;
            if (Session->data_chan_state & DATA_CHAN_PASV_CMD_ISSUED)
            {
                /*
                 * If there was a PORT command previously in
                 * a series of pipelined requests, this
                 * cancels it.
                 */
                Session->data_chan_state &= ~DATA_CHAN_PASV_CMD_ISSUED;
            }

            Session->serverIP = 0;
            Session->serverPort = 0;
        }
        break;
    }

    ThisFmt->next_param = this_param;

    return FTPP_SUCCESS;
}

/*
 * Function: check_ftp_param_validity(
 *                            Packet *p,
 *                            char *params_begin,
 *                            char *params_end,
 *                            FTP_PARAM_FMT *param_format,
 *                            FTP_SESSION *Session)
 *
 * Purpose: Recursively determines whether each of the parameters for
 *          an FTP command are valid.
 *
 * Arguments: p              => Pointer to the current packet
 *            params_begin   => Pointer to beginning of parameters
 *            params_end     => End of params buffer
 *            param_format   => Parameter format specifier for this command
 *            Session        => Pointer to the session info
 *
 * Returns: int => return code indicating error or success
 *
 */
int check_ftp_param_validity(SFSnortPacket *p,
                             char *params_begin,
                             char *params_end,
                             FTP_PARAM_FMT *param_format,
                             FTP_SESSION *Session)
{
    int iRet = FTPP_ALERT;
    FTP_PARAM_FMT *ThisFmt = param_format;
    FTP_PARAM_FMT *NextFmt;
    char *this_param = params_begin;

    if (!param_format)
        return FTPP_INVALID_ARG;

    if (!params_begin)
        return FTPP_INVALID_ARG;

    if ((!ThisFmt->next_param_fmt) && (params_begin >= params_end))
        return FTPP_SUCCESS;

    ThisFmt->next_param = params_begin;

    if (ThisFmt->optional_fmt)
    {
        /* Check against optional */
        iRet = validate_param(p, this_param, params_end,
                              ThisFmt->optional_fmt, Session);
        if (iRet == FTPP_SUCCESS)
        {
            char *next_param;
            NextFmt = ThisFmt->optional_fmt;
            next_param = NextFmt->next_param+1;
            iRet = check_ftp_param_validity(p, next_param, params_end,
                                            NextFmt, Session);
            if (iRet == FTPP_SUCCESS)
            {
                this_param = NextFmt->next_param+1;
            }
        }
    }

    if ((iRet != FTPP_SUCCESS) && (ThisFmt->choices))
    {
        /* Check against choices -- one of many */
        int i;
        int valid = 0;
        for (i=0;i<ThisFmt->numChoices && !valid;i++)
        {
            /* Try choice [i] */
            iRet = validate_param(p, this_param, params_end,
                              ThisFmt->choices[i], Session);
            if (iRet == FTPP_SUCCESS)
            {
                char *next_param;
                NextFmt = ThisFmt->choices[i];
                next_param = NextFmt->next_param+1;
                iRet = check_ftp_param_validity(p, next_param, params_end,
                                                NextFmt, Session);
                if (iRet == FTPP_SUCCESS)
                {
                    this_param = NextFmt->next_param+1;
                    valid = 1;
                    break;
                }
            }
        }
    }
    else if ((iRet != FTPP_SUCCESS) && (ThisFmt->next_param_fmt))
    {
        /* Check against next param */
        iRet = validate_param(p, this_param, params_end,
                          ThisFmt->next_param_fmt, Session);
        if (iRet == FTPP_SUCCESS)
        {
            char *next_param;
            NextFmt = ThisFmt->next_param_fmt;
            next_param = NextFmt->next_param+1;
            iRet = check_ftp_param_validity(p, next_param, params_end,
                                            NextFmt, Session);
            if (iRet == FTPP_SUCCESS)
            {
                this_param = NextFmt->next_param+1;
            }
        }
    }

    if (iRet == FTPP_SUCCESS)
    {
        ThisFmt->next_param = this_param;
    }
    return iRet;
}

/*
 * Function: initialize_ftp(FTP_SESSION *Session, Packet *p, int iMode)
 *
 * Purpose: Initializes the state machine for checking an FTP packet.
 *          Does normalization checks.
 * 
 * Arguments: Session        => Pointer to session info
 *            p              => pointer to the current packet struct
 *            iMode          => Mode indicating server or client checks
 *
 * Returns: int => return code indicating error or success
 *
 */
int initialize_ftp(FTP_SESSION *Session, SFSnortPacket *p, int iMode)
{
    int iRet;
    unsigned char *read_ptr = p->payload;
    FTP_CLIENT_REQ *req;

    /* Normalize this packet ala telnet */
    iRet = normalize_telnet(Session->global_conf, NULL, p, iMode);
    if (iRet != FTPP_SUCCESS && iRet != FTPP_NORMALIZED)
    {
        if (iRet == FTPP_ALERT)
        {
            if (Session->global_conf->global_telnet.detect_anomalies)
            {
                ftp_eo_event_log(Session, FTP_EO_EVASIVE_TELNET_CMD, NULL, NULL);
        }   }
        return iRet;
    }
    
    if (p->flags & FLAG_ALT_DECODE)
    {
        /* Normalized data will always be in decode buffer */
        if ( ((Session->client_conf->telnet_cmds.alert) &&
              (iMode == FTPP_SI_CLIENT_MODE)) ||
             ((Session->server_conf->telnet_cmds.alert) &&
              (iMode == FTPP_SI_SERVER_MODE)) )
        {
            /* alert -- FTP channel with telnet commands */
            ftp_eo_event_log(Session, FTP_EO_TELNET_CMD, NULL, NULL);
            return FTPP_ALERT; /* Nothing else to do since we alerted */
        }

        read_ptr = _dpd.altBuffer;
    }

    if (iMode == FTPP_SI_CLIENT_MODE)
        req = &Session->client.request;
    else if (iMode == FTPP_SI_SERVER_MODE)
        req = (FTP_CLIENT_REQ *)&Session->server.response;
    else
        return FTPP_INVALID_ARG;

    /* Set the beginning of the pipeline to the start of the
     * (normalized) buffer */
    req->pipeline_req = read_ptr;

    return FTPP_SUCCESS;
}

/*
 * Function: do_stateful_checks(FTP_SESSION *Session, Packet *p,
 *                            FTP_CLIENT_REQ *req, int rsp_code)
 *
 * Purpose: Handle stateful checks and state updates for FTP response
 *          packets.
 *
 * Arguments: Session        => Pointer to session info
 *            p              => Pointer to the current packet struct
 *            req            => Pointer to current response from packet
 *                              (this function may be called multiple
 *                              times for pipelined requests).
 *            rsp_code       => Integer response value for server response
 *
 * Returns: int => return code indicating error or success
 *
 */
int do_stateful_checks(FTP_SESSION *Session, SFSnortPacket *p,
                       FTP_CLIENT_REQ *req, int rsp_code)
{
    int iRet = FTPP_SUCCESS;
    if (Session->server_conf->data_chan)
    {
        if (rsp_code == 226)
        {
            /* Just ignore this code -- end of transfer...
             * If we saw all the other dat for this channel
             * Session->data_chan_state should be NO_STATE. */
        }
        else if (Session->data_chan_state & DATA_CHAN_PASV_CMD_ISSUED)
        {
            if (ftp_cmd_pipe_index == Session->data_chan_index)
            {
                if (Session->data_xfer_index == -1)
                    ftp_cmd_pipe_index = 0;
                Session->data_chan_index = -1;
                if (rsp_code == 227)
                {
                    u_int32_t ip=0;
                    u_int16_t port=0;
                    char *ip_begin = req->param_begin;
                    Session->data_chan_state &= ~DATA_CHAN_PASV_CMD_ISSUED;
                    Session->data_chan_state |= DATA_CHAN_PASV_CMD_ACCEPT;
                    Session->data_chan_index = -1;
                    /* Interpret response message to identify the
                     * Server IP/Port.  Server response is inside
                     * a pair of ()s.  Find the left (, and use same
                     * means to find IP/Port as is done for the PORT
                     * command. */
                    while ((*ip_begin != '(') &&
                           (ip_begin < req->param_end))
                    {
                        ip_begin++;
                    }

                    if (ip_begin < req->param_end)
                    {
                        ip_begin++;
                        iRet = getIP(&ip_begin, req->param_end, ')',
                                     &ip, &port);
                        if (iRet == FTPP_SUCCESS)
                        {
                            Session->serverIP = htonl(ip);
                            Session->serverPort = port;
                            Session->clientIP = 0;
                            Session->clientPort = 0;
                        }
                    }
                    else
                    {
                        iRet = FTPP_MALFORMED_FTP_RESPONSE;
                    }
                }
                else
                {
                    Session->data_chan_index = -1;
                    Session->data_chan_state &= ~DATA_CHAN_PASV_CMD_ISSUED;
                }
            }
        }
        else if (Session->data_chan_state & DATA_CHAN_PORT_CMD_ISSUED)
        {
            if (ftp_cmd_pipe_index == Session->data_chan_index)
            {
                if (Session->data_xfer_index == -1)
                    ftp_cmd_pipe_index = 0;
                Session->data_chan_index = -1;
                if (rsp_code == 200)
                {
                    Session->data_chan_state &= ~DATA_CHAN_PORT_CMD_ISSUED;
                    Session->data_chan_state |= DATA_CHAN_PORT_CMD_ACCEPT;
                    Session->data_chan_index = -1;
                }
                else if (ftp_cmd_pipe_index == Session->data_chan_index)
                {
                    Session->data_chan_index = -1;
                    Session->data_chan_state &= ~DATA_CHAN_PORT_CMD_ISSUED;
                }
            }
        }
        else if (Session->data_chan_state & DATA_CHAN_XFER_CMD_ISSUED)
        {
            if (ftp_cmd_pipe_index == Session->data_xfer_index)
            {
                if (Session->data_chan_index == -1)
                    ftp_cmd_pipe_index = 0;
                Session->data_xfer_index = -1;
                if ((rsp_code == 150) || (rsp_code == 125))
                {
                    struct in_addr client, server;
                    Session->data_chan_state &= ~DATA_CHAN_XFER_CMD_ISSUED;
                    Session->data_chan_state = DATA_CHAN_XFER_STARTED;
                    if (Session->serverIP == 0)
                    {
                        /* This means we're not in passive mode. */
                        /* Server is listening/sending from its own IP,
                         * FTP Port -1 */ 
                        /* Client IP, Port specified via PORT command */
                        Session->serverIP = p->ip4_header->source.s_addr;
                    
                        /* Can't necessarily guarantee this, especially
                         * in the case of a proxy'd connection where the
                         * data channel might not be on port 20 (or server
                         * port-1).  Comment it out for now.
                         */
                        /*
                        Session->serverPort = ntohs(p->tcph->th_sport) -1;
                        */
                    }
                    if (Session->clientIP == 0)
                    {
                        /* This means we're in passive mode. */
                        /* Server info is known. */
                        /* Client IP is known from response packet, but
                         * port is unknown */
                        Session->clientIP = p->ip4_header->destination.s_addr;
                    }
                    client.s_addr = Session->clientIP;
                    server.s_addr = Session->serverIP;

                    if (Session->server_conf->data_chan)
                    {
                        /* Call into Streams to mark data channel as something
                         * to ignore. */
                        _dpd.streamAPI->ignore_session(Session->clientIP,
                                Session->clientPort, Session->serverIP,
                                Session->serverPort,
                                p->ip4_header->proto, SSN_DIR_BOTH,
                                0 /* Not permanent */ );
                    }
                }
                /* Clear the session info for next transfer -->
                 * reset host/port */
                Session->serverIP = Session->clientIP = 0;
                Session->serverPort = Session->clientPort = 0;

                Session->data_chan_state = NO_STATE;
            }
        }
    } /* if (Session->server_conf->data_chan) */

    if (Session->global_conf->encrypted.on)
    {
        switch(Session->encr_state)
        {
        case AUTH_TLS_CMD_ISSUED:
            if (rsp_code == 234)
            {
                /* Could check that response msg includes "TLS" */
                Session->encr_state = AUTH_TLS_ENCRYPTED;
                if (Session->global_conf->encrypted.alert)
                {
                    /* Alert on encrypted channel */
                    ftp_eo_event_log(Session, FTP_EO_ENCRYPTED,
                        NULL, NULL);
                }
                DEBUG_WRAP(_dpd.debugMsg(DEBUG_FTPTELNET, 
                    "FTP stream is now TLS encrypted\n"););
            }
            break;
        case AUTH_SSL_CMD_ISSUED:
            if (rsp_code == 234)
            {
                /* Could check that response msg includes "SSL" */
                Session->encr_state = AUTH_SSL_ENCRYPTED;
                if (Session->global_conf->encrypted.alert)
                {
                    /* Alert on encrypted channel */
                    ftp_eo_event_log(Session, FTP_EO_ENCRYPTED,
                        NULL, NULL);
                }
                DEBUG_WRAP(_dpd.debugMsg(DEBUG_FTPTELNET, 
                    "FTP stream is now SSL encrypted\n"););
            }
            break;
        case AUTH_UNKNOWN_CMD_ISSUED:
            if (rsp_code == 234)
            {
                Session->encr_state = AUTH_UNKNOWN_ENCRYPTED;
                if (Session->global_conf->encrypted.alert)
                {
                    /* Alert on encrypted channel */
                    ftp_eo_event_log(Session, FTP_EO_ENCRYPTED,
                        NULL, NULL);
                }
                DEBUG_WRAP(_dpd.debugMsg(DEBUG_FTPTELNET,
                    "FTP stream is now encrypted\n"););
            }
            break;
        }
    } /* if (Session->global_conf->encrypted.on) */

    return iRet;
}

/*
 * Function: check_ftp(FTP_SESSION *Session, Packet *p, int iMode)
 *
 * Purpose: Handle some trivial validation checks of an FTP packet.  Namely,
 *          check argument length and some protocol enforcement.  
 * 
 *          Wishful: This results in exposing the FTP command (and looking
 *          at the results) to the rules layer.
 *
 * Arguments: Session        => Pointer to session info
 *            p              => pointer to the current packet struct
 *            iMode          => Mode indicating server or client checks
 *
 * Returns: int => return code indicating error or success
 *
 */
#define NUL 0x00
#define CR 0x0d
#define LF 0x0a
#define SP 0x20
#define DASH 0x2D

#define FTP_CMD_OK 0
#define FTP_CMD_INV 1
#define FTP_RESPONSE_INV 1
#define FTP_RESPONSE 2
#define FTP_RESPONSE_2BCONT 2
#define FTP_RESPONSE_CONT   3
#define FTP_RESPONSE_CONT   3
#define FTP_RESPONSE_ENDCONT 4
int check_ftp(FTP_SESSION  *ftpssn, SFSnortPacket *p, int iMode)
{
    int iRet = FTPP_SUCCESS;
    int encrypted = 0;
    int space = 0;
    long state = FTP_CMD_OK;
    int rsp_code = 0;

    FTP_CLIENT_REQ *req;
    FTP_CMD_CONF *CmdConf = NULL;

    unsigned char *read_ptr;
    unsigned char *end = p->payload + p->payload_size;
    if (p->flags & FLAG_ALT_DECODE)
        end = _dpd.altBuffer + p->normalized_payload_size;

    if (iMode == FTPP_SI_CLIENT_MODE)
    {
        req = &ftpssn->client.request;
        ftp_cmd_pipe_index = 0;
    }
    else if (iMode == FTPP_SI_SERVER_MODE)
        req = (FTP_CLIENT_REQ *)&ftpssn->server.response;
    else
        return FTPP_INVALID_ARG;

    while (req->pipeline_req)
    {
        state = FTP_CMD_OK;

        read_ptr = req->pipeline_req;
    
        /* Starts at the beginning of the buffer/line,
         * so next up is a command */
        req->cmd_begin = read_ptr;
        while ((*read_ptr != SP) &&
               (*read_ptr != CR) &&
               (*read_ptr != LF) && /* Check for LF when there wasn't a CR,
                                     * protocol violation, but accepted by
                                     * some servers. */
               (*read_ptr != DASH) &&
               (read_ptr < end))
        {
            /* If the first char is a digit this is a response
             * in server mode. */
            if (isdigit(*read_ptr) && (iMode == FTPP_SI_SERVER_MODE))
            {
                state = FTP_RESPONSE;
            }
            /* Or, if this is not a char, this is garbage in client mode */
            else if (!isalpha(*read_ptr) && (iMode == FTPP_SI_CLIENT_MODE))
            {
                state = FTP_CMD_INV;
            }

            read_ptr++;
        }
        req->cmd_end = read_ptr;
        req->cmd_size = req->cmd_end - req->cmd_begin;

        if (iMode == FTPP_SI_CLIENT_MODE)
        {
            if ( ((req->cmd_size != 4) && (req->cmd_size != 3)) ||
                 (state == FTP_CMD_INV) )
            {
                /* Uh, something is very wrong...
                 * nonalpha char seen or cmd is not 3 or 4 chars.
                 * See if this might be encrypted, ie, non-alpha bytes. */
                char *ptr = req->cmd_begin;
                while (ptr < req->cmd_end)
                {
                    if (!isalpha(*ptr))
                    {
                        encrypted = 1;
                        break;
                    }
                    ptr++;
                }
            }

            if (encrypted)
            {
                /* If the session wasn't already marked as encrypted...
                 * Don't want to double-alert if we've already
                 * determined the session is encrypted and we're
                 * checking encrypted sessions.
                 */
                if (ftpssn->encr_state == 0)
                {
                    ftpssn->encr_state = AUTH_UNKNOWN_ENCRYPTED;
                    if (ftpssn->global_conf->encrypted.alert)
                    {
                        /* Alert on encrypted channel */
                        ftp_eo_event_log(ftpssn, FTP_EO_ENCRYPTED,
                            NULL, NULL);
                    }
                    if (!ftpssn->global_conf->check_encrypted_data)
                    {
                        /* Mark this session & packet as one to ignore */
                        _dpd.streamAPI->stop_inspection(p->stream_session_ptr, p,
                                                SSN_DIR_BOTH, -1, 0);
                    }
                    DEBUG_WRAP(_dpd.debugMsg(DEBUG_FTPTELNET,
                        "FTP client stream is now encrypted\n"););
                }
                break;
            }
            else
            {
                /* 
                 * Check the list of valid FTP commands as
                 * supplied in ftpssn.
                 */
                if (req->cmd_size > 4)
                {
                    /* Alert, cmd not found */
                    ftp_eo_event_log(ftpssn, FTP_EO_INVALID_CMD, NULL, NULL);
                    state = FTP_CMD_INV;
                }
                else
                {
                    CmdConf = ftp_cmd_lookup_find(ftpssn->server_conf->cmd_lookup,
                                              req->cmd_begin,
                                              req->cmd_size,
                                              &iRet);
                    if ((iRet == FTPP_NOT_FOUND) || (CmdConf == NULL))
                    {
                        /* Alert, cmd not found */
                        ftp_eo_event_log(ftpssn, FTP_EO_INVALID_CMD, NULL, NULL);
                        state = FTP_CMD_INV;
                    }
                    else
                    {
                        /* In case we were encrypted, but aren't now */
                        ftpssn->encr_state = 0;
                    }
                }
            }
        }
        else if (iMode == FTPP_SI_SERVER_MODE)
        {
            if ( (req->cmd_size != 3) || (state == FTP_RESPONSE_INV) )
            {
                /* Uh, something is very wrong...
                 * nondigit char seen or resp code is not 3 chars.
                 * See if this might be encrypted, ie, non-alpha bytes. */
                char *ptr = req->cmd_begin;
                while (ptr < req->cmd_end)
                {
                    if (!isdigit(*ptr))
                    {
                        encrypted = 1;
                        break;
                    }
                    ptr++;
                }
            }

            if (encrypted)
            {
                /* If the session wasn't already marked as encrypted...
                 * Don't want to double-alert if we've already
                 * determined the session is encrypted and we're
                 * checking encrypted sessions.
                 */
                if (ftpssn->encr_state == 0)
                {
                    ftpssn->encr_state = AUTH_UNKNOWN_ENCRYPTED;
                    if (ftpssn->global_conf->encrypted.alert)
                    {
                        /* Alert on encrypted channel */
                        ftp_eo_event_log(ftpssn, FTP_EO_ENCRYPTED,
                            NULL, NULL);
                    }
                    if (!ftpssn->global_conf->check_encrypted_data)
                    {
                        /* Mark this session & packet as one to ignore */
                        _dpd.streamAPI->stop_inspection(p->stream_session_ptr, p,
                                                SSN_DIR_BOTH, -1, 0);
                    }
                    DEBUG_WRAP(_dpd.debugMsg(DEBUG_FTPTELNET,
                        "FTP server stream is now encrypted\n"););
                }
                break;
            }
            else
            {
                /* In case we were encrypted, but aren't now */
                ftpssn->encr_state = 0;
            }

            if (*read_ptr != DASH)
            {
                unsigned char *resp_begin = req->cmd_begin;
                unsigned char *resp_end = req->cmd_end;
                if (resp_end - resp_begin >= 3)
                {
                    if (isdigit(*(resp_begin)) &&
                        isdigit(*(resp_begin+1)) &&
                        isdigit(*(resp_begin+2)) )
                    {
                        rsp_code = ( (*(resp_begin) - '0') * 100 + 
                                     (*(resp_begin+1) - '0') * 10 + 
                                     (*(resp_begin+2) - '0') );
                        if (rsp_code == ftpssn->server.response.state)
                        {
                            /* End of continued response */
                            state = FTP_RESPONSE_ENDCONT;
                            ftpssn->server.response.state = 0;
                        }
                        else
                        {
                            /* Single line response */
                            state = FTP_RESPONSE;
                        }
                    }
                }

                if (ftpssn->server.response.state != 0)
                {
                    req->cmd_begin = NULL;
                    req->cmd_end = NULL;
                    if (*read_ptr != SP)
                        read_ptr--;
                    state = FTP_RESPONSE_CONT;
                }
            }
            else if ((state == FTP_RESPONSE) && (*read_ptr == DASH))
            {
                unsigned char *resp_begin = req->cmd_begin;
                if (isdigit(*(resp_begin)) &&
                    isdigit(*(resp_begin+1)) &&
                    isdigit(*(resp_begin+2)) )
                {
                    int resp_code = ( (*(resp_begin) - '0') * 100 + 
                                      (*(resp_begin+1) - '0') * 10 + 
                                      (*(resp_begin+2) - '0') );
                    if (resp_code == ftpssn->server.response.state)
                    {
                        /* Continuation of previous response */
                        state = FTP_RESPONSE_CONT;
                    }
                    else
                    {
                        /* Start of response, state stays as -2 */
                        state = FTP_RESPONSE_2BCONT;
                        ftpssn->server.response.state = resp_code;
                        rsp_code = resp_code;
                    }
                }
                else
                {
                    DEBUG_WRAP(_dpd.debugMsg(DEBUG_FTPTELNET,
                        "invalid FTP response code."););
                    ftpssn->server.response.state = FTP_RESPONSE_INV;
                }
            }
        }


        if (*read_ptr == SP)
        {
            space = 1;
        }

        read_ptr++; /* Move past the space, dash, or CR */

        /* If there is anything left... */
        
        if (read_ptr < end)
        {
            /* Look for an LF --> implies no parameters/message */
            if (*read_ptr == LF)
            {
                read_ptr++;
                req->param_begin = NULL;
                req->param_end = NULL;
            }
            else if (!space && ftpssn->server.response.state == 0)
            {
                DEBUG_WRAP(_dpd.debugMsg(DEBUG_FTPTELNET,
                    "Missing LF from end of FTP command\n"););
            }
            else
            {    
                /* Now grab the command parameters/response message */
                if (read_ptr < end)
                {
                    req->param_begin = read_ptr;
                    while ((*read_ptr != CR) && (read_ptr < end))
                    {
                        read_ptr++;
                    }
                    req->param_end = read_ptr;
                    read_ptr++;
                }

                if (read_ptr < end)
                {
                    /* Cool, got the end of the parameters, move past
                     * the LF, so we can process the next one in
                     * the pipeline.
                     */
                    if (*read_ptr == LF)
                    {
                       read_ptr++;
                    }
                    else
                    {
                        DEBUG_WRAP(_dpd.debugMsg(DEBUG_FTPTELNET,
                            "Missing LF from end of FTP command with params\n"););
                    }
                }
            }
        }
        else
        {
            /* Nothing left --> no parameters/message.  Not even an LF */
            req->param_begin = NULL;
            req->param_end = NULL;
            DEBUG_WRAP(_dpd.debugMsg(DEBUG_FTPTELNET,
                "Missing LF from end of FTP command sans params\n"););
        }
    
        /* Set the pointer for the next request/response
         * in the pipeline. */
        if (read_ptr < end)
            req->pipeline_req = read_ptr;
        else
            req->pipeline_req = NULL;

        req->param_size = req->param_end - req->param_begin;
        switch (state)
        {
        case FTP_CMD_INV:
            DEBUG_WRAP(_dpd.debugMsg(DEBUG_FTPTELNET,
                "Illegal FTP command found: %.*s\n",
                req->cmd_size, req->cmd_begin));
            iRet = FTPP_ALERT;
            break;
        case FTP_RESPONSE: /* Response */
            DEBUG_WRAP(_dpd.debugMsg(DEBUG_FTPTELNET,
                "FTP response: code: %.*s : M len %d : M %.*s\n",
                req->cmd_size, req->cmd_begin, req->param_size,
                req->param_size, req->param_begin));
            if ((ftpssn->client_conf->max_resp_len > 0) && 
                (req->param_size > ftpssn->client_conf->max_resp_len))
            {
                /* Alert on response message overflow */
                ftp_eo_event_log(ftpssn, FTP_EO_RESPONSE_LENGTH_OVERFLOW,
                    NULL, NULL);
                iRet = FTPP_ALERT;
            }

            if (ftpssn->global_conf->inspection_type ==
                FTPP_UI_CONFIG_STATEFUL)
            {
                int newRet = do_stateful_checks(ftpssn, p, req, rsp_code);
                if (newRet != FTPP_SUCCESS)
                    iRet = newRet;
            }
            break;
        case FTP_RESPONSE_CONT: /* Response continued */
            DEBUG_WRAP(_dpd.debugMsg(DEBUG_FTPTELNET,
                "FTP response: continuation of code: %d : M len %d : M %.*s\n",
                ftpssn->server.response.state, req->param_size,
                req->param_size, req->param_begin));
            if ((ftpssn->client_conf->max_resp_len > 0) && 
                (req->param_size > ftpssn->client_conf->max_resp_len))
            {
                /* Alert on response message overflow */
                ftp_eo_event_log(ftpssn, FTP_EO_RESPONSE_LENGTH_OVERFLOW,
                    NULL, NULL);
                iRet = FTPP_ALERT;
            }
            break;
        case FTP_RESPONSE_ENDCONT: /* Continued response end */
            DEBUG_WRAP(_dpd.debugMsg(DEBUG_FTPTELNET,
                "FTP response: final continue of code: %.*s : M len %d : "
                "M %.*s\n", req->cmd_size, req->cmd_begin,
                req->param_size, req->param_size, req->param_begin));
            if ((ftpssn->client_conf->max_resp_len > 0) && 
                (req->param_size > ftpssn->client_conf->max_resp_len))
            {
                /* Alert on response message overflow */
                ftp_eo_event_log(ftpssn, FTP_EO_RESPONSE_LENGTH_OVERFLOW,
                    NULL, NULL);
                iRet = FTPP_ALERT;
            }
            break;
        default:
            DEBUG_WRAP(_dpd.debugMsg(DEBUG_FTPTELNET, "FTP command: CMD: %.*s : "
                "P len %d : P %.*s\n", req->cmd_size, req->cmd_begin,
                req->param_size, req->param_size, req->param_begin));
            if (CmdConf)
            {
                if ((CmdConf->max_param_len >= 0) &&
                    (req->param_size > CmdConf->max_param_len))
                {
                    /* Alert on param length overrun */
                    ftp_eo_event_log(ftpssn, FTP_EO_PARAMETER_LENGTH_OVERFLOW,
                        NULL, NULL);
                    DEBUG_WRAP(_dpd.debugMsg(DEBUG_FTPTELNET, "FTP command: %.*s"
                        "parameter length overrun %d > %d \n",
                        req->cmd_size, req->cmd_begin, req->param_size,
                        CmdConf->max_param_len));
                    iRet = FTPP_ALERT;
                    break;
                }

                if (CmdConf->data_chan_cmd)
                {
                    ftpssn->data_chan_state |= DATA_CHAN_PASV_CMD_ISSUED;
                    ftpssn->data_chan_index = ftp_cmd_pipe_index;
                    if (ftpssn->data_chan_state & DATA_CHAN_PORT_CMD_ISSUED)
                    {
                        /*
                         * If there was a PORT command previously in
                         * a series of pipelined requests, this
                         * cancels it.
                         */
                        ftpssn->data_chan_state &= ~DATA_CHAN_PORT_CMD_ISSUED;
                    }
                }
                else if (CmdConf->data_xfer_cmd)
                {
                    ftpssn->data_chan_state |= DATA_CHAN_XFER_CMD_ISSUED;
                    ftpssn->data_xfer_index = ftp_cmd_pipe_index;
                }
                else if (CmdConf->encr_cmd)
                {
                    if (req->param_begin && (req->param_size > 0) &&
                        ((req->param_begin[0] == 'T') || (req->param_begin[0] == 't')))
                    {
                        ftpssn->encr_state = AUTH_TLS_CMD_ISSUED;
                    }
                    else if (req->param_begin && (req->param_size > 0) &&
                             ((req->param_begin[0] == 'S') || (req->param_begin[0] == 's')))
                    {
                        ftpssn->encr_state = AUTH_SSL_CMD_ISSUED;
                    }
                    else
                    {
                        ftpssn->encr_state = AUTH_UNKNOWN_CMD_ISSUED;
                    }
                }
                if (CmdConf->check_validity)
                {
                    iRet = check_ftp_param_validity(p, req->param_begin,
                                    req->param_end, CmdConf->param_format,
                                    ftpssn);
                    /* If negative, haven't already alerted on violation */
                    if (iRet < 0)
                    {
                        /* Set Alert on malformatted parameter */
                        ftp_eo_event_log(ftpssn, FTP_EO_MALFORMED_PARAMETER,
                            NULL, NULL);
                        iRet = FTPP_ALERT;
                        break;
                    }
                    else if (iRet > 0)
                    {
                        /* Already alerted -- ie, string format attack. */
                        break;
                    }
                }
            }
            break;
        }

        if (iMode == FTPP_SI_CLIENT_MODE)
            ftp_cmd_pipe_index++;
        else if ((rsp_code != 226) && (rsp_code != 426))
        {
             /*
              * In terms of counting responses, ignore
              * 226 response saying transfer complete
              * 426 response saying transfer aborted
              * The 226 may or may not be sent by the server.
              * Both are 2nd response to a transfer command.
              */
            ftp_cmd_pipe_index++;
        }
    }

    if (iMode == FTPP_SI_CLIENT_MODE)
    {
        ftp_cmd_pipe_index = 0;
    }

    if (encrypted)
        return FTPP_ALERT;

    return iRet;
}
