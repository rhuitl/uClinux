
/*
 * snort_smtp.h
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
 * This file defines everything specific to the SMTP preprocessor.
 *
 */


#ifndef __SMTP_H__
#define __SMTP_H__

#include "sf_snort_packet.h"
#include "sf_dynamic_preprocessor.h"

/* SMTP normally runs on port 25 */
#define SMTP_DEFAULT_SERVER_PORT  25
/* XLINK2STATE sometimes runs on port 691 */
#define XLINK2STATE_DEFAULT_PORT  691

/* Direction packet is coming from, if we can figure it out */
#define SMTP_PKT_FROM_UNKNOWN   0
#define SMTP_PKT_FROM_CLIENT    1
#define SMTP_PKT_FROM_SERVER    2

/* Inspection type */
#define SMTP_STATELESS   0
#define SMTP_STATEFUL    1

/* X-Link2State overlong length */
#define XLINK2STATE_MAX_LEN     520

/* Max length of boundary string, defined in RFC 2046 */
#define MAX_BOUNDARY_LEN    71

typedef enum _SMTP_state
{
    COMMAND       = 0x0000,            /*  Command section of SMTP message          */
    DATA          = 0x0001,            /*  DATA section header or body              */
    DATA_PEND     = 0x0002,            /*  DATA section, pending reply by server    */
    DATA_BODY     = 0x0004,            /*  DATA body section                        */
    MIME_HEADER   = 0x0008,            /*  MIME header section within DATA section  */
    TLS_DATA      = 0x0010             /*  Successful handshake, TLS encrypted data */

} SMTP_state;

#define NUM_SMTP_STATE    5


typedef struct _SMTP
{
    SMTP_state  state;
    u_int       message_number;
    u_int       pkt_direction;
    u_int       got_data_cmd;
    u_int       got_data_resp;
    u_int       got_starttls;
    u_int       got_server_tls;
    u_int       last_byte;
    u_int       cur_client_line_len;
    u_int       cur_server_line_len;
    u_char      last_byte_is_lf;
    u_int       normalizing;            /* Currently normalizing COMMAND section   */
    u_int       token_id;               /* ID of token found in stream             */
    u_int       token_iid;              /* Location in array of commands           */
    u_int       token_index;            /* Location in p->data of token            */
    u_int       token_length;           /* Length of token                         */
    u_int       xlink2state_gotfirstchunk;  /* 1 if got FIRST chunk                    */
    u_char      xlink2state_alerted;    /* If alerted on X-Link2State this session */
    u_int8_t    boundary[MAX_BOUNDARY_LEN];  /* MIME boundary string               */
    u_int       boundary_len;
    void       *data_search;

} SMTP;

    
typedef struct _SMTP_token
{
    char   *name;           /*  "HELO", "MAIL FROM", ".\n", "354", "250", etc */
    u_int   name_len;       /*  Length of name string                         */
    u_int   id;             /*  Identifying ID, not always unique             */
    u_int   alert;          /*  1 if alert when seen                          */
    u_int   normalize;      /*  1 if we should normalize this command         */
    u_int   max_len;        /*  Max length of this particular command         */

} SMTP_token;

typedef struct _SMTP_cmd
{
    char   *name;            /*  "HELO", "MAIL FROM", ".\n", "354", "250", etc */
    u_int   id;              /*  Identifying ID, not always unique             */

} SMTP_cmd;



typedef enum _cmd_e
{
    CMD_MASK        = 0x00000000,
    CMD_UNKNOWN     = 0x00000001,
    CMD_HELO        = 0x00000002,
    CMD_EHLO        = 0x00000004,
    CMD_MAIL        = 0x00000008,
    CMD_RCPT        = 0x00000010,
    CMD_RSET        = 0x00000020,
    CMD_DATA        = 0x00000040,
    
    CMD_NOOP        = 0x00000200,
    CMD_QUIT        = 0x00000400,
    CMD_VRFY        = 0x00000800,
    CMD_HELP        = 0x00001000,
    CMD_EXPN        = 0x00002000,
    CMD_BDAT        = 0x00004000,
    CMD_STARTTLS    = 0x00008000,
    CMD_XEXCH50     = 0x00010000,
    CMD_XLINK2STATE = 0x00020000,

    CMD_TYPE        = 0x00100000,

    DATA_BODY_END   = 0x00000080,
    DATA_HEADER_END = 0x00000100,
    DATA_BOUNDARY   = 0x01000000,
    
    CMD_OTHER       = 0x10000000,

    CMD_LAST        = 0x80000000
} cmd_e;

    

typedef enum _resp_e
{
    RESP_MASK    = 0x00000000,
    RESP_UNKNOWN = 0x00000001,
    RESP_354     = 0x00000002,    /*  Valid DATA command  */
    RESP_250     = 0x00000004,
    RESP_421     = 0x00000008,
    RESP_554     = 0x00000010,    /*  No valid recipients */
    
    RESP_NONE    = 0x00100000
} resp_e;


typedef enum _norm_e
{
    normalize_none = 0,
    normalize_all,
    normalize_cmds
} norm_e;


typedef struct _SMTP_CONFIG
{
    u_char      ports[8192];
    u_int       inspection_type;
    norm_e      normalize;
    u_int       ignore_data;
    u_int       ignore_tls_data;
    u_int       max_command_line_len;
    u_int       max_header_line_len;
    u_int       max_response_line_len;
    u_int       no_alerts;
    u_int       alert_unknown_cmds;
    u_int       alert_xlink2state;
    u_int       drop_xlink2state;
    u_int       print_cmds;    
    SMTP_token *cmd;
    int         cmd_size;

} SMTP_CONFIG   ;

/*  Exported functions */
void SMTP_Init(void);
void SMTP_Free(void);
//void SnortSMTP(Packet *p);
void SnortSMTP(SFSnortPacket *p);

#define GENERATOR_SMTP 124
extern DynamicPreprocessorData _dpd;

#endif  /* __SMTP_H__ */
