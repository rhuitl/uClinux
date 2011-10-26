/*
 * snort_dcerpc.h
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
 * 
 * Description:
 *
 * Declares external routines that handle decoding SMB commands
 *
 * NOTES:
 * - 08.12.04:  Initial Development.  SAS
 *
 */
#ifndef _SNORT_SMB_H_
#define _SNORT_SMB_H_

#include "sf_snort_packet.h"
#include "sf_dynamic_preprocessor.h"

#ifdef WIN32
#pragma pack(push,snort_smb_hdrs,1)
#endif

/* Default maximum frag size, in bytes */
#define DEFAULT_MAX_FRAG_SIZE   3000
#define MAX_MAX_FRAG_SIZE       5840

/* Default maximum memory use, in KB */
#define DEFAULT_MEMCAP          100000

#define SMB_FRAGMENTATION       0x0001  /* SMB fragmentation     */
#define RPC_FRAGMENTATION       0x0002  /* DCE/RPC fragmentation */
#define SUSPEND_FRAGMENTATION   0x0004  /* Memcap reached, don't try to do more */


#define STATE_START             0
#define STATE_GOT_TREE_CONNECT  1
#define STATE_GOT_NTCREATE      2   /* Or got SMB Open */
#define STATE_IS_DCERPC         3   /* Valid DCE/RPC session */

typedef struct _DCERPC
{
    u_int8_t    state;
    u_int8_t    smb_state;
    u_int8_t    fragmentation;
    u_int8_t   *write_andx_buf;
    u_int16_t   write_andx_buf_len;
    u_int16_t   write_andx_buf_size;
    u_int8_t   *dcerpc_req_buf;
    u_int16_t   dcerpc_req_buf_len;
    u_int16_t   dcerpc_req_buf_size;


} DCERPC;

#ifdef WIN32
#pragma pack(pop,snort_smb_hdrs,1)
#endif

#define MAX_PORT_INDEX 65536 / 8

/* Convert port value into an index for the dns_config.ports array */
#define PORT_INDEX(port) port / 8

/* Convert port value into a value for bitwise operations */
#define CONV_PORT(port) 1 << (port % 8)
    
int  DCERPCProcessConf(char *pcToken, char *ErrorString, int ErrStrLen);
int  DCERPCDecode(void *p);
void DCERPC_Exit();

#define GENERATOR_SMB 125
extern DynamicPreprocessorData _dpd;

#endif /* _SNORT_SMB_H_ */

