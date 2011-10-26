/*
 * snort_dcerpc.c
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
 * This performs the DCERPC decoding.
 *
 * Arguments:
 *   
 * Effect:
 *
 * None
 *
 * NOTES:
 * - 08.12.04:  Initial Development.  SAS
 *
 */

#include "debug.h"
#include "snort_dcerpc.h"
#include "smb_structs.h"
#include "smb_andx_decode.h"
#include "smb_file_decode.h"
#include "dcerpc.h"

#include "profiler.h"
#ifdef PERF_PROFILING
extern PreprocStats dcerpcPerfStats;
extern PreprocStats dcerpcDetectPerfStats;
extern PreprocStats dcerpcIgnorePerfStats;
extern int dcerpcDetectCalled;
#endif

extern char SMBPorts[MAX_PORT_INDEX];
extern char DCERPCPorts[MAX_PORT_INDEX];

extern u_int8_t _autodetect;
    
static int DCERPC_Setup(void *pkt);

/* Session structure */
DCERPC    *_dcerpc;
/* Save packet so we don't have to pass it around */
SFSnortPacket *_dcerpc_pkt;



int ProcessRawSMB(SFSnortPacket *p, u_int8_t *data, u_int16_t size)
{
    /* Must remember to convert stuff to host order before using it... */
    SMB_HDR *smbHdr;
    u_int16_t nbt_data_size;
    u_int8_t *smb_command;
    u_int16_t smb_data_size;

    /* Check for size enough for NBT_HDR and SMB_HDR */
    if ( size <= (sizeof(NBT_HDR) + sizeof(SMB_HDR)) )
    {
        /* Not enough data */
        return 0;
    }

    /* Raw SMB also has 4 bytes prepended to SMB data */
    smbHdr = (SMB_HDR *)(data + sizeof(NBT_HDR));
    nbt_data_size = size - sizeof(NBT_HDR);
    smb_command = (u_int8_t *)smbHdr + sizeof(SMB_HDR);
    smb_data_size = nbt_data_size - sizeof(SMB_HDR);

    if (memcmp(smbHdr->protocol, "\xffSMB", 4) != 0)
    {
        /* Not an SMB request, nothing really to do here... */
        return 0;
    }

    if ( DCERPC_Setup(p) == 0 )
    {
    	return 0;
    }

    return ProcessNextSMBCommand(smbHdr->command, smbHdr, smb_command, smb_data_size, nbt_data_size);
}


inline int ProcessRawDCERPC(SFSnortPacket *p, u_int8_t *data, u_int16_t size)
{
    if ( DCERPC_Setup(p) == 0 )
    {
    	return 0;
    }

    return ProcessDCERPCMessage(NULL, data, size);
}

/*
 * Free SMB-specific related to this session
 *
 * @param   v   pointer to SMB session structure
 *
 * @return  none
 */
void DCERPC_SessionFree(void * v)
{
    DCERPC *x = (DCERPC *) v;

    if ( x && x->write_andx_buf )
        free(x->write_andx_buf);
    
    if ( x && x->dcerpc_req_buf )
        free(x->dcerpc_req_buf);

    if ( x )
        free(x);
      
    return;
}


/*
 * Do first-packet setup
 *
 * @param   p   standard Packet structure
 *
 * @return  1 if successful
 *          0 if not
 */
static int DCERPC_Setup(void *pkt)
{
	SFSnortPacket *p = (SFSnortPacket *)pkt;
    DCERPC *x = NULL;

    /*  Get session pointer */
    x = (DCERPC *)_dpd.streamAPI->get_application_data(p->stream_session_ptr, PP_DCERPC);

    if ( x == NULL )
    {
        x = (DCERPC *)calloc(1, sizeof(DCERPC));

        if ( x == NULL )
        {
            DynamicPreprocessorFatalMessage("%s(%d) => Failed to allocate for SMB session data\n", 
                                            _dpd.config_file, _dpd.config_line);
            return 1;
        }
        else
        {
            _dpd.streamAPI->set_application_data(p->stream_session_ptr, PP_DCERPC,
                                                 (void *)x, &DCERPC_SessionFree);        
        }
    }   
  
    _dcerpc = x;
    _dcerpc_pkt = p;

	return 1;
}

int DCERPC_AutoDetect(SFSnortPacket *p, u_int8_t *data, u_int16_t size)
{
    NBT_HDR *nbtHdr;
    SMB_HDR *smbHdr;
    DCERPC_HDR *dcerpc;

    if ( !_autodetect )
    {
        return 0;
    }

    if ( size > (sizeof(NBT_HDR) + sizeof(SMB_HDR)) )
    {
        /* See if this looks like SMB */
        smbHdr = (SMB_HDR *) (data + sizeof(NBT_HDR));

        if (memcmp(smbHdr->protocol, "\xffSMB", 4) == 0)
        {
            /* Do an extra check on NetBIOS header, which should be valid for both
               NetBIOS and raw SMB */
            nbtHdr = (NBT_HDR *)data;

            if (nbtHdr->type == SMB_SESSION )
            {
                ProcessRawSMB(p, data, size);            
                return 1;
            }
        }
    }

    /* Might be DCE/RPC */
    /*  Make sure it's a reasonable size */
    if (size > sizeof(DCERPC_REQ))
    {
        dcerpc = (DCERPC_HDR *) data;

        /*  Minimal DCE/RPC check - check for version and request */
        if ( dcerpc->version == 5 && dcerpc->packet_type == DCERPC_REQUEST )
        {
            ProcessRawDCERPC(p, data, size);
            return 1;
        }
    }

    return 0;
}

int DCERPCDecode(void *pkt)
{
    SFSnortPacket *p = (SFSnortPacket *) pkt;
	
    /* Don't examine if the packet is rebuilt 
        TODO:  Not a final solution! */
    if ( p->flags & FLAG_REBUILT_STREAM )
        return 0;

    if ( _autodetect )
        return DCERPC_AutoDetect(p, p->payload, p->payload_size);
    
    /* check the port list */
    if (SMBPorts[PORT_INDEX(p->dst_port)] & CONV_PORT(p->dst_port))
    {
        /* Raw SMB */
        ProcessRawSMB(p, p->payload, p->payload_size);
        return 1;
    }

    if (DCERPCPorts[PORT_INDEX(p->dst_port)] & CONV_PORT(p->dst_port))
    {
        ProcessRawDCERPC(p, p->payload, p->payload_size);
        return 1;
    }

    return 0;
}

void DCERPC_Exit(void)
{
#ifdef PERF_PROFILING
#ifdef DEBUG_DCERPC_PRINT
    printf("SMB Debug\n");
    printf("  Number of packets seen:      %u\n", dcerpcPerfStats.checks);
    printf("  Number of packets ignored: %d\n", dcerpcIgnorePerfStats.checks);
#endif
#endif
}


int ProcessNextSMBCommand(u_int8_t command, SMB_HDR *smbHdr,
                          u_int8_t *data, u_int16_t size, u_int16_t total_size)
{
    switch (command)
    {
        case SMB_COM_TREE_CONNECT_ANDX:
            return ProcessSMBTreeConnXReq(smbHdr, data, size, total_size);
        case SMB_COM_NT_CREATE_ANDX:
            return ProcessSMBNTCreateX(smbHdr, data, size, total_size);
        case SMB_COM_WRITE_ANDX: 
            return ProcessSMBWriteX(smbHdr, data, size, total_size);
        case SMB_COM_TRANSACTION:
            return ProcessSMBTransaction(smbHdr, data, size, total_size);
        case SMB_COM_READ_ANDX:
            return ProcessSMBReadX(smbHdr, data, size, total_size);

#ifdef UNUSED_SMB_COMMAND

        case SMB_COM_SESSION_SETUP_ANDX:
            return ProcessSMBSetupXReq(smbHdr, data, size, total_size);
        case SMB_COM_LOGOFF_ANDX:
            return ProcessSMBLogoffXReq(smbHdr, data, size, total_size);
        case SMB_COM_READ_ANDX:
            return ProcessSMBReadX(smbHdr, data, size, total_size);
        case SMB_COM_LOCKING_ANDX:
            return ProcessSMBLockingX(smbHdr, data, size, total_size);

        case SMB_COM_NEGOTIATE:
            return ProcessSMBNegProtReq(smbHdr, data, size, total_size);
        case SMB_COM_TRANSACTION2:
            return ProcessSMBTransaction2(smbHdr, data, size, total_size);
        case SMB_COM_TRANSACTION2_SECONDARY:
            return ProcessSMBTransaction2Secondary(smbHdr, data, size, total_size);
        case SMB_COM_NT_TRANSACT:
            return ProcessSMBNTTransact(smbHdr, data, size, total_size);
        case SMB_COM_NT_TRANSACT_SECONDARY:
            return ProcessSMBNTTransactSecondary(smbHdr, data, size, total_size);
        case SMB_COM_TRANSACTION_SECONDARY:
            break;
        
        case SMB_COM_ECHO:
            return ProcessSMBEcho(smbHdr, data, size, total_size);
        case SMB_COM_SEEK:
            return ProcessSMBSeek(smbHdr, data, size, total_size);
        case SMB_COM_FLUSH:
            return ProcessSMBFlush(smbHdr, data, size, total_size);
        case SMB_COM_CLOSE:
        case SMB_COM_CLOSE_AND_TREE_DISC:
            return ProcessSMBClose(smbHdr, data, size, total_size);
        case SMB_COM_TREE_DISCONNECT:
        case SMB_COM_NT_CANCEL:
            return ProcessSMBNoParams(smbHdr, data, size, total_size);
#endif
        default:
#ifdef DEBUG_DCERPC_PRINT
            printf("====> Unprocessed command 0x%02x <==== \n", command);
#endif
            break;
    }

    return 0;
}

