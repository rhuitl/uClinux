/*
 * smb_andx_structs.h
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
 * Defines data structures representing SMB commands
 *
 * NOTES:
 * - 08.12.04:  Initial Development.  SAS
 *
 */
#ifndef _SMB_ANDX_STRUCTS_H_
#define _SMB_ANDX_STRUCTS_H_

#include "smb_structs.h"

#ifdef WIN32
#pragma pack(push,smb_hdrs,1)
#else
#pragma pack(1)
#endif

typedef struct sess_setupx_req_hdr
{ 
    u_int8_t wordCount;        /* Count of parameter words */
    u_int8_t andXCommand;
    u_int8_t andXReserved;
    u_int16_t andXOffset;

    u_int16_t maxBufSize;
    u_int16_t maxMPXCount;
    u_int16_t vcNumber;
    u_int32_t sessionKey;
} SMB_SESS_SETUPX_REQ_HDR;

typedef struct sess_setupx_req_auth_old
{
    u_int16_t passwdLen;
    u_int32_t reserved2;
    u_int16_t byteCount;
} SMB_SESS_SETUPX_REQ_AUTH_OLD;

typedef struct sess_setupx_req_auth_ntlm12
{
    u_int16_t secBlobLength;
    u_int32_t reserved2;
    u_int32_t capabilities;
    u_int16_t byteCount;
} SMB_SESS_SETUPX_REQ_AUTH_NTLM12;

typedef struct sess_setupx_req_auth_ntlm12_noext
{
    u_int16_t iPasswdLen;
    u_int16_t passwdLen;
    u_int32_t reserved2;
    u_int32_t capabilities;
    u_int16_t byteCount;
} SMB_SESS_SETUPX_REQ_AUTH_NTLM12_NOEXT;

typedef struct tree_connx_req_hdr
{
    u_int8_t wordCount;        /* Count of parameter words */
    u_int8_t andXCommand;
    u_int8_t andXReserved;
    u_int16_t andXOffset;

    u_int16_t flags;
    u_int16_t passwdLen;
    u_int16_t byteCount;
} SMB_TREE_CONNECTX_REQ;

typedef struct logoffx_req_hdr
{
    u_int8_t wordCount;        /* Count of parameter words */
    u_int8_t andXCommand;
    u_int8_t andXReserved;
    u_int16_t andXOffset;

    u_int16_t byteCount;       /* Should be 0 */
} SMB_LOGOFFX_REQ;

typedef struct ntcreatex_req_hdr
{
    u_int8_t wordCount;        /* Count of parameter words */
    u_int8_t andXCommand;
    u_int8_t andXReserved;
    u_int16_t andXOffset;

    u_int8_t reserved2;
    u_int16_t nameLength;
    u_int32_t flags;

    u_int32_t rootDirFid;
    SMB_ACCESS_MASK desiredAccess;
    SMB_LARGE_INTEGER allocationSize;

    u_int32_t extFileAttributes;
    u_int32_t shareAccess;
    u_int32_t createDisposition;
    u_int32_t createOptions;
    u_int32_t impersonationLevel;

    u_int8_t securityFlags;
    u_int16_t byteCount;

} SMB_NTCREATEX_REQ;

typedef struct readx_hdr
{
    u_int8_t wordCount;
    u_int8_t andXCommand;
    u_int8_t andXReserved;
    u_int16_t andXOffset;

    u_int16_t fid;
    u_int32_t offset;

    u_int16_t maxCount;
    u_int16_t minCount;
    u_int32_t maxCountHigh;

    u_int16_t remaining;
    u_int32_t highOffset;
    u_int16_t byteCount;

} SMB_READX_REQ;

typedef struct lockingx_hdr
{
    u_int8_t wordCount;
    u_int8_t andXCommand;
    u_int8_t andXReserved;
    u_int16_t andXOffset;

    u_int16_t fid;
    u_int8_t lockType;
    u_int8_t oplockLevel;
    u_int32_t timeout;

    u_int16_t numUnlocks;
    u_int16_t numLocks;

    u_int16_t byteCount;

} SMB_LOCKINGX_REQ;

#define LOCKINGX_SHARED_LOCK 0x01
#define LOCKINGX_OPLOCK_RELEASE 0x02
#define LOCKINGX_CHANGE_LOCKTYPE 0x04
#define LOCKINGX_CANCEL_LOCK 0x08
#define LOCKINGX_LARGE_FILES 0x10

typedef struct lockingx_range
{
    u_int16_t pid;
    u_int32_t offset;
    u_int32_t length;
} SMB_LOCKINGX_RANGE;

typedef struct largefile_lockingx_range
{
    u_int16_t pid;
    u_int16_t pad;

    u_int32_t offsetHigh;
    u_int32_t offsetLow;
    u_int32_t lengthHigh;
    u_int32_t lengthLow;
} SMB_LARGEFILE_LOCKINGX_RANGE;

typedef struct writex_hdr
{
    u_int8_t wordCount;
    u_int8_t andXCommand;
    u_int8_t andXReserved;
    u_int16_t andXOffset;

    u_int16_t fid;
    u_int32_t offset;
    u_int32_t reserved;

    u_int16_t writeMode;

    u_int16_t remaining;
    u_int16_t dataLengthHigh;
    u_int16_t dataLength;
    u_int16_t dataOffset;
    u_int32_t highOffset;
    u_int16_t byteCount;

} SMB_WRITEX_REQ;

typedef struct trans_hdr
{
    u_int8_t  wordCount;
    u_int16_t totalParamCount;
    u_int16_t totalDataCount;
    u_int16_t maxParamCount;
    u_int16_t maxDataCount;
    u_int8_t  maxSetupCount;
    u_int8_t  transReserved;

    u_int16_t flags;
    u_int32_t timeout;
    u_int16_t reserved;

    u_int16_t parameterCount;
    u_int16_t parameterOffset;
    u_int16_t dataCount;
    u_int16_t dataOffset;
    u_int8_t  setupCount;
    u_int8_t  reserved2;
    u_int16_t function;
    u_int16_t fid;
    u_int16_t byteCount;

} SMB_TRANS_REQ;

#ifdef WIN32
#pragma pack(pop,smb_hdrs)
#else
#pragma pack()
#endif

#endif /* _SMB_ANDX_STRUCTS_H_ */
