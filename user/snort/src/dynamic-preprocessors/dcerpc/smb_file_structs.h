/*
 * smb_file_structs.h
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
#ifndef _SMB_FILE_STRUCTS_H_
#define _SMB_FILE_STRUCTS_H_

#ifdef WIN32
#pragma pack(push,smb_hdrs,1)
#endif

typedef struct echo_req_hdr
{
    u_int8_t wordCount;        /* Count of parameter words */
    u_int8_t echoCount;

    u_int16_t byteCount;       /* Should be 0 */
} SMB_ECHO_REQ;

typedef struct close_hdr
{
    u_int8_t wordCount;
    u_int16_t fid;
    SMB_UTIME lastWriteTime;
    u_int16_t byteCount;
} SMB_CLOSE_REQ;

typedef struct seek_hdr
{
    u_int8_t wordCount;
    u_int16_t fid;
    u_int16_t mode;
    u_int32_t offset;
    u_int16_t byteCount;
} SMB_SEEK_REQ;

typedef struct flush_hdr
{
    u_int8_t wordCount;
    u_int16_t fid;
    u_int16_t byteCount;
} SMB_FLUSH_REQ;

typedef struct tree_disconnect_hdr
{
    u_int8_t wordCount;
    u_int16_t byteCount;
} SMB_TREE_DISCONNECT_REQ;



#ifdef WIN32
#pragma pack(pop,smb_hdrs)
#endif

#endif /* _SMB_FILE_STRUCTS_H_ */
