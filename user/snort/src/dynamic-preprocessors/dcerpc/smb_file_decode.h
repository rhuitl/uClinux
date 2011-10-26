/*
 * smb_file_decode.h
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
 * Declares routines that handle decoding SMB File commands
 *
 * NOTES:
 * - 08.12.04:  Initial Development.  SAS
 *
 */
#ifndef _SMB_FILE_DECODE_H_
#define _SMB_FILE_DECODE_H_

int ProcessSMBEcho(SMB_HDR *smbHdr, u_int8_t *data, u_int16_t size);
int ProcessSMBClose(SMB_HDR *smbHdr, u_int8_t *data, u_int16_t size);
int ProcessSMBSeek(SMB_HDR *smbHdr, u_int8_t *data, u_int16_t size);
int ProcessSMBFlush(SMB_HDR *smbHdr, u_int8_t *data, u_int16_t size);
int ProcessSMBNoParams(SMB_HDR *smbHdr, u_int8_t *data, u_int16_t size);

#endif /* _SMB_FILE_DECODE_H_ */
