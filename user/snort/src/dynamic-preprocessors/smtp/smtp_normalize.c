/*
 * smtp_normalize.c
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
 * This file handles normalizing SMTP traffic into the alternate buffer.
 *
 * Entry point functions:
 *
 *    SMTP_NeedNormalize()
 *    SMTP_Normalize()
 *
 *
 */

#include <string.h>
#include "preprocids.h"
#include "snort_smtp.h"
#include "bounds.h"

/*
 *  Externs
 */
//extern u_int8_t DecodeBuffer[DECODE_BLEN]; /* decode.c */


/*
 * Check to see if current line needs normalization
 *
 * @param   data    string to check
 *
 * @return  response
 * @retval  1           line needs normalization
 * @retval  0           line does not need normalization
 */
int SMTP_NeedNormalize(char *data, char *buf_end)
{
    int num_spaces = 0;

    /* If more than one space char, return true */
    while ( *data && (*data == ' ' || *data == '\t') )
    {
        num_spaces++;
        if ( num_spaces > 1 )
            return 1;
        data++;

        if (data > buf_end)
            break;
    }

    return 0;
}

/*
 * Normalize current line in buffer.  Walk buffer, consolidating whitespace into
 *   alternate buffer, then return number of bytes walked in packet data buffer.
 *
 * @param   p           standard Packet structure
 * @param   offset      offset into p->data to data of interest
 * @param   cmd_len     length of command on this line
 *
 * @return  length
 * @retval  integer     length of line
 */
int SMTP_Normalize(SFSnortPacket *p, int offset, int cmd_len)
{
    int   i = 0;
    int   datalen;
    char *data;
    int   past_spaces = 0;
    int   first_space = 1;
    char *startBuffer = &_dpd.altBuffer[0];
    char *endBuffer = startBuffer + _dpd.altBufferLen;
    int ret;

    data = p->payload + offset;
    datalen = p->payload_size - offset;

    //memcpy(_dpd.altBuffer + p->normalized_payload_size, data, cmd_len);
    ret = SafeMemcpy(startBuffer + p->normalized_payload_size, data, cmd_len,
                     startBuffer, endBuffer);

    //if (ret == SAFEMEM_ERROR)
    //{
    //    DEBUG_WRAP(_dpd.debugMsg(DEBUG_SMTP, "SMTP_Normalize() => SafeMemcpy failed\n"););
    //    return -1;
    //}

    data += cmd_len;
    i += cmd_len;
    p->normalized_payload_size += cmd_len;

    for ( ; *data && *data != '\n' && i < datalen; i++, data++ )
    {
        if ( !past_spaces && i > cmd_len && *data != ' ' && *data != '\t' )
        {
            past_spaces = 1;
        }
        
        if ( first_space || past_spaces )
        {
            *(_dpd.altBuffer + p->normalized_payload_size) = *data;
            p->normalized_payload_size++;
            if (p->normalized_payload_size > _dpd.altBufferLen)
            {
                break;
            }
            first_space = 0;
        }
    }    

    return i;
}
