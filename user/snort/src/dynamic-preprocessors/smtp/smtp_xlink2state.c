/*
 * smtp_xlink2state.c
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
 * This file handles the X-Link2State vulnerability.
 *
 * Entry point function:
 *
 *    ParseXLink2State()
 *
 *
 */

#ifndef WIN32
#include <strings.h>
#endif
#include <ctype.h>
#include "snort_packet_header.h"

#include "snort_smtp.h"
#include "smtp_util.h"

extern SMTP         *_smtp;
extern SMTP_CONFIG   _smtp_config;


#define XLINK_OTHER     1
#define XLINK_FIRST     2
#define XLINK_CHUNK     3

#define XLINK_LEN      12   /* strlen("X-LINK2STATE") */

/*
 * Check for X-LINK2STATE keywords FIRST or CHUNK
 *   
 *
 * @param   x           pointer to "X-LINK2STATE" in buffer
 * @param   x_len       length of buffer after x
 *
 * @retval  int         identifies which keyword found, if any
 */
static u_int CheckKeyword(u_int8_t *x, u_int x_len)
{
    x += XLINK_LEN;  
    x_len -= XLINK_LEN;

    /* Skip over spaces */
    while ( isspace(*x) && x_len != 0 )
    {
        x++;
        x_len--;
    }

    if ( x_len > 5 && !strncasecmp(x, "FIRST", 5) )
        return XLINK_FIRST;

    if ( x_len > 5 && !strncasecmp(x, "CHUNK", 5) )
        return XLINK_CHUNK;

    return XLINK_OTHER;
}


/*
 * Handle X-Link2State vulnerability
 *   
 *  From Lurene Grenier:
 
    The X-LINK2STATE command always takes the following form:

    X-LINK2STATE [FIRST|NEXT|LAST] CHUNK=<SOME DATA>

    The overwrite occurs when three criteria are met:

    No chunk identifier exists - ie neither FIRST, NEXT, or LAST are specified
    No previous FIRST chunk was sent
    <SOME DATA> has a length greater than 520 bytes

    Normally you send a FIRST chunk, then some intermediary chunks marked with
    either NEXT or not marked, then finally a LAST chunk.  If no first chunk is
    sent, and a chunk with no specifier is sent, it assumes it must append to
    something, but it has nothing to append to, so an overwrite occurs. Sending out
    of order chunks WITH specifiers results in an exception.

    So simply:

    if (gotFirstChunk)
        next; # chunks came with proper first chunk specified
    if (/X-LINK2STATE [FIRST|NEXT|LAST] CHUNK/) {
        if (/X-LINK2STATE FIRST CHUNK/) gotFirstChunk = TRUE;
        next; # some specifier is marked 
    }
    if (chunkLen > 520)
       attempt = TRUE; # Gotcha!

    Usually it takes more than one unspecified packet in a row, but I think this is
    just a symptom of the fact that we're triggering a heap overwrite, and not a
    condition of the bug. However, if we're still getting FPs this might be an
    avenue to try.

 *
 * @param   p           standard Packet structure
 * @param   x           pointer to "X-LINK2STATE" in buffer
 *
 * @retval  1           if alert raised
 * @retval  0           if no alert raised
 */
int ParseXLink2State(SFSnortPacket *p, u_int8_t *x)
{
    u_int8_t *eq;
    u_int8_t *start;
    u_int8_t *lf;
    u_int32_t len = 0;
    u_int     x_len;
    u_int     x_keyword;

    /* If we got a FIRST chunk on this stream, this is not an exploit */
    if ( _smtp->xlink2state_gotfirstchunk )
        return 0;

    /* Calculate length from pointer to end of packet data */
    x_len = p->payload_size - (x - p->payload);

    /* Check for "FIRST" or "CHUNK" after X-LINK2STATE */
    x_keyword = CheckKeyword(x, x_len);

    if ( x_keyword == XLINK_OTHER )
        return 0;

    if ( x_keyword == XLINK_FIRST )
    {
        _smtp->xlink2state_gotfirstchunk = 1;
        return 0;
    }

    /* Must be XLINK_CHUNK */

    eq = safe_strchr(x, '=', x_len);
    if ( !eq )
        return 0;

    /*  Look for one of two patterns:

        ... CHUNK={0000006d} MULTI (5) ({00000000051} ...
        ... CHUNK=AAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n
     */
    if ( *(eq+1) == '{' )
    {
        /* Parse length - can we always trust it? */
        start = eq + 2;
        /* The number is hex, so pass in base 16.  16^8 - 1 is the max size of an unsigned long. */ 
        len = safe_sscanf(start, 8, 16);
    }
    else
    {
        start = eq + 1;
    }

    if ( len == 0 )
    {
        lf = safe_strchr(x, '\n', x_len);
        if ( !lf )
            return 0;

        len = lf - start;
    }

    if ( len > XLINK2STATE_MAX_LEN )
    {
        /* Need to drop the packet if we're told to
         * and we're inline mode (outside of whether its
         * thresholded). */
        if (_smtp_config.drop_xlink2state && _dpd.inlineMode())
        {
            _dpd.inlineDrop(p);
        }

        _dpd.alertAdd(GENERATOR_SMTP, 1, 1, 0, 3, "X-Link2State command: attempted buffer overflow", 0);
        _smtp->xlink2state_alerted = 1;

        return 1;
    }

    /* Check for more than one command in packet */
    lf = safe_strchr(x, '\n', x_len);
    if ( !lf )
        return 0;

    if ( (u_int) (lf - x + 1) < x_len )
    {
        x = lf + 1;
        ParseXLink2State(p, x);
    }

    return 0;
}
