/*
 *  $Id$
 *
 *  libnet
 *  libnet_build_vrrp.c - VRRP packet assembler
 *
 *  Copyright (c) 1998 - 2001 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#if (HAVE_CONFIG_H)
#include "../include/config.h"
#endif
#include "../include/libnet.h"

int
libnet_build_vrrp(u_char vrouter_id, u_char priority, u_char ip_count,
            u_char auth_type, u_char advert_int, const u_char *payload,
            int payload_s, u_char *buf)
{
    struct libnet_vrrp_hdr vrrp_hdr;

    if (!buf)
    {
        return (-1);
    }

    vrrp_hdr.vrrp_v          = 0x2;                      /* Version 2 */
    vrrp_hdr.vrrp_t          = LIBNET_VRRP_TYPE_ADVERT;  /* Advertisement */
    vrrp_hdr.vrrp_vrouter_id = vrouter_id;
    vrrp_hdr.vrrp_priority   = priority;
    vrrp_hdr.vrrp_ip_count   = ip_count;
    vrrp_hdr.vrrp_auth_type  = auth_type;
    vrrp_hdr.vrrp_advert_int = advert_int;

    if (payload && payload_s)
    {
        /*
         *  Unchecked runtime error for buf + VRRP_H + payload to be greater
         *  than the allocated heap memory.
         */
        memcpy(buf + LIBNET_VRRP_H, payload, payload_s);
    }
    memcpy(buf, &vrrp_hdr, sizeof(vrrp_hdr));
    return (1);
}


/* EOF */
