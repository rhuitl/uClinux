/***********************************************************************
*
* debug.c
*
* Implementation of user-space PPPoE redirector for Linux.
*
* Functions for printing debugging information
*
* Copyright (C) 2000 by Roaring Penguin Software Inc.
*
* This program may be distributed according to the terms of the GNU
* General Public License, version 2 or (at your option) any later version.
*
***********************************************************************/

static char const RCSID[] =
"$Id: debug.c,v 1.6 2000/07/27 01:01:41 dfs Exp $";

#include "pppoe.h"

/**********************************************************************
*%FUNCTION: dumpHex
*%ARGUMENTS:
* fp -- file to dump to
* buf -- buffer to dump
* len -- length of data
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Dumps buffer to fp in an easy-to-read format
***********************************************************************/
void
dumpHex(FILE *fp, unsigned char const *buf, int len)
{
    int i;

    if (!fp) return;
    for (i=0; i<len; i++) {
	if (i == len-1 || !((i+1)%16)) {
	    fprintf(fp, "%02x\n", (unsigned) buf[i]);
	} else if (!((i+1)%8)) {
	    fprintf(fp, "%02x-", (unsigned) buf[i]);
	} else {
	    fprintf(fp, "%02x ", (unsigned) buf[i]);
	}
    }
}

/**********************************************************************
*%FUNCTION: dumpPacket
*%ARGUMENTS:
* fp -- file to dump to
* packet -- a PPPoE packet
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Dumps the PPPoE packet to fp in an easy-to-read format
***********************************************************************/
void
dumpPacket(FILE *fp, struct PPPoEPacket *packet)
{
    int len = ntohs(packet->length);
    UINT16_t type = etherType(packet);
    if (!fp) return;
    fprintf(fp, "PPPOE ");
    if (type == Eth_PPPOE_Discovery) {
	fprintf(fp, "Discovery (%x) ", (unsigned) type);
    } else if (type == Eth_PPPOE_Session) {
	fprintf(fp, "Session (%x) ", (unsigned) type);
    } else {
	fprintf(fp, "Unknown (%x) ", (unsigned) type);
    }

    switch(packet->code) {
    case CODE_PADI: fprintf(fp, "PADI "); break;
    case CODE_PADO: fprintf(fp, "PADO "); break;
    case CODE_PADR: fprintf(fp, "PADR "); break;
    case CODE_PADS: fprintf(fp, "PADS "); break;
    case CODE_PADT: fprintf(fp, "PADT "); break;
    case CODE_SESS: fprintf(fp, "SESS "); break;
    }

    fprintf(fp, "sess-id %d length %d\n",
	    (int) ntohs(packet->session),
	    len);

    /* Ugly... I apologize... */
    fprintf(fp,
	    "SourceAddr %02x:%02x:%02x:%02x:%02x:%02x "
	    "DestAddr %02x:%02x:%02x:%02x:%02x:%02x\n",
	    (unsigned) packet->ethHdr.h_source[0],
	    (unsigned) packet->ethHdr.h_source[1],
	    (unsigned) packet->ethHdr.h_source[2],
	    (unsigned) packet->ethHdr.h_source[3],
	    (unsigned) packet->ethHdr.h_source[4],
	    (unsigned) packet->ethHdr.h_source[5],
	    (unsigned) packet->ethHdr.h_dest[0],
	    (unsigned) packet->ethHdr.h_dest[1],
	    (unsigned) packet->ethHdr.h_dest[2],
	    (unsigned) packet->ethHdr.h_dest[3],
	    (unsigned) packet->ethHdr.h_dest[4],
	    (unsigned) packet->ethHdr.h_dest[5]);
    dumpHex(fp, packet->payload, ntohs(packet->length));
}
