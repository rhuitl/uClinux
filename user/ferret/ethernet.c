/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "formats.h"
#include "netframe.h"
#include "ferret.h"
#include <string.h>
#include <stdio.h>

typedef unsigned char MACADDR[6];


void process_ethernet_frame(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset;
	unsigned ethertype;
	unsigned oui;

	if (length <= 14) {
		; //FRAMERR(frame, "wifi.data: too short\n");
		return;
	}

	frame->src_mac = px+6;
	frame->dst_mac = px+0;

	offset = 12;


	/* Look for SAP header */
	if (offset + 6 >= length) {
		FRAMERR(frame, "wifi.sap: too short\n");
		return;
	}

	ethertype = ex16be(px+offset);
	offset += 2;

	switch (ethertype) {
	case 0x0800:
		process_ip(seap, frame, px+offset, length-offset);
		break;
	case 0x0806:
		process_arp(seap, frame, px+offset, length-offset);
		break;
	case 0x888e: /*802.11x authentication*/
		process_802_1x_auth(seap, frame, px+offset, length-offset);
		break;
	case 0x86dd: /* IPv6*/
		process_ipv6(seap, frame, px+offset, length-offset);
		break;
	case 0x809b:
		process_ipv6(seap, frame, px+offset, length-offset);
		break;
	case 0x872d: /* Cisco OWL */
		break;

	default:
		if (ethertype < 1518) {
			if (memcmp(px+offset, "\xaa\xaa\x03", 3) != 0) {
				process_record(seap,
					"proto",	REC_SZ,			"ethernet",				-1,
					"op",		REC_SZ,			"data.unknown",		-1,
					"data",REC_PRINTABLE,	px+offset,				length-offset,
					0);
				return;
			}
			offset +=3 ;

			oui = ex24be(px+offset);
			SAMPLE("SAP", "ethertype", REC_UNSIGNED, &oui, sizeof(oui));

			/* Look for OUI code */
			switch (oui){
			case 0x000000:
				/* fall through below */
				break;
			case 0x004096: /* Cisco Wireless */
				return;
				break;
			case 0x00000c:
				offset +=3;
				if (offset < length)
				process_cisco00000c(seap, frame, px+offset, length-offset);
				return;
			case 0x080007:
				break; /*apple*/
			default:
				FRAMERR(frame, "Unknown SAP OUI: 0x%06x\n", oui);
				return;
			}
			offset +=3;

			/* EtherType */
			if (offset+2 >= length) {
				FRAMERR(frame, "ethertype: packet too short\n");
				return;
			}

		}

		if (ethertype == length-offset && ex16be(px+offset) == 0xAAAA) {
			;
		}
		else
			FRAMERR_BADVAL(frame, "ethertype", ethertype);
	}
}
