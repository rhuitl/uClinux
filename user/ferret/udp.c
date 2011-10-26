/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "netframe.h"
#include "ferret.h"
#include "formats.h"
#include <string.h>

void process_udp(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	struct {
		unsigned src_port;
		unsigned dst_port;
		unsigned length;
		unsigned checksum;
	} udp;

	if (length == 0) {
		FRAMERR(frame, "udp: frame empty\n");
		return;
	}
	if (length < 8) {
		FRAMERR(frame, "udp: frame too short\n");
		return;
	}

	udp.src_port = ex16be(px+0);
	udp.dst_port = ex16be(px+2);
	udp.length = ex16be(px+4);
	udp.checksum = ex16be(px+6);

	frame->src_port = udp.src_port;
	frame->dst_port = udp.dst_port;

	if (udp.length < 8) {
		FRAMERR_TRUNCATED(frame, "udp");
		return;
	}

	if (length > udp.length)
		length = udp.length;

	offset += 8;

	switch (frame->dst_ipv4) {
	case 0xe0000123: /* 224.0.1.35 - SLP */
		if (udp.dst_port == 427)
			SAMPLE("SLP", "packet",	REC_SZ, "test",-1);
		else
			FRAMERR(frame, "unknown port %d\n", udp.dst_port);
		return;
	}

	SAMPLE("UDP", "src",	REC_UNSIGNED, &udp.src_port, sizeof(udp.src_port));
	SAMPLE("UDP", "dst",	REC_UNSIGNED, &udp.dst_port, sizeof(udp.dst_port));

	switch (udp.src_port) {
	case 68:
	case 67:
		process_dhcp(seap, frame, px+offset, length-offset);
		break;
	case 53:
		process_dns(seap, frame, px+offset, length-offset);
		break;
	case 137:
		process_dns(seap, frame, px+offset, length-offset);
		break;
	case 138:
		process_netbios_dgm(seap, frame, px+offset, length-offset);
		break;
	case 389:
		process_ldap(seap, frame, px+offset, length-offset);
		break;
	case 631:
		if (udp.dst_port == 631) {
			process_cups(seap, frame, px+offset, length-offset);
		}
		break;
	case 1900:
		if (length-offset > 9 && memicmp(px+offset, "HTTP/1.1 ", 9) == 0) {
			process_upnp_response(seap, frame, px+offset, length-offset);
		}
		break;
	case 14906: /* ??? */
		break;
	case 4500:
		break;
	default:
		switch (udp.dst_port) {
		case 0:
			break;
		case 68:
		case 67:
			process_dhcp(seap, frame, px+offset, length-offset);
			break;
		case 53:
		case 5353:
			process_dns(seap, frame, px+offset, length-offset);
			break;
		case 137:
			process_dns(seap, frame, px+offset, length-offset);
			break;
		case 138:
			process_netbios_dgm(seap, frame, px+offset, length-offset);
			break;
		case 1900:
			if (frame->dst_ipv4 == 0xeffffffa)
				process_ssdp(seap, frame, px+offset, length-offset);
			break;
		case 5369:
			break;
		case 29301:
			break;
		case 123:
			break;
		case 5499:
			break;
		case 2233: /*intel/shiva vpn*/
			break;
		case 27900: /* GameSpy*/
			break;
		case 9283:
			process_callwave_iam(seap, frame, px+offset, length-offset);
			break;
		case 161:
			process_snmp(seap, frame, px+offset, length-offset);
			break;
		case 192: /* ??? */
			break;
		case 389:
			process_ldap(seap, frame, px+offset, length-offset);
			break;
		case 427: /* SRVLOC */
			process_srvloc(seap, frame, px+offset, length-offset);
			break;
		case 14906: /* ??? */
			break;
		case 500:
			process_isakmp(seap, frame, px+offset, length-offset);
			break;
		case 2222:
			break;
		default:
			if (frame->dst_ipv4 == 0xc0a8a89b || frame->src_ipv4 == 0xc0a8a89b)
				;
			else
			FRAMERR(frame, "udp: unknown, [%d.%d.%d.%d]->[%d.%d.%d.%d] src=%d, dst=%d\n", 
				(frame->src_ipv4>>24)&0xFF,(frame->src_ipv4>>16)&0xFF,(frame->src_ipv4>>8)&0xFF,(frame->src_ipv4>>0)&0xFF,
				(frame->dst_ipv4>>24)&0xFF,(frame->dst_ipv4>>16)&0xFF,(frame->dst_ipv4>>8)&0xFF,(frame->dst_ipv4>>0)&0xFF,
				frame->src_port, frame->dst_port);
		}
	}

}

