/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "netframe.h"
#include "formats.h"
#include "ferret.h"


#include <string.h>

void process_ipv6(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	struct {
		unsigned version;
		unsigned traffic_class;
		unsigned flow_label;
		unsigned payload_length;
		unsigned next_header;
		unsigned hop_limit;
		unsigned char src_ipv6[16];
		unsigned char dst_ipv6[16];
	} ip;

	if (length == 0) {
		FRAMERR(frame, "ip: frame empty\n");
		return;
	}
	if (length < 40) {
		FRAMERR(frame, "ip: truncated\n");
		return;
	}

	ip.version = px[0]>>4;
	ip.traffic_class = ((px[0]&0xF)<<4) | ((px[1]&0xF0)>>4);
	ip.flow_label = ((px[1]&0xF)<<16) | ex16be(px+2);
	ip.payload_length = ex16be(px+4);
	ip.next_header = px[6];
	ip.hop_limit = px[7];
	memcpy(frame->src_ipv6, px+8, 16);
	memcpy(frame->dst_ipv6, px+24, 16);
	frame->ipver = 6;

	if (ip.version != 6) {
		FRAMERR(frame, "ip: version=%d, expected version=6\n", ip.version);
		return;
	}
	offset += 40;

	SAMPLE("IPv6", "next-header", REC_UNSIGNED, &ip.next_header, sizeof(ip.next_header));

again:
	if (offset > length) {
		FRAMERR(frame, "ipv6: truncated\n");
		return;
	}
	switch (ip.next_header) {
	case 0: /* IPv6 options field */
	case 43: /* routing header */
	case 60: /* destination options */
		if (offset + 8 > length) {
			FRAMERR(frame, "ipv6: truncated\n");
			return;
		}
		ip.next_header = px[offset];
		offset += px[offset+1] + 8;
		goto again;
		break;
		break;
	case 44: /* fragment header */
		FRAMERR(frame, "ipv6: truncated\n");
		return;
	case 59: /* no next header */
		return;
	case 58: /* ICMPv6 */
		process_icmpv6(seap, frame, px+offset, length-offset);
		break;
	case 17:
		process_udp(seap, frame, px+offset, length-offset);
		break;
	default:
		FRAMERR(frame, "ipv6: unknown next header=%d\n", ip.next_header);
	}

}

