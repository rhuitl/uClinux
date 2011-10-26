/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "netframe.h"
#include "formats.h"

void process_ip(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	struct {
		unsigned version;
		unsigned header_length;
		unsigned total_length;
		unsigned fragment_length;
		unsigned tos;
		unsigned id;
		unsigned flags;
		unsigned fragment_offset;
		unsigned ttl;
		unsigned protocol;
		unsigned checksum;
		unsigned src_ip;
		unsigned dst_ip;
	} ip;
	if (length == 0) {
		FRAMERR(frame, "ip: frame empty\n");
		return;
	}


	ip.version = px[0]>>4;
	ip.header_length = (px[0]&0xF) * 4;
	ip.tos = ex16be(px+1);
	ip.total_length = ex16be(px+2);
	ip.id = ex16be(px+4);
	ip.flags = px[6]&0xE0;
	ip.fragment_offset = (ex16be(px+6) & 0x3FFF) << 3;
	ip.ttl = px[8];
	ip.protocol = px[9];
	ip.checksum = ex16be(px+10);
	ip.src_ip = ex32be(px+12);
	ip.dst_ip = ex32be(px+16);

	if (ip.fragment_offset != 0)
		return;

	frame->src_ipv4 = ip.src_ip;
	frame->dst_ipv4 = ip.dst_ip;

	if (ip.version != 4) {
		FRAMERR(frame, "ip: version=%d, expected version=4\n", ip.version);
		return;
	}
	if (ip.header_length < 20) {
		FRAMERR(frame, "ip: header length=%d, expected length>=20\n", ip.header_length);
		return;
	}
	if (ip.header_length > length) {
		FRAMERR(frame, "ip: header length=%d, expected length>=%d\n", length, ip.header_length);
		return;
	}

	if (ip.header_length > 20) {
		unsigned o = 20;
		unsigned max = ip.header_length;

		while (o < ip.header_length) {
			unsigned tag = px[o++];
			unsigned len;

			if (tag == 0)
				break;
			if (tag == 1)
				continue;

			if (o >= max) {
				FRAMERR(frame, "ip: options too long\n");
				break;
			}
			len = px[o++];

			if (len < 2) {
				FRAMERR(frame, "ip: invalid length field\n");
				break;
			}
			if (o+len-2 > max) {
				FRAMERR(frame, "ip: options too long\n");
				break;
			}

			switch (tag) {
			case 0x94: /* alert */
				if (len != 4)
					FRAMERR(frame, "ip: bad length, option=%d, length=%d\n", tag, len);
				if (ex16be(px+o) != 0)
					FRAMERR(frame, "ip: bad value, option=%d, length=%d\n", tag, len);
				break;
			default:
				FRAMERR(frame, "ip: unknown option=%d, length=%d\n", tag, len);
			}

			o += len-2;
		}
	}

	offset += ip.header_length;
	if (offset > length) {
		FRAMERR(frame, "ip: header too short, missing %d bytes\n", ip.header_length - length);
		return;
	}


	switch (ip.protocol) {
	case 0x01: /* ICMP */
		process_icmp(seap, frame, px+offset, length-offset);
		break;
	case 0x02: /* IGMP */
		process_igmp(seap, frame, px+offset, length-offset);
		break;
	case 0x11: /* UDP */
		process_udp(seap, frame, px+offset, length-offset);
		break;
	case 0x06:
		process_tcp(seap, frame, px+offset, length-offset);
		break;
	case 47: /* GRE - Generic Router Encapsulation Protocol */
		process_gre(seap, frame, px+offset, length-offset);
		break;
	case 50: /* ESP - Encapsulated Security Protocol */
		break;
	default:
		FRAMERR(frame, "ip: unknown protocol=%d\n", ip.protocol);
	}

}

