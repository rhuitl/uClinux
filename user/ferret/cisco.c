/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "netframe.h"
#include "formats.h"
#include "ferret.h"
#include <ctype.h>


#include <string.h>

/*
 * Cisco Discovery Protocol 
 */
static void process_CDP(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	unsigned version;
	unsigned ttl;
	unsigned checksum;

	if (offset+4 > length) {
		FRAMERR(frame, "%s: truncated\n", "cisco");
		return;
	}

	version = px[offset++];
	ttl = px[offset++];
	checksum = ex16be(px+2);
	offset += 2;

	SAMPLE("Cisco Discovery Protocol", "version", REC_UNSIGNED, &version, sizeof(version));

	while (offset < length) {
		unsigned tag;
		unsigned len;
		unsigned i;

		if (offset+4 > length) {
			FRAMERR(frame, "%s: truncated\n", "cisco");
			return;
		}

		tag = ex16be(px+offset);
		len = ex16be(px+offset+2);
		offset += 4;

		if (len < 4) {
			FRAMERR(frame, "%s: bad value: 0x%x\n", "cdp", tag);
			return;
		} else
			len -= 4;

		if (len > length-offset)
			len = length-offset;
		
		SAMPLE("Cisco Discovery Protocol", "tag", REC_UNSIGNED, &tag, sizeof(tag));

		switch (tag) {
		case 0x0000:
			return;
		case 0x0001: /* Device ID */
			process_record(seap, 
				"ID-MAC",REC_MACADDR,frame->src_mac, 6,
				"Cisco Device ID",REC_PRINTABLE,px+offset,len,
				0);
			break;
		case 0x0002: /* Addresses */
			if (len < 4) {
				FRAMERR(frame, "%s: truncated\n", "cdp");
				break;
			}
			i=0;
			{
				unsigned address_count = ex32be(px+offset);

				i += 4;

				while (address_count && i<len) {
					unsigned protocol_type;
					unsigned protocol_length;
					unsigned protocol = 0;
					unsigned address_length;
					if (i-len < 5)
						break;
					address_count--;

					protocol_type = px[offset+i++];
					protocol_length = px[offset+i++];
					if (protocol_length != 1)
						FRAMERR(frame, "%s: unknown value: 0x%x\n", "cdp", protocol_length);
					while (protocol_length && i<len) {
						protocol <<= 8;
						protocol |= px[offset+i++];
						protocol_length--;
					}
					address_length = ex16be(px+offset+i);
					i+= 2;
					switch (protocol_type) {
					case 1:
						switch (protocol) {
						case 0xCC: /*IPv4 address */
							if (address_length != 4)
								FRAMERR(frame, "%s: unknown value: 0x%x\n", "cdp", address_length);
							else if (len-i < 4)
								FRAMERR(frame, "%s: truncated\n", "cdp");
							else {
								unsigned ip = ex32be(px+offset+i);
								process_record(seap, 
									"ID-MAC",REC_MACADDR,frame->src_mac, 6,
									"ip",REC_IPv4, &ip, sizeof(ip),
									0);
								process_record(seap, 
									"ID-IP",REC_IPv4, &ip, sizeof(ip),
									"mac",REC_MACADDR,frame->src_mac, 6,
									0);
							}
							break;
						default:
							SAMPLE("CDP", "ip-protocol-type", REC_UNSIGNED, &protocol, sizeof(unsigned));
							FRAMERR(frame, "%s: unknown value: 0x%x\n", "cdp", protocol);
						}
						break;
					default:
						SAMPLE("CDP", "address-protocol-type", REC_UNSIGNED, &protocol_type, sizeof(unsigned));
						FRAMERR(frame, "%s: unknown value: 0x%x\n", "cdp", protocol_type);
						break;
					}
				}
			}


			break;
		case 0x0003: /* Port ID*/
			process_record(seap, 
				"ID-MAC",REC_MACADDR,frame->src_mac, 6,
				"Cisco Port ID",REC_PRINTABLE,px+offset,len,
				0);
			break;
		case 0x0004:
			{
				unsigned n = 0;

				for (i=0; i<len; i++) {
					n <<= 8;
					n |= px[offset + i];
				}
				if (n & 0x00000001)
					process_record(seap, "ID-MAC",REC_MACADDR,frame->src_mac, 6, "Capabilities", REC_SZ, "router", -1, 0);
				if (n & 0x00000002)
					process_record(seap, "ID-MAC",REC_MACADDR,frame->src_mac, 6, "Capabilities", REC_SZ, "bridge", -1, 0);
				if (n & 0x00000004)
					process_record(seap, "ID-MAC",REC_MACADDR,frame->src_mac, 6, "Capabilities", REC_SZ, "source route bridge", -1, 0);
				if (n & 0x00000008)
					process_record(seap, "ID-MAC",REC_MACADDR,frame->src_mac, 6, "Capabilities", REC_SZ, "switch", -1, 0);
				if (n & 0x00000010)
					process_record(seap, "ID-MAC",REC_MACADDR,frame->src_mac, 6, "Capabilities", REC_SZ, "host", -1, 0);
				if (n & 0x00000020)
					process_record(seap, "ID-MAC",REC_MACADDR,frame->src_mac, 6, "Capabilities", REC_SZ, "IGMP", -1, 0);
				if (n & 0x00000040)
					process_record(seap, "ID-MAC",REC_MACADDR,frame->src_mac, 6, "Capabilities", REC_SZ, "repeater", -1, 0);
			}
			break;
		case 0x0005: /* IOS Version */
			for (i=0; i<len; i++)
				if (!isspace(px[offset+i]))
					break;
			process_record(seap, 
				"ID-MAC",REC_MACADDR,frame->src_mac, 6,
				"IOS Version",REC_PRINTABLE,px+offset+i,len-i,
				0);
			break;
		case 0x0006: /* Platform*/
			process_record(seap, 
				"ID-MAC",REC_MACADDR,frame->src_mac, 6,
				"Cisco Platform",REC_PRINTABLE,px+offset,len,
				0);
			break;
		default:
			FRAMERR(frame, "%s: unknown value: 0x%x\n", "cdp", tag);
		}

		offset += len;
		
	}
}

void process_cisco00000c(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	unsigned pid;

	if (offset+2 > length) {
		FRAMERR(frame, "%s: truncated\n", "cisco");
		return;
	}

	pid = ex16be(px);
	SAMPLE("Cisco", "0x00000c-pid", REC_UNSIGNED, &pid, sizeof(pid));
	offset+= 2;

	switch (pid) {
	case 0x2000:
		process_CDP(seap, frame, px+offset, length-offset);
		break;
	default:
		FRAMERR(frame, "%s: unknown value: 0x%x\n", "cisco", pid);
	}
}

