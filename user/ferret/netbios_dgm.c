/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "netframe.h"
#include "formats.h"

#include <ctype.h>
#include <string.h>

unsigned netbios_copy_name(struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned offset, char *name, unsigned sizeof_name)
{
	unsigned j=0;
	unsigned k=0;

	name[0] = '\0';

	while (offset < length) {
		unsigned len;
		len = px[offset++];
		if (len == 0)
			break;
		if (len & 0xc0) {
			if (offset >= length) {
				FRAMERR(frame, "netbios: name too short\n");
				break;
			}
			len = (len << 8) || px[offset++];
			break;
		}

		for (j=0; j<len && offset<length; j++) {
			char c = px[offset++];

			if (c < 'A' || c > 'A'+15)
				FRAMERR(frame, "netbios: bad netbios name char %c (0x%02x) \n", c, c);
			if (k > sizeof_name-1) {
				FRAMERR(frame, "netbios: name too long\n");
				break;
			}
			name[k] = (char)((c-'A')<<4);
			name[k+1] = '\0';
			j++;

			if (offset >= length) {
				FRAMERR(frame, "netbios: name too short\n");
				break;
			}
			c = px[offset++];
			if (c < 'A' || c > 'A'+15)
				FRAMERR(frame, "netbios: bad netbios name char %c (0x%02x) \n", c, c);

			name[k] |= (char)((c-'A')&0x0F);

			if (!isprint(name[k])) {
				if (k+3 > sizeof_name-1) {
					FRAMERR(frame, "netbios: name too long\n");
					break;
				}
				name[k+1] = "0123456789ABCDEF"[(name[k]>>4)&0xF];
				name[k+2] = "0123456789ABCDEF"[(name[k]>>0)&0xF];
				name[k+3] = '>';
				name[k+4] = '\0';
				name[k] = '<';
				k += 4;
			} else
				k++;
		}
	}
	return offset;
}

void process_netbios_dgm(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	struct {
		unsigned type;
		unsigned flags;
		unsigned id;
		unsigned source_ip;
		unsigned source_port;
		unsigned length;
		unsigned offset;
		char source[70];
		char destination[70];
	} netbios;

	if (length == 0) {
		FRAMERR(frame, "netbios: frame empty\n");
		return;
	}
	if (length < 10) {
		FRAMERR(frame, "netbios: frame too short\n");
		return;
	}

	if (px[0] != 0x11) {
		FRAMERR(frame, "netbios: unknown type %d\n", px[0]);
		return;
	}

	netbios.type = px[0];
	netbios.flags = px[1];
	netbios.id = ex16be(px+2);
	netbios.source_ip = ex32be(px+4);
	netbios.source_port = ex16be(px+8);
	netbios.length = ex16be(px+10);
	netbios.offset = ex16be(px+12);

	offset = 14;

	offset = netbios_copy_name(frame, px, length, offset, netbios.source, sizeof(netbios.source));
	offset = netbios_copy_name(frame, px, length, offset, netbios.destination, sizeof(netbios.destination));

	frame->netbios_source = netbios.source;
	frame->netbios_destination = netbios.destination;

	offset += netbios.offset;

	if (offset > length) {
		FRAMERR(frame, "netbios: not enough data\n");
		return;
	}

	if (offset > 4 && memcmp(px+offset, "\xFFSMB", 4) == 0)
		process_smb_dgm(seap, frame, px+offset, length-offset);
	else {
		FRAMERR(frame, "netbios: unknown netbios datagram\n");
		return;
	}
}

