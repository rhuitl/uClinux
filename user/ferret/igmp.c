/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "ferret.h"
#include "netframe.h"
#include "formats.h"


static const char *group_name(struct NetFrame *frame, unsigned group_address)
{
	switch (group_address) {
	case 0xeffffffa: return "SSDP"; break;
	case 0xe00000fb: return "mDNS"; break;
	case 0xe0000116: return "SLP (General)"; break;
	case 0xe0000123: return "SLP (Discovery)"; break;
	case 0xe4c8c8c9: return "(unknown)"; break;
	case 0xeffffffd: return "SLP (Admin Scoped)"; break;
	default: 
		FRAMERR(frame, "igmp: unknown group: %d.%d.%d.%d\n", 
			(group_address>>24)&0xFF,
			(group_address>>16)&0xFF,
			(group_address>> 8)&0xFF,
			(group_address>> 0)&0xFF
			);
		return "(unknown)";
	}
}
void process_igmp(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct {
		unsigned version;
		unsigned type;
		unsigned max_resp_time;
		unsigned checksum;
		unsigned group_address;
	} igmp;

	if (length == 0) {
		FRAMERR(frame, "igmp: frame empty\n");
		return;
	}
	if (length < 8) {
		FRAMERR(frame, "igmp: frame too short\n");
		return;
	}

	igmp.type = px[0];
	igmp.max_resp_time = px[1];
	igmp.checksum = ex16be(px+2);
	igmp.group_address = ex32be(px+4);

	switch (igmp.type) {
	case 0x11: /* membership query */
		break;
	case 0x16: /* membership report */
		process_record(seap,
			"proto",	REC_SZ,			"IGMP",				-1,
			"op",		REC_SZ,			"Membership",		-1,
			"group",	REC_IPv4,		&igmp.group_address,	sizeof(igmp.group_address),
			"groupname",REC_SZ,			group_name(frame, igmp.group_address),	-1,
			0);
		break;
	case 0x17:
		process_record(seap,
			"proto",	REC_SZ,			"IGMP",				-1,
			"op",		REC_SZ,			"Membership",		-1,
			"group",	REC_IPv4,		&igmp.group_address,	sizeof(igmp.group_address),
			"groupname",REC_SZ,			group_name(frame, igmp.group_address),	-1,
			0);
		break;
	case 0x22: /*v3 membersip report */
		{
			unsigned num_records = ex16be(px+6);
			unsigned i;
			unsigned offset=8;

			if (num_records != 1) 
				SAMPLE("igmp", "igmpv3.numrecs",	REC_UNSIGNED, &num_records,	sizeof(num_records));

			for (i=0; i<num_records && offset+8 <= length; i++) {
				unsigned ip = ex32be(px+offset+4);
				unsigned sources = ex16be(px+offset+2);
				unsigned aux_data_len = px[offset+1]*4;
				process_record(seap,
					"proto",	REC_SZ,			"IGMP",				-1,
					"op",		REC_SZ,			"Membership",		-1,
					"group",	REC_IPv4,		&ip,	sizeof(ip),
					"groupname",REC_SZ,			group_name(frame, ip),	-1,
					0);
				offset += sources*4+aux_data_len+8;
			}
		}
		break;
	default:
		FRAMERR(frame, "igmp: unknown type=%d\n", igmp.type);
		break;
	}
}

