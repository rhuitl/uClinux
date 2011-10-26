/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "netframe.h"
#include "ferret.h"
#include "formats.h"

#include <string.h>

struct SNMP
{
	unsigned version;
	unsigned pdu_tag;
	const unsigned char *community;
	unsigned community_length;
	unsigned request_id;
	unsigned error_index;
	unsigned error_status;
};

const unsigned snmp_length(struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned *r_offset)
{
	unsigned result;

	if ( (*r_offset >= length) 
		|| (px[*r_offset] & 0x80) 
		&& ((*r_offset) + (px[*r_offset]&0x7F) >= length)) {
		FRAMERR(frame, "snmp: truncated\n");
		*r_offset = length;
		return 0xFFFFffff;
	}
	result = px[(*r_offset)++];
	if (result & 0x80) {
		unsigned length_of_length = result & 0x7F;
		if (length_of_length == 0) {
			FRAMERR(frame, "snmp: unexpected value\n");
			*r_offset = length;
			return 0xFFFFffff;
		}
		result = 0;
		while (length_of_length) {
			result = result * 256 + px[(*r_offset)++];
			if (result > 0x10000) {
				FRAMERR(frame, "snmp: unexpected value\n");
				*r_offset = length;
				return 0xFFFFffff;
			}
		}
	}
	return result;
}
const unsigned snmp_integer(struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned *r_offset)
{
	unsigned int_length;
	unsigned result;

	if (px[(*r_offset)++] != 0x02) {
		FRAMERR(frame, "snmp: unexpected tag\n");
		*r_offset = length;
		return 0xFFFFffff;
	}

	int_length = snmp_length(frame, px, length, r_offset);
	if (int_length == 0xFFFFffff) {
		*r_offset = length;
		return 0xFFFFffff;
	}
	if (*r_offset + int_length > length) {
		FRAMERR(frame, "snmp: truncated\n");
		*r_offset = length;
		return 0xFFFFffff;
	}

	result = 0;
	while (int_length--)
		result = result * 256 + px[(*r_offset)++];

	return result;
}

static unsigned snmp_tag(const unsigned char *px, unsigned length, unsigned *r_offset)
{
	if (*r_offset >= length)
		return 0;
	return px[(*r_offset)++];
}

void process_snmp(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	unsigned outer_length;
	struct SNMP snmp[1];

	memset(&snmp, 0, sizeof(*snmp));

	/* tag */
	if (snmp_tag(px, length, &offset) != 0x30)
		return;

	/* length */
	outer_length = snmp_length(frame, px, length, &offset);
	if (length > outer_length + offset)
		length = outer_length + offset;

	/* Version */
	snmp->version = snmp_integer(frame, px, length, &offset);
	if (snmp->version != 0)
		return;

	/* Community */
	if (snmp_tag(px, length, &offset) != 0x04)
		return;
	snmp->community_length = snmp_length(frame, px, length, &offset);
	snmp->community = px+offset;
	offset += snmp->community_length;

	/* PDU */
	snmp->pdu_tag = snmp_tag(px, length, &offset);
	if (snmp->pdu_tag < 0xA0 || 0xA5 < snmp->pdu_tag)
		return;
	outer_length = snmp_length(frame, px, length, &offset);
	if (length > outer_length + offset)
		length = outer_length + offset;

	/* Request ID */
	snmp->request_id = snmp_integer(frame, px, length, &offset);
	snmp->error_status = snmp_integer(frame, px, length, &offset);
	snmp->error_index = snmp_integer(frame, px, length, &offset);

	/* Varbind List */
	if (snmp_tag(px, length, &offset) != 0x30)
		return;
	outer_length = snmp_length(frame, px, length, &offset);
	if (length > outer_length + offset)
		length = outer_length + offset;

	/* Var-bind list */
	while (offset < length) {
		unsigned varbind_length;
		unsigned varbind_end;
		if (px[offset++] != 0x30) {
			FRAMERR(frame, "snmp: unexpected value\n");
			break;
		}
		varbind_length = snmp_length(frame, px, length, &offset);
		if (varbind_length == 0xFFFFffff)
			break;
		varbind_end = offset + varbind_length;
		if (varbind_end > length) {
			FRAMERR(frame, "snmp: unexpected value\n");
			return;
		}
		
		/* OID */
		if (snmp_tag(px,length,&offset) != 6)
			return;
		else {
			unsigned oid_length = snmp_length(frame, px, length, &offset);
			const unsigned char *oid = px+offset;
			unsigned value_tag;
			unsigned value_length;

			offset += oid_length;
			if (offset > length)
				return;

			value_tag = snmp_tag(px,length,&offset);
			value_length = snmp_length(frame, px, length, &offset);
		
			switch (snmp->pdu_tag) {
			case 0xA0:
				process_record(seap, 
					"proto",REC_SZ,"SNMP",-1,
					"GET", REC_FRAMESRC,	frame, -1,
					"community",REC_PRINTABLE, snmp->community, snmp->community_length,
					0);
				process_record(seap, 
					"proto",REC_SZ,"SNMP",-1,
					"GET", REC_FRAMESRC,	frame, -1,
					"oid",REC_OID, oid, oid_length,
					0);
				break;
			default:
				FRAMERR(frame, "snmp: unknown msg type\n");
			}

		}

	}

}

