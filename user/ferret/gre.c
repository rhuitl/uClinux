/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "netframe.h"
#include "ferret.h"
#include "formats.h"
#include <string.h>


void process_gre_pptp(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned flags;
	unsigned offset;
	unsigned payload_length;
	unsigned call_id;
	unsigned sequence_number;
	unsigned acknowledgement_number;


	/*
		0                   1                   2                   3
		0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |C|R|K|S|s|Recur|A| Flags | Ver |         Protocol Type         |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |    Key (HW) Payload Length    |       Key (LW) Call ID        |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                  Sequence Number (Optional)                   |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |               Acknowledgment Number (Optional)                |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
	flags = ex16be(px);
	payload_length = ex16be(px+4);
	call_id = ex16be(px+6);

	if ((flags&0xE80F) != 0x2001) {
		FRAMERR_UNKNOWN_UNSIGNED(frame, "gre", flags);
		return;
	}

	offset = 8;
	if (flags & 0x1000) {
		sequence_number = ex32be(px+offset);
		offset += 4;
	}
	if (flags & 0x0080) {
		acknowledgement_number = ex32be(px+offset);
		offset += 4;
	}
	if (offset >= length) {
		FRAMERR_TRUNCATED(frame, "gre");
		return;
	}


	process_pptp(seap, frame, px+offset, length-offset);


}


void process_gre(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned flags;
	unsigned version;
	unsigned protocol;
	unsigned offset;
	
/*
      0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |C|R|K|S|s|Recur|  Flags  | Ver |         Protocol Type         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |      Checksum (optional)      |       Offset (optional)       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         Key (optional)                        |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                    Sequence Number (optional)                 |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         Routing (optional)
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

	if (length < 8) {
		FRAMERR_TRUNCATED(frame, "gre");
		return;
	}

	flags = ex16be(px);
	version = px[1]&0x7;
	protocol = ex16be(px+2);

	offset = 4;

	if (version == 1 && protocol == 0x880b)
		process_gre_pptp(seap, frame, px, length);
	else {
		FRAMERR_UNKNOWN_UNSIGNED(frame, "gre", version);
	}


}

