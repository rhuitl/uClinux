/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "netframe.h"
#include "ferret.h"
#include "formats.h"
#include <string.h>

void process_pptp_linkcontrol(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned code;
	unsigned id;

	if (length < 4) {
		FRAMERR_TRUNCATED(frame, "gre");
		return;
	}

	code = px[0];
	id = px[1];
	length = ex16be(px+2);

	SAMPLE("PPP", "link-control-code", REC_UNSIGNED, &code, sizeof(code));
}

void process_pptp_chap(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned code;
	unsigned id;
	unsigned sublength;
	unsigned offset;

	if (length < 4) {
		FRAMERR_TRUNCATED(frame, "gre");
		return;
	}

	code = px[0];
	id = px[1];
	sublength = ex16be(px+2);
	if (sublength < 4) {
		FRAMERR_BADVAL(frame, "ppp-chap", sublength);
		return;
	}
	offset = 4;

	if (length > sublength)
		length = sublength;

	SAMPLE("PPP", "chap-code", REC_UNSIGNED, &code, sizeof(code));
	switch (code) {
	case 1: /* challenge */
		{
			unsigned value_size;
			const unsigned char *value;

			if (offset+1 >= length) {
				FRAMERR_TRUNCATED(frame, "ppp-chap");
				return;
			}
			value_size = px[offset++];
			if (value_size > length-offset)
				value_size = length-offset;
			value = px+offset;
			offset += value_size;

			switch (value_size) {
			case 16:
				process_record(seap,
					"proto",			REC_SZ,			"PPP",					-1,
					"CHAP",				REC_SZ,			"challenge-v2",			-1,
					"challenge",		REC_HEXSTRING,  value, value_size,
					"name",				REC_PRINTABLE,	px+offset,			length-offset,
					0);
				break;
			case 8:
				process_record(seap,
					"proto",			REC_SZ,			"PPP",					-1,
					"CHAP",				REC_SZ,			"challenge-v1",			-1,
					"challenge",		REC_HEXSTRING,  value, value_size,
					"name",				REC_PRINTABLE,	px+offset,			length-offset,
					0);
				break;
			default:
				FRAMERR_BADVAL(frame, "ppp-chap", value_size);
			}

		}
	}


}

void process_pptp(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned protocol;

	if (length < 4) {
		FRAMERR_TRUNCATED(frame, "gre");
		return;
	}

	if (ex16be(px) == 0xFF03) {
		px+=2;
		length-=2;
	}

	protocol = ex16be(px);
	SAMPLE("PPP", "packet-type", REC_UNSIGNED, &protocol, sizeof(protocol));
	switch (protocol) {
	case 0xc021: /* Link Control Protocol */
		process_pptp_linkcontrol(seap, frame, px+2, length-2);
		break;
	case 0xc223: /* PPP CHAP - Challenge Handshake Authentication protocol */
		process_pptp_chap(seap, frame, px+2, length-2);
		break;
	default:
		; //FRAMERR_UNKNOWN_UNSIGNED(frame, "ppp", protocol);
	}


}

