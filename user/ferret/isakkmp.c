/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "netframe.h"
#include "ferret.h"
#include "formats.h"
#include <string.h>


void process_isakmp(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned type;

	if (length < 1) {
		FRAMERR_TRUNCATED(frame, "isakmp");
		return;
	}

	type = px[0];
	SAMPLE("ISAKMP", "type", REC_UNSIGNED, &type, sizeof(type));

	switch (type) {
	case 0xFF: /* keep alive */
		break;
	default:
		FRAMERR_UNKNOWN_UNSIGNED(frame, "isakmp", type);
		break;
	}
}

