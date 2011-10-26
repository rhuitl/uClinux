/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "ferret.h"
#include "netframe.h"
#include "formats.h"

#include <ctype.h>
#include <string.h>


void process_callwave_iam(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	if (length > 5) {
		if (ex32le(px+1) == (int)length) {
			unsigned op = px[0];
			process_record(seap,
				"proto",	REC_SZ,			"CallWave-IAM",				-1,
				"op",		REC_UNSIGNED,	&op,						sizeof(op),
				"ip.src",	REC_FRAMESRC,	frame,						-1,
				"length",	REC_UNSIGNED,	&length,					sizeof(length),
				0);

		}
	}
}

