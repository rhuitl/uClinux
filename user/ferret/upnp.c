/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "ferret.h"
#include "netframe.h"
#include "formats.h"
#include <ctype.h>
#include <string.h>

void process_upnp_response(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;

	while (offset < length) {
		const unsigned char *line = px+offset;
		unsigned line_length;

		for (line_length=0; offset+line_length < length && px[offset+line_length] != '\n'; line_length++)
			;
		offset += line_length;
		if (offset<length && px[offset] == '\n')
			offset++;
		while (line_length && isspace(line[line_length-1]))
			line_length--;

		if (line_length>3 && memicmp(line, "ST:", 3) == 0) {
			process_record(seap,
				"proto",	REC_SZ,			"upnp",				-1,
				"ip.src",	REC_FRAMESRC,	frame,				-1,
				"ST",		REC_PRINTABLE,	line+3, line_length-3,
				0);
		}
	}
}


