/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "ferret.h"
#include "netframe.h"
#include "formats.h"

#include <ctype.h>

void extract_num(const unsigned char *px, unsigned length, unsigned *r_offset, unsigned *r_num)
{
	*r_num = 0;

	while (*r_offset<length && isspace(px[*r_offset]))
		(*r_offset)++;
	while (*r_offset<length && isdigit(px[*r_offset])) {
		(*r_num) *= 10;
		(*r_num) += px[*r_offset] - '0';
		(*r_offset)++;
	}
	while (*r_offset<length && isspace(px[*r_offset]))
		(*r_offset)++;
}

void extract_string(const unsigned char *px, unsigned length, unsigned *r_offset, const unsigned char **r_start, unsigned *r_length)
{
	unsigned quoted=0;
	*r_length = 0;

	if (*r_offset >= length)
		return;

	if (px[*r_offset] == '\"') {
		quoted = 1;
		(*r_offset)++;
	}
	*r_start = px+*r_offset;

	while (*r_offset < length) {
		if (quoted) {
			if (px[*r_offset] == '\"') {
				(*r_offset)++;
				break;
			}
		} else {
			if (isspace(px[*r_offset]))
				break;
		}

		(*r_offset)++;
		(*r_length)++;
	}

	while (*r_offset<length && isspace(px[*r_offset]))
		(*r_offset)++;
}
void process_cups(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset = 0;
	unsigned type=0;
	unsigned state = 0;
	unsigned char *uri;
	unsigned uri_length;
	unsigned char *location;
	unsigned location_length;
	unsigned char *information;
	unsigned information_length;
	unsigned char *model;
	unsigned model_length;

	extract_num(px, length, &offset, &type);
	extract_num(px, length, &offset, &state);

	extract_string(px, length, &offset, &uri, &uri_length);
	extract_string(px, length, &offset, &location, &location_length);
	extract_string(px, length, &offset, &information, &information_length);
	extract_string(px, length, &offset, &model, &model_length);

	process_record(seap,
			"proto",	REC_SZ,			"CUPS",				-1,
			"ip.src",	REC_FRAMESRC,	frame, -1,
			"type",		REC_UNSIGNED,	&type, sizeof(type),
			0);
	process_record(seap,
			"proto",	REC_SZ,			"CUPS",				-1,
			"ip.src",	REC_FRAMESRC,	frame, -1,
			"state",	REC_UNSIGNED,	&state, sizeof(state),
			0);
	process_record(seap,
			"proto",	REC_SZ,			"CUPS",				-1,
			"ip.src",	REC_FRAMESRC,	frame, -1,
			"uri",		REC_PRINTABLE,	uri, uri_length,
			0);
	process_record(seap,
			"proto",	REC_SZ,			"CUPS",				-1,
			"ip.src",	REC_FRAMESRC,	frame, -1,
			"location",		REC_PRINTABLE,	location, location_length,
			0);
	process_record(seap,
			"proto",	REC_SZ,			"CUPS",				-1,
			"ip.src",	REC_FRAMESRC,	frame, -1,
			"info",		REC_PRINTABLE,	information, information_length,
			0);
	process_record(seap,
			"proto",	REC_SZ,			"CUPS",				-1,
			"ip.src",	REC_FRAMESRC,	frame, -1,
			"model",	REC_PRINTABLE,	model, model_length,
			0);
}

