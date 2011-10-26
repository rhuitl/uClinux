/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "netframe.h"
#include "ferret.h"
#include "formats.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

void process_simple_pop3_response(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	seap;frame;px;length;
}

void process_simple_pop3_request(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	char command[16];
	const char *parm;
	unsigned parm_length;
	unsigned i;
	unsigned  x;

	frame;
	/* Remove leading whitespace */
	for (i=0; i<length && isspace(px[i]); i++)
		;

	/* Grab command */
	x=0;
	while (i<length && !isspace(px[i])) {
		if (x < sizeof(command) -1) {
			command[x++] = (char)toupper(px[i++]);
			command[x] = '\0';
		}
	}

	/* skip space after command */
	while (i<length && isspace(px[i]))
		i++;

	/* Grab parm */
	parm = (const char*)px+i;
	x=i;
	while (i<length && px[i] != '\n')
		i++;
	parm_length = i-x;

	if (parm_length && parm[parm_length-1] == '\n')
		parm_length--;
	if (parm_length && parm[parm_length-1] == '\r')
		parm_length--;

	SAMPLE("POP3", "command", REC_SZ, command, -1);

	process_record(seap,
		"proto",			REC_SZ,			"POP3",					-1,
		"op",				REC_SZ,			command,					-1,
		"parm",				REC_PRINTABLE,	parm, parm_length,
		"client",			REC_FRAMESRC, frame, -1,
		"server",			REC_FRAMEDST, frame, -1,
		0);

	/* test parms */
	if (stricmp(command, "USER")==0) {
		process_record(seap,
			"ID-IP",			REC_FRAMESRC,	frame, -1,
			"pop3-user",		REC_PRINTABLE,  parm, parm_length,
			0);
	}
	if (stricmp(command, "PASS")==0) {
		process_record(seap,
			"ID-IP",			REC_FRAMESRC,	frame, -1,
			"pop3-passwd",		REC_PRINTABLE,  parm, parm_length,
			0);
	}
}
