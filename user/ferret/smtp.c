/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "netframe.h"
#include "ferret.h"
#include "formats.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

static int is_command(const char *value, const unsigned char *name, unsigned name_length)
{
	unsigned i;

	for (i=0; i<name_length && value[i]; i++) {
		if (tolower(name[i]) != tolower(value[i]))
			return 0;
	}
	if (i != name_length || value[i] != '\0')
		return 0;

	return 1;
}

void smtp_copy(unsigned char *dst, const unsigned char *src, unsigned src_length)
{
	unsigned dst_length = 128;
	unsigned s,d;

	for (d=0, s=0; d<dst_length && s<src_length; d++, s++) {
		dst[d] = src[s];
		if (isspace(dst[d])) {
			dst[d] = ' ';
			while (s+1<src_length && isspace(src[s+1]))
				s++;
		}
	}

	if (d<dst_length)
		dst[d] = '\0';
	else
		dst[dst_length-1] = '\0';
}

void process_simple_smtp_response(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	seap;frame;px;length;
}

void process_simple_smtp_data(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	unsigned command;
	unsigned command_length;
	unsigned parm;
	unsigned parm_length;

	frame;

	while (offset<length) {

		/* Handle end-of-email '.' issue */
		if (offset<length && px[offset] == '.') {
			if (offset+1<length && px[offset] == '\n' && offset+2<length && px[offset] == '\r' && px[offset+1] == '\n') {
				seap->session->app.smtp.is_body = 0;
				seap->session->app.smtp.is_data = 0;
				return;
			}
		}
		if (seap->session->app.smtp.is_body) {
			while (offset<length && px[offset] != '\n')
				offset++;
			if (offset<length && px[offset] == '\n')
				offset++;
			continue;
		}


		while (offset<length && isspace(px[offset]) && px[offset] != '\n')
			offset++;
		command = offset;
		
		while (offset<length && px[offset] != ':' && px[offset] != '\n')
			offset++;
		command_length = offset-command;
		if (command_length == 0) {
			seap->session->app.smtp.is_body = 1;
			continue;
		}

		while (command_length && isspace(px[offset+command_length]))
			command_length--;
		if (command_length && px[offset+command_length] == ':')
			command_length--;
		while (command_length && isspace(px[offset+command_length]))
			command_length--;
	
		while (offset<length && px[offset] == ':')
			offset++;
		while (offset<length && isspace(px[offset]) && px[offset] != '\n')
			offset++;

		parm = offset;
		if (offset<length && px[offset] == '\n' || offset+1<length && px[offset] == '\r' && px[offset+1] == '\n') {
			seap->session->app.smtp.is_body = 1;
			return;
		}
again:
		while (offset<length && px[offset] != '\n')
			offset++;
		if (offset<length && px[offset] == '\n')
			offset++;
		if (offset<length && px[offset] != '\n' && isspace(px[offset]) && (offset+1<length && px[offset] != '\r' && px[offset] != '\n'))
			goto again;
		parm_length = offset-parm;
		while (parm_length && isspace(px[parm+parm_length-1]))
			parm_length--;

		process_record(seap,
				"proto",			REC_SZ,			"RFC822msg",					-1,
				"header",			REC_PRINTABLE,	px+command,					command_length,
				"value",			REC_PRINTABLE,	px+parm, parm_length,
				"client",			REC_FRAMESRC, frame, -1,
				"server",			REC_FRAMEDST, frame, -1,
				0);
		if (is_command("subject", px+command, command_length)) {
			smtp_copy(seap->session->app.smtp.subject, px+parm, parm_length);
		}
		if (is_command("X-Mailer", px+command, command_length)) {
			process_record(seap,
				"ID-IP",			REC_FRAMESRC,	frame, -1,
				"X-Mailer",			REC_PRINTABLE,  px+parm, parm_length,
				0);
		}
		if (is_command("X-MimeOLE", px+command, command_length)) {
			process_record(seap,
				"ID-IP",			REC_FRAMESRC,	frame, -1,
				"X-MimeOLE",			REC_PRINTABLE,  px+parm, parm_length,
				0);
		}
	}
}

void strip_address(unsigned char **r_parm, unsigned *r_length)
{
	unsigned char *parm = *r_parm;
	unsigned parm_length = *r_length;

		if (parm_length && parm[0] == '<') {
			parm++;
			parm_length--;
		}
		{
			unsigned jj;
			for (jj=0; jj<parm_length && parm[jj] != '>'; jj++)
				;

			printf("");
			parm_length = jj;
		}

	*r_parm = parm;
	*r_length = parm_length;
}


void process_simple_smtp_request(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	char command[16];
	const char *parm;
	unsigned parm_length;
	unsigned i;
	unsigned  x;

	if (seap->session && seap->session->app.smtp.is_data) {
		process_simple_smtp_data(seap, frame, px, length);
		return;
	}

	frame;
	/* Remove leading whitespace */
	for (i=0; i<length && isspace(px[i]); i++)
		;

	/* Grab command */
	x=0;
again:
	while (i<length && !isspace(px[i])) {
		if (x < sizeof(command) -1) {
			command[x++] = (char)toupper(px[i]);
			command[x] = '\0';
		}
		i++;
	}

	/* skip space after command */
	while (i<length && isspace(px[i]))
		i++;

	if (stricmp(command, "mail")==0 || stricmp(command, "rcpt")==0)
		goto again;

	SAMPLE("SMTP", "command", REC_SZ, command, -1);

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

	process_record(seap,
		"proto",			REC_SZ,			"SMTP",					-1,
		"op",				REC_SZ,			command,					-1,
		"parm",				REC_PRINTABLE,	parm, parm_length,
		"client",			REC_FRAMESRC, frame, -1,
		"server",			REC_FRAMEDST, frame, -1,
		0);

	/* test parms */
	if (stricmp(command, "MAILFROM:")==0) {
		strip_address(&parm, &parm_length);

		if (seap->session)
			smtp_copy(seap->session->app.smtp.from, parm, parm_length);

		process_record(seap,
			"ID-IP",			REC_FRAMESRC,	frame, -1,
			"e-mail",			REC_PRINTABLE,  parm, parm_length,
			0);
	}
	if (stricmp(command, "RCPTTO:")==0) {
		strip_address(&parm, &parm_length);

		if (seap->session)
			smtp_copy(seap->session->app.smtp.to, parm, parm_length);
		process_record(seap,
			"ID-IP",			REC_FRAMESRC,	frame, -1,
			"friend",			REC_PRINTABLE,  parm, parm_length,
			0);
	}

	if (stricmp(command, "DATA")==0 && seap->session) {
		seap->session->app.smtp.is_data = 1;
	}
	if (stricmp(command, "RSET")==0 && seap->session) {
		seap->session->app.smtp.is_data = 0;
	}


}
