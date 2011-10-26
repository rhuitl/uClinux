/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "netframe.h"
#include "ferret.h"
#include "formats.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

static int equals(const unsigned char *px, unsigned name, unsigned name_length, const char *value)
{
	unsigned i;

	for (i=0; i<name_length && value[i]; i++) {
		if (tolower(px[name+i]) != tolower(value[i]))
			return 0;
	}
	if (i != name_length || value[i] != '\0')
		return 0;

	return 1;
}

void process_simple_http(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	char method[16];
	const char *url;
	unsigned url_length;
	unsigned i;
	unsigned  x;
	const char *host=0;
	unsigned host_length=0;
	const char *user_agent=0;
	unsigned user_agent_length=0;

	frame;
	/* Remove leading whitespace */
	for (i=0; i<length && isspace(px[i]); i++)
		;

	/* Grab method */
	x=0;
	while (i<length && !isspace(px[i])) {
		if (x < sizeof(method) -1) {
			method[x++] = (char)toupper(px[i++]);
			method[x] = '\0';
		}
	}

	/* skip space after method */
	while (i<length && isspace(px[i]))
		i++;

	/* Grab url */
	url = (const char*)px+i;
	x=i;
	while (i<length && px[i] != '\n')
		i++;
	url_length = i-x;

	if (url_length && url[url_length-1] == '\n')
		url_length--;
	if (url_length && url[url_length-1] == '\r')
		url_length--;

	/* Remove trailing HTTP/ver from URL */
	{
		int j=url_length;

		if (isdigit(url[j-1])) {
			while (j && isdigit(url[j-1]))
				j--;
			if (j && url[j-1] == '.') {
				j--;
				if (isdigit(url[j-1])) {
					while (j && isdigit(url[j-1]))
						j--;
					if (j && url[j-1] == '/') {
						j--;
						if (j>4 && memicmp(url+j-4, "HTTP", 4)==0)
							j-=4;
						if (j && isspace(url[j-1])) {
							while (j && isspace(url[j-1]))
								j--;
							url_length = j;
						}
					}
				}
			}
		}
	}

	i++;

	while (i<length) {
		unsigned name=i;
		unsigned name_length;
		unsigned value;
		unsigned value_length;

		name=i;
		while (i<length && px[i] != ':' && px[i] != '\n')
			i++;
		name_length = i-name;
		while (name_length && isspace(px[name+name_length-1]))
			name_length--;

		if (name_length == 0)
			break;

		if (i<length && px[i] == ':')
			i++;
		while (i<length && px[i] != '\n' && isspace(px[i]))
			i++;
		value = i;
		while (i<length && px[i] != '\n')
			i++;
		value_length = i-value;

		while (value_length && isspace(px[value+value_length-1]))
			value_length--;

		if (i<length && px[i] == '\n')
			i++;

		if (equals(px,name,name_length, "Host")) {
			host = (const char*)(px+value);
			host_length = value_length;
		}
		if (equals(px,name,name_length, "User-Agent")) {
			user_agent = (const char*)(px+value);
			user_agent_length = value_length;
		}
	}


	if (host) {
		process_record(seap,
			"proto",			REC_SZ,			"HTTP",					-1,
			"op",				REC_SZ,			method,					-1,
			"Host",				REC_PRINTABLE,  host,					host_length,
			"URL",				REC_PRINTABLE,	url,					url_length,
			0);
	} else {
		process_record(seap,
			"proto",			REC_SZ,			"HTTP",					-1,
			"op",				REC_SZ,			method,					-1,
			"Host",				REC_FRAMEDST,	frame, -1,
			"URL",				REC_PRINTABLE,	url,					url_length,
			0);
	}

	if (user_agent && user_agent_length)
		process_record(seap,
			"ID-IP",			REC_FRAMESRC,	frame, -1,
			"User-Agent",		REC_PRINTABLE,  user_agent,				user_agent_length,
			0);

}
