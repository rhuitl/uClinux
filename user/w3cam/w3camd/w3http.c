/*
 * w3http.c
 *
 * Copyright (C) 1998 - 2000 Rasca, Berlin
 * EMail: thron@gmx.de
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "w3http.h"

static http_code _http_status[] = {
	{100,	"Continue", 				sizeof("Continue")},
	{101,	"Switching Protocols",		sizeof("Switching Protocols")},
	{200,	"Ok",						sizeof("Ok")},
	{201,	"Created",					sizeof("Created")},
	{202,	"Accepted",					sizeof("Accepted")},
	{204,	"No Content",				sizeof("No Content")},
	{400,	"Bad Request",				sizeof("Bad Request")},
	{500,	"Internal Server Error",	sizeof("Internal Server Error")},
};

static http_code _http_header[] = {
	{HTTP_SERVER,		"Server: ",			sizeof ("Server: ")},
	{HTTP_CONTENT_TYPE,	"Content-Type: ",	sizeof ("Content-type: ")},
	{HTTP_CONTENT_LENGTH,"Content-Length: ",sizeof ("Content-length: ")},
	{HTTP_MIME_VERSION,	"MIME-Version: ",	sizeof ("MIME-Version: ")},
	{HTTP_EXPIRES,		"Expires: ",		sizeof ("Expires: ")},
	{HTTP_HEADER_END,	"\r\n",				sizeof ("\r\n")},
};

#define HTTP_PROTOCOL "HTTP/1.1"

#define STATUS_CHECK(n) if (n <0 || n>=HTTP_STATUS_END) no = HTTP_SERVER_ERROR;
#define STATUS_ASSIGN(n,c) c = &_http_status[no];

#define HEADER_CHECK(n) if (n <0 || n> HTTP_HEADER_END) no = HTTP_CONTENT_TYPE;
#define HEADER_ASSIGN(n,c) c = &_http_header[no];

/*
 */
int
http_status (int fd, int no)
{
	http_code *c;
	char buf[128];
	int rc;

	STATUS_CHECK(no);
	STATUS_ASSIGN(no,c);

	sprintf (buf, HTTP_PROTOCOL" %d %s\r\n", c->num, c->str);
	rc = write (fd, buf, strlen(buf));
	return (rc);
}

/*
 */
int
http_header (int fd, int no, char *value)
{
#define MAX_HEADER	2048
	http_code *c;
	char buf[MAX_HEADER+3];
	int rc, len;

	HEADER_CHECK(no);
	HEADER_ASSIGN(no,c);

	sprintf (buf, "%s", c->str);
	rc = write (fd, buf, strlen(buf));

	if (value) {
		len = strlen (value);
		if (len > MAX_HEADER)
			value = "--buffer too short!--";
		sprintf (buf, "%s\r\n", value);
		rc += write (fd, buf, strlen(buf));
	}
	return (rc);
}

/*
 */
static char *
hex_to_asc (const char *str, int len)
{
	char *p, *s;
	char buff[4];
	int chr;

	if (!str)
		return (NULL);
	s = (char *) malloc (len + 1);
	p = s;
	buff[2] = '\0';
	while (*str && len) {
		if (*str == '%') {
			strncpy (buff, str+1, 2);
			sscanf (buff, "%02X", &chr);
			*p = (unsigned char) chr;
			str += 3;
			len -= 3;
		} else {
			if (*str == '+')
				*p = ' ';
			else
				*p = *str;
			str++;
			len--;
		}
		p++;
	}
	*p = '\0';
	return (s);
}


/*
 */
static char **
parse_string (const char *str)
{
	char **kv = NULL;
	const char *p, *end;
	int num = 1, i;
	int len;

	if (!str)
		return (NULL);
	p = str;
	while ((p = strchr (p, '&')) != NULL) {
		num++;
		p++;
	}
	kv = (char **) calloc ((num * 2 +1), sizeof (char **));
	p = str;
	i = 0;
	do {
		len = 0;
		if (*p == '&') {
			p++;
		}
		end = p;
		while ((*end != '=') && (*end != '\0') && (*end != '&')) {
			len++;
			end++;
		}
		kv[i] = hex_to_asc (p, len);
		if (*end == '&') {
			/* variable has no value .. */
			p += len;
			i++;
			continue;
		}
		p += len+1;
		end = p;
		i++;
		len = 0;
		while ((*end != '&') && (*end != '\0')) {
			len++;
			end++;
		}
		kv[i] = hex_to_asc (p, len);
		if (len > 0)
			p++;
		i++;
	} while ((p = strchr (p, '&')) != NULL);
	return (kv);
}

/*
 */
char *
http_parse (char *buf, char ***args)
{
	char *url, *ep;
	int len;

	if (strncasecmp (buf, "GET ", 4))
		return (NULL);
	ep = strstr (buf, " HTTP/");
	if (!ep)
		ep = strstr (buf, " http/");
	if (!ep)
		return (NULL);

	len = ep - buf - 4;
	url = malloc (len+1);
	if (!url)
		return (NULL);
	strncpy (url, buf+4, len);
	url[len] = '\0';
	if (args) {
		char *p;
		if ((p = strchr (url, '?')) != NULL) {
			*args = parse_string (p+1);
		}
	}
#ifdef DEBUG2
	printf ("%s: get_url() buf=%s\n", __FILE__, buf);
#endif
	return (url);
}

/*
 */
char *
http_arg_val (char **args, char *key)
{
	char *val = NULL;
	if (!args)
		return (NULL);
	if (!key)
		return (NULL);
	while (*args) {
		if (strcmp (key, *args) == 0)
			return (*(args+1));
		args += 2;
	}
	return (val);
}

/*
 */
void
http_free_args (char **args)
{
	char **p;
	if (args) {
		p = args;
		while (*p) {
			free (*p++);
		}
		free (args);
	}
}

