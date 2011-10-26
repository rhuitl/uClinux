/*
 * w3http.h
 *
 * Copyright (C) 1998 Rasca, Berlin
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

#ifndef __W3HTTP_H__
#define __W3HTTP_H__

typedef struct {
	int num;
	char *str;
	int len;
} http_code ;

/* status types */
enum {
	HTTP_CONTINUE,
	HTTP_SWITCHING_PROTOCOLS,
	HTTP_OK,
	HTTP_CREATED,
	HTTP_ACCEPTED,
	HTTP_NO_CONTENT,
	HTTP_BAD_REQUEST,
	HTTP_SERVER_ERROR,
	HTTP_STATUS_END,
};

/* header types */
enum {
	HTTP_SERVER,
	HTTP_CONTENT_TYPE,
	HTTP_CONTENT_LENGTH,
	HTTP_MIME_VERSION,
	HTTP_EXPIRES,
	HTTP_HEADER_END,
};

int http_status (int, int);
int http_header (int, int, char *);
char *http_parse (char *, char ***);
char *http_arg_val (char **, char *);
void http_free_args (char **);

#endif
