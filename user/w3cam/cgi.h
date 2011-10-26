/*
 * public header for cgi.c
 *
 * Copyright (C) '97,'98 Rasca, Berlin
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define URL_MAX	2048

#define CGI_METHOD_HEAD		1
#define CGI_METHOD_GET		2
#define CGI_METHOD_POST		3
#define CGI_METHOD_PUT		4
#define CGI_METHOD_DELETE	5
#define CGI_METHOD_LINK		6
#define CGI_METHOD_UNLINK	7

#ifndef VER
#define VER "1.1"
#endif

#define MULTIPART_FORM	1

typedef struct {
	int num;
	char *str;
} http_code;

/*
 * http 1.0 and 1.1 status codes
 */
enum {
	http_continue,
	http_ok,
	http_created,
	http_accepted,
	http_non_authoritative,
	http_no_content,
	http_reset_content,
	http_moved_permanently,
	http_moved_temporarily,
	http_not_modyfied,
	http_use_proxy,
	http_bad_request,
	http_unauthorized,
	http_forbidden,
	http_not_found,
	http_gone,
	http_internal_server_error,
	http_not_implemented,
	http_bad_gateway,
	http_service_unavailable,
};

typedef struct {
	char *name;
	char *filename;
	char *data;
	char *content_type;
	char *boundary;
	int content_encoding;
	int content_length;
} mime;

int cgi_init (const char *);
void cgi_response (int status_num, char *content_type);
void cgi_status (int status_num);
const char *cgi_url_ref (void);
const char *cgi_base (void);
const char *cgi_server_software (void);
const char *cgi_server_name (void);
const char *cgi_client_software (void);
const char *cgi_script_name (void);
void cgi_content_type (const char *ct, const char *name);
void cgi_html_start (const char *);
void cgi_html_end (const char *);
void cgi_redirect (const char *);
int cgi_lock (const char *);
int cgi_unlock (const char *);
char **cgi_parse_form (void);
char **cgi_parse_stdin (void);
char **cgi_parse_query (void);
char **cgi_parse_string (const char *s);
char *cgi_form_value (const char *);
char *cgi_cfg_value (const char *);
const char *cgi_logdir();
const char *cgi_sourceURL();
const char *cgi_defaultMTA();
int cgi_content (void);
int cgi_method (void);
char *cgi_gmt_str (long date);
void cgi_refresh (int, char *);
void cgi_multipart (const char *);
