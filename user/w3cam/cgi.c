/*
 * CGI C-library, v1.1.1
 *
 * Copyright (C) '97,'98,'.. Rasca, Berlin
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

#include <stdlib.h>		/* getenv() */
#include <stdio.h>		/* printf() */
#include <string.h>		/* strcat() */
#include <limits.h>		/* PATH_MAX */
#include <unistd.h>		/* getpid() */
#include <sys/stat.h>	/* stat() */
#include <sys/utsname.h>/* uname() */
#include <time.h>		/* time() */
#include "cgi.h"

#define MAX_LINE	1024
#define EMPTY		'\0'

static char *cgi_background = NULL;
static char *cgi_foreground = NULL;
static char *cgi_stylesheet = NULL;
static char *cgi_source_url = NULL;
static char *cgi_loggingdir = NULL;
static char *cgi_defaultmta = NULL;
static char *cgi_bottomline = NULL;
static char *cgi_meta_desc = NULL;
static char *cgi_meta_keyw = NULL;
static char **cgi_form = NULL;
static char **cgi_cfg = NULL;
static char *program = NULL;
static const char *prog_wp = NULL;
static int  run_as_nph = 0;
static int  cgi_refresh_time = 0;
static char *cgi_refresh_url = 0;

/* http 1.0 status codes
 */
static http_code http[] =
	{ /*
	status code, reason-phrase
		*/
	{ 100, "Continue" },						/* 1.1 */
    { 200, "Ok" },
    { 201, "Created" },
    { 202, "Accepted" },
	{ 203, "Non-Authoritative Information"},	/* 1.1 */
    { 204, "No Content" },
	{ 205, "Reset Content" },					/* 1.1 */
    { 301, "Moved Permanently" },
    { 302, "Moved Temporarily" },
    { 304, "Not Modified" },
	{ 305, "Use Proxy" },						/* 1.1 */
    { 400, "Bad Request" },
    { 401, "Unauthorized" },
    { 403, "Forbidden" },
    { 404, "Not Found" },
	{ 410, "Gone" },							/* 1.1 */
    { 500, "Internal Server Error" },
    { 501, "Not Implemented" },
    { 502, "Bad Gateway" },
    { 503, "Service Unavailable" },
    { 000, NULL },
    };

/*
 * return RFC 822, 1123 date string
 * next call will override previous value!
 */
char *
cgi_gmt_str (long date)
{
	char *day[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
	char *mon[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
				    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	static char str[48];	/* should be enough */
	struct tm *s;

	s = gmtime (&date);
	sprintf (str, "%s, %02d %s %d %02d:%02d:%02d GMT", day[s->tm_wday],
			s->tm_mday, mon[s->tm_mon], s->tm_year + 1900, s->tm_hour,
			s->tm_min, s->tm_sec);
	return (str);
}


/*
 * returns the url, where the cgi is included/started
 */
const char *
cgi_url_ref ()
{
	char *url;
	static char urlb[URL_MAX+1];

	url = getenv ("HTTP_REFERER");
	if (!url) {
		/* not CGI conform, but try ..
		 */
		url = getenv ("REFERER_URL");
	}
	if (!url) {
		url = getenv ("DOCUMENT_URI");
		if (url) {
			urlb[0] = '\0';
			strcat (urlb, "http://");
			strcat (urlb, cgi_server_name());
			strcat (urlb, ":");
			strcat (urlb, getenv("SERVER_PORT"));
			strcat (urlb, url);
			url = urlb;
		} else {
			const char *server;
			/* may be lynx is starting local CGIs ..? */
			server = cgi_server_software();
			if (server && prog_wp) {
				if (strstr (server, "Lynx")) {
					if ((strlen (prog_wp) + 8) < URL_MAX) {
						sprintf (urlb, "lynxcgi:%s", prog_wp);
						url = urlb;
					}
				}
			}
		}
	}
	if (url) {
		if (*url == '\0') {
			url = NULL;
		}
	}
	return (url);
}


/*
 * returns the name of the server software
 */
const char *
cgi_server_software (void)
{
	return (getenv ("SERVER_SOFTWARE"));
}

/*
 * returns the name of the server
 */
const char *
cgi_server_name (void)
{
	const char *sn;
	struct utsname un;

	sn = getenv ("SERVER_NAME");
	if (!sn) {
		sn = getenv ("HOSTNAME");
		if (!sn) {
			uname (&un);
			sn = un.nodename;
		}
	}
	return (sn);
}

/*
 * returns the name of the script
 */
const char *
cgi_script_name (void)
{
	const char *sn = NULL;
	const char *server;
	static char url[URL_MAX+1];

	sn = getenv ("SCRIPT_NAME");
	if (!sn) {
		/* lynx cgi ? */
		server = cgi_server_software();
		if (server && prog_wp) {
			if (strstr (server, "Lynx")) {
				if ((strlen (prog_wp) + 8) < URL_MAX) {
					sprintf (url, "lynxcgi:%s", prog_wp);
					sn = url;
				}
			}
		}
	}
	return (sn);
}

/*
 * returns the name of the browser software
 */
const char *
cgi_client_software (void)
{
	return (getenv ("HTTP_USER_AGENT"));
}

/*
 */
const char *
cgi_remote_host (void)
{
	const char *host;

	host = getenv ("REMOTE_HOST");
	if (!host)
		return ( getenv ("REMOTE_ADDR") );
	return ( host );
}

/*
 * print a http status line
 */
void
cgi_status (int num)
{
	printf ("HTTP/1.0 %d %s\r\n", http[num].num, http[num].str);
}

/*
 * send the content type given in "ct", if "name" is not
 * NULL it is added in the following way, e.g.
 * Content-Type: text/html; name="foo.gif"
 */
void
cgi_content_type (const char *ct, const char *name)
{
	if (run_as_nph) {
		cgi_status (http_ok);
		printf ("Server: %s/libcgi/%s\r\n", program, VER);
		printf ("Date: %s\r\n", cgi_gmt_str (time(NULL)));
	}
	if (name) {
		printf ("Content-Type: %s; name=\"%s\"\r\n\r\n", ct, name);
	} else {
		printf ("Content-Type: %s\r\n\r\n", ct);
	}
}

/*
 */
void
cgi_multipart (const char *boundary)
{
	if (run_as_nph) {
		cgi_status (http_ok);
		printf ("Server: %s/libcgi/%s\r\n", program, VER);
		printf ("Date: %s\r\n", cgi_gmt_str (time(NULL)));
	}
	printf ("Content-Type: multipart/x-mixed-replace;boundary=%s\n", boundary);
	printf ("\n%s\n", boundary);
}

/*
 * send a status line and content type if 'content_t' is not NULL,
 * e.g. cgi_response (http_ok, "text/html");
 */
void
cgi_response (int num, char *content_t)
{
	if (run_as_nph) {
		cgi_status (num);
		printf ("Server: %s/libcgi/%s\r\n", program, VER);
		printf ("Date: %s\r\n", cgi_gmt_str (time(NULL)));
	}
	if (content_t) {
		printf ("Content-Type: %s\r\n", content_t);
	}
	printf ("\r\n");
}

/*
 * return the base url
 */
const char *
cgi_base (void)
{
	static char base[URL_MAX+1];
	const char *url_ref, *p;
	int i, len;

	url_ref = cgi_url_ref();
	if (url_ref) {
		len = strlen (url_ref);
		if (url_ref[len-1] == '/') {
			strcpy (base, url_ref);
		} else {
			p = strrchr (url_ref, '/');
			if (p) {
				i = 0;
				while (url_ref < (p+1)) {
					base[i] = *url_ref;
					url_ref++;
					i++;
				}
				base[i] = '\0';
			} else {
				/* should never be reached ..! */
				return (NULL);
			}
		}
		return (base);
	}
	return (NULL);
}

/*
 * redirect to the given url, which could be a relative or an
 * absolute url. note: relative urls could be a problem with
 * some browsers, cause sometimes there is no way to find out
 * the "REFERER"..
 */
void
cgi_redirect (const char *url)
{
	const char *p, *s, *hash;
	char buff[URL_MAX+1];

	if (run_as_nph) {
		cgi_status (http_moved_permanently);
		printf ("Server: %s/libcgi/%s\r\n", program, VER);
		printf ("Date: %s\r\n", cgi_gmt_str (time(NULL)));
	}
	if (strstr (url, "://") > url) {
		/* it´s an absolute URL ..
		 */
		printf ("Location: %s\r\n", url);
	} else if (*url == '/') {
		/* relative URL which starts at the root
		 */
		if ((s = p = cgi_base ()) != NULL ) {
			int i;
			for (i = 0; i < 3; i++) {
				if (p) {
					p = strchr (p, '/');
				}
				p++;
			}
			if (p) {
				strncpy (buff, s, p-s-1);
				buff[p-s-1] = '\0'; 
				printf ("Location: %s%s\r\n", buff, url);
			} else {
				printf ("Location: %s\r\n", url);
			}
		} else {
			printf ("Location: %s\r\n", url);
		}
	} else if (*url == '#') {
		p = cgi_url_ref();
		if (p) {
			hash = strrchr (p, '#');
			if (!hash) {
				printf ("Location: %s%s\r\n", p, url);
			} else {
				/* there is still a name value, we have to remove it ..
				 */
				strncpy (buff, p, hash-p);
				buff[hash-p] = '\0';
				strcat (buff, url);
				printf ("Location: %s\r\n", buff);
			}
		} else
			printf ("Location: %s\r\n", url);
	} else {
		/* some other kind of relative URL..
		 */
		p = cgi_base();
		printf ("Location: %s%s\r\n", p ? p:"", url);
	}
	printf ("Content-Type: text/html\r\n\r\n");
}

/*
 * lock a name file
 */
int
cgi_lock (const char *file)
{
	char pfile[PATH_MAX+1];
	char lfile[PATH_MAX+1];
	FILE *pfp;
	int pid, loop;
	struct stat info;

	loop = 5; /* try five times to lock .. */
	pid = getpid();
	strcpy (pfile, file);
	sprintf (pfile+strlen(file), ".%d", pid);
	strcpy (lfile, file);
	strcat (lfile, ".LCK");

	pfp = fopen (pfile, "wb");
	if (!pfp) {
		perror (pfile);
		return (0);
	}
	fwrite (&pid, sizeof (pid), 1, pfp);
	fclose (pfp);
	while ((stat (lfile, &info) == 0) || (link (pfile, lfile) != 0)) {
		sleep (1);
		loop--;
		if (loop < 1) {
			unlink (pfile);
			return (0);
		}
	}
	return (1);
}


/*
 * unlock the named file
 */
int
cgi_unlock (const char *file)
{
	char pfile[PATH_MAX+1];
	char lfile[PATH_MAX+1];
	int pid;

	pid = getpid();
	strcpy (pfile, file);
	sprintf (pfile+strlen(file), ".%d", pid);
	strcpy (lfile, file);
	strcat (lfile, ".LCK");
	unlink (pfile);
	unlink (lfile);
	return (1);
}



/*
 */
void
cgi_html_start (const char *title)
{
	printf ("<HTML>\n");
	printf ("<HEAD>\n");
	printf ("\t<TITLE>%s</TITLE>\n", title);
	if (cgi_source_url) {
		printf ("\t<!-- source: %s -->\n", cgi_source_url);
	}
	if (cgi_meta_desc) {
		printf ("\t<META name=\"description\" content=\"%s\">\n",
				cgi_meta_desc);
	}
	if (cgi_meta_keyw) {
		printf ("\t<META name=\"keywords\" content=\"%s\">\n",
				cgi_meta_keyw);
	}
	if (cgi_refresh_time > 0) {
		printf ("\t<META http-equiv=refresh content=\"%d; url='",
				cgi_refresh_time);
		if (cgi_refresh_url)
			printf ("%s'\">\n", cgi_refresh_url);
		else if (getenv("QUERY_STRING"))
			printf ("%s?%s'\">\n", cgi_script_name(), getenv("QUERY_STRING"));
		else
			printf ("%s'\">\n", cgi_script_name());
	}
	if (cgi_stylesheet) {
		printf ("\t<LINK rel=stylesheet href=\"%s\">\n", cgi_stylesheet);
	}
	printf ("</HEAD>\n");
	printf ("<BODY");
	if (cgi_background) {
		if (*cgi_background == '/') {
			printf (" background=\"%s\"", cgi_background);
		} else {
			printf (" bgcolor=\"%s\"", cgi_background);
		}
	}
	if (cgi_foreground)
		printf (" text=\"%s\"", cgi_foreground);
	printf (">\n");
}

/*
 */
void
cgi_html_end (const char *s)
{
	if (s) {
		printf ("%s\n", s);
	}
	if (cgi_bottomline) {
		printf ("%s\n", cgi_bottomline);
	}
	printf ("</BODY>\n</HTML>\n");
}


/*
 */
const char *
cgi_sourceURL (void)
{
	return (cgi_source_url);
}

/*
 */
const char *
cgi_logdir (void)
{
	return (cgi_loggingdir);
}

/*
 */
const char *
cgi_defaultMTA (void)
{
	return (cgi_defaultmta);
}

/*
 */
int
cgi_init (const char *pname)
{
#	define CFG_bg	"background"
#	define CFG_fg	"foreground"
#	define CFG_css	"stylesheet"
#	define CFG_src	"source_url"
#	define CFG_log	"loggingdir"
#	define CFG_btl	"bottomline"
#	define CFG_mta	"detaultMTA"
#	define CFG_desc	"meta_desc"
#	define CFG_keyw	"meta_keyw"
	char cfgfile[PATH_MAX+1];
	char buff[MAX_LINE], *p;
	char key[256], value[256];
	FILE *fp;
	int len;
	int cfg_num = 0;

	prog_wp = pname;
	program = strrchr (pname, '/');
	if (program) program++;
	else program = (char *)pname;
	if (strstr (program, "nph-"))
		run_as_nph = 1;
	strcpy (cfgfile, pname);
	strcat (cfgfile, ".scf");
	fp = fopen (cfgfile, "rb");
	if (!fp) {
		return (0);
	}
	while (fgets (buff, MAX_LINE, fp) != NULL) {
		p = buff;
		while (*p && (*p == ' ' || *p == '\t'))
			p++;
		if (*p == '#')
			continue;
		*value = EMPTY;
		sscanf (p, " %[^= \t] = %[^\n]", key, value);
		if (*value) {
			len = strlen (value);
			if (len > 0) {
				if (*value == '"') {
					/* remove quote chars */
					memmove (value, value+1, len + 1);
					p = strrchr (value, '"');
					if (p)
						*p = EMPTY;
				} else {
					/* use last white char as end point */
					p = strchr (value, '\t');
					if (p)
						*p = EMPTY;
					else {
						p = strchr (value, ' ');
						if (p)
							*p = EMPTY;
					}
				}
			}
		} else {
			continue;
		}
#ifdef DEBUG
		fprintf (stderr, "key=%s, value=%s\n", key, value);
#endif
		len = strlen (key);
		if ((len == strlen (CFG_bg)) && (strcmp (key, CFG_bg) ==0)) {
			cgi_background = (char *) malloc (strlen (value) +1);
			strcpy (cgi_background, value);
		} else
		if ((len == strlen (CFG_fg)) && (strcmp (key, CFG_fg) ==0)) {
			cgi_foreground = (char *) malloc (strlen (value) +1);
			strcpy (cgi_foreground, value);
		} else
		if ((len == strlen (CFG_css)) && (strcmp (key, CFG_css) ==0)) {
			cgi_stylesheet = (char *) malloc (strlen (value) +1);
			strcpy (cgi_stylesheet, value);
		} else
		if ((len == strlen (CFG_src)) && (strcmp (key, CFG_src) ==0)) {
			cgi_source_url = (char *) malloc (strlen (value) +1);
			strcpy (cgi_source_url, value);
		} else
		if ((len == strlen (CFG_log)) && (strcmp (key, CFG_log) ==0)) {
			cgi_loggingdir = (char *) malloc (strlen (value) +1);
			strcpy (cgi_loggingdir, value);
		} else
		if ((len == strlen (CFG_btl)) && (strcmp (key, CFG_btl) ==0)) {
			cgi_bottomline = (char *) malloc (strlen (value) +1);
			strcpy (cgi_bottomline, value);
		} else
		if ((len == strlen (CFG_mta)) && (strcmp (key, CFG_mta) ==0)) {
			cgi_defaultmta = (char *) malloc (strlen (value) +1);
			strcpy (cgi_defaultmta, value);
		} else
		if ((len == strlen (CFG_desc)) && (strcmp (key, CFG_desc) ==0)) {
			cgi_meta_desc = (char *) malloc (strlen (value) +1);
			strcpy (cgi_meta_desc, value);
		} else
		if ((len == strlen (CFG_keyw)) && (strcmp (key, CFG_keyw) ==0)) {
			cgi_meta_keyw = (char *) malloc (strlen (value) +1);
			strcpy (cgi_meta_keyw, value);
		} else {
			/* private configuration data
			 */
			cfg_num += 2;
			if (cfg_num == 2) {	/* first time */
				cgi_cfg = calloc (3, sizeof(char *));
			} else {
				cgi_cfg = realloc (cgi_cfg, (cfg_num+1) * sizeof (char *));
			}
			cgi_cfg[cfg_num-2] = strdup (key);
			cgi_cfg[cfg_num-1] = strdup (value);
			cgi_cfg[cfg_num] = NULL;
		}
	}
	fclose (fp);
	return (1);
}


/*
 */
int
cgi_content (void)
{
	char *c;
	c = getenv ("CONTENT_TYPE");
	if (c) {
		if (strstr (c, "multipart/form-data"))
			return (MULTIPART_FORM);
	}
	return (0);
}


/*
 * returns the method: CGI_METHOD_{GET|POST|PUT}
 */
int
cgi_method (void)
{
	const char *method;
	int rc = 0;

	method = getenv ("REQUEST_METHOD");
	if (method) {
		if (strcmp (method, "GET") == 0)
			rc = CGI_METHOD_GET;
		else if (strcmp (method, "POST") == 0)
			rc = CGI_METHOD_POST;
		else if (strcmp (method, "PUT") == 0)
			rc = CGI_METHOD_PUT;
		else if (strcmp (method, "DELETE") == 0)
			rc = CGI_METHOD_DELETE;
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
char **
cgi_parse_string (const char *str)
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
 * return content length as int
 */
int
cgi_content_length (void)
{
	const char *len_env;
	int len = 0;

	len_env = getenv ("CONTENT_LENGTH");
	if (!len_env)
		return (0);
	sscanf (len_env, " %d ", &len);
	return (len);
}

/*
 * read multipart request
 * still not ready!
 */
mime **
cgi_parse_multipart (void)
{
	mime **mpart = NULL;
	char *boundary;
	char line[MAX_LINE];
	int len, sl, read = 0, max = MAX_LINE;

	boundary = getenv("CONTENT_TYPE");
	boundary = strstr (boundary, "boundary=");
	len = cgi_content_length ();
	if (!boundary || !len)
		return (NULL);

	if (len < MAX_LINE)
		max = len;
	boundary += 9;
	do {
		/* find the start boundary
		 */
		fgets (line, max, stdin);
		read += strlen (line);
		if (strstr (line, boundary))
			break;
	} while (read < len);

	printf ("found\n");
	do {
		fgets (line, max, stdin);
		sl = strlen (line);
		if (sl >= 20) {
			if (strncasecmp (line, "content-disposition:", 20)) {
			}
		}
		read += sl;
	} while (read < len);
	return (mpart);
}


/*
 * read stdin and encode query data
 */
char **
cgi_parse_stdin (void)
{
	char **form = NULL;
	char *buff;
	int len;

	len = cgi_content_length();
	if (!len)
		return (NULL);
	buff = (char *) malloc (len+1);
	buff[len] = '\0';
	fread (buff, 1, len, stdin);
	form = cgi_parse_string(buff);
	free (buff);
	return (form);
}

/*
 */
char **
cgi_parse_query (void)
{
	char *qs = getenv ("QUERY_STRING");
	if (!qs)
		return (NULL);
	return (cgi_parse_string (qs));
}

/*
 * parse a formular, not depending on the request method
 * PUT method not done until now
 */
char **
cgi_parse_form (void)
{
	int method;

	/* changes globals! (cgi_form) */
	method = cgi_method();
	if (method == CGI_METHOD_POST) {
		if (cgi_content() == MULTIPART_FORM)
			cgi_form = (char **) cgi_parse_multipart ();
		else
			cgi_form = cgi_parse_stdin();
	} else if (method == CGI_METHOD_GET)
		cgi_form = cgi_parse_query();
	else
		cgi_form = NULL;
	return (cgi_form);
}

/*
 * return the corresponding value for a given key
 */
char *
cgi_form_value (const char *key)
{
	char **form;
	if (!key)
		return (NULL);
	if (!cgi_form)
		return (NULL);
	form = cgi_form;
	while (*form) {
		if (strcmp (key, *form) == 0)
			return (*(form+1));
		form += 2;
	}
	return (NULL);
}

/*
 * return the corresponding value for a given key
 */
char *
cgi_cfg_value (const char *key)
{
	char **cfg;
	if (!key)
		return (NULL);
	if (!cgi_cfg)
		return (NULL);
	cfg = cgi_cfg;
	while (*cfg) {
		if (strcmp (key, *cfg) == 0)
			return (*(cfg+1));
		cfg += 2;
	}
	return (NULL);
}

/*
 * set refresh time, use 0 to disable
 */
void
cgi_refresh (int t, char *url)
{
	cgi_refresh_time = t;
	cgi_refresh_url = url;
}

