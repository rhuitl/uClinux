/*
 *  Boa, an http server
 *  Copyright (C) 1995 Paul Phillips <psp@well.com>
 *  Some changes Copyright (C) 1996,97 Larry Doolittle <ldoolitt@jlab.org>
 *  Some changes Copyright (C) 1996 Charles F. Randall <crandall@goldsys.com>
 *  Some changes Copyright (C) 1997 Jon Nelson <nels0988@tc.umn.edu>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 1, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/* boa: cgi.c */

#include "boa.h"
#include "syslog.h"

static char **common_cgi_env;

/*
 * Name: create_common_env
 *
 * Description: Set up the environment variables that are common to
 * all CGI scripts
 */

void create_common_env()
{
	int index = 0;


	common_cgi_env = (char **) malloc(sizeof(char *) * COMMON_CGI_VARS);
	common_cgi_env[index++] = env_gen("PATH", DEFAULT_PATH);
	common_cgi_env[index++] = env_gen("SERVER_SOFTWARE", SERVER_VERSION);
	common_cgi_env[index++] = env_gen("SERVER_NAME", server_name);
	common_cgi_env[index++] = env_gen("GATEWAY_INTERFACE", CGI_VERSION);
	common_cgi_env[index++] = env_gen("SERVER_PORT", simple_itoa(server_port));

	/* NCSA and APACHE added -- not in CGI spec */
	common_cgi_env[index++] = env_gen("DOCUMENT_ROOT", document_root);

	/* NCSA added */
	common_cgi_env[index++] = env_gen("SERVER_ROOT", server_root);

	/* APACHE added */
	common_cgi_env[index++] = env_gen("SERVER_ADMIN", server_admin);
}

/*
 * Name: create_env
 * 
 * Description: Allocates memory for environment before execing a CGI 
 * script.  I like spelling creat with an extra e, don't you?
 */

void create_env(request * req)
{
	int i;


	req->cgi_env = (char **) malloc(sizeof(char *) * MAX_CGI_VARS);

	for (i = 0; i < COMMON_CGI_VARS; i++)
		req->cgi_env[i] = common_cgi_env[i];

	req->cgi_env_index = COMMON_CGI_VARS;

	{
		char *w;

		switch (req->method) {
		case M_POST:
			w = "POST";
			break;
		case M_HEAD:
			w = "HEAD";
			break;
		case M_GET:
			w = "GET";
			break;
		default:
			w = "UNKNOWN";
			break;
		}
		req->cgi_env[req->cgi_env_index++] =
			env_gen("REQUEST_METHOD", w);
	}
}

/*
 * Name: env_gen_extra
 * This routine calls malloc: please free the memory when you are done
 */
char *env_gen_extra(const char *key, const char *value, int extra)
{
	char *result;
	int key_len, value_len;
	key_len = strlen(key);
	value_len = strlen(value);
	/* leave room for '=' sign and null terminator */
	result = malloc(extra + key_len + value_len + 2);
	if (result) {
		memcpy(result + extra, key, key_len);
		*(result + extra + key_len) = '=';
		memcpy(result + extra + key_len + 1, value, value_len);
		*(result + extra + key_len + value_len + 1) = '\0';
	}
	return result;
}

/* 
 * Name: add_cgi_env
 *
 * Description: adds a variable to CGI's environment
 * Used for HTTP_ headers
 */

void add_cgi_env(request * req, char *key, char *value)
{
	char *p;

	if (req->cgi_env_index >= (MAX_CGI_VARS - 17))	/* 16 in complete_env */
		return;

	p = env_gen_extra(key, value, 5);
	memcpy(p, "HTTP_", 5);
	req->cgi_env[req->cgi_env_index++] = p;
	req->cgi_env[req->cgi_env_index] = 0;           /* fix cgi_env */
}

/* 
 * Name: complete_env
 * 
 * Description: adds the known client header env variables
 * and terminates the environment array
 */

void complete_env(request * req)
{

	if (req->method == M_POST) {
		if (req->content_type)
			req->cgi_env[req->cgi_env_index++] =
				env_gen("CONTENT_TYPE", req->content_type);
		else
			req->cgi_env[req->cgi_env_index++] =
				env_gen("CONTENT_TYPE", default_type);

		if (req->content_length) {
			req->cgi_env[req->cgi_env_index++] =
				env_gen("CONTENT_LENGTH", req->content_length);
		}
	}
/*      
   if (req->accept[0]) {
   req->cgi_env[req->cgi_env_index++] =
   env_gen("HTTP_ACCEPT", req->accept);
   }
 */


        req->cgi_env[req->cgi_env_index++] =
                env_gen("SERVER_PROTOCOL", req->http_version);

        if (req->path_info) {
                req->cgi_env[req->cgi_env_index++] =
                        env_gen("PATH_INFO", req->path_info);
                /* path_translated depends upon path_info */
                req->cgi_env[req->cgi_env_index++] =
                        env_gen("PATH_TRANSLATED", req->path_translated);
        }

        if (req->script_name) 
           {
             req->cgi_env[req->cgi_env_index++] =
                env_gen("SCRIPT_NAME", req->script_name);
           }

        if (req->query_string) {
                req->cgi_env[req->cgi_env_index++] =
                        env_gen("QUERY_STRING", req->query_string);
        }

#ifndef NO_COOKIES
        if (req->cookie) {
                req->cgi_env[req->cgi_env_index++] =
                        env_gen("HTTP_COOKIE", req->cookie);
		req->cookie = NULL;
        }
#endif

        req->cgi_env[req->cgi_env_index++] =
                env_gen("REMOTE_ADDR", req->remote_ip_addr);

        req->cgi_env[req->cgi_env_index++] =
                env_gen("REMOTE_PORT", simple_itoa(req->remote_port));

#ifndef NO_AGENT_LOG
if (req->user_agent)
        req->cgi_env[req->cgi_env_index++] =
                env_gen("HTTP_USER_AGENT", req->user_agent);
#endif

#ifndef NO_REFERER_LOG
if (req->referer)
        req->cgi_env[req->cgi_env_index++] =
                env_gen("HTTP_REFERER", req->referer);
#endif

#ifdef USE_NLS
if (req->cp_name)
		req->cgi_env[req->cgi_env_index++] =
			env_gen("CLIENT_CODEPAGE", req->cp_name);
#endif

#ifdef USE_AUTH
{
if (*req->user != '\0')
		req->cgi_env[req->cgi_env_index++] =
			env_gen("REMOTE_USER", req->user);
}
#endif

	req->cgi_env[req->cgi_env_index] = NULL;	/* terminate */
}

/*
 * Name: make_args_cgi
 *
 * Build argv list for a CGI script according to spec
 *
 */

#define ARGC_MAX 128
void create_argv(request * req, char **aargv)
{
	char *p, *q, *r;
	int aargc;

	q = req->query_string;
	aargv[0] = req->pathname;

	if (q && !strchr(q, '=')) {
		/* fprintf(stderr,"Parsing string %s\n",q); */
		q = strdup(q);
		for (aargc = 1; q && (aargc < ARGC_MAX);) {
			r = q;
			if ((p = strchr(q, '+'))) {
				*p = '\0';
				q = p + 1;
			} else {
				q = NULL;
			}
			if (unescape_uri(r)) {
				/* printf("parameter %d: %s\n",aargc,r); */
				aargv[aargc++] = r;
			}
		}
		aargv[aargc] = NULL;
	} else {
		aargv[1] = NULL;
	}
}

/*
 * Name: init_cgi
 * 
 * Description: Called for GET/POST requests that refer to ScriptAlias 
 * directories or application/x-httpd-cgi files.  Ties stdout to socket,
 * stdin to data if POST, and execs CGI.
 * stderr remains tied to our log file; is this good?
 * 
 * Returns:
 * 0 - error or NPH, either way the socket is closed
 * 1 - success
 */

int init_cgi(request * req)
{
	int child_pid;
	int p[2];

	SQUASH_KA(req);

	complete_env(req);

	if (req->is_cgi == CGI) {
		if (pipe(p) == -1) {
#ifdef BOA_TIME_LOG
			log_error_time();
			perror("pipe");
#endif
			syslog(LOG_ERR, "pipe: %d.\n", errno);
			return 0;
		}
		if (fcntl(p[0], F_SETFL, O_NONBLOCK) == -1) {
#ifdef BOA_TIME_LOG
			fprintf(stderr, "Unable to do something: %d.\n", errno);
#endif
			syslog(LOG_ERR, "Unable to do something: %d.\n", errno);
			close(p[0]);
			close(p[1]);
			return 0;
		}
	}
#ifdef __uClinux__
	if ((child_pid = vfork()) == -1) {	/* vfork unsuccessful */
#else
	if ((child_pid = fork()) == -1) {	/* fork unsuccessful */
#endif
		if (req->is_cgi == CGI) {
			close(p[0]);
			close(p[1]);
		}
#ifdef BOA_TIME_LOG
		log_error_time();
		perror("fork");
#endif
		return 0;
	}
	/* if here, fork was successful */

	if (!child_pid) {			/* 0 == child */
		int newstdin = -1, newstdout = -1, newstderr = -1;

		if (req->is_cgi != CGI) {	/* nph or gunzip, etc... */
			newstdout = req->fd;
		} else {
			/* tie stdout to write end of pipe */
			close(p[0]);
			newstdout = p[1];
		}

		/* tie post_data_fd to POST stdin */
		if (req->method == M_POST) {	/* tie stdin to file */
			lseek(req->post_data_fd, SEEK_SET, 0);
			newstdin = req->post_data_fd;
		}

		/* Close access log, so CGI program can't scribble 
		 * where it shouldn't 
		 */
		close_access_log();

		/* tie STDERR to cgi_log_fd */
		if (cgi_log_fd)
			newstderr = cgi_log_fd;
		else
			newstderr = open("/dev/null", O_WRONLY);

		/* Set up stdin/out/err without trampling over each other. */
		if (newstdin >= 0 && newstdin != STDIN_FILENO) {
			if (newstdout == STDIN_FILENO)
				newstdout = dup(newstdout);
			if (newstderr == STDIN_FILENO)
				newstderr = dup(newstderr);
			dup2(newstdin, STDIN_FILENO);
			close(newstdin);
		}
		if (newstdout >= 0 && newstdout != STDOUT_FILENO) {
			if (newstderr == STDOUT_FILENO)
				newstderr = dup(newstderr);
			dup2(newstdout, STDOUT_FILENO);
			close(newstdout);
			/* Switch socket flags back to blocking */
			if (fcntl(STDOUT_FILENO, F_SETFL, 0) == -1) {
#ifdef BOA_TIME_LOG
				perror("cgi-fcntl");
#endif
			}
		}
		if (newstderr >= 0 && newstderr != STDERR_FILENO) {
			dup2(newstderr, STDERR_FILENO);
			close(newstderr);
		}

		if (req->is_cgi) {
			char *aargv[ARGC_MAX + 1];
			create_argv(req, aargv);
			execve(req->pathname, aargv, req->cgi_env);
		} else {
			if (req->pathname[strlen(req->pathname) - 1] == '/')
				execl(dirmaker, dirmaker, req->pathname, req->request_uri, NULL);
			else {
#if 0
				execl(GUNZIP, GUNZIP, "--stdout", "--decompress",
					  req->pathname, NULL);
#endif
				syslog(LOG_ERR, "gunzip not found");
				
			}
		}
		/* execve failed */
		log_error_time();
		perror(req->pathname);
		_exit(1);
	}
	/* if here, fork was successful */

	if (verbose_cgi_logs) {
#ifdef BOA_TIME_LOG
		log_error_time();
		fprintf(stderr, "Forked child \"%s\" pid %d\n",
				req->pathname, child_pid);
#endif
		syslog(LOG_INFO, "Forked child \"%s\" pid %d\n",
				req->pathname, child_pid);
	}
	if (req->is_cgi != CGI)
		return 0;

	req->data_fd = p[0];

	/* close duplicate write end of pipe */
	close(p[1]);
	
	req->status = PIPE_READ;
	req->filesize = req->filepos = 0; /* why is this here??? */

	if (req->is_cgi == CGI) {		/* cgi */
		/* for cgi_header... I get half the buffer! */
		req->header_line = req->header_end = 
 			(req->buffer + BUFFER_SIZE / 2);
		req->cgi_status = CGI_READ;	/* got to parse cgi header */
	} else	{					/* gunzip or similar */
		req->header_line = req->header_end = req->buffer;
		req->cgi_status = CGI_WRITE;	/* don't do it. */
	}
	
	return 1;					/* success */
}
