/* vi:set tabstop=2: */
/*
 *  Boa, an http server
 *  Copyright (C) 1995 Paul Phillips <psp@well.com>
 *  Some changes Copyright (C) 1996,97 Larry Doolittle <ldoolitt@jlab.org>
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

#ifndef _GLOBALS_H
#define _GLOBALS_H

#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "defines.h"
#include "compat.h"

struct request {				/* pending requests */
	int fd;						/* client's socket fd */
	char *pathname;				/* pathname of requested file */
	int status:5;					/* see #defines.h */
	int simple:1;					/* simple request? */
	int keepalive:3;				/* keepalive status */
	int kacount;				/* keepalive count */

	int data_fd;				/* fd of data */
	unsigned long filesize;		/* filesize */
	unsigned long filepos;		/* position in file */
	char *data_mem;				/* mmapped/malloced char array */
	time_t time_last;			/* time of last succ. op. */
	int method;					/* M_GET, M_POST, etc. */

	char *logline;				/* line to log file */

	int client_stream_pos;		/* how much have we read... */
	int pipeline_start;			/* how much have we processed */
	char *header_line;		
	char *header_end;
	int buffer_start;
	int buffer_end;
#ifdef USE_NLS
	int buffer_conv;			/* How much have we converted */
#endif

	char *http_version;			/* HTTP/?.? of req */
	int response_status;		/* R_NOT_FOUND etc. */

	char *if_modified_since;	/* If-Modified-Since */
	char remote_ip_addr[20];	/* after inet_ntoa */
	char *local_ip_addr;		/* used for VIRTUAL_HOST */
	int remote_port;			/* could be used for ident */
        char *host;                     /* used for HTTP Host: line */

	time_t last_modified;		/* Last-modified: */
#ifdef USE_CHARSET_HEADER
	int send_charset;
#endif
	/* CGI needed vars */

	int cgi_status;				/* similar to status */
	int is_cgi;					/* true if CGI/NPH */
	char **cgi_env;				/* CGI environment */
	int cgi_env_index;			/* index into array */

	int post_data_fd;			/* fd for post data tmpfile */
	char *post_file_name;		/* only used processing POST */

	char *path_info;			/* env variable */
	char *path_translated;		/* env variable */
	char *script_name;			/* env variable */
	char *query_string;			/* env variable */
#ifndef NO_COOKIES
	char *cookie;				/* env variable */
#endif
	char *content_type;			/* env variable */
	char *content_length;		/* env variable */
#if (! defined NO_REFERER_LOG ) || (defined USE_NLS_REFERER_REDIR)
	char *referer;				/* for referer.log */
#endif

#if (!defined NO_AGENT_LOG) || (defined USE_BROWSERMATCH) || (defined USE_NLS)
	char *user_agent;			/* for agent.log */
#endif
	
#ifdef USE_NLS
	char *cp_name;
	unsigned char *cp_table;
	unsigned long bytesconverted;
#endif
	
#ifdef USE_AUTH
	char *authorization;
#endif

	struct request *next;		/* next */
	struct request *prev;		/* previous */

#ifdef SERVER_SSL
	void* ssl;
#endif /*SERVER_SSL*/
	char user[16];			/* user's login name */

	/* We only clear this structure down to here when accepting new
	 * connections.
	 *
	 * If you want your attribute zapped, put them before this comment.
	 * If you don't care, put it after and adjust the NO_ZERO_FILL_LENGTH
	 * setting below.
	 *
	 * You've been warned.  Life is too short to debug this morass again.
	 */
	char buffer[BUFFER_SIZE + 1];			/* generic I/O buffer */
	char request_uri[MAX_HEADER_LENGTH + 1];	/* uri */
	char client_stream[CLIENT_STREAM_SIZE];		/* data from client - fit or be hosed */
#ifdef ACCEPT_ON
	char accept[MAX_ACCEPT_LENGTH];		/* Accept: fields */
#endif
	/* Be very very careful about adding fields here.  See previous
	 * largish comment for why.
	 */
};

#ifdef ACCEPT_ON

#define NO_ZERO_FILL_LENGTH (BUFFER_SIZE + 1 + \
                             MAX_HEADER_LENGTH + 1 + \
                             CLIENT_STREAM_SIZE + \
                             MAX_ACCEPT_LENGTH)

#else

#define NO_ZERO_FILL_LENGTH (BUFFER_SIZE + 1 + \
                             MAX_HEADER_LENGTH + 1 + \
                             CLIENT_STREAM_SIZE)

#endif

/* how does an array of chars of size zero get treated */

typedef struct request request;
#ifdef CRASHDEBUG
extern request *crashdebug_current;
#endif

struct alias {
	char *fakename;				/* URI path to file */
	char *realname;				/* Actual path to file */
	int type;					/* ALIAS, SCRIPTALIAS, REDIRECT */
	int fake_len;				/* strlen of fakename */
	int real_len;				/* strlen of realname */
	struct alias *next;
};

typedef struct alias alias;

struct status {
	long requests;
	long errors;
	long connections;
};

extern alias *alias_hashtable[ALIAS_HASHTABLE_SIZE];
#ifdef USE_NLS
extern alias *cp_url_hashtable[ALIAS_HASHTABLE_SIZE];
#endif
 

extern struct status status;

extern char *optarg;			/* For getopt */
extern FILE *yyin;				/* yacc input */

extern request *request_ready;	/* first in ready list */
extern request *request_block;	/* first in blocked list */
extern request *request_free;	/* first in free list */

extern fd_set block_read_fdset;	/* fds blocked on read */
extern fd_set block_write_fdset;	/* fds blocked on write */

extern int sock_opt;			/* sock_opt = 1: for setsockopt */

/* global server variables */

extern char *server_chroot;
extern int verbose_logs;
extern char *access_log_name;
extern char *error_log_name;
extern char *referer_log_name;
extern char *agent_log_name;
extern char *cgi_log_name;
extern int cgi_log_fd;

extern int server_port;
extern uid_t server_uid;
extern gid_t server_gid;
extern char *server_admin;
extern char *server_root;
extern char *server_name;
extern int virtualhost;

extern char *document_root;
extern char *user_dir;
extern char *directory_index;
extern char *default_type;
extern char *dirmaker;
extern char *mime_types;

extern int ka_timeout;
extern int ka_max;

extern int sighup_flag;
extern int sigchld_flag;
extern int lame_duck_mode;

extern int verbose_cgi_logs;

extern int backlog;

extern int max_connections;

/* nls.c */
extern char *local_codepage;

#endif
