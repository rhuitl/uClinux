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

#ifndef _BOA_H
#define _BOA_H

#ifdef DEBUG
#define DBG(x) x
#else
#define DBG(x)
#endif

#include "defines.h"
#include "globals.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>				/* OPEN_MAX */
#include <netinet/in.h>			/* sockaddr_in, sockaddr */
#include <stdlib.h>				/* malloc, free, etc. */
#include <stdio.h>				/* stdin, stdout, stderr */
#include <string.h>				/* strdup */
#include <time.h>				/* localtime, time */
#include <pwd.h>

#include <arpa/inet.h>			/* inet_ntoa */

#include <unistd.h>
#include <sys/mman.h>			/* mmap */
#include <sys/time.h>			/* select */
#include <sys/resource.h>		/* setrlimit */
#include <sys/types.h>			/* socket, bind, accept */
#include <sys/socket.h>			/* socket, bind, accept, setsockopt, */
#include <sys/stat.h>			/* open */
#include "syslog.h"

#include "compat.h"				/* oh what fun is porting */

/* new parser */
#define ALIAS                   0
#define SCRIPTALIAS             1
#define REDIRECT                2

struct ccommand {
        char *name;
        int type;
        void (*action) (char *,char *,void *);
        void *object;
};
struct ccommand *lookup_keyword(char *c);

/* alias */

void add_alias(char *fakename, char *realname, int script);
void chroot_aliases();
int translate_uri(request * req);
int init_script_alias(request * req, alias * current);
void dump_alias(void);
	

/* boa */

void die(int exit_code);
void fdset_update(void);

/* config */

void read_config_files(void);
#ifdef EMBED
	void set_server_port(int port);
#endif

/* get */

int init_get(request * req);
int process_get(request * req);
int get_dir(request * req, struct stat *statbuf);

/* hash */

void add_mime_type(char *extension, char *type);
void add_virtual_host(char *name,char *docroot);
int get_mime_hash_value(char *extension);
char *get_mime_type(char *filename);
char *get_home_dir(char *name);
char *get_virtual_host(char *name);
void chroot_virtual_hosts();
void dump_mime(void);
void dump_passwd(void);
#ifdef USE_BROWSERMATCH
void add_browsermatch(char *browser,char *action);
int get_browser_hash_value(char *browser);
void browser_match_request(request *req);
#endif

/* log */

void open_logs(void);
void close_access_log(void);
void log_access(request * req);
void log_referer(request * req);
void log_user_agent(request * req);
void log_error_time(void);
void log_error_doc(request * req);
void boa_perror(request * req, char *message);

/* queue */

void block_request(request * req);
void ready_request(request * req);
void dequeue(request ** head, request * req);
void enqueue(request ** head, request * req);

/* read */

int read_header(request * req);
int read_body(request * req);
int write_body(request * req);

/* request */

request *new_request(void);
void get_request(void);
void free_request(request ** list_head_addr, request * req);
void process_requests(void);
int process_header_end(request * req);
int process_header_line(request * req);
int process_logline(request * req);
int process_option_line(request * req);
void add_accept_header(request * req, char *mime_type);
void free_requests(void);
void dump_request(request *req);

/* response */

void print_content_type(request * req);
void print_content_length(request * req);
void print_last_modified(request * req);
void print_http_headers(request * req);

void send_r_request_ok(request * req);	/* 200 */
void send_redirect_perm(request * req, char *url);	/* 301 */
void send_redirect_temp(request * req, char *url);	/* 302 */
void send_r_not_modified(request * req);	/* 304 */
void send_r_bad_request(request * req);		/* 400 */
void send_r_unauthorized(request * req, char *name);	/* 401 */
void send_r_forbidden(request * req);	/* 403 */
void send_r_not_found(request * req);	/* 404 */
void send_r_error(request * req);	/* 500 */
void send_r_not_implemented(request * req);		/* 501 */
void send_r_bad_version(request * req);		/* 505 */

/* cgi */

void create_common_env(void);
void create_env(request * req);
#define env_gen(x,y) env_gen_extra(x,y,0)
char *env_gen_extra(const char *key, const char *value, int extra);
void add_cgi_env(request * req, char *key, char *value);
void complete_env(request * req);
void create_argv(request * req, char **aargv);
int init_cgi(request * req);

/* signals */

void init_signals(void);
void sighup_run(void);
void sigchld_run(void);
void lame_duck_mode_run(int server_s);

/* util */

void clean_pathname(char *pathname);
int strmatch(char *str,char *s2);
int modified_since(time_t * mtime, char *if_modified_since);
int month2int(char *month);
char *to_upper(char *str);
int unescape_uri(char *uri);
char *escape_uri(char *uri);
void close_unused_fds(request * head);
void fixup_server_root(void);
char *get_commonlog_time(void);
int req_write_rfc822_time(request *req, time_t s);
char *simple_itoa(int i);
char *escape_string(char *inp, char *buf);
int req_write(request *req, char *msg);
int req_flush(request *req);
int base64decode(void *dst,char *src,int maxlen);
void base64encode(unsigned char *from, char *to, int len);

/* cgi_header */
int process_cgi_header(request * req);

/* pipe */
int write_from_pipe(request * req);
int read_from_pipe(request * req);

/* timestamp */
void timestamp(void);

extern int request_type(request *req);

/* nls */
#ifdef USE_NLS
void nls_load_codepage(char *name,char *filename);
int get_cp_hash_value(char *name);
unsigned char *nls_get_table(char *name);
void add_cp_brows(char *browser,char *codepage);
int nls_try_redirect(request * req);
void nls_set_codepage(request *req);
#endif

/* auth */
#ifdef USE_AUTH
void auth_add(char *directory,char *file);
int auth_authorize(request * req);
void auth_check();
void nls_convert(unsigned char * buffer, unsigned char * table, long count);
void dump_auth(void);
#endif

#endif
