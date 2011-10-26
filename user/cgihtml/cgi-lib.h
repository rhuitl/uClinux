/* cgi-lib.h - header file for cgi-lib.c
   Eugene Kim, <eekim@eekim.com>
   $Id: cgi-lib.h,v 1.8 1997/02/03 06:39:32 eekim Exp $

   Copyright (C) 1996, 1997 Eugene Eric Kim
   All Rights Reserved
*/

#include <stdlib.h>
#include "cgi-llist.h"

/* change this if you are using HTTP upload */
#ifndef UPLOADDIR
#define UPLOADDIR "/tmp"
#endif

/* CGI Environment Variables */
#define SERVER_SOFTWARE getenv("SERVER_SOFTWARE")
#define SERVER_NAME getenv("SERVER_NAME")
#define GATEWAY_INTERFACE getenv("GATEWAY_INTERFACE")

#define SERVER_PROTOCOL getenv("SERVER_PROTOCOL")
#define SERVER_PORT getenv("SERVER_PORT")
#define REQUEST_METHOD getenv("REQUEST_METHOD")
#define PATH_INFO getenv("PATH_INFO")
#define PATH_TRANSLATED getenv("PATH_TRANSLATED")
#define SCRIPT_NAME getenv("SCRIPT_NAME")
#define QUERY_STRING getenv("QUERY_STRING")
#define REMOTE_HOST getenv("REMOTE_HOST")
#define REMOTE_ADDR getenv("REMOTE_ADDR")
#define AUTH_TYPE getenv("AUTH_TYPE")
#define REMOTE_USER getenv("REMOTE_USER")
#define REMOTE_IDENT getenv("REMOTE_IDENT")
#define CONTENT_TYPE getenv("CONTENT_TYPE")
#define CONTENT_LENGTH getenv("CONTENT_LENGTH")

#define HTTP_USER_AGENT getenv("HTTP_USER_AGENT")

short accept_image();

/* form processing routines */
void unescape_url(char *url);
int read_cgi_input(llist* entries);
char *cgi_val(llist l,char *name);
char **cgi_val_multi(llist l, char *name);
char *cgi_name(llist l,char *value);
char **cgi_name_multi(llist l, char *value);

/* miscellaneous CGI routines */
int parse_cookies(llist *entries);
void print_cgi_env();
void print_entries(llist l);
char *escape_input(char *str);

/* boolean functions */
short is_form_empty(llist l);
short is_field_exists(llist l, char *str);
short is_field_empty(llist l, char *str);
