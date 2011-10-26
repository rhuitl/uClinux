/* vi:set tabstop=2 cindent shiftwidth=2: */
/*
 *  Boa, an http server
 *  Copyright (C) 1995 Paul Phillips <psp@well.com>
 *  Some changes (C) 1998 Martin Hinner <martin@tdp.cz>
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

/* boa: config.c */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>

#ifndef EMBED
# include "y.tab.h"
#else
# define STMT_NO_ARGS	0
# define STMT_ONE_ARG	1
# define STMT_TWO_ARGS	2
  char *mime_types;
#endif

#include "boa.h"
#include <netdb.h>

#ifdef EMBED
  FILE *yyin;
#else
  extern FILE *yyin;
  int yyparse(void);				/* Better match the output of lex */
#endif

#ifdef DEBUG
#define DBG(x) x
#else
#define DBG(x)
#endif

/* these came from config.c */
int server_port;
uid_t server_uid;
gid_t server_gid;
char *server_admin;
char *server_root;
char *server_name;
char *server_chroot;
int virtualhost;

char *document_root;
char *user_dir;
char *directory_index;
char *default_type;
char *dirmaker;

int ka_timeout;
int ka_max;

/* These came from log.c */
int verbose_logs = 1;

/* This comes from cgi.c */
int verbose_cgi_logs = 0;

/* These come from boa_grammar.y */
void add_alias(char * fakename, char * realname, int script);
void add_mime_type(char * extension, char * type);

/* These are new */
void c_set_user     (char *v1, char *v2, void *t);
void c_set_group    (char *v1, char *v2, void *t);
void c_set_string   (char *v1, char *v2, void *t);
void c_set_int      (char *v1, char *v2, void *t);
void c_set_unity    (char *v1, char *v2, void *t);
void c_add_type     (char *v1, char *v2, void *t);
void c_add_alias    (char *v1, char *v2, void *t);
void c_add_cp_url   (char *v1, char *v2, void *t);
void c_add_cp_brows	(char *v1, char *v2, void *t);
void c_add_vhost    (char *v1, char *v2, void *t);
void c_add_browserm (char *v1, char *v2, void *t);
void c_codepage			(char *v1, char *v2, void *t);
void c_add_auth			(char *v1, char *v2, void *t);

/* Fakery to keep the value passed to action() a void *,
   see usage in table and c_add_alias() below */
int script_number   = SCRIPTALIAS;
int redirect_number = REDIRECT;
int alias_number    = ALIAS;

/* Need to be able to limit connections */
int max_connections = -1; /* -1 = unlimited */

/* Help keep the table below compact */
#define S0A STMT_NO_ARGS
#define S1A STMT_ONE_ARG
#define S2A STMT_TWO_ARGS

struct ccommand clist[] = {
	{ "Port",             S1A, c_set_int,      &server_port },
	{ "MaxConnections",   S1A, c_set_int,      &max_connections },
	{ "User",             S1A, c_set_user,     NULL },
	{ "Group",            S1A, c_set_group,    NULL },
	{ "ServerAdmin",      S1A, c_set_string,   &server_admin },
	{ "ServerRoot",       S1A, c_set_string,   &server_root },
	{ "ChRoot",           S1A, c_set_string,   &server_chroot },
#ifdef BOA_TIME_LOG
	{ "ErrorLog",         S1A, c_set_string,   &error_log_name },
	{ "AccessLog",        S1A, c_set_string,   &access_log_name },
	{ "CgiLog",           S1A, c_set_string,   &cgi_log_name },
#endif
#if defined(BOA_TIME_LOG) && !defined(NO_REFERER_LOG)
	{ "RefererLog",       S1A, c_set_string,   &referer_log_name },
#endif
#if defined(BOA_TIME_LOG) && !defined(NO_AGENT_LOG)
	{ "AgentLog",         S1A, c_set_string,   &agent_log_name },
#endif
	{ "VerboseCGILogs",   S0A, c_set_unity,    &verbose_cgi_logs },
	{ "ServerName",       S1A, c_set_string,   &server_name },
	{ "VirtualHost",      S2A, c_add_vhost,    NULL },
	{ "DocumentRoot",     S1A, c_set_string,   &document_root },
	{ "UserDir",          S1A, c_set_string,   &user_dir },
	{ "DirectoryIndex",   S1A, c_set_string,   &directory_index },
	{ "DirectoryMaker",   S1A, c_set_string,   &dirmaker },
	{ "KeepAliveMax",     S1A, c_set_int,      &ka_max },
	{ "KeepAliveTimeout", S1A, c_set_int,      &ka_timeout },
	{ "MimeTypes",        S1A, c_set_string,   &mime_types },
	{ "DefaultType",      S1A, c_set_string,   &default_type },
	
	{ "LocalCodepage",    S1A, c_set_string,   &local_codepage },
	{ "Codepage",					S2A, c_codepage,     NULL },
	{ "CodepageByURL",    S2A, c_add_cp_url,   NULL },
	{ "CodepageByBrowser",S2A, c_add_cp_brows, NULL },
	
#ifdef USE_BROWSERMATCH
	{ "BrowserMatch",     S2A, c_add_browserm, NULL },
#endif
#ifdef USE_AUTH
	{ "Auth",							S2A, c_add_auth,		 NULL },
#endif
	{ "AddType",          S2A, c_add_type,     NULL },
	{ "ScriptAlias",      S2A, c_add_alias,    &script_number },
	{ "Redirect",         S2A, c_add_alias,    &redirect_number },
	{ "Alias",            S2A, c_add_alias,    &alias_number }
};

void set_server_port(int port) {
	server_port = port;
}

void c_set_user  (char *v1, char *v2, void *t)
{
	struct passwd * passwdbuf;
	char *endptr;
	int i;
	DBG(printf("User %s = ", v1);)
	i = strtol(v1, &endptr, 0);
	if (*v1 != '\0' && *endptr == '\0') {
		server_uid = i;
	} else {
		passwdbuf = getpwnam(v1);
		if(!passwdbuf) {
			fprintf(stderr, "No such user: %s\n", v1);
			exit(1);
		}
		server_uid = passwdbuf->pw_uid;
	}
	DBG(printf("%d\n", server_uid);)
}

void c_set_group (char *v1, char *v2, void *t)
{
	struct group * groupbuf;
	char *endptr;
	int i;
	DBG(printf("Group %s = ", v1);)
	i = strtol(v1, &endptr, 0);
	if (*v1 != '\0' && *endptr == '\0') {
		server_gid = i;
	} else {
		groupbuf = getgrnam(v1);
		if(!groupbuf) {
			fprintf(stderr, "No such group: %s\n", v1);
			exit(1);
		}
		server_gid = groupbuf->gr_gid;
	}
	DBG(printf("%d\n", server_gid);)
}

void c_set_string(char *v1, char *v2, void *t)
{
	char *s;
	DBG(printf("Setting pointer %p to string %s ..", t, v1);)
	if (t) {
		s=*(char **)t;
		if (s) free(s);
		*(char **)t = strdup(v1);
		DBG(printf("done.\n");)
	} else {
		DBG(printf("skipped.\n");)
	}
}

void c_set_int   (char *v1, char *v2, void *t){
	char *endptr;
	int i;
	DBG(printf("Setting pointer %p to integer string %s ..", t, v1);)
	if (t) {
		i=strtol(v1, &endptr, 0); /* Automatic base 10/16/8 switching */
		if (*v1 != '\0' && *endptr == '\0') {
			*(int *)t = i;
			DBG(printf(" Integer converted as %d, done\n",i);)
		} else {
			/* XXX should tell line number to user */
#if 0
			fprintf(stderr, "Error: %s found where integer expected\n",v1);
#endif
		}
	} else {
		DBG(printf("skipped.\n");)
	}
}

void c_set_unity (char *v1, char *v2, void *t)
{
	DBG(printf ("Setting pointer %p to unity\n", t);)
	if (t) *(int *)t = 1;
}

void c_add_type  (char *v1, char *v2, void *t)
{
	  add_mime_type(v2,v1);
}

void c_add_vhost  (char *v1, char *v2, void *t)
{
	add_virtual_host(v1,v2);
}

void c_add_alias (char *v1, char *v2, void *t)
{
	add_alias(v1, v2, *(int *)t);
}

void c_add_cp_url (char *v1, char *v2, void *t)
{
#ifdef USE_NLS
	add_cp_url(v1, v2);
#endif
}

void c_add_cp_brows (char *v1, char *v2, void *t)
{
#ifdef USE_NLS
	  add_cp_brows(v1, v2);
#endif
}

void c_add_browserm (char *v1, char *v2, void *t)
{
#ifdef USE_BROWSERMATCH
  add_browsermatch(v1, v2);
#endif
}

void c_codepage(char *v1, char *v2, void *t)
{
#ifdef USE_NLS
	nls_load_codepage(v1,v2);
#endif
}

void c_add_auth(char *v1, char *v2, void *t)
{
#ifdef USE_AUTH
	  auth_add(v1,v2);
#endif
}

struct ccommand *lookup_keyword(char *c)
{
	struct ccommand *p;
	DBG(printf("Checking string '%s' against keyword list\n",c);)
	for (p=clist; p<clist+(sizeof(clist)/sizeof(struct ccommand)); p++) {
		if (strcmp(c,p->name)==0) return p;
	}
	return NULL;
}


#ifdef EMBED

#include <ctype.h>

int
embedparse(FILE *fp)
{
	static char			 buf[128];
	char						*cp, *ep, *keyw;
#define MAX_ARG		3
	char						*arg[MAX_ARG];
	int							 args, line;
	struct ccommand	*cmd;

	if (fp == NULL)
		return(-1);
	
	bzero(arg, sizeof(arg));
	
	line = 0;
	while (fgets(buf, sizeof(buf), fp)) {
		line++;
		ep = buf + strlen(buf);
		if (*(ep - 1) != '\n') {
			fputs("Input line too long.\n", stderr);
			return(-1);
		}
		*--ep = 0; /* remove newline */
		while (ep > buf && isspace(*(ep - 1))) /* remove trailing whitespace */
			*--ep = 0;
		for (cp = buf; cp < ep && isspace(*cp); cp++)
			;
		if (cp >= ep || *cp == '#') /* skip blanks and comments */
			continue;
		keyw = cp;
		while (cp < ep && !isspace(*cp))
			cp++;
		while (cp < ep && isspace(*cp))
			*cp++ = '\0';
		cmd = lookup_keyword(keyw);
		if (cmd == NULL) {
			fprintf(stderr, "Bad keyword '%s'\n", keyw);
			return(-1);
		}
		args = 0;
		while (cp < ep && args < MAX_ARG) {
			arg[args++] = cp;
			while (cp < ep && !isspace(*cp))
				cp++;
			while (cp < ep && isspace(*cp))
				*cp++ = '\0';
		}
		DBG(fprintf(stderr, "%s args=%d '%s' '%s' '%s'\n", keyw, args,
				args >= 1 ? arg[0] : "",
				args >= 2 ? arg[1] : "",
				args >= 3 ? arg[2] : ""));
		switch (cmd->type) {
		case STMT_NO_ARGS:
			if (args != 0) {
				fprintf(stderr, "%s takes no arguments, line %d\n", keyw, line);
				return(-1);
			}
			break;
		case STMT_ONE_ARG:
			if (args != 1) {
				fprintf(stderr, "%s has only 1 argument, line %d\n", keyw, line);
				return(-1);
			}
			break;
		case STMT_TWO_ARGS:
			if (args != 2) {
				fprintf(stderr, "%s has only 2 arguments, line %d\n", keyw, line);
				return(-1);
			}
			break;
		default:
			fprintf(stderr, "unknown command type %s\n", keyw);
			return(-1);
		}
		if (cmd->action)
			(*cmd->action)(arg[0], arg[1], cmd->object);
	}
	return(0);
}

#endif /* EMBED */


/*
 * Name: read_config_files
 * 
 * Description: Reads config files via yyparse, then makes sure that 
 * all required variables were set properly.
 */
void read_config_files(void)
{
  char hostnamebuf[MAX_SITENAME_LENGTH + 1];
  struct hostent *hostentbuf;
	int	read_file = 0;

	mime_types = strdup("/etc/mime.types");

#ifdef EMBED

	/*
	 * default some variables so that we don't actually need a config
	 * file,  make sure you only include settings that can be undone
	 * by the config file in this section
	 */
	server_port = 80;
	default_type = strdup("text/html");
	document_root = strdup("/home/httpd");
	directory_index = strdup("index.html");
	server_name = strdup("");
	server_admin = strdup("root@localhost");
#ifdef BOA_TIME_LOG
	error_log_name = strdup("/var/log/boa.err.log");
	access_log_name = strdup("/var/log/boa.access.log");
#endif

	if ((yyin = fopen("boa.conf", "r"))) {
		if (embedparse(yyin)) {
			fputs("Error parsing config files, exiting\n", stderr);
			exit(1);
		}
		fclose(yyin);
		read_file++;
	}

	if ((yyin = fopen("/etc/config/boa.conf", "r"))) {
		if (embedparse(yyin)) {
			fputs("Error parsing config files, exiting\n", stderr);
			exit(1);
		}
		fclose(yyin);
		read_file++;
	}

	/*
	 * some of these defaults cannot be reversed from a config file,
	 * so only do them if no config file exists,  if you don't like
	 * this,  create a boa.conf for your application.
	 */
	if (read_file == 0) {
		add_alias("/cgi-bin/", "/home/httpd/cgi-bin/", SCRIPTALIAS);
		auth_add("/cgi-bin/", "/etc/config/passwd");
#ifdef ROOT_AUTH
		auth_add("/index.html", "/etc/config/passwd");
		auth_add("/", "/etc/config/passwd");
#endif /*ROOT_AUTH*/
	}
#ifdef CONFIG_USER_OLD_PASSWORDS
	{	extern char auth_old_password[16];
		char temps[256], *p;
		FILE *fp;

#ifdef CONFIG_USER_FLATFSD_FLATFSD
		fp = fopen("/etc/config/config", "r");
#else
		fp = fopen("/etc/passwd", "r");
#endif
		*auth_old_password = '\0';
		if (fp != NULL) {
			while (fgets(temps, 256, fp) != NULL) {
				if ((p = strchr(temps, '\n')) != NULL)
					*p = '\0';
				if ((p = strchr(temps, ' ')) != NULL) {
					*p++ = '\0';
					if (strcmp(temps, "passwd") == 0) {
						strcpy(auth_old_password, p);
						break;
					}
				}
				
			}
			fclose(fp);
		}
	}
#endif
  /* mime types are not parsed from file with embedded parser*/
	{	char temps[256], *p;
		FILE *fp;

		fp = fopen(mime_types, "r");
		if (fp != NULL) {
			while (fgets(temps, 256, fp) != NULL) {
			  /* process next line */
			  if(temps[0] != '#') {
			    if ((p = strchr(temps, '\n')) != NULL)
			      *p = '\0'; /* null terminate line */
			    if (((p = strchr(temps, ' ')) != NULL) ||
				((p = strchr(temps, '\t')) != NULL)) {
			      /* find *first* blank */
			      for(p=temps;!isblank(*p);p++);

			      *p++ = '\0';
			      while(isblank(*p)) {
				p++;
			      };/* skip space */

			      add_mime_type(p,temps);
			    }
			  }
			}
			fclose(fp);
		} else {
			fputs("Error opening MimeTypes=", stderr);
			fputs(mime_types,stderr);
			fputs("\n", stderr);
		}
	}
#else /* EMBED */

	yyin = fopen("boa.conf", "r");

	if (!yyin) {
		fputs("Could not open boa.conf for reading.\n", stderr);
		exit(1);
	}
	if (yyparse()) {
		fputs("Error parsing config files, exiting\n", stderr);
		exit(1);
	}

#endif /* EMBED */

  if (!server_name) {
    gethostname(hostnamebuf, MAX_SITENAME_LENGTH);
    hostentbuf = gethostbyname(hostnamebuf);
    if (!hostentbuf) {
      fputs("Cannot determine hostname. Set ServerName in boa.conf.\n",
      stderr);
      exit(1);
    }
    server_name = strdup((char *)hostentbuf->h_name);
  }

	if(chdir(server_root) == -1) {
		fprintf(stderr, "Could not chdir to ServerRoot.\n");
		exit(1);
	}
}
