/*
 *	DDNS v3 Client
 *
 *		Author:		Alan Yates <alany@ay.com.au>
 *		Win32 Port:	Kieron Briggs <kieron@kieron.nu>
 *		Version:	$Id: ddns3.c,v 1.2 2003/03/20 05:21:59 alany Exp $
 */
#include <stdio.h>
#ifdef WIN32
#include <windows.h>
#define strcasecmp(x,y) stricmp((x),(y))
else
#include <unistd.h>
#endif
#include <string.h>
#include <stdlib.h>
#include "ctx.h"

#define	ERR_USAGE	-1
#define	ERR_ARGUMENTS	-2
#define	ERR_CONNECTION	-3
#define	ERR_AUTH	-4
#define ERR_CLOSING	-5
#define ERR_LOGIC	-6

struct client_vars {
	char *host;
	char *port;
	char *auth;
	char *user;
	char *pass;
	int debug;
} CV;

static void
help(void) {
	fprintf(stderr, "\n");
	fprintf(stderr, "DDNS Client v3 (c) :: http://www.ddns.nu/\n");
	fprintf(stderr, "(c) 1999-2002 Alan Yates <alany@ay.com.au>\n");
	fprintf(stderr, "$Id: ddns3.c,v 1.2 2003/03/20 05:21:59 alany Exp $\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Usage: ddns3 <required args> [optional args] <action list>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Required args\n");
	fprintf(stderr, "	--user	username\n");
	fprintf(stderr, "	--pass	password\n");
	fprintf(stderr, "Optional args\n");
	fprintf(stderr, "	--host	server-hostname		specify server host\n");
	fprintf(stderr, "	--port	server-tcp-port		specify server port\n");
	fprintf(stderr, "	--debug				activate debug mode\n");
	fprintf(stderr, "	--auth	auth-name		specify authentication type\n");
	fprintf(stderr, "Authentication types:\n");
#ifdef WIN32
	fprintf(stderr, "	plaintext, md5, ddns (default), strong\n");
#else
	fprintf(stderr, "	plaintext, crypt, md5, ddns (default), strong\n");
#endif
	fprintf(stderr, "Actions:\n");
	fprintf(stderr, "	list				lists IP-Handles\n");
	fprintf(stderr, "	set <handle> <ip>		sets an IP-Handle's value\n");
	fprintf(stderr, "	guess <handle> <source>		sets an IP-Handle's value\n");
	fprintf(stderr, "					guessing the IP from the <source>\n");
	fprintf(stderr, "					end of the connection, ends are\n");
	fprintf(stderr, "					named 'remote' or 'local'\n");
	fprintf(stderr, "\n");
}

static int
parse_args(int argc, char **argv, char **env) {
	int i;

	if(argc == 1) {
		help();
		exit(ERR_USAGE);
	}

	for(i = 1; i < argc; i++) {
		if(!strcmp("--user", argv[i]) && i+1 < argc) {
			CV.user = argv[++i];
		} else if(!strcmp("--pass", argv[i]) && i+1 < argc) {
			CV.pass = argv[++i];
		} else if(!strcmp("--host", argv[i]) && i+1 < argc) {
			CV.host = argv[++i];
		} else if(!strcmp("--port", argv[i]) && i+1 < argc) {
			CV.port = argv[++i];
		} else if(!strcmp("--auth", argv[i]) && i+1 < argc) {
			CV.auth = argv[++i];
		} else if(!strcmp("--debug", argv[i])) {
			CV.debug = -1;
		}
		else if(!strcmp("list", argv[i])) break;
		else if(!strcmp("set", argv[i])) break;
		else if(!strcmp("guess", argv[i])) break;
		else {
			fprintf(stderr, "unknown or malformed argument: %s\n", argv[i]);
			exit(ERR_ARGUMENTS);
		}
	}
	return i;
}

static void
defaults(void) {
	CV.host = "ns.ddns.nu";
	CV.port = "5000";
	CV.auth = "ddns";
	CV.debug = 0;
}

static void
check_args(void) {
	int err = 0;

	if(!CV.user) {
		fprintf(stderr, "client_error: you must specify a username\n");
		err ++;
	}

	if(!CV.pass) {
		fprintf(stderr, "client_error: you must specify a password\n");
		err ++;
	}

	if(err > 0) {
		fprintf(stderr, "client_exit: argument parsing; %d errors\n", err);
		exit(ERR_ARGUMENTS);
	}
}

static int
actions(struct ddns3_ctx *c, int argc, char **argv, int start) {
	int i, err = 0;
	for(i = start; i < argc; i++) {
		if(!strcmp("list", argv[i])) {
			if(ddns3_ctx_list(c) < 0) {
				fprintf(stderr, "server_message: %s", c->buf);
				fprintf(stderr, "client_error: could not get handle list\n");
				err++;
			} else {
				int j;
				for(j = 0; c->list[j]; j += 2) {
					printf("%-20s %s\n", c->list[j], c->list[j+1]);
				}
			}
		} else if(!strcmp("set", argv[i]) && i+2 < argc) {
			if(ddns3_ctx_set(c, argv[i+1], argv[i+2]) < 0) {
				fprintf(stderr, "server_message: %s", c->buf);
				fprintf(stderr, "client_error: could not set handle %s to ip %s, closing\n", argv[i+1], argv[i+2]);
				err++;
			} else printf("server_message: %s", c->buf);
			
			i += 2;
		} else if(!strcmp("guess", argv[i]) && i+2 < argc) {
			int type = -1;
			if(!strcasecmp("remote", argv[i+2])) type = GUESS_REMOTE;
			else if(!strcasecmp("local", argv[i+2])) type = GUESS_LOCAL;
			else {
				fprintf(stderr, "client_error: invalid guess type: %s\n", argv[i+2]);
				return ERR_ARGUMENTS;
			}
			if(ddns3_ctx_guess(c, argv[i+1], type) < 0) {
				fprintf(stderr, "server_message: %s", c->buf);
				fprintf(stderr, "client_error: could not set handle %s by guessing IP, closing\n", argv[i+1]);
				err++;
			} else printf("server_message: %s", c->buf);

			i += 2;
		} else {
			fprintf(stderr, "unknown or mangled action: %s\n", argv[i]);
			return ERR_ARGUMENTS;
		}
	}
	
	return err;
}

int
main(int argc, char **argv, char **env) {
	int start, ret;
	struct ddns3_ctx *c;

	/* arguments and ugly stuff */
	memset(&CV, 0, sizeof(struct client_vars));
	defaults();
	start = parse_args(argc, argv, env);
	check_args();

	/* now the long and ugly stuff */

	/* connect and login to DDNS server */
	if(ddns3_ctx_new(&c, CV.host, atoi(CV.port)) < 0) {
		fprintf(stderr, "client_error: creating ddns3_ctx, exiting\n");
		exit(ERR_LOGIC);
	}
	if(ddns3_ctx_connect(c) < 0) {
		fprintf(stderr, "server_message: %s", c->buf);
		fprintf(stderr, "client_error: could not connect to %s:%d, exiting\n", CV.host, atoi(CV.port));
		exit(ERR_CONNECTION);
	}
	if(ddns3_ctx_login(c, CV.auth, CV.user, CV.pass) < 0) {
		fprintf(stderr, "server_message: %s", c->buf);
		fprintf(stderr, "client_error: could not authenticate\n");
		exit(ERR_AUTH);
	}

	/* do what we have to */
	ret = actions(c, argc, argv, start);

	/* close connection nicely */
	if(ddns3_ctx_logout(c) < 0) {
		fprintf(stderr, "server_message: %s", c->buf);
		fprintf(stderr, "client_error: could not logout, giving up clean goodbye, exiting\n");
		exit(ERR_CLOSING);
	}
	if(ddns3_ctx_disconnect(c) < 0) {
		fprintf(stderr, "server_message: %s", c->buf);
		fprintf(stderr, "client_error: disconnect failed, giving up\n");
		exit(ERR_CLOSING);
	}
	if(ddns3_ctx_del(&c) < 0) {
		fprintf(stderr, "client_error: could not delete ddns3_ctx, oh well\n");
		exit(ERR_LOGIC);
	}
	
	return ret;
}
