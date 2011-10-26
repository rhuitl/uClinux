/***************************************
    This is part of frox: A simple transparent FTP proxy
    Copyright (C) 2000 James Hollingshead

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    common.h -- miscellaneous definitions.
					
***************************************/

#ifndef COMMON_H
#define COMMON_H		/*+ To stop multiple inclusions. + */

#include "config.h"

#include <stdio.h>
#include <sys/types.h>

#ifndef HAVE_U_INT16_T
typedef unsigned short u_int16_t;
#endif
#ifndef HAVE_U_INT32_T
typedef unsigned long u_int32_t;
#endif

#if STDC_HEADERS
# include <stdlib.h>
# include <string.h>
#elif HAVE_STRINGS_H
# include <strings.h>
#endif /* STDC_HEADERS */

#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif	/* HAVE_SYS_TIME_H */
#endif /* TIME_WITH_SYS_TIME */

#include "sstr.h"

/* Defines */
#ifdef DEBUG
#define debug(S) fprintf(stderr,S)
#define debug2(S,T) fprintf(stderr,S,T)
#else
#define debug(S)
#define debug2(S,T)
#endif

#define debug_err(S)  fprintf(stderr, "ERROR: \"%s\" at line %d of %s\n", S, \
                      __LINE__, __FILE__);
#define debug_perr(S) fprintf(stderr, \
                      "ERROR: \"%s: %s\" at line %d of %s\n", S, \
                      strerror(errno), __LINE__, __FILE__);

#define TRUE 1
#define FALSE 0

#define DM    242
#define IP    244
#define WILL  251
#define WONT  252
#define DO    253
#define DONT  254
#define IAC   255

#define BUF_LEN 4096
#define DATA_BUF_LEN 65536
#define MAX_LINE_LEN 256	/* For control connections */

#define GET_CLNT 1
#define GET_SRVR 2
#define GET_BOTH 3

/*Log levels */
#define VERBOSE 25
#define INFO    20		/* Who connects, etc. */
#define IMPORT  15		/* Startup messages as well. */
#define ERROR   10		/* Non critical errors */
#define ATTACK   5		/* Suspicious stuff */

#define CACHE_CMDS 0
#define FTP_CMDS 1
#define NUM_CMD_ARRAYS 2

typedef enum _socketuse {
	ACTV,
	PASV,
	CTRL
} socketuse;

/* Details of a file transfer - for logging purposes only at
 * the moment */

typedef struct _connection {
	struct sockaddr_in address;
	int fd;

	sstr *buf;
} connection;

/* Confusingly there are three different addresses for the server
 * stored here.
 *
 * apparent_server_address is the address that the client believes it
 * is connected to, and is used to initiate transparent data
 * connections to the client. For a client using NTP this will
 * generally be the address of frox.
 *
 * The one in server_control is the address that frox physically
 * connects to, and from which it expects to receive the data
 * connection if "SameAddress" is set. This may be different from above
 * if frox is connecting via another proxy ("FTPProxy" is set), or if
 * a ccp script has redirected frox.
 * 
 * final_server_address is the address of the ftp server we are
 * downloading from. It is used for caching and to send a modified
 * user command to an intermediary proxy. */

typedef struct _session_info {
	connection client_control;
	connection server_control;
	connection client_data;
	connection server_data;
	sstr *server_name;

	sstr *last_command;	/*Added to support APConv */
	sstr *username, *passwd;

	struct sockaddr_in apparent_server_address;
	struct sockaddr_in final_server_address;

	enum { ACTIVE, PASSIVE, APCONV, PACONV } mode;
	enum { UPLOAD, DOWNLOAD, NEITHER } state;
	enum { SUPPRESSED, FAKED, AWAITED, DONE } greeting;	/*220 greeting */
	sstr *greetingmsg;
	int server_listen;	/*fd we are listening on */
	int client_listen;

	struct cmd_struct *cmd_arrays[NUM_CMD_ARRAYS];

/*Details related to the current transfer. Mainly for logging*/
	int needs_logging;
	sstr *strictpath;	/*URI style path, built from cwd commands */
	sstr *filename;

	int virus;		/* -1=not checked, 0=clear, 1=infected */
	int cached;		/* 0=cache miss, 1=cache hit */
	int upload;
	int anonymous;
	void *ssl_sc, *ssl_sd;	/*SSL handles for server control and data */

} session_info;

#include "configs.h"
#include "misc.h"

/*******************
**Global Variables**
********************/
extern session_info *info;
extern pid_t cmgrpid, tdatapid;

#endif /* COMMON_H */
