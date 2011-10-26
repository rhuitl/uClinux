/*
 * Copyright (c) 1985, 1989 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: @(#)ftp_var.h	5.9 (Berkeley) 6/1/90
 *	$Id: ftp_var.h,v 1.1 2000-07-18 01:47:08 gerg Exp $
 */

/*
 * FTP global variables.
 */

#include <setjmp.h>
#include <sys/param.h>

/*
 * Tick counter step size.
 */
#define TICKBYTES     10240

#ifndef Extern
#define Extern extern
#endif


/*
 * Options and other state info.
 */
Extern int	rl_inhibit;	/* disable readline support */
Extern int	traceflag;	/* trace packets exchanged */
Extern int	hash;		/* print # for each buffer transferred */
Extern int	tick;		/* print byte counter during transfers */
Extern int	sendport;	/* use PORT cmd for each data connection */
Extern int	verbose;	/* print messages coming back from server */
Extern int	connected;	/* connected to server */
Extern int	fromatty;	/* input is from a terminal */
Extern int	interactive;	/* interactively prompt on m* cmds */
Extern int	debug;		/* debugging level */
Extern int	bell;		/* ring bell on cmd completion */
Extern int	doglob;		/* glob local file names */
Extern int	autologin;	/* establish user account on connection */
Extern int	proxy;		/* proxy server connection active */
Extern int	proxflag;	/* proxy connection exists */
Extern int	sunique;	/* store files on server with unique name */
Extern int	runique;	/* store local files with unique name */
Extern int	mcase;		/* map upper to lower case for mget names */
Extern int	ntflag;		/* use ntin ntout tables for name xlation */
Extern int	mapflag;	/* use mapin mapout templates on file names */
Extern int	code;		/* return/reply code for ftp command */
Extern int	crflag;		/* if 1, strip car. rets. on ascii gets */
Extern char     pasv[64];       /* passive port for proxy data connection */
Extern int      passivemode;    /* passive mode enabled */
Extern char	*altarg;	/* argv[1] with no shell-like preprocessing  */
Extern char	ntin[17];	/* input translation table */
Extern char	ntout[17];	/* output translation table */
Extern char	mapin[MAXPATHLEN];	/* input map template */
Extern char	mapout[MAXPATHLEN];	/* output map template */
Extern char	typename[32];		/* name of file transfer type */
Extern int	type;			/* requested file transfer type */
Extern int	curtype;		/* current file transfer type */
Extern char	structname[32];		/* name of file transfer structure */
Extern int	stru;			/* file transfer structure */
Extern char	formname[32];		/* name of file transfer format */
Extern int	form;			/* file transfer format */
Extern char	modename[32];		/* name of file transfer mode */
Extern int	mode;			/* file transfer mode */
Extern char	bytename[32];		/* local byte size in ascii */
Extern int	bytesize;		/* local byte size in binary */

Extern char	*hostname;	/* name of host connected to */
Extern int	unix_server;	/* server is unix, can use binary for ascii */
Extern int	unix_proxy;	/* proxy is unix, can use binary for ascii */

/*Extern struct	servent *sp;*/	/* service spec for tcp/ftp */
Extern int	ftp_port;	/* htons'd port number for ftp service */

Extern sigjmp_buf toplevel;	/* non-local goto stuff for cmd scanner */

Extern char	line[200];	/* input line buffer */
Extern char	*stringbase;	/* current scan point in line buffer */
Extern char	argbuf[200];	/* argument storage buffer */
Extern char	*argbase;	/* current storage point in arg buffer */
Extern int	cpend;		/* flag: if != 0, then pending server reply */
Extern int	mflag;		/* flag: if != 0, then active multi command */

Extern int	options;	/* used during socket creation */

/*
 * Format of command table.
 */
struct cmd {
	const char *c_name;	/* name of command */
	const char *c_help;	/* help string */
	char c_bell;		/* give bell when command completes */
	char c_conn;		/* must be connected to use command */
	char c_proxy;		/* proxy server may execute */

        /* Exactly one of these should be non-NULL. */
	void (*c_handler_v)(int, char **); /* function to call */
	void (*c_handler_0)(void);
	void (*c_handler_1)(const char *);
};

struct macel {
	char mac_name[9];	/* macro name */
	char *mac_start;	/* start of macro in macbuf */
	char *mac_end;		/* end of macro in macbuf */
};

Extern int macnum;			/* number of defined macros */
Extern struct macel macros[16];
Extern char macbuf[4096];
#define MACBUF_SIZE 4096

char *hookup(char *host, int port);
struct cmd *getcmd(const char *);
char **makeargv(int *pargc, char **parg);
int dologin(const char *host);
int command(const char *fmt, ...);
void sendrequest(const char *cmd, char *local, char *remote, int printnames);
void recvrequest(const char *cmd, char *local, char *remote, 
		 const char *lmode, int printnames);
int another(int *pargc, char ***pargv, const char *prompt);
void blkfree(char **av0);
void fatal(const char *msg);
int getreply(int expecteof);
void domacro(int argc, char *argv[]);
void pswitch(int flag);
int xruserpass(const char *host, char **aname, char **apass, char **aacct);
void setpeer(int argc, char *argv[]);
void quit(void);
void changetype(int newtype, int show);
