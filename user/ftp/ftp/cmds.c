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
 */

/*
 * from: @(#)cmds.c	5.26 (Berkeley) 3/5/91
 */
char cmds_rcsid[] = 
   "$Id: cmds.c,v 1.3 2001-08-07 03:33:22 pdh Exp $";

/*
 * FTP User Program -- Command Routines.
 */
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <arpa/ftp.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <ctype.h>
#include <limits.h>	/* for PATH_MAX */
#include <time.h>
#include <string.h>
#include <unistd.h>
#ifdef __USE_READLINE__
#include <readline/readline.h>
#include <readline/history.h>
#endif

#include "ftp_var.h"
#include "pathnames.h"
#include "cmds.h"
#include "glob.h"

void intr(int);

extern FILE *cout;
extern int data;
extern const char *home;
extern off_t restart_point;
extern char reply_string[];

static char *mname;
static sigjmp_buf jabort;
static sigjmp_buf abortprox;

static char *remglob(char *argv[], int doswitch);
static int checkglob(int fd, const char *pattern);
static char *dotrans(char *name);
static char *domap(char *name);
static char *globulize(char *str);
static int confirm(const char *cmd, const char *file);
static int getit(int argc, char *argv[], int restartit, const char *modestr);
static void quote1(const char *initial, int argc, char **argv);


/*
 * pipeprotect: protect against "special" local filenames by prepending
 * "./". Special local filenames are "-" and "|..." AND "/...".
 */
static char *pipeprotect(char *name) 
{
	char *nu;
	if (strcmp(name, "-") && *name!='|' && *name!='/') {
		return name;
	}

	/* We're going to leak this memory. XXX. */
	nu = malloc(strlen(name)+3);
	if (nu==NULL) {
		perror("malloc");
		code = -1;
		return NULL;
	}
	strcpy(nu, ".");
	if (*name != '/') strcat(nu, "/");
	strcat(nu, name);
	return nu;
}

/*
 * Look for embedded ".." in a pathname and change it to "!!", printing
 * a warning.
 */
static char *pathprotect(char *name)
{
	int gotdots=0, i, len;
	
	/* Convert null terminator to trailing / to catch a trailing ".." */
	len = strlen(name)+1;
	name[len-1] = '/';

	/*
	 * State machine loop. gotdots is < 0 if not looking at dots,
	 * 0 if we just saw a / and thus might start getting dots,
	 * and the count of dots seen so far if we have seen some.
	 */
	for (i=0; i<len; i++) {
		if (name[i]=='.' && gotdots>=0) gotdots++;
		else if (name[i]=='/' && gotdots<0) gotdots=0;
		else if (name[i]=='/' && gotdots==2) {
		    printf("Warning: embedded .. in %.*s (changing to !!)\n",
			   len-1, name);
		    name[i-1] = '!';
		    name[i-2] = '!';
		    gotdots = 0;
		}
		else if (name[i]=='/') gotdots = 0;
		else gotdots = -1;
	}
	name[len-1] = 0;
	return name;
}


/*
 * `Another' gets another argument, and stores the new argc and argv.
 * It reverts to the top level (via main.c's intr()) on EOF/error.
 *
 * Returns false if no new arguments have been added.
 */
int
another(int *pargc, char ***pargv, const char *prompt)
{
	int margc;
	char **margv;

	unsigned len = strlen(line);
	int ret;

	if (len >= sizeof(line) - 3) {
		printf("sorry, arguments too long\n");
		intr(0);
	}
	printf("(%s) ", prompt);
	line[len++] = ' ';
	if (fgets(&line[len], sizeof(line) - len, stdin) == NULL)
		intr(0);
	len += strlen(&line[len]);
	if (len > 0 && line[len - 1] == '\n')
		line[len - 1] = '\0';
	margv = makeargv(&margc, NULL);
	ret = margc > *pargc;
	*pargc = margc;
	*pargv = margv;
	return ret;
}

/*
 * Connect to peer server and
 * auto-login, if possible.
 */
void
setpeer(int argc, char *argv[])
{
	char *host;
	unsigned short port;

	if (connected) {
		printf("Already connected to %s, use close first.\n",
			hostname);
		code = -1;
		return;
	}
	if (argc < 2)
		(void) another(&argc, &argv, "to");
	if (argc < 2 || argc > 3) {
		printf("usage: %s host-name [port]\n", argv[0]);
		code = -1;
		return;
	}
	port = ftp_port;
	if (argc > 2) {
		port = atoi(argv[2]);
		if (port < 1) {
			printf("%s: bad port number-- %s\n", argv[1], argv[2]);
			printf ("usage: %s host-name [port]\n", argv[0]);
			code = -1;
			return;
		}
		port = htons(port);
	}
	host = hookup(argv[1], port);
	if (host) {
		int overbose;

		connected = 1;
		/*
		 * Set up defaults for FTP.
		 */
		(void) strcpy(typename, "ascii"), type = TYPE_A;
		curtype = TYPE_A;
		(void) strcpy(formname, "non-print"), form = FORM_N;
		(void) strcpy(modename, "stream"), mode = MODE_S;
		(void) strcpy(structname, "file"), stru = STRU_F;
		(void) strcpy(bytename, "8"), bytesize = 8;
		if (autologin)
			(void) dologin(argv[1]);

#if defined(__unix__) && CHAR_BIT == 8
/*
 * this ifdef is to keep someone form "porting" this to an incompatible
 * system and not checking this out. This way they have to think about it.
 */
		overbose = verbose;
		if (debug == 0)
			verbose = -1;
		if (command("SYST") == COMPLETE && overbose) {
			register char *cp, c = 0;
			cp = index(reply_string+4, ' ');
			if (cp == NULL)
				cp = index(reply_string+4, '\r');
			if (cp) {
				if (cp[-1] == '.')
					cp--;
				c = *cp;
				*cp = '\0';
			}

			printf("Remote system type is %s.\n",
				reply_string+4);
			if (cp)
				*cp = c;
		}
		if (!strncmp(reply_string, "215 UNIX Type: L8", 17)) {
			if (proxy)
				unix_proxy = 1;
			else
				unix_server = 1;
			/*
			 * Set type to 0 (not specified by user),
			 * meaning binary by default, but don't bother
			 * telling server.  We can use binary
			 * for text files unless changed by the user.
			 */
			type = 0;
			(void) strcpy(typename, "binary");
			if (overbose)
			    printf("Using %s mode to transfer files.\n",
				typename);
		} else {
			if (proxy)
				unix_proxy = 0;
			else
				unix_server = 0;
			if (overbose && 
			    !strncmp(reply_string, "215 TOPS20", 10))
				printf(
"Remember to set tenex mode when transfering binary files from this machine.\n");
		}
		verbose = overbose;
#endif /* unix */
	}
}

struct	types {
	const char *t_name;
	const char *t_mode;
	int t_type;
	const char *t_arg;
} types[] = {
	{ "ascii",	"A",	TYPE_A,	NULL },
	{ "binary",	"I",	TYPE_I,	NULL },
	{ "image",	"I",	TYPE_I,	NULL },
	{ "ebcdic",	"E",	TYPE_E,	NULL },
	{ "tenex",	"L",	TYPE_L,	bytename },
	{ NULL, NULL, 0, NULL }
};

/*
 * Set transfer type.
 */
static 
void
do_settype(const char *thetype) 
{
	struct types *p;
	int comret;

	for (p = types; p->t_name; p++)
		if (strcmp(thetype, p->t_name) == 0)
			break;
	if (p->t_name == 0) {
		printf("%s: unknown mode\n", thetype);
		code = -1;
		return;
	}
	if ((p->t_arg != NULL) && (*(p->t_arg) != '\0'))
		comret = command("TYPE %s %s", p->t_mode, p->t_arg);
	else
		comret = command("TYPE %s", p->t_mode);
	if (comret == COMPLETE) {
		(void) strcpy(typename, p->t_name);
		curtype = type = p->t_type;
	}
}

void
settype(int argc, char *argv[])
{
	struct types *p;
	if (argc > 2) {
		const char *sep;

		printf("usage: %s [", argv[0]);
		sep = " ";
		for (p = types; p->t_name; p++) {
			printf("%s%s", sep, p->t_name);
			sep = " | ";
		}
		printf(" ]\n");
		code = -1;
		return;
	}
	if (argc < 2) {
		printf("Using %s mode to transfer files.\n", typename);
		code = 0;
		return;
	}
	do_settype(argv[1]);
}

/*
 * Internal form of settype; changes current type in use with server
 * without changing our notion of the type for data transfers.
 * Used to change to and from ascii for listings.
 */
void
changetype(int newtype, int show)
{
	register struct types *p;
	int comret, oldverbose = verbose;
	int oldtick = tick;

	if (newtype == 0)
		newtype = TYPE_I;
	if (newtype == curtype)
		return;
	if (debug == 0 && show == 0)
		verbose = 0;
	tick = 0;
	for (p = types; p->t_name; p++)
		if (newtype == p->t_type)
			break;
	if (p->t_name == 0) {
		printf("ftp: internal error: unknown type %d\n", newtype);
		return;
	}
	if (newtype == TYPE_L && bytename[0] != '\0')
		comret = command("TYPE %s %s", p->t_mode, bytename);
	else
		comret = command("TYPE %s", p->t_mode);
	if (comret == COMPLETE)
		curtype = newtype;
	verbose = oldverbose;
	tick = oldtick;
}

/*
 * Set binary transfer type.
 */
/*VARARGS*/
void
setbinary(void)
{
	do_settype("binary");
}

/*
 * Set ascii transfer type.
 */
/*VARARGS*/
void
setascii(void)
{
	do_settype("ascii");
}

/*
 * Set tenex transfer type.
 */
/*VARARGS*/
void
settenex(void)
{
	do_settype("tenex");
}

/*
 * Set file transfer mode.
 */
/*ARGSUSED*/
void
setmode(void)
{
	printf("We only support %s mode, sorry.\n", modename);
	code = -1;
}

/*
 * Set file transfer format.
 */
/*ARGSUSED*/
void
setform(void)
{
	printf("We only support %s format, sorry.\n", formname);
	code = -1;
}

/*
 * Set file transfer structure.
 */
void
setstruct(void)
{
	printf("We only support %s structure, sorry.\n", structname);
	code = -1;
}

/*
 * Send a single file.
 */
void
put(int argc, char *argv[])
{
	const char *cmd;
	int loc = 0;
	char *oldargv1, *oldargv2;

	if (argc == 2) {
		argc++;
		argv[2] = argv[1];
		loc++;
	}
	if (argc < 2 && !another(&argc, &argv, "local-file"))
		goto usage;
	if (argc < 3 && !another(&argc, &argv, "remote-file")) {
usage:
		printf("usage: %s local-file remote-file\n", argv[0]);
		code = -1;
		return;
	}
	oldargv1 = argv[1];
	oldargv2 = argv[2];
	argv[1] = globulize(argv[1]);
	if (!argv[1]) {
		code = -1;
		return;
	}
	/*
	 * If "globulize" modifies argv[1], and argv[2] is a copy of
	 * the old argv[1], make it a copy of the new argv[1].
	 */
	if (argv[1] != oldargv1 && argv[2] == oldargv1) {
		argv[2] = argv[1];
	}
	cmd = (argv[0][0] == 'a') ? "APPE" : ((sunique) ? "STOU" : "STOR");
	if (loc && ntflag) {
		argv[2] = dotrans(argv[2]);
	}
	if (loc && mapflag) {
		argv[2] = domap(argv[2]);
	}
	sendrequest(cmd, argv[1], argv[2],
	    argv[1] != oldargv1 || argv[2] != oldargv2);
}

void mabort(int);

/*
 * Send multiple files.
 */
void
mput(int argc, char *argv[])
{
	register int i;
	void (*oldintr)(int);
	int ointer;
	char *tp;

	if (argc < 2 && !another(&argc, &argv, "local-files")) {
		printf("usage: %s local-files\n", argv[0]);
		code = -1;
		return;
	}
	mname = argv[0];
	mflag = 1;
	oldintr = signal(SIGINT, mabort);
	(void) sigsetjmp(jabort, 1);
	if (proxy) {
		char *cp, *tp2, tmpbuf[PATH_MAX];

		while ((cp = remglob(argv,0)) != NULL) {
			if (*cp == 0) {
				mflag = 0;
				continue;
			}
			if (mflag && confirm(argv[0], cp)) {
				tp = cp;
				if (mcase) {
					while (*tp && !islower(*tp)) {
						tp++;
					}
					if (!*tp) {
						tp = cp;
						tp2 = tmpbuf;
						while ((*tp2 = *tp) != '\0') {
						     if (isupper(*tp2)) {
						        *tp2 = 'a' + *tp2 - 'A';
						     }
						     tp++;
						     tp2++;
						}
					}
					tp = tmpbuf;
				}
				if (ntflag) {
					tp = dotrans(tp);
				}
				if (mapflag) {
					tp = domap(tp);
				}
				sendrequest((sunique) ? "STOU" : "STOR",
				    cp, tp, cp != tp || !interactive);
				if (!mflag && fromatty) {
					ointer = interactive;
					interactive = 1;
					if (confirm("Continue with","mput")) {
						mflag++;
					}
					interactive = ointer;
				}
			}
		}
		(void) signal(SIGINT, oldintr);
		mflag = 0;
		return;
	}
	for (i = 1; i < argc; i++) {
		register char **cpp, **gargs;

		if (!doglob) {
			if (mflag && confirm(argv[0], argv[i])) {
				tp = (ntflag) ? dotrans(argv[i]) : argv[i];
				tp = (mapflag) ? domap(tp) : tp;
				sendrequest((sunique) ? "STOU" : "STOR",
				    argv[i], tp, tp != argv[i] || !interactive);
				if (!mflag && fromatty) {
					ointer = interactive;
					interactive = 1;
					if (confirm("Continue with","mput")) {
						mflag++;
					}
					interactive = ointer;
				}
			}
			continue;
		}
		gargs = ftpglob(argv[i]);
		if (globerr != NULL) {
			printf("%s\n", globerr);
			if (gargs) {
				blkfree(gargs);
				free((char *)gargs);
			}
			continue;
		}
		for (cpp = gargs; cpp && *cpp != NULL; cpp++) {
			if (mflag && confirm(argv[0], *cpp)) {
				tp = (ntflag) ? dotrans(*cpp) : *cpp;
				tp = (mapflag) ? domap(tp) : tp;
				sendrequest((sunique) ? "STOU" : "STOR",
				    *cpp, tp, *cpp != tp || !interactive);
				if (!mflag && fromatty) {
					ointer = interactive;
					interactive = 1;
					if (confirm("Continue with","mput")) {
						mflag++;
					}
					interactive = ointer;
				}
			}
		}
		if (gargs != NULL) {
			blkfree(gargs);
			free((char *)gargs);
		}
	}
	(void) signal(SIGINT, oldintr);
	mflag = 0;
}

void
reget(int argc, char *argv[])
{
	(void) getit(argc, argv, 1, "r+w");
}

void
get(int argc, char *argv[])
{
	(void) getit(argc, argv, 0, restart_point ? "r+w" : "w" );
}

/*
 * Receive one file.
 */
static int
getit(int argc, char *argv[], int restartit, const char *modestr)
{
	int loc = 0;
	char *oldargv1, *oldargv2;

	if (argc == 2) {
		argc++;
		/* 
		 * Protect the user from accidentally retrieving special
		 * local names.
		 */
		argv[2] = pipeprotect(argv[1]);
		if (!argv[2]) {
			code = -1;
			return 0;
		}
		loc++;
	}
	if (argc < 2 && !another(&argc, &argv, "remote-file"))
		goto usage;
	if (argc < 3 && !another(&argc, &argv, "local-file")) {
usage:
		printf("usage: %s remote-file [ local-file ]\n", argv[0]);
		code = -1;
		return (0);
	}
	oldargv1 = argv[1];
	oldargv2 = argv[2];
	argv[2] = globulize(argv[2]);
	if (!argv[2]) {
		code = -1;
		return (0);
	}
	if (loc && mcase) {
		char *tp = argv[1], *tp2, tmpbuf[PATH_MAX];

		while (*tp && !islower(*tp)) {
			tp++;
		}
		if (!*tp) {
			tp = argv[2];
			tp2 = tmpbuf;
			while ((*tp2 = *tp) != '\0') {
				if (isupper(*tp2)) {
					*tp2 = 'a' + *tp2 - 'A';
				}
				tp++;
				tp2++;
			}
			argv[2] = tmpbuf;
		}
	}
	if (loc && ntflag)
		argv[2] = dotrans(argv[2]);
	if (loc && mapflag)
		argv[2] = domap(argv[2]);
	if (restartit) {
		struct stat stbuf;
		int ret;

		ret = stat(argv[2], &stbuf);
		if (restartit == 1) {
			if (ret < 0) {
				fprintf(stderr, "local: %s: %s\n", argv[2],
					strerror(errno));
				return (0);
			}
			restart_point = stbuf.st_size;
		} else {
			if (ret == 0) {
				int overbose;

				overbose = verbose;
				if (debug == 0)
					verbose = -1;
				if (command("MDTM %s", argv[1]) == COMPLETE) {
					int yy, mo, day, hour, min, sec;
					struct tm *tm;
					verbose = overbose;
					sscanf(reply_string,
					    "%*s %04d%02d%02d%02d%02d%02d",
					    &yy, &mo, &day, &hour, &min, &sec);
					tm = gmtime(&stbuf.st_mtime);
					tm->tm_mon++;
/* Indentation is misleading, but changes keep small. */
/* 
 * I think the indentation and braces are now correct. Whoever put this
 * in the way it was originally should be prohibited by law.
 */
					if (tm->tm_year+1900 > yy)
					    	return (1);
					if (tm->tm_year+1900 == yy) {
					   if (tm->tm_mon > mo)
					      return (1);
					   if (tm->tm_mon == mo) {
					      if (tm->tm_mday > day)
						 return (1);
					      if (tm->tm_mday == day) {
						 if (tm->tm_hour > hour)
							return (1);
						 if (tm->tm_hour == hour) {
						    if (tm->tm_min > min)
						       return (1);
						    if (tm->tm_min == min) {
						       if (tm->tm_sec > sec)
							  return (1);
						    }
						 }
					      }
					   }
					}
				} else {
					printf("%s\n", reply_string);
					verbose = overbose;
					return (0);
				}
			}
		}
	}

	recvrequest("RETR", argv[2], argv[1], modestr,
		    argv[1] != oldargv1 || argv[2] != oldargv2);
	restart_point = 0;
	return (0);
}

void
mabort(int ignore)
{
	int ointer;

	(void)ignore;

	printf("\n");
	(void) fflush(stdout);
	if (mflag && fromatty) {
		ointer = interactive;
		interactive = 1;
		if (confirm("Continue with", mname)) {
			interactive = ointer;
			siglongjmp(jabort,0);
		}
		interactive = ointer;
	}
	mflag = 0;
	siglongjmp(jabort,0);
}

/*
 * Get multiple files.
 */
void
mget(int argc, char **argv)
{
	void (*oldintr)(int);
	int ointer;
	char *cp, *tp, *tp2, tmpbuf[PATH_MAX];

	if (argc < 2 && !another(&argc, &argv, "remote-files")) {
		printf("usage: %s remote-files\n", argv[0]);
		code = -1;
		return;
	}
	mname = argv[0];
	mflag = 1;
	oldintr = signal(SIGINT,mabort);
	(void) sigsetjmp(jabort, 1);
	while ((cp = remglob(argv,proxy)) != NULL) {
		if (*cp == '\0') {
			mflag = 0;
			continue;
		}
		if (mflag && confirm(argv[0], cp)) {
			tp = cp;
			if (mcase) {
				while (*tp && !islower(*tp)) {
					tp++;
				}
				if (!*tp) {
					tp = cp;
					tp2 = tmpbuf;
					while ((*tp2 = *tp) != '\0') {
						if (isupper(*tp2)) {
							*tp2 = 'a' + *tp2 - 'A';
						}
						tp++;
						tp2++;
					}
				}
				tp = tmpbuf;
			}
			if (ntflag) {
				tp = dotrans(tp);
			}
			if (mapflag) {
				tp = domap(tp);
			}
			/* Reject embedded ".." */
			tp = pathprotect(tp);

			/* Prepend ./ to "-" or "!*" or leading "/" */
			tp = pipeprotect(tp);
			if (tp == NULL) {
				/* hmm... how best to handle this? */
				mflag = 0;
			}
			else {
				recvrequest("RETR", tp, cp, "w",
					    tp != cp || !interactive);
			}
			if (!mflag && fromatty) {
				ointer = interactive;
				interactive = 1;
				if (confirm("Continue with","mget")) {
					mflag++;
				}
				interactive = ointer;
			}
		}
	}
	(void) signal(SIGINT,oldintr);
	mflag = 0;
}

char *
remglob(char *argv[], int doswitch)
{
	char temp[16];
	static char buf[PATH_MAX];
	static FILE *ftemp = NULL;
	static char **args;
	int oldverbose, oldhash, badglob = 0;
	char *cp;

	if (!mflag) {
		if (!doglob) {
			args = NULL;
		}
		else {
			if (ftemp) {
				(void) fclose(ftemp);
				ftemp = NULL;
			}
		}
		return(NULL);
	}
	if (!doglob) {
		if (args == NULL)
			args = argv;
		if ((cp = *++args) == NULL)
			args = NULL;
		return (cp);
	}
	if (ftemp == NULL) {
		int oldumask, fd;
		(void) strcpy(temp, _PATH_TMP);

		/* libc 5.2.18 creates with mode 0666, which is dumb */
		oldumask = umask(077);
		fd = mkstemp(temp);
		umask(oldumask);

		if (fd<0) {
			printf("Error creating temporary file, oops\n");
			return NULL;
		}
		
		oldverbose = verbose, verbose = 0;
		oldhash = hash, hash = 0;
		if (doswitch) {
			pswitch(!proxy);
		}
		while (*++argv != NULL) {
			int	dupfd = dup(fd);

			recvrequest ("NLST", temp, *argv, "a", 0);
			if (!checkglob(dupfd, *argv)) {
				badglob = 1;
				break;
			}
		}
		unlink(temp);

		if (doswitch) {
			pswitch(!proxy);
		}
		verbose = oldverbose; hash = oldhash;
		if (badglob) {
			printf("Refusing to handle insecure file list\n");
			close(fd);
			return NULL;
		}
		ftemp = fdopen(fd, "r");
		if (ftemp == NULL) {
			printf("fdopen failed, oops\n");
			return NULL;
		}
		rewind(ftemp);
	}
	if (fgets(buf, sizeof (buf), ftemp) == NULL) {
		(void) fclose(ftemp), ftemp = NULL;
		return (NULL);
	}
	if ((cp = index(buf, '\n')) != NULL)
		*cp = '\0';
	return (buf);
}

/*
 * Check whether given pattern matches `..'
 * We assume only a glob pattern starting with a dot will match
 * dot entries on the server.
 */
static int
isdotdotglob(const char *pattern)
{
	int	havedot = 0;
	char	c;

	if (*pattern++ != '.')
		return 0;
	while ((c = *pattern++) != '\0' && c != '/') {
		if (c == '*' || c == '?')
			continue;
		if (c == '.' && havedot++)
			return 0;
	}
	return 1;
}

/*
 * This function makes sure the list of globbed files returned from
 * the server doesn't contain anything dangerous such as
 * /home/<yourname>/.forward, or ../.forward,
 * or |mail foe@doe </etc/passwd, etc.
 * Covered areas:
 *  -	returned name starts with / but glob pattern doesn't
 *  -	glob pattern starts with / but returned name doesn't
 *  -	returned name starts with |
 *  -	returned name contains .. in a position where glob
 *	pattern doesn't match ..
 *	I.e. foo/.* allows foo/../bar but not foo/.bar/../fly
 *
 * Note that globbed names starting with / should really be stored
 * under the current working directory; this is handled in mget above.
 *						--okir
 */
static int
checkglob(int fd, const char *pattern)
{
	const char	*sp;
	char		buffer[MAXPATHLEN], dotdot[MAXPATHLEN];
	int		okay = 1, nrslash, initial, nr;
	FILE		*fp;

	/* Find slashes in glob pattern, and verify whether component
	 * matches `..'
	 */
	initial = (pattern[0] == '/');
	for (sp = pattern, nrslash = 0; sp != 0; sp = strchr(sp, '/')) {
		while (*sp == '/')
			sp++;
		if (nrslash >= MAXPATHLEN) {
			printf("Incredible pattern: %s\n", pattern);
			return 0;
		}
		dotdot[nrslash++] = isdotdotglob(sp);
	}

	fp = fdopen(fd, "r");
	while (okay && fgets(buffer, sizeof(buffer), fp) != NULL) {
		char	*sp;

		if ((sp = strchr(buffer, '\n')) != 0) {
			*sp = '\0';
		} else {
			printf("Extremely long filename from server: %s",
				buffer);
			okay = 0;
			break;
		}
		if (buffer[0] == '|'
		 || (buffer[0] != '/' && initial)
		 || (buffer[0] == '/' && !initial))
			okay = 0;
		for (sp = buffer, nr = 0; sp; sp = strchr(sp, '/'), nr++) {
			while (*sp == '/')
				sp++;
			if (sp[0] == '.' && !strncmp(sp, "../", 3)
			 && (nr >= nrslash || !dotdot[nr]))
				okay = 0;
		}
	}

	if (!okay)
		printf("Filename provided by server "
		       "doesn't match pattern `%s': %s\n", pattern, buffer);

	fclose(fp);
	return okay;
}

static const char *
onoff(int bool)
{
	return (bool ? "on" : "off");
}

/*
 * Show status.
 */
void
status(void)
{
	int i;

	if (connected)
		printf("Connected to %s.\n", hostname);
	else
		printf("Not connected.\n");
	if (!proxy) {
		pswitch(1);
		if (connected) {
			printf("Connected for proxy commands to %s.\n", hostname);
		}
		else {
			printf("No proxy connection.\n");
		}
		pswitch(0);
	}
	printf("Mode: %s; Type: %s; Form: %s; Structure: %s\n",
		modename, typename, formname, structname);
	printf("Verbose: %s; Bell: %s; Prompting: %s; Globbing: %s\n", 
		onoff(verbose), onoff(bell), onoff(interactive),
		onoff(doglob));
	printf("Store unique: %s; Receive unique: %s\n", onoff(sunique),
		onoff(runique));
	printf("Case: %s; CR stripping: %s\n",onoff(mcase),onoff(crflag));
	if (ntflag) {
		printf("Ntrans: (in) %s (out) %s\n", ntin,ntout);
	}
	else {
		printf("Ntrans: off\n");
	}
	if (mapflag) {
		printf("Nmap: (in) %s (out) %s\n", mapin, mapout);
	}
	else {
		printf("Nmap: off\n");
	}
	printf("Hash mark printing: %s; Use of PORT cmds: %s\n",
		onoff(hash), onoff(sendport));
	printf("Tick counter printing: %s\n", onoff(tick));
	if (macnum > 0) {
		printf("Macros:\n");
		for (i=0; i<macnum; i++) {
			printf("\t%s\n",macros[i].mac_name);
		}
	}
	code = 0;
}

/*
 * Set beep on cmd completed mode.
 */
void
setbell(void)
{

	bell = !bell;
	printf("Bell mode %s.\n", onoff(bell));
	code = bell;
}

/*
 * Turn on packet tracing.
 */
void
settrace(void)
{
	traceflag = !traceflag;
	printf("Packet tracing %s.\n", onoff(traceflag));
	code = traceflag;
}

/*
 * Toggle hash mark printing during transfers.
 */
void
sethash(void)
{
	hash = !hash;
	if (hash && tick)
		settick();
 
	printf("Hash mark printing %s", onoff(hash));
	code = hash;
	if (hash)
		printf(" (%d bytes/hash mark)", 1024);
	printf(".\n");
}

/*
 * Toggle tick counter printing during transfers.
 */
void
settick(void)
{
	tick = !tick;
	if (hash && tick)
		sethash();
	printf("Tick counter printing %s", onoff(tick));
	code = tick;
	if (tick)
		printf(" (%d bytes/tick increment)", TICKBYTES);
	printf(".\n");
}

/*
 * Turn on printing of server echos.
 */
void
setverbose(void)
{
	verbose = !verbose;
	printf("Verbose mode %s.\n", onoff(verbose));
	code = verbose;
}

/*
 * Toggle PORT cmd use before each data connection.
 */
void
setport(void)
{
	sendport = !sendport;
	printf("Use of PORT cmds %s.\n", onoff(sendport));
	code = sendport;
}

/*
 * Turn on interactive prompting
 * during mget, mput, and mdelete.
 */
void
setprompt(void)
{
	interactive = !interactive;
	printf("Interactive mode %s.\n", onoff(interactive));
	code = interactive;
}

/*
 * Toggle metacharacter interpretation
 * on local file names.
 */
void
setglob(void)
{
	doglob = !doglob;
	printf("Globbing %s.\n", onoff(doglob));
	code = doglob;
}

/*
 * Set debugging mode on/off and/or
 * set level of debugging.
 */
void
setdebug(int argc, char *argv[])
{
	int val;

	if (argc > 1) {
		val = atoi(argv[1]);
		if (val < 0) {
			printf("%s: bad debugging value.\n", argv[1]);
			code = -1;
			return;
		}
	} else
		val = !debug;
	debug = val;
	if (debug)
		options |= SO_DEBUG;
	else
		options &= ~SO_DEBUG;
	printf("Debugging %s (debug=%d).\n", onoff(debug), debug);
	code = debug > 0;
}

/*
 * Set current working directory
 * on remote machine.
 */
void
cd(int argc, char *argv[])
{

	if (argc < 2 && !another(&argc, &argv, "remote-directory")) {
		printf("usage: %s remote-directory\n", argv[0]);
		code = -1;
		return;
	}
	if (command("CWD %s", argv[1]) == ERROR && code == 500) {
		if (verbose)
			printf("CWD command not recognized, trying XCWD\n");
		(void) command("XCWD %s", argv[1]);
	}
}

/*
 * Set current working directory
 * on local machine.
 */
void
lcd(int argc, char *argv[])
{
	char buf[PATH_MAX];
	const char *dir = NULL;

	if (argc == 1) {
	    /*dir = home;*/
	    dir = ".";
	}
	else if (argc != 2) {
		printf("usage: %s local-directory\n", argv[0]);
		code = -1;
		return;
	}
	else {
	    dir = globulize(argv[1]);
	}
	if (!dir) {
		code = -1;
		return;
	}
	if (chdir(dir) < 0) {
		fprintf(stderr, "local: %s: %s\n", dir, strerror(errno));
		code = -1;
		return;
	}
	if (!getcwd(buf, sizeof(buf))) {
	    if (errno==ERANGE) strcpy(buf, "<too long>");
	    else strcpy(buf, "???");
	}
	printf("Local directory now %s\n", buf);
	code = 0;
}

/*
 * Delete a single file.
 */
void
delete_cmd(int argc, char *argv[])
{

	if (argc < 2 && !another(&argc, &argv, "remote-file")) {
		printf("usage: %s remote-file\n", argv[0]);
		code = -1;
		return;
	}
	(void) command("DELE %s", argv[1]);
}

/*
 * Delete multiple files.
 */
void
mdelete(int argc, char *argv[])
{
	void (*oldintr)(int);
	int ointer;
	char *cp;

	if (argc < 2 && !another(&argc, &argv, "remote-files")) {
		printf("usage: %s remote-files\n", argv[0]);
		code = -1;
		return;
	}
	mname = argv[0];
	mflag = 1;
	oldintr = signal(SIGINT, mabort);
	(void) sigsetjmp(jabort, 1);
	while ((cp = remglob(argv,0)) != NULL) {
		if (*cp == '\0') {
			mflag = 0;
			continue;
		}
		if (mflag && confirm(argv[0], cp)) {
			(void) command("DELE %s", cp);
			if (!mflag && fromatty) {
				ointer = interactive;
				interactive = 1;
				if (confirm("Continue with", "mdelete")) {
					mflag++;
				}
				interactive = ointer;
			}
		}
	}
	(void) signal(SIGINT, oldintr);
	mflag = 0;
}

/*
 * Rename a remote file.
 */
void
renamefile(int argc, char *argv[])
{

	if (argc < 2 && !another(&argc, &argv, "from-name"))
		goto usage;
	if (argc < 3 && !another(&argc, &argv, "to-name")) {
usage:
		printf("%s from-name to-name\n", argv[0]);
		code = -1;
		return;
	}
	if (command("RNFR %s", argv[1]) == CONTINUE)
		(void) command("RNTO %s", argv[2]);
}

/*
 * Get a directory listing
 * of remote files.
 */
void
ls(int argc, char *argv[])
{
	static char foo[2] = "-";
	const char *cmd;

	if (argc < 2) {
		argc++, argv[1] = NULL;
	}
	if (argc < 3) {
		argc++, argv[2] = foo;
	}
	if (argc > 3) {
		printf("usage: %s remote-directory local-file\n", argv[0]);
		code = -1;
		return;
	}
	cmd = argv[0][0] == 'n' ? "NLST" : "LIST";
	if (strcmp(argv[2], "-") && (argv[2] = globulize(argv[2]))==NULL) {
		code = -1;
		return;
	}
	if (strcmp(argv[2], "-") && *argv[2] != '|')
		if ((argv[2] = globulize(argv[2]))==NULL || 
		    !confirm("output to local-file:", argv[2])) {
			code = -1;
			return;
	}
	recvrequest(cmd, argv[2], argv[1], "w", 0);
}

/*
 * Get a directory listing
 * of multiple remote files.
 */
void
mls(int argc, char *argv[])
{
	void (*oldintr)(int);
	int ointer, i;
	const char *volatile cmd;
	char *volatile dest;
	const char *modestr;

	if (argc < 2 && !another(&argc, &argv, "remote-files"))
		goto usage;
	if (argc < 3 && !another(&argc, &argv, "local-file")) {
usage:
		printf("usage: %s remote-files local-file\n", argv[0]);
		code = -1;
		return;
	}
	dest = argv[argc - 1];
	argv[argc - 1] = NULL;
	if (strcmp(dest, "-") && *dest != '|')
		if ((dest = globulize(dest))==NULL ||
		    !confirm("output to local-file:", dest)) {
			code = -1;
			return;
	}
	cmd = argv[0][1] == 'l' ? "NLST" : "LIST";
	mname = argv[0];
	mflag = 1;
	oldintr = signal(SIGINT, mabort);

	/*
	 * This just plain seems wrong.
	 */
	(void) sigsetjmp(jabort, 1);

	for (i = 1; mflag && i < argc-1; ++i) {
		modestr = (i == 1) ? "w" : "a";
		recvrequest(cmd, dest, argv[i], modestr, 0);
		if (!mflag && fromatty) {
			ointer = interactive;
			interactive = 1;
			if (confirm("Continue with", argv[0])) {
				mflag ++;
			}
			interactive = ointer;
		}
	}
	(void) signal(SIGINT, oldintr);
	mflag = 0;
}

/*
 * Do a shell escape
 */
void
shell(const char *arg)
{
	int pid;
	void (*old1)(int);
	void (*old2)(int);
	char shellnam[40];
	const char *theshell, *namep; 

	old1 = signal (SIGINT, SIG_IGN);
	old2 = signal (SIGQUIT, SIG_IGN);
#ifdef __uClinux__
	if ((pid = vfork()) == 0) {
#else
	if ((pid = fork()) == 0) {
#endif
		for (pid = 3; pid < 20; pid++)
			(void) close(pid);
		(void) signal(SIGINT, SIG_DFL);
		(void) signal(SIGQUIT, SIG_DFL);
		theshell = getenv("SHELL");
		if (theshell == NULL)
			theshell = _PATH_BSHELL;
		namep = strrchr(theshell, '/');
		if (namep == NULL)
			namep = theshell;
		else 
			namep++;
		(void) strcpy(shellnam,"-");
		(void) strcat(shellnam, namep);
		if (strcmp(namep, "sh") != 0)
			shellnam[0] = '+';
		if (debug) {
			printf("%s\n", theshell);
			(void) fflush (stdout);
		}
		if (arg) {
			execl(theshell, shellnam, "-c", arg, NULL);
		}
		else {
			execl(theshell, shellnam, NULL);
		}
		perror(theshell);
		code = -1;
		exit(1);
	}
	if (pid > 0) while (wait(NULL) != pid);

	(void) signal(SIGINT, old1);
	(void) signal(SIGQUIT, old2);
	if (pid == -1) {
		perror("Try again later");
		code = -1;
	}
	else {
		code = 0;
	}
}

/*
 * Send new user information (re-login)
 */
void
user(int argc, char *argv[])
{
	char theacct[80];
	int n, aflag = 0;

	if (argc < 2)
		(void) another(&argc, &argv, "username");
	if (argc < 2 || argc > 4) {
		printf("usage: %s username [password] [account]\n", argv[0]);
		code = -1;
		return;
	}
	n = command("USER %s", argv[1]);
	if (n == CONTINUE) {
		if (argc < 3 )
			argv[2] = getpass("Password: "), argc++;
		n = command("PASS %s", argv[2]);
	}
	if (n == CONTINUE) {
		if (argc < 4) {
			printf("Account: "); (void) fflush(stdout);
			fgets(theacct, sizeof(theacct), stdin);
			argv[3] = theacct; argc++;
		}
		n = command("ACCT %s", argv[3]);
		aflag++;
	}
	if (n != COMPLETE) {
		fprintf(stdout, "Login failed.\n");
		return;
	}
	if (!aflag && argc == 4) {
		(void) command("ACCT %s", argv[3]);
	}
}

/*
 * Print working directory.
 */
void
pwd(void)
{
	int oldverbose = verbose;

	/*
	 * If we aren't verbose, this doesn't do anything!
	 */
	verbose = 1;
	if (command("PWD") == ERROR && code == 500) {
		printf("PWD command not recognized, trying XPWD\n");
		(void) command("XPWD");
	}
	verbose = oldverbose;
}

/*
 * Make a directory.
 */
void
makedir(int argc, char *argv[])
{

	if (argc < 2 && !another(&argc, &argv, "directory-name")) {
		printf("usage: %s directory-name\n", argv[0]);
		code = -1;
		return;
	}
	if (command("MKD %s", argv[1]) == ERROR && code == 500) {
		if (verbose)
			printf("MKD command not recognized, trying XMKD\n");
		(void) command("XMKD %s", argv[1]);
	}
}

/*
 * Remove a directory.
 */
void
removedir(int argc, char *argv[])
{

	if (argc < 2 && !another(&argc, &argv, "directory-name")) {
		printf("usage: %s directory-name\n", argv[0]);
		code = -1;
		return;
	}
	if (command("RMD %s", argv[1]) == ERROR && code == 500) {
		if (verbose)
			printf("RMD command not recognized, trying XRMD\n");
		(void) command("XRMD %s", argv[1]);
	}
}

/*
 * Send a line, verbatim, to the remote machine.
 */
void
quote(int argc, char *argv[])
{
	if (argc < 2 && !another(&argc, &argv, "command line to send")) {
		printf("usage: %s line-to-send\n", argv[0]);
		code = -1;
		return;
	}
	quote1("", argc, argv);
}

/*
 * Send a SITE command to the remote machine.  The line
 * is sent verbatim to the remote machine, except that the
 * word "SITE" is added at the front.
 */
void
site(int argc, char *argv[])
{
	if (argc < 2 && !another(&argc, &argv, "arguments to SITE command")) {
		printf("usage: %s line-to-send\n", argv[0]);
		code = -1;
		return;
	}
	quote1("SITE ", argc, argv);
}

/*
 * Turn argv[1..argc) into a space-separated string, then prepend initial text.
 * Send the result as a one-line command and get response.
 */
static void
quote1(const char *initial, int argc, char **argv)
{
	register int i, len;
	char buf[BUFSIZ];		/* must be >= sizeof(line) */

	(void) strcpy(buf, initial);
	if (argc > 1) {
		len = strlen(buf);
		len += strlen(strcpy(&buf[len], argv[1]));
		for (i = 2; i < argc; i++) {
			buf[len++] = ' ';
			len += strlen(strcpy(&buf[len], argv[i]));
		}
	}
	if (command(buf) == PRELIM) {
		while (getreply(0) == PRELIM);
	}
}

void
do_chmod(int argc, char *argv[])
{

	if (argc < 2 && !another(&argc, &argv, "mode"))
		goto usage;
	if (argc < 3 && !another(&argc, &argv, "file-name")) {
usage:
		printf("usage: %s mode file-name\n", argv[0]);
		code = -1;
		return;
	}
	(void) command("SITE CHMOD %s %s", argv[1], argv[2]);
}

void
do_umask(int argc, char *argv[])
{
	int oldverbose = verbose;

	verbose = 1;
	(void) command(argc == 1 ? "SITE UMASK" : "SITE UMASK %s", argv[1]);
	verbose = oldverbose;
}

void
idle_cmd(int argc, char *argv[])
{
	int oldverbose = verbose;

	verbose = 1;
	(void) command(argc == 1 ? "SITE IDLE" : "SITE IDLE %s", argv[1]);
	verbose = oldverbose;
}

/*
 * Ask the other side for help.
 */
void
rmthelp(int argc, char *argv[])
{
	int oldverbose = verbose;

	verbose = 1;
	(void) command(argc == 1 ? "HELP" : "HELP %s", argv[1]);
	verbose = oldverbose;
}

/*
 * Terminate session and exit.
 */
void
quit(void)
{

	if (connected)
		disconnect();
	pswitch(1);
	if (connected) {
		disconnect();
	}
	exit(0);
}

/*
 * Terminate session, but don't exit.
 */
void
disconnect(void)
{
	if (!connected)
		return;
	(void) command("QUIT");
	if (cout) {
		(void) fclose(cout);
	}
	cout = NULL;
	connected = 0;
	data = -1;
	if (!proxy) {
		macnum = 0;
	}
}

static int
confirm(const char *cmd, const char *file)
{
	char lyne[BUFSIZ];

	if (!interactive)
		return (1);

#ifdef __USE_READLINE__
	if (fromatty && !rl_inhibit) {
		char *lineread;
		snprintf(lyne, BUFSIZ, "%s %s? ", cmd, file);
		lineread = readline(lyne);
		if (!lineread) return 0;
		strcpy(lyne, lineread);
		free(lineread);
	}
	else {
#endif
		printf("%s %s? ", cmd, file);
		fflush(stdout);
		if (fgets(lyne, sizeof(lyne), stdin) == NULL) {
		    return 0;
		}
#ifdef __USE_READLINE__
	}
#endif
	return (*lyne != 'n' && *lyne != 'N');
}

void
fatal(const char *msg)
{

	fprintf(stderr, "ftp: %s\n", msg);
	exit(1);
}

/*
 * Glob a local file name specification with
 * the expectation of a single return value.
 * Can't control multiple values being expanded
 * from the expression, we return only the first.
 */
static 
char *
globulize(char *cpp)
{
	char **globbed;
	char *rv = cpp;

	if (!doglob) return cpp;

	globbed = ftpglob(cpp);
	if (globerr != NULL) {
		printf("%s: %s\n", cpp, globerr);
		if (globbed) {
			blkfree(globbed);
			free(globbed);
		}
		return NULL;
	}
	if (globbed) {
		rv = globbed[0];
		/* don't waste too much memory */
		if (globbed[0]) {
			blkfree(globbed+1);
		}
		free(globbed);
	}
	return rv;
}

void
account(int argc, char *argv[])
{
	char buf[128], *ap;

	if (argc > 1) {
		*buf = 0;
		while (argc > 1) {
			--argc;
			++argv;
			strncat(buf, *argv, sizeof(buf)-strlen(buf));
			buf[sizeof(buf)-1] = 0;
		}
		ap = buf;
	}
	else {
		ap = getpass("Account:");
	}
	command("ACCT %s", ap);
}

static 
void
proxabort(int ignore)
{
	(void)ignore;

	if (!proxy) {
		pswitch(1);
	}
	if (connected) {
		proxflag = 1;
	}
	else {
		proxflag = 0;
	}
	pswitch(0);
	siglongjmp(abortprox,1);
}

void
doproxy(int argc, char *argv[])
{
	register struct cmd *c;
	void (*oldintr)(int);

	if (argc < 2 && !another(&argc, &argv, "command")) {
		printf("usage: %s command\n", argv[0]);
		code = -1;
		return;
	}
	c = getcmd(argv[1]);
	if (c == (struct cmd *) -1) {
		printf("?Ambiguous command\n");
		(void) fflush(stdout);
		code = -1;
		return;
	}
	if (c == 0) {
		printf("?Invalid command\n");
		(void) fflush(stdout);
		code = -1;
		return;
	}
	if (!c->c_proxy) {
		printf("?Invalid proxy command\n");
		(void) fflush(stdout);
		code = -1;
		return;
	}
	if (sigsetjmp(abortprox, 1)) {
		code = -1;
		return;
	}
	oldintr = signal(SIGINT, proxabort);
	pswitch(1);
	if (c->c_conn && !connected) {
		printf("Not connected\n");
		(void) fflush(stdout);
		pswitch(0);
		(void) signal(SIGINT, oldintr);
		code = -1;
		return;
	}

	if (c->c_handler_v) c->c_handler_v(argc-1, argv+1);
	else if (c->c_handler_0) c->c_handler_0();
	else c->c_handler_1(NULL);  /* should not reach this */

	if (connected) {
		proxflag = 1;
	}
	else {
		proxflag = 0;
	}
	pswitch(0);
	(void) signal(SIGINT, oldintr);
}

void
setcase(void)
{
	mcase = !mcase;
	printf("Case mapping %s.\n", onoff(mcase));
	code = mcase;
}

void
setcr(void)
{
	crflag = !crflag;
	printf("Carriage Return stripping %s.\n", onoff(crflag));
	code = crflag;
}

void
setntrans(int argc, char *argv[])
{
	if (argc == 1) {
		ntflag = 0;
		printf("Ntrans off.\n");
		code = ntflag;
		return;
	}
	ntflag++;
	code = ntflag;
	(void) strncpy(ntin, argv[1], 16);
	ntin[16] = '\0';
	if (argc == 2) {
		ntout[0] = '\0';
		return;
	}
	(void) strncpy(ntout, argv[2], 16);
	ntout[16] = '\0';
}

static char *
dotrans(char *name)
{
	static char new[PATH_MAX];
	char *cp1, *cp2 = new;
	register int i, ostop, found;

	for (ostop = 0; *(ntout + ostop) && ostop < 16; ostop++);
	for (cp1 = name; *cp1; cp1++) {
		found = 0;
		for (i = 0; *(ntin + i) && i < 16; i++) {
			if (*cp1 == *(ntin + i)) {
				found++;
				if (i < ostop) {
					*cp2++ = *(ntout + i);
				}
				break;
			}
		}
		if (!found) {
			*cp2++ = *cp1;
		}
	}
	*cp2 = '\0';
	return(new);
}

void
setnmap(int argc, char *argv[])
{
	char *cp;

	if (argc == 1) {
		mapflag = 0;
		printf("Nmap off.\n");
		code = mapflag;
		return;
	}
	if (argc < 3 && !another(&argc, &argv, "mapout")) {
		printf("Usage: %s [mapin mapout]\n",argv[0]);
		code = -1;
		return;
	}
	mapflag = 1;
	code = 1;
	cp = index(altarg, ' ');
	if (proxy) {
		while(*++cp == ' ');
		altarg = cp;
		cp = index(altarg, ' ');
	}
	*cp = '\0';
	(void) strncpy(mapin, altarg, PATH_MAX - 1);
	mapin[PATH_MAX-1] = 0;
	while (*++cp == ' ');
	(void) strncpy(mapout, cp, PATH_MAX - 1);
	mapout[PATH_MAX-1] = 0;
}

static
char *
domap(char *name)
{
	static char new[PATH_MAX];
	register char *cp1 = name, *cp2 = mapin;
	char *tp[9], *te[9];
	int i, toks[9], toknum = 0, match = 1;

	for (i=0; i < 9; ++i) {
		toks[i] = 0;
	}
	while (match && *cp1 && *cp2) {
		switch (*cp2) {
			case '\\':
				if (*++cp2 != *cp1) {
					match = 0;
				}
				break;
			case '$':
				if (*(cp2+1) >= '1' && *(cp2+1) <= '9') {
					if (*cp1 != *(++cp2+1)) {
						toknum = *cp2 - '1';
						toks[toknum]++;
						tp[toknum] = cp1;
						while (*++cp1 && *(cp2+1)
							!= *cp1);
						te[toknum] = cp1;
					}
					cp2++;
					break;
				}
				/* FALLTHROUGH */
			default:
				if (*cp2 != *cp1) {
					match = 0;
				}
				break;
		}
		if (match && *cp1) {
			cp1++;
		}
		if (match && *cp2) {
			cp2++;
		}
	}
	if (!match && *cp1) /* last token mismatch */
	{
		toks[toknum] = 0;
	}
	cp1 = new;
	*cp1 = '\0';
	cp2 = mapout;
	while (*cp2) {
		match = 0;
		switch (*cp2) {
			case '\\':
				if (*(cp2 + 1)) {
					*cp1++ = *++cp2;
				}
				break;
			case '[':
LOOP:
				if (*++cp2 == '$' && isdigit(*(cp2+1))) { 
					if (*++cp2 == '0') {
						char *cp3 = name;

						while (*cp3) {
							*cp1++ = *cp3++;
						}
						match = 1;
					}
					else if (toks[toknum = *cp2 - '1']) {
						char *cp3 = tp[toknum];

						while (cp3 != te[toknum]) {
							*cp1++ = *cp3++;
						}
						match = 1;
					}
				}
				else {
					while (*cp2 && *cp2 != ',' && 
					    *cp2 != ']') {
						if (*cp2 == '\\') {
							cp2++;
						}
						else if (*cp2 == '$' &&
   						        isdigit(*(cp2+1))) {
							if (*++cp2 == '0') {
							   char *cp3 = name;

							   while (*cp3) {
								*cp1++ = *cp3++;
							   }
							}
							else if (toks[toknum =
							    *cp2 - '1']) {
							   char *cp3=tp[toknum];

							   while (cp3 !=
								  te[toknum]) {
								*cp1++ = *cp3++;
							   }
							}
						}
						else if (*cp2) {
							*cp1++ = *cp2++;
						}
					}
					if (!*cp2) {
						printf("nmap: unbalanced brackets\n");
						return(name);
					}
					match = 1;
					cp2--;
				}
				if (match) {
					while (*++cp2 && *cp2 != ']') {
					      if (*cp2 == '\\' && *(cp2 + 1)) {
							cp2++;
					      }
					}
					if (!*cp2) {
						printf("nmap: unbalanced brackets\n");
						return(name);
					}
					break;
				}
				switch (*++cp2) {
					case ',':
						goto LOOP;
					case ']':
						break;
					default:
						cp2--;
						goto LOOP;
				}
				break;
			case '$':
				if (isdigit(*(cp2 + 1))) {
					if (*++cp2 == '0') {
						char *cp3 = name;

						while (*cp3) {
							*cp1++ = *cp3++;
						}
					}
					else if (toks[toknum = *cp2 - '1']) {
						char *cp3 = tp[toknum];

						while (cp3 != te[toknum]) {
							*cp1++ = *cp3++;
						}
					}
					break;
				}
				/* intentional drop through */
			default:
				*cp1++ = *cp2;
				break;
		}
		cp2++;
	}
	*cp1 = '\0';
	if (!*new) {
		return(name);
	}
	return(new);
}

void
setsunique(void)
{
	sunique = !sunique;
	printf("Store unique %s.\n", onoff(sunique));
	code = sunique;
}

void
setrunique(void)
{
	runique = !runique;
	printf("Receive unique %s.\n", onoff(runique));
	code = runique;
}

/* change directory to parent directory */
void
cdup(void)
{
	if (command("CDUP") == ERROR && code == 500) {
		if (verbose)
			printf("CDUP command not recognized, trying XCUP\n");
		(void) command("XCUP");
	}
}

/* restart transfer at specific point */
void
restart(int argc, char *argv[])
{
	if (argc != 2)
		printf("restart: offset not specified\n");
	else {
		restart_point = atol(argv[1]);
		printf("restarting at %ld. %s\n", restart_point,
		    "execute get, put or append to initiate transfer");
	}
}

/* show remote system type */
void
syst(void)
{
	command("SYST");
}

void
macdef(int argc, char *argv[])
{
	char *tmp;
	int c;

	if (macnum == 16) {
		printf("Limit of 16 macros have already been defined\n");
		code = -1;
		return;
	}
	if (argc < 2 && !another(&argc, &argv, "macro name")) {
		printf("Usage: %s macro_name\n",argv[0]);
		code = -1;
		return;
	}
	if (interactive) {
		printf("Enter macro line by line, terminating it with a null line\n");
	}
	(void) strncpy(macros[macnum].mac_name, argv[1], 8);
	macros[macnum].mac_name[8] = 0;
	if (macnum == 0) {
		macros[macnum].mac_start = macbuf;
	}
	else {
		macros[macnum].mac_start = macros[macnum - 1].mac_end + 1;
	}
	tmp = macros[macnum].mac_start;
	/* stepping over the end of the array, remember to take away 1! */
	while (tmp != macbuf+MACBUF_SIZE) {
		if ((c = getchar()) == EOF) {
			printf("macdef:end of file encountered\n");
			code = -1;
			return;
		}
		if ((*tmp = c) == '\n') {
			if (tmp == macros[macnum].mac_start) {
				macros[macnum++].mac_end = tmp;
				code = 0;
				return;
			}
			if (*(tmp-1) == '\0') {
				macros[macnum++].mac_end = tmp - 1;
				code = 0;
				return;
			}
			*tmp = '\0';
		}
		tmp++;
	}
	while (1) {
		while ((c = getchar()) != '\n' && c != EOF)
			/* LOOP */;
		if (c == EOF || getchar() == '\n') {
			printf("Macro not defined - 4k buffer exceeded\n");
			code = -1;
			return;
		}
	}
}

/*
 * Start up passive mode interaction
 */
void
setpassive(void)
{
        passivemode = !passivemode;
        printf("Passive mode %s.\n", onoff(passivemode));
        code = passivemode;
}

/*
 * get size of file on remote machine
 */
void
sizecmd(int argc, char *argv[])
{

	if (argc < 2 && !another(&argc, &argv, "filename")) {
		printf("usage: %s filename\n", argv[0]);
		code = -1;
		return;
	}
	(void) command("SIZE %s", argv[1]);
}

/*
 * get last modification time of file on remote machine
 */
void
modtime(int argc, char *argv[])
{
	int overbose;

	if (argc < 2 && !another(&argc, &argv, "filename")) {
		printf("usage: %s filename\n", argv[0]);
		code = -1;
		return;
	}
	overbose = verbose;
	if (debug == 0)
		verbose = -1;
	if (command("MDTM %s", argv[1]) == COMPLETE) {
		int yy, mo, day, hour, min, sec;
		sscanf(reply_string, "%*s %04d%02d%02d%02d%02d%02d", &yy, &mo,
			&day, &hour, &min, &sec);
		/* might want to print this in local time */
		printf("%s\t%02d/%02d/%04d %02d:%02d:%02d GMT\n", argv[1],
			mo, day, yy, hour, min, sec);
	} else
		printf("%s\n", reply_string);
	verbose = overbose;
}

/*
 * show status on remote machine
 */
void
rmtstatus(int argc, char *argv[])
{
	(void) command(argc > 1 ? "STAT %s" : "STAT" , argv[1]);
}

/*
 * get file if modtime is more recent than current file
 */
void
newer(int argc, char *argv[])
{
	if (getit(argc, argv, -1, "w")) {
		/* This should be controlled by some verbose flag */
		printf("Local file \"%s\" is newer than remote file \"%s\"\n",
			argv[2], argv[1]);
	}
}
