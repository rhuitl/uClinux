/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#if 0
char copyright[] =
"@(#) Copyright (c) 1983 Regents of the University of California.\n\
 All rights reserved.\n";
#endif /* not lint */

#if 0
static char sccsid[] = "@(#)main.c	5.8 (Berkeley) 10/11/88";
#endif /* not lint */

/* Many bug fixes are from Jim Guyton <guyton@rand-unix> */

/*
 * TFTP User Program -- Command Interface.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <setjmp.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <unistd.h>

#include "exit_codes.h"
#include "netflash.h"
#include "tftp.h"

#define	TIMEOUT		5		/* secs between rexmt's */

struct	sockaddr_in tftpsin;
int	tftpf;
short   tftpport;
int	tftptrace;
int	tftpverbose;
int	tftpconnected;
char	tftpmode[32];
char	tftpline[200];
int	tftpmargc;
char	*tftpmargv[20];
char	*tftpprompt = "tftp";
jmp_buf	tftptoplevel;
static void	tftpintr(int signo);
#ifndef EMBED
struct	servent *sp;
#endif

static void tftpgetusage(char *s);
static void tftpmakeargv(void);
static void tftpsetmode(char *newmode);
#if 0
static void tftpquit(void);
static void tftpsettrace(void);
static void tftpsetverbose(void);
#endif

#define HELPINDENT (sizeof("connect"))

struct cmd {
	char	*name;
	char	*help;
	void	(*handler)(int argc, char *argv[]);
};

#if 0
char	tftpvhelp[] = "toggle verbose mode";
char	tftpthelp[] = "toggle packet tracing";
char	tftpchelp[] = "connect to remote tftp";
char	tftpqhelp[] = "exit tftp";
char	tftphhelp[] = "print help information";
char	tftpshelp[] = "send file";
#endif
char	tftprhelp[] = "receive file";
#if 0
char	tftpmhelp[] = "set file transfer mode";
char	tftpsthelp[] = "show current status";
char	tftpxhelp[] = "set per-packet retransmission timeout";
char	tftpihelp[] = "set total retransmission timeout";
char    tftpashelp[] = "set mode to netascii";
char    tftpbnhelp[] = "set mode to octet";
#else
#endif

struct cmd tftpcmdtab[] = {
#if 0
	{ "connect",	tftpchelp,	tftpsetpeer },
	{ "mode",       tftpmhelp,      tftpmodecmd },
	{ "put",	tftpshelp,	tftpput },
#endif
	{ "get",	tftprhelp,	tftpget },
#if 0
	{ "quit",	tftpqhelp,	tftpquit },
	{ "verbose",	tftpvhelp,	tftpsetverbose },
	{ "trace",	tftpthelp,	tftpsettrace },
	{ "status",	tftpsthelp,	tftpstatus },
	{ "binary",     tftpbnhelp,     tftpsetbinary },
	{ "ascii",      tftpashelp,     tftpsetascii },
	{ "rexmt",	tftpxhelp,	tftpsetrexmt },
	{ "timeout",	tftpihelp,	tftpsettimeout },
	{ "?",		tftphhelp,	tftphelp },
#endif
	{ 0 }
};
struct	cmd *tftpgetcmd();
char	*tftptail();

void
tftpmain(argc, argv)
	char *argv[];
{
	struct sockaddr_in sin;
	int top;
#ifdef SETSRC
	struct in_addr	src_addr;
#endif

#ifndef EMBED
	sp = getservbyname("tftp", "udp");
	if (sp == 0) {
		fprintf(stderr, "tftp: udp/tftp: unknown service\n");
		exit(1);
	}
#endif
	tftpf = socket(AF_INET, SOCK_DGRAM, 0);
	if (tftpf < 0) {
		perror("tftp: socket");
		exit(3);
	}
	bzero((char *)&sin, sizeof (sin));

#ifdef SETSRC
	if (argc == 3) {
		inet_aton(argv[2], &src_addr);
		memcpy(&sin.sin_addr.s_addr, &src_addr.s_addr, sizeof(sin.sin_addr.s_addr));
		argv[argc--] = NULL; /* remove extra argument as not to confuse tftpsetpeer() */
	}
#endif
	sin.sin_family = AF_INET;
	if (bind(tftpf, (struct sockaddr *) &sin, sizeof (sin)) < 0) {
		perror("tftp: bind");
		exit(1);
	}
	strcpy(tftpmode, "netascii");
	signal(SIGINT, tftpintr);
	if (argc > 1) {
		if (setjmp(tftptoplevel) != 0)
			exit(TF_TIMEOUT);
		tftpsetpeer(argc, argv);
	}
	top = setjmp(tftptoplevel) == 0;
#if 0
	for (;;)
		tftpcommand(top);
#endif
	signal(SIGINT, SIG_DFL);
}

char    tftphostname[100];

void
tftpsetpeer(argc, argv)
	int argc;
	char *argv[];
{
	struct hostent *host;

	if (argc < 2) {
		strcpy(tftpline, "Connect ");
		printf("(to) ");
		fgets(&tftpline[strlen(tftpline)], sizeof(tftpline)-strlen(tftpline), stdin);
		tftpmakeargv();
		argc = tftpmargc;
		argv = tftpmargv;
	}
	if (argc > 3) {
		printf("usage: %s host-name [port]\n", argv[0]);
		return;
	}

	if ((tftpsin.sin_addr.s_addr = inet_addr(argv[1])) == -1) {
		if ((host = gethostbyname(argv[1]))) {
			tftpsin.sin_family = host->h_addrtype;
			bcopy(host->h_addr, &tftpsin.sin_addr, host->h_length);
			strcpy(tftphostname, host->h_name);
		} else {
			tftpconnected = 0;
			printf("%s: unknown host\n", argv[1]);
			return;
		}
	} else {
		tftpsin.sin_family = AF_INET;
		strcpy(tftphostname, argv[1]);
	}
#ifdef EMBED
	tftpport = htons(69);
#else
	tftpport = sp->s_port;
#endif
	if (argc == 3) {
		tftpport = atoi(argv[2]);
		if (tftpport < 0) {
			printf("%s: bad port number\n", argv[2]);
			tftpconnected = 0;
			return;
		}
		tftpport = htons(tftpport);
	}
	tftpconnected = 1;
}

struct	modes {
	char *m_name;
	char *m_mode;
} tftpmodes[] = {
	{ "ascii",	"netascii" },
	{ "netascii",   "netascii" },
	{ "binary",     "octet" },
	{ "image",      "octet" },
	{ "octet",     "octet" },
/*      { "mail",       "mail" },       */
	{ 0,		0 }
};

void
tftpmodecmd(argc, argv)
	char *argv[];
{
	register struct modes *p;
	char *sep;

	if (argc < 2) {
		printf("Using %s mode to transfer files.\n", tftpmode);
		return;
	}
	if (argc == 2) {
		for (p = tftpmodes; p->m_name; p++)
			if (strcmp(argv[1], p->m_name) == 0)
				break;
		if (p->m_name) {
			tftpsetmode(p->m_mode);
			return;
		}
		printf("%s: unknown mode\n", argv[1]);
		/* drop through and print usage message */
	}

	printf("usage: %s [", argv[0]);
	sep = " ";
	for (p = tftpmodes; p->m_name; p++) {
		printf("%s%s", sep, p->m_name);
		if (*sep == ' ')
			sep = " | ";
	}
	printf(" ]\n");
	return;
}

void
tftpsetbinary(argc, argv)
char *argv[];
{       tftpsetmode("octet");
}

void
tftpsetascii(argc, argv)
char *argv[];
{       tftpsetmode("netascii");
}

static void
tftpsetmode(newmode)
char *newmode;
{
	strcpy(tftpmode, newmode);
	if (tftpverbose)
		printf("mode set to %s\n", tftpmode);
}


#if 0
/*
 * Send file(s).
 */
tftpput(argc, argv)
	char *argv[];
{
	int fd;
	register int n;
	register char *cp, *targ;

	if (argc < 2) {
		strcpy(tftpline, "send ");
		printf("(file) ");
		fgets(&tftpline[strlen(tftpline)], sizeof(tftpline)-strlen(tftpline), stdin);
		tftpmakeargv();
		argc = tftpmargc;
		argv = tftpmargv;
	}
	if (argc < 2) {
		tftpputusage(argv[0]);
		return;
	}
	targ = argv[argc - 1];
	if (strchr(argv[argc - 1], ':')) {
		char *cp;
		struct hostent *hp;

		for (n = 1; n < argc - 1; n++)
			if (strchr(argv[n], ':')) {
				tftpputusage(argv[0]);
				return;
			}
		cp = argv[argc - 1];
		targ = strchr(cp, ':');
		*targ++ = 0;
		hp = gethostbyname(cp);
		if (hp == NULL) {
			fprintf(stderr, "tftp: %s: ", cp);
			herror((char *)NULL);
			return;
		}
		bcopy(hp->h_addr, (caddr_t)&tftpsin.sin_addr, hp->h_length);
		tftpsin.sin_family = hp->h_addrtype;
		tftpconnected = 1;
		strcpy(tftphostname, hp->h_name);
	}
	if (!tftpconnected) {
		printf("No target machine specified.\n");
		return;
	}
	if (argc < 4) {
		cp = argc == 2 ? tftptail(targ) : argv[1];
		fd = open(cp, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "tftp: "); perror(cp);
			return;
		}
		if (tftpverbose)
			printf("putting %s to %s:%s [%s]\n",
				cp, tftphostname, targ, tftpmode);
		tftpsin.sin_port = tftpport;
		tftpsendfile(fd, targ, tftpmode);
		return;
	}
				/* this assumes the target is a directory */
				/* on a remote unix system.  hmmmm.  */
	cp = strchr(targ, '\0'); 
	*cp++ = '/';
	for (n = 1; n < argc - 1; n++) {
		strcpy(cp, tail(argv[n]));
		fd = open(argv[n], O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "tftp: "); perror(argv[n]);
			continue;
		}
		if (tftpverbose)
			printf("putting %s to %s:%s [%s]\n",
				argv[n], tftphostname, targ, tftpmode);
		tftpsin.sin_port = tftpport;
		tftpsendfile(fd, targ, tftpmode);
	}
}

tftpputusage(s)
	char *s;
{
	printf("usage: %s file ... host:target, or\n", s);
	printf("       %s file ... target (when already connected)\n", s);
}
#endif

/*
 * Receive file(s).
 */
void
tftpget(argc, argv)
	char *argv[];
{
	int fd;
	register int n;
	register char *cp;
	char *src;

	if (setjmp(tftptoplevel))
		return;
	signal(SIGINT, tftpintr);

	if (argc < 2) {
		strcpy(tftpline, "get ");
		printf("(files) ");
		fgets(&tftpline[strlen(tftpline)], sizeof(tftpline)-strlen(tftpline),stdin);
		tftpmakeargv();
		argc = tftpmargc;
		argv = tftpmargv;
	}
	if (argc < 2) {
		tftpgetusage(argv[0]);
		return;
	}
	if (!tftpconnected) {
		for (n = 1; n < argc ; n++)
			if (strchr(argv[n], ':') == 0) {
				tftpgetusage(argv[0]);
				return;
			}
	}
	for (n = 1; n < argc ; n++) {
		src = strchr(argv[n], ':');
		if (src == NULL)
			src = argv[n];
		else {
			struct hostent *hp;

			*src++ = 0;
			hp = gethostbyname(argv[n]);
			if (hp == NULL) {
#ifdef EMBED
				fprintf(stderr, "tftp: %s: UNKNOWN\n", argv[n]);
#else
				fprintf(stderr, "tftp: %s: ", argv[n]);
				herror((char *)NULL);
#endif
				continue;
			}
			bcopy(hp->h_addr, (caddr_t)&tftpsin.sin_addr, hp->h_length);
			tftpsin.sin_family = hp->h_addrtype;
			tftpconnected = 1;
			strcpy(tftphostname, hp->h_name);
		}
		if (argc < 4) {
			cp = argc == 3 ? argv[2] : tftptail(src);
			fd = local_creat(cp, 0644);
			if (fd < 0) {
				fprintf(stderr, "tftp: "); perror(cp);
				return;
			}
			if (tftpverbose)
				printf("getting from %s:%s to %s [%s]\n",
					tftphostname, src, cp, tftpmode);
			tftpsin.sin_port = tftpport;
			tftprecvfile(fd, src, tftpmode);
			break;
		}
		cp = tftptail(src);         /* new .. jdg */
		fd = local_creat(cp, 0644);
		if (fd < 0) {
			fprintf(stderr, "tftp: "); perror(cp);
			continue;
		}
		if (tftpverbose)
			printf("getting from %s:%s to %s [%s]\n",
				tftphostname, src, cp, tftpmode);
		tftpsin.sin_port = tftpport;
		tftprecvfile(fd, src, tftpmode);
	}
}

static void
tftpgetusage(s)
char * s;
{
	printf("usage: %s host:file host:file ... file, or\n", s);
	printf("       %s file file ... file if connected\n", s);
}

int	tftprexmtval = TIMEOUT;

#if 0
tftpsetrexmt(argc, argv)
	char *argv[];
{
	int t;

	if (argc < 2) {
		strcpy(tftpline, "Rexmt-timeout ");
		printf("(value) ");
		fgets(&tftpline[strlen(tftpline)], sizeof(tftpline)-strlen(tftpline), stdin);
		tftpmakeargv();
		argc = tftpmargc;
		argv = tftpmargv;
	}
	if (argc != 2) {
		printf("usage: %s value\n", argv[0]);
		return;
	}
	t = atoi(argv[1]);
	if (t < 0)
		printf("%s: bad value\n", t);
	else
		tftprexmtval = t;
}
#endif

int	tftpmaxtimeout = 5 * TIMEOUT;

#if 0
tftpsettimeout(argc, argv)
	char *argv[];
{
	int t;

	if (argc < 2) {
		strcpy(tftpline, "Maximum-timeout ");
		printf("(value) ");
		fgets(&tftpline[strlen(tftpline)], sizeof(tftpline)-strlen(tftpline), stdin);
		tftpmakeargv();
		argc = tftpmargc;
		argv = tftpmargv;
	}
	if (argc != 2) {
		printf("usage: %s value\n", argv[0]);
		return;
	}
	t = atoi(argv[1]);
	if (t < 0)
		printf("%s: bad value\n", t);
	else
		tftpmaxtimeout = t;
}

tftpstatus(argc, argv)
	char *argv[];
{
	if (tftpconnected)
		printf("Connected to %s.\n", hostname);
	else
		printf("Not connected.\n");
	printf("Mode: %s Verbose: %s Tracing: %s\n", tftpmode,
		tftpverbose ? "on" : "off", trace ? "on" : "off");
	printf("Rexmt-interval: %d seconds, Max-timeout: %d seconds\n",
		tftprexmtval, tftpmaxtimeout);
}
#endif

void tftpintr(int signo)
{
	signal(SIGALRM, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	alarm(0);
	longjmp(tftptoplevel, -1);
}

char *
tftptail(filename)
	char *filename;
{
	register char *s;
	
	while (*filename) {
		s = strrchr(filename, '/');
		if (s == NULL)
			break;
		if (s[1])
			return (s + 1);
		*s = '\0';
	}
	return (filename);
}

#if 0
/*
 * Command parser.
 */
tftpcommand(top)
	int top;
{
	register struct cmd *c;

	if (!top)
		putchar('\n');
	for (;;) {
		printf("%s> ", prompt);
		if (fgets(tftpline, sizeof(tftpline), stdin) == 0) {
			if (feof(stdin)) {
				tftpquit();
			} else {
				continue;
			}
		}
		if (tftpline[0] == 0)
			continue;
		tftpmakeargv();
		c = tftpgetcmd(tftpmargv[0]);
		if (c == (struct cmd *)-1) {
			printf("?Ambiguous command\n");
			continue;
		}
		if (c == 0) {
			printf("?Invalid command\n");
			continue;
		}
		(*c->handler)(tftpmargc, tftpmargv);
	}
}

struct cmd *
tftpgetcmd(name)
	register char *name;
{
	register char *p, *q;
	register struct cmd *c, *found;
	register int nmatches, longest;

	longest = 0;
	nmatches = 0;
	found = 0;
	for (c = tftpcmdtab; p = c->name; c++) {
		for (q = name; *q == *p++; q++)
			if (*q == 0)		/* exact match? */
				return (c);
		if (!*q) {			/* the name was a prefix */
			if (q - name > longest) {
				longest = q - name;
				nmatches = 1;
				found = c;
			} else if (q - name == longest)
				nmatches++;
		}
	}
	if (nmatches > 1)
		return ((struct cmd *)-1);
	return (found);
}
#endif

/*
 * Slice a string up into argc/argv.
 */
static void
tftpmakeargv()
{
	register char *cp;
	register char **argp = tftpmargv;

	tftpmargc = 0;
	for (cp = tftpline; *cp;) {
		while (isspace(*cp))
			cp++;
		if (*cp == '\0')
			break;
		*argp++ = cp;
		tftpmargc += 1;
		while (*cp != '\0' && !isspace(*cp))
			cp++;
		if (*cp == '\0')
			break;
		*cp++ = '\0';
	}
	*argp++ = 0;
}

#if 0
/*VARARGS*/
static void
tftpquit()
{
	exit(0);
}

/*
 * Help command.
 */
tftphelp(argc, argv)
	int argc;
	char *argv[];
{
	register struct cmd *c;

	if (argc == 1) {
		printf("Commands may be abbreviated.  Commands are:\n\n");
		for (c = cmdtab; c->name; c++)
			printf("%-*s\t%s\n", HELPINDENT, c->name, c->help);
		return;
	}
	while (--argc > 0) {
		register char *arg;
		arg = *++argv;
		c = tftpgetcmd(arg);
		if (c == (struct cmd *)-1)
			printf("?Ambiguous help command %s\n", arg);
		else if (c == (struct cmd *)0)
			printf("?Invalid help command %s\n", arg);
		else
			printf("%s\n", c->help);
	}
}
#endif

#if 0
/*VARARGS*/
void
tftpsettrace()
{
	tftptrace = !tftptrace;
	printf("Packet tracing %s.\n", tftptrace ? "on" : "off");
}

/*VARARGS*/
void
tftpsetverbose()
{
	tftpverbose = !tftpverbose;
	printf("Verbose mode %s.\n", tftpverbose ? "on" : "off");
}
#endif
