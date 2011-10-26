/*
 * Copyright (c) 1983 Regents of the University of California.
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

char copyright[] =
  "@(#) Copyright (c) 1983 Regents of the University of California.\n"
  "All rights reserved.\n";

/*
 * From: @(#)main.c	5.10 (Berkeley) 3/1/91
 */
char main_rcsid[] = 
  "$Id: main.c,v 1.9 1996/11/25 18:42:46 dholland Exp $";

/* Many bug fixes are from Jim Guyton <guyton@rand-unix> */

/*
 * TFTP User Program -- Command Interface.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <setjmp.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <unistd.h>

#define	TIMEOUT		5		/* secs between rexmt's */

struct sockaddr_in s_inn;
int f;
int trace;
int verbose;
int rexmtval = TIMEOUT;
int maxtimeout = 5 * TIMEOUT;
sigjmp_buf toplevel;
void sendfile(int fd, char *name, char *modestr);
void recvfile(int fd, char *name, char *modestr);


static int connected;
static short port;
static char mode[32];
static char line[200];
static int margc;
static char *margv[20];
static const char *prompt = "tftp";
static struct servent *sp;

static void intr(int);

void makeargv(void);
void command(int top);
void quit(int argc, char *argv[]);
void help(int argc, char *argv[]);
void setverbose(int argc, char *argv[]);
void settrace(int argc, char *argv[]);
void status(int argc, char *argv[]);
void get(int argc, char *argv[]);
void put(int argc, char *argv[]);
void setpeer(int argc, char *argv[]);
void modecmd(int argc, char *argv[]);
void setrexmt(int argc, char *argv[]);
void settimeout(int argc, char *argv[]);
void setbinary(int argc, char *argv[]);
void setascii(int argc, char *argv[]);
void setmode(const char *newmode);
void putusage(const char *s);
void getusage(const char *s);

#define HELPINDENT ((int) sizeof("connect"))

struct cmd {
	const char *name;
	const char *help;
	void (*handler)(int, char *[]);
};

char	vhelp[] = "toggle verbose mode";
char	thelp[] = "toggle packet tracing";
char	chelp[] = "connect to remote tftp";
char	qhelp[] = "exit tftp";
char	hhelp[] = "print help information";
char	shelp[] = "send file";
char	rhelp[] = "receive file";
char	mhelp[] = "set file transfer mode";
char	sthelp[] = "show current status";
char	xhelp[] = "set per-packet retransmission timeout";
char	ihelp[] = "set total retransmission timeout";
char    ashelp[] = "set mode to netascii";
char    bnhelp[] = "set mode to octet";

struct cmd cmdtab[] = {
	{ "connect",	chelp,		setpeer },
	{ "mode",       mhelp,          modecmd },
	{ "put",	shelp,		put },
	{ "get",	rhelp,		get },
	{ "quit",	qhelp,		quit },
	{ "verbose",	vhelp,		setverbose },
	{ "trace",	thelp,		settrace },
	{ "status",	sthelp,		status },
	{ "binary",     bnhelp,         setbinary },
	{ "ascii",      ashelp,         setascii },
	{ "rexmt",	xhelp,		setrexmt },
	{ "timeout",	ihelp,		settimeout },
	{ "?",		hhelp,		help },
	{ 0 }
};

static struct cmd *getcmd(const char *name);
static char *tail(char *filename);

int
main(int argc, char *argv[])
{
	struct sockaddr_in s_in;
	int top;

	sp = getservbyname("tftp", "udp");
	if (sp == 0) {
		fprintf(stderr, "tftp: udp/tftp: unknown service\n");
		exit(1);
	}
	f = socket(AF_INET, SOCK_DGRAM, 0);
	if (f < 0) {
		perror("tftp: socket");
		exit(3);
	}
	memset(&s_in, 0, sizeof(s_in));
	s_in.sin_family = AF_INET;
	if (bind(f, (struct sockaddr *)&s_in, sizeof (s_in)) < 0) {
		perror("tftp: bind");
		exit(1);
	}
	strcpy(mode, "netascii");
	signal(SIGINT, intr);
	if (argc > 1) {
		if (sigsetjmp(toplevel, 1) != 0)
			exit(0);
		setpeer(argc, argv);
	}
	top = sigsetjmp(toplevel, 1) == 0;
	for (;;)
		command(top);
}

static char hostname[100];

void
setpeer(int argc, char *argv[])
{
	struct hostent *host;

	if (argc < 2) {
		strcpy(line, "Connect ");
		printf("(to) ");
		fgets(&line[strlen(line)], sizeof(line) - strlen(line), stdin);
		makeargv();
		argc = margc;
		argv = margv;
	}
	if (argc > 3) {
		printf("usage: %s host-name [port]\n", argv[0]);
		return;
	}
	host = gethostbyname(argv[1]);
	if (host) {
		s_inn.sin_family = host->h_addrtype;
		if (host->h_length > (int)sizeof(s_inn.sin_addr)) {
			host->h_length = sizeof(s_inn.sin_addr);
		}
		memcpy(&s_inn.sin_addr, host->h_addr, host->h_length);
		strncpy(hostname, host->h_name, sizeof(hostname));
		hostname[sizeof(hostname)-1] = 0;
	} 
	else {
		s_inn.sin_family = AF_INET;
		if (!inet_aton(argv[1], &s_inn.sin_addr)) {
			connected = 0;
			printf("%s: unknown host\n", argv[1]);
			return;
		}
		strcpy(hostname, argv[1]);
	}
	port = sp->s_port;
	if (argc == 3) {
		port = atoi(argv[2]);
		if (port < 0) {
			printf("%s: bad port number\n", argv[2]);
			connected = 0;
			return;
		}
		port = htons(port);
	}
	connected = 1;
}

struct	modes {
	const char *m_name;
	const char *m_mode;
} modes[] = {
	{ "ascii",	"netascii" },
	{ "netascii",   "netascii" },
	{ "binary",     "octet" },
	{ "image",      "octet" },
	{ "octet",      "octet" },
/*      { "mail",       "mail" },       */
	{ 0,		0 }
};

void
modecmd(int argc, char *argv[])
{
	register struct modes *p;
	const char *sep;

	if (argc < 2) {
		printf("Using %s mode to transfer files.\n", mode);
		return;
	}
	if (argc == 2) {
		for (p = modes; p->m_name; p++)
			if (strcmp(argv[1], p->m_name) == 0)
				break;
		if (p->m_name) {
			setmode(p->m_mode);
			return;
		}
		printf("%s: unknown mode\n", argv[1]);
		/* drop through and print usage message */
	}

	printf("usage: %s [", argv[0]);
	sep = " ";
	for (p = modes; p->m_name; p++) {
		printf("%s%s", sep, p->m_name);
		if (*sep == ' ')
			sep = " | ";
	}
	printf(" ]\n");
	return;
}

void
setbinary(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	setmode("octet");
}

void
setascii(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	setmode("netascii");
}

void
setmode(const char *newmode)
{
	strcpy(mode, newmode);
	if (verbose)
		printf("mode set to %s\n", mode);
}


/*
 * Send file(s).
 */
void
put(int argc, char *argv[])
{
	int fd;
	register int n;
	register char *ccp, *targ;

	if (argc < 2) {
		strcpy(line, "send ");
		printf("(file) ");
		fgets(&line[strlen(line)], sizeof(line) - strlen(line), stdin);
		makeargv();
		argc = margc;
		argv = margv;
	}
	if (argc < 2) {
		putusage(argv[0]);
		return;
	}
	targ = argv[argc - 1];
	if (index(argv[argc - 1], ':')) {
		char *cp;
		struct hostent *hp;

		for (n = 1; n < argc - 1; n++)
			if (index(argv[n], ':')) {
				putusage(argv[0]);
				return;
			}
		cp = argv[argc - 1];
		targ = index(cp, ':');
		*targ++ = 0;
		hp = gethostbyname(cp);
		if (hp == NULL) {
			fprintf(stderr, "tftp: %s: ", cp);
			herror((char *)NULL);
			return;
		}
		if (hp->h_length > (int)sizeof(s_inn.sin_addr)) {
			hp->h_length = sizeof(s_inn.sin_addr);
		}
		memcpy(&s_inn.sin_addr, hp->h_addr, hp->h_length);
		s_inn.sin_family = hp->h_addrtype;
		connected = 1;
		strncpy(hostname, hp->h_name, sizeof(hostname));
		hostname[sizeof(hostname)-1] = 0;
	}
	if (!connected) {
		printf("No target machine specified.\n");
		return;
	}
	if (argc < 4) {
		ccp = argc == 2 ? tail(targ) : argv[1];
		fd = open(ccp, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "tftp: "); 
			perror(ccp);
			return;
		}
		if (verbose)
			printf("putting %s to %s:%s [%s]\n",
				ccp, hostname, targ, mode);
		s_inn.sin_port = port;
		sendfile(fd, targ, mode);
		return;
	}
				/* this assumes the target is a directory */
				/* on a remote unix system.  hmmmm.  */
	ccp = targ+strlen(targ);
	*ccp++ = '/';
	for (n = 1; n < argc - 1; n++) {
		strcpy(ccp, tail(argv[n]));
		fd = open(argv[n], O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "tftp: "); perror(argv[n]);
			continue;
		}
		if (verbose)
			printf("putting %s to %s:%s [%s]\n",
				argv[n], hostname, targ, mode);
		s_inn.sin_port = port;
		sendfile(fd, targ, mode);
	}
}

void
putusage(const char *s)
{
	printf("usage: %s file ... host:target, or\n", s);
	printf("       %s file ... target (when already connected)\n", s);
}

/*
 * Receive file(s).
 */
void
get(int argc, char *argv[])
{
	int fd;
	register int n;
	register char *cp;
	char *src;

	if (argc < 2) {
		strcpy(line, "get ");
		printf("(files) ");
		fgets(&line[strlen(line)], sizeof(line) - strlen(line), stdin);
		makeargv();
		argc = margc;
		argv = margv;
	}
	if (argc < 2) {
		getusage(argv[0]);
		return;
	}
	if (!connected) {
		for (n = 1; n < argc ; n++)
			if (index(argv[n], ':') == 0) {
				getusage(argv[0]);
				return;
			}
	}
	for (n = 1; n < argc ; n++) {
		src = index(argv[n], ':');
		if (src == NULL)
			src = argv[n];
		else {
			struct hostent *hp;

			*src++ = 0;
			hp = gethostbyname(argv[n]);
			if (hp == NULL) {
				fprintf(stderr, "tftp: %s: ", argv[n]);
				herror(NULL);
				continue;
			}
			if (hp->h_length > (int)sizeof(s_inn.sin_addr)) {
				hp->h_length = sizeof(s_inn.sin_addr);
			}
			memcpy(&s_inn.sin_addr, hp->h_addr, hp->h_length);
			s_inn.sin_family = hp->h_addrtype;
			connected = 1;
			strncpy(hostname, hp->h_name, sizeof(hostname));
			hostname[sizeof(hostname)-1] = 0;
		}
		if (argc < 4) {
			cp = argc == 3 ? argv[2] : tail(src);
			fd = creat(cp, 0644);
			if (fd < 0) {
				fprintf(stderr, "tftp: "); perror(cp);
				return;
			}
			if (verbose)
				printf("getting from %s:%s to %s [%s]\n",
					hostname, src, cp, mode);
			s_inn.sin_port = port;
			recvfile(fd, src, mode);
			break;
		}
		cp = tail(src);         /* new .. jdg */
		fd = creat(cp, 0644);
		if (fd < 0) {
			fprintf(stderr, "tftp: "); perror(cp);
			continue;
		}
		if (verbose)
			printf("getting from %s:%s to %s [%s]\n",
				hostname, src, cp, mode);
		s_inn.sin_port = port;
		recvfile(fd, src, mode);
	}
}

void
getusage(const char *s)
{
	printf("usage: %s host:file host:file ... file, or\n", s);
	printf("       %s file file ... file if connected\n", s);
}


void
setrexmt(int argc, char *argv[])
{
	int t;

	if (argc < 2) {
		strcpy(line, "Rexmt-timeout ");
		printf("(value) ");
		fgets(&line[strlen(line)], sizeof(line) - strlen(line), stdin);
		makeargv();
		argc = margc;
		argv = margv;
	}
	if (argc != 2) {
		printf("usage: %s value\n", argv[0]);
		return;
	}
	t = atoi(argv[1]);
	if (t < 0)
		printf("%s: bad value\n", argv[1]);
	else
		rexmtval = t;
}

void
settimeout(int argc, char *argv[])
{
	int t;

	if (argc < 2) {
		strcpy(line, "Maximum-timeout ");
		printf("(value) ");
		fgets(&line[strlen(line)], sizeof(line) - strlen(line), stdin);
		makeargv();
		argc = margc;
		argv = margv;
	}
	if (argc != 2) {
		printf("usage: %s value\n", argv[0]);
		return;
	}
	t = atoi(argv[1]);
	if (t < 0)
		printf("%s: bad value\n", argv[1]);
	else
		maxtimeout = t;
}

void
status(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	if (connected)
		printf("Connected to %s.\n", hostname);
	else
		printf("Not connected.\n");
	printf("Mode: %s Verbose: %s Tracing: %s\n", mode,
		verbose ? "on" : "off", trace ? "on" : "off");
	printf("Rexmt-interval: %d seconds, Max-timeout: %d seconds\n",
		rexmtval, maxtimeout);
}

static
void
intr(int ignore)
{
	(void)ignore;

	signal(SIGALRM, SIG_IGN);
	alarm(0);
	siglongjmp(toplevel, -1);
}

static
char *
tail(char *filename)
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
	return filename;
}

/*
 * Command parser.
 */
void
command(int top)
{
	register struct cmd *c;

	if (!top)
		putchar('\n');
	for (;;) {
		printf("%s> ", prompt);
		if (fgets(line, sizeof(line), stdin) == 0) {
			if (feof(stdin)) {
				quit(0, NULL);
			} else {
				continue;
			}
		}
		if (line[0] == 0)
			continue;
		makeargv();
		c = getcmd(margv[0]);
		if (c == (struct cmd *)-1) {
			printf("?Ambiguous command\n");
			continue;
		}
		if (c == 0) {
			printf("?Invalid command\n");
			continue;
		}
		(*c->handler)(margc, margv);
	}
}

struct cmd *
getcmd(const char *name)
{
	const char *p, *q;
	struct cmd *c, *found;
	int nmatches, longest;

	longest = 0;
	nmatches = 0;
	found = 0;
	for (c = cmdtab; (p = c->name)!=NULL; c++) {
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

/*
 * Slice a string up into argc/argv.
 */
void
makeargv(void)
{
	register char *cp;
	register char **argp = margv;

	margc = 0;
	for (cp = line; *cp;) {
		while (isspace(*cp))
			cp++;
		if (*cp == '\0')
			break;
		*argp++ = cp;
		margc += 1;
		while (*cp != '\0' && !isspace(*cp))
			cp++;
		if (*cp == '\0')
			break;
		*cp++ = '\0';
	}
	*argp++ = 0;
}

void
quit(int ign1, char *ign2[])
{
	(void)ign1;
	(void)ign2;
	exit(0);
}

/*
 * Help command.
 */
void
help(int argc, char *argv[])
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
		c = getcmd(arg);
		if (c == (struct cmd *)-1)
			printf("?Ambiguous help command %s\n", arg);
		else if (c == (struct cmd *)0)
			printf("?Invalid help command %s\n", arg);
		else
			printf("%s\n", c->help);
	}
}

void
settrace(int ign1, char *ign2[])
{
	(void)ign1;
	(void)ign2;
	trace = !trace;
	printf("Packet tracing %s.\n", trace ? "on" : "off");
}

void
setverbose(int ign1, char *ign2[])
{
	(void)ign1;
	(void)ign2;
	verbose = !verbose;
	printf("Verbose mode %s.\n", verbose ? "on" : "off");
}
