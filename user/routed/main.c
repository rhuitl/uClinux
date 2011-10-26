/*
 * Copyright (c) 1983, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
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
  "@(#) Copyright (c) 1983, 1988, 1993\n"
  "      The Regents of the University of California.  All rights reserved.\n";

/*
 * From: @(#)main.c	5.23 (Berkeley) 7/1/91
 * From: @(#)main.c	8.1 (Berkeley) 6/5/93
 */
char main_rcsid[] = 
  "$Id: main.c,v 1.14 1999/10/02 16:43:56 dholland Exp $";

#include "version.h"

/*
 * Routing Table Management Daemon
 */

#include "defs.h"
#include <sys/ioctl.h>
#include <sys/file.h>

#include <errno.h>
/* #include <signal.h>  (redundant with defs.h) */
#include <syslog.h>
#include <assert.h>
#include <sys/utsname.h>

#define BUFSPACE (127*1024)	/* max. input buffer size to request */

struct sockaddr_in addr;	/* address of daemon's socket */
int sock;			/* source and sink of all data */
char	packet[MAXPACKETSIZE+1];
int rip_port;

int	supplier = -1;		/* process should supply updates */
int	gateway = 0;		/* 1 if we are a gateway to parts beyond */
int	debug = 0;
struct	rip *msg = (struct rip *)packet;
int	kernel_version;

static void getkversion(void);
static int getsocket(void);
static void process(int);

int
main(int argc, char *argv[])
{
	int n, nfd, tflags = 0, ch;
	struct timeval *tvp, waittime;
	struct itimerval itval;
	struct rip *query = msg;
	fd_set ibits;
	sigset_t sigset, osigset;
	
	while ((ch = getopt(argc, argv, "sqtdg")) != EOF) {
		switch (ch) {
			case 's': supplier = 1; break;
			case 'q': supplier = 0; break;
			case 't': 
				tflags++;
				break;
			case 'd': 
				debug++;
				setlogmask(LOG_UPTO(LOG_DEBUG));
				break;
			case 'g': gateway = 1; break;
			default:
				fprintf(stderr, "usage: routed [ -sqtdg ]\n");
				exit(1);
		}
	}

	getkversion();

	sock = getsocket();
	assert(sock>=0);

	openlog("routed", LOG_PID | LOG_ODELAY, LOG_DAEMON);

	if (debug == 0 && tflags == 0) {
#ifndef EMBED
		switch (fork()) {
			case -1: perror("fork"); exit(1);
			case 0: break;  /* child */
			default: exit(0);   /* parent */
		}
#endif
		close(0);
		close(1);
		close(2);
		setsid();
		setlogmask(LOG_UPTO(LOG_WARNING));
	}
	else {
		setlogmask(LOG_UPTO(LOG_DEBUG));
	}

	/*
	 * Any extra argument is considered
	 * a tracing log file.
	 * 
	 * Note: because traceon() redirects stderr, anything planning to
	 * crash on startup should do so before this point.
	 */

	if (argc > 1) {
		traceon(argv[argc - 1]);
	}
	while (tflags-- > 0) {
		bumploglevel();
	}

	gettimeofday(&now, NULL);

	/*
	 * Collect an initial view of the world by
	 * checking the interface configuration and the gateway kludge
	 * file.  Then, send a request packet on all
	 * directly connected networks to find out what
	 * everyone else thinks.
	 */

	rtinit();
	ifinit();
	gwkludge();
	if (gateway > 0) {
		rtdefault();
	}
	if (supplier < 0) {
		supplier = 0;
	}
	query->rip_cmd = RIPCMD_REQUEST;
	query->rip_vers = RIPVERSION;
	if (sizeof(query->rip_nets[0].rip_dst.sa_family) > 1) {
		/* XXX */
		query->rip_nets[0].rip_dst.sa_family = htons((u_short)AF_UNSPEC);
	}
	else {
		/* unreachable code (at least on most platforms) */
		query->rip_nets[0].rip_dst.sa_family = AF_UNSPEC;
	}
	query->rip_nets[0].rip_metric = htonl((u_long)HOPCNT_INFINITY);

	toall(sndmsg, 0, NULL);

	signal(SIGALRM, timer);
	signal(SIGHUP, hup);
	signal(SIGTERM, hup);
	signal(SIGINT, rtdeleteall);
	signal(SIGUSR1, sigtrace);
	signal(SIGUSR2, sigtrace);

	itval.it_interval.tv_sec = TIMER_RATE;
	itval.it_value.tv_sec = TIMER_RATE;
	itval.it_interval.tv_usec = 0;
	itval.it_value.tv_usec = 0;

	srandom(time(NULL) ^ getpid());

	if (setitimer(ITIMER_REAL, &itval, (struct itimerval *)NULL) < 0) {
		syslog(LOG_ERR, "setitimer: %m\n");
	}

	FD_ZERO(&ibits);
	nfd = sock + 1;			/* 1 + max(fd's) */
	for (;;) {
		FD_SET(sock, &ibits);

		/*
		 * If we need a dynamic update that was held off,
		 * needupdate will be set, and nextbcast is the time
		 * by which we want select to return.  Compute time
		 * until dynamic update should be sent, and select only
		 * until then.  If we have already passed nextbcast,
		 * just poll.
		 */
		if (needupdate) {
			waittime = nextbcast;
			timevalsub(&waittime, &now);
			if (waittime.tv_sec < 0) {
				waittime.tv_sec = 0;
				waittime.tv_usec = 0;
			}
			if (traceactions)
				fprintf(ftrace,
				 "select until dynamic update %ld/%ld sec/usec\n",
				    (long)waittime.tv_sec, (long)waittime.tv_usec);
			tvp = &waittime;
		}
		else {
			tvp = (struct timeval *)NULL;
		}

		n = select(nfd, &ibits, 0, 0, tvp);
		if (n <= 0) {
			/*
			 * Need delayed dynamic update if select returned
			 * nothing and we timed out.  Otherwise, ignore
			 * errors (e.g. EINTR).
			 */
			if (n < 0) {
				if (errno == EINTR)
					continue;
				syslog(LOG_ERR, "select: %m");
			}
			sigemptyset(&sigset);
			sigaddset(&sigset, SIGALRM);
			sigprocmask(SIG_BLOCK, &sigset, &osigset);
			if (n == 0 && needupdate) {
				if (traceactions)
					fprintf(ftrace,
					    "send delayed dynamic update\n");
				(void) gettimeofday(&now,
					    (struct timezone *)NULL);
				toall(supply, RTS_CHANGED,
				    (struct interface *)NULL);
				lastbcast = now;
				needupdate = 0;
				nextbcast.tv_sec = 0;
			}
			sigprocmask(SIG_SETMASK, &osigset, NULL);
			continue;
		}

		gettimeofday(&now, (struct timezone *)NULL);
		sigemptyset(&sigset);
		sigaddset(&sigset, SIGALRM);
		sigprocmask(SIG_BLOCK, &sigset, &osigset);

		if (FD_ISSET(sock, &ibits)) {
			process(sock);
		}

		/* handle ICMP redirects */
		sigprocmask(SIG_SETMASK, &osigset, NULL);
	}
}

/*
 * Put Linux kernel version into
 * the global variable kernel_version.
 * Example: 1.2.8 = 0x010208
 */

static
void
getkversion(void)
{
	struct utsname uts;
	int maj, min, pl;

	maj = min = pl = 0;
	uname(&uts);
	sscanf(uts.release, "%d.%d.%d", &maj, &min, &pl);
	kernel_version = (maj << 16) | (min << 8) | pl;
}

void
timevaladd(struct timeval *t1, struct timeval *t2)
{

	t1->tv_sec += t2->tv_sec;
	if ((t1->tv_usec += t2->tv_usec) > 1000000) {
		t1->tv_sec++;
		t1->tv_usec -= 1000000;
	}
}

void
timevalsub(struct timeval *t1, struct timeval *t2)
{

	t1->tv_sec -= t2->tv_sec;
	if ((t1->tv_usec -= t2->tv_usec) < 0) {
		t1->tv_sec--;
		t1->tv_usec += 1000000;
	}
}

static
void
process(int fd)
{
	struct sockaddr from;
	socklen_t fromlen;
	int cc;
	union {
		char	buf[MAXPACKETSIZE+1];
		struct	rip rip;
	} inbuf;

	for (;;) {
		fromlen = sizeof(from);
		cc = recvfrom(fd, &inbuf, sizeof(inbuf), 0, &from, &fromlen);
		if (cc <= 0) {
			if (cc < 0 && errno != EWOULDBLOCK)
				perror("recvfrom");
			break;
		}
		if (fromlen != sizeof (struct sockaddr_in)) {
			break;
		}
		rip_input(&from, &inbuf.rip, cc);
	}
}

/*
 * This function is called during startup, and should error to stderr,
 * not syslog, and should exit on error.
 */
static
int
getsocket(void)
{
	int s, on = 1;
	struct servent *sp;

	sp = getservbyname("router", "udp");
	if (sp == NULL) {
		fprintf(stderr, "routed: router/udp: unknown service\n");
		exit(1);
	}
	rip_port = sp->s_port;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket");
		exit(1);
	}

#ifdef SO_BROADCAST
	if (setsockopt(s, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0) {
		perror("setsockopt SO_BROADCAST");
		exit(1);
	}
#endif

#ifdef SO_RCVBUF
	on = BUFSPACE;
	while (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &on, sizeof(on))) {
		if (on <= 8192) {
			/* give up */
			perror("setsockopt SO_RCVBUF");
			break;
		}
		/* try 1k less */
		on -= 1024;
	}
	if (traceactions) {
		fprintf(ftrace, "recv buf %d\n", on);
	}
#endif

	addr.sin_family = AF_INET;
	addr.sin_port = rip_port;

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(s);
		exit(1);
	}

	if (fcntl(s, F_SETFL, O_NONBLOCK) == -1) {
		perror("fcntl O_NONBLOCK");
	}

	return (s);
}
