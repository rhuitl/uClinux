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
 *
 *	from: @(#)defs.h	5.10 (Berkeley) 2/28/91
 *	from: @(#)defs.h	8.1 (Berkeley) 6/5/93
 *	$Id: defs.h,v 1.9 1999/08/01 19:19:16 dholland Exp $
 */

/*
 * Internal data structure definitions for
 * user routing process.  Based on Xerox NS
 * protocol specs with mods relevant to more
 * general addressing scheme.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/route.h>
#include <netinet/in.h>
#include <protocols/routed.h>
#include <arpa/inet.h>

#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "trace.h"
#include "interface.h"
#include "table.h"
#include "af.h"

/*
 * When we find any interfaces marked down we rescan the
 * kernel every CHECK_INTERVAL seconds to see if they've
 * come up.
 */
#define	CHECK_INTERVAL	(1*60)

#define equal(a1, a2) \
	(memcmp((a1), (a2), sizeof (struct sockaddr)) == 0)

extern struct sockaddr_in addr;	/* address of daemon's socket */

extern int sock;			/* source and sink of all data */
extern int supplier;			/* process should supply updates */
extern int lookforinterfaces;	/* if 1 probe kernel for new up interfaces */
extern struct timeval now;		/* current idea of time */
extern struct timeval lastbcast;	/* last time all/changes broadcast */
extern struct timeval lastfullupdate;	/* last time full table broadcast */
extern struct timeval nextbcast;    /* time to wait before changes broadcast */
extern int needupdate;		    /* true if we need update at nextbcast */
extern struct sockaddr_in inet_default;	/* default inet addr */
extern int kernel_version;		/* kernel we are running under */

extern char	packet[MAXPACKETSIZE+1];
extern struct	rip *msg;

extern int rip_port;              /* port number we use (network byte order) */

void supply(struct sockaddr *, int, struct interface *, int);

void addrouteforif __P((struct interface *));
void bumploglevel(void);
void dumppacket(FILE *, char *, struct sockaddr *, char *,int, struct timeval *);
void gwkludge(void);
void hup(int);
void ifinit(void);
int inet_maskof(u_long);
u_long inet_netof_subnet(struct in_addr);
int inet_rtflags(struct sockaddr *);
int inet_sendroute(struct rt_entry *, struct sockaddr *);
void quit(char *);
void rip_input(struct sockaddr *, struct rip *, int);
void rtadd(struct sockaddr *, struct sockaddr *, int, int);
void rtchange(struct rt_entry *, struct sockaddr *, short);
void rtdefault(void);
void rtdelete(struct rt_entry *);
void rtdeleteall(int);
void rtinit(void);
int rtioctl(int, struct rtuentry *);
void sigtrace(int);
void sndmsg(struct sockaddr *, int, struct interface *, int);
void timer(int);
void timevaladd(struct timeval *t1, struct timeval *t2);
void timevalsub(struct timeval *t1, struct timeval *t2);
void toall(void (*)(struct sockaddr *, int, struct interface *, int), 
		int, struct interface *);
void traceoff(void);
void traceon(char *);
void trace(struct ifdebug *, struct sockaddr *, char *, int, int);
void traceaction(FILE *, char *, struct rt_entry *);
void traceinit(struct interface *);
void tracenewmetric(FILE *, struct rt_entry *, int);

#define ADD 1
#define DELETE 2
#define CHANGE 3
#define ROOT "root"
#define NOBODY "nobody"

#ifndef TIMER_RATE
#define TIMER_RATE SUPPLY_INTERVAL
#endif

