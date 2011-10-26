/*
 * Copyright (c) 1983, 1993
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

/*
 * From: @(#)af.c	5.11 (Berkeley) 2/28/91
 * From: @(#)af.c	8.1 (Berkeley) 6/5/93
 */
char af_rcsid[] = 
  "$Id: af.c,v 1.8 1999/09/28 15:48:20 dholland Exp $";

#include "defs.h"

/*
 * Address family support routines
 */

void inet_canon(struct sockaddr *);
int inet_checkhost(struct sockaddr *);
char *inet_format(struct sockaddr *, char *, size_t);
void inet_hash(struct sockaddr *, struct afhash *);
int inet_netmatch(struct sockaddr *, struct sockaddr *);
int inet_portcheck(struct sockaddr *);
int inet_portmatch(struct sockaddr *);
void inet_output(int, int, struct sockaddr *, int);

#define NIL	{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
#define	INET \
	{ inet_hash,		inet_netmatch,		inet_output, \
	  inet_portmatch,	inet_portcheck,		inet_checkhost, \
	  inet_rtflags,		inet_sendroute,		inet_canon, \
	  inet_format \
	}

struct afswitch afswitch[AF_MAX] = 
{
	NIL,		/* 0- unused */
	NIL,		/* 1- Unix domain, unused */
	INET,		/* Internet */
	/* 
	 * Expect a warning here from gcc 2.95 about missing initializer.
	 * They appear to have decided that the standard behavior of C 
	 * where unspecified initializers are 0 - something tons of old
	 * unix code relies on - is evil. Trouble is, here, AF_MAX is
	 * defined by the kernel, so even if we were to put in a whole
	 * pile of NILs here, it would become kernel-version dependent
	 * for no good reason. Idiots. Someone fix gcc.
	 */
};

int af_max = sizeof(afswitch) / sizeof(afswitch[0]);

struct sockaddr_in inet_default = 
{
	AF_INET, 0, { INADDR_ANY }, { 0 }
};

void inet_hash(struct sockaddr *sa, struct afhash *hp)
{
	struct sockaddr_in *sin=(struct sockaddr_in *)sa;
	u_long n;

	n = inet_netof_subnet(sin->sin_addr);
	if (n)
	    while ((n & 0xff) == 0)
		n >>= 8;
	hp->afh_nethash = n;
	hp->afh_hosthash = ntohl(sin->sin_addr.s_addr);
	hp->afh_hosthash &= 0x7fffffff;
}

int inet_netmatch(struct sockaddr *sa1, struct sockaddr *sa2)
{
	struct sockaddr_in *sin1=(struct sockaddr_in *)sa1;
	struct sockaddr_in *sin2=(struct sockaddr_in *)sa2;
	return (inet_netof_subnet(sin1->sin_addr) ==
	    inet_netof_subnet(sin2->sin_addr));
}

/*
 * Verify the message is from the right port.
 */
int inet_portmatch(struct sockaddr *sa)
{
	struct sockaddr_in *sin=(struct sockaddr_in *)sa;
	return (sin->sin_port == rip_port);
}

/*
 * Verify the message is from a "trusted" port.
 */
int inet_portcheck(struct sockaddr *sa)
{
	struct sockaddr_in *sin=(struct sockaddr_in *)sa;
	return (ntohs(sin->sin_port) <= IPPORT_RESERVED);
}

/*
 * Internet output routine.
 */
void inet_output(int s, int flags, struct sockaddr *sa, int size)
{
	struct sockaddr_in dst = *(struct sockaddr_in *)sa;

	if (dst.sin_port == 0) {
		dst.sin_port = rip_port;
	}
	if (sendto(s, packet, size, flags, (struct sockaddr *)&dst, 
		   sizeof(dst)) < 0) {
		perror("sendto");
	}
}

/*
 * Return 1 if the address is believed
 * for an Internet host -- THIS IS A KLUDGE.
 */
int inet_checkhost(struct sockaddr *sa)
{
	struct sockaddr_in *sin=(struct sockaddr_in *)sa;
	u_long i = ntohl(sin->sin_addr.s_addr);

	if (IN_EXPERIMENTAL(i) || sin->sin_port != 0)
		return (0);
	if (i != 0 && (i & 0xff000000) == 0)
		return (0);
	for (i = 0; i < sizeof(sin->sin_zero)/sizeof(sin->sin_zero[0]); i++)
		if (sin->sin_zero[i])
			return (0);
	return (1);
}

void inet_canon(struct sockaddr *sa)
{
	struct sockaddr_in *sin=(struct sockaddr_in *)sa;
	sin->sin_port = 0;
}

char *inet_format(struct sockaddr *sa, char *buf, size_t sz)
{
	struct sockaddr_in *sin=(struct sockaddr_in *)sa;
	strncpy(buf, inet_ntoa(sin->sin_addr), sz);
	buf[sz - 1] = '\0';
	return (buf);
}
