/*
 * Copyright (c) 1995, 1996, 1998 Theo de Raadt.  All rights reserved.
 * Copyright (c) 1983, 1993, 1994
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
 * 3. Neither the name of the University nor the names of its contributors
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

#if defined(LIBC_SCCS) && !defined(lint)
static char *rcsid = "$OpenBSD: rcmd.c,v 1.48 2003/09/25 21:14:46 millert Exp $";
#endif /* LIBC_SCCS and not lint */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <signal.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>
// #include <netgroup.h>

// int	__ivaliduser(FILE *, in_addr_t, const char *, const char *);
int	__ivaliduser_sa(FILE *, struct sockaddr *, socklen_t,
	    const char *, const char *);
static int __icheckhost(struct sockaddr *, socklen_t, const char *);
static char *__gethostloop(struct sockaddr *, socklen_t);

/*
 * XXX
 * Don't make static, used by lpd(8).
 *
 * Returns 0 if ok, -1 if not ok.
 */
 /*
int
__ivaliduser(hostf, raddrl, luser, ruser)
	FILE *hostf;
	in_addr_t raddrl;
	const char *luser, *ruser;
{
	struct sockaddr_in sin;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(struct sockaddr_in);
	memcpy(&sin.sin_addr, &raddrl, sizeof(sin.sin_addr));
	return __ivaliduser_sa(hostf, (struct sockaddr *)&sin, sin.sin_len,
		    luser, ruser);
}*/

int
__ivaliduser_sa(hostf, raddr, salen, luser, ruser)
	FILE *hostf;
	struct sockaddr *raddr;
	socklen_t salen;
	const char *luser, *ruser;
{
	register char *user, *p;
	char *buf;
	const char *auser, *ahost;
	int hostok, userok;
	char *rhost = (char *)-1;
	char domain[MAXHOSTNAMELEN];

#define BUFFER_SIZE 2048
	size_t buflen;
	char buffer[BUFFER_SIZE];

	getdomainname(domain, sizeof(domain));

	while ((buf = fgets(buffer, BUFFER_SIZE, hostf))) {
		buflen = strlen( buffer );
		p = buf;
		if (*p == '#')
			continue;
		while (p < buf + buflen && *p != '\n' && *p != ' ' && *p != '\t') {
			if (!isprint(*p))
				goto bail;
			*p = isupper(*p) ? tolower(*p) : *p;
			p++;
		}
		if (p >= buf + buflen)
			continue;
		if (*p == ' ' || *p == '\t') {
			*p++ = '\0';
			while (p < buf + buflen && (*p == ' ' || *p == '\t'))
				p++;
			if (p >= buf + buflen)
				continue;
			user = p;
			while (p < buf + buflen && *p != '\n' && *p != ' ' &&
			    *p != '\t') {
				if (!isprint(*p))
					goto bail;
				p++;
			}
		} else
			user = p;
		*p = '\0';

		if (p == buf)
			continue;

		auser = *user ? user : luser;
		ahost = buf;

		if (strlen(ahost) >= MAXHOSTNAMELEN)
			continue;

#ifndef __UCLIBC__
		/*
		 * innetgr() must lookup a hostname (we do not attempt
		 * to change the semantics so that netgroups may have
		 * #.#.#.# addresses in the list.)
		 */
		if (ahost[0] == '+')
			switch (ahost[1]) {
			case '\0':
				hostok = 1;
				break;
			case '@':
				if (rhost == (char *)-1)
					rhost = __gethostloop(raddr, salen);
				hostok = 0;
				if (rhost)
					hostok = innetgr(&ahost[2], rhost,
					    NULL, domain);
				break;
			default:
				hostok = __icheckhost(raddr, salen, &ahost[1]);
				break;
			}
		else if (ahost[0] == '-')
			switch (ahost[1]) {
			case '\0':
				hostok = -1;
				break;
			case '@':
				if (rhost == (char *)-1)
					rhost = __gethostloop(raddr, salen);
				hostok = 0;
				if (rhost)
					hostok = -innetgr(&ahost[2], rhost,
					    NULL, domain);
				break;
			default:
				hostok = -__icheckhost(raddr, salen, &ahost[1]);
				break;
			}
		else
			hostok = __icheckhost(raddr, salen, ahost);


		if (auser[0] == '+')
			switch (auser[1]) {
			case '\0':
				userok = 1;
				break;
			case '@':
				userok = innetgr(&auser[2], NULL, ruser,
				    domain);
				break;
			default:
				userok = strcmp(ruser, &auser[1]) ? 0 : 1;
				break;
			}
		else if (auser[0] == '-')
			switch (auser[1]) {
			case '\0':
				userok = -1;
				break;
			case '@':
				userok = -innetgr(&auser[2], NULL, ruser,
				    domain);
				break;
			default:
				userok = strcmp(ruser, &auser[1]) ? 0 : -1;
				break;
			}
		else
#endif
			userok = strcmp(ruser, auser) ? 0 : 1;

		/* Check if one component did not match */
		if (hostok == 0 || userok == 0)
			continue;

		/* Check if we got a forbidden pair */
		if (userok <= -1 || hostok <= -1)
			return (-1);

		/* Check if we got a valid pair */
		if (hostok >= 1 && userok >= 1)
			return (0);
	}
bail:
	return (-1);
}

/*
 * Returns "true" if match, 0 if no match.  If we do not find any
 * semblance of an A->PTR->A loop, allow a simple #.#.#.# match to work.
 *
 * NI_WITHSCOPEID is useful for comparing sin6_scope_id portion
 * if af == AF_INET6.
 */
static int
__icheckhost(raddr, salen, lhost)
	struct sockaddr *raddr;
	socklen_t salen;
	const char *lhost;
{
	struct addrinfo hints, *res, *r;
	char h1[NI_MAXHOST], h2[NI_MAXHOST];
	int error;
#ifdef NI_WITHSCOPEID
	const int niflags = NI_NUMERICHOST | NI_WITHSCOPEID;
#else
	const int niflags = NI_NUMERICHOST;
#endif

	h1[0] = '\0';
	if (getnameinfo(raddr, salen, h1, sizeof(h1), NULL, 0,
	    niflags) != 0)
		return (0);

	/* Resolve laddr into sockaddr */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = raddr->sa_family;
	hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
	res = NULL;
	error = getaddrinfo(lhost, "0", &hints, &res);
	if (error)
		return (0);

	/*
	 * Try string comparisons between raddr and laddr.
	 */
	for (r = res; r; r = r->ai_next) {
		h2[0] = '\0';
		if (getnameinfo(r->ai_addr, r->ai_addrlen, h2, sizeof(h2),
		    NULL, 0, niflags) != 0)
			continue;
		if (strcmp(h1, h2) == 0) {
			freeaddrinfo(res);
			return (1);
		}
	}

	/* No match. */
	freeaddrinfo(res);
	return (0);
}

/*
 * Return the hostname associated with the supplied address.
 * Do a reverse lookup as well for security. If a loop cannot
 * be found, pack the result of inet_ntoa() into the string.
 *
 * NI_WITHSCOPEID is useful for comparing sin6_scope_id portion
 * if af == AF_INET6.
 */
static char *
__gethostloop(raddr, salen)
	struct sockaddr *raddr;
	socklen_t salen;
{
	static char remotehost[NI_MAXHOST];
	char h1[NI_MAXHOST], h2[NI_MAXHOST];
	struct addrinfo hints, *res, *r;
	int error;
#ifdef NI_WITHSCOPEID
	const int niflags = NI_NUMERICHOST | NI_WITHSCOPEID;
#else
	const int niflags = NI_NUMERICHOST;
#endif

	h1[0] = remotehost[0] = '\0';
	if (getnameinfo(raddr, salen, remotehost, sizeof(remotehost),
	    NULL, 0, NI_NAMEREQD) != 0)
		return (NULL);
	if (getnameinfo(raddr, salen, h1, sizeof(h1), NULL, 0,
	    niflags) != 0)
		return (NULL);

	/*
	 * Look up the name and check that the supplied
	 * address is in the list
	 */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = raddr->sa_family;
	hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
	hints.ai_flags = AI_CANONNAME;
	res = NULL;
	error = getaddrinfo(remotehost, "0", &hints, &res);
	if (error)
		return (NULL);

	for (r = res; r; r = r->ai_next) {
		h2[0] = '\0';
		if (getnameinfo(r->ai_addr, r->ai_addrlen, h2, sizeof(h2),
		    NULL, 0, niflags) != 0)
			continue;
		if (strcmp(h1, h2) == 0) {
			freeaddrinfo(res);
			return (remotehost);
		}
	}

	/*
	 * either the DNS adminstrator has made a configuration
	 * mistake, or someone has attempted to spoof us
	 */
	syslog(LOG_NOTICE, "rcmd: address %s not listed for host %s",
	    h1, res->ai_canonname ? res->ai_canonname : remotehost);
	freeaddrinfo(res);
	return (NULL);
}
