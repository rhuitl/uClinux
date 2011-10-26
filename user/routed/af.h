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
 *
 *	from: @(#)af.h	5.7 (Berkeley) 6/1/90
 *	from: @(#)af.h	8.1 (Berkeley) 6/5/93
 *	$Id: af.h,v 1.3 1996/11/25 16:36:17 dholland Exp $
 */

/*
 * Routing table management daemon.
 */

/*
 * Structure returned by af_hash routines.
 */
struct afhash {
	u_int	afh_hosthash;		/* host based hash */
	u_int	afh_nethash;		/* network based hash */
};

/*
 * Per address family routines.
 */
struct afswitch {
	void	(*af_hash)(struct sockaddr *, struct afhash *);			/* returns keys based on address */
	int	(*af_netmatch)(struct sockaddr *, struct sockaddr *);		/* verifies net # matching */
	void	(*af_output)(int, int, struct sockaddr *, int);			/* interprets address for sending */
	int	(*af_portmatch)(struct sockaddr *);				/* packet from some other router? */
	int	(*af_portcheck)(struct sockaddr *);				/* packet from privileged peer? */
	int	(*af_checkhost)(struct sockaddr *);				/* tells if address is valid */
	int	(*af_rtflags)(struct sockaddr *);				/* get flags for route (host or net) */
	int	(*af_sendroute)(struct rt_entry *, struct sockaddr *);		/* check bounds of subnet broadcast */
	void	(*af_canon)(struct sockaddr *);					/* canonicalize address for compares */
	char	*(*af_format)(struct sockaddr *, char *, size_t);		/* convert address to string */
};


extern struct	afswitch afswitch[];	/* table proper */
extern int	af_max;			/* number of entries in table */


