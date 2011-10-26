/*
 * Copyright (c) 1989 Regents of the University of California.
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

#ifndef EMBED
/*
 * From: @(#)global.c	5.2 (Berkeley) 6/1/90
 */
char global_rcsid[] = 
  "$Id: global.c,v 1.2 2003-07-21 03:11:25 davidm Exp $";
#endif

/*
 * Allocate global variables.  
 */

#include "defs.h"
#include "ext.h"

/*
 * Telnet server variable declarations
 */
#define extern
extern char	options[256];
extern char	do_dont_resp[256];
extern char	will_wont_resp[256];
extern int	linemode;	/* linemode on/off */
#ifdef	LINEMODE
extern int	uselinemode;	/* what linemode to use (on/off) */
extern int	editmode;	/* edit modes in use */
extern int	useeditmode;	/* edit modes to use */
extern int	alwayslinemode;	/* command line option */
# ifdef	KLUDGELINEMODE
extern int	lmodetype;	/* Client support for linemode */
# endif	/* KLUDGELINEMODE */
#endif	/* LINEMODE */
extern int	flowmode;	/* current flow control state */
#ifdef DIAGNOSTICS
extern int	diagnostic;	/* telnet diagnostic capabilities */
#endif /* DIAGNOSTICS */
#ifdef BFTPDAEMON
extern int	bftpd;		/* behave as bftp daemon */
#endif /* BFTPDAEMON */
#if	defined(SecurID)
extern int	require_SecurID;
#endif

extern slcfun	slctab[NSLC + 1];	/* slc mapping table */

extern char	*terminaltype;

/*
 * I/O data buffers, pointers, and counters.
 */
extern char	ptyobuf[BUFSIZ+NETSLOP], *pfrontp, *pbackp;

extern char	netibuf[BUFSIZ], *netip;

extern char	netobuf[BUFSIZ+NETSLOP], *nfrontp, *nbackp;
extern char	*neturg;		/* one past last bye of urgent data */

extern int	pcc, ncc;

#if defined(CRAY2) && defined(UNICOS5)
extern int unpcc;  /* characters left unprocessed by CRAY-2 terminal routine */
extern char *unptyip;  /* pointer to remaining characters in buffer */
#endif

extern int	pty, net;
extern int	SYNCHing;		/* we are in TELNET SYNCH mode */

struct _clocks clocks;
