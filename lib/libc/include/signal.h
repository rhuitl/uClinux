/* Copyright (C) 1991, 1992, 1993, 1994 Free Software Foundation, Inc.
This file is part of the GNU C Library.

The GNU C Library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

The GNU C Library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the, 1992 Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

/*
 *	ANSI Standard: 4.7 SIGNAL HANDLING <signal.h>
 */

#ifndef _SIGNAL_H
#define _SIGNAL_H

#include <features.h>
#include <sys/types.h>
#include <bits/signal.h>

#ifndef SIGCLD
#define SIGCLD		SIGCHLD
#endif

/* SVR4 */
#ifndef SA_RESETHAND
#define SA_RESETHAND SA_ONESHOT
#endif

/* SVR4 */
#ifndef SA_NODEFER
#define SA_NODEFER SA_NOMASK
#endif

typedef int sig_atomic_t;

typedef __sighandler_t	SignalHandler;

#ifndef BADSIG
#define BADSIG		SIG_ERR
#endif

/* The Interviews version also has these ... */

#define SignalBad	((SignalHandler)-1)
#define SignalDefault	((SignalHandler)0)
#define SignalIgnore	((SignalHandler)1)

__BEGIN_DECLS

extern __const char * __const sys_siglist[];
extern __const char * __const _sys_siglist[];

extern __sighandler_t
		signal __P ((int __sig, __sighandler_t));
extern __sighandler_t
		__signal __P ((int __sig, __sighandler_t, int flags));
extern int	raise __P ((int __sig));
extern int	__kill __P ((pid_t __pid, int __sig));
extern int	kill __P ((pid_t __pid, int __sig));
extern int	killpg __P ((int __pgrp, int __sig));
extern int	sigaddset __P ((sigset_t *__mask, int __sig));
extern int	sigdelset __P ((sigset_t *__mask, int __sig));
extern int	sigemptyset __P ((sigset_t *__mask));
extern int	sigfillset __P ((sigset_t *__mask));
extern int	sigismember __P ((__const sigset_t *__mask, int __sig));
extern int	sigpending __P ((sigset_t *__set));

extern int	__sigprocmask __P ((int __how, __const sigset_t *__set,
			sigset_t *__oldset));
extern int	sigprocmask __P ((int __how, __const sigset_t *__set,
			sigset_t *__oldset));

extern int	sigsuspend __P ((__const sigset_t *sigmask));

extern int	__sigaction __P ((int __sig, struct sigaction *__act,
			struct sigaction *__oldact));
extern int	sigaction __P ((int __sig, struct sigaction *__act,
			struct sigaction *__oldact));

#define __sigemptyset(set)	((*(set) = 0L), 0)
#define __sigfillset(set)       ((*(set) = -1L), 0)
#define __sigaddset(set, sig)   ((*(set) |= __sigmask (sig)), 0)
#define __sigdelset(set, sig)   ((*(set) &= ~__sigmask (sig)), 0)
#define __sigismember(set, sig) ((*(set) & __sigmask (sig)) ? 1 : 0)


#if 1
#define sigemptyset	__sigemptyset
#define sigfillset	__sigfillset

/* We don't do that any more since it causes problems due to
 * "sig" > _NSIG and "sig" < 1. It isn't worth the touble to make
 * them inline and static. Use __sigxxxxx if you want speed with
 * correct "sig".
 */
#if 1
#define sigaddset	__sigaddset
#define sigdelset	__sigdelset
#define sigismember	__sigismember
#endif

#endif


/* Return a mask that includes SIG only.  */
#ifndef __sigmask
#define __sigmask(sig)	(1 << ((sig) - 1))
#endif

extern int __sigsetmask __P ((int __mask));
extern int __siggetmask __P ((void));
extern int __sigblock __P ((int __mask));
extern int __sigpause __P ((int __mask));

#ifdef  __USE_SVID
/* SVID names for the same things.  */
extern __sighandler_t ssignal __P ((int __sig, __sighandler_t __handler));
extern int gsignal __P ((int __sig));

#endif /* Use SVID.  */
 
/* BSD */
#ifdef __USE_BSD
#define sigmask		__sigmask

extern int	sigblock __P ((int __mask));
extern int	sigpause __P ((int __mask));
extern int	sigsetmask __P ((int __mask));
extern int	siggetmask __P ((void));
extern void	psignal __P ((int __sig, __const char *__str));

extern int	siginterrupt __P ((int __sig, int __flag));

/* The `sig' bit is set if the interrupt on it
 * is enabled via siginterrupt (). */
extern sigset_t _sigintr;

#endif  /* Use BSD.  */

#ifdef __USE_BSD_SIGNAL

extern __sighandler_t
		__bsd_signal __P ((int __sig, __sighandler_t));
#define signal	__bsd_signal

#endif	/* __USE_BSD_SIGNAL */

__END_DECLS

#if _MIT_POSIX_THREADS
#define __SIGFILLSET		0xffffffff
#define __SIGEMPTYSET		0
#define __SIGADDSET(s,n)	((*s) |= (1 << ((n) - 1)))
#define __SIGDELSET(s,n)	((*s) &= ~(1 << ((n) - 1)))
#define __SIGISMEMBER(s,n)	((*s) & (1 << ((n) - 1)))
#endif

#endif /* _SIGNAL_H */
