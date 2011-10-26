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
 * From: @(#)sys_term.c	5.16 (Berkeley) 3/22/91
 */
char st_rcsid[] = 
  "$Id: sys_term.c,v 1.8 2004-12-06 22:35:28 davidm Exp $";
#endif

#include "telnetd.h"
#include "pathnames.h"
#include "logout.h"
#include "logwtmp.h"

#if defined(AUTHENTICATE)
#include <libtelnet/auth.h>
#endif

#ifndef __UC_LIBC__
#define USE_OPENPTY 1
#endif
#if defined(CONFIG_USER_TELNETD_DOES_NOT_USE_OPENPTY)
#undef USE_OPENPTY
#endif
//#define DEVFS 1
#ifdef USE_OPENPTY
#include <pty.h>
#endif

#ifdef NEWINIT
#include <initreq.h>

#else /* NEWINIT*/
#include <utmp.h>
struct utmp wtmp;

#ifndef CRAY
#ifndef _PATH_WTMP
#define _PATH_WTMP  "/usr/adm/wtmp"
#endif
#ifndef _PATH_UTMP
#define _PATH_UTMP  "/etc/utmp"
#endif

char wtmpf[] = _PATH_WTMP;
#ifndef __linux__
char utmpf[] = _PATH_UTMP;
#endif

#else /* CRAY */
char wtmpf[] = "/etc/wtmp";
#include <tmpdir.h>
#include <sys/wait.h>
#endif	/* CRAY */

#endif	/* NEWINIT */

#define SCPYN(a, b)	(void) strncpy(a, b, sizeof(a))
#define SCMPN(a, b)	strncmp(a, b, sizeof(a))

#ifdef STREAMS
#include <sys/stream.h>
#endif

#ifdef t_erase
#undef t_erase
#undef t_kill
#undef t_intrc
#undef t_quitc
#undef t_startc
#undef t_stopc
#undef t_eofc
#undef t_brkc
#undef t_suspc
#undef t_dsuspc
#undef t_rprntc
#undef t_flushc
#undef t_werasc
#undef t_lnextc
#endif

#if defined(UNICOS5) && defined(CRAY2) && !defined(EXTPROC)
#define EXTPROC 0400
#endif

#ifndef	USE_TERMIO
struct termbuf {
    struct sgttyb sg;
    struct tchars tc;
    struct ltchars ltc;
    int state;
    int lflags;
} termbuf, termbuf2;
#define	cfsetospeed(tp, val)	(tp)->sg.sg_ospeed = (val)
#define	cfsetispeed(tp, val)	(tp)->sg.sg_ispeed = (val)
#define	cfgetospeed(tp)		(tp)->sg.sg_ospeed
#define	cfgetispeed(tp)		(tp)->sg.sg_ispeed

#else	/* USE_TERMIO */

#ifdef SYSV_TERMIO
# define termios termio
#endif

#ifndef TCSANOW

#if defined(TCSETS)
#define	TCSANOW		TCSETS
#define	TCSADRAIN	TCSETSW
#define	tcgetattr(f, t)	ioctl(f, TCGETS, (char *)t)

#elif defined(TCSETA)
#define	TCSANOW		TCSETA
#define	TCSADRAIN	TCSETAW
#define	tcgetattr(f, t)	ioctl(f, TCGETA, (char *)t)

#else
#define	TCSANOW		TIOCSETA
#define	TCSADRAIN	TIOCSETAW
#define	tcgetattr(f, t)	ioctl(f, TIOCGETA, (char *)t)
#endif

#define	tcsetattr(f, a, t)	ioctl(f, a, t)
#define	cfsetospeed(tp, val)	(tp)->c_cflag &= ~CBAUD; \
					(tp)->c_cflag |= (val)
#define	cfgetospeed(tp)		((tp)->c_cflag & CBAUD)

#ifdef CIBAUD
#define	cfsetispeed(tp, val)	(tp)->c_cflag &= ~CIBAUD; \
				(tp)->c_cflag |= ((val)<<IBSHIFT)
#define	cfgetispeed(tp)		(((tp)->c_cflag & CIBAUD)>>IBSHIFT)

#else
#define	cfsetispeed(tp, val)	(tp)->c_cflag &= ~CBAUD; \
				(tp)->c_cflag |= (val)
#define	cfgetispeed(tp)		((tp)->c_cflag & CBAUD)
#endif

#endif /* TCSANOW */

struct termios termbuf, termbuf2;	/* pty control structure */
#endif	/* USE_TERMIO */

#ifndef USE_OPENPTY
static int cleanopen(char *_line);
#endif

/*
 * init_termbuf()
 * copy_termbuf(cp)
 * set_termbuf()
 *
 * These three routines are used to get and set the "termbuf" structure
 * to and from the kernel.  init_termbuf() gets the current settings.
 * copy_termbuf() hands in a new "termbuf" to write to the kernel, and
 * set_termbuf() writes the structure into the kernel.
 */

void init_termbuf(void) {
#ifndef	USE_TERMIO
    ioctl(pty, TIOCGETP, (char *)&termbuf.sg);
    ioctl(pty, TIOCGETC, (char *)&termbuf.tc);
    ioctl(pty, TIOCGLTC, (char *)&termbuf.ltc);
#ifdef TIOCGSTATE
    ioctl(pty, TIOCGSTATE, (char *)&termbuf.state);
#endif
#else
    tcgetattr(pty, &termbuf);
#endif
    termbuf2 = termbuf;
}

#if defined(LINEMODE) && defined(TIOCPKT_IOCTL)
void copy_termbuf(char *cp, int len) {
    if (len > sizeof(termbuf)) len = sizeof(termbuf);
    bcopy(cp, (char *)&termbuf, len);
    termbuf2 = termbuf;
}
#endif /* defined(LINEMODE) && defined(TIOCPKT_IOCTL) */

void set_termbuf(void) {
    /*
     * Only make the necessary changes.
     */
#ifndef	USE_TERMIO
    if (bcmp((char *)&termbuf.sg, (char *)&termbuf2.sg, sizeof(termbuf.sg)))
	(void) ioctl(pty, TIOCSETN, (char *)&termbuf.sg);
    if (bcmp((char *)&termbuf.tc, (char *)&termbuf2.tc, sizeof(termbuf.tc)))
	(void) ioctl(pty, TIOCSETC, (char *)&termbuf.tc);
    if (bcmp((char *)&termbuf.ltc, (char *)&termbuf2.ltc, sizeof(termbuf.ltc)))
	(void) ioctl(pty, TIOCSLTC, (char *)&termbuf.ltc);
    if (termbuf.lflags != termbuf2.lflags)
	(void) ioctl(pty, TIOCLSET, (char *)&termbuf.lflags);

#else /* USE_TERMIO */
    if (memcmp((char *)&termbuf, (char *)&termbuf2, sizeof(termbuf))) {
	tcsetattr(pty, TCSANOW, &termbuf);
    }
#if defined(CRAY2) && defined(UNCIOS5)
	needtermstat = 1;
#endif
#endif	/* USE_TERMIO */
}


/*
 * spcset(func, valp, valpp)
 *
 * This function takes various special characters (func), and
 * sets *valp to the current value of that character, and
 * *valpp to point to where in the "termbuf" structure that
 * value is kept.
 *
 * It returns the SLC_ level of support for this function.
 */

#ifndef	USE_TERMIO
int spcset(int func, cc_t *valp, cc_t **valpp) {
    switch(func) {
    case SLC_EOF:
	*valp = termbuf.tc.t_eofc;
	*valpp = (cc_t *)&termbuf.tc.t_eofc;
	return(SLC_VARIABLE);
    case SLC_EC:
	*valp = termbuf.sg.sg_erase;
	*valpp = (cc_t *)&termbuf.sg.sg_erase;
	return(SLC_VARIABLE);
    case SLC_EL:
	*valp = termbuf.sg.sg_kill;
	*valpp = (cc_t *)&termbuf.sg.sg_kill;
	return(SLC_VARIABLE);
    case SLC_IP:
	*valp = termbuf.tc.t_intrc;
	*valpp = (cc_t *)&termbuf.tc.t_intrc;
	return(SLC_VARIABLE|SLC_FLUSHIN|SLC_FLUSHOUT);
    case SLC_ABORT:
	*valp = termbuf.tc.t_quitc;
	*valpp = (cc_t *)&termbuf.tc.t_quitc;
	return(SLC_VARIABLE|SLC_FLUSHIN|SLC_FLUSHOUT);
    case SLC_XON:
	*valp = termbuf.tc.t_startc;
	*valpp = (cc_t *)&termbuf.tc.t_startc;
	return(SLC_VARIABLE);
    case SLC_XOFF:
	*valp = termbuf.tc.t_stopc;
	*valpp = (cc_t *)&termbuf.tc.t_stopc;
	return(SLC_VARIABLE);
    case SLC_AO:
	*valp = termbuf.ltc.t_flushc;
	*valpp = (cc_t *)&termbuf.ltc.t_flushc;
	return(SLC_VARIABLE);
    case SLC_SUSP:
	*valp = termbuf.ltc.t_suspc;
	*valpp = (cc_t *)&termbuf.ltc.t_suspc;
	return(SLC_VARIABLE);
    case SLC_EW:
	*valp = termbuf.ltc.t_werasc;
	*valpp = (cc_t *)&termbuf.ltc.t_werasc;
	return(SLC_VARIABLE);
    case SLC_RP:
	*valp = termbuf.ltc.t_rprntc;
	*valpp = (cc_t *)&termbuf.ltc.t_rprntc;
	return(SLC_VARIABLE);
    case SLC_LNEXT:
	*valp = termbuf.ltc.t_lnextc;
	*valpp = (cc_t *)&termbuf.ltc.t_lnextc;
	return(SLC_VARIABLE);
    case SLC_FORW1:
	*valp = termbuf.tc.t_brkc;
	*valpp = (cc_t *)&termbuf.ltc.t_lnextc;
	return(SLC_VARIABLE);
    case SLC_BRK:
    case SLC_SYNCH:
    case SLC_AYT:
    case SLC_EOR:
	*valp = (cc_t)0;
	*valpp = (cc_t *)0;
	return(SLC_DEFAULT);
    default:
	*valp = (cc_t)0;
	*valpp = (cc_t *)0;
	return(SLC_NOSUPPORT);
    }
}

#else	/* USE_TERMIO */

int spcset(int func, cc_t *valp, cc_t **valpp) {

#define	setval(a, b)	*valp = termbuf.c_cc[a]; \
			*valpp = &termbuf.c_cc[a]; \
			return(b);
#define	defval(a) *valp = ((cc_t)a); *valpp = (cc_t *)0; return(SLC_DEFAULT);

    switch(func) {
    case SLC_EOF:
	setval(VEOF, SLC_VARIABLE);
    case SLC_EC:
	setval(VERASE, SLC_VARIABLE);
    case SLC_EL:
	setval(VKILL, SLC_VARIABLE);
    case SLC_IP:
	setval(VINTR, SLC_VARIABLE|SLC_FLUSHIN|SLC_FLUSHOUT);
    case SLC_ABORT:
	setval(VQUIT, SLC_VARIABLE|SLC_FLUSHIN|SLC_FLUSHOUT);
    case SLC_XON:
#ifdef VSTART
	setval(VSTART, SLC_VARIABLE);
#else
	defval(0x13);
#endif
    case SLC_XOFF:
#ifdef	VSTOP
	setval(VSTOP, SLC_VARIABLE);
#else
	defval(0x11);
#endif
    case SLC_EW:
#ifdef	VWERASE
	setval(VWERASE, SLC_VARIABLE);
#else
	defval(0);
#endif
    case SLC_RP:
#ifdef	VREPRINT
	setval(VREPRINT, SLC_VARIABLE);
#else
	defval(0);
#endif
    case SLC_LNEXT:
#ifdef	VLNEXT
	setval(VLNEXT, SLC_VARIABLE);
#else
	defval(0);
#endif
    case SLC_AO:
#if	!defined(VDISCARD) && defined(VFLUSHO)
# define VDISCARD VFLUSHO
#endif
#ifdef	VDISCARD
	setval(VDISCARD, SLC_VARIABLE|SLC_FLUSHOUT);
#else
	defval(0);
#endif
    case SLC_SUSP:
#ifdef	VSUSP
	setval(VSUSP, SLC_VARIABLE|SLC_FLUSHIN);
#else
	defval(0);
#endif
#ifdef	VEOL
    case SLC_FORW1:
	setval(VEOL, SLC_VARIABLE);
#endif
#ifdef	VEOL2
    case SLC_FORW2:
	setval(VEOL2, SLC_VARIABLE);
#endif
    case SLC_AYT:
#ifdef	VSTATUS
	setval(VSTATUS, SLC_VARIABLE);
#else
	defval(0);
#endif
	
    case SLC_BRK:
    case SLC_SYNCH:
    case SLC_EOR:
	defval(0);
	
    default:
	*valp = 0;
	*valpp = 0;
	return(SLC_NOSUPPORT);
    }
}
#endif	/* USE_TERMIO */

#ifdef CRAY
/*
 * getnpty()
 *
 * Return the number of pty's configured into the system.
 */
int getnpty(void) {
#ifdef _SC_CRAY_NPTY
    int numptys;
    if ((numptys = sysconf(_SC_CRAY_NPTY)) != -1) return numptys;
    else
#endif /* _SC_CRAY_NPTY */
        return 128;
}
#endif /* CRAY */

#ifndef	convex
/*
 * getpty()
 *
 * Allocate a pty.  As a side effect, the external character
 * array "line" contains the name of the slave side.
 *
 * Returns the file descriptor of the opened pty.
 */
char *line = 0;

int ptyslavefd = -1;

#ifdef	CRAY
char *myline = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
#endif	/* CRAY */

int getpty(void) {
#ifdef USE_OPENPTY
	int ptymasterfd;
	if (openpty(&ptymasterfd, &ptyslavefd, line, NULL, NULL))
		return -1;
	return ptymasterfd;

#else /* ! USE_OPENPTY */

    int p;
#ifndef CRAY

#ifndef DEVFS
    char *p1, *p2;
    int i,j;
#else
    int npty;
#endif

    static char Xline[] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    if (!line)
        line = Xline;

#ifndef DEVFS

    sprintf(line, "/dev/ptyXX");
    p1 = &line[8];
    p2 = &line[9];

    for (i = 0; i < 16; i++) {
	struct stat stb;

	*p1 = "pqrstuvwxyzabcde"[i];
	*p2 = '0';
	if (stat(line, &stb) < 0)
	    continue;
	for (j = 0; j < 16; j++) {
	    *p2 = "0123456789abcdef"[j];
	    p = open(line, 2);
	    if (p > 0) {
		line[5] = 't';
		return(p);
	    }
	}
    }

#else /* DEVFS */

	for (npty = 0; npty <= 255; npty++) {
          sprintf(line, "/dev/pty/m%d", npty);
          p = open(line, 2);
          if (p >= 0) 
	  {
		line[9] = 's';
	 	return(p); 
	  } 	
        }

#endif /* DEVFS */

#else	/* CRAY */
    int npty;
    extern lowpty, highpty;
    struct stat sb;
    
    for (npty = lowpty; npty <= highpty; npty++) {
	(void) sprintf(myline, "/dev/pty/%03d", npty);
	p = open(myline, 2);
	if (p < 0) continue;
	(void) sprintf(line, "/dev/ttyp%03d", npty);
	/*
	 * Here are some shenanigans to make sure that there
	 * are no listeners lurking on the line.
	 */
	if (stat(line, &sb) < 0) {
	    (void) close(p);
	    continue;
	}
	if(sb.st_uid || sb.st_gid || sb.st_mode != 0600) {
	    chown(line, 0, 0);
	    chmod(line, 0600);
	    (void)close(p);
	    p = open(myline, 2);
	    if (p < 0)
		continue;
	}
	/*
	 * Now it should be safe...check for accessability.
	 */
	if (access(line, 6) == 0)
	    return(p);
	else {
	    /* no tty side to pty so skip it */
	    (void) close(p);
	}
    }
#endif	/* CRAY */
    return(-1);
#endif /* USE_OPENPTY */
}
#endif	/* convex */

#ifdef	LINEMODE
/*
 * tty_flowmode()	Find out if flow control is enabled or disabled.
 * tty_linemode()	Find out if linemode (external processing) is enabled.
 * tty_setlinemod(on)	Turn on/off linemode.
 * tty_isecho()		Find out if echoing is turned on.
 * tty_setecho(on)	Enable/disable character echoing.
 * tty_israw()		Find out if terminal is in RAW mode.
 * tty_binaryin(on)	Turn on/off BINARY on input.
 * tty_binaryout(on)	Turn on/off BINARY on output.
 * tty_isediting()	Find out if line editing is enabled.
 * tty_istrapsig()	Find out if signal trapping is enabled.
 * tty_setedit(on)	Turn on/off line editing.
 * tty_setsig(on)	Turn on/off signal trapping.
 * tty_issofttab()	Find out if tab expansion is enabled.
 * tty_setsofttab(on)	Turn on/off soft tab expansion.
 * tty_islitecho()	Find out if typed control chars are echoed literally
 * tty_setlitecho()	Turn on/off literal echo of control chars
 * tty_tspeed(val)	Set transmit speed to val.
 * tty_rspeed(val)	Set receive speed to val.
 */

int tty_flowmode(void) {
#ifndef USE_TERMIO
    return(((termbuf.tc.t_startc) > 0 && (termbuf.tc.t_stopc) > 0) ? 1 : 0);
#else
    return(termbuf.c_iflag & IXON ? 1 : 0);
#endif
}

#ifdef convex
static int linestate;
#endif

int tty_linemode(void) {
#ifndef convex
#ifndef	USE_TERMIO
    return(termbuf.state & TS_EXTPROC);
#else
    return(termbuf.c_lflag & EXTPROC);
#endif
#else
    return(linestate);
#endif
}

void tty_setlinemode(int on) {
#ifdef TIOCEXT
# ifndef convex
    set_termbuf();
# else
    linestate = on;
# endif
    ioctl(pty, TIOCEXT, (char *)&on);
# ifndef convex
    init_termbuf();
# endif
#else	/* !TIOCEXT */
# ifdef	EXTPROC
    if (on) termbuf.c_lflag |= EXTPROC;
    else termbuf.c_lflag &= ~EXTPROC;
# endif
#endif	/* TIOCEXT */
}

int tty_isecho(void) {
#ifndef USE_TERMIO
    return (termbuf.sg.sg_flags & ECHO);
#else
    return (termbuf.c_lflag & ECHO);
#endif
}
#endif	/* LINEMODE */

void tty_setecho(int on) {
#ifndef	USE_TERMIO
    if (on) termbuf.sg.sg_flags |= ECHO|CRMOD;
    else termbuf.sg.sg_flags &= ~(ECHO|CRMOD);
#else
    if (on) termbuf.c_lflag |= ECHO;
    else termbuf.c_lflag &= ~ECHO;
#endif
}

#if defined(LINEMODE) && defined(KLUDGELINEMODE)
int tty_israw(void) {
#ifndef USE_TERMIO
    return(termbuf.sg.sg_flags & RAW);
#else
    return(!(termbuf.c_lflag & ICANON));
#endif
}
#endif	/* defined(LINEMODE) && defined(KLUDGELINEMODE) */

void tty_binaryin(int on) {
#ifndef	USE_TERMIO
    if (on) termbuf.lflags |= LPASS8;
    else termbuf.lflags &= ~LPASS8;
#else
    if (on) {
	termbuf.c_iflag &= ~ISTRIP;
    }
    else {
	termbuf.c_iflag |= ISTRIP;
    }
#endif
}

void tty_binaryout(int on) {
#ifndef	USE_TERMIO
    if (on) termbuf.lflags |= LLITOUT;
    else termbuf.lflags &= ~LLITOUT;
#else
    if (on) {
	termbuf.c_cflag &= ~(CSIZE|PARENB);
	termbuf.c_cflag |= CS8;
	termbuf.c_oflag &= ~OPOST;
    } 
    else {
	termbuf.c_cflag &= ~CSIZE;
	termbuf.c_cflag |= CS7|PARENB;
	termbuf.c_oflag |= OPOST;
    }
#endif
}

int tty_isbinaryin(void) {
#ifndef	USE_TERMIO
    return(termbuf.lflags & LPASS8);
#else
    return(!(termbuf.c_iflag & ISTRIP));
#endif
}

int tty_isbinaryout(void) {
#ifndef	USE_TERMIO
    return(termbuf.lflags & LLITOUT);
#else
    return(!(termbuf.c_oflag&OPOST));
#endif
}

#ifdef	LINEMODE
int tty_isediting(void) {
#ifndef USE_TERMIO
    return(!(termbuf.sg.sg_flags & (CBREAK|RAW)));
#else
    return(termbuf.c_lflag & ICANON);
#endif
}

int tty_istrapsig(void) {
#ifndef USE_TERMIO
    return(!(termbuf.sg.sg_flags&RAW));
#else
    return(termbuf.c_lflag & ISIG);
#endif
}

void tty_setedit(int on) {
#ifndef USE_TERMIO
    if (on) termbuf.sg.sg_flags &= ~CBREAK;
    else termbuf.sg.sg_flags |= CBREAK;
#else
    if (on) termbuf.c_lflag |= ICANON;
    else termbuf.c_lflag &= ~ICANON;
#endif
}

void tty_setsig(int on) {
#ifndef	USE_TERMIO
    (void)on;
#else
    if (on) termbuf.c_lflag |= ISIG;
    else termbuf.c_lflag &= ~ISIG;
#endif
}
#endif	/* LINEMODE */

int tty_issofttab(void) {
#ifndef	USE_TERMIO
    return (termbuf.sg.sg_flags & XTABS);
#else
#ifdef OXTABS
    return (termbuf.c_oflag & OXTABS);
#endif
#ifdef TABDLY
    return ((termbuf.c_oflag & TABDLY) == TAB3);
#endif
#endif
}

void tty_setsofttab(int on) {
#ifndef	USE_TERMIO
    if (on) termbuf.sg.sg_flags |= XTABS;
    else termbuf.sg.sg_flags &= ~XTABS;
#else
    if (on) {
# ifdef	OXTABS
	termbuf.c_oflag |= OXTABS;
# endif
# ifdef	TABDLY
	termbuf.c_oflag &= ~TABDLY;
	termbuf.c_oflag |= TAB3;
# endif
    } 
    else {
# ifdef	OXTABS
	termbuf.c_oflag &= ~OXTABS;
# endif
# ifdef	TABDLY
	termbuf.c_oflag &= ~TABDLY;
	termbuf.c_oflag |= TAB0;
# endif
    }
#endif
}

int tty_islitecho(void) {
#ifndef	USE_TERMIO
    return (!(termbuf.lflags & LCTLECH));
#else
# ifdef	ECHOCTL
    return (!(termbuf.c_lflag & ECHOCTL));
# endif
# ifdef	TCTLECH
    return (!(termbuf.c_lflag & TCTLECH));
# endif
# if !defined(ECHOCTL) && !defined(TCTLECH)
    return 0;	/* assumes ctl chars are echoed '^x' */
# endif
#endif
}

void tty_setlitecho(int on) {
#ifndef	USE_TERMIO
    if (on) termbuf.lflags &= ~LCTLECH;
    else termbuf.lflags |= LCTLECH;
#else
# ifdef	ECHOCTL
    if (on) termbuf.c_lflag &= ~ECHOCTL;
    else termbuf.c_lflag |= ECHOCTL;
# endif
# ifdef	TCTLECH
    if (on) termbuf.c_lflag &= ~TCTLECH;
    else termbuf.c_lflag |= TCTLECH;
# endif
#endif
}

int tty_iscrnl(void) {
#ifndef	USE_TERMIO
    return (termbuf.sg.sg_flags & CRMOD);
#else
    return (termbuf.c_iflag & ICRNL);
#endif
}

/*
 * A table of available terminal speeds
 */
struct termspeeds {
	int	speed;
	int	value;
} termspeeds[] = {
	{ 0,     B0 },    { 50,    B50 },   { 75,    B75 },
	{ 110,   B110 },  { 134,   B134 },  { 150,   B150 },
	{ 200,   B200 },  { 300,   B300 },  { 600,   B600 },
	{ 1200,  B1200 }, { 1800,  B1800 }, { 2400,  B2400 },
	{ 4800,  B4800 }, { 9600,  B9600 }, { 19200, B9600 },
	{ 38400, B9600 }, { -1,    B9600 }
};

void tty_tspeed(int val) {
    struct termspeeds *tp;
    for (tp = termspeeds; (tp->speed != -1) && (val > tp->speed); tp++);
    cfsetospeed(&termbuf, tp->value);
}

void tty_rspeed(int val) {
    struct termspeeds *tp;
    for (tp = termspeeds; (tp->speed != -1) && (val > tp->speed); tp++);
    cfsetispeed(&termbuf, tp->value);
}

#if defined(CRAY2) && defined(UNICOS5)
int tty_isnewmap(void) {
    return((termbuf.c_oflag & OPOST) && (termbuf.c_oflag & ONLCR) &&
	   !(termbuf.c_oflag & ONLRET));
}
#endif

#ifdef	CRAY
# ifndef NEWINIT
extern struct utmp wtmp;
extern char wtmpf[];
# else /* NEWINIT */
int gotalarm;

void nologinproc(int sig) {
    (void)sig;
    gotalarm++;
}
# endif	/* NEWINIT */
#endif /* CRAY */

#ifndef	NEWINIT
# ifdef	CRAY
extern void utmp_sig_init P((void));
extern void utmp_sig_reset P((void));
extern void utmp_sig_wait P((void));
extern void utmp_sig_notify P((int));
# endif
#endif

/*
 * getptyslave()
 *
 * Open the slave side of the pty, and do any initialization
 * that is necessary.  The return value is a file descriptor
 * for the slave side.
 */
#ifdef	TIOCGWINSZ
extern int def_row, def_col;
#endif
extern int def_tspeed, def_rspeed;

static int getptyslave(void) {
#ifdef USE_OPENPTY
	struct winsize ws;
	int t = ptyslavefd;

        init_termbuf();

	if (def_row || def_col) {
		memset((char *)&ws, 0, sizeof(ws));
		ws.ws_col = def_col;
		ws.ws_row = def_row;
		ioctl(t, TIOCSWINSZ, (char *)&ws);
	}

	set_termbuf();

	tty_rspeed((def_rspeed > 0) ? def_rspeed : 9600);
	tty_tspeed((def_tspeed > 0) ? def_tspeed : 9600);

	if (login_tty(t) == -1)
		fatalperror(net, "login_tty");
	if (net > 2)
		close(net);
	if (pty > 2)
		close(pty);

	return t;

#else /* ! USE_OPENPTY */

    register int t = -1;

#if !defined(CRAY) || !defined(NEWINIT)
# ifdef	LINEMODE
    int waslm;
# endif
# ifdef	TIOCGWINSZ
    struct winsize ws;
# endif
    /*
     * Opening the slave side may cause initilization of the
     * kernel tty structure.  We need remember the state of
     * 	if linemode was turned on
     *	terminal window size
     *	terminal speed
     * so that we can re-set them if we need to.
     */
# ifdef	LINEMODE
    waslm = tty_linemode();
# endif


    /*
     * Make sure that we don't have a controlling tty, and
     * that we are the session (process group) leader.
     */
# ifdef	TIOCNOTTY
    t = open(_PATH_TTY, O_RDWR);
    if (t >= 0) {
	ioctl(t, TIOCNOTTY, (char *)0);
	close(t);
    }
# endif


# ifdef	CRAY
    /*
     * Wait for our parent to get the utmp stuff to get done.
     */
    utmp_sig_wait();
# endif

    t = cleanopen(line);
    if (t < 0) fatalperror(net, line);

    /*
     * set up the tty modes as we like them to be.
     */
    init_termbuf();
# ifdef	TIOCGWINSZ
    if (def_row || def_col) {
	bzero((char *)&ws, sizeof(ws));
	ws.ws_col = def_col;
	ws.ws_row = def_row;
	ioctl(t, TIOCSWINSZ, (char *)&ws);
    }
# endif

    /*
     * Settings for sgtty based systems
     */
# ifndef	USE_TERMIO
    termbuf.sg.sg_flags |= CRMOD|ANYP|ECHO|XTABS;
# endif	/* USE_TERMIO */

    /*
     * Settings for UNICOS
     */
# ifdef	CRAY
    termbuf.c_oflag = OPOST|ONLCR|TAB3;
    termbuf.c_iflag = IGNPAR|ISTRIP|ICRNL|IXON;
    termbuf.c_lflag = ISIG|ICANON|ECHO|ECHOE|ECHOK;
    termbuf.c_cflag = EXTB|HUPCL|CS8;
# endif

    /*
     * Settings for all other termios/termio based
     * systems, other than 4.4BSD.  In 4.4BSD the
     * kernel does the initial terminal setup.
     */
# if defined(USE_TERMIO) && !defined(CRAY) && (BSD <= 43)
#  ifndef	OXTABS
#   define OXTABS	0
#  endif
    termbuf.c_lflag |= ECHO;
    termbuf.c_oflag |= ONLCR|OXTABS;
    termbuf.c_iflag |= ICRNL;
    termbuf.c_iflag &= ~IXOFF;
# endif /* defined(USE_TERMIO) && !defined(CRAY) && (BSD <= 43) */
    tty_rspeed((def_rspeed > 0) ? def_rspeed : 9600);
    tty_tspeed((def_tspeed > 0) ? def_tspeed : 9600);
# ifdef	LINEMODE
    if (waslm) tty_setlinemode(1);
# endif	/* LINEMODE */

    /*
     * Set the tty modes, and make this our controlling tty.
     */
    set_termbuf();
    if (login_tty(t) == -1) fatalperror(net, "login_tty");
#endif	/* !defined(CRAY) || !defined(NEWINIT) */
    if (net > 2) close(net);
    if (pty > 2) close(pty);
    return t;  /* ? was nothing here... */

#endif /* USE_OPENPTY */
}

#ifndef USE_OPENPTY

#if !defined(CRAY) || !defined(NEWINIT)
#ifndef	O_NOCTTY
#define	O_NOCTTY	0
#endif
/*
 * Open the specified slave side of the pty,
 * making sure that we have a clean tty.
 */
static int cleanopen(char *lyne) {
    register int t;

    /*
     * Make sure that other people can't open the
     * slave side of the connection.
     */
    chown(lyne, 0, 0);
    chmod(lyne, 0600);

# if !defined(CRAY) && (BSD > 43)
    revoke(lyne);
# endif
    t = open(lyne, O_RDWR|O_NOCTTY);
    if (t < 0) return(-1);

    /*
     * Hangup anybody else using this ttyp, then reopen it for
     * ourselves.
     */
# if !defined(__linux__)
    /* this looks buggy to me, our ctty is really a pty at this point */
# if !defined(CRAY) && (BSD <= 43)
    signal(SIGHUP, SIG_IGN);
    vhangup();
    signal(SIGHUP, SIG_DFL);
    t = open(lyne, O_RDWR|O_NOCTTY);
    if (t < 0) return(-1);
# endif
# endif
# if defined(CRAY) && defined(TCVHUP)
    {
	register int i;
	signal(SIGHUP, SIG_IGN);
	ioctl(t, TCVHUP, (char *)0);
	signal(SIGHUP, SIG_DFL);
	setpgrp();
	i = open(lyne, O_RDWR);
	if (i < 0) return(-1);
	close(t);
	t = i;
    }
# endif	/* defined(CRAY) && defined(TCVHUP) */
    return(t);
}
#endif	/* !defined(CRAY) || !defined(NEWINIT) */
#endif /* ! USE_OPENPTY */

#if BSD <= 43
int login_tty(int t) {
    if (setsid() < 0) fatalperror(net, "setsid()");
# ifdef	TIOCSCTTY
    if (ioctl(t, TIOCSCTTY, (char *)0) < 0) {
	fatalperror(net, "ioctl(sctty)");
    }
#  if defined(CRAY) && defined(SESS_CTTY)	/* SESS_CTTY is in param.h */
    /*
     * Close the hard fd to /dev/ttypXXX, and re-open through
     * the indirect /dev/tty interface.
     */
    close(t);
    if ((t = open("/dev/tty", O_RDWR)) < 0) {
	fatalperror(net, "open(/dev/tty)");
    }
#  endif
# else
    close(open(lyne, O_RDWR));
# endif
    if (t != 0) dup2(t, 0);
    if (t != 1) dup2(t, 1);
    if (t != 2) dup2(t, 2);
    if (t > 2) close(t);
    return 0;
}
#endif	/* BSD <= 43 */

#ifdef NEWINIT
char *gen_id = "fe";
#endif

/*
 * startslave(host)
 *
 * Given a hostname, do whatever
 * is necessary to startup the login process on the slave side of the pty.
 */

/* ARGSUSED */
void startslave(const char *host, int autologin, char *autoname) {
    int i;
#ifdef	NEWINIT
    extern char *ptyip;
    struct init_request request;
    void nologinproc();
    int n;
#endif	/* NEWINIT */

#if defined(AUTHENTICATE)
    if (!autoname || !autoname[0]) autologin = 0;
    if (autologin < auth_level) {
	fatal(net, "Authorization failed");
	exit(1);
    }
#endif

#ifndef	NEWINIT

    if ((i = vfork())) {
    	if (i<0)
	    fatalperror(net, "fork");
	/* parent */
	signal(SIGHUP,SIG_IGN);
    } else {
	/* child */
	signal(SIGHUP,SIG_IGN);
	getptyslave();
	start_login(host, autologin, autoname);
	_exit(0);
	/*NOTREACHED*/
    }
#else	/* NEWINIT */

    /*
     * Init will start up login process if we ask nicely.  We only wait
     * for it to start up and begin normal telnet operation.
     */
    if ((i = open(INIT_FIFO, O_WRONLY)) < 0) {
	char tbuf[128];
	sprintf(tbuf, "Can't open %s\n", INIT_FIFO);
	fatalperror(net, tbuf);
    }
    memset(&request, 0, sizeof(request));
    request.magic = INIT_MAGIC;
    SCPYN(request.gen_id, gen_id);
    SCPYN(request.tty_id, &line[8]);
    SCPYN(request.host, host);
    SCPYN(request.term_type, terminaltype ? terminaltype : "network");
#if !defined(UNICOS5)
    request.signal = SIGCLD;
    request.pid = getpid();
#endif
#ifdef BFTPDAEMON
    /*
     * Are we working as the bftp daemon?
     */
    if (bftpd) {
	SCPYN(request.exec_name, BFTPPATH);
    }
#endif /* BFTPDAEMON */
    if (write(i, (char *)&request, sizeof(request)) < 0) {
	char tbuf[128];
	sprintf(tbuf, "Can't write to %s\n", INIT_FIFO);
	fatalperror(net, tbuf);
    }
    close(i);
    signal(SIGALRM, nologinproc);
    for (i = 0; ; i++) {
	char tbuf[128];
	alarm(15);
	n = read(pty, ptyip, BUFSIZ);
	if (i == 3 || n >= 0 || !gotalarm) break;
	gotalarm = 0;
	sprintf(tbuf, "telnetd: waiting for /etc/init to start login process on %s\r\n", line);
	write(net, tbuf, strlen(tbuf));
    }
    if (n < 0 && gotalarm) fatal(net, "/etc/init didn't start login process");
    pcc += n;
    alarm(0);
    signal(SIGALRM, SIG_DFL);
    return;
#endif	/* NEWINIT */
}

char *envinit[3];

void init_env(void) {
#if 0
    char **envp;
    envp = envinit;
    if ((*envp = getenv("TZ"))!=NULL)
	*envp++ -= 3;
#ifdef	CRAY
    else *envp++ = "TZ=GMT0";
#endif
    *envp = 0;
    environ = envinit;
#endif
}

#ifndef	NEWINIT

/*
 * start_login(host)
 *
 * Assuming that we are now running as a child processes, this
 * function will turn us into the login process.
 */

void start_login(const char *host, int autologin, const char *name) {
#ifdef EMBED
	execlp("login", "login", "-h", host, NULL);
	execlp("sh", "sh", NULL);
#else 
	execlp("login", "login", "-t", NULL);
	execlp("sh", "sh", "-t", NULL);
#endif
}

#if 0
static const char **addarg(const char **, const char *);

void start_login(const char *host, int autologin, const char *name) {   
    const char **argv;
    (void)autologin;

    /*
     * -h : pass on name of host.
     *		WARNING:  -h is accepted by login if and only if
     *			getuid() == 0.
     * -p : don't clobber the environment (so terminal type stays set).
     *
     * -f : force this login, he has already been authenticated
     */
    argv = addarg(0, loginprg);
    argv = addarg(argv, "-h");
    argv = addarg(argv, host);
#if !defined(NO_LOGIN_P)
    argv = addarg(argv, "-p");
#endif
#ifdef BFTPDAEMON
    /*
     * Are we working as the bftp daemon?  If so, then ask login
     * to start bftp instead of shell.
     */
    if (bftpd) {
	argv = addarg(argv, "-e");
	argv = addarg(argv, BFTPPATH);
    } 
    else
#endif
    {
#if defined (SecurID)
	/*
	 * don't worry about the -f that might get sent.
	 * A -s is supposed to override it anyhow.
	 */
	if (require_SecurID) argv = addarg(argv, "-s");
#endif
	if (*name=='-') {
	    syslog(LOG_ERR, "Attempt to login with an option!");
	    name = "";
	}
#if defined (AUTHENTICATE)
	if (auth_level >= 0 && autologin == AUTH_VALID) {
# if !defined(NO_LOGIN_F)
	    argv = addarg(argv, "-f");
# endif
	    argv = addarg(argv, name);
	} 
	else
#endif
	{
	    if (getenv("USER")) {
		argv = addarg(argv, getenv("USER"));
		if (*getenv("USER") == '-') {
		    write(1,"I don't hear you!\r\n",19);
		    syslog(LOG_ERR,"Attempt to login with an option!");
		    exit(1);
		}
#if defined(CRAY) && defined(NO_LOGIN_P)
		{
		    register char **cpp;
		    for (cpp = environ; *cpp; cpp++)
			argv = addarg(argv, *cpp);
		}
#endif
	    }
	}
    }
    closelog();
    execv(loginprg, (char **) argv);

    syslog(LOG_ERR, "%s: %m\n", loginprg);
    fatalperror(net, loginprg);
}

static const char **addarg(const char **argv, const char *val) {
    const char **cpp;
    
    if (argv == NULL) {
	/*
	 * 10 entries, a leading length, and a null
	 */
	argv = malloc(sizeof(*argv) * 12);
	if (argv == NULL) return NULL;
	*argv++ = (char *)10;
	*argv = NULL;
    }
    for (cpp = argv; *cpp; cpp++);
    if (cpp == &argv[(int)argv[-1]]) {
	--argv;
	*argv = (char *)((int)(argv[0]) + 10);
	argv = realloc(argv, (int)(argv[0]) + 2);
	if (argv == NULL) return NULL;
	argv++;
	cpp = &argv[(int)argv[-1] - 10];
    }
    *cpp++ = val;
    *cpp = 0;
    return(argv);
}
#endif
#endif	/* NEWINIT */

/*
 * cleanup()
 *
 * This is the routine to call when we are all through, to
 * clean up anything that needs to be cleaned up.
 */
void cleanup(int sig) {
#ifndef	CRAY
# if (BSD > 43) || defined(convex) || defined(__linux__)
    char *p;
    (void)sig;

	if (line) {
    p = line + sizeof("/dev/") - 1;
    if (logout(p)) logwtmp(p, "", "");
#ifdef PARANOID_TTYS
    /*
     * dholland 16-Aug-96 chmod the tty when not in use
     * This will make it harder to attach unwanted stuff to it
     * (which is a security risk) but will break some programs.
     */
    chmod(line, 0600);
#else
    chmod(line, 0666);
#endif
    chown(line, 0, 0);
    *p = 'p';
    chmod(line, 0666);
    chown(line, 0, 0);
	}
    shutdown(net, 2);
    exit(1);
#else
    void rmut();

    rmut();
    vhangup();	/* XXX */
    shutdown(net, 2);
    exit(1);
# endif
#else	/* CRAY */
# ifdef	NEWINIT
    shutdown(net, 2);
    exit(1);
# else	/* NEWINIT */
    static int incleanup = 0;
    int t;

    /*
     * 1: Pick up the zombie, if we are being called
     *    as the signal handler.
     * 2: If we are a nested cleanup(), return.
     * 3: Try to clean up TMPDIR.
     * 4: Fill in utmp with shutdown of process.
     * 5: Close down the network and pty connections.
     * 6: Finish up the TMPDIR cleanup, if needed.
     */
    if (sig == SIGCHLD) {
	/*
	 * dholland 16-Aug-96 this was a busy loop
	 * theoretically the sleep shouldn't be reached anyway.
	 */
	while (waitpid(-1, 0, WNOHANG) > 0) sleep(1);
    }
    t = sigblock(sigmask(SIGCHLD));
    if (incleanup) {
	sigsetmask(t);
	return;
    }
    incleanup = 1;
    sigsetmask(t);

    t = cleantmp(&wtmp);
    setutent();	/* just to make sure */
	if (line)
    rmut(line);
    close(pty);
    shutdown(net, 2);
    if (t == 0) {
	cleantmp(&wtmp);
    }
    exit(1);
# endif	/* NEWINT */
#endif	/* CRAY */
}

#if defined(CRAY) && !defined(NEWINIT)
/*
 * _utmp_sig_rcv
 * utmp_sig_init
 * utmp_sig_wait
 *	These three functions are used to coordinate the handling of
 *	the utmp file between the server and the soon-to-be-login shell.
 *	The server actually creates the utmp structure, the child calls
 *	utmp_sig_wait(), until the server calls utmp_sig_notify() and
 *	signals the future-login shell to proceed.
 */
static int caught=0;		/* NZ when signal intercepted */
static void (*func)(int);	/* address of previous handler */

void _utmp_sig_rcv(int sig) {
    (void)sig;
    caught = 1;
    signal(SIGUSR1, func);
}

void utmp_sig_init(void) {
    /*
     * register signal handler for UTMP creation
     */
    if ((int)(func = signal(SIGUSR1, _utmp_sig_rcv)) == -1) {
	fatalperror(net, "telnetd/signal");
    }
}

void utmp_sig_reset(void) {
    signal(SIGUSR1, func);	/* reset handler to default */
}

void utmp_sig_wait(void) {
    /*
     * Wait for parent to write our utmp entry.
     */
    sigoff();
    while (caught == 0) {
	pause();	/* wait until we get a signal (sigon) */
	sigoff();	/* turn off signals while we check caught */
    }
    sigon();		/* turn on signals again */
}

void utmp_sig_notify(pid) {
    kill(pid, SIGUSR1);
}

static int gotsigjob = 0;

/*ARGSUSED*/
void sigjob(int sig) {
    int jid;
    struct jobtemp *jp;
    (void)sig;

    while ((jid = waitjob(NULL)) != -1) {
	if (jid == 0) return;
	gotsigjob++;
	jobend(jid, NULL, NULL);
    }
}

/*
 * Clean up the TMPDIR that login created.
 * The first time this is called we pick up the info
 * from the utmp.  If the job has already gone away,
 * then we'll clean up and be done.  If not, then
 * when this is called the second time it will wait
 * for the signal that the job is done.
 */
int cleantmp(struct utmp *wtp) {
    struct utmp *utp;
    static int first = 1;
    register int mask, omask, ret;
    extern struct utmp *getutid P((struct utmp *));

    mask = sigmask(WJSIGNAL);

    if (first == 0) {
	omask = sigblock(mask);
	while (gotsigjob == 0)
	    sigpause(omask);
	return(1);
    }
    first = 0;
    setutent();	/* just to make sure */
    
    utp = getutid(wtp);
	if (utp == 0) {
	    syslog(LOG_ERR, "Can't get /var/run/utmp entry to clean TMPDIR");
	    return -1;
	}
    /*
     * Nothing to clean up if the user shell was never started.
     */
    if (utp->ut_type != USER_PROCESS || utp->ut_jid == 0) return 1;

    /*
     * Block the WJSIGNAL while we are in jobend().
     */
    omask = sigblock(mask);
    ret = jobend(utp->ut_jid, utp->ut_tpath, utp->ut_user);
    sigsetmask(omask);
    return ret;
}

int jobend(int jid, char *path, char *user) {
    static int saved_jid = 0;
    static char saved_path[sizeof(wtmp.ut_tpath)+1];
    static char saved_user[sizeof(wtmp.ut_user)+1];

    if (path) {
	strncpy(saved_path, path, sizeof(wtmp.ut_tpath));
	strncpy(saved_user, user, sizeof(wtmp.ut_user));
	saved_path[sizeof(saved_path)] = '\0';
	saved_user[sizeof(saved_user)] = '\0';
    }
    if (saved_jid == 0) {
	saved_jid = jid;
	return(0);
    }
    cleantmpdir(jid, saved_path, saved_user);
    return(1);
}

/*
 * Fork a child process to clean up the TMPDIR
 */
int cleantmpdir(int jid, char *tpath, char *user) {
    switch(fork()) {
    case -1:
	syslog(LOG_ERR, "TMPDIR cleanup(%s): fork() failed: %m\n", tpath);
	break;
    case 0:
	execl(CLEANTMPCMD, CLEANTMPCMD, user, tpath, 0);
	syslog(LOG_ERR, "TMPDIR cleanup(%s): execl(%s) failed: %m\n",
	       tpath, CLEANTMPCMD);
	exit(1);
    default:
	/*
	 * Forget about child.  We will exit, and
	 * /etc/init will pick it up.
	 */
	break;
    }
}
#endif	/* defined(CRAY) && !defined(NEWINIT) */

/*
 * rmut()
 *
 * This is the function called by cleanup() to
 * remove the utmp entry for this person.
 */

#if	!defined(CRAY) && BSD <= 43 && !defined(__linux__)
void rmut(void) {
    int f;
    int found = 0;
    struct utmp *u, *utmp;
    int nutmp;
    struct stat statbf;

    f = open(utmpf, O_RDWR);
    if (f >= 0) {
	(void) fstat(f, &statbf);
	utmp = (struct utmp *)malloc((unsigned)statbf.st_size);
	if (!utmp) syslog(LOG_ERR, "utmp malloc failed");
	if (statbf.st_size && utmp) {
	    nutmp = read(f, (char *)utmp, (int)statbf.st_size);
	    nutmp /= sizeof(struct utmp);
		
	    for (u = utmp ; u < &utmp[nutmp] ; u++) {
		if (SCMPN(u->ut_line, line+5) ||
		    u->ut_name[0]==0)
		    continue;
		lseek(f, ((long)u)-((long)utmp), L_SET);
		SCPYN(u->ut_name, "");
		SCPYN(u->ut_host, "");
		time(&u->ut_time);
		write(f, (char *)u, sizeof(wtmp));
		found++;
	    }
	}
	close(f);
    }
    if (found) {
	f = open(wtmpf, O_WRONLY|O_APPEND);
	if (f >= 0) {
	    SCPYN(wtmp.ut_line, line+5);
	    SCPYN(wtmp.ut_name, "");
	    SCPYN(wtmp.ut_host, "");
	    time(&wtmp.ut_time);
	    write(f, (char *)&wtmp, sizeof(wtmp));
	    close(f);
	}
    }
    chmod(line, 0666);
    chown(line, 0, 0);
    line[strlen("/dev/")] = 'p';
    chmod(line, 0666);
    chown(line, 0, 0);
}  /* end of rmut */
#endif	/* CRAY */
