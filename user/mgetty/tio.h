#ident "$Id: tio.h,v 4.6 1999/10/23 21:56:58 gert Exp $ Copyright (c) 1993 Gert Doering"

#ifndef __TIO_H__
#define __TIO_H__

/* tio.h
 *
 * contains definitions / prototypes needed for tio.c
 *
 */

#ifdef NEXTSGTTY
# define BSD_SGTTY
# undef POSIX_TERMIOS
# undef SYSV_TERMIO
#endif

#if !defined( POSIX_TERMIOS ) && !defined( BSD_SGTTY ) && !defined( SYSV_TERMIO)
# if defined(linux) || defined(sunos4) || defined(_AIX) || defined(BSD) || \
     defined(SVR4) || defined(solaris2) || defined(m88k) || defined(M_UNIX) ||\
     defined(__sgi)
#  define POSIX_TERMIOS
# else
#  define SYSV_TERMIO
# endif
#endif

#ifdef SYSV_TERMIO

#undef POSIX_TERMIOS
#undef BSD_SGTTY
#include <termio.h>
typedef struct termio TIO;
#endif

#ifdef POSIX_TERMIOS
#undef BSD_SGTTY
#include <termios.h>
typedef struct termios TIO;
#endif

#ifdef BSD_SGTTY
#include <sgtty.h>
typedef struct sgttyb TIO;
#endif

/* on SCO and other SVR3 systems, the TIOCMGET calls are only available
 * with special drivers, like the digiboard drivers, or my hacked "FAS"
 */
#ifdef USE_FAS_TIOCMGET
# include <sys/fas.h>
#endif

/* make sure <sys/ioctl.h> gets included: contains TIOCM* definitions
 * on AIX, and ioctl() prototype on NeXT and Linux
 */
#if defined(_AIX) || defined(NeXT) || defined(linux)
# include <sys/ioctl.h>
#endif

/* define some types for gettydefs.c */

#ifdef SYSV_TERMIO

/* You may have to look at sys/termio.h to determine the type of the
 * c_?flag structure members.
 */
typedef unsigned short tioflag_t;

#define TIONCC NCC
#endif

#ifdef POSIX_TERMIOS
typedef tcflag_t tioflag_t;
#define TIONCC NCCS
#endif

#if defined(BSD_SGTTY) && defined(USE_GETTYDEFS)
#include "cannot use /etc/gettydefs with sgtty (yet?)"
#endif

/* SVR4 came up with a new method of setting h/w flow control */
/* unfortunately, it's broken in 4.2 and Solaris2, and not there in IRIX! */
#if defined(SVR4) && \
    !defined(SVR42) && !defined(solaris2) && !defined(sgi)
# define USE_TERMIOX
#endif

/* AIX 4.x has it as well, AIX 3.x has not, check with _AIX41 */
#if defined(_AIX) && defined(_AIX41) && !defined(USE_TERMIOX) 
# define USE_TERMIOX
#endif

/* if not defined in the default header files, #define some important things
 */
#ifdef _AIX
#include <sys/ttychars.h>
#endif
#ifdef _HPUX_SOURCE
# include <sys/modem.h>
#endif

#if	!defined(VSWTCH) && defined(VSWTC)
#define	VSWTCH	VSWTC
#endif

#ifndef _POSIX_VDISABLE
#define _POSIX_VDISABLE '\377'
#endif

/* default control chars */
#ifndef CESC
#define	CESC	'\\'
#endif
#ifndef CINTR
#define	CINTR	0177	/* DEL */
#endif
#ifndef CQUIT
#define	CQUIT	034	/* FS, cntl | */
#endif
#ifndef CERASE
#define	CERASE	'\b'	/* BS, nonstandard */
#endif
#ifndef CKILL
#define	CKILL	'\025'	/* NAK, nonstandard */
#endif
#ifndef CEOF
#define	CEOF	04	/* cntl d */
#endif
#ifndef CSTART
#define	CSTART	021	/* cntl q */
#endif
#ifndef CSTOP
#define	CSTOP	023	/* cntl s */
#endif
#ifndef CEOL
#define	CEOL	000	/* cntl j */
#endif

#ifdef CSWTCH
# undef CSWTCH		/* usually ^z, unwanted here */
#endif
#define CSWTCH	000	/* <undef> */

#ifndef CSUSP
# ifdef SVR42
#  define CSUSP 026	/* cntl z */
# else
#  define CSUSP _POSIX_VDISABLE		/* have only job control aware */
					/* shells use it */
# endif
#endif

/* the following are used only if the corresponding V... defines are */
/* available, and that's only on SVR42 (as far as I know) */
#ifndef CDSUSP
#define CDSUSP		025	/* cntl y */
#endif
#ifndef CRPRNT
#define CRPRNT		000	/* <undef> */
#endif
#ifndef CFLUSH
#define CFLUSH		000	/* <undef> */
#endif
#ifndef CWERASE
#define CWERASE		000	/* <undef> */
#endif
#ifndef CLNEXT
#define CLNEXT		000	/* <undef> */
#endif

/* queue selection flags (for tio_flush_queue) */
#define TIO_Q_IN	0x01		/* incoming data queue */
#define TIO_Q_OUT	0x02		/* outgoing data queue */
#define TIO_Q_BOTH	( TIO_Q_IN | TIO_Q_OUT )

/* RS232 line status flags */
/* system flags are used if available, otherwise we define our own */
#ifdef TIOCM_DTR
# define TIO_F_SYSTEM_DEFS
# define TIO_F_DTR TIOCM_DTR
# define TIO_F_DSR TIOCM_DSR
# define TIO_F_RTS TIOCM_RTS
# define TIO_F_CTS TIOCM_CTS
# define TIO_F_DCD TIOCM_CAR
# define TIO_F_RI  TIOCM_RNG
#else
# define TIO_F_DTR 0x001
# define TIO_F_DSR 0x002
# define TIO_F_RTS 0x004
# define TIO_F_CTS 0x008
# define TIO_F_DCD 0x010
# define TIO_F_RI  0x020
#endif

/* function prototypes */
int  tio_get _PROTO (( int fd, TIO *t ));
int  tio_set _PROTO (( int fd, TIO *t ));
int  tio_check_speed _PROTO (( int speed ));
int  tio_set_speed   _PROTO (( TIO *t, unsigned int speed ));
int  tio_get_speed   _PROTO (( TIO *t ));
void tio_mode_raw    _PROTO (( TIO *t ));
void tio_mode_cbreak _PROTO (( TIO *t ));
void tio_mode_sane   _PROTO (( TIO *t, int set_clocal_flag ));
void tio_default_cc  _PROTO (( TIO *t ));
void tio_map_cr      _PROTO (( TIO *t, int perform_crnl_mapping ));
void tio_map_uclc    _PROTO (( TIO *t, int perform_case_mapping ));
int  tio_set_flow_control  _PROTO(( int fd, TIO *t, int flowctrl_type ));
int  tio_set_flow_control2 _PROTO(( int fd, int flowctrl_type ));
void tio_carrier     _PROTO (( TIO *t, int carrier_sensitive ));
int  tio_toggle_dtr  _PROTO(( int fd, int msec_wait ));
int  tio_flush_queue _PROTO(( int fd, int queue ));
int  tio_flow        _PROTO(( int fd, int restart_output ));
int  tio_break       _PROTO(( int fd ));
int  tio_drain_output _PROTO(( int fd ));

int  tio_get_rs232_lines _PROTO(( int fd ));		/* get line status */
int  tio_set_rs232_lines _PROTO(( int fd, int do_dtr, int do_rts ));

#ifdef USE_GETTYDEFS
typedef struct {
    char *tag;
    TIO before;
    TIO after;
    char *prompt;
    char *nexttag;
} GDE;

int	loadgettydefs _PROTO((char *s));
void	dumpgettydefs _PROTO((char *file));
GDE	*getgettydef _PROTO((char *s));
#endif		/* USE_GETTYDEFS */
#endif		/* __TIO_H__ */
