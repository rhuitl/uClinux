#ident "$Id: tio.c,v 4.5 2000/10/22 10:45:20 gert Exp $ Copyright (c) 1993 Gert Doering"

/* tio.c
 *
 * contains routines dealing with SysV termio / POSIX termios / BSD sgtty
 *
 */

#include <unistd.h>
#include <sys/types.h>
#include <errno.h>

#ifdef NeXT
#include <sys/file.h>
#endif

#include "mgetty.h"
#include "tio.h"

#ifdef POSIX_TERMIOS
static char tio_compilation_type[]="@(#)tio.c compiled with POSIX_TERMIOS";
#endif
#ifdef SYSV_TERMIO
static char tio_compilation_type[]="@(#)tio.c compiled with SYSV_TERMIO";
#endif
#ifdef BSD_SGTTY
static char tio_compilation_type[]="@(#)tio.c compiled with BSD_SGTTY";
#endif

#ifdef USE_TERMIOX
# include <sys/termiox.h>
#endif

#if defined( M_UNIX ) && defined( MAM_BUG )
#include <fcntl.h>
#endif

#ifdef sysV68
#include <fcntl.h>
#include <errno.h>
#include <sys/tty.h>
#include <sys/sxt.h>
#include <sys/mvme332xt.h>
#endif

/* some systems do not define all flags needed later, e.g. NetBSD */

#ifdef BSD
# ifndef IUCLC
# define IUCLC 0
# endif
# ifndef TAB3
#  ifdef NeXT
#   define TAB3 XTABS
#  else
#   define TAB3 OXTABS
#  endif	/* !NeXT */
# endif
#endif

/* baud rate table */
static struct	speedtab {
#ifdef POSIX_TERMIOS
    speed_t	cbaud;
#else
    unsigned short cbaud;	/* baud rate, e.g. B9600 */
#endif
    int	 nspeed;		/* speed in numeric format */
    char *speed;		/* speed in display format */
} speedtab[] = {
	{ B50,	  50,	 "50"	 },
	{ B75,	  75,	 "75"	 },
	{ B110,	  110,	 "110"	 },
	{ B134,	  134,	 "134"	 },
	{ B150,	  150,	 "150"	 },
	{ B200,	  200,	 "200"	 },
	{ B300,	  300,	 "300"	 },
	{ B600,	  600,	 "600"	 },
#ifdef	B900
	{ B900,	  900,	 "900"	},
#endif
	{ B1200,  1200,	 "1200"	 },
	{ B1800,  1800,	 "1800"	 },
	{ B2400,  2400,	 "2400"	 },
#ifdef	B3600
	{ B3600,  3600,	 "3600"	},
#endif
	{ B4800,  4800,	 "4800"	 },
#ifdef	B7200
	{ B7200,  7200,  "7200"	},
#endif
	{ B9600,  9600,	 "9600"	 },
#ifdef	B14400
	{ B14400, 14400, "14400" },
#endif
#ifdef	B19200
	{ B19200, 19200, "19200" },
#endif	/* B19200 */
#ifdef	B28800
	{ B28800, 28800, "28800" },
#endif
#ifdef	B38400
	{ B38400, 38400, "38400" },
#endif	/* B38400 */
#ifdef	EXTA
	{ EXTA,	  19200, "EXTA"	 },
#endif
#ifdef	EXTB
	{ EXTB,	  38400, "EXTB"	 },
#endif
#ifdef	B57600
	{ B57600, 57600, "57600" },
#endif
#ifdef	B76800
	{ B76800, 76800, "76800" },
#endif
#ifdef	B115200
	{ B115200,115200,"115200"},
#endif
#ifdef B230400
	{ B230400,230400,"230400"},
#endif
#ifdef B460800
	{ B460800,460800,"460800"},
#endif
	{ 0,	  0,	 ""	 }
};


/* get current tio settings for given filedescriptor */

int tio_get _P2((fd, t), int fd, TIO *t )
{ 
#ifdef SYSV_TERMIO
    if ( ioctl( fd, TCGETA, t ) < 0 )
    {
	lprintf( L_ERROR, "TCGETA failed" ); return ERROR;
    }
#endif
#ifdef POSIX_TERMIOS
    if ( tcgetattr( fd, t ) < 0 )
    {
	lprintf( L_ERROR, "tcgetattr failed" ); return ERROR;
    }
#endif
#ifdef BSD_SGTTY
    if ( gtty( fd, t ) < 0 )
    {
	lprintf( L_ERROR, "gtty failed" ); return ERROR;
    }
#endif
    return NOERROR;
}

int tio_set _P2( (fd, t), int fd, TIO * t)	/*!! FIXME: flags, wait */
{
#ifdef sunos4
    int modem_lines;
#endif
#ifdef SYSV_TERMIO
    if ( ioctl( fd, TCSETA, t ) < 0 )
    {
	lprintf( L_ERROR, "ioctl TCSETA failed" ); return ERROR;
    }
#endif
#ifdef POSIX_TERMIOS
    if ( tcsetattr( fd, TCSANOW, t ) < 0 )
    {
	lprintf( L_ERROR, "tcsetattr failed" ); return ERROR;
    }
#ifdef sunos4
    /* On SunOS, make sure that RTS and DTR are asserted if you wanna
     * use hardware flow control
     */
    if (t->c_cflag & CRTSCTS)
    {
        /* make sure RTS is asserted!!!!!! */
        ioctl(fd, TIOCMGET, &modem_lines);
        modem_lines |= (TIOCM_RTS | TIOCM_DTR);
        ioctl(fd, TIOCMSET, &modem_lines);
    }
#endif /* sunos4 */
#endif /* posix_termios */

#ifdef BSD_SGTTY
    if ( stty( fd, t ) < 0 )
    {
	lprintf( L_ERROR, "stty failed" ); return ERROR;
    }
#endif
    return NOERROR;
}

/* check whether a given speed (integer) is valid for the given system */
int tio_check_speed _P1( (speed), int speed )
{
    int i;
    for ( i=0; speedtab[i].cbaud != 0; i++ )
    {
	if ( speedtab[i].nspeed == speed )
	{
	    return speedtab[i].cbaud;
	}
    }
    lprintf( L_NOISE, "speed %d not found in table", speed );
    return -1;
}

/* set speed, do not touch the other flags
 * "speed" is given as numeric baud rate, not as Bxxx constant
 */
int tio_set_speed _P2( (t, speed ), TIO *t, unsigned int speed )
{
    int i, symspeed=0;

    for ( i=0; speedtab[i].cbaud != 0; i++ )
    {
	if ( speedtab[i].nspeed == speed ) 
		{ symspeed = speedtab[i].cbaud; break; }
    }

    if ( symspeed == 0 )
    {
	errno=EINVAL;
	lprintf( L_ERROR, "tss: unknown/unsupported bit rate: %d", speed );
	return ERROR;
    }

    lprintf( L_NOISE, "tss: set speed to %d (%03o)", speed, symspeed );
	
#ifdef SYSV_TERMIO
    t->c_cflag = ( t->c_cflag & ~CBAUD) | symspeed;
#endif
#ifdef POSIX_TERMIOS
    cfsetospeed( t, symspeed );
    cfsetispeed( t, symspeed );
#endif
#ifdef BSD_SGTTY
    t->sg_ispeed = t->sg_ospeed = symspeed;
#endif
    return NOERROR;
}

/* get port speed. Return integer value, not symbolic constant */
int tio_get_speed _P1( (t), TIO *t )
{
#ifdef SYSV_TERMIO
    ushort cbaud = t->c_cflag & CBAUD;
#endif
#ifdef POSIX_TERMIOS
    speed_t cbaud = cfgetospeed( t );
#endif
#ifdef BSD_SGTTY
    int cbaud = t->sg_ospeed;
#endif
    struct speedtab * p;

    for ( p=speedtab; p->nspeed != 0; p++ )
    {
	if ( p->cbaud == cbaud ) break;
    }
    return p->nspeed;
}
 

/* set "raw" mode: do not process input or output, do not buffer */
/* do not touch cflags or xon/xoff flow control flags */

void tio_mode_raw _P1( (t), TIO * t )
{
#if defined(SYSV_TERMIO) || defined( POSIX_TERMIOS)
    t->c_iflag &= ( IXON | IXOFF | IXANY );	/* clear all flags except */
						/* xon / xoff handshake */
    t->c_oflag  = 0;				/* no output processing */
    t->c_lflag  = 0;				/* no signals, no echo */

    t->c_cc[VMIN]  = 1;				/* disable line buffering */
    t->c_cc[VTIME] = 0;
#else
    t->sg_flags = RAW;
#endif
}

/* "cbreak" mode - do not process input in lines, but process ctrl
 * characters, echo characters back, ...
 * warning: must be based on raw / sane mode
 */
void tio_mode_cbreak _P1( (t), TIO * t )
{
#if defined(SYSV_TERMIO) || defined(POSIX_TERMIOS)
    t->c_oflag = 0;
    t->c_iflag &= ~( IGNCR | ICRNL | INLCR | IUCLC );
    t->c_lflag &= ~( ICANON | ISIG );
    t->c_cc[VMIN] = 1;
    t->c_cc[VTIME]= 0;
#else
    t->sg_flags |= CBREAK;
#endif
}

/* set "sane" mode, usable for login, ...
 * unlike the other tio_mode_* functions, this function initializes
 * all flags, and should be called before calling any other function
 */
void tio_mode_sane _P2( (t, local), TIO * t, int local )
{
#if defined(SYSV_TERMIO) || defined( POSIX_TERMIOS )
    t->c_iflag = BRKINT | IGNPAR | IXON | IXANY;
    t->c_oflag = OPOST | TAB3;
    /* be careful, only touch "known" flags */
    t->c_cflag&= ~(CSIZE | CSTOPB | PARENB | PARODD | CLOCAL);
    t->c_cflag|= CS8 | CREAD | HUPCL | ( local? CLOCAL:0 );
    t->c_lflag = ECHOK | ECHOE | ECHO | ISIG | ICANON;

#if !defined(POSIX_TERMIOS)
    t->c_line  = 0;
#endif

    /* initialize the most important c_cc's here */
    t->c_cc[VEOF] = 0x04;
#if defined(VEOL) && VEOL < TIONCC
    t->c_cc[VEOL] = 0;
#endif

#ifdef VSWTCH
    t->c_cc[VSWTCH] = 0;
#endif

#else		/* BSD_SGTTY */
    t->sg_flags = ECHO | EVENP | ODDP;
/*    t->sg_flags = ECHO; */
    t->sg_erase = 0x7f;            /* erase character */
    t->sg_kill  = 0x25;            /* kill character, ^u */
#endif
}

/* tio_default_cc( TIO )
 *
 * initialize all c_cc fields (for POSIX and SYSV) to proper start
 * values (normally, the serial driver should do this, but there are
 * numerous systems where some of the more esoteric (VDSUSP...) flags
 * are plain wrong (e.g. set to "m" or so)
 *
 * do /not/ initialize VERASE and VINTR, since some systems use
 * ^H / DEL here, others DEL / ^C.
 */
void tio_default_cc _P1( (t), TIO *t )
{
#ifdef BSD_SGTTY
    t->sg_erase = 0x7f;            /* erase character */
    t->sg_kill  = 0x25;            /* kill character, ^u */

#else /* posix or sysv */
    t->c_cc[VQUIT]  = CQUIT;
    t->c_cc[VKILL]  = CKILL;
    t->c_cc[VEOF]   = CEOF;
#if defined(VEOL) && VEOL < TIONCC
    t->c_cc[VEOL] = CEOL;
#endif
#if defined(VSTART) && VSTART < TIONCC
    t->c_cc[VSTART] = CSTART;
#endif
#if defined(VSTOP) && VSTOP < TIONCC
    t->c_cc[VSTOP] = CSTOP;
#endif
#if defined(VSUSP) && VSUSP < TIONCC
    t->c_cc[VSUSP] = CSUSP;
#endif
#if defined(VSWTCH) && VSWTCH < TIONCC
    t->c_cc[VSWTCH] = CSWTCH;
#endif
    /* the following are for SVR4.2 (and higher) */
#if defined(VDSUSP) && VDSUSP < TIONCC
    t->c_cc[VDSUSP] = CDSUSP;
#endif
#if defined(VREPRINT) && VREPRINT < TIONCC
    t->c_cc[VREPRINT] = CRPRNT;
#endif
#if defined(VDISCARD) && VDISCARD < TIONCC
    t->c_cc[VDISCARD] = CFLUSH;
#endif
#if defined(VWERASE) && VWERASE < TIONCC
    t->c_cc[VWERASE] = CWERASE;
#endif
#if defined(VLNEXT) && VLNEXT < TIONCC
    t->c_cc[VLNEXT] = CLNEXT;
#endif

#endif /* bsd <-> posix + sysv */
}


void tio_map_cr _P2( (t, perform_mapping), TIO * t, int
		    perform_mapping )
{
#if defined(SYSV_TERMIO) || defined(POSIX_TERMIOS)
    if ( perform_mapping )
    {
	t->c_iflag |= ICRNL;
	t->c_oflag |= ONLCR;
    }
    else
    {
	t->c_iflag &= ~ICRNL;
	t->c_oflag &= ~ONLCR;
    }
#else		/* BSD_SGTTY (tested only on NeXT yet, but should work) */
    if ( perform_mapping )
    {
        t->sg_flags |= CRMOD ;
    }
    else
    {
        t->sg_flags &= ~CRMOD ;
    }
#endif
}

/* enable uppercase <-> lowercase mapping */

void tio_map_uclc _P2( (t, perform_mapping), TIO * t, int
		    perform_mapping )
{
#if defined(__bsdi__) || !defined(OLCUC) || !defined(XCASE)
    lprintf( L_WARN, "uclc mapping not available" );
#else
# if defined(SYSV_TERMIO) || defined(POSIX_TERMIOS)
    if ( perform_mapping )
    {
	t->c_iflag |= IUCLC;
	t->c_oflag |= OLCUC;
	t->c_lflag |= XCASE;
    }
    else
    {
	t->c_iflag &= ~IUCLC;
	t->c_oflag &= ~OLCUC;
	t->c_lflag &= ~XCASE;
    }
# else		/* BSD_SGTTY */
#  include "not implemented yet"
# endif
#endif		/* BSDI */
}

/* tio_carrier()
 * specify whether the port should be carrier-sensitive or not
 */

void tio_carrier _P2( (t, carrier_sensitive), TIO *t, int carrier_sensitive )
{
#if defined(SYSV_TERMIO) || defined(POSIX_TERMIOS)
    if ( carrier_sensitive )
    {
	t->c_cflag &= ~CLOCAL;
    }
    else
    {
	t->c_cflag |= CLOCAL;
    }
#else		/* BSD_SGTTY (tested only on NeXT yet, but should work) */
    if ( carrier_sensitive )
    {
        t->sg_flags &= ~LNOHANG ;
    }
    else
    {
        t->sg_flags |= LNOHANG ;
    }
#endif
}

/* set handshake */
 
/* hardware handshake flags - use what is available on local system
 */

#ifdef CRTSCTS
# define HARDWARE_HANDSHAKE CRTSCTS		/* linux, SunOS */
#else
# ifdef CRTSFL
#  define HARDWARE_HANDSHAKE CRTSFL		/* SCO 3.2v4.2 */
# else
#  ifdef RTSFLOW
#   define HARDWARE_HANDSHAKE RTSFLOW | CTSFLOW	/* SCO 3.2v2 */
#  else
#   ifdef CTSCD
#    define HARDWARE_HANDSHAKE CTSCD		/* AT&T 3b1? */
#   else
#    define HARDWARE_HANDSHAKE 0		/* nothing there... */
#   endif
#  endif
# endif
#endif

/* Dial-Out parallel to a Dial-in on SCO 3.2v4.0 does only work if
 * *only* CTSFLOW is set (Uwe S. Fuerst)
 */
#ifdef BROKEN_SCO_324
# undef HARDWARE_HANDSHAKE
# define HARDWARE_HANDSHAKE CTSFLOW
#endif

/* tio_set_flow_control
 *
 * set flow control according to the <type> parameter. It can be any
 * combination of
 *   FLOW_XON_IN - use Xon/Xoff on incoming data
 *   FLOW_XON_OUT- respect Xon/Xoff on outgoing data
 *   FLOW_HARD   - use RTS/respect CTS line for hardware handshake
 * (not every combination will work on every system)
 *
 * WARNING: for most systems, this function will not touch the tty
 *          settings, only modify the TIO structure. On some systems,
 *          you have to use extra ioctl()s [notably SVR4, sysV68, and
 *          AIX] to modify hardware flow control settings. On those
 *          systems, these calls are done immediately.
 */

int tio_set_flow_control _P3( (fd, t, type), int fd, TIO * t, int type )
{
#ifdef USE_TERMIOX
    struct termiox tix;
#endif

    lprintf( L_NOISE, "tio_set_flow_control(%s%s%s )",
		      type & FLOW_HARD   ? " HARD": "",
		      type & FLOW_XON_IN ? " XON_IN": "",
		      type & FLOW_XON_OUT? " XON_OUT": "" );
    
#if defined( SYSV_TERMIO ) || defined( POSIX_TERMIOS )
    t->c_cflag &= ~HARDWARE_HANDSHAKE;
    t->c_iflag &= ~( IXON | IXOFF | IXANY );

    if ( type & FLOW_HARD )
			t->c_cflag |= HARDWARE_HANDSHAKE;
    if ( type & FLOW_XON_IN )
			t->c_iflag |= IXOFF;
    /* for login, we want IXON|IXANY, for voice, we must not set IXANY! */
    if ( type & FLOW_XON_OUT )
    {
	                t->c_iflag |= IXON;
        if ( type & FLOW_XON_IXANY )
	                t->c_iflag |= IXANY;
    }
#else
# ifdef NEXTSGTTY
    lprintf( L_WARN, "tio_set_flow_control: not yet implemented" );
# else
#  include "not yet implemented"
# endif
#endif

    /* SVR4 came up with a new method of setting h/w flow control */
#ifdef USE_TERMIOX
    lprintf( L_NOISE, "tio_set_flow_control: using termiox" );

    if (ioctl(fd, TCGETX, &tix) < 0)
    {
	lprintf( L_ERROR, "ioctl TCGETX" ); return ERROR;
    }
    if ( type & FLOW_HARD )
        tix.x_hflag |= (RTSXOFF | CTSXON);
    else
        tix.x_hflag &= ~(RTSXOFF | CTSXON);
    
    if ( ioctl(fd, TCSETX, &tix) < 0 )
    {
	lprintf( L_ERROR, "ioctl TCSETX" ); return ERROR;
    }
#endif
    /* AIX has yet another method to set hardware flow control
     * interesting enough, in AIX 4, this ioctl still exists but doesn't
     * work anymore -- instead, they have adopted termiox. *bah*
     */
#if defined(_AIX) && !defined(USE_TERMIOX)
    lprintf( L_NOISE, "tio_set_flow_control: using TXADDCD" );

    if ( ioctl( fd, ( type & FLOW_HARD ) ? TXADDCD : TXDELCD, "rts" ) < 0 )
    {
	lprintf( L_NOISE, "ioctl TXADDCD/TXDELCD failed, errno=%d", errno);
	return ERROR;
    }
#ifdef DEBUG
    {	union txname t; int i;
	lprintf( L_NOISE, "control disciplines:");
	for ( i=1; ; i++ ) {
	    t.tx_which = i;
	    if ( ioctl( fd, TXGETCD, &t ) ) {
		lprintf( L_FATAL, "TXGETCD error" ); break;
	    }
	    if ( t.tx_name == NULL || !t.tx_name[0] ) break;
	    lputc( L_NOISE, ' ');
	    lputs( L_NOISE, t.tx_name );
	}
    }
#endif			/* DEBUG */
#endif			/* _AIX */

/*
 * sysV68 uses special ioctls, too. The following code should work for
 * mvme332xt controllers. The mvme337 driver supports the same ioctls
 * but has not been tested. Others may not support hardware flow
 * control at all. Refer to the corresponding mvmeXXX(7) manpage for
 * details.
 */
#ifdef sysV68
    lprintf( L_NOISE, "tio_set_flow_control: using TCSETHW" );

    if ( type & FLOW_HARD ) {
	if ( ioctl(fd, TCSETHW, 1) < 0 ) {
		lprintf( L_ERROR, "ioctl TCSETHW on failed" );
		return ERROR;
	}
    } else {
	if ( ioctl(fd, TCSETHW, 0) < 0 ) {
		/* We use a lower logging priority if errno is EINVAL, so
		 * mgetty can be used on devices which do not support the
		 * special m332xt ioctls without filling syslog with
		 * unnecessary error messages.
		 */
		if (EINVAL == errno) {
			lprintf( L_NOISE, "ioctl TCSETHW off failed" );
		} else {
			lprintf( L_ERROR, "ioctl TCSETHW off failed" );
			return ERROR;
		}
	}
    }
#endif /* sysV68 */
    return NOERROR;
}

/* for convenience - do not have to get termio settings before, but
 * it's slower (two system calls more)
 */
int tio_set_flow_control2 _P2( (fd, type), int fd, int type )
{
TIO t;

    if ( tio_get( fd, &t ) == ERROR ) return ERROR;

    tio_set_flow_control( fd, &t, type );

    return tio_set( fd, &t );
}

int tio_toggle_dtr _P2( (fd, msec_wait), int fd, int msec_wait )
{
    /* On SVR4.2, lowering DTR by setting the port speed to zero will
     * bring the port to some strange state where every ioctl() later
     * on simply fails - so use special "modem control" ioctl()s to
     * lower and raise DTR
     * Strange enough, on *some* platforms, you have to pass the mctl
     * flag word by value, on others by reference. Oh world...
     */
#if defined(TIOCMBIS) && \
    ( defined(sun) || defined(SVR4) || defined(NeXT) || defined(linux) )
    
    int mctl = TIOCM_DTR;

#if !defined( TIOCM_VALUE )
    if ( ioctl( fd, TIOCMBIC, &mctl ) < 0 )
#else
    if ( ioctl( fd, TIOCMBIC, (char *) mctl ) < 0 )
#endif
    {
	lprintf( L_ERROR, "TIOCMBIC failed" ); return ERROR;
    }
    delay( msec_wait );
#if !defined( TIOCM_VALUE)
    if ( ioctl( fd, TIOCMBIS, &mctl ) < 0 )
#else
    if ( ioctl( fd, TIOCMBIS, (char *) mctl ) < 0 )
#endif
    {
	lprintf( L_ERROR, "TIOCMBIS failed" ); return ERROR;
    }
    return NOERROR;
#else						/* !TIOCMBI* */

    /* On HP/UX, lowering DTR by setting the port speed to B0 will
     * leave it there. So, do it via HP/UX's special ioctl()'s...
     */
#if defined(_HPUX_SOURCE) || defined(MCGETA)
    unsigned long mflag = 0L;

    if ( ioctl( fd, MCSETAF, &mflag ) < 0 )
    {
	lprintf( L_ERROR, "MCSETAF failed" ); return ERROR;
    }
    delay( msec_wait );
    if ( ioctl( fd, MCGETA, &mflag ) < 0 )
    {
	lprintf( L_ERROR, "MCGETA failed" ); return ERROR;
    }
    mflag = MRTS | MDTR;
    if ( ioctl( fd, MCSETAF, &mflag ) < 0 )
    {
	lprintf( L_ERROR, "MCSETAF failed" ); return ERROR;
    }
    return NOERROR;

#else /* !MCGETA */
    
    /* The "standard" way of doing things - via speed = B0
     */
    TIO t, save_t;
#ifdef sunos4
    int modem_lines;
#endif
    int result;

    if ( tio_get( fd, &t ) == ERROR ) return ERROR;

    save_t = t;
    
#ifdef SYSV_TERMIO 
    t.c_cflag = ( t.c_cflag & ~CBAUD ) | B0;		/* speed = 0 */
#endif
#ifdef POSIX_TERMIOS
    cfsetospeed( &t, B0 );
    cfsetispeed( &t, B0 );
#endif
#ifdef BSD_SGTTY
    t.sg_ispeed = t.sg_ospeed = B0
#endif

    tio_set( fd, &t );
    delay( msec_wait );
    
#ifdef sunos4
    /* on SunOS, if you hangup via B0, the DTR line will *stay* low.
     * So: enable it manually again.
     */
    ioctl(fd, TIOCMGET, &modem_lines);
    modem_lines |= (TIOCM_RTS | TIOCM_DTR);
    ioctl(fd, TIOCMSET, &modem_lines);
#endif
    result = tio_set( fd, &save_t );
    
#if (defined(M_UNIX) && defined(MAM_BUG)) || defined (sysV68)
    /* some Unix variants apparently forget to raise DTR again
     * after lowering it. Reopening the port fixes it. Crude, but works.
     */
    close( open( "/dev/tty", O_RDONLY | O_NDELAY ) );
#endif
    
    return result;
#endif					/* !MCSETA */
#endif					/* !SVR4 */
}


/* flush input or output data queue
 *
 * "queue" is one of the TIO_Q* values from tio.h
 */

int tio_flush_queue _P2( (fd, queue), int fd, int queue )
{
    int r = NOERROR;
#ifdef POSIX_TERMIOS
    switch( queue )
    {
      case TIO_Q_IN:   r = tcflush( fd, TCIFLUSH ); break;
      case TIO_Q_OUT:  r = tcflush( fd, TCOFLUSH ); break;
      case TIO_Q_BOTH: r = tcflush( fd, TCIOFLUSH );break;
      default:
	lprintf( L_WARN, "tio_flush_queue: invalid ``queue'' argument" );
	return ERROR;
    }
#endif
#ifdef SYSV_TERMIO
    switch ( queue )
    {
      case TIO_Q_IN:   r = ioctl( fd, TCFLSH, 0 ); break;
      case TIO_Q_OUT:  r = ioctl( fd, TCFLSH, 1 ); break;
      case TIO_Q_BOTH: r = ioctl( fd, TCFLSH, 2 ); break;
      default:
	lprintf( L_WARN, "tio_flush_queue: invalid ``queue'' argument" );
	return ERROR;
    }
#endif
#ifdef BSD_SGTTY
    int arg;
    
    switch ( queue )
    {
      case TIO_Q_IN:   arg = FREAD; break;
      case TIO_Q_OUT:  arg = FWRITE; break;
      case TIO_Q_BOTH: arg = FREAD | FWRITE; break;
      default:
	lprintf( L_WARN, "tio_flush_queue: invalid ``queue'' argument" );
	return ERROR;
    }
    r = ioctl( fd, TIOCFLUSH, (char *) &arg );
#endif
    if ( r != 0 ) lprintf( L_ERROR, "tio: cannot flush queue" );

    return r;
}

/* control flow control: if "restart_output" is TRUE, stopped tty output is
 * resumed, if it is FALSE, the output is stopped
 *
 * I'm fairly sure it won't work on all supported systems...
 */
   
int tio_flow _P2( (fd, restart_output), int fd, int restart_output )
{
    int r;
#ifdef POSIX_TERMIOS
    if ( restart_output ) r = tcflow( fd, TCOON );
                     else r = tcflow( fd, TCOOFF );
#endif
#ifdef SYSV_TERMIO
    if ( restart_output ) r = ioctl( fd, TCXONC, 1 );
                     else r = ioctl( fd, TCXONC, 0 );
#endif
#ifdef BSD_SGTTY
    if ( restart_output ) r = ioctl( fd, TIOCSTART, NULL );
                     else r = ioctl( fd, TIOCSTOP, NULL );
#endif
    if ( r != 0 ) lprintf( L_ERROR, "tio: cannot change flow ctrl state" );

    return r;
}


/* tio_drain(fd): wait for output queue to drain
 */

int tio_drain_output _P1( (fd), int fd )
{
#ifdef POSIX_TERMIOS
    if ( tcdrain( fd ) == ERROR )
    {
	lprintf( L_ERROR, "tio_drain: tcdrain" ); return ERROR;
    }
#else
# ifdef SYSV_TERMIO
    if ( ioctl( fd, TCSBRK, 1 ) == ERROR )
    {
    	lprintf( L_ERROR, "tio_drain: TCSBRK/1" ); return ERROR;
    }
# else	/* no way to wait for data to drain with BSD_SGTTY */
    lprintf( L_WARN, "tio_drain: expect spurious failures" );
# endif
#endif
    return NOERROR;
}

/* send a BREAK signal to the tty
 *
 * kernel break via tcsendbreak() or ioctl(TCSENDBRK) lasts at least
 * 0.25 seconds. We can speed up this by switching baud rate to 1/4,
 * and then sending a 0-byte (activated #ifdef FAST_BREAK).
 * 
 * on some systems (don't we love it all?) the "real" break functions
 * don't work, so we must use FAST_BREAK.
 */

int tio_break _P1((fd), int fd)
{
/* SunOS4 doesn't seem to like "tcsendbreak" (noop), so send a "long zero" */
#if defined(sunos4) || defined(M_UNIX) || defined(FAST_BREAK)
    TIO tio, tio_save; int speed; char null = 0;

    lprintf( L_NOISE, "sending FAST break" );

    if ( tio_get( fd, &tio ) == ERROR )
    {
	lprintf( L_ERROR, "tio_break: can't get tio" ); return ERROR;
    }
    tio_save = tio;
    if ( (speed = tio_get_speed( &tio ) ) < 150 ||
	 tio_set_speed( &tio, speed/4 ) == ERROR ||
	 tio_set( fd, &tio ) == ERROR )
    {
	lprintf( L_ERROR, "tio_break: can't set 1/4 speed" ); return ERROR;
    }
    if ( write( fd, &null, 1 ) != 1 )
    {
	lprintf( L_ERROR, "tio_break: can't write 0-byte" ); return ERROR;
    }

    /* before we switch baud rates back, make sure zero byte has been sent!
     */
    if ( tio_drain_output( fd ) == ERROR ) return ERROR;

    if ( tio_set( fd, &tio_save ) == ERROR )
    {
	lprintf( L_ERROR, "tio_break: can't reset old TIO state" ); return ERROR;
    }

#else	/* !FAST_BREAK -> use standard functions */

    lprintf( L_NOISE, "sending system call break" );
#ifdef POSIX_TERMIOS
    if ( tcsendbreak( fd, 0 ) < 0 )
    {
    	lprintf( L_ERROR, "tcsendbreak() failed" );
    	return ERROR;
    }
#endif
#ifdef SYSV_TERMIO
    if ( ioctl( fd, TCSBRK, 0 ) < 0 )
    {
    	lprintf( L_ERROR, "ioctl( TCSBRK ) failed" );
    	return ERROR;
    }
#endif
#ifdef BSD_SGTTY
   if ( ioctl( fd, TIOCSBRK, 0 ) < 0 )
   {
   	lprintf( L_ERROR, "ioctl( TIOCSBRK ) failed" );
   	return ERROR;
   }
   delay( 250 );
   if ( ioctl( fd, TIOCCBRK, 0 ) < 0 )
   {
   	lprintf( L_ERROR, "ioctl( TIOCCBRK ) failed" );
   	return ERROR;
   }
#endif
#endif /* FAST_BREAK */
   return NOERROR;
}

/* tio_get_rs232_lines()
 *
 * get the status of all RS232 status lines
 * (coded by the TIO_F_* flags. On systems that have the BSD TIOCM_*
 * flags, we use them, on others we may have to do some other tricks)
 *
 * "-1" can mean "error" or "not supported on this system" (e.g. SCO).
 */

int tio_get_rs232_lines _P1( (fd), int fd)
{
    int flags;
#ifdef TIO_F_SYSTEM_DEFS
    if ( ioctl(fd, TIOCMGET, &flags ) < 0 )
    	lprintf( L_ERROR, "tio_get_rs232_lines: TIOCMGET failed" );

#else /* !TIO_F_SYSTEM_DEFS */
    flags=-1;
#endif

    if ( flags != -1 )
    {
        lprintf( L_NOISE, "tio_get_rs232_lines: status:" );
        if ( flags & TIO_F_RTS ) lputs( L_NOISE, " RTS" );
        if ( flags & TIO_F_CTS ) lputs( L_NOISE, " CTS" );
        if ( flags & TIO_F_DSR ) lputs( L_NOISE, " DSR" );
        if ( flags & TIO_F_DTR ) lputs( L_NOISE, " DTR" );
        if ( flags & TIO_F_DCD ) lputs( L_NOISE, " DCD" );
        if ( flags & TIO_F_RI  ) lputs( L_NOISE, " RI" );
    }
    return flags;
}

/* tio_set_rs232_lines()
 *
 * set the status of the DTR and RTS RS232 status lines
 * (coded by the TIO_F_* flags. On systems that have the BSD TIOCM_*
 * flags, we use them, on others we may have to do some other tricks)
 *
 * "-1" can mean "error" or "not supported on this system" (e.g. SCO).
 */

int tio_set_rs232_lines _P3( (fd, do_dtr, do_rts), 
				int fd, int do_dtr, int do_rts )
{
    int mctl, rc=0;

#ifdef TIO_F_SYSTEM_DEFS
    mctl = TIOCM_DTR;
    if ( do_dtr != -1 &&
         ioctl( fd, do_dtr? TIOCMBIS: TIOCMBIC, &mctl ) < 0 )
    {
	lprintf( L_ERROR, "tio_set_rs232_lines: %s DTR failed",
			do_dtr? "set": "clear" );
	rc=-1;
    }

    mctl = TIOCM_RTS;
    if ( do_rts != -1 &&
         ioctl( fd, do_rts? TIOCMBIS: TIOCMBIC, &mctl ) < 0 )
    {
	lprintf( L_ERROR, "tio_set_rs232_lines: %s RTS failed",
			do_rts? "set": "clear" );
	rc=-1;
    }

#else
    lprintf( L_WARN, "setting of RS232 lines not supported" );
#endif
    return rc;
}
