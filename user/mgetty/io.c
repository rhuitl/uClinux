#ident "$Id: io.c,v 4.2 1997/06/28 20:41:29 gert Exp $ Copyright (c) Gert Doering"

/* io.c
 *
 * This module contains a few low-level I/O functions
 * (will be extended)
 */

#include <stdio.h>
#include <unistd.h>
#include "syslibs.h"
#include <signal.h>
#include <errno.h>

#include "mgetty.h"

/* warning: these includes have to appear *after* "mgetty.h"! */

#ifdef USE_POLL
# include <poll.h>
# ifndef _AIX
int poll _PROTO(( struct pollfd fds[], unsigned long nfds, int timeout ));
# endif		/* AIX */
#endif		/* USE_POLL */

/* SCO Unix defines XENIX as well, which will confuse the code below */
#if defined(M_XENIX) && defined(M_UNIX)
#  undef M_XENIX
#endif

#ifdef USE_SELECT
# include <string.h>
# if defined (linux) || defined (sunos4) || defined (SVR4) || \
     defined (__hpux) || defined (MEIBE) || defined(sgi) || \
     defined (ISC) || defined (BSD) || defined(sysV68) || \
     defined(m88k) || defined(M_XENIX)
#  include <sys/types.h>
#  include <sys/time.h>
#  ifdef ISC
#   include <sys/bsdtypes.h>
#  endif			/* ISC */
#  ifdef M_XENIX
#   include <sys/select.h>
#  endif
# else				/* not sys/types.h + sys/time.h */
#  include <sys/select.h>
# endif

# ifdef NEED_BZERO
#  define bzero( ptr, length ) memset( ptr, 0, length )
# endif
	       
#endif /* USE_SELECT */

void delay _P1( (waittime),
		int waittime )		/* wait waittime milliseconds */
{
#ifdef USE_USLEEP
    usleep( waittime * 1000 );
#else
#ifdef USE_POLL
struct pollfd sdummy;
    poll( &sdummy, 0, waittime );
#else
#ifdef USE_NAP
    nap( (long) waittime );
#else
#ifdef USE_SELECT
    struct timeval s;

    s.tv_sec = waittime / 1000;
    s.tv_usec = (waittime % 1000) * 1000;
    select( 0, (fd_set *) NULL, (fd_set *) NULL, (fd_set *) NULL, &s );

#else				/* neither poll nor nap nor select available */
    if ( waittime < 2000 ) waittime = 2000;	/* round up */
    sleep( waittime / 1000);			/* a sleep of 1 may not sleep at all */
#endif	/* use select */
#endif	/* use nap */
#endif	/* use poll */
#endif	/* use usleep */
}

/* check_for_input( open file deskriptor )
 *
 * returns TRUE if there's something to read on filedes, FALSE otherwise
 */

boolean	check_for_input _P1( (filedes),
			     int filedes )
{
#ifdef USE_SELECT
    fd_set	readfds;
    struct	timeval timeout;
#endif
#ifdef USE_POLL
    struct	pollfd fds;
#endif
    int ret;

#ifdef USE_SELECT

    FD_ZERO( &readfds );
    FD_SET( filedes, &readfds );
    timeout.tv_sec = timeout.tv_usec = 0;
    ret = select( FD_SETSIZE , &readfds, NULL, NULL, &timeout );

#else
# ifdef USE_POLL

    fds.fd = filedes;
    fds.events = POLLIN;
    fds.revents= 0;
    ret = poll( &fds, 1, 0 );

# else

    ret = 0;	/* CHEAT! */

# endif
#endif

    if ( ret < 0 ) lprintf( L_ERROR, "poll / select failed" );

    return ( ret > 0 );
}

#if !defined( USE_SELECT) && !defined( USE_POLL )
static RETSIGTYPE wfi_timeout(SIG_HDLR_ARGS) {}
#endif
    
/* wait until a character is available
 * where select() or poll() exists, no characters will be read,
 * if only read() can be used, at least one character will be dropped
 *
 * return TRUE if data is found, FALSE if "msecs" milliseconds have passed
 */
boolean wait_for_input _P2( (fd, msecs), int fd, int msecs )
{
#ifdef USE_SELECT
    fd_set	readfds;
    struct timeval timeout, *tptr;
#endif
#ifdef USE_POLL
    struct	pollfd fds;
    int		timeout;
#endif
    int slct;

#ifdef USE_SELECT
    
    FD_ZERO( &readfds );
    FD_SET( fd, &readfds );
    if ( msecs >= 0 )
    {
	timeout.tv_sec = msecs / 1000;
	timeout.tv_usec = (msecs % 1000) * 1000;	/* microsecs! */
	tptr = &timeout;
    }
    else
        tptr = NULL;
    
    slct = select( FD_SETSIZE, &readfds, NULL, NULL, tptr );
    lprintf( L_JUNK, "select returned %d", slct );

#else	/* use poll */
# ifdef USE_POLL

    if ( msecs < 0 ) timeout = -1;
                else timeout = msecs;
    
    fds.fd = fd;
    fds.events = POLLIN;
    fds.revents= 0;
    slct = poll( &fds, 1, timeout );
    lprintf( L_JUNK, "poll returned %d", slct );

# else
    {
	char t;
	int oerrno;
	
	if ( msecs > 0 )
	{
	    signal( SIGALRM, wfi_timeout );
	    alarm( (msecs+999)/1000 );
	}

	slct = read( fd, &t, 1 );

	oerrno = errno;
	alarm(0); signal( SIGALRM, SIG_DFL );
	errno = oerrno;
	
	if ( slct < 0 )
	{
	    if ( errno == EINTR )
	         lprintf( L_JUNK, "read: timeout" );
	    else
	         lprintf( L_ERROR, "read: error" );
	}
	else
	{
	    lprintf(L_JUNK, "read returned: "); lputc(L_JUNK, t );
	}
    }
# endif
#endif
    return ( slct>0 );
}
