#ident "$Id: do_chat.c,v 4.2 2003/10/05 11:58:57 gert Exp $ Copyright (c) Gert Doering"

/* do_chat.c
 *
 * This module handles all the non-fax talk with the modem
 */

#include <stdio.h>
#include "syslibs.h"
#include <unistd.h>
#include <signal.h>
#include <string.h>
#ifndef sunos4
#include <sys/ioctl.h>
#endif

#ifndef EINTR
#include <errno.h>
#endif

#include "mgetty.h"
#include "policy.h"
#include "tio.h"

boolean chat_has_timeout;
static RETSIGTYPE chat_timeout(SIG_HDLR_ARGS)
{
    chat_has_timeout = TRUE;
}

extern boolean virtual_ring;

/* send one string to "fd", honouring \c, \d and \\ */

int do_chat_send _P2( (fd, p), int fd, char * p )
{
    boolean nocr = FALSE;		/* do not set CR/LF (\c) */

    /* before sending, maybe we have to pause a little */
#ifdef DO_CHAT_SEND_DELAY
    delay(DO_CHAT_SEND_DELAY);
#endif
	
    lprintf( L_MESG, "send: " );

    while ( *p != 0 ) 
    {
	if ( *p == '\\' )		/* special stuff */
	{
	    switch ( *(++p) )
	    {
	      case 'd': lputs( L_MESG, "\\d"); delay(500); break;
	      case 'c': nocr = TRUE; break;
	      default:
		write( fd, p, 1 );
		lputc( L_MESG, *p );
	    }
	}
	else
	{
	    if ( write( fd, p, 1 ) != 1 )
	    {
		lprintf( L_ERROR, "do_chat: can't write to modem!" );
		return ERROR;
	    }
	    lputc( L_MESG, *p );
	}
	p++;
    }

    if ( ! nocr )
    {
	write( fd, MODEM_CMD_SUFFIX, sizeof(MODEM_CMD_SUFFIX)-1 );
	p = MODEM_CMD_SUFFIX;
	while ( *p ) lputc( L_MESG, *(p++) );
    }

    return NOERROR;
}


int do_chat _P6((fd, expect_send, actions, action, chat_timeout_time,
		timeout_first ),
		int fd, char * expect_send[],
	        chat_action_t actions[], action_t * action,
                int chat_timeout_time, boolean timeout_first )
{
#define BUFFERSIZE 500
char	buffer[BUFFERSIZE];
int	i,cnt;
int	retcode = SUCCESS;
int	str;
int	h;
TIO	tio, save_tio;
#define	LSIZE	100
static	char	lbuf[LSIZE];
static	char	*lptr = lbuf;

    tio_get( fd, &tio );
    save_tio = tio;
    tio_mode_raw( &tio );
    tio_set( fd, &tio );

    signal( SIGALRM, chat_timeout );

    /* default "action" is timeout */
    if ( actions != NULL && action != NULL ) *action = A_TIMOUT;

    str=0;
    while ( expect_send[str] != NULL )
    {
	/* expect a string (expect_send[str] or abort[]) */
	i = 0;

	if ( strlen( expect_send[str] ) != 0 )
	{
	    lprintf( L_MESG, "waiting for ``%s''", expect_send[str] );

	    lprintf( L_NOISE, "got: " );

	    chat_has_timeout = FALSE;

	    /* set alarm timer. for the first string, the timer is only
	       set if the flag "timeout_first" is true */

	    if ( str != 0 || timeout_first )
		alarm( chat_timeout_time );
	    else
		alarm( 0 );

	    do
	    {
		if ( virtual_ring &&
		     strncmp( expect_send[str], "RING", 4 ) == 0 )
		{
		    lputs( L_MESG, " ``found''" );
		    break;
		}
		
		cnt = read( fd, &buffer[i], 1 );

		if ( cnt < 0 )
		{
		    if ( errno == EINTR ) cnt = 0;	/* signal */
		    else
		    {					/* unsp. error */
		        lprintf( L_ERROR, "do_chat: error in read()");
			retcode = FAIL;
			break;				/* -> abort */
		    }
		}

		if ( chat_has_timeout )		/* timeout */
		{
		    lprintf( L_WARN, "timeout in chat script, waiting for `%s'", expect_send[str] );
		    retcode = FAIL;
		    break;
		}

		if ( cnt > 0 )
		{
		    lputc( L_NOISE, buffer[i] );

		    /* build full lines, feed them to caller-id / connect
		     * string parsing routine in cnd.c
		     */
		    if ( buffer[i] == '\r' || buffer[i] == '\n' ||
			 (lptr >= lbuf+LSIZE-3) )
		    {
			*lptr = '\0';
			if (lbuf[0])
			    cndfind(lbuf);
			lptr = lbuf;
		    }
		    else
			*lptr++ = buffer[i];
		}

		i += cnt;
		if ( i>BUFFERSIZE-5 )	/* buffer full -> junk oldest stuff*/
		{
		    memcpy( &buffer[0], &buffer[BUFFERSIZE/2], i-BUFFERSIZE/2+1 );
		    i-=BUFFERSIZE/2;
		}

		/* look for the "expect"-string */

		cnt = strlen( expect_send[str] );
		if ( i >= cnt &&
		     memcmp( &buffer[i-cnt], expect_send[str], cnt ) == 0 )
		{
		    lputs( L_MESG, " ** found **" );
		    break;
		}

		/* look for one of the "abort"-strings */
                if ( actions != NULL )
		  for ( h=0; actions[h].expect != NULL; h ++ )
		{
		    cnt = strlen( actions[h].expect );
		    if ( i>=cnt && 
			 memcmp( &buffer[i-cnt], actions[h].expect, cnt ) == 0 )
		    {
			lprintf( L_MESG,"found action string: ``%s''",
			                actions[h].expect );
			*action = actions[h].action;
			retcode = FAIL;
			break;
		    }
		}
	    }
	    while ( i<BUFFERSIZE && retcode != FAIL );

	    /* disable timeout alarm clock */
	    alarm(0);

	    /* found abort string or timeout? */
	    if ( retcode == FAIL ) break;

	}		/* end if (strlen(expect_send[str] != 0) */

	str++;
	/* end of list? */

	if ( expect_send[str] == NULL ) break;

	/* send a string, translate (a few) esc-sequences */
	do_chat_send(fd,  expect_send[str++] );
	
    }				/* end while ( expect_send[str] != NULL ) */

    /* reset terminal settings */
    tio_set( fd, &save_tio );

    return retcode;
}

/* clean_line()
 *
 * wait for the line "fd" to be silent for "waittime" tenths of a second
 * if more than 500 bytes are read, stop logging them. We don't want to
 * have the log files fill up all of the hard disk.
 */

int clean_line _P2 ((fd, waittime), int fd, int waittime )
{
    char buffer[2];
    int	 bytes = 0;				/* bytes read */

#if defined(MEIBE) || defined(NEXTSGTTY) || defined(BROKEN_VTIME)
    /* on some systems, the VMIN/VTIME mechanism is obviously totally
     * broken. So, use a select()/flush queue loop instead.
     */
    lprintf( L_NOISE, "waiting for line to clear (select/%d ms), read: ", waittime * 100 );

    while( wait_for_input( fd, waittime * 100 ) &&
	   read( fd, buffer, 1 ) > 0 &&
	   bytes < 10000 )
    {
	if ( ++bytes < 500 ) lputc( L_NOISE, buffer[0] );
    }
#else
TIO	tio, save_tio;

    lprintf( L_NOISE, "waiting for line to clear (VTIME=%d), read: ", waittime);

    /* set terminal timeout to "waittime" tenth of a second */
    tio_get( fd, &tio );
    save_tio = tio;				/*!! FIXME - sgtty?! */
    tio.c_lflag &= ~ICANON;
    tio.c_cc[VMIN] = 0;
    tio.c_cc[VTIME] = waittime;
    tio_set( fd, &tio );

    /* read everything that comes from modem until a timeout occurs */
    while ( read( fd, buffer, 1 ) > 0 &&
	    bytes < 10000 )
    {
        if ( ++bytes < 500 ) lputc( L_NOISE, buffer[0] );
    }

    /* reset terminal settings */
    tio_set( fd, &save_tio );
    
#endif

    if ( bytes > 500 )
        lprintf( L_WARN, "clean_line: only 500 of %d bytes logged", bytes );
    if ( bytes >= 10000 )
    {
	extern char * Device;
        lprintf( L_FATAL, "clean_line: got too much junk (dev=%s).", Device );
    }
    
    return 0;
}
