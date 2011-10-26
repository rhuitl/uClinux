#ident "$Id: modem.c,v 4.4 1997/12/05 23:48:08 gert Exp $ Copyright (c) Gert Doering"

/* modem.c
 *
 * Module containing *very* basic modem functions
 *   - send a command
 *   - get a response back from the modem
 *   - send a command, wait for OK/ERROR response
 */

#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include "mgetty.h"
#include "policy.h"

/* get one line from the modem, only printable characters, terminated
 * by \r or \n. The termination character is *not* included
 */

char * mdm_get_line _P1( (fd), int fd )
{
    static char buffer[200];
    int bufferp;
    char c;
    
    bufferp = 0;
    lprintf( L_JUNK, "got:" );
    
    do
    {
	if( mdm_read_byte( fd, &c ) != 1 )
	{
	    lprintf( L_ERROR, "mdm_get_line: cannot read byte, return" );
	    return NULL;
	}

	lputc( L_JUNK, c );

	if ( isprint( c ) &&
	     bufferp < sizeof(buffer) )
	{
	    buffer[ bufferp++ ] = c;
	}
    }
    while ( bufferp == 0 || ( c != 0x0a && c != 0x0d ) );

    buffer[bufferp] = 0;

    return buffer;
}

/* wait for a given modem response string,
 * handle all the various class 2 / class 2.0 status responses
 */

static boolean fwf_timeout = FALSE;

static RETSIGTYPE fwf_sig_alarm(SIG_HDLR_ARGS)      	/* SIGALRM handler */
{
    signal( SIGALRM, fwf_sig_alarm );
    lprintf( L_WARN, "Warning: got alarm signal!" );
    fwf_timeout = TRUE;
}

/* send a command string to the modem, terminated with the
 * MODEM_CMD_SUFFIX character / string from policy.h
 */

int mdm_send _P2( (send, fd),
		  char * send, int fd )
{
#ifdef DO_CHAT_SEND_DELAY
    delay(DO_CHAT_SEND_DELAY);
#endif

    lprintf( L_MESG, "mdm_send: '%s'", send );

    if ( write( fd, send, strlen( send ) ) != strlen( send ) ||
	 write( fd, MODEM_CMD_SUFFIX, sizeof(MODEM_CMD_SUFFIX)-1 ) !=
	        ( sizeof(MODEM_CMD_SUFFIX)-1 ) )
    {
	lprintf( L_ERROR, "mdm_send: cannot write" );
	return ERROR;
    }

    return NOERROR;
}

/* simple send / expect sequence, for things that do not require
 * parsing of the modem responses, or where the side-effects are
 * unwanted.
 */

int mdm_command _P2( (send, fd), char * send, int fd )
{
    char * l;
    
    if ( mdm_send( send, fd ) == ERROR ) return ERROR;

    /* wait for OK or ERROR, *without* side effects (as fax_wait_for
     * would have)
     */
    signal( SIGALRM, fwf_sig_alarm ); alarm(10); fwf_timeout = FALSE;

    do
    {
	l = mdm_get_line( fd );
	if ( l == NULL ) break;
	lprintf( L_NOISE, "mdm_command: string '%s'", l );
    }
    while ( strcmp( l, "OK" ) != 0 && strcmp( l, "ERROR" ) != 0 );

    alarm(0); signal( SIGALRM, SIG_DFL );
    
    if ( l == NULL || strcmp( l, "ERROR" ) == 0 )
    {
	lputs( L_MESG, " -> ERROR" );
	return ERROR;
    }
    lputs( L_MESG, " -> OK" );
	
    return NOERROR;
}

/* mdm_read_byte
 * read one byte from "fd", with buffering
 * caveat: only one fd allowed (only one buffer), no way to flush buffers
 */

int mdm_read_byte _P2( (fd, c),
		       int fd, char * c )
{
static char frb_buf[512];
static int  frb_rp = 0;
static int  frb_len = 0;

    if ( frb_rp >= frb_len )
    {
	frb_len = read( fd, frb_buf, sizeof( frb_buf ) );
	if ( frb_len <= 0 )
	{
	    if ( frb_len == 0 ) errno = 0;	/* undefined otherwise */
	    lprintf( L_ERROR, "mdm_read_byte: read returned %d", frb_len );
	    return frb_len;
	}
	frb_rp = 0;
    }

    *c = frb_buf[ frb_rp++ ];
    return 1;
}

/* for modem identify (and maybe other nice purposes, who knows)
 * this function is handy:
 * - send some AT command, wait for OK/ERROR or 10 seconds timeout
 * - return a pointer to a static buffer holding the "nth" non-empty
 *   answer line from the modem (for multi-line responses), or the 
 *   last line if n==-1
 */
char * mdm_get_idstring _P3( (send, n, fd), char * send, int n, int fd )
{
    char * l; int i;
    static char rbuf[80];

    if ( mdm_send( send, fd ) == ERROR ) return "<ERROR>";

    /* wait for OK or ERROR, *without* side effects (as fax_wait_for
     * would have)
     */
    signal( SIGALRM, fwf_sig_alarm ); alarm(10); fwf_timeout = FALSE;

    i=0;
    rbuf[0] = '\0';

    while(1)
    {
	l = mdm_get_line( fd );

	if ( l == NULL ) break;				/* error */
	if ( strcmp( l, send ) == 0 ) continue;		/* command echo */

        if ( strcmp( l, "OK" ) == 0 ||			/* final string */
	     strcmp( l, "ERROR" ) == 0 ) break;

        i++;
	lprintf( L_NOISE, "mdm_gis: string %d: '%s'", i, l );

	if ( i==-1 || i==n )		/* copy string */
	    { strncpy( rbuf, l, sizeof(rbuf)-1); rbuf[sizeof(rbuf)-1]='\0'; }
    }

    alarm(0); signal( SIGALRM, SIG_DFL );
    
    if ( l == NULL ) return "<ERROR>";			/* error */

    return rbuf;
}
