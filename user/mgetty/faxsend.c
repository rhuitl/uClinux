#ident "$Id: faxsend.c,v 4.6 1999/03/13 14:06:36 gert Exp $ Copyright (c) 1994 Gert Doering"

/* faxsend.c
 *
 * Send single fax pages using a class 2 or class 2.0 faxmodem.
 * Called by faxrec.c (poll server) and sendfax.c (sending faxes).
 *
 * Depends on "modem_type" being set to Mt_class2_0 for 2.0 support.
 *
 * Eventually add headers to each page.
 *
 * The code is still quite rough, but it works.
 */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "syslibs.h"

#ifndef sunos4
#include <sys/ioctl.h>
#endif
#include <signal.h>

#include "mgetty.h"
#include "tio.h"
#include "policy.h"
#include "fax_lib.h"

static boolean fax_sendpg_timeout = FALSE;

static RETSIGTYPE fax_send_timeout(SIG_HDLR_ARGS)
{
    signal( SIGALRM, fax_send_timeout );	/* reactivate handler */
    
    lprintf( L_WARN, "fax_send: timeout" );
    fax_sendpg_timeout = TRUE;
}

/* DLE ETX: send at end of all fax data to terminate page */

static	char	fax_end_of_page[] = { DLE, ETX };

static void fax_send_panic_exit _P1( (fd), int fd )
{
    lprintf( L_FATAL, "PANIC: timeout sending fax page data, trying force modem reset\n" );

    /* by all means, reset modem */

    /* heavily use alarm(), to make sure nothing blocks */

    /* flush output queue */
    alarm( 5 ); tio_flush_queue( fd, TIO_Q_OUT );

    /* restart possibly suspended output */
    alarm( 5 ); tio_flow( fd, TRUE );

    /* tell modem that the page is finished. Try twice */
    alarm( 5 );	write( fd, fax_end_of_page, sizeof( fax_end_of_page ) );
    
    alarm( 5 );	write( fd, fax_end_of_page, sizeof( fax_end_of_page ) );

    /* Hang up. Various methods */
    alarm( 5 ); write( fd, "AT+FK\r\n", 7 );
    alarm( 5 ); write( fd, "ATH0\r\n", 6 );

    /* Now, try to reset it by lowering DTR */
    alarm( 10 );
    tio_toggle_dtr( fd, 500 );
    delay(500);
    tio_toggle_dtr( fd, 500 );
    delay(500);

    /* try again to hang up + reset it */
    alarm( 5 ); write( fd, "ATH0Z\r\n", 7 );
    delay(500);

    /* if the modem is *still* off-hook, there's nothing we can do. */
    /* Hope that mgetty will be able to reinitialize it */

    alarm( 0 );
    rmlocks();
    exit(15);
}

/* fax_send_page - send one complete fax-G3-file to the modem
 *
 * modem has to be in sync, waiting for at+fdt
 * page punctuation is transmitted according to "ppm"
 * number of bytes transmitted is added to "*bytes_sent" (for statistics)
 */
int fax_send_page _P5( (g3_file, bytes_sent, tio, ppm, fd),
		       char * g3_file, int * bytes_sent, TIO * tio,
		       Post_page_messages ppm, int fd )
{
    int g3fd;
    char ch;
    char buf[256];			/* read chunk */
    char wbuf[ sizeof(buf) * 2 ];	/* worst case: size doubles */

    int w_total = 0;			/* total bytes written */

    int rc;				/* return code */

#ifdef CLASS1
    if ( modem_type == Mt_class1 )
    		return fax1_send_page( g3_file, bytes_sent, tio, ppm, fd );
#endif

    lprintf( L_NOISE, "fax_send_page(\"%s\") started...", g3_file );

    /* disable software output flow control! It would eat the XON otherwise! */
    tio_set_flow_control( fd, tio, (FAXSEND_FLOW) & FLOW_HARD );
    tio_set( fd, tio );

    /* tell modem that we're ready to send - modem will answer
     * with a couple of "+F..." messages and finally CONNECT and XON
     */

    if ( fax_command( "AT+FDT", "CONNECT", fd ) == ERROR ||
	 fax_hangup != 0 )
    {
	lprintf( L_WARN, "AT+FDT -> some error (%d), abort fax send!",
		 fax_hangup_code );
	return ERROR;
    }

    /* alarm handler */
    signal( SIGALRM, fax_send_timeout );

    /* when modem is ready to receive data, it will send us an XON
     * (20 seconds timeout)
     *
     * Not all issues of the class 2 draft require this Xon, and, further,
     * the class 2.0 and 2.1 standard do *not* have it, so it's optional.
     */
    if ( modem_type == Mt_class2 &&
	 ( modem_quirks & MQ_NO_XON ) == 0 )
    {
	lprintf( L_NOISE, "waiting for XON, got:" );

	alarm( 20 );
	do
	{
	    if ( mdm_read_byte( fd, &ch ) != 1 )
	    {
		lprintf( L_ERROR, "timeout waiting for XON" );
		fprintf( stderr, "error waiting for XON!\n" );
		close( fd );
		exit(11);		/*! FIXME! should be done farther up */
	    }
	    lputc( L_NOISE, ch );
	}
	while ( ch != XON );
	alarm(0);
    }					/* end if ( mt == class 2 ) */

    /* Now enable software flow control, if desired, we've got the Xon
     */
    tio_set_flow_control( fd, tio, (FAXSEND_FLOW) & (FLOW_HARD|FLOW_XON_OUT));
    tio_set( fd, tio );

    /* send one page */
    lprintf( L_MESG, "sending %s...", g3_file );

    g3fd = open( g3_file, O_RDONLY );
    if ( g3fd == -1 )
    {
	lprintf( L_ERROR, "cannot open %s", g3_file );
	lprintf( L_WARN, "have to send empty page instead" );
    }
    else
    {
	int r, i, w;
	int w_refresh = 0;
	boolean first = TRUE;

	alarm( 40 );		/* timeout if we get stuck in flow control */

	while ( ( r = read( g3fd, buf, 64 ) ) > 0 )
	{
	    /* refresh alarm counter every 1000 bytes */
	    if ( w_refresh > 1000 )
	    {
		w_refresh -= 1000;
		alarm( 30 );
	    }
	    
	    i = 0;
	    /* skip over GhostScript / digifaxhigh header */

	    if ( first )
	    {
		first = FALSE;
		if ( r >= 64 && strcmp( buf+1,
					"PC Research, Inc" ) == 0 )
		{
		    lprintf( L_MESG, "skipping over GhostScript header" );
		    i = 64;
		    /* for dfax files, we can check if the resolutions match
		     */
		    if ( ( fax_par_d.vr != 0 ) != ( buf[29] != 0 ) )
		    {
			fprintf( stderr, "WARNING: sending in %s mode, fax data is %s mode\n",
				 fax_par_d.vr? "fine" : "normal",
				 buf[29]     ? "fine" : "normal" );
			lprintf( L_WARN, "resolution mismatch" );
		    }
		}
                else
		/* it's incredible how stupid users are - check for */
		/* "tiffg3" files and issue a warning if the file is */
		/* suspect */
                if ( r >= 2 && ( ( buf[0] == 0x49 && buf[1] == 0x49 ) ||
                                 ( buf[0] == 0x4d && buf[1] == 0x4d ) ) )
		{
		    lprintf( L_WARN, "file may be 'tiffg3' - TIFF is *not* a valid input format" );
		    fprintf( stderr, "WARNING: file may be 'tiffg3' - TIFF file format is *not* supported!\n" );
		    fprintf( stderr, "         Thus, fax transmission will most propably fail\n" );
		}   
                else
                if ( r < 10 || buf[0] != 0 )
		{
		    lprintf( L_WARN, "file looks 'suspicious', buf=%02x %02x %02x %02x...", buf[0] &0xff, buf[1] &0xff, buf[2] &0xff, buf[3] &0xff );
                    fprintf( stderr, "WARNING: are you sure that this is a G3 fax file? Doesn't seem to be...\n" );
		}
	    }

	    /* escape DLE characters. If necessary (+FBO=0), swap bits */
	    
	    for ( w = 0; i < r; i++ )
	    {
		wbuf[ w ] = fax_send_swaptable[ (unsigned char) buf[i] ];
		if ( wbuf[ w++ ] == DLE ) wbuf[ w++ ] = DLE;
	    }

	    lprintf( L_JUNK, "read %d, write %d", r, w );

	    if ( write( fd, wbuf, w ) != w )
	    {
		lprintf( L_ERROR, "could not write all %d bytes", w );
	    }

	    /* check for timeout */

	    if ( fax_sendpg_timeout )
	    {
		fax_send_panic_exit( fd );
	    }

	    w_total += w;
	    w_refresh += w;
	    
	    /* look if there's something to read
	     *
	     * normally there shouldn't be anything, but I have
	     * seen very old ZyXEL releases sending junk and then
	     * failing completely... so this may help when debugging
	     *
	     * Also, if you don't use FLOW_SOFT for sendfax, and 
	     * your modem insists on xon/xoff flow control, you'll
	     * see these characters [0x11/0x13] here.
	     */

	    if ( check_for_input( fd ) )
	    {
		lprintf( L_NOISE, "input: got " );
		do
		{
		    /* intentionally don't use mdm_read_byte here */
		    if ( read( fd, &ch, 1 ) != 1 )
		    {
			lprintf( L_ERROR, "read failed" );
			break;
		    }
		    else
			lputc( L_NOISE, ch );
		}
		while ( check_for_input( fd ) );
	    }
	}		/* end while (more g3 data to read) */
	close(g3fd);
    }			/* end if (open file succeeded) */

    lprintf( L_MESG, "page complete, %d bytes sent", w_total );

    if ( bytes_sent != NULL )
            *bytes_sent += w_total;

    /* send end-of-page characters and post-page-message */
    rc = fax_send_ppm( fd, tio, ppm );

    alarm(0);

    return rc;
}

/* send end-of-page code, set fax_page_transmit_status
 *
 * class 2  : send <DLE> <ETX>, then send AT+FET=... according to "type"
 * class 2.0: send <DLE>{<mps>|<eop>|<eom>}, then send AT+FPS?
 */
int fax_send_ppm _P3( (fd, tio, ppm),
		      int fd, TIO * tio, Post_page_messages ppm )
{
    int rc;

    /* set alarm clock to a time long enough to handle *very* slow links
     * on modems with *very* large buffers (2400 / ZyXEL...)
     */
    alarm( FAX_RESPONSE_TIMEOUT );
    
    if ( modem_type == Mt_class2_0 )
    {
	/* in class 2.0, end-of-page *and* page punctuation are
	 * transmitted in one. The modem will return OK or ERROR,
	 * depending on the remote page transmit status
	 */
	/* EIA 592, 8.3.3.7 */
	char ppm_char, ppm_buf[2], *ppm_r;
	
	switch( ppm )
	{
	  case pp_mps:		/* another page next */
	    ppm_char = 0x2c; break;
	  case pp_eom:		/* last page, another document next */
	    ppm_char = 0x3b; break;
	  case pp_eop:		/* no more pages or documents */
	    /* stop being sensitive to DCD drops */
#ifdef sun
	    /* On SUNs, HW handshake has to be off while carrier is low */
	    /* -> to avoid underruns, drain buffers first (Nils Jonsson) */
	    tio_drain_output( fd );
	    tio_set_flow_control(fd, tio, (FAXSEND_FLOW) & FLOW_XON_OUT);
#endif
	    tio_carrier( tio, FALSE );
	    tio_set( fd, tio );

	    ppm_char = 0x2e; break;
	  default:
	    lprintf( L_WARN, "ppm type %d not implemented", ppm );
	    return ERROR;
	}

	lprintf( L_MESG, "sending DLE '" );
	lputc( L_MESG, ppm_char ); lputc( L_MESG, '\'' );
	
	ppm_buf[0] = DLE; ppm_buf[1] = ppm_char;
	if ( write( fd, ppm_buf, 2 ) != 2 )
	{
	    lprintf( L_ERROR, "cannot write PPM" );
	    return ERROR;
	}

	/* FIXME: I think this should be done with fax_wait_for()! */
	do
	{
	    ppm_r = mdm_get_line( fd );
	    if ( ppm_r == NULL ) return ERROR;

	    /* hangup code. See fax_wait_for() for comments */
	    if ( strncmp( ppm_r, "+FHS:", 5 ) == 0 )
	    {
		fax_hangup = 1;
		signal( SIGHUP, SIG_IGN );
		sscanf( &ppm_r[5], "%d", &fax_hangup_code );
		lprintf( L_MESG, "connection hangup: '%s'", ppm_r );
		lprintf( L_NOISE,"(%s)", fax_strerror( fax_hangup_code ));
	    }
	}
	while ( strcmp( ppm_r, "OK" ) != 0 &&
	        strcmp( ppm_r, "ERROR" ) != 0 );
	lprintf( L_MESG, "got response: '%s'", ppm_r );

	/* fax page status is encoded here! */
	/* FIXME: query page tx status from modem */
	fax_page_tx_status = ( strcmp( ppm_r, "OK" ) == 0 ) ? 1: 2;

	/* FIXME: this way? */
/*	fax_command( "AT+FPS?", "OK", fd ); */
	
	return NOERROR;
    }
    else
    {
	/* transmit end of page (<DLE><ETX> -> OK) */

	lprintf( L_MESG, "sending DLE ETX..." );
	write( fd, fax_end_of_page, sizeof( fax_end_of_page ));
	
	if ( fax_wait_for( "OK", fd ) == ERROR ) return ERROR;

	/* transmit page punctuation */

	switch ( ppm )
	{
	  case pp_mps:		/* another page next */
	    rc = fax_command( "AT+FET=0", "OK", fd );
	    break;
	  case pp_eom:		/* last page, another document next */
	    rc = fax_command( "AT+FET=1", "OK", fd );
	    break;
	  case pp_eop:		/* no more pages or documents, over & out */

	    /* take care of modems pulling DCD low before the final
	     * result code has reached the host
	     */
	    tio_carrier( tio, FALSE );
#ifdef sun
	    /* HW handshake has to be off while carrier is low */
	    tio_set_flow_control(fd, tio, (FAXSEND_FLOW) & FLOW_XON_OUT);
#endif
	    tio_set( fd, tio );

	    rc = fax_command( "AT+FET=2", "OK", fd );
	    break;
	  default:		/* pri-xxx codes */
	    lprintf( L_WARN, "ppm type %d not implemented", ppm );
	    rc = ERROR;
	}

	return rc;
    }				/* end if ( ! modem == 2.0 ) */
}
