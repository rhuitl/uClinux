#ident "$Id: sendfax.c,v 4.18 2001/12/17 22:31:52 gert Exp $ Copyright (c) Gert Doering"

/* sendfax.c
 *
 * Send a Fax using a class 2 faxmodem.
 * Calls routines in faxrec.c and faxlib.c
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
#include <sys/types.h>
#ifndef ENOENT
# include <errno.h>
#endif

#include "version.h"
#include "mgetty.h"
#include "tio.h"
#include "policy.h"
#include "fax_lib.h"

/* configuration */
#include "config.h"
#include "conf_sf.h"

/* use direct bit order in modem, that means, we have to reverse */
#define REVERSE 1

char * fac_tel_no;
boolean	verbose = FALSE;
extern time_t	call_start;			/* for accounting */

/* seems to missing nearly everywhere */
#if !defined(__NetBSD__) && !defined(__OpenBSD__)
time_t	time _PROTO(( time_t * tloc ));
#endif

void exit_usage _P2( (program, msg ),
		     char * program, char * msg )
{
    if ( msg != NULL )
    {
	lprintf( L_ERROR, "exit_usage: %s", msg );
        fprintf( stderr, "%s: %s\n", program, msg );
    }
    
    fprintf( stderr,
	     "usage: %s [options] <fax-number> <page(s) in g3-format>\n", program);
    fprintf( stderr,
	     "\tvalid options: -p, -v, -l <device(s)>, -x <debug>, -n, -S, -r, -D <x>\n");
    lprintf( L_AUDIT, "failed: command line error" );
    exit(1);
}

TIO fax_tio;
char *Device = "unset";

int fax_open_device _P2( (fax_tty, use_stdin),
			 char * fax_tty, boolean use_stdin )
{
    char	device[MAXPATH];
    int	fd;

    if ( use_stdin )			/* fax modem on stdin */
    {
	fd = 0;
	Device = ttyname(fd);		/* for faxrec() */
	if ( Device == NULL || *Device == '\0' ) Device = "unknown";
    }
    else
    {
	int tries;
	
	/* ignore leading "/dev/" prefix */
	if ( strncmp( fax_tty, "/dev/", 5 ) == 0 ) fax_tty += 5;
	
	if ( verbose ) printf( "Trying fax device '/dev/%s'... ", fax_tty );

	tries = 0;
	while ( makelock( fax_tty ) != SUCCESS )
	{
	    if ( ++ tries < 3 )
	    {
	        if ( verbose ) { printf( "locked... " ); fflush( stdout ); }
		sleep(5);
	    }
	    else
	    {
	        if ( verbose ) { printf( "locked, give up!\n" );
				 fflush( stdout ); }
		lprintf( L_MESG, "cannot lock %s", fax_tty );
		return -1;
	    }
	}
	
	sprintf( device, "/dev/%s", fax_tty );

	if ( ( fd = open( device, O_RDWR | O_NDELAY ) ) == -1 )
	{
	    lprintf( L_ERROR, "error opening %s", device );
	    if ( verbose ) printf( "cannot open!\n" );
	    rmlocks();
	    return fd;
	}

	/* make device name externally visible (faxrec())
	 * we have to dup() it, because caller will change fax_tty
	 */
	Device = malloc( strlen(fax_tty)+1 );
	if ( Device == NULL )
	    { perror( "sendfax: can't malloc" ); exit(2); }
	strcpy(Device, fax_tty);
    }

    /* unset O_NDELAY (otherwise waiting for characters */
    /* would be "busy waiting", eating up all cpu) */

    if ( fcntl( fd, F_SETFL, O_RDWR ) == -1 )
    {
	lprintf( L_ERROR, "error in fcntl" );
	close( fd );
	if ( verbose ) printf( "cannot fcntl!\n" );
	rmlocks();
	return -1;
    }

    /* initialize baud rate, hardware handshake, ... */
    tio_get( fd, &fax_tio );

    /* even if we use a modem that requires Xon/Xoff flow control,
     * do *not* enable it here - it would interefere with the Xon
     * received at the top of a page.
     */
    tio_mode_sane( &fax_tio, TRUE );
    tio_set_speed( &fax_tio, c_int(speed) );
    tio_mode_raw( &fax_tio );
#ifdef sun
    /* sunos does not rx with RTSCTS unless carrier present */
    tio_set_flow_control( fd, &fax_tio, FLOW_NONE );
#else
    tio_set_flow_control( fd, &fax_tio, (FAXSEND_FLOW) & FLOW_HARD );
#endif
    
    if ( tio_set( fd, &fax_tio ) == ERROR )
    {
	lprintf( L_ERROR, "error in tio_set" );
	close( fd );
	if ( verbose ) printf( "cannot set termio values!\n" );
	rmlocks();
	return -1;
    }

    /* reset parameters */
    fax_to_poll = FALSE;

    fax_remote_id[0] = 0;
    fax_param[0] = 0;

    if ( use_stdin )
    {
	lprintf( L_NOISE, "fax_open_device, fax on stdin" );
    }
    else
    {
	log_init_paths( NULL, NULL, &fax_tty[ strlen(fax_tty)-3 ] );
	lprintf( L_NOISE, "fax_open_device succeeded, %s -> %d", fax_tty, fd );
    }
    
    if ( verbose ) printf( "OK.\n" );

    return fd;
}

/* fax_open: loop through all devices in fax_ttys until fax_open_device()
 * succeeds on one of them; then return file descriptor
 * return "-1" of no open succeeded (all locked, permission denied, ...)
 */

int fax_open _P2( (fax_ttys, use_stdin),
	      char * fax_ttys, boolean use_stdin )
{
char * p, * fax_tty;
int fd;

    p = fax_tty = fax_ttys;
    do
    {
	p = strchr( fax_tty, ':' );
	if ( p != NULL ) *p = 0;
	fd = fax_open_device( fax_tty, use_stdin );
	if ( p != NULL ) *p = ':';
	fax_tty = p+1;
    }
    while ( p != NULL && fd == -1 );
    return fd;
}

/* finish off - close modem device, rm lockfile */

void fax_close _P1( (fd),
		    int fd )
{
    tio_flush_queue( fd, TIO_Q_BOTH );		/* unlock flow ctl. */
    fax_send( "AT+FCLASS=0", fd );
    delay(500);
    tio_flush_queue( fd, TIO_Q_BOTH );		/* unlock flow ctl. */
    close( fd );
    rmlocks();
}


/* sendfax-specific fax initializations */

/* polling: set calling station ID, receiver on, local poll on */

static int faxpoll_client_init _P2( (fd, cid), int fd, char * cid )
{
    char buf[60];

    if ( modem_type == Mt_class2_0 )
    {
	sprintf( buf, "AT+FPI=\"%.40s\"", cid );
	if ( mdm_command( buf, fd ) == ERROR ) return ERROR;
        if ( mdm_command( "AT+FSP=1", fd ) == ERROR ) return ERROR;
    }
    else
    {
	sprintf( buf, "AT+FCIG=\"%.40s\"", cid );
	if ( mdm_command( buf, fd ) == ERROR ) return ERROR;
	if ( mdm_command( "AT+FSPL=1", fd ) == ERROR ) return ERROR;
    }
    if ( mdm_command( "AT+FCR=1", fd ) == ERROR ) return ERROR;

    return NOERROR;
}


RETSIGTYPE fax_sig_goodbye _P1( (signo), int signo )
{
    if ( call_start == 0 ) call_start = time(NULL);
    
    lprintf( L_AUDIT, 
	     "failed: got signal %d, pid=%d, dev=%s, time=%ds, acct=\"%s\"", 
	     signo, getpid(), Device,
	     ( time(NULL)-call_start ), c_string(acct_handle));
    rmlocks();
    exit(15);				/* will close the fax device */
}

int main _P2( (argc, argv),
	      int argc, char ** argv )
{
    int	argidx;
    int	fd;
    char buf[1000];
    int	i;
    int	tries;			/* number of unsuccessful tries */

    int	total_bytes = 0;	/* number of bytes sent */
    int total_pages = 0;	/* number of pages (files) sent */
    int total_resent= 0;	/* number of pages resent */


    /* initialize logging */
    log_init_paths( argv[0], FAX_LOG, NULL );

    /* parse switches (-> conf_sf.c) and read global config file */
    if ( sendfax_parse_args( argc, argv ) == ERROR )
    {
	exit_usage( argv[0], NULL );
    }

    /* read config file (defaults) */
    sendfax_get_config( NULL );

    lprintf( L_MESG, "sendfax: %s", mgetty_version );
    lprintf( L_NOISE, "%s compiled at %s, %s", __FILE__, __DATE__, __TIME__ );

    /* for simplicity, put a few config things into global variables */
    verbose = c_bool( verbose );

    argidx = optind;

    /* fax number given? */
    if ( argidx == argc )
    {
	exit_usage( argv[0], "no fax number specified" );
    }
    fac_tel_no = argv[ argidx++ ];

    lprintf( L_MESG, "sending fax to %s", fac_tel_no );

    /* check, if all the arguments passed are normal files and
     * readable
     */
    for ( i=argidx; i<argc; i++ )
    {
	lprintf( L_MESG, "checking %s", argv[i] );
	if ( access( argv[i], R_OK ) == -1 )
	{
	    if ( errno == ENOENT && i == argidx 	/* first file */
		 && c_bool( rename_files ) )		/* and '-r' set */
	    {
		argidx++; continue;    			/* just skip */
	    }
	    
	    lprintf( L_ERROR, "cannot access %s", argv[i] );
	    fprintf( stderr, "%s: cannot access %s\n", argv[0], argv[i]);
	    exit(1);
	}
    }

    /* check if any files specified / left */
    if ( ! c_bool(fax_poll_wanted) && argidx == argc )
    {
	exit_usage( argv[0], "no files to send" );
    }

    /* if modem on stdin, shut off blurb */
    if ( c_bool(use_stdin) ) verbose = FALSE;
    
    fd = fax_open( c_string(ttys), c_bool(use_stdin) );

    if ( fd == -1 )
    {
	lprintf( L_AUDIT, "failed: can't get modem (locked/permissions)");
	fprintf( stderr, "%s: cannot access fax device(s) (locked?)\n", argv[0] );
	exit(2);
    }

    /* read config file (port specific) */
    sendfax_get_config( Device );

    /* sanity checks */
    if ( strcmp( c_string(modem_type), "cls2" ) != 0 &&
	 strcmp( c_string(modem_type), "c2.0" ) != 0 &&
	 strcmp( c_string(modem_type), "cls1" ) != 0 &&
	 strncmp(c_string(modem_type), "auto", 4) != 0 )
    {
	fprintf( stderr, "%s: warning: invalid modem class '%s'\n",
		 argv[0], c_string(modem_type) );
    }

    /* arrange that lock files get removed if INTR or QUIT is pressed */
    signal( SIGINT, fax_sig_goodbye );
    signal( SIGQUIT, fax_sig_goodbye );
    signal( SIGTERM, fax_sig_goodbye );

#ifdef HAVE_SIGINTERRUPT
    /* interruptible system calls */
    siginterrupt( SIGINT,  TRUE );
    siginterrupt( SIGALRM, TRUE );
    siginterrupt( SIGHUP,  TRUE );
#endif

    /* now set speed for this port (do this *after* sendfax_get_config())!
     */
    if ( tio_set_speed( &fax_tio, c_int(speed) ) == ERROR ||
         tio_set( fd, &fax_tio ) == ERROR )
    {
	fprintf( stderr, "%s: cannot set serial port speed %d on \"%s\"\n",
			argv[0], c_int(speed), Device );
	close(fd);
	rmlocks();
	lprintf( L_AUDIT, "failed: tio_set*, dev=%s, acct=\"%s\"", 
		     Device, c_string(acct_handle));
	exit(2);
    }

    /* some modems send an "OK" after DTR is raised - catch it
     */
    if ( c_isset(open_delay) )
    {
	lprintf( L_NOISE, "pausing %d ms", c_int(open_delay));
	delay(c_int(open_delay));		/* give modem time to settle */
    }
    tio_flush_queue(fd, TIO_Q_BOTH);		/* clear junk */

    /* Is there a modem...? */
    if ( mdm_command( "ATV1Q0", fd ) == ERROR )
    {
	/* no??!? -- try again, maybe modem was just unwilling... */
	if ( mdm_command( "ATV1Q0", fd ) == ERROR )
	{
	    lprintf( L_AUDIT, "failed initializing modem, dev=%s, acct=\"%s\"",
		     Device, c_string(acct_handle) );
	    fprintf( stderr, "The modem doesn't respond!\n" );
	    tio_flush_queue( fd, TIO_Q_BOTH );	/* unlock flow ctl. */
	    close(fd);
	    rmlocks();
	    exit(3);
	}
	lprintf( L_WARN, "retry succeded, dev=%s", Device );
    }

    /* extra initialization: -m / modem-init */
    if ( c_isset(modem_init) )
    {
	if ( strncmp( c_string(modem_init), "AT", 2 ) != 0 )
	{
	    write( fd, "AT", 2 );
	}

	if ( fax_command( c_string(modem_init), "OK", fd ) == ERROR )
	{
	    lprintf( L_WARN, "cannot send extra modem init string '%s'",
		    c_string(modem_init) );
	    fprintf( stderr, "%s: modem doesnt't accept '%s'\n",
		    argv[0], c_string(modem_init) );
	    fax_close( fd );
	    exit(3);
	}
    }		/* end if (c_isset(modem_init)) */

    /* get modem type (class 2 / class 2.0), switch modem to fax mode */

    if ( (modem_type = 
	  fax_get_modem_type( fd, c_string(modem_type) ) ) == Mt_unknown )
    {
	lprintf( L_AUDIT, "failed: modem type unknown, dev=%s", Device);
	fprintf( stderr, "%s: cannot set modem to fax mode\n", argv[0] );
	fax_close( fd );
	exit( 3 );
    }

    if ( modem_type == Mt_data )
    {
	lprintf( L_AUDIT, "failed: no class 2/2.0 fax modem, dev=%s", Device);
	fprintf( stderr, "%s: not a class 2/2.0 fax modem\n", argv[0] );
	fax_close( fd );
	exit( 3 );
    }

    /* some modems need a baud rate switch after +FCLASS=2,
     * see policy.h for details
     */
    if ( c_isset(switchbd) && c_int(switchbd) != 0 &&
	 c_int(switchbd) != c_int(speed) )
    {
	lprintf( L_MESG, "switchbd: change to %d", c_int(switchbd) );
	tio_set_speed( &fax_tio, c_int(switchbd) );
	tio_set( fd, &fax_tio );
    }

    if ( fax_set_l_id( fd, c_string(station_id) ) == ERROR )
    {
	lprintf( L_AUDIT, "failed: cannot set fax station ID, dev=%s", Device);
	fprintf( stderr, "%s: cannot set fax station ID\n", argv[0] );
	fax_close( fd );
	exit(3);
    }

    /* set desired resolution, maximum and minimum bit rate */

    /* FIXME: ask modem if it can do 14400 bps / fine res. at all */
    fax_set_fdcc( fd, !c_bool(normal_res), c_int(fax_max_speed), 0 );

#if REVERSE
    fax_set_bor( fd, 0 );
#else
    fax_set_bor( fd, 1 );
#endif

    /* AT+FNR=... is necessary in class 2.0 to make the modem tell us 
     * about the remote fax ID, transmission speed, NSFs, etc.
     */
    if ( modem_type == Mt_class2_0 )
	mdm_command( (modem_quirks & MQ_SHOW_NSF)? "AT+FNR=1,1,1,1"
						 : "AT+FNR=1,1,1,0", fd );

    /* tell the modem if we are willing to poll faxes
     */
    if ( c_bool(fax_poll_wanted) )
    {
	if ( faxpoll_client_init( fd, c_string(station_id) ) == ERROR )
	{
	    lprintf( L_WARN, "cannot enable polling" );
	    fprintf( stderr, "Warning: polling is not possible!\n" );
	    conf_set_bool( &c.fax_poll_wanted, FALSE );
	}
    }

    /* set modem to use desired flow control type, dial out
     */
    if ( fax_set_flowcontrol( fd, (FAXSEND_FLOW) & FLOW_HARD ) == ERROR )
    {
	lprintf( L_WARN, "cannot set modem flow control" );
    }

    if ( c_isset( modem_handshake ) && 
	 strlen( c_string(modem_handshake) ) != 0 &&
	 mdm_command( c_string(modem_handshake), fd ) == ERROR )
    {
	lprintf( L_WARN, "cannot set 'modem_handshake'; ignored" );
    }

    if ( verbose ) { printf( "Dialing %s... ", fac_tel_no ); fflush(stdout); }

    call_start = time( NULL );

    sprintf( buf, "%s%s", c_string(dial_prefix), fac_tel_no );

#ifdef CLASS1
    if ( modem_type == Mt_class1 )
        i = fax1_dial_and_phase_AB( buf, fd );
    else
#endif
        i = fax_command( buf, "OK", fd );

    if ( i == ERROR )
    {
	lprintf( L_AUDIT, "failed dialing, phone=\"%s\", +FHS:%02d, dev=%s, time=%ds, acct=\"%s\"",
		 fac_tel_no, fax_hangup_code, Device,
		 ( time(NULL)-call_start ), c_string(acct_handle) );

	/* close fax line */
	fax_close( fd );
	
	/* print message, and end program -
	   return codes signals kind of dial failure */
	
	if ( fax_hangup_code == FHUP_BUSY ||	/* BUSY */
	     fax_hangup_code == 3 ||		/* no loop current */
	     fax_hangup_code == 4 )		/* ringing, no answer */
	{
	    if ( verbose )
	        printf( "dial failed (BUSY/NO ANSWER)\n" );
	    exit(4);
	}
	else if ( fax_hangup_code == FHUP_NODIAL )
	{
	    if ( verbose )
	        printf( "dial failed (NO DIALTONE)\n" );
	    exit(5);
	}
	else
	{
	    fprintf( stderr, "\n%s: dial %s failed (ERROR / NO CARRIER)\n",
		     argv[0], fac_tel_no );
	    exit(10);
	}
    }
    if ( verbose ) printf( "OK.\n" );

    if ( c_bool( ignore_carrier ))	/* ignore carrier */
    {
	lprintf( L_MESG, "sendfax: IGNORE DCD (carrier) status" );
    }
    else				/* honour carrier */
    {
	/* by now, the modem should have raised DCD, so remove CLOCAL flag */
	tio_carrier( &fax_tio, TRUE );

#ifdef sun
	/* now we can request hardware flow control since we have carrier */
	tio_set_flow_control( fd, &fax_tio, (FAXSEND_FLOW) & (FLOW_HARD|FLOW_XON_OUT) );
#endif	/* sun */
	tio_set( fd, &fax_tio );

	lprintf( L_MESG, "sendfax: honouring DCD (carrier) drops now" );
    }

    total_pages = argc-argidx;		/* for statistics */

    /* process all files to send / abort, if Modem sent +FHNG result */

    tries = 0;
    while ( argidx < argc )
    {
	Post_page_messages ppm;
	
	/* send page header, if requested */
	if ( c_string(fax_page_header) )
	{
#if 0
	    if ( fax_send_page( c_string(fax_page_header), fd ) == ERROR )
		 break;
#else
	    fprintf( stderr, "WARNING: no page header is transmitted. Does not work yet!\n" );
#endif
	}

	/* send page */
	if ( verbose ) printf( "sending '%s'...\n", argv[ argidx ] );

	/* how to continue after page? */

	if ( argidx == argc -1 )	/* last page to send */
	{
	    if ( c_bool(fax_poll_wanted) &&	/* do we want to poll? */
		 fax_to_poll )			/* yeah!! */
	        ppm = pp_eom;		/* another doc. next (->phase B) */
	    else
	        ppm = pp_eop;		/* over & out (->hangup) */
	}
	else				/* not last page -> */
	        ppm = pp_mps;		/* another page next */
	
	fax_page_tx_status = -1;	/* set by fax_send_page() */

	if ( fax_send_page( argv[ argidx ],
			    &total_bytes, &fax_tio, ppm, fd ) == ERROR )
	{
	    break;
	}

	/* after the page punctuation command, the modem
	 * will send us a +FPTS:<ppm> page transmit status.
	 * The ppm value is written to fax_page_tx_status by
	 * fax_send_page() / fax_send_ppm()
	 * If the other side requests retransmission, do so.
	 */

	switch ( fax_page_tx_status )
	{
	  case 1: break;			/* page good */
						/* page bad - r. req. */
	  case 2:
	    if ( c_int(max_tries) <= 0 )	/* ignore */
	    {
		fprintf( stderr, "WARNING: page bad (RTN), ignoring\n" );
		lprintf( L_WARN, "WARNING: RTN ignored\n" );
	    }
	    else				/* try again */
	    {
		fprintf( stderr, "ERROR: RTN: page bad - retrain requested\n" );
		tries ++;	
		if ( tries >= c_int(max_tries) )	/* max tries reached */
		{
		    if ( c_bool(max_tries_ctd) )	/* go on */
		    {
			fprintf( stderr, "WARNING: maximum number of retries reached, going on\n" );
			lprintf( L_WARN, "max. tries (%d) reached, going on", tries );
		    }
		    else				/* abort */
		    {
			fprintf( stderr, "ERROR: too many retries - aborting send\n" );
			fax_hangup_code = -1;
			fax_hangup = 1;
		    }
		}
		else
		{
		    if ( verbose )
		       printf( "sending page again (retry %d)\n", tries );
		    total_resent++;
		    continue;	/* don't go to next page */
		}
	    }
	    break;
	  case 3: fprintf( stderr, "WARNING: RTP: page good, but retrain requested\n" );
		    break;
	  case 4:
	  case 5: fprintf( stderr, "WARNING: procedure interrupt requested - don't know how to handle it\n" );
		    break;
	  case -1:			/* something broke */
		  lprintf( L_WARN, "fpts:-1" );
		  break;
	  default:fprintf( stderr, "WARNING: invalid code: +FPTS:%d\n",
				   fax_page_tx_status );
		  break;
	}

	if ( fax_hangup && fax_hangup_code != 0 ) break;

	/* page transmitted successfully, rename file to ".done" */
	if ( c_bool( rename_files ) )
	{
	    char done[MAXPATH+6];
	    if ( strlen( argv[argidx] ) > sizeof(done)-6 )
	        fprintf( stderr, "file name %s too long\n", argv[argidx] );
	    else
	    {
		sprintf( done, "%s.done", argv[argidx] );
		if ( rename( argv[argidx], done ) == -1 )
		    lprintf( L_ERROR, "can't rename work file to %s", done );
	    }
	}
	
	argidx++;		/* next page */
	tries=0;		/* no tries yet */
    }				/* end main page loop */

    if ( argidx < argc || ( fax_hangup && fax_hangup_code != 0 ) )
    {
	lprintf( L_AUDIT, "failed transmitting %s: phone=\"%s\", +FHS:%02d, dev=%s, time=%ds, acct=\"%s\"",
		 argv[argidx], fac_tel_no, fax_hangup_code, Device,
		 ( time(NULL)-call_start ), c_string(acct_handle) );

	fprintf( stderr, "\n%s: FAILED to transmit '%s'.\n",
		         argv[0], argv[argidx] );

	if ( fax_hangup_code == -1 )
	    fprintf( stderr, "(number of tries exhausted)\n" );
	else
	    fprintf( stderr, "Transmission error: +FHNG:%2d (%s)\n",
			     fax_hangup_code,
			     fax_strerror( fax_hangup_code ) );
	fax_close( fd );
	exit(12);
    }

    /* OK, handle (optional) fax polling now.
     * Fax polling will only be tried if user specified "-p" and the
     * faxmodem sent us a "+FPOLL" response
     */

    if ( c_bool(fax_poll_wanted) )
    {
    int pagenum = 0;

	if ( verbose ) printf( "starting fax poll\n" );

	if ( ! fax_to_poll )
	{
	    printf( "remote does not have document to poll!\n" );
	}
	else
	{
	    /* class 2.0 modems use the correct byte order, Rockwell-
	     * compatible class 2 modems get it wrong.
	     */
	    if ( modem_type == Mt_class2_0 ) fax_set_bor( fd, 1 );
	    
	    /* switch to fax receiver flow control */
	    tio_set_flow_control( fd, &fax_tio,
				 (FAXREC_FLOW) & (FLOW_HARD|FLOW_XON_IN) );
	    tio_set( fd, &fax_tio );
	    if ( fax_get_pages( fd, &pagenum, c_string(poll_dir),
			        -1, -1, -1 ) == ERROR )
	    {
		fprintf( stderr, "warning: polling failed\n" );
		lprintf( L_AUDIT, "failed: polling failed, phone=\"%s\", +FHS:%02d, dev=%s, time=%ds, acct=\"%s\"",
			 fac_tel_no, fax_hangup_code, Device,
			 ( time(NULL)-call_start ), c_string(acct_handle) );
		fax_close( fd );
		exit(12);
	    }
	}
	if ( verbose ) printf( "%d pages successfully polled!\n", pagenum );
    }

    fax_close( fd );

    lprintf( L_AUDIT, "success, phone=\"%s\", dev=%s, time=%ds, pages=%d(+%d), bytes=%d, acct=\"%s\"",
	              fac_tel_no, Device, ( time(NULL)-call_start ),
	              total_pages, total_resent, total_bytes,
	              c_string(acct_handle) );
    return 0;
}
