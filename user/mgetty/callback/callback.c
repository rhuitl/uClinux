#ident "%W% %E% Copyright (c) Gert Doering"

/* callback.c
 *
 * main module of the mgetty based callback / connect terminal (ct) system
 *
 * Operation:
 *   - detach from terminal and controlling process
 *   - find free tty line *which is controlled by mgetty*
 *     (won't work if no mgetty there)
 *   - init modem
 *   - dial out, try different numbers if desired
 *   - upon CONNECT, send mgetty on that line a SIGUSR1 (via MGETTY_PID_FILE)
 *     [if compiled w/o MG_PID_FILE, read utmp and try to find mgetty pid]
 *     + mgetty is in state St_dialout (because a lock file exists)
 *     + in this state, SIGUSR1 means "take the line back from me"
 *     + mgetty reopens the line, sends a SIGUSR1 back (pid of callback
 *       program taken from lock file)
 *     + mgetty overwrites lock file with its own [attention! RACE!]
 *   - wait 5 seconds
 *   - exit
 *     + mgetty sends "Welcome... login:"-prompt
 *     + mgetty calls /bin/login (bypass login.config!!)
 *
 * Use:
 *   - call "callback" from login.config for automatic dial-back
 *   - call "ct" (connect terminal) from the shell
 */

#include <stdio.h>
#include <fcntl.h>
#include "syslibs.h"
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>

#include <signal.h>

#ifndef sunos4
#include <sys/ioctl.h>
#endif

#ifdef NeXT
#include <memory.h>
#endif

#include "mgetty.h"
#include "policy.h"
#include "tio.h"
#include "mg_utmp.h"
#include "version.h"

#include "config.h"
#include "conf_cb.h"

#if (defined(M_XENIX) && !defined(M_UNIX)) || defined(NEXTSGTTY)
#define O_NOCTTY 0
#endif

/* what kind of "surprising" things are recognized */
chat_action_t	dial_chat_actions[] = { { "NO CARRIER", A_FAIL },
					{ "NO DIALTONE",A_FAIL },
					{ "BUSY",	A_FAIL },
					{ "ERROR",	A_FAIL },
					{ "RING\r",	A_FAIL },
					{ NULL,		A_FAIL } };

/* prototypes for system functions (that are missing in some 
 * system header files)
 */
#if !defined(__NetBSD__) && !defined(__OpenBSD__)
time_t		time _PROTO(( time_t * tloc ));
#endif

/* conf_cb.c */
void exit_usage _PROTO((int num));

char	* Device;			/* device to use */
char	* DevID;			/* device name withouth '/'s */

extern time_t	call_start;		/* time when we sent ATA */
					/* defined in faxrec.c */

boolean mgetty_ACK = FALSE;		/* mgetty has ACKed the "take over" */
static RETSIGTYPE sig_mgetty_ack()
{
    signal( SIGUSR1, sig_mgetty_ack );
    lprintf( L_NOISE, "got ACK signal from mgetty" );
    mgetty_ACK = TRUE;
}
boolean timeout = FALSE;
static RETSIGTYPE sig_timer()
{
    signal( SIGALRM, sig_timer );
    lprintf( L_NOISE, "got alarm signal -> huh?" );
    timeout = TRUE;
}
static RETSIGTYPE sig_goodbye _P1 ( (signo), int signo )
{
    lprintf( L_AUDIT, "failed dev=%s, pid=%d, got signal %d, exiting",
	              Device, getpid(), signo );
    rmlocks();
    exit(10);
}

/* find the process ID of the mgetty process monitoring a given line */
int find_mgetty _P1( (device), char * device )
{
    int pid;

/* look in mgetty's PID file (this is the easy way out) */

    char pid_file_name[ MAXPATH ];
    FILE * fp;
    char *DevID, *p;

    /* name mangling for SVR4 systems ("/dev/term/a" -> "term-a") */
    DevID = p = strdup( Device );
    if ( !DevID )
	    { perror( "callback: can't malloc" ); exit(99); }

    while( *p ) { if ( *p == '/' ) *p = '-'; p++; }

    sprintf( pid_file_name, "%s/mgetty.pid.%s", VARRUNDIR, DevID );
    lprintf( L_NOISE, "find_mgetty: look in PID file %s", pid_file_name);

    fp = fopen( pid_file_name, "r" );
    if ( fp == NULL )
    {
	lprintf( L_ERROR, "can't read mgetty pid file %s", pid_file_name );
	return -1;
    }

    if ( fscanf( fp, "%d", &pid ) != 1 )
    {
        lprintf( L_ERROR, "can't read mgetty pid from %s", pid_file_name );
        pid = -1;
    }
    fclose( fp );

    lprintf( L_MESG, "PID for mgetty on line %s: %d", device, pid );
    return pid;
}
    
void detach_tty _P0( void )
{
int r;
    /* detach from controlling tty (close all FD's, get rid of c.tty, ...)
     */
    lprintf( L_MESG, "detaching from ctty..." );
    printf( "\nDialing continues in the background, all further messages will\nbe written to the logfile '" );
    printf( LOG_PATH, "callback" );
    printf( "'.\nPlease look there for errors / diagnostics.\n\n" );
    fflush(stdout);
    tio_drain_output(1); /* make sure data is sent to modem */
    sleep(1);		/* and modem has sent it out */

    switch( fork() )
    {
      case 0:	/* child */
	/* close old tty */
	close(0); close(1); close(2);
#ifndef M_UNIX
	/* detach from controlling tty (we need to get a new one :)) */
	if ( ( r = open( "/dev/tty", O_RDWR ) ) >= 0 )
	{
	    ioctl( r, TIOCNOTTY, NULL );
	    close( r );
	}
#endif
	/* get a new process group */
#if defined(BSD) || defined(sunos4) 
	setpgrp( 0, getpid() );
#else
	setpgrp();
#endif
	break;
      case -1:	/* error */
        perror( "fork failed, can't detach myself" );
        fprintf( stderr, "giving up.\n" );
        exit(4);
      default: /* parent */
        exit(0);
    }
}

/* make file descriptor stdin/stdout/stderr [only]
 */
int fd_make_stddev _P1( (fd), int fd )
{
    if ( fd > 0 )
    {
	(void) close(0);
	if ( dup(fd) != 0 )
	{
	    lprintf( L_ERROR, "can't dup(fd=%d) to stdin", fd );
	    return ERROR;
	}
	close(fd);
    }

    (void) close(1); (void) close(2);

    if ( dup(0) != 1 )
    {
	lprintf( L_ERROR, "can't dup(0) to stdout" ); return ERROR;
    }
    if ( dup(0) != 2 )
    {
	lprintf( L_ERROR, "can't dup(0) to stderr" ); return ERROR;
    }
    return NOERROR;
}
   

/* open device, and set up all terminal parameters properly
 */

int callback_init_device _P1( (dev), char * dev )
{
int fd;
TIO tio;

    fd = open( dev, O_RDWR | O_NDELAY | O_NOCTTY );

    if ( fd == -1 )
    {
	lprintf( L_ERROR, "can't open %s", dev );
	return -1;
    }

    /* set back to non-blocking */
    fcntl( fd, F_SETFL, O_RDWR );

    if ( tio_get( fd, &tio ) == ERROR ) { close(fd); return -1; }
    tio_mode_sane( &tio, TRUE );
    tio_set_speed( &tio, c_int(speed) );
    tio_default_cc( &tio );
    tio_mode_raw( &tio );

#ifdef sun
    tio_set_flow_control( fd, &tio, (DATA_FLOW) & (FLOW_SOFT) );
#else
    tio_set_flow_control( fd, &tio, DATA_FLOW );
#endif

    if ( tio_set( fd, &tio ) == ERROR ) { close(fd); return -1; }

    return fd;
}

/* loop through all devices in "ttys" (separated with ":"),
 * try to lock and open() them, check if mgetty running,
 * return file descriptor or -1
 *
 * if all ttys are locked, try every "rtime" seconds until "end_time"
 * seconds are reached (unix time), then give up.
 *
 * the device opened is stored in "device", the process id of the mgetty
 * process monitoring the line in "*mgetty_pid".
 */
int callback_find_device _P5( (ttys, device, mgetty_pid, rtime, end_time),
			      char * ttys, char * device, int * mgetty_pid,
			      int rtime, int end_time )
{
char * p, *p_help;
int fd;
char tty[MAXLINE];
boolean found_locked;			/* found some tty locked */

    lprintf( L_NOISE, "cbfd: search ttys '%s'", ttys );

    do
    {
	found_locked = FALSE;
	p = ttys;
	while( *p != 0 )
	{
	    p_help = memccpy( tty, p, ':', strlen(p)+1 );

	    if ( p_help != NULL ) { p_help--; *p_help = 0; p++; }
	    p+=strlen(tty);

	    if ( strncmp( tty, "/dev/", 5 ) == 0 ) 
	    {
		strcpy( device, tty );
	    }
	    else
	    {
		if ( tty[0] == '/' )
		{
		    lprintf( L_WARN, "%s: absolute paths must start with /dev, skipping", tty );
		    continue;
		}
		sprintf( device, "/dev/%s", tty );
	    }
	    Device = device+5;	/* device name without "/dev/" */

	    lprintf( L_NOISE, "cbfd: device: '%s'", device );

	    /* try locking */
	    if ( makelock( Device ) != SUCCESS )
	    {
		lprintf( L_MESG, "%s: locked", Device );
		found_locked = TRUE;
		continue;
	    }
	    /* mgetty there? */
	    if ( (*mgetty_pid = find_mgetty( Device )) == -1 )
	    {
		lprintf( L_MESG, "no mgetty on %s, can't use this line", Device );
		rmlocks();
		continue;
	    }
	    /* try open/setup device */
	    if ( ( fd = callback_init_device( device )) == -1 )
	    {
		lprintf( L_MESG, "can't init %s, skipping", Device );
		rmlocks();
		continue;
	    }
	    /* got 'em */
	    return fd;
	}	/* end while( process all ttys ) */

	/* if some locked ttys were seen, we try again later. If none
	 * were found, retrying would be quite useless, so we don't.
	 */
	if ( found_locked )
	{
	    lprintf( L_NOISE, "delaying %d seconds before next try", rtime );
	    sleep(rtime);
	}
    }		
    while( found_locked && time(NULL) < end_time );

    return -1;
}

int dialup _P4((fd, phone, count, end_time), 
		int fd, char ** phone, int count, int end_time )
{
int n;
char dialbuf[MAXLINE];
char * r;

    /* set up timeout watchdog, in case modem dies and does not send
     * anything back to us in the maximum time-to-connect */
    signal( SIGALRM, sig_timer );

    n=0;
    do
    {
	alarm(180);				/* 3 minute timeout */

        lprintf( L_MESG, "dialing %s...", phone[n] );
	sprintf( dialbuf, "%s%s", c_string(dial_prefix), phone[n] );
	mdm_send( dialbuf, fd );

	while( 1 )
	{
	    r = mdm_get_line( fd );
	    if ( r == NULL ) break;

	    lprintf( L_MESG, "dialup: got '%s'", r );

	    if ( strncmp( r, "CONNECT", 7 ) == 0 )
	    {
	        alarm(0); lprintf( L_MESG, "got CONNECT, success!" ); 
		return NOERROR;
	    }
	    if ( strncmp( r, "ERROR", 5 ) == 0 ||
		 strncmp( r, "OK", 2 ) == 0 ||
		 strncmp( r, "BUSY", 4 ) == 0 ||
		 strncmp( r, "NO DIALTONE", 11 ) == 0 ||
		 strncmp( r, "NO CARRIER", 10 ) == 0 ||
		 strncmp( r, "NO ANSWER", 10 ) == 0 )
	    {
		lprintf( L_MESG, "dialup attempt failed, try next number");
		break;
	    }
	}
	alarm(0);

	if ( ++n >= count ) n=0;		/* next phone number */

	sleep( c_int(retry_time) );
    }
    while( time(NULL) < end_time && ! timeout );

    lprintf( L_MESG, "time ran out, giving up" );
    return ERROR;
}

/* provide some "dummy" things for do_chat(), otherwise callback won't link */
/*!!! FIXME - we don't really want this */
int virtual_ring = FALSE;
void cndfind _P1( (p), char * p ) { /* DUMMY */ }

int main _P2((argc, argv), int argc, char ** argv)
{
    char devname[MAXLINE+1];		/* full device name (with /dev/) */
    int		mgetty_pid = -1;	/* pid of mgetty on that device */

    char ** t_numbers;			/* telephone numbers */
    int  t_count;			/* number of numbers */
    char * t_help;
    char phonebuf[40];			/* telephone number entered */

    char buf[MAXLINE+1];

    TIO	tio;
    int fd;
    int i;
    
    time_t	end_time;
    action_t action;

    /* startup
     */

    /* catch all nasty signals, clean up behind, and log...
     */
    (void) signal(SIGHUP, SIG_IGN);
    (void) signal(SIGINT, sig_goodbye);
    (void) signal(SIGQUIT, sig_goodbye);
    (void) signal(SIGTERM, sig_goodbye);

    /* some systems, notable BSD 4.3, have to be told that system
     * calls are not to be automatically restarted after those signals.
     */
#ifdef HAVE_SIGINTERRUPT
    siginterrupt( SIGINT,  TRUE );
    siginterrupt( SIGALRM, TRUE );
    siginterrupt( SIGHUP,  TRUE );
    siginterrupt( SIGUSR1, TRUE );
    siginterrupt( SIGUSR2, TRUE );
#endif

    Device = "unknown";

    /* we *must* run as root to signal mgetty
     */
    if ( geteuid() != 0 )
    {
	fprintf( stderr, "\nSorry, callback must be run as userid \"root\", otherwise it won't work.\n\n" );
	lprintf( L_AUDIT, "fail: non-root user id %d", getuid() );
	exit(2);
    }

    /* process the command line
     */
    callback_parse_args( argc, argv );

    /* remaining command line arguments is/are telephone number(s)
     */
    
    if (optind < argc)	/* phone number given on the command line */
    {
        t_count = argc - optind;
        t_numbers = &argv[optind];
    }
    else		/* read telephone number from stdin */
    {
	lprintf( L_MESG, "reading telephone number from stdin" );

	printf( "Telephone number for callback: " );
	/*!!! FIXME: accept only proper telephone numbers */
	fgets( phonebuf, 30, stdin );

	t_count = 1;
	t_numbers = &t_help;
	t_numbers[0] = phonebuf;

        i = strlen(phonebuf);
	while (i>0 && !isprint(phonebuf[i-1]))
	    phonebuf[--i] = 0;
    }

    /* Initialize Logging */
    sprintf( buf, LOG_PATH, "callback" );
    log_init_paths( argv[0], buf, NULL );
    lprintf( L_NOISE, "callback: %s", mgetty_version );

    lprintf( L_JUNK, "%d telephone numbers given:", t_count );
    for( i=0; i<t_count; i++ ) lprintf( L_JUNK, "#%d: %s", i+1, t_numbers[i] );

    /* read global configuration data (to get device list) */
    callback_get_config( NULL );

    /* this is the last time we try anything [unix time] */
    end_time = time(NULL) + c_int(max_retry_time);

    if ( !c_bool(nodetach) )
	detach_tty();

    /* give init time to restart mgetty (otherwise, "find_device"
     * will complain). This *IS* a race condition :-(
     *
     * Also, wait for a randomized time, to confuse potential attackers.
     */
    srand((unsigned)time(NULL));
    i = c_int(delay) + ( (c_int(delay_rand)>0) ? rand()%c_int(delay_rand)
					       : rand()%5 );
    if (i<4) i=4;
    lprintf( L_NOISE, "delaying %d seconds", i );
    sleep(i);

    /* try each device in turn until we find one that is not locked,
     * can be open()ed, and has an mgetty process monitoring it
     */
    fd = callback_find_device( c_string(ttys), devname, &mgetty_pid,
				c_int(retry_time), end_time );

    if ( fd == -1 )
    {
	lprintf( L_ERROR, "can't get dialout device, exiting" );
	exit(2);
    }

    /*!!! do we really need this? */
    if ( fd_make_stddev( fd ) == ERROR )
    {
	lprintf( L_ERROR, "can't make stdin/stdout/sterr, exiting" );
	exit(2);
    }
    fd=0; /* use stdin from now on */

    /* switch off stdio buffering */
    setbuf( stdin,  (char *) NULL );
    setbuf( stdout, (char *) NULL );
    setbuf( stderr, (char *) NULL );

    /* set log "infix" according to device name */
    log_init_paths( NULL, NULL, &Device[strlen(Device)-3] );

    /* read device specific configuration file
     */
    callback_get_config( Device );

    /* make a short (+randomized!) pause, giving mgetty enough time
     * to initialize modem, and making "spoofing" harder
     */

    /* init modem
     */
    lprintf( L_MESG, "initializing modem..." );
    if ( do_chat( fd, c_chat(modem_init), 
                  dial_chat_actions, &action, 10, TRUE ) != SUCCESS )
    {
        if ( action == A_TIMOUT )
        {
	    lprintf( L_ERROR, "Error: modem does not answer, giving up!" ); 
	    return ERROR;
	}
	lprintf( L_WARN, "modem init failed: expect problems." );
    }

    /* dial all numbers, in turn, until CONNECT is established
     * if no connection is made on first turn, sleep 60 seconds, and try again
     */
    if ( dialup( fd, t_numbers, t_count, end_time ) == ERROR )
    {
	lprintf( L_ERROR, "can't dial any of the given numbers, exiting" );
	exit(10);
    }

    /* connection is made
     */

#if 0
    /* drain input - make sure there are no leftover "NO CARRIER"s
     * or "ERROR"s lying around from some previous dial-out
     */

    clean_line( STDIN, 1);

    /* wait .3s for line to clear (some modems send a \n after "OK",
       this may confuse the "call-chat"-routines) */

    clean_line( STDIN, 3);

    /* sleep... waiting for activity */

    /* wait for line to clear (after "CONNECT" a baud rate may
       be sent by the modem, on a non-MNP-Modem the MNP-request
       string sent by a calling MNP-Modem is discarded here, too) */
    
    clean_line( STDIN, 3);

#endif
    /* honor carrier now: terminate if modem hangs up prematurely
     */
    tio_get( STDIN, &tio );
    tio_carrier( &tio, TRUE );
    tio_set( STDIN, &tio );
    
    /* wait a little bit, then print "pre-welcome" message
     */
    delay( c_int(prompt_waittime) );

    printf( "Connection established, please wait...\r\n" );

    /* wait for data to be sent to modem before charging ahead...
     */
    tio_drain_output( STDIN );
    delay( 300 );

    /* signal mgetty, wait for answer, die peacefully.
     */
    signal( SIGUSR1, sig_mgetty_ack );

    if ( kill( mgetty_pid, SIGUSR1 ) < 0 )
    {
        lprintf( L_ERROR, "can't signal mgetty process %d, giving up",
		 mgetty_pid);
        printf( "Fatal error: can't pass control, hanging up.\r\n" );
        sleep(5);
        exit(5);
    }

    signal( SIGALRM, sig_timer );
    alarm(30);
    pause();		/* just sleep until SIGALRM or SIGUSR1 arrives */
    alarm(0);

    if ( timeout || !mgetty_ACK )
    {
        lprintf( L_FATAL, "wait_ack: something went wrong, didn't get ACK in time" );
        printf( "Fatal error: can't pass control, hanging up.\r\n" );
	sleep(5);
        exit(5);
    }

    lprintf( L_AUDIT, "callback: success, device=%s, mgetty=%d", devname, mgetty_pid );
    return 0;
}

