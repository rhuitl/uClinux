#ident "$Id: mgetty.c,v 4.36 2003/11/17 19:08:20 gert Exp $ Copyright (c) Gert Doering"

/* mgetty.c
 *
 * mgetty main module - initialize modem, lock, get log name, call login
 *
 * some parts of the code (lock handling, writing of the utmp entry)
 * are based on the "getty kit 2.0" by Paul Sutcliffe, Jr.,
 * paul@devon.lns.pa.us, and are used with permission here.
 */

#include <stdio.h>
#include "syslibs.h"
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/times.h>

#include <sys/stat.h>
#include <signal.h>

#include "version.h"
#include "mgetty.h"
#include "policy.h"
#include "tio.h"
#include "fax_lib.h"
#include "mg_utmp.h"

#include "config.h"
#include "conf_mg.h"

#ifdef VOICE
#include "voice/include/voice.h"
#endif

/* how much time may pass between two RINGs until mgetty goes into */
/* "waiting" state again */
int     ring_chat_timeout = 10;

/* what kind of "surprising" things are recognized */
chat_action_t	ring_chat_actions[] = { { "CONNECT",	A_CONN },
					{ "NO CARRIER", A_FAIL },
					{ "BUSY",	A_FAIL },
					{ "ERROR",	A_FAIL },
					{ "+FCON",	A_FAX  },
					{ "+FCO\r",	A_FAX  },
					{ "FAX",	A_FAX  },
					{ "+FHS:",	A_FAIL },
					{ "+FHNG:",	A_FAIL },
#ifdef VOICE
					{ "VCON",       A_VCON },
#endif
					{ NULL,		A_FAIL } };

/* the same actions are recognized while answering as are */
/* when waiting for RING, except for "CONNECT" */

chat_action_t	* answer_chat_actions = &ring_chat_actions[1];


/* prototypes for system functions (that are missing in some 
 * system header files)
 */
#if !defined(__NetBSD__) && !defined(__OpenBSD__)
time_t		time _PROTO(( time_t * tloc ));
#endif

/* logname.c */
int getlogname _PROTO(( char * prompt, TIO * termio,
		char * buf, int maxsize, int max_login_time, 
		boolean do_fido ));

/* conf_mg.c */
void exit_usage _PROTO((int num));

char	* Device;			/* device to use */
char	* DevID;			/* device name withouth '/'s */

extern time_t	call_start;		/* time when we sent ATA */
					/* defined in faxrec.c */

void gettermio _PROTO((char * tag, boolean first, TIO * tio));

/* "simulated RING" handler */
boolean virtual_ring = FALSE;
static RETSIGTYPE sig_pick_phone(SIG_HDLR_ARGS)
{
    signal( SIGUSR1, sig_pick_phone );
    virtual_ring = TRUE;
}
/* handle other signals: log them, and say goodbye... */
static RETSIGTYPE sig_goodbye _P1 ( (signo), int signo )
{
    lprintf( L_AUDIT, "failed dev=%s, pid=%d, got signal %d, exiting",
	              Device, getpid(), signo );
    rmlocks();
    exit(10);
}

/* create a file with the process ID of the mgetty currently
 * active on a given device in it.
 */
static char pid_file_name[ MAXPATH ];
static void make_pid_file _P0( void )
{
    FILE * fp;

    sprintf( pid_file_name, "%s/mgetty.pid.%s", VARRUNDIR, DevID );

    fp = fopen( pid_file_name, "w" );
    if ( fp == NULL )
	lprintf( L_ERROR, "can't create pid file %s", pid_file_name );
    else
    {
	fprintf( fp, "%d\n", (int) getpid() ); fclose( fp );
    }
    if ( chmod( pid_file_name, 0644 ) != 0 )
        lprintf( L_ERROR, "can't chmod() pid file" );
}
    

enum mgetty_States
     { St_unknown,
       St_go_to_jail,			/* reset after unwanted call */
       St_waiting,			/* wait for activity on tty */
       St_check_modem,			/* check if modem is alive */
       St_wait_for_RINGs,		/* wait for <n> RINGs before ATA */
       St_answer_phone,			/* ATA, wait for CONNECT/+FCO(N) */
       St_nologin,			/* no login allowed, wait for
					   RINGing to stop */
       St_dialout,			/* parallel dialout, wait for
					   lockfile to disappear */
       St_get_login,			/* prompt "login:", call login() */
       St_callback_login,		/* ditto, but after callback */
       St_incoming_fax			/* +FCON detected */
   } mgetty_state = St_unknown;

/* called on SIGUSR2. Exit, if no user online, ignore otherwise */
static RETSIGTYPE sig_new_config(SIG_HDLR_ARGS)
{
    signal( SIGUSR2, sig_new_config );
    if ( mgetty_state != St_answer_phone &&
	 mgetty_state != St_get_login &&
	 mgetty_state != St_callback_login &&
	 mgetty_state != St_incoming_fax )
    {
	lprintf( L_AUDIT, "exit dev=%s, pid=%d, got signal USR2, exiting",
	              Device, getpid() );
	rmlocks();
	exit(0);
    }
    lprintf( L_MESG, "Got SIGUSR2, modem is off-hook --> ignored" );
}
   
enum mgetty_States st_sig_callback _P2( (pid, devname),
				        int pid, char * devname )
{
    TIO tio;
    
    lprintf( L_MESG, "Got callback signal from pid=%d!", pid );

    /* reopen device */
    if ( mg_open_device( devname, FALSE ) == ERROR )
    {
	lprintf( L_FATAL, "stsc: can't reopen device" );
	exit(0);
    }

    /* setup device (but do *NOT*!! set speed) */
    if ( tio_get( STDIN, &tio ) == ERROR )
    {
	lprintf( L_FATAL, "stsc: can't get TIO" ); exit(0);
    }
    tio_mode_sane( &tio, c_bool( ignore_carrier ) );
    tio_default_cc( &tio );
    tio_mode_raw( &tio );
    tio_set_flow_control( STDIN, &tio, DATA_FLOW );
    if ( tio_set( STDIN, &tio ) == ERROR )
    {
	lprintf( L_FATAL, "stsc: can't set TIO" ); exit(0);
    }
    
    /* make line controlling tty */
    mg_get_ctty( STDIN, devname );

    /* steal lock file from callback process */
    lprintf( L_MESG, "stealing lock file from pid=%d", pid );
    if ( steal_lock( Device, pid ) == ERROR ) return St_dialout;

    /* signal user */
    printf( "...ok\r\n" );

    /* signal callback process (but give it some time to enter pause()! */
    delay(500);
    if ( kill( pid, SIGUSR1 ) < 0 )
    {
	lprintf( L_ERROR, "can't signal callback process" );
    }

    /* now give user a login prompt! */
    return St_callback_login;
}

/* line locked, parallel dialout in process.
 *
 * Two things can happen now:
 *   - lock file disappears --> dialout terminated, exit(), restart
 *   - get signal SIGUSR1 --> dialout was callback, mgetty takes over
 */
enum mgetty_States st_dialout _P1( (devname), char * devname )
{
    int pid;
    
    /* the line is locked, a parallel dialout is in process */

    virtual_ring = FALSE;			/* used to signal callback */

    /* write a note to utmp/wtmp about dialout, including process args
     * (don't do this on two-user-license systems!)
     */
#ifndef USER_LIMIT
    pid = checklock( Device );		/* !! FIXME, ugly */
    make_utmp_wtmp( Device, UT_USER, "dialout", get_ps_args(pid) );
#endif

    /* close all file descriptors -> other processes can read port */
    close(0);
    close(1);
    close(2);

    /* this is kind of tricky: sometimes uucico dial-outs do still
       collide with mgetty. So, when my uucico times out, I do
       *immediately* restart it. The double check makes sure that
       mgetty gives me at least 5 seconds to restart uucico */
    
    do {
	/* wait for lock to disappear */
	while ( ( pid = checklock(Device) ) != NO_LOCK ) 
	{
	    sleep(10);

	    /* virtual ring? this would mean an active callback! */
	    if ( virtual_ring )
	    {
		return st_sig_callback( pid, devname );
	    }
	}
	
	/* wait a moment, then check for reappearing locks */
	sleep(5);
    }
    while ( checklock(Device) != NO_LOCK );	

    /* OK, leave & get restarted by init */
    exit(0);
}					/* end st_dialout() */

void get_ugid _PROTO(( conf_data * user, conf_data * group,
			uid_t * uid, gid_t * gid ));
       
int main _P2((argc, argv), int argc, char ** argv)
{
    char devname[MAXLINE+1];		/* full device name (with /dev/) */
    char buf[MAXLINE+1];
    TIO	tio;
    FILE *fp;
    int i;
    
    action_t	what_action;
    int		rings_wanted;
    int		rings = 0;
    int		dist_ring = 0;		/* type of RING detected */

#if defined(_3B1_) || defined(MEIBE) || defined(sysV68)
    extern struct passwd *getpwuid(), *getpwnam();
#endif

    uid_t	uid;			/* typical uid for UUCP */
    gid_t	gid;

#ifdef VOICE
    boolean	use_voice_mode = TRUE;
#endif
	
    /* startup: initialize all signal handlers *NOW*
     */
    (void) signal(SIGHUP, SIG_IGN);

    /* set to remove lockfile(s) and print "got signal..." message
     */
    (void) signal(SIGINT, sig_goodbye);
    (void) signal(SIGQUIT, sig_goodbye);
    (void) signal(SIGTERM, sig_goodbye);

    /* sometimes it may be desired to have mgetty pick up the phone even
       if it didn't RING often enough (because you accidently picked it up
       manually...) or if it didn't RING at all (because you have a fax
       machine directly attached to the modem...), so send mgetty a signal
       SIGUSR1 and it will behave as if a RING was seen
       In addition, this is used by the "callback" module.
       */
    signal( SIGUSR1, sig_pick_phone );

    /* for reloading the configuration file, we need a way to tell mgetty
       "restart, but only if no user is online". Use SIGUSR2 for that
       */
    signal( SIGUSR2, sig_new_config );

#ifdef HAVE_SIGINTERRUPT
    /* some systems, notable BSD 4.3, have to be told that system
     * calls are not to be automatically restarted after those signals.
     */
    siginterrupt( SIGINT,  TRUE );
    siginterrupt( SIGALRM, TRUE );
    siginterrupt( SIGHUP,  TRUE );
    siginterrupt( SIGUSR1, TRUE );
    siginterrupt( SIGUSR2, TRUE );
#endif

    Device = "unknown";

    /* process the command line
     */
    mgetty_parse_args( argc, argv );

    /* normal System V getty argument handling
     */
    
    if (optind < argc)
        Device = argv[optind++];
    else {
	lprintf(L_FATAL,"no line given");
	exit_usage(2);
    }

    /* remove leading /dev/ prefix */
    if ( strncmp( Device, "/dev/", 5 ) == 0 ) Device += 5;

    /* need full name of the device */
    sprintf( devname, "/dev/%s", Device);

    /* Device ID = Device name without "/dev/", all '/' converted to '-' */
    DevID = mydup( Device );
    for ( i=0; DevID[i] != 0; i++ )
        if ( DevID[i] == '/' ) DevID[i] = '-';
		  
    /* name of the logfile is device-dependant */
    sprintf( buf, LOG_PATH, DevID );
    log_init_paths( argv[0], buf, &Device[strlen(Device)-3] );

#ifdef VOICE
    lprintf( L_MESG, "vgetty: %s", vgetty_version);
#endif
    lprintf( L_MESG, "mgetty: %s", mgetty_version);
    lprintf( L_NOISE, "%s compiled at %s, %s", __FILE__, __DATE__, __TIME__ );
    i=getppid();
    lprintf( L_NOISE, "user id: %d, pid: %d, parent pid: %d", getuid(), getpid(), i);
    if ( i != 1 )
    {
        char *n = get_ps_args(i);
	lprintf( L_WARN, "WARNING: parent process not init(pid=1), but pid=%d (%s)", i, n != NULL? n: "unknown" );
    }
	    
    /* read configuration file */
    mgetty_get_config( Device );

#ifdef VOICE
    check_system();
    voice_config("vgetty", DevID);
    voice_register_event_handler(vgetty_handle_event);
#endif

#ifdef USE_GETTYDEFS
    if (optind < argc)
        conf_set_string( &c.gettydefs_tag, argv[optind++] );
    
    lprintf( L_MESG, "gettydefs tag used: %s", c_string(gettydefs_tag) );
#endif

    make_pid_file();

    lprintf(L_MESG, "check for lockfiles");

    /* deal with the lockfiles; we don't want to charge
     * ahead if uucp, kermit or whatever else is already
     * using the line.
     * (Well... if we reach this point, most propably init has
     * hung up anyway :-( )
     */

    /* check for existing lock file(s)
     */
    if (checklock(Device) != NO_LOCK)
    {
	st_dialout(NULL);
    }

    /* try to lock the line
     */
    lprintf(L_MESG, "locking the line");

    if ( makelock(Device) == FAIL )
    {
	st_dialout(NULL);
    }

    /* the line is mine now ...  */

    /* set proper port ownership and permissions
     */
    get_ugid( &c.port_owner, &c.port_group, &uid, &gid );
    chown( devname, uid, gid );
    if ( c_isset(port_mode) ) 
	chmod( devname, c_int(port_mode) );

    /* if necessary, kill any processes that still has the serial device 
     * open (Marc Boucher, Marc Schaefer).
     */
#if defined( EXEC_FUSER )
    sprintf( buf, EXEC_FUSER, devname );
    if ( ( i = system( buf ) ) != 0 )
        lprintf( L_WARN, "%s: return code %d", buf, i );
#endif

    /* setup terminal */

    /* Currently, the tio set here is ignored.
       The invocation is only for the sideeffects of:
       - loading the gettydefs file if enabled.
       - setting port speed appropriately, if not set yet.
       */
    gettermio(c_string(gettydefs_tag), TRUE, (TIO *) NULL);

    /* open + initialize device (mg_m_init.c) */
    if ( mg_get_device( devname, c_bool(blocking),
		        c_bool(toggle_dtr), c_int(toggle_dtr_waittime),
		        c_int(speed) ) == ERROR )
    {
	lprintf( L_FATAL, "cannot get terminal line dev=%s, exiting", Device);
	exit(30);
    }
    
    /* drain input - make sure there are no leftover "NO CARRIER"s
     * or "ERROR"s lying around from some previous dial-out
     */
    clean_line( STDIN, 1);

    /* do modem initialization, normal stuff first, then fax
     */
    if ( c_bool(direct_line) )
        Connect = "DIRECT";		/* for "\I" in issue/prompt */
    else
    {
	/* initialize data part */
	if ( mg_init_data( STDIN, c_chat(init_chat), c_bool(need_dsr),
	                          c_chat(force_init_chat) ) == FAIL )
	{
	    lprintf( L_AUDIT, "failed in mg_init_data, dev=%s, pid=%d",
	                      Device, getpid() );
	    tio_flush_queue( STDIN, TIO_Q_BOTH );	/* unblock flow ctrl */
	    rmlocks();
	    exit(1);
	}

	/* if desired, get some "last call statistics" info */
	if ( c_isset(statistics_chat) )
	{
	    get_statistics( STDIN, c_chat(statistics_chat),
		 c_isset(statistics_file)? c_string(statistics_file): NULL );
	}

	/* initialize ``normal'' fax functions */
	if ( ( ! c_bool(data_only) ) &&
	     strcmp( c_string(modem_type), "data" ) != 0 && 
	     mg_init_fax( STDIN, c_string(modem_type),
			  c_string(station_id), c_bool(fax_only),
			  c_int(fax_max_speed) ) == SUCCESS )
	{
	    /* initialize fax polling server (only if faxmodem) */
	    if ( c_isset(fax_server_file) )
	    {
		faxpoll_server_init( STDIN, c_string(fax_server_file) );
	    }
	}

#ifdef VOICE
    voice_fd = STDIN;
    voice_init();

    if ( use_voice_mode ) {
	/* With external modems, the auto-answer LED can be used
	 * to show a status flag. vgetty uses this to indicate
	 * that new messages have arrived.
	 */
	vgetty_message_light();
    }
#endif /* VOICE */

	/* some modems forget some of their settings during fax/voice
	 * initialization -- use this as 'last chance' to set those things
	 * [don't care for errors here]
	 */
	if ( c_isset( post_init_chat ) )
	{
	    lprintf( L_NOISE, "running post_init_chat" );
	    do_chat( STDIN, c_chat(post_init_chat), NULL, NULL, 10, TRUE );
	}
    }

    /* wait .3s for line to clear (some modems send a \n after "OK",
       this may confuse the "call-chat"-routines) */

    clean_line( STDIN, 3);

    /* remove locks, so any other process can dial-out. When waiting
       for "RING" we check for foreign lockfiles, if there are any, we
       give up the line - otherwise we lock it again */

    rmlocks();	

#if ( defined(linux) && defined(NO_SYSVINIT) ) || defined(sysV68)
    /* on linux, "simple init" does not make a wtmp entry when you
     * log so we have to do it here (otherwise, "who" won't work) */
    make_utmp_wtmp( Device, UT_INIT, "uugetty", NULL );
#endif

    /* sleep... waiting for activity */
    mgetty_state = St_waiting;

    while ( mgetty_state != St_get_login && 
	    mgetty_state != St_callback_login )
    {
	switch (mgetty_state)	/* state machine */
	{
	  case St_go_to_jail:
	    /* after a rejected call (caller ID, not enough RINGs,
	     * /etc/nologin file), do some cleanups, and go back to
	     * field one: St_waiting
	     */
	    CallTime = CallName = CalledNr = "";	/* dirty */
	    CallerId = "none";
	    clean_line( STDIN, 3);			/* let line settle */
	    rmlocks();
	    mgetty_state = St_waiting;
	    break;
	    
	  case St_waiting:
	    /* wait for incoming characters (using select() or poll() to
	     * prevent eating away from processes dialing out)
	     */
	    lprintf( L_MESG, "waiting..." );

	    /* ignore accidential sighup, caused by dialout or such
	     */
	    signal( SIGHUP, SIG_IGN );
	    
	    /* here's mgetty's magic. Wait with select() or something
	     * similar non-destructive for activity on the line.
	     * If called with "-b" or as "getty", the blocking has
	     * already happened in the open() call.
	     */
	    if ( ! c_bool(blocking) )
	    {
		int wait_time = c_int(modem_check_time)*1000;

		if ( ! wait_for_input( STDIN, wait_time ) &&
		     ! c_bool(direct_line) && ! virtual_ring )
		{
		    /* no activity - is the modem alive or dead? */
		    log_close();
		    mgetty_state = St_check_modem;
		    break;
		}
	    }

	    /* close (and reopen) log file, to make sure it hasn't been
	     * moved away while sleeping and waiting for 'activity'
	     */
	    log_close();
	
	    /* check for LOCK files, if there are none, grab line and lock it
	     */
    
	    lprintf( L_NOISE, "checking lockfiles, locking the line" );

	    if ( makelock(Device) == FAIL)
	    {
		lprintf( L_NOISE, "lock file exists (dialout)!" );
		mgetty_state = St_dialout;
		break;
	    }

	    /* now: honour SIGHUP
	     */
	    signal(SIGHUP, sig_goodbye );

	    rings = 0;
	    
	    /* check, whether /etc/nologin.<device> exists. If yes, do not
	       answer the phone. Instead, wait for ringing to stop. */
#ifdef NOLOGIN_FILE
	    sprintf( buf, NOLOGIN_FILE, DevID );

	    if ( access( buf, F_OK ) == 0 )
	    {
		lprintf( L_MESG, "%s exists - do not accept call!", buf );
		mgetty_state = St_nologin;
		break;
	    }
#endif
	    mgetty_state = St_wait_for_RINGs;
	    break;


	  case St_check_modem:
	    /* some modems have the nasty habit of just dying after some
	       time... so, mgetty regularily checks with AT...OK whether
	       the modem is still alive */
	    lprintf( L_MESG, "checking if modem is still alive" );

	    if ( makelock( Device ) == FAIL )
	    {
		mgetty_state = St_dialout; break;
	    }

	    /* try twice */
	    if ( mdm_command( "AT", STDIN ) == SUCCESS ||
		 mdm_command( "AT", STDIN ) == SUCCESS )
	    {
		mgetty_state = St_go_to_jail; break;
	    }

	    lprintf( L_FATAL, "modem on dev=%s doesn't react!", Device );

	    /* give up */
	    exit(30);

	    break;
		
	  case St_nologin:
#ifdef NOLOGIN_FILE
	    /* if a "/etc/nologin.<device>" file exists, wait for RINGing
	       to stop, but count RINGs (in case the user removes the
	       nologin file while the phone is RINGing), and if the modem
	       auto-answers, handle it properly */
	    
	    sprintf( buf, NOLOGIN_FILE, DevID );

	    /* while phone is ringing... */
	    
	    while( wait_for_ring( STDIN, NULL, 10, ring_chat_actions, 
				  &what_action, &dist_ring ) == SUCCESS )
	    {
		rings++;
		if ( access( buf, F_OK ) != 0 ||	/* removed? */
		     virtual_ring == TRUE )		/* SIGUSR1? */
		{
		    mgetty_state = St_wait_for_RINGs;	/* -> accept */
		    break;
		}
	    }

	    /* did nologin file disappear? */
	    if ( mgetty_state != St_nologin ) break;

	    /* phone stopped ringing (do_chat() != SUCCESS) */
	    switch( what_action )
	    {
	      case A_TIMOUT:	/* stopped ringing */
		lprintf( L_AUDIT, "rejected, rings=%d", rings );
		mgetty_state = St_go_to_jail;
		break;
	      case A_CONN:	/* CONNECT */
		clean_line( STDIN, 5 );
		printf( "\r\n\r\nSorry, no login allowed\r\n" );
		printf( "\r\nGoodbye...\r\n\r\n" );
		sleep(5); exit(20); break;
	      case A_FAX:	/* +FCON */
		mgetty_state = St_incoming_fax; break;
	      default:
		lprintf( L_MESG, "unexpected action: %d", what_action );
		exit(20);
	    }
#endif
	    break;


	  case St_dialout:
	    /* wait for lock file to disappear *OR* for callback in progress */
	    mgetty_state = st_dialout(devname);
	    break;

	  case St_wait_for_RINGs:
	    /* Wait until the proper number of RING strings have been
	       seen. In case the modem auto-answers (yuck!) or someone
	       hits DATA/VOICE, we'll accept CONNECT, +FCON, ... also. */
	       
	    if ( c_bool(direct_line) )			/* no RING needed */
	    {
		mg_get_ctty( STDIN, devname );		/* get controll.tty */
		mgetty_state = St_get_login;
		break;
	    }

	    dist_ring=0;		/* yet unspecified RING type */

	    if ( c_bool(ringback) )	/* don't pick up on first call */
	    {
		int n = 0;
		
		while( wait_for_ring( STDIN, NULL, 17, ring_chat_actions, 
				      &what_action, &dist_ring ) == SUCCESS &&
		        ! virtual_ring )
		{ n++; }
		
		if ( what_action != A_TIMOUT ) goto Ring_got_action;

		lprintf( L_MESG, "ringback: phone stopped after %d RINGs, waiting for re-ring", n );
	    }

	    /* how many rings to wait for (normally) */
	    rings_wanted = c_int(rings_wanted);
#ifdef VOICE
	    if ( use_voice_mode ) {
		/* modify, if toll saver, or in vgetty answer-file */
		vgetty_rings(&rings_wanted);
	    }
#endif /* VOICE */

	    while ( rings < rings_wanted )
	    {
		if ( wait_for_ring( STDIN, c_chat(msn_list), 
			  ( c_bool(ringback) && rings == 0 )
				? c_int(ringback_time) : ring_chat_timeout,
			  ring_chat_actions, &what_action, 
			  &dist_ring ) == FAIL)
		{
		    break;		/* ringing stopped, or "action" */
		}
		rings++;
	    }

	    /* enough rings? */
	    if ( rings >= rings_wanted )
	    {
		mgetty_state = St_answer_phone; break;
	    }

Ring_got_action:
	    /* not enough rings, timeout or action? */

	    switch( what_action )
	    {
	      case A_TIMOUT:		/* stopped ringing */
		if ( rings == 0 &&	/* no ring *AT ALL* */
		     ! c_bool(ringback))/* and not "missed" ringback */
		{
		    lprintf( L_WARN, "huh? Junk on the line?" );
		    lprintf( L_WARN, " >>> could be a dial-out program without proper locking - check this!" );
		    rmlocks();		/* line is free again */
		    exit(0);		/* let init restart mgetty */
		}
		if ( c_bool(ringback) )
		    lprintf( L_AUDIT, "missed ringback!" );
		else
		    lprintf( L_AUDIT, "phone stopped ringing (rings=%d, dev=%s, pid=%d, caller='%s')", rings, Device, getpid(), CallerId );

		mgetty_state = St_go_to_jail;
		break;
	      case A_CONN:		/* CONNECT */
		mg_get_ctty( STDIN, devname );
		mgetty_state = St_get_login; break;
	      case A_FAX:		/* +FCON */
		mgetty_state = St_incoming_fax; break;
#ifdef VOICE
	      case A_VCON:
		vgetty_button(rings);
		use_voice_mode = FALSE;
		mgetty_state = St_answer_phone;
		break;
#endif
	      case A_FAIL:
		lprintf( L_AUDIT, "failed A_FAIL dev=%s, pid=%d, caller='%s'",
			          Device, getpid(), CallerId );
		exit(20);
	      default:
		lprintf( L_MESG, "unexpected action: %d", what_action );
		exit(20);
	    }
	    break;


	  case St_answer_phone:
	    /* Answer an incoming call, after the desired number of
	       RINGs. If we have caller ID information, and checking
	       it is desired, do it now, and possibly reject call if
	       not allowed in. If we have to do some chat with the modem
	       to get the Caller ID, do it now. */

	    if ( c_isset(getcnd_chat) )
	    {
		do_chat( STDIN, c_chat(getcnd_chat), NULL, NULL, 10, TRUE );
	    }
		
	    /* Check Caller ID.  Static table first, then cnd-program.  */

	    if ( !cndlookup() ||
	         ( c_isset(cnd_program) &&
		   cnd_call( c_string(cnd_program), Device, dist_ring ) == 1))
	    {
		lprintf( L_AUDIT, "denied caller dev=%s, pid=%d, caller='%s'",
			 Device, getpid(), CallerId);
		clean_line( STDIN, 80 ); /* wait for ringing to stop */

		mgetty_state = St_go_to_jail;
		break;
	    }

	    /* from here, there's no way back. Either the call will succeed
	       and mgetty will exec() something else, or it will fail and
	       mgetty will exit(). */
	    
	    /* get line as ctty: hangup will come through
	     */
	    mg_get_ctty( STDIN, devname );
		
	    /* remember time of phone pickup */
	    call_start = time( NULL );

#ifdef VOICE
	    if ( use_voice_mode ) {
		int rc; 
		/* Answer in voice mode. The function will return only if it
		   detects a data call, otherwise it will call exit(). */
		rc = vgetty_answer(rings, rings_wanted, dist_ring);
		
		/* The modem will be in voice mode when voice_answer is
		 * called. If the function returns, the modem is ready
		 * to be connected in DATA mode with ATA.
		 *
		 * Exception: a CONNECT has been seen (-> go to "login:")
		 *   or a fax connection is established (go to fax receive)
		 */

		if ( rc == VMA_CONNECT )
		    { mgetty_state = St_get_login; break; }
		if ( rc == VMA_FCO || rc == VMA_FCON || rc == VMA_FAX )
		    { mgetty_state = St_incoming_fax; break; }
	    }
#endif /* VOICE */

	    if ( do_chat( STDIN, c_chat(answer_chat), answer_chat_actions,
			 &what_action, c_int(answer_chat_timeout), TRUE)
			 == FAIL )
	    {	
		if ( what_action == A_FAX )
		{
		    mgetty_state = St_incoming_fax;
		    break;
		}

		lprintf( L_AUDIT, 
		  "failed %s dev=%s, pid=%d, caller='%s', conn='%s', name='%s'",
		    what_action == A_TIMOUT? "timeout": "A_FAIL", 
		    Device, getpid(), CallerId, Connect, CallName );
  
		rmlocks();
		exit(1);
	    }

	    /* some (old) modems require the host to change port speed
	     * to the speed returned in the CONNECT string, usually
	     * CONNECT 2400 / 1200 / "" (meaning 300)
	     */
	    if ( c_bool(autobauding) )
	    {
		int cspeed;
		
		if ( strlen( Connect ) == 0 )	/* "CONNECT\r" */
		    cspeed = 300;
		else
		    cspeed = atoi(Connect);

		lprintf( L_MESG, "autobauding: switch to %d bps", cspeed );

		if ( tio_check_speed( cspeed ) >= 0 )
		{				/* valid speed */
		    conf_set_int( &c.speed, cspeed );
		    tio_get( STDIN, &tio );
		    tio_set_speed( &tio, cspeed );
		    tio_set( STDIN, &tio );
		}
		else
		{
		    lprintf( L_ERROR, "autobauding: cannot parse 'CONNECT %s'",
			               Connect );
		}
	    }
	    
	    mgetty_state = St_get_login;
	    break;
	    
	  case St_incoming_fax:
	    /* incoming fax, receive it (->faxrec.c) */

	    lprintf( L_MESG, "start fax receiver..." );
	    get_ugid( &c.fax_owner, &c.fax_group, &uid, &gid );
	    faxrec( c_string(fax_spool_in), c_int(switchbd),
		    uid, gid, c_int(fax_mode),
		    c_isset(notify_mail)? c_string(notify_mail): NULL );

    /* some modems require a manual hangup, with a pause before it. Notably
       this is the creatix fax/voice modem, which is quite widespread,
       unfortunately... */

	    delay(1500);
	    mdm_command( "ATH0", STDIN );

	    rmlocks();
	    exit( 0 );
	    break;
	    
	  default:
	    /* unknown machine state */
	    
	    lprintf( L_WARN, "unknown state: %s", mgetty_state );
	    exit( 33 );
	}		/* end switch( mgetty_state ) */
    }			/* end while( state != St_get_login ) */

    /* this is "state St_get_login". Not included in switch/case,
       because it doesn't branch to other states. It may loop for
       a while, but it will never return
       */

    /* wait for line to clear (after "CONNECT" a baud rate may
       be sent by the modem, on a non-MNP-Modem the MNP-request
       string sent by a calling MNP-Modem is discarded here, too) */
    
    clean_line( STDIN, 3);

    tio_get( STDIN, &tio );
    /* honor carrier now: terminate if modem hangs up prematurely
     * (can be bypassed if modem / serial port broken)
     */
    if ( !c_bool( ignore_carrier ) )
    {
	tio_carrier( &tio, TRUE );
	tio_set( STDIN, &tio );
    }
    else
        lprintf( L_MESG, "warning: carrier signal is ignored" );
    
    /* make utmp and wtmp entry (otherwise login won't work)
     */
    make_utmp_wtmp( Device, UT_LOGIN, "LOGIN", 
		      strcmp( CallerId, "none" ) != 0 ? CallerId: Connect );

    /* wait a little bit befor printing login: prompt (to give
     * the other side time to get ready)
     */
    delay( c_int(prompt_waittime) );

    /* loop until a successful login is made
     */
    for (;;)
    {
	/* protect against blocked output (for whatever reason) */
	signal( SIGALRM, sig_goodbye );
	alarm( 60 );

	/* set ttystate for /etc/issue ("before" setting) */
	gettermio(c_string(gettydefs_tag), TRUE, &tio);

	/* we have carrier, assert flow control (including HARD and IXANY!) */
	tio_set_flow_control( STDIN, &tio, DATA_FLOW | FLOW_XON_IXANY );
	tio_set( STDIN, &tio );
	
#ifdef NeXT
	/* work around NeXT's weird problems with POSIX termios vs. sgtty */
	NeXT_repair_line(STDIN);
#endif
	
	fputc('\r', stdout);	/* just in case */
	
	if (c_isset(issue_file))
	{
	    /* display ISSUE, if desired
	     */
	    lprintf( L_NOISE, "print welcome banner (%s)", c_string(issue_file));

	    if (c_string(issue_file)[0] == '!')		/* exec */
            {
                system( c_string(issue_file)+1 );
            }
            else if (c_string(issue_file)[0] != '/')
	    {
		printf( "%s\r\n", ln_escape_prompt( c_string(issue_file) ) );
	    }
	    else if ( (fp = fopen(c_string(issue_file), "r")) != (FILE *) NULL)
	    {
		while ( fgets(buf, sizeof(buf), fp) != (char *) NULL )
		{
		    char * p = ln_escape_prompt( buf );
		    if ( p != NULL ) fputs( p, stdout );
		    fputc('\r', stdout );
		}
		fclose(fp);
	    }
	}

	/* set permissions to "rw-------" for login */
	(void) chmod(devname, 0600);

	/* set ttystate for login ("after"),
	 *  cr-nl mapping flags are set by getlogname()!
	 */
#ifdef USE_GETTYDEFS
	gettermio(c_string(gettydefs_tag), FALSE, &tio);
	tio_set( STDIN, &tio );

	lprintf(L_NOISE, "i: %06o, o: %06o, c: %06o, l: %06o, p: %s",
		tio.c_iflag, tio.c_oflag, tio.c_cflag, tio.c_lflag,
		c_string(login_prompt));
#endif
	/* turn off alarm (getlogname has its own timeout) */
	alarm(0);

	/* read a login name from tty
	   (if just <cr> is pressed, re-print issue file)

	   also adjust ICRNL / IGNCR to characters recv'd at end of line:
	   cr+nl -> IGNCR, cr -> ICRNL, NL -> 0/ and: cr -> ONLCR, nl -> 0
	   for c_oflag */

	if ( getlogname( c_string(login_prompt), &tio, buf, sizeof(buf), 
			 c_bool(blocking)? 0: c_int(login_time), 
			 c_bool(do_send_emsi) ) == -1 ) 
	{
	     continue;
	}

	/* remove PID file (mgetty is due to exec() login) */
	(void) unlink( pid_file_name );

	/* dreadful hack for Linux, set TERM if desired */
	if ( c_isset(termtype) )
	{
	    char * t = malloc( 6 + strlen( c_string(termtype)) );
	    if ( t != NULL )
	        { sprintf( t, "TERM=%s", c_string(termtype) ); putenv(t); }
	}

	/* catch "standard question #29" (DCD low -> /bin/login gets stuck) */
	i = tio_get_rs232_lines(STDIN);
	if ( i != -1 && (( i & TIO_F_DCD ) == 0 ) )
	{
	    lprintf( L_WARN, "WARNING: starting login while DCD is low!" );
	}

	/* hand off to login dispatcher (which will call /bin/login) */
	login_dispatch( buf, mgetty_state == St_callback_login? TRUE: FALSE,
			c_string(login_config) );

	/* doesn't return, if it does, something broke */
	exit(FAIL);
    }
}

void
gettermio _P3 ((id, first, tio), char *id, boolean first, TIO *tio )
{
    char *rp;

#ifdef USE_GETTYDEFS
    static loaded = 0;
    GDE *gdp;
#endif

    /* default setting */
    if ( tio != NULL ) tio_mode_sane( tio, c_bool( ignore_carrier ) );
    rp = NULL;

#ifdef USE_GETTYDEFS
    /* if gettydefs used, override "tio_mode_sane" settings */

    if (!loaded)
    {
	if (!loadgettydefs(GETTYDEFS)) {
	    lprintf(L_WARN, "Couldn't load gettydefs - using defaults");
	}
	loaded = 1;
    }
    if ( (gdp = getgettydef(id)) != NULL )
    {
	lprintf(L_NOISE, "Using %s gettydefs entry, \"%s\"", gdp->tag,
		first? "before" : "after" );
	if (first)	/* "before" -> set port speed */
	{
	    if ( c.speed.flags == C_EMPTY ||	/* still default value */
		 c.speed.flags == C_PRESET )	/* -> use gettydefs */
	        conf_set_int( &c.speed, tio_get_speed( &(gdp->before)) );
	} else		/* "after" -> set termio flags *BUT NOT* speed */
            if ( tio != NULL )
	{
	    *tio = gdp->after;
	    tio_set_speed( tio, c_int(speed) );
	}
	rp = gdp->prompt;
    }

#endif

    if ( rp )		/* set login prompt only if still default */
    {
	if ( c.login_prompt.flags == C_EMPTY || 
	     c.login_prompt.flags == C_PRESET )
	{
	    c.login_prompt.d.p = (void *) rp;
	    c.login_prompt.flags = C_CONF;
	}
    }
}
