#ident "$Id: mg_m_init.c,v 4.8 2000/10/03 14:24:52 gert Exp $ Copyright (c) Gert Doering"

/* mg_m_init.c - part of mgetty+sendfax
 *
 * Initialize (fax-) modem for use with mgetty
 */

#include <stdio.h>
#include "syslibs.h"
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#ifndef sunos4
#include <sys/ioctl.h>
#endif

#ifdef linux
# include <sys/types.h>
typedef u_int32_t __u32;
# include <linux/serial.h>
#endif

#include "mgetty.h"
#include "tio.h"
#include "policy.h"
#include "fax_lib.h"

#if (defined(M_XENIX) && !defined(M_UNIX)) || defined(NEXTSGTTY)
#define O_NOCTTY 0
#endif

chat_action_t	init_chat_actions[] = { { "ERROR", A_FAIL },
					{ "BUSY", A_FAIL },
					{ "NO CARRIER", A_FAIL },
					{ NULL, A_FAIL } };

static int init_chat_timeout = 20;

/* initialize data section */

int mg_init_data _P4( (fd, chat_seq, need_dsr, force_chat_seq), 
		      int fd, char * chat_seq[], 
		      boolean need_dsr, char * force_chat_seq[] )
{
    action_t what_action;
    
    if ( do_chat( fd, chat_seq, init_chat_actions,
		 &what_action, init_chat_timeout, TRUE ) == SUCCESS )
    {
	return SUCCESS;
    }

    /* maybe the modem init failed, because the modem was switched
     * off.  So, we check now that there is a DSR or a CTS signal
     * coming from the modem - and if not, we sleep until it comes back.
     * WARNING: this can fail on systems not allowing to read out the
     * RS232 status lines, thus it is optional, and off by default!
     */
    if ( need_dsr )
    {
        int rs_lines = tio_get_rs232_lines(fd);

	if ( rs_lines != -1 && 
	      (rs_lines & (TIO_F_DSR|TIO_F_CTS) ) == 0 )
	{
	    lprintf( L_WARN, "No DSR/CTS signals, assuming modem is switched off, waiting..." );
	    while( (tio_get_rs232_lines(fd) & (TIO_F_DSR|TIO_F_CTS) ) == 0)
	    {
		sleep(60);
	    }
	}
    }

    /* if init_chat failed because the modem didn't respond, and we have 
     * a "force_chat" sequence, try this.
     * (force_chat might contain DLE ETX for voice modems, or just plain 
     * simple +++ATH0 for data modems (mis-)configured with AT&D0)
     */
    if ( what_action == A_TIMOUT && force_chat_seq != NULL )
    {
	lprintf( L_WARN, "init chat timed out, trying force-init-chat" );

	if ( do_chat( fd, force_chat_seq, init_chat_actions,
		     &what_action, init_chat_timeout, TRUE ) == SUCCESS ||
	     what_action != A_TIMOUT )
        {
	    lprintf( L_NOISE, "force-init succeeded, retrying init-chat");

	    clean_line(fd, 3);
	    if ( do_chat( fd, chat_seq, init_chat_actions,
			 &what_action, init_chat_timeout, TRUE ) == SUCCESS )
	    {
		return SUCCESS;
	    }
        }
    }

    /* either no force_chat available, or that didn't help either: BARF!
     */
    errno = ( what_action == A_TIMOUT )? EINTR: EINVAL;
    lprintf( L_ERROR, "init chat failed, exiting..." );
    return FAIL;
}


/* initialization stuff for fax */

/* initialize fax section */

int mg_init_fax _P5( (fd, mclass, fax_id, fax_only, fax_max_speed),
		      int fd, char * mclass, char * fax_id, 
		      boolean fax_only, int fax_max_speed )
{
    /* find out whether this beast is a fax modem... */

    modem_type = fax_get_modem_type( fd, mclass );
    
    if ( modem_type == Mt_data )
    {
	lprintf( L_NOISE, "no class 2/2.0 faxmodem, no faxing available" );
	return FAIL;
    }
    
    if ( modem_type == Mt_class2_0 )
    {
	/* set adaptive answering, bit order, receiver on */
	
	if ( mdm_command( fax_only? "AT+FAA=0;+FCR=1":
			            "AT+FAA=1;+FCR=1", fd ) == FAIL )
	{
	    lprintf( L_MESG, "cannot set answer/reception flags" );
	}
	if ( fax_set_bor( fd, 1 ) == FAIL )
	{
	    lprintf( L_MESG, "cannot set bit order, trying +BOR=0" );
	    fax_set_bor( fd, 0 );
	}

	/* report everything except NSF (unless asked for it) */
	mdm_command( (modem_quirks & MQ_SHOW_NSF)? "AT+FNR=1,1,1,1"
						 : "AT+FNR=1,1,1,0", fd );
    }

    if ( modem_type == Mt_class2 )
    {
	/* even if we know that it's a class 2 modem, set it to
	 * +FCLASS=0: there are some weird modems out there that won't
	 * properly auto-detect fax/data when in +FCLASS=2 mode...
	 *
	 * Exception: Dr.Neuhaus modems do adaptive answering *only* if in
	 *            +FCLASS=2 mode -> check flag set by auto-detection
	 */
	if ( !fax_only && ! ( modem_quirks & MQ_NEED2 ) )
	{
	    if ( mdm_command( "AT+FCLASS=0", fd ) == FAIL )
	    {
		lprintf( L_MESG, "weird: cannot set class 0" );
	    }
	}

	/* now, set various flags and modem settings. Failures are logged,
	   but ignored - after all, either the modem works or not, we'll
	   see it when answering the phone ... */
    
	/* set adaptive answering, bit order, receiver on */

	if ( mdm_command( fax_only? "AT+FAA=0;+FCR=1":
			            "AT+FAA=1;+FCR=1", fd ) == FAIL )
	{
	    lprintf( L_MESG, "cannot set answer/reception flags" );
	}
	if ( fax_set_bor( fd, 0 ) == FAIL )
	{
	    lprintf( L_MESG, "cannot set bit order. Huh?" );
	}
    }

    /* common part for class 2 and class 2.0 */

    /* local fax station id */
    fax_set_l_id( fd, fax_id );

    /* capabilities */

    if ( fax_set_fdcc( fd, 1, fax_max_speed, 0 ) == FAIL )
    {
	lprintf( L_MESG, "huh? Cannot set +FDCC parameters" );
    }
    
    return SUCCESS;
}


    
/* initialize fax poll server functions (if possible) */
   
extern char * faxpoll_server_file;		/* in faxrec.c */

void faxpoll_server_init _P2( (fd,f), int fd, char * f )
{
    faxpoll_server_file = NULL;
    if ( access( f, R_OK ) != 0 )
    {
	lprintf( L_ERROR, "cannot access/read '%s'", f );
    }
    else if ( mdm_command( modem_type == Mt_class2_0? "AT+FLP=1":"AT+FLPL=1",
			   fd ) == FAIL)
    {
	lprintf( L_WARN, "faxpoll_server_init: no polling available" );
    }
    else
    {
	faxpoll_server_file = f;
	lprintf( L_NOISE, "faxpoll_server_init: OK, waiting for poll" );
    }
}


/* open device (non-blocking / blocking)
 *
 * open with O_NOCTTY, to avoid preventing dial-out processes from
 * getting the line as controlling tty
 */


int mg_open_device _P2 ( (devname, blocking),
		         char * devname, boolean blocking )
{
    int fd;

    if ( ! blocking )
    {
	fd = open(devname, O_RDWR | O_NDELAY | O_NOCTTY );
	if ( fd < 0 )
	{
	    lprintf( L_FATAL, "mod: cannot open line %s", devname );
	    return ERROR;
	}

	/* unset O_NDELAY (otherwise waiting for characters */
	/* would be "busy waiting", eating up all cpu) */
	
	fcntl( fd, F_SETFL, O_RDWR);
    }
    else		/* blocking open */
    {
      again:
	fd = open( devname, O_RDWR | O_NOCTTY );
	    
	if ( fd < 0)
	{
	    if ( errno == EAGAIN ) goto again;
	    
	    lprintf( L_FATAL, "mod: cannot open line %s", devname );
	    return ERROR;
	}
    }
#ifdef NEXTSGTTY
    /* get rid of controlling tty: on NeXT, there is no O_NOCTTY */
    ioctl( fd, TIOCNOTTY, 0 );
#endif

    /* make new fd == stdin if it isn't already */

    if (fd > 0)
    {
	(void) close(0);
	if (dup(fd) != 0)
	{
	    lprintf( L_FATAL, "mod: cannot make %s stdin", devname );
	    return ERROR;
	}
    }

    /* make stdout and stderr, too */

    (void) close(1);
    (void) close(2);
    
    if (dup(0) != 1)
    {
	lprintf( L_FATAL, "mod: cannot dup to stdout"); return ERROR;
    }
    if (dup(0) != 2)
    {
	lprintf( L_FATAL, "mod: cannot dup to stderr"); return ERROR;
    }

    if ( fd > 2 ) (void) close(fd);

    /* switch off stdio buffering */

    setbuf(stdin, (char *) NULL);
    setbuf(stdout, (char *) NULL);
    setbuf(stderr, (char *) NULL);

    return NOERROR;
}

/* init device: toggle DTR (if requested), set TIO values */

int mg_init_device _P4( (fd, toggle_dtr, toggle_dtr_waittime, portspeed ),
		       int fd,
		       boolean toggle_dtr, int toggle_dtr_waittime,
		       unsigned int portspeed )
{
    TIO tio;
    
    if (toggle_dtr)
    {
	lprintf( L_MESG, "lowering DTR to reset Modem" );
	tio_toggle_dtr( fd, toggle_dtr_waittime );
    }

#ifdef TIOCSSOFTCAR
    /* turn off SunOS soft carrier "feature" */

    { int off = 0;
    if ( ioctl( fd, TIOCSSOFTCAR, &off ) < 0 )
	lprintf( L_ERROR, "cannot turn off soft carrier" );
    }
#endif


    /* initialize port */
	
    if ( tio_get( fd, &tio ) == ERROR )
    {
	lprintf( L_FATAL, "cannot get TIO" );
	return ERROR;
    }
    
    tio_mode_sane( &tio, TRUE );	/* initialize all flags */
    tio_set_speed( &tio, portspeed );	/* set bit rate */
    tio_default_cc( &tio );		/* init c_cc[] array */
    tio_mode_raw( &tio );

#ifdef sun
    /* SunOS does not rx with RTSCTS unless carrier present */
    tio_set_flow_control( STDIN, &tio, (DATA_FLOW) & (FLOW_SOFT) );
#else
    tio_set_flow_control( STDIN, &tio, DATA_FLOW );
#endif
    
    if ( tio_set( STDIN, &tio ) == ERROR )
    {
	lprintf( L_FATAL, "cannot set TIO" );
	return ERROR;
    }

#ifdef linux
    /* if port speed is set to 38400, kernel flag might turn it into
     * 57600 or 115200. Make sure the user knows about it!
     */
    if ( portspeed == 38400 )
    {
	struct serial_struct serinfo;

	if ( ioctl( STDIN, TIOCGSERIAL, &serinfo ) == 0 &&
	     ( serinfo.flags & ASYNC_SPD_MASK ) != 0 )
	{
	    lprintf( L_WARN, "WARNING: obsolete setserial spd_hi/spd_vhi used, 38400 is not real port speed" );
	}
    }
#endif

    return NOERROR;
}

/* open + initialize device
 *
 * if first init fails, try again: on Linux and SunOS, the port isn't
 * able anymore after carrier drop, but after reopening it, it is.
 */
int mg_get_device _P5( (devname, blocking_open,
			toggle_dtr, toggle_dtr_waittime, portspeed ),
		      
		        char * devname, boolean blocking_open,
		        boolean toggle_dtr, int toggle_dtr_waittime,
		        unsigned int portspeed)
{
    boolean first_try = TRUE;
    int rs_lines;

    /* most likely, HUPCL was set and so DTR is low right now. Give
     * modem some time to settle down.
     */
    delay(500);
    
    /* open device, make it stdin/out/err */
try_again:
    if ( mg_open_device( devname, blocking_open ) == ERROR )
    {
	lprintf( L_FATAL, "open device %s failed", devname );
	return ERROR;
    }

    /* catch "standard question #17" (DCD drop -> fd invalid -> I/O error) */
    rs_lines = tio_get_rs232_lines(STDIN);
    if ( rs_lines != -1 )
    {
#ifdef linux
	if ( rs_lines & TIO_F_DCD )
	    lprintf( L_MESG, "WARNING: DCD line still active, check modem settings (AT&Dx)" );
#endif
	if ( ! (rs_lines & TIO_F_DSR) )
	    lprintf( L_WARN, "WARNING: DSR is off - modem turned off or bad cable?" );
    }
    
    /* initialize device (hangup, raw, speed). May fail! */
    if ( mg_init_device( STDIN, toggle_dtr, toggle_dtr_waittime,
			 portspeed ) == ERROR )
    {
	if ( first_try )
	{
	    lprintf( L_WARN, "mg_init_device failed, trying again" );
	    first_try = FALSE; goto try_again;
	}

	lprintf( L_FATAL, "mg_init_device failed, exiting" );
	return ERROR;
    }

    return NOERROR;
}
    
		      
/* get a given tty as controlling tty
 *
 * on many systems, this works with ioctl( TIOCSCTTY ), on some
 * others, you have to reopen the device
 */

int mg_get_ctty _P2( (fd, devname), int fd, char * devname )
{
    /* BSD systems, Linux, *NOT* HP-UX */
#if defined( TIOCSCTTY ) && !defined( _HPUX_SOURCE)
    if ( setsid() == -1 && errno != EPERM )
    {
	lprintf( L_ERROR, "cannot make myself session leader (setsid)" );
    }
    if ( ioctl( fd, TIOCSCTTY, NULL ) != 0 )
    {
	lprintf( L_ERROR, "cannot set controlling tty (ioctl)" );
	if ( getppid() != 1 )
	{
	    lprintf( L_WARN, ">>> this might be caused because you have run mgetty/vgetty" );
	    lprintf( L_WARN, ">>> from the command line.  Don't do that, use /etc/inittab!" );
	}
	return ERROR;
    }
#else
    /* SVR3 and earlier */
    fd = open( devname, O_RDWR | O_NDELAY );

    if ( fd == -1 )
    {
        lprintf( L_ERROR, "cannot set controlling tty (open)" );
	return ERROR;
    }

    fcntl( fd, F_SETFL, O_RDWR);		/* unset O_NDELAY */
    close( fd );
#endif						/* !def TIOCSCTTY */

    return NOERROR;
}
