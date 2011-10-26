#ident "$Id: faxrec.c,v 4.12 2003/06/12 14:56:35 gert Exp $ Copyright (c) Gert Doering"

/* faxrec.c - part of mgetty+sendfax
 *
 * this module is used when the modem sends a string that triggers the
 * action "A_FAX" - typically this should be "+FCON".
 *
 * The incoming fax is received, and stored to $FAX_SPOOL_IN (one file per
 * page). After completition, the result is mailed to $MAIL_TO.
 * If FAX_NOTIFY_PROGRAM is defined, this program is called with all
 * data about the fax as arguments (see policy.h for a description)
 */

#include <stdio.h>
#include "syslibs.h"
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/times.h>
#include <sys/stat.h>

#ifndef sunos4
#include <sys/ioctl.h>
#endif

#include "mgetty.h"
#include "tio.h"
#include "policy.h"
#include "fax_lib.h"
#include "mg_utmp.h"

extern time_t call_start;		/* in faxrecp.c, set in mgetty.c */
static time_t call_done;

#if !defined(__NetBSD__) && !defined(__OpenBSD__)
time_t	time _PROTO(( time_t * tloc ));
#endif

/* all stuff in here was programmed according to a description of the
 * class 2 standard as implemented in the SupraFAX Faxmodem
 */

void fax_notify_mail _PROTO(( int number_of_pages, int p_number_of_pages, 
			      char * mail_to ));
#ifdef FAX_NOTIFY_PROGRAM
void fax_notify_program _PROTO(( int number_of_pages ));
#endif
void faxpoll_send_pages _PROTO(( int fd, int *ppagenum, TIO * tio, char * pollfile));

char * faxpoll_server_file = NULL;

void faxrec _P6((spool_in, switchbd, uid, gid, mode, mail_to),
		char * spool_in, unsigned int switchbd,
		int uid, int gid, int mode, char * mail_to)
{
int pagenum = 0, ppagenum = 0;		/* pages received / sent */
TIO tio;
extern  char * Device;

    lprintf( L_NOISE, "fax receiver: entry" );

    /* Setup tty interface
     * Do not set c_cflag, assume that caller has set bit rate,
     * hardware handshake, ... properly
     * For some modems, it's necessary to switch to 19200 bps.
     */

#ifdef FAX_USRobotics
    /* the ultra smart USR modems do it in yet another way... */
    fax_wait_for( "OK", STDIN );
#endif

    tio_get( STDIN, &tio );

    /* switch bit rates, if necessary */
    if ( switchbd != 0 ) tio_set_speed( &tio, switchbd );

    tio_mode_raw( &tio );		/* no input or output post-*/
					/* processing, no signals */
    tio_set( STDIN, &tio );

    /* read: +FTSI:, +FDCS, OK */

#ifndef FAX_USRobotics
    fax_wait_for( "OK", STDIN );
#endif

    /* if the "switchbd" flag is set wrongly, the fax_wait_for() command
     * will time out -> write a warning to the log file and give up
     */
    if ( fax_hangup_code == FHUP_TIMEOUT )
    {
	lprintf( L_WARN, ">> The problem seen above might be caused by a wrong value of the" );
	lprintf( L_WARN, ">> 'switchbd' option in 'mgetty.config' (currently set to '%d')", switchbd );

	if ( switchbd > 0 && switchbd != 19200 )
		lprintf( L_WARN, ">> try using 'switchbd 19200' or 'switchbd 0'");
	else if ( switchbd > 0 )
		lprintf( L_WARN, ">> try using 'switchbd 0'" );
	else    lprintf( L_WARN, ">> try using 'switchbd 19200'" );

	fax_hangup = 1;
    }

    /* write a note to utmp/wtmp about incoming fax, including remote id
     * (don't do this on two-user-license systems!)
     */
#ifndef USER_LIMIT
    make_utmp_wtmp( Device, UT_USER, "fax_inc", fax_remote_id );
#endif

    /* *now* set flow control (we could have set it earlier, but on SunOS,
     * enabling CRTSCTS while DCD is low will make the port hang)
     */
    tio_set_flow_control( STDIN, &tio,
			 (FAXREC_FLOW) & (FLOW_HARD|FLOW_XON_IN) );
    tio_set( STDIN, &tio );

    /* tell modem about the flow control used (+FLO=...) */
    fax_set_flowcontrol( STDIN, (FAXREC_FLOW) & FLOW_HARD );

    fax_get_pages( STDIN, &pagenum, spool_in, uid, gid, mode );

    /* send polled documents (very simple yet) */
    if ( faxpoll_server_file != NULL && fax_poll_req )
    {
	lprintf( L_MESG, "starting fax poll send..." );
	
	faxpoll_send_pages( STDIN, &ppagenum, &tio, faxpoll_server_file );
    }

    call_done = time(NULL);
	
    lprintf( L_NOISE, "fax receiver: hangup & end" );

    /* send mail to MAIL_TO */
    if ( mail_to != NULL && strlen(mail_to) != 0 )
        fax_notify_mail( pagenum, ppagenum, mail_to );

#ifdef FAX_NOTIFY_PROGRAM
    /* notify program */
    fax_notify_program( pagenum );
#endif

    call_done = call_done - call_start;
    /* write audit information and return (caller will exit() then) */
    lprintf( L_AUDIT,
"fax dev=%s, pid=%d, caller='%s', name='%s', id='%s', +FHNG=%03d, pages=%d/%d, time=%02d:%02d:%02d\n",
	Device, getpid(), CallerId, CallName, fax_remote_id, 
	fax_hangup_code, pagenum, ppagenum,
	call_done / 3600, (call_done / 60) % 60, call_done % 60);
}

extern	char *	fax_file_names;
extern	int	fax_fn_size;

void fax_notify_mail _P3( (pagenum, ppagenum, mail_to),
			  int pagenum, int ppagenum, char * mail_to )
{
FILE  * pipe_fp;
char  * file_name, * p;
char	buf[256];
int	r;
time_t	ti;
extern  char * Device;

    lprintf( L_NOISE, "fax_notify_mail: sending mail to: %s", mail_to );

    sprintf( buf, "%s %s >/dev/null 2>&1", MAILER, mail_to );

    pipe_fp = popen( buf, "w" );
    if ( pipe_fp == NULL )
    {
	lprintf( L_ERROR, "fax_notify_mail: cannot open pipe to %s", MAILER );
	return;
    }

#ifdef NEED_MAIL_HEADERS
    fprintf( pipe_fp, "Subject: fax from %s\n", fax_remote_id[0] ?
	               fax_remote_id: "(anonymous sender)" );
    fprintf( pipe_fp, "To: %s\n", mail_to );
    fprintf( pipe_fp, "From: root (Fax Getty)\n" );
    fprintf( pipe_fp, "\n" );
#endif

    if ( fax_hangup_code == 0 )
    {
	if ( pagenum != 0 || !fax_poll_req )
	    fprintf( pipe_fp, "A fax was successfully received:\n" );
	else
	    fprintf( pipe_fp, "A to-be-polled fax was successfully sent:\n" );
    }
    else
        fprintf( pipe_fp, "An incoming fax transmission failed (+FHNG:%3d):\n",
                 fax_hangup_code );

    fprintf( pipe_fp, "Sender ID: %s\n", fax_remote_id );
    fprintf( pipe_fp, "Pages received: %d\n", pagenum );
    if ( fax_poll_req )
    {
	fprintf( pipe_fp, "Pages sent    : %d\n", ppagenum );
	fprintf( pipe_fp, "Fax poll specs: %s\n", faxpoll_server_file );
    }

    fprintf( pipe_fp, "\nModem device: %s\n", Device );
    fprintf( pipe_fp, "\nCommunication parameters: %s\n", fax_param );
    fprintf( pipe_fp, "    Resolution : %s\n",
	      (fax_par_d.vr == 0 || fax_par_d.vr == 8) ? "normal" :"fine");
    fprintf( pipe_fp, "    Bit Rate   : %d\n", ( fax_par_d.br+1 ) * 2400 );
    fprintf( pipe_fp, "    Page Width : %d pixels\n", fax_par_d.wd == 0? 1728:
	              ( fax_par_d.wd == 1 ? 2048: 2432 ) );
    fprintf( pipe_fp, "    Page Length: %s\n",
		      fax_par_d.ln == 2? "unlimited":
			   fax_par_d.ln == 1? "B4 (364 mm)" : "A4 (297 mm)" );
    fprintf( pipe_fp, "    Compression: %d (%s)\n", fax_par_d.df, 
	              fax_par_d.df == 0 ? "1d mod Huffman":
	              (fax_par_d.df == 1 ? "2d mod READ": "2d uncompressed") );
    fprintf( pipe_fp, "    Error Corr.: %s\n", fax_par_d.ec? "ECM":"none" );
    fprintf( pipe_fp, "    Scan Time  : %d\n\n", fax_par_d.st );

    ti = call_done - call_start;	/* time spent */

    fprintf( pipe_fp, "Reception Time : %02d:%02d\n\n", (int) ti/60, (int) ti%60 );

    if ( fax_hangup_code != 0 )
    {
	fprintf( pipe_fp, "\nThe fax receive was *not* fully successful\n" );
	fprintf( pipe_fp, "The Modem returned +FHNG:%3d\n", fax_hangup_code );
	fprintf( pipe_fp, "\t\t   (%s)\n", fax_strerror( fax_hangup_code ) );
    }

    /* list the spooled fax files (jcp/gd) */

    if ( pagenum != 0 )
    {
	fprintf( pipe_fp, "\nSpooled G3 fax files:\n\n" );

	p = file_name = fax_file_names;
    
	while ( p != NULL )
	{
	    p = strchr( file_name, ' ' );
	    if ( p != NULL ) *p = 0;
	    fprintf( pipe_fp, "  %s\n", file_name );
	    if ( p != NULL ) *p = ' ';
	    file_name = p+1;
	}
    }

    fprintf( pipe_fp, "\n\nregards, your modem subsystem.\n" );

    if ( ( r = pclose( pipe_fp ) ) != 0 )
    {
	lprintf( L_WARN, "fax_notify_mail: mailer exit status: %d (%d)", r, r>>8 );
    }
}

#ifdef FAX_NOTIFY_PROGRAM
void fax_notify_program _P1( (pagenum),
			     int pagenum )
{
int	r;
char *	line;

    if ( fax_file_names == NULL ) fax_file_names="";

    line = malloc( fax_fn_size + sizeof( FAX_NOTIFY_PROGRAM) + 100 );
    if ( line == NULL )
    {
	lprintf( L_ERROR, "fax_notify_program: cannot malloc" );
	return;
    }

    /* build command line
     * note: stdout / stderr redirected to console, we don't
     *       want the program talking to the modem
     */
    sprintf( line, "%s %d '%s' %d %s >%s 2>&1 </dev/null",
					 FAX_NOTIFY_PROGRAM,
					 fax_hangup_code,
					 fax_remote_id,
					 pagenum,
					 fax_file_names,
					 CONSOLE);

    lprintf( L_NOISE, "notify: '%.320s'", line );

    switch( fork() )
    {
	case 0:		/* child */
	    /* detach from controlling tty -> no SIGHUP */
	    close( 0 ); close( 1 ); close( 2 );
#if defined(BSD) || defined(sunos4)
	    setpgrp( 0, getpid() );
	    if ( ( r = open( "/dev/tty", O_RDWR ) ) >= 0 )
	    {
		ioctl( r, TIOCNOTTY, NULL );
		close( r );
	    }
#else
	    setpgrp();
#endif
	    setup_environment();
	    r = system( line );

	    if ( r != 0 )
		lprintf( L_ERROR, "system() failed" );
	    exit(0);
	case -1:
	    lprintf( L_ERROR, "fork() failed" );
	    break;
    }
    free( line );
}
#endif

void faxpoll_send_pages _P4( (fd, ppagenum, tio, pollfile),
			     int fd, int *ppagenum, TIO *tio, char *pollfile )
{
    FILE * fp;
    char buf[MAXPATH];
    char * file;
    char * fgetline _PROTO(( FILE * fp ));
    int    tries;

    fp = fopen( pollfile, "r" );
    if ( fp == NULL )
    {
	lprintf( L_ERROR, "can't open %s", pollfile ); return;
    }

    /* for historical reasons: if the file starts with "0x00",
       assume it's not a text file but a G3 file
     */

    if ( fread( buf, 1, 1, fp ) != 1 || buf[0] == 0 )
    {
	fclose( fp );
	
	lprintf( L_MESG, "fax poll: %s is (likely) G3 file", pollfile );

	/* send page, no more pages to follow */
	fax_send_page( faxpoll_server_file, NULL, tio, pp_eop, fd );
	(*ppagenum)++;

	return;
    }

    /* read line by line, send as separate pages.
     * comments and continuation lines allowed
     */
    rewind( fp );

    file = fgetline( fp );

    while ( file != NULL && !fax_hangup )
    {
	/* copy filename (we need to know *before* sending the file
	   whether it's the last one, and fgetline() uses a static buffer)
	 */
	
	strncpy( buf, file, sizeof(buf)-1 );
	buf[sizeof(buf)-1] = 0;

	file = fgetline( fp );

	lprintf( L_MESG, "fax poll: send %s...", buf );

	fax_page_tx_status = -1;
	tries = 0;

	/* send file, retransmit (once) if RTN received */
	do
	{
	    if ( file == NULL )		/* last page */
	        fax_send_page( buf, NULL, tio, pp_eop, fd );
	    else			/* not the very last */
	        fax_send_page( buf, NULL, tio, pp_mps, fd );
	    tries++;

	    if ( fax_hangup )
	    {
		lprintf( L_WARN, "fax poll failed: +FHNG:%d (%s)",
			 fax_hangup_code, fax_strerror(fax_hangup_code));
		break;
	    }
	    if ( fax_page_tx_status != 1 )
	        lprintf( L_WARN, "fax poll: +FPS: %d", fax_page_tx_status );
	}
	while( fax_page_tx_status == 2 && tries < 2 );
	(*ppagenum)++;
    }
    fclose( fp );
}
