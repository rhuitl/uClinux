/*
 * This file is only temporarily needed until the fax part and the voice
 * part are better integrated
 *
 * $Id: voice_fax.c,v 1.6 2001/12/17 22:32:01 gert Exp $
 *
 */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "../../syslibs.h"
#ifndef sunos4
#include <sys/ioctl.h>
#endif
#include <signal.h>
#include <sys/types.h>
#ifndef ENOENT
# include <errno.h>
#endif

#include "../../mgetty.h"
#include "../../tio.h"
#include "../../policy.h"
#include "../../fax_lib.h"

/* use direct bit order in modem, that means, we have to reverse */
#define REVERSE 1

/* seems to missing nearly everywhere */
#if !defined(__NetBSD__) && !defined(__OpenBSD__)
time_t    time _PROTO(( time_t * tloc ));
#endif

/* from faxrecp.c */
extern  char *  fax_file_names;

/* from shell.c */
extern int voice_fax_hangup_code;
extern char * voice_fax_remote_id;
extern char * voice_fax_files;

int voice_faxsnd _P3( (name, switchbd, max_tries),
                char **name, int switchbd, int max_tries)
{
    int   tries;              /* number of unsuccessful tries */
    TIO tio;
    time_t call_start;

    int   total_bytes = 0;    /* number of bytes sent */
    int total_pages = 0; /* number of pages (files) sent */
    int total_resent= 0; /* number of pages resent */
    faxlib_init();

    tio_get( STDIN, &tio );

    if ( switchbd != 0 ) tio_set_speed( &tio, switchbd );
    tio_mode_raw( &tio );               /* no input or output post-*/

    tio_set( STDIN, &tio );

#if REVERSE
    fax_set_bor( STDIN, 0 );
#else
    fax_set_bor( STDIN, 1 );
#endif

    /* set modem to use desired flow control type, dial out
     */
    if ( fax_set_flowcontrol( STDIN, (FAXSEND_FLOW) & FLOW_HARD ) == ERROR )
    {
     lprintf( L_WARN, "cannot set modem flow control" );
    }

    call_start = time( NULL );
    tries = 0;

    /* process all files to send / abort, if Modem sent +FHNG result */

    if (fax_command( "ATD", "OK", STDIN ) == ERROR) /* skip main loop */;
      else
    while ( *name )
    {
     Post_page_messages ppm;
     total_pages++;
     /* how to continue after page? */

     if ( ! *(name+1) )  /* last page to send */
             ppm = pp_eop;         /* over & out (->hangup) */
     else                /* not last page -> */
             ppm = pp_mps;         /* another page next */

     fax_page_tx_status = -1; /* set by fax_send_page() */

     if ( fax_send_page( *name, &total_bytes, &tio, ppm, STDIN ) == ERROR )
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
       case 1: break;              /* page good */
                              /* page bad - r. req. */
       case 2:
         if ( max_tries <= 0 )     /* ignore */
         {
          lprintf( L_WARN, "WARNING: RTN ignored" );
         }
         else                 /* try again */
         {
          tries ++;
          if ( tries >= max_tries )     /* max tries reached */
          {
               lprintf( L_WARN, "ERROR: too many retries - aborting send" );
               fax_hangup_code = -1;
               fax_hangup = 1;
          }
          else
          {
              total_resent++;
              continue;  /* don't go to next page */
          }
         }
         break;
       case 3: lprintf( L_WARN, "WARNING: RTP: page good, but retrain requested" );
              break;
       case 4:
       case 5: lprintf( L_WARN, "WARNING: procedure interrupt requested - don't know how to handle it" );
              break;
       case -1:               /* something broke */
            lprintf( L_WARN, "fpts:-1" );
            break;
       default:lprintf( L_WARN, "WARNING: invalid code: +FPTS:%d",
                       fax_page_tx_status );
            break;
     }

     if ( fax_hangup && fax_hangup_code != 0 ) break;

     tries=0;       /* no tries yet */
     name++;                 /* next page */
    }                    /* end main page loop */

    call_start = time(NULL)-call_start;
    lprintf( L_AUDIT, "+FHS:%02d, time=%ds, pages=%d(+%d), bytes=%d",
                   fax_hangup_code, call_start,
                   total_pages, total_resent, total_bytes );

    voice_fax_hangup_code = fax_hangup_code;
    voice_fax_remote_id = fax_remote_id;
    voice_fax_files = NULL;

    return 0;
}


void voice_faxrec _P2((spool_in, switchbd),
          char * spool_in, unsigned int switchbd)
{
    int pagenum = 0;
    TIO tio;
    time_t call_start;

    faxlib_init();

    lprintf( L_NOISE, "fax receiver: entry" );

    /* Setup tty interface
     * Do not set c_cflag, assume that caller has set bit rate,
     * hardware handshake, ... properly
     * For some modems, it's necessary to switch to 19200 bps.
     */

#ifdef FAX_USRobotics
    /* the ultra smart USR modems do it in yet another way... */
    fax_wait_for( "OK", 0 );
#endif

    tio_get( STDIN, &tio );

    /* switch bit rates, if necessary */
    if ( switchbd != 0 ) tio_set_speed( &tio, switchbd );

    tio_mode_raw( &tio );          /* no input or output post-*/
                         /* processing, no signals */
    tio_set( STDIN, &tio );

    call_start = time( NULL );

    /* read: +FTSI:, +FDCS, OK */

#ifndef FAX_USRobotics
    fax_wait_for( "OK", 0 );
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

    /* *now* set flow control (we could have set it earlier, but on SunOS,
     * enabling CRTSCTS while DCD is low will make the port hang)
     */
    tio_set_flow_control( STDIN, &tio,
                (FAXREC_FLOW) & (FLOW_HARD|FLOW_XON_IN) );
    tio_set( STDIN, &tio );

    /* tell modem about the flow control used (+FLO=...) */
    fax_set_flowcontrol( STDIN, (FAXREC_FLOW) & FLOW_HARD );

    fax_get_pages( 0, &pagenum, spool_in, 0, 0, 0660 );

    lprintf( L_NOISE, "fax receiver: hangup & end" );

    /* write audit information and return (caller will exit() then) */
    lprintf( L_AUDIT, "fax caller=%s, name='%s', id='%s', +FHNG=%03d, pages=%d, time=%ds",
     CallerId, CallName, fax_remote_id, fax_hangup_code, pagenum,
                   ( time(NULL)-call_start ));

    voice_fax_hangup_code = fax_hangup_code;
    voice_fax_remote_id = fax_remote_id;
    voice_fax_files = fax_file_names;

    return;
}

