#ident "$Id: ltest.c,v 1.6 2002/11/23 20:35:50 gert Exp $ Copyright (c) Gert Doering"

/* ltest.c
 *
 * show status of all the RS232 lines (RTS, CTS, ...)
 * Calls routines in io.c, tio.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include "mgetty.h"
#include "tio.h"

char * Device;
int delay_time = 0;			/* in milliseconds, 0 = one-shot */

/* we don't want logging here */
#ifdef USE_VARARGS
int lprintf() { return 0; }
#else
int lprintf(int level, const char *format, ...) { return 0; }
#endif
int lputs( int level, char * string ) { return 0; }

int main( int argc, char ** argv )
{
int opt, fd, f, last_f;
time_t ti;
struct tm * tm;
boolean	opt_delta = FALSE;		/* show only deltas */
boolean opt_keyboard = FALSE;		/* read commands from keyboard */
TIO tio, save_tio;			/* for stdin */

    while ((opt = getopt(argc, argv, "i:m:dk")) != EOF)
    {
	switch( opt )
	{
	    case 'i': delay_time = 1000 * atoi(optarg); break;	/* secs */
	    case 'm': delay_time = atoi(optarg); break;		/* msecs */
	    case 'd': opt_delta = TRUE; break;
	    case 'k': opt_keyboard = TRUE; break;
	    default:
		fprintf( stderr, "Valid options: -i <seconds-delay>, -m <msec-delay>, -d, -k\n" ); exit(7);
	}
    }

    if ( optind < argc )		/* argument == tty to use */
    {
	Device = argv[optind++];
	fd = open( Device, O_RDONLY | O_NDELAY );

	if ( fd < 0 )
		{ perror( "Opening device failed" ); exit(17); }

	fcntl( fd, F_SETFL, O_RDONLY );
    }
    else				/* default: use stdin */
    {
	Device = "stdin"; fd = fileno(stdin);
    }

    /* if input from keyboard allowed, set stdin to "raw"
     */
    if ( opt_keyboard )
    {
	if ( fd == fileno(stdin) )
	{
	    fprintf( stderr, "can't read modem + keyboard data from stdin\n");
	    exit(7);
	}
	if ( tio_get( 0, &tio ) == ERROR )
	{
	    fprintf( stderr, "can't read termios settings for keyboard\n" );
	    exit(1);
	}
	save_tio = tio;
	tio_mode_raw( &tio );
	if ( tio_set( 0, &tio ) == ERROR )
	{
	    fprintf( stderr, "can't set termios settings for keyboard\n" );
	    exit(2);
	}
	printf( "keyboard active. Press 'D' to change DTR, 'R' to change RTS.\r\n" );
    }

    last_f = -1;
    do
    {
	f = tio_get_rs232_lines( fd );

	if ( f == -1 )
	{
	    printf( "%s: can't read RS232 line status (-1)\n", Device );
	    exit(17);
	}

        /* display data only if something changed *or* if (not opt_delta)
	 */
	if ( ! opt_delta || f != last_f )
	{
	    ti = time(NULL);
	    tm = localtime(&ti);
	    printf( "%s, %02d:%02d:%02d: active lines:", Device, 
			    tm->tm_hour, tm->tm_min, tm->tm_sec );

	    if ( f & TIO_F_DTR ) printf( " DTR" );
	    if ( f & TIO_F_DSR ) printf( " DSR" );
	    if ( f & TIO_F_RTS ) printf( " RTS" );
	    if ( f & TIO_F_CTS ) printf( " CTS" );
	    if ( f & TIO_F_DCD ) printf( " DCD" );
	    if ( f & TIO_F_RI  ) printf( " RI" );

	    if ( f == 0 ) printf( " <none>" );

	    printf( "\r\n" );
	    
	    last_f = f;
	}

	if ( delay_time ) delay( delay_time );

	/* check keyboard */
        while ( opt_keyboard && check_for_input(0) )
	{
	    char ch;
	    if ( read( 0, &ch, 1 ) != 1 )
	    {
		fprintf( stderr, "error reading from keyboard, abort.\n");
		delay_time=0; break;
	    }
	    switch(ch)
	    {
	      case 'd':		/* toggle DTR */
	      case 'D': 
		tio_set_rs232_lines( fd, last_f & TIO_F_DTR? 0: 1, -1 );
		break;
	      case 'r':		/* toggle RTS */
	      case 'R':
		tio_set_rs232_lines( fd, -1, last_f & TIO_F_RTS? 0: 1 );
		break;
	      case 3:		/* exit */
	      case 'q':
	      case 'x':
		delay_time = 0; break;
	    }
	}
    }
    while( delay_time );

    if ( opt_keyboard )		/* reset termios settings */
	tio_set( 0, &save_tio );

    return 0;
}

