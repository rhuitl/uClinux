#ident "$Id: mid.c,v 1.10 2003/11/17 19:05:10 gert Exp $ Copyright (c) Gert Doering"

/* mid.c
 *
 * identify modem (ATI<n>, AT+FMFR?, AT+FCLASS=?, ...), 
 * optionally mail results to Marc or Gert
 *
 * Calls routines in io.c, tio.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>

#include "mgetty.h"
#include "policy.h"
#include "tio.h"

char * query_strings[] = { "ATE1Q0V1", 
			   "ATI",  "ATI0", "ATI1", "ATI2", "ATI3", "ATI4",
                           "ATI5", "ATI6", "ATI7", "ATI8", "ATI9", "ATI10",
                           "ATI11","ATI12","ATI13","ATI14","ATI15",
			   "AT+FCLASS=?",
			   "AT+FMFR?", "AT+FMDL?", "AT+FREV?",
			   "AT+FMI?", "AT+FMM?", "AT+FMR?",
			   "AT+GMI?", "AT+GMM?", "AT+GMR?", "AT+GCAP?",
			   "AT+FCLASS=8", "AT+VSM=?",
			   NULL };

/* we don't want logging here */
#ifdef USE_VARARGS
int lprintf() { return 0; }
#else
int lprintf(int level, const char *format, ...) { return 0; }
#endif
int lputs( int level, char * string ) { return 0; }

/* interrupt handler for SIGALARM */
boolean got_interrupt;
RETSIGTYPE oops(SIG_HDLR_ARGS)
		{ got_interrupt=TRUE; }

int test_modem( char * device, int speed, FILE * fp )
{
int fd;
TIO tio, save_tio;
char **query = query_strings;

char buf[100];
int l;

    fprintf( fp, "testing for modem on %s with %d bps...\n", device, speed );

    /* lock device */
    if ( makelock( device ) == FAIL )
    {
	fprintf( stderr, "can't lock device '%s', skipping\n", device );
	return -1;
    }

    fd = open( device, O_RDWR | O_NDELAY );
    if ( fd < 0 )
    {
	fprintf( stderr, "error opening '%s': %s\n", device, strerror(errno));
	return -1;
    }

    /* unset O_NDELAY (otherwise waiting for characters */
    /* would be "busy waiting", eating up all cpu) */
    fcntl( fd, F_SETFL, O_RDWR);

    if ( tio_get( fd, &tio ) == ERROR )
    {
	fprintf( stderr, "error reading TIO settings for '%s': %s\n",
		 device, strerror(errno));
	close(fd); rmlocks();
	return -1;
    }
    save_tio = tio;
    tio_mode_sane( &tio, TRUE );
    tio_set_speed( &tio, speed );
    tio_mode_raw( &tio );
    if ( tio_set( fd, &tio ) == ERROR )
    {
	fprintf( stderr, "error setting TIO settings for '%s': %s\n",
		 device, strerror(errno));
	close(fd); rmlocks();
	return -1;
    }

    while( *query != NULL )
    {
	fprintf( fp, ">>> %s\n", *query );
	if ( fp != stdout ) printf( "%s...\n", *query );

	signal( SIGALRM, oops );
	alarm(3);
	got_interrupt = FALSE;

	write( fd, *query, strlen(*query) );
	write( fd, MODEM_CMD_SUFFIX, sizeof(MODEM_CMD_SUFFIX)-1 );

	do
	{
	    l = read( fd, buf, sizeof(buf) );
	    if ( l>0 ) 
	    {
		fwrite( buf, 1, l, fp );
	    } 
	}
	while( l>0 && ! got_interrupt );

	if ( errno != EINTR || !got_interrupt )
	{
	    fprintf( stderr, "error reading from device '%s': %s\n",
		     device, strerror(errno));
	    break;
	}

	query++;
    }

    if ( tio_set( fd, &save_tio ) == ERROR )
    {
	fprintf( stderr, "error setting TIO settings for '%s': %s\n",
		 device, strerror(errno));
    }
    close(fd);
    rmlocks();
    signal( SIGALRM, SIG_DFL );
    return 0;
}

void exit_usage( char * program, char * msg )
{
    if ( msg != NULL )
	fprintf( stderr, "%s: %s\n", program, msg );

    fprintf( stderr, "valid options: -m, -M <mailaddr>, -f <file>\n" );
    exit(99);
}

int main( int argc, char ** argv )
{
int opt;
char device[MAXPATH];

char * mailaddr = "gert@greenie.muc.de";	/* send to this e-mail addr */
boolean send_mail = FALSE;			/* send mail? */
int speed = 38400;				/* port speed */

FILE * out_fp = stdout;

    while ((opt = getopt(argc, argv, "mM:f:s:")) != EOF)
    {
	switch( opt )
	{
	    case 'm': send_mail = TRUE; break;
	    case 'M': send_mail = TRUE; mailaddr = optarg; break;
	    case 's': speed = atoi(optarg); break;
	    default:
		exit_usage( argv[0], NULL );
	}
    }

    if ( optind == argc )		/* no ttys specified */
		exit_usage( argv[0], "no tty device specified" );
    
    /* prepare file descriptors, etc.
     */

    if ( send_mail )
    {
	char mailer[MAXPATH];

	sprintf( mailer, "%s %.*s", MAILER, 
		 (int)(sizeof(mailer)-sizeof(MAILER)-10), mailaddr );
	out_fp = popen( mailer, "w" );

	if ( out_fp == NULL )
	{
	    fprintf( stderr, "%s: can't open pipe to '%s': %s", 
			argv[0], mailer, strerror(errno));
	    exit(1);
	}

	fprintf( out_fp, "To: %s\nSubject: mid run\n\n", mailaddr );
	printf( "Working... - output is mailed to %s\n", mailaddr );
    }

#ifdef HAVE_SIGINTERRUPT
    /* some systems, notable BSD 4.3, have to be told that system
     * calls are not to be automatically restarted after those signals.
     */
    siginterrupt( SIGINT,  TRUE );
    siginterrupt( SIGALRM, TRUE );
    siginterrupt( SIGHUP,  TRUE );
#endif

    /* now walk through all the modems, query them, and report back...
     */
    while( optind<argc )
    {
	if ( strlen(argv[optind]) > sizeof(device)-10 )
	{ 
	    fprintf( stderr, "%s: device name '%s' too long\n", 
		     argv[0], argv[optind] ); optind++; continue;
	}
	if ( argv[optind][0] == '/' )
	    strcpy( device, argv[optind] );
	else
	    sprintf( device, "/dev/%s", argv[optind]);

	test_modem( device, speed, out_fp );

	optind++;
    }

    if ( out_fp != stdout ) 
	pclose(out_fp);
	
    return 0;
}

