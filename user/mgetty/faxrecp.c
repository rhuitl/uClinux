#ident "$Id: faxrecp.c,v 1.8 2003/06/12 14:56:36 gert Exp $ Copyright (c) Gert Doering"

/* faxrecp.c - part of mgetty+sendfax
 *
 * this module does the "low level" work of receiving fax pages and
 * storing to disk (similar to "faxsend.c" for "low level sending")
 */

#include <stdio.h>
#include "syslibs.h"
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>
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

time_t call_start;		/* initialized in mgetty.c */

RETSIGTYPE fax_sig_hangup(SIG_HDLR_ARGS)
{
    signal( SIGHUP, fax_sig_hangup );
    /* exit if we have not read "+FHNG:xxx" yet (unexpected hangup) */
    if ( ! fax_hangup )
    {
	lprintf( L_WARN, "how rude, got hangup! exiting..." );
	exit(5);
    }
}

static boolean fax_timeout = FALSE;

RETSIGTYPE fax_sig_alarm(SIG_HDLR_ARGS)
{
    signal( SIGALRM, fax_sig_alarm );
    lprintf( L_MESG, "timeout..." );
    fax_timeout = TRUE;
}

char *	fax_file_names = NULL;
int	fax_fn_size = 0;

int fax_get_page_data _P6((fd, pagenum, directory, uid, gid, file_mode),
			  int fd, int pagenum, char * directory,
			  int uid, int gid, int file_mode )
{
char	temp[MAXPATH];
int	fax_fd;
FILE *	fax_fp;
char	c;
char	WasDLE;
int	ErrorCount = 0;
int	ByteCount = 0;
int i,j;
extern  char * Device;
char	DevId[3];

    /* call_start is only initialized if we're called from mgetty, not
     * when fax polling (sendfax) or from another getty (contrib/faxin).
     * So, eventually set it here
     */

    if ( call_start == 0L ) call_start = time( NULL );

    /* generate spool file name
     *
     * the format depends on the length of filenames allowed. If only
     * short filenames are allowed, it is f[nf]iiiiiii.jj, iii being
     * kind of a sequence number and jj the page number.
     * if long filenames are allowed, the filename will include the
     * fax id of the sending fax
     * the "iiiiii" part will start repeating after approx. 8 years
     */

    /* on some systems -- solaris2 -- the device name may look like
     * "/dev/cub/a", so use "ba" instead of "/a" for the device id
     */

    strcpy( DevId, &Device[strlen(Device)-2] );
    if ( DevId[0] == '/' ) DevId[0] = Device[strlen(Device)-3];
    if ( DevId[0] == '/' ) DevId[0] = '-';

#ifdef SHORT_FILENAMES
    sprintf(temp, "%s/f%c%07x%s.%02d", directory,
		 (fax_par_d.vr == 0 || fax_par_d.vr == 8) ? 'n': 'f',
	         (int) call_start & 0xfffffff,
	         DevId, pagenum );
#else
    /* include sender's fax id - if present - into filename */
    sprintf(temp, "%s/f%c%07x%s-", directory,
		(fax_par_d.vr == 0 || fax_par_d.vr == 8) ? 'n': 'f',
		(int) call_start & 0xfffffff,
		DevId );
    i = strlen(temp);

    /* filter out all characters but a-z, 0-9 */
    for ( j=0; fax_remote_id[j] != 0; j++ )
    {
	char c = fax_remote_id[j];

	if ( isalnum(c) ) temp[i++] = c;
	else
	    { if ( temp[i-1] != '-' ) temp[i++] = '-' ; }
    }
    if ( temp[i-1] == '-' ) i--;
    sprintf( &temp[i], ".%02d", pagenum );
#endif

    if ( checkspace(directory) < 1 )
    {
	lprintf( L_ERROR, "Not enough space on %s for fax reception - dropping line", directory);
	return ERROR;
    }

    fax_fd = open( temp, O_WRONLY|O_EXCL|O_CREAT, 0440 );

    if ( fax_fd < 0 )
    {
	lprintf( L_ERROR, "opening %s failed, giving up", temp );
	return ERROR;
    }

    fax_fp = fdopen( fax_fd, "w" );

    /* do permission and owner changes as soon as possible -- security */

    /* change file mode */
    if ( file_mode != -1 &&
	 chmod( temp, file_mode ) != 0 ) 
    {
	lprintf( L_ERROR, "fax_get_page_data: cannot change file mode" );
    }

    /* change file owner and group (jcp) */
    if ( uid != -1 &&
	 chown( temp, (uid_t) uid, (gid_t) gid ) != 0 )
    {
	lprintf( L_ERROR, "fax_get_page_data: cannot change owner, group" );
    }


    /* store file name in fax_file_names */

    if ( fax_file_names != NULL )
	if ( strlen( temp ) + strlen( fax_file_names ) + 2 > fax_fn_size )
	{
	    fax_fn_size += MAXPATH * 2;
	    fax_file_names = realloc( fax_file_names, fax_fn_size );
	}
    if ( fax_file_names != NULL )
    {
	strcat( fax_file_names, " " );
	strcat( fax_file_names, temp );
    }

    /* install signal handlers */
    signal( SIGALRM, fax_sig_alarm );
    signal( SIGHUP, fax_sig_hangup );
    fax_timeout = FALSE;

    WasDLE = 0;

    /* skip any leading garbage
     * it's reasonable to assume that a fax will start with a zero
     * byte (actually, T.4 requires it).
     * This has the additional benefit that we'll see error messages
     */

    lprintf( L_NOISE, "fax_get_page_data: wait for EOL, got: " );
    alarm( FAX_PAGE_TIMEOUT );

    while ( !fax_timeout )
    {
	if ( mdm_read_byte( fd, &c ) != 1 )
	{
	    lprintf( L_ERROR, "error waiting for page start" );
	    return ERROR;
	}
	lputc( L_NOISE, c );
	if ( c == 0 )   { fputc( c, fax_fp ); break; }
	if ( c == DLE ) { WasDLE = 1; break; }
    }

    lprintf( L_MESG, "fax_get_page_data: receiving %s...", temp );

    while ( !fax_timeout )
    {
	/* refresh alarm timer every 1024 bytes
	 * (to refresh it for every byte is far too expensive)
	 */
	if ( ( ByteCount & 0x3ff ) == 0 )
	{
	    alarm(FAX_PAGE_TIMEOUT);
	}

	if ( mdm_read_byte( fd, &c ) != 1 )
	{
	    ErrorCount++;
	    lprintf( L_ERROR, "fax_get_page_data: cannot read from port (%d)!",
	                      ErrorCount );
	    if (ErrorCount > 10) return ERROR;
	}
	ByteCount++;

	if ( !WasDLE )
	{
	    if ( c == DLE ) WasDLE = 1;
	               else fputc( c, fax_fp );
	}
	else	/* WasDLE */
	{
	    if ( c == DLE ) fputc( c, fax_fp );		/* DLE DLE -> DLE */
	    else
	      if ( c == SUB )				/* DLE SUB -> 2x DLE */
	    {						/* (class 2.0) */
		fputc( DLE, fax_fp ); fputc( DLE, fax_fp );
	    }
	    else
	      if ( c == ETX ) break;			/* DLE ETX -> end */
	    
	    WasDLE = 0;
	}
    }

    alarm(0);

    fclose( fax_fp );

    lprintf( L_MESG, "fax_get_page_data: page end, bytes received: %d", ByteCount);

    if ( fax_timeout )
    {
	lprintf( L_MESG, "fax_get_page_data: aborting receive, timeout!" );
	return ERROR;
    }

    return NOERROR;
}

/* receive fax pages
 * will return the number of received pages in *pagenum
 */

int fax_get_pages _P6( (fd, pagenum, dirlist, uid, gid, mode ),
		       int fd, int * pagenum, char * dirlist,
		       int uid, int gid, int mode )
{
static const char start_rcv = DC2;

    char directory[MAXPATH];
    char * p, * p_help;

    /* find a directory in dirlist that has enough free disk space
     * (2x minfree). If none has "plenty", use the last one, until
     * space in there is less than 1x minfree, then give up.
     */
    p = dirlist;

    do
    {
        int l = strlen(p)+1;
	if ( l > sizeof(directory)-1 ) l=sizeof(directory)-1;

    	p_help = memccpy( directory, p, ':', l );

	if ( p_help != NULL ) { *(p_help-1) = '\0'; p++; }
	directory[l] = '\0';
	p += strlen(directory);

	if ( access( directory, W_OK ) < 0 )
	{
	    lprintf( L_ERROR, "fax_get_pages: can't write to '%s'", directory);
	    continue;
	}

        if ( checkspace(directory) > 1 )  { break; }

	lprintf( L_WARN, "fax_get_pages: not enough disk space in '%s'",
		 directory);
    }
    while( *p != '\0' );

    *pagenum = 0;

    /* allocate memory for fax page file names
     */

    fax_file_names = malloc( fax_fn_size = MAXPATH * 4 );
    if ( fax_file_names != NULL ) fax_file_names[0] = 0;

    if ( fax_poll_req || fax_hangup )
    {
	lprintf( L_MESG, "fax_get_pages: no pages to receive" );
	return NOERROR;
    }

    /* send command for start page receive
     * read: +FCFR:, [+FTSI, +FDCS:], CONNECT
     */

    if ( fax_command( "AT+FDR", "CONNECT", fd ) == ERROR )
    {
	lprintf( L_WARN, "fax_get_pages: cannot start page receive" );
	return ERROR;
    }

    while ( !fax_hangup && !fax_poll_req )	/* page receive loop */
    {
	/* send command for start receive page data */
	lprintf( L_NOISE, "sending DC2" );
	write( fd, &start_rcv, 1);

	/* read page data (into temp file), change <DLE><DLE> to <DLE>,
	   wait for <DLE><ETX> for end of data */

	if ( fax_get_page_data( fd, ++(*pagenum), directory,
			        uid, gid, mode ) == ERROR )
	{
	    fax_hangup_code = -1;
	    return ERROR;
	}

	/* read +FPTS:1 +FET 0 / 2 */

	if ( fax_wait_for( "OK", fd ) == ERROR ) return ERROR;

	/* check line count and bad line count. If page too short (less
	 * than 50 lines) or bad line count too high (> lc/5), reject
	 * page (+FPS=2, MPS, page bad - retrain requested)
	 *
	 * Don't do this on generic Rockwell modems.  It won't work.
	 */

	if ( ( modem_quirks & MQ_NO_LQC ) == 0 &&
	     fhs_details &&
	     ( fhs_lc < 50 || fhs_blc > (fhs_lc/10)+30 || fhs_blc > 500 ) )
	{
	    lprintf( L_WARN, "Page doesn't look good, request retrain (MPS)" );

	    fax_command( "AT+FPS=2", "OK", fd );
	}

	/* teergrubing mode (s)
	 */
	if ( modem_quirks & 0x100 )
	{
	    lprintf( L_WARN, "teergrubing -> signalling 'page bad'" );
	    fax_command( "AT+FPS=2", "OK", fd );
	}
	if ( modem_quirks & 0x200 )
	{
	    lprintf( L_WARN, "teergrubing -> hanging up hard" );
	    fax_command( "ATH0", "OK", fd );
	    return ERROR;
	}

	/* send command to receive next page
	 * and to release post page response (+FP[T]S) to remote fax
	 */
	fax_send( "AT+FDR", fd );

	/* read: +FCFR, [+FDCS:], CONNECT */
	/* if it was the *last* page, modem will send +FHNG:0 ->
	 * fax_hangup will be set to TRUE
	 */

	if ( fax_wait_for( "CONNECT", fd ) == ERROR ) return ERROR;
    }

    return NOERROR;
}
