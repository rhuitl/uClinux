#ident "$Id: do_stat.c,v 4.2 1997/12/08 07:47:01 gert Exp $ Copyright (c) Gert Doering"

/* do_stat.c
 *
 * This module handles grabbing the modem call statistics and logging it
 * (basically, it's a stripped down version of do_chat() with different
 * logging capabilities, working only on a line-by-line basis)
 */

#include <stdio.h>
#include "syslibs.h"
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#ifndef sunos4
#include <sys/ioctl.h>
#endif

#ifndef EINTR
#include <errno.h>
#endif

#include "mgetty.h"
#include "policy.h"
#include "tio.h"


static boolean has_timeout;
static RETSIGTYPE timeout(SIG_HDLR_ARGS)
{
    has_timeout = TRUE;
}

void get_statistics _P3( (fd, expect_send, tgt_file),
			 int fd, char * expect_send[], char * tgt_file )
{
char line[MAXLINE];
int  r;
FILE * fp = NULL;			/* target file */

    if ( tgt_file != NULL )		/* to file, not to lprintf() */
    {
	fp = fopen( tgt_file, "a" );
	if ( fp == NULL )
	    lprintf( L_ERROR, "do_stat: can't open %s", tgt_file );
	else				/* open ok, log time */
	{
	    time_t now = time(NULL);
	    char *snow = ctime( &now );
	    if ( snow )
	        fprintf( fp, "--- %.*s ---\n", (int) strlen(snow)-1, snow);
	}
    }

    while ( *expect_send != NULL )
    {
	/* handle "expect" part */

	r=0;
	if ( **expect_send != 0 )			/* !empty string */
	{
	    lprintf( L_MESG, "do_stat: expect '%s'", *expect_send );

	    /* 10 seconds timeout should be sufficient here */
	    signal( SIGALRM, timeout );
	    alarm(10);

	    while( 1 )
	    {
		if ( read( fd, &line[r], 1 ) != 1 )
		{
		    if ( has_timeout )
			lprintf( L_WARN, "do_stat: timeout" );
		    else
			lprintf( L_ERROR, "do_stat: error reading data" );
		    alarm(0); return;
		}

		if ( line[r] == '\r' || line[r] == '\n' )	/* line full */
		{
		    line[r] = 0;				/* terminate */

		    if ( r != 0 ) 				/* log... */
		    {
			if ( fp == NULL )			/* to logfile */
			    lprintf( L_MESG, "*** %s", line );
			else					/* to stat.f. */
			    fprintf( fp, "%s\n", line );
		    }

		    if ( strncmp( line, *expect_send, 
				  strlen( *expect_send ) ) == 0 )
		    {
			lputs( L_MESG, " ** found **" );  break;
		    }
		    r=0;
		}
		else if ( r<sizeof(line)-1) r++;
	    }						/* expect loop */

	    alarm(0);
	}						/* if (!empty) */

	expect_send++;

	if ( *expect_send == NULL ) break;

	/* handle "send" part */
	do_chat_send( fd, *expect_send );

	expect_send++;
    }

    if ( fp != NULL ) fclose( fp );
}

