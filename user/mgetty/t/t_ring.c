/* $Id: t_ring.c,v 1.3 2005/03/23 09:56:21 gert Exp $
 *
 * test program for mgetty "ring.c"
 *
 * feed wait_for_ring() via mdm_read_char() from here
 *
 * table driven: 
 *   <input string> <# rings> <dist-ring#> <caller id>
 *
 * $Log: t_ring.c,v $
 * Revision 1.3  2005/03/23 09:56:21  gert
 * add test for <DLE>P (handset on-hook)
 *
 * Revision 1.2  2005/03/16 11:06:44  gert
 * add "msnlist" for testing destination number -> distinctive RING mapping
 * add more special cases for CallerID delivery
 * modify ELSA;from;to test case for destination MSN matching
 *
 * Revision 1.1  2005/03/15 13:22:08  gert
 * regression test for "ring.c" module (feed fake character strings, see whether
 * ring count, dist.ring number/MSN, caller ID, etc. match)
 *
 */

#include "mgetty.h"
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#ifdef T_LOG_VERBOSE
# include <stdarg.h>
#endif

char *msnlist[] = {"9999", "35655023", "35655024", "35655025", "4023", NULL};

struct t_ring_tests { char * input;
		      int ring_count;
		      int dist_ring;
		      char * caller_id; } t_ring_tests[] = 
{{"RING\nRING\nRING\n", 3, -1, "" },
 {"RING 2\n", 1, 2, "" },
 {"RING A\nRING B\nRING C\nRING\n", 4, 3, "" },
 {"RING\n    FM:040404\n", 2, 0, "040404" },	/* ZyXEL + whitespc */
 {"RING\nNMBR = 0555\nRING\n", 3, -1, "0555" },	/* Rockwell */
 {"RING/0666\n", 1, 0, "" },			/* i4l - RING/to */
 {"RING;707070\n",      1, 0, "707070" },	/* ELSA - RING;from */
 {"RING;717171;999999\n", 1, 1, "717171" },	/* ELSA - RING;from;to */
 {"RING: 3 DN9 8888\n", 1, 9, "8888" },		/* Zoom */
 {"RING 090909\n", 1, 0, "090909" },		/* USR Type B */
 {"DROF=0\nDRON=11\nRING\nDROF=40\nDRON=20\nRING\n", 2, 3, "" },
						/* V.253 dist ring */
 {"\020R\n\020R\n", 2, 0, "" },			/* voice mode RING */
 {"\020R\n\020P\n", 2, -80, "" },		/* voice mode ACTION */

	/* test MSN matching (right-to-left), ZyXEL format */
 {"RING\nFM:1234 TO:35655023\n",       2, 2, "1234" },	/* exact match */
 {"RING\n FM:4321  TO: 08935655025\n", 2, 4, "4321" },  /* dest# longer */
 {"RING\nFM:5678 TO:356550\n",         2, 0, "5678" },	/* incomplete (l.) */
 {"RING\nFM:8765 TO:023\n",            2, 0, "8765" },	/* incomplete (r.) */

	/* various ways to report caller ID */
 {"RING/01234023\nCALLER NUMBER: 556677\nRING\n", 2, 5, "556677" }, /* i4l */

	/* special things: i4l fmt 2 - not matched vs. msnlist yet (TODO?) */
 {"RING\nCALLED NUMBER: 35655024\n",   1, -1, "" },	/* i4l fmt 2 */

	/* end */
 {NULL, 0, 0, NULL }};

/* TODO: add more tests for other caller ID formats (->cnd.c) */

static char * read_p;

/* fake logging functions */
int lputc( int level, char ch ) { return 0; }
int lputs( int level, char * s ) { return 0; }
int lprintf( int level, const char * format, ...) 
#ifdef T_LOG_VERBOSE
    { va_list pvar; va_start( pvar, format ); 
      vprintf( format, pvar ); putchar('\n'); }
#else
    { return 0; }
#endif

/* fake modem read function */
int mdm_read_byte( int fd, char * c )
{
    while( *read_p != '\0' )
	{ *c = *read_p++; return 1; }

    /* nothing more in buffer -> pretend timeout */
    raise(SIGALRM);
    errno = EINTR;
    return -1;
}

boolean virtual_ring = FALSE;

int main( int argc, char ** argv )
{
    int rings, dist_ring;
    action_t what_action;
    struct t_ring_tests *t = t_ring_tests;
    int i;
    int fail = 0;

    i = 1;
    while( t->input != NULL )
    {
        read_p = t->input;
	rings = 0;
	dist_ring = -1;
	CallerId = "";
	while( wait_for_ring( STDIN, msnlist, 10, NULL /* actions */,
			       &what_action, &dist_ring ) == SUCCESS )
	{
	    rings ++;
	}

	if ( rings != t->ring_count )
	{
	    fprintf( stderr, " %02d failed: rings=%d, should be %d\n",
				i, rings, t->ring_count );
	    fail++;
	}
	if ( dist_ring != t->dist_ring )
	{
	    fprintf( stderr, " %02d failed: dist_ring=%d, should be %d\n",
				i, dist_ring, t->dist_ring );
	    fail++;
	}
	if ( strcmp( CallerId, t->caller_id ) != 0  )
	{
	    fprintf( stderr, " %02d failed: caller_id='%s', should be '%s'\n",
				i, CallerId, t->caller_id );
	    fail++;
	}
	/* TODO: test actions */
	/* TODO: feed with msn_list (char **, 2nd parameter) */
	t++; i++;
    }

    if ( fail>0 )
	fprintf( stderr, "total: %d failed tests\n", fail );
    return (fail>0);
}
