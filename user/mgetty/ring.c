#ident "$Id: ring.c,v 4.20 2005/03/23 09:56:57 gert Exp $ Copyright (c) Gert Doering"

/* ring.c
 *
 * This module handles incoming RINGs, distinctive RINGs (RING 1, RING 2,
 * etc.), and out-of-band messages (<DLE>v, "CONNECT", ...).
 *
 * Also, on ISDN "modems", multiple subscriber numbers (MSN) are mapped
 * to distinctive RING types. At least, if the ISDN device returns this
 * data.  It's known to work for ZyXEL and ELSA products.
 *
 * Works closely with "cnd.c" to grab CallerID for analog modems.
 */

#include <stdio.h>
#include "syslibs.h"
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>

#ifndef EINTR
#include <errno.h>
#endif

#include "mgetty.h"
#include "policy.h"
#include "tio.h"
#include "fax_lib.h"

/* strdup variant that returns "<null>" in case of out-of-memory */
static char * safedup( char * in )
{
    char * p = strdup( in );
    return ( p == NULL ) ? "<null>" : p;
}

/* find number given in msn_list, return index */
static int find_msn _P2((string, msn_list),
			 char * string, char ** msn_list )
{
int i, len, len2;
char * p;

    lprintf( L_NOISE, "MSN: '%s'", string );
    CalledNr = safedup(string);			/* save away */

    if ( msn_list == NULL ) return 0;		/* nothing to match against */

    len=strlen(string);

    /* hack off sub-addresses ("<msn>/<subaddr>")
     * (future versions could do comparisons with and without subaddr...) */
    p = strchr( string, '/' );
    if ( p != NULL ) { len = (p - string); }

    for( i=0; msn_list[i] != NULL; i++ )
    {
	lprintf( L_JUNK, "match: '%s'", msn_list[i] );
	len2=strlen( msn_list[i] );
	if ( len2 <= len && 
	     strncmp( msn_list[i], &string[len-len2], len2 ) == 0 )
		{ return i+1; }
    }
    return 0;				/* not found -> unspecified */
}

/* ELSA CallerID data comes in as "RING;<from>[;<to>]"
 *
 * this function is also used for others that report the number in
 * the format [non-digit(s)]<from>[non-digit(s)]<to>
 */
static int ring_handle_ELSA _P2((string, msn_list),
				 char * string, char ** msn_list )
{
char * p;
char ch;

    lprintf( L_MESG, "ELSA: '%s'", string );

    /* remember first character, for differenciation between
     * ELSA-style ("RING;from") and ISDN4Linux ("RING/to") [grrr]
     */
    ch = *string;

    /* skip over leading "garbage" */
    while( *string != '\0' && !isdigit(*string) ) string++;

    /* grab caller number (all up to the first non-digit) */
    p=string;
    while( isdigit(*p) ) p++;

    if ( *p == '\0' )		/* only one number listed */
    {
	if ( ch == '/' )	/* isdn4linux -> number is MSN */
	    return find_msn( string, msn_list );

				/* not -> it's caller ID, and no MSN */
	CallerId = safedup( string );
	return 0;
    }
    else			/* MSN listed -> terminate string, get MSN */
    {
	*p = '\0';
	CallerId = safedup( string );

	p++;
	while( *p != '\0' && !isdigit(*p) ) p++;

	return find_msn( p, msn_list );
    }
}

/* Zoom MX/S CallerID data comes in as "RING: <type> DN<id> <from> <?>"
 * contributed by Thomas Schuett <info@thomas-schuett.de> */
static int ring_handle_ZoomMX _P1((string), char * string)
{
char * p;
    lprintf( L_MESG, "Zoom MX/S: '%s'", string );

    p=&string[8];
    while( isdigit(*p) ) p++;

    *p = '\0';
    CallerId = safedup( &string[8] );
    return ( string[6]-'0');
}

/* ZyXEL CallerID data comes in as "FM:<from> [TO:<to>]" or "TO:<to>"
 *
 * unless Subadressing is used, in which case this looks like
 *   [FM:[CallingPN] [/Subaddress/]][TO:[CalledPN] [/Subaddress/]]
 * for now, subaddresses are completely ignored (here and in find_msn)
 */
static int ring_handle_ZyXEL _P2((string, msn_list),
				 char * string, char ** msn_list )
{
char * p, ch;
    lprintf( L_MESG, "ZyXEL: '%s'", string );

    if ( strncmp( string, "FM:", 3 ) == 0 )		/* caller ID */
    {
	string+=3;
	p=string;
	while( isdigit(*p) ) p++;
	ch = *p; *p = '\0';
	CallerId = safedup(string);
	*p = ch;
	while( isspace(*p) ) p++;

	/* skip potential sub-addresses ("/<something>/") */
	if ( *p == '/' )
	{
	    p++; 
	    while ( *p != '\0' && *p != '/' ) { p++; }
	    if ( *p != '\0' ) p++;
	}
	string = p;
    }
    if ( strncmp( string, "TO:", 3 ) == 0 )		/* target msn */
    {
	return find_msn( string+3, msn_list );
    }
    return 0;			/* unspecified */
}

/* handle V.253 DRON/DROF result codes 
 * (signalling "Ring ON" / "Ring OFf" time)
 *
 * basically we build a binary word from the RINGs, and use that as 
 * distinctive RING number.  "Long" = 1, "Short" = 0
 *
 * the very first code (always DROF) is always "long".
 *
 * example cadence (standard verizon "one long RING" call):
 *  DROF=0
 *  DRON=11
 *  RING
 *  DROF=40
 *  DRON=20
 *  RING
 */
static int drox_bitstring;
static int drox_count;
static void ring_handle_DROx( char * p )
{
    int len, bit;

    /* skip whitespace and '=' (covers "DRON=nnn" and "DRON = nnn")
     */
    while( isspace(*p) || *p == '=' ) { p++; }

    len = atoi( p );

    bit = ( drox_count == 0 || len > 9 ) ? 1 : 0;

    lputs( L_NOISE, bit? "<long>": "<short>" );

    drox_bitstring = (drox_bitstring << 1 ) | bit;
    drox_count++;
}


static boolean chat_has_timeout;
static RETSIGTYPE chat_timeout(SIG_HDLR_ARGS)
{
    chat_has_timeout = TRUE;
}

extern boolean virtual_ring;

int wait_for_ring _P6((fd, msn_list, timeout, 
		       actions, action, dist_ring_number),
		int fd, char ** msn_list, int timeout, 
	        chat_action_t actions[], action_t * action,
		int * dist_ring_number )
{
#define BUFSIZE 500
char	buf[BUFSIZE], ch, *p;
int	i, w, r;
int	rc = SUCCESS;
boolean	got_dle;		/* for <DLE><char> events (voice mode) */

    lprintf( L_MESG, "wfr: waiting for ``RING''" );
    lprintf( L_NOISE, "got: ");

    w=0;
    got_dle = FALSE;

    signal( SIGALRM, chat_timeout );
    alarm( timeout );
    chat_has_timeout = FALSE;

    while(TRUE)
    {
	if ( virtual_ring )
	{
	    lputs( L_NOISE, "``found''" );
	    break;
	}

	r = mdm_read_byte( fd, &ch );

	if ( r <= 0 )				/* unsuccessful */
	{
	    if ( chat_has_timeout )		/* timeout */
		lprintf( L_WARN, "wfr: timeout waiting for RING" );
	    else
		lprintf( L_ERROR, "wfr: error in read()" );

	    if ( action != NULL ) *action = A_TIMOUT;
	    rc = FAIL; break;
	}

	lputc( L_NOISE, ch );

	/* In voice mode, modems send <DLE><x> sequences to signal
	 * certain events, among them (IS-101) "RING".
	 */
	if ( got_dle )		/* last char was <DLE> */
	{
	    switch( ch )
	    {
		case 'h':
		case 'p':	/* handset on hook */
		case 'H':
		case 'P':	/* handset off hook */
		case 'r':	/* ringback detected */
		    *dist_ring_number = - (int)ch; 
		    goto have_ring; break;
		case 'R':	/* RING detected */
		    *dist_ring_number = 0;
		    goto have_ring; break;
		default:
		    got_dle = FALSE;
	    }
	}
	else 
	    if ( ch == DLE ) got_dle = TRUE;

	/* line termination character? no -> add to buffer and go on */
	if ( ch != '\r' && ch != '\n' )
	{
	    /* skip whitespace at start of buffer */
	    if ( w == 0 && isspace(ch) ) continue;

	    /* add character to buffer */
	    if( w < BUFSIZ-2 )
		buf[w++] = ch;

	    /* check for "actions" */
	    if ( actions != NULL )
	      for( i=0; actions[i].expect != NULL; i++ )
	    {
		int len = strlen( actions[i].expect );
		if ( w == len &&
		     memcmp( buf, actions[i].expect, len ) == 0 )
		{
		    lprintf( L_MESG, "wfr: found action string: ``%s''",
				     actions[i].expect );
		    *action = actions[i].action;
		    rc = FAIL; break;
		}
	    }
	    if ( rc == FAIL ) break;		/* break out of while() */

	    /* go on */
	    continue;
	}

	/* got a full line */
	if ( w == 0 ) { continue; }		/* ignore empty lines */
	buf[w] = '\0';
	cndfind( buf );				/* grab caller ID */

	/* ZyXEL CallerID/MSN display? */
	if ( strncmp( buf, "FM:", 3 ) == 0 ||
	     strncmp( buf, "TO:", 3 ) == 0 )
	    { *dist_ring_number = ring_handle_ZyXEL( buf, msn_list ); break; }

	/* Rockwell (et al) caller ID - handled by cndfind(), but
	 * we count it as "RING" to be able to pick up immediately 
	 * instead of waiting for the next "real" RING
	 * (but don't do this for V253 DRON/DROF modems!)
	 */
	if ( strncmp( buf, "NMBR", 4 ) == 0 && drox_count == 0 ) { break; }

	/* V.253 ring cadences */
	if ( strncmp( buf, "DRON", 4 ) == 0 ||
	     strncmp( buf, "DROF", 4 ) == 0 )
		{ ring_handle_DROx( buf+4 ); w=0; continue; }

	/* now check the different RING types 
	 * if not "RING<whatever>", clear buffer and get next line
	 */
	if ( strncmp( buf, "RING", 4 ) != 0 )
	    { w = 0; lprintf( L_NOISE, "got: " ); continue; }

	p=&buf[4];
	while( isspace(*p) ) p++;

	if ( *p == '\0' )			/* "classic RING" */
	    { break; }

	if ( *p == ';' )			/* ELSA type */
	    { *dist_ring_number = ring_handle_ELSA( p, msn_list ); break; }

	if ( *p== ':' )				/* Zoom MX type */
	    { *dist_ring_number = ring_handle_ZoomMX( p ); break; }
	    
	if ( strlen(p) > 1 )			/* USR type B: "RING 1234" */
	    { *dist_ring_number = ring_handle_ELSA( p, msn_list ); break; }

	if ( isdigit( *p ) )			/* RING 1 */
	    { *dist_ring_number = *p-'0'; break; }

	if ( isalpha( *p ) )			/* RING A */
	    { *dist_ring_number = tolower(*p)-'a' +1; break; }
    }

have_ring:
    alarm(0);

    if ( drox_count > 0 )
    {
	lprintf( L_NOISE, "wfr: DRON/DROF cadence: %x", drox_bitstring );
	*dist_ring_number = drox_bitstring;
	drox_count=0; drox_bitstring=0;
    }

    lprintf( L_NOISE, "wfr: rc=%d, drn=%d", rc, *dist_ring_number );
    return rc;
}
