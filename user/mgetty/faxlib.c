#ident "$Id: faxlib.c,v 4.58 2004/11/13 22:14:31 gert Exp $ Copyright (c) Gert Doering"

/* faxlib.c
 *
 * Module containing generic faxmodem functions (as: send a command, wait
 * for modem responses, parse modem responses)
 *
 * Only class 2 and class 2.0 stuff is here. Class 1 stuff is so
 * different that it goes to a separate library.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include "mgetty.h"
#include "policy.h"
#include "fax_lib.h"

Modem_type modem_type = Mt_unknown;	/* uninitialized */

char	fax_remote_id[40];		/* remote FAX id +FTSI */
char	fax_param[1000];		/* transm. parameters +FDCS */
fax_param_t	fax_par_d;		/* fax params detailed */
char	fax_hangup = 0;
int	fax_hangup_code = FHUP_UNKNOWN;	/* hangup cause +FHNG:<xxx> */
int	fax_page_tx_status = 0;		/* +FPTS:<ppm> */
boolean	fax_to_poll = FALSE;		/* there's something to poll */
boolean fax_poll_req = FALSE;		/* poll requested */

boolean	fhs_details = FALSE;		/* +FHS:xxx with detail info */
int	fhs_lc, fhs_blc, fhs_cblc, fhs_lbc;

int	modem_quirks = 0;		/* modem specials */


/* wait for a given modem response string,
 * handle all the various class 2 / class 2.0 status responses
 */

/* copy fax station id, removing quote characters (dangerous for shell!)
 * and leading/trailing whitespace
 */
static void fwf_copy_remote_id _P1( (id), char * id )
{
int w = 0;

    while ( isspace(*id) || *id == '"' ) id++;	/* skip leading whitespace */

    while ( *id && w < sizeof(fax_remote_id)-1 )
    {
        if ( *id != '"' && *id != '\'' ) fax_remote_id[w++] = *id;
        id++;
    }

    /* remove trailing whitespace */
    while ( w>0 && isspace(fax_remote_id[w-1]) ) w--;

    fax_remote_id[w]=0;
}

static boolean fwf_timeout = FALSE;

static RETSIGTYPE fwf_sig_alarm(SIG_HDLR_ARGS)      	/* SIGALRM handler */
{
    signal( SIGALRM, fwf_sig_alarm );
    lprintf( L_WARN, "Warning: got alarm signal!" );
    fwf_timeout = TRUE;
}

int fax_wait_for _P2( (s, fd),
		      char * s, int fd )
{
char * line;
int  ix;

    lprintf( L_MESG, "fax_wait_for(%s)", s );

    if ( fax_hangup )
    {
	lputs( L_MESG, ": already hangup!" );
	return ERROR;
    }

    fwf_timeout = FALSE;
    signal( SIGALRM, fwf_sig_alarm );

    alarm( FAX_RESPONSE_TIMEOUT );

    do
    {
	line = mdm_get_line( fd );

	if ( line == NULL )
	{
	    alarm( 0 ); signal( SIGALRM, SIG_DFL );
	    if ( fwf_timeout ) fax_hangup_code = FHUP_TIMEOUT;
	    return ERROR;
	}
	
	lprintf( L_NOISE, "fax_wait_for: string '%s'", line );

	/* find ":" character (or end-of-string) */
	for ( ix=0; line[ix] != 0; ix++ )
	    if ( line[ix] == ':' ) { ix++; break; }
	if ( line[ix] == ' ' ) ix++;

	if ( strncmp( line, "+FTSI:", 6 ) == 0 ||
	     strncmp( line, "+FCSI:", 6 ) == 0 ||
	     strncmp( line, "+FCIG:", 6 ) == 0 ||
	     strncmp( line, "+FTI:", 5 ) == 0 ||
	     strncmp( line, "+FCI:", 5 ) == 0 ||
	     strncmp( line, "+FPI:", 5 ) == 0 )
	{
	    lprintf( L_MESG, "fax_id: '%s'", line );
	    fwf_copy_remote_id( &line[ix] );
	}

	else if ( strncmp( line, "+FDCS:", 6 ) == 0 ||
		  strncmp( line, "+FCS:", 5 ) == 0 )
	{
	    lprintf( L_MESG, "transmission par.: '%s'", line );
	    strcpy( fax_param, line );
	    if ( sscanf( &fax_param[ix], "%hd,%hx,%hd,%hd,%hd,%hd,%hd,%hd",
			 &fax_par_d.vr, &fax_par_d.br, &fax_par_d.wd,
			 &fax_par_d.ln, &fax_par_d.df, &fax_par_d.ec,
			 &fax_par_d.bf, &fax_par_d.st ) != 8 )
	    {
		lprintf( L_WARN, "cannot evaluate +FCS-Code!" );
		fax_par_d.vr = 0;
	    }
	}

	else if ( strncmp( line, "+FHNG:", 6 ) == 0 ||
		  strncmp( line, "+FHS:", 5 ) == 0 )
	{
	    /* hangup. First, set flag to indicate +FHNG: was read.
	     * The SIGHUP signal catcher will check this, and not exit.
	     * Next, reset the action for SIGHUP, to be ignore, so we
	     * (and child processes) are not interrupted while we cleanup.
	     * If the wait_for string is not "OK", return immediately,
	     * since that is all that the modem can send after +FHNG
	     */
	    fax_hangup = 1; /* set this as soon as possible */
	    /* change action for SIGHUP signals to be ignore */
#ifdef SIG_ERR
	    if ( signal( SIGHUP, SIG_IGN ) == SIG_ERR )
	    {
		lprintf( L_WARN, "fax_wait_for: cannot reset SIGHUP handler." );
	    }
#else
	    signal( SIGHUP, SIG_IGN );
#endif
	    lprintf( L_MESG, "connection hangup: '%s'", line );
	    sscanf( &line[ix], "%d", &fax_hangup_code );

	    lprintf( L_NOISE,"(%s)", fax_strerror( fax_hangup_code ));

	    if ( strcmp( s, "OK" ) != 0 ) break;
	}

	else if ( strncmp( line, "+FPTS:", 6 ) == 0 ||
		  strncmp( line, "+FPS:", 5 ) == 0 )
	{
	    /* page transmit status
	     * store into global variable (read by sendfax.c)
	     */
	    lprintf( L_MESG, "page status: %s", line );
	    sscanf( &line[ix], "%d", &fax_page_tx_status );

	    /* evaluate line count, bad line count, ... for reception */
	    fhs_lc = 9999; fhs_blc = fhs_cblc = fhs_lbc = 0;
	    fhs_details = FALSE;

	    if ( line[ix+1] == ',' &&		/* +FPS:s,lc,blc */
		 sscanf( &line[ix+2],
			 ( modem_type == Mt_class2 || 
			  (modem_quirks & MQ_FPS_NOT_HEX) )
			                          ?"%d,%d,%d,%d"
						  :"%x,%x,%x,%x",
		         &fhs_lc, &fhs_blc, &fhs_cblc, &fhs_lbc ) >= 2 )
	    {
		lprintf( L_NOISE, "%d lines received, %d lines bad, %d bytes lost", fhs_lc, fhs_blc, fhs_lbc );
		fhs_details = TRUE;
	    }
	}

	else if ( strcmp( line, "+FPOLL" ) == 0 ||
		  strcmp( line, "+FPO" ) == 0 )
	{
	    /* the other side is telling us that it has a document that
	     * we can poll (with AT+FDR)
	     */
	    lprintf( L_MESG, "got +FPO -> will do polling" );
	    fax_to_poll = TRUE;
	}

	else if ( strncmp( line, "+FDTC:", 6 ) == 0 ||
		  strncmp( line, "+FTC:", 5 ) == 0 )
	{
	    /* we sent a +FLPL=1, and the other side wants to poll
	     * that document now (send it with AT+FDT)
	     */
	    lprintf( L_MESG, "got +FTC -> will send polled document" );
	    fax_poll_req = TRUE;
	    
	    /* we're waiting for a CONNECT here, in response to a
	     * AT+FDR command, but only an OK will come. So, change
	     * expect string to "OK"
	     */
	    lprintf( L_MESG, "fax_wait_for('OK')" );
	    s = "OK";
	}
	
	else
	if ( strcmp( line, "ERROR" ) == 0 ||
	     strcmp( line, "NO CARRIER" ) == 0 ||
	     strcmp( line, "BUSY" ) == 0 ||
	     strcmp( line, "NO DIALTONE" ) == 0 ||
	     strcmp( line, "NO DIAL TONE" ) == 0 )
	{
#if 0		/* not needed right now (fax_send_ppm), problem with USR!! */
	    if ( modem_type == Mt_class2_0 )		/* valid response */
	    {						/* in class 2.0! */
		if ( strcmp( line, "ERROR" ) == 0 )
		{
		    lprintf( L_MESG, "ERROR response" );
		    alarm(0);
		    return NOERROR;			/* !C2 */
		}
	    }
#endif

	    /* in class 2, one of the above codes means total failure */
	    
	    lprintf( L_MESG, "ABORTING: line='%s'", line );
	    fax_hangup = 1;
	    
	    if ( strcmp(line, "BUSY") == 0 ) fax_hangup_code = FHUP_BUSY;
	    else if (strcmp(line, "NO DIALTONE") == 0 ||
		     strcmp(line, "NO DIAL TONE") == 0)
	                                     fax_hangup_code = FHUP_NODIAL;
	    else                             fax_hangup_code = FHUP_ERROR;
	    
	    alarm( 0 ); signal( SIGALRM, SIG_DFL );
	    return ERROR;
	}

    }
    while ( strncmp( s, line, strlen(s) ) != 0 );
    lputs( L_MESG, "** found **" );

    alarm( 0 );
    signal( SIGALRM, SIG_DFL );

    if ( fax_hangup && fax_hangup_code != 0 ) return ERROR;

    return NOERROR;
}

/* (re-) initialize all global/static variables set by faxlib.c
 * necessary if fax state machine runs multiple times, e.g. in vgetty
 */
void faxlib_init _P0( void )
{
    fax_hangup = 0;
    fax_hangup_code = FHUP_UNKNOWN;
    fax_page_tx_status = 0;
    fax_to_poll = fax_poll_req = FALSE;
    fhs_details = FALSE;
    fax_remote_id[0] = '\0';
}

/* send a command string to the modem, terminated with the
 * MODEM_CMD_SUFFIX character / string from policy.h
 */

int fax_send _P2( (send, fd),
		  char * send, int fd )
{
#ifdef FAX_COMMAND_DELAY
    delay(FAX_COMMAND_DELAY);
#endif

    lprintf( L_MESG, "fax_send: '%s'", send );

    if ( write( fd, send, strlen( send ) ) != strlen( send ) ||
	 write( fd, MODEM_CMD_SUFFIX, sizeof(MODEM_CMD_SUFFIX)-1 ) !=
	        ( sizeof(MODEM_CMD_SUFFIX)-1 ) )
    {
	lprintf( L_ERROR, "fax_send: cannot write" );
	return ERROR;
    }

    return NOERROR;
}

/* simple send / expect sequence, but pass "expect"ing through
 * fax_wait_for() to handle all the class 2 fax responses
 */

int fax_command _P3( (send, expect, fd),
		     char * send, char * expect, int fd )
{
    if ( fax_send( send, fd ) == ERROR ) return ERROR;
    return fax_wait_for( expect, fd );
}

/* Couple of routines to set this and that fax parameter, using class 2
 * or 2.0 commands, according to the setting of "modem_type"
 */

/* set local fax id */

int fax_set_l_id _P2( (fd, fax_id), int fd, char * fax_id )
{
    char flid[60];

#ifdef CLASS1
    if ( modem_type == Mt_class1 )
		return fax1_set_l_id( fd, fax_id );
#endif

    if ( modem_type == Mt_class2_0 )
        sprintf( flid, "AT+FLI=\"%.40s\"",  fax_id );
    else
        sprintf( flid, "AT+FLID=\"%.40s\"", fax_id );
    
    if ( mdm_command( flid, fd ) == FAIL )
    {
	lprintf( L_MESG, "cannot set local fax id. Huh?" );
	return ERROR;
    }
    return NOERROR;
}

/* set resolution, minimum and maximum bit rate */
int fax_set_fdcc _P4( (fd, fine, max, min),
		      int fd, int fine, int max, int min )
{
    char buf[50];

#ifdef CLASS1
    if ( modem_type == Mt_class1 )
		return fax1_set_fdcc( fd, fine, max, min );
#endif

#ifdef FAX_USRobotics			/* will go away...! */
    modem_quirks |= MQ_USR_FMINSP;
#endif

    if ( modem_quirks & MQ_USR_FMINSP )
    {
	/* some early versions of the USR fax firmware got this wrong, (put 
	 * "max" speed into register for "min" speed!!) so don't set speed
	 */
	sprintf( buf, "AT+FCC=%d", fine );
    }
    else				/* standard case, working modem */
    {
	sprintf( buf, "AT%s=%d,%d,0,2,0,0,0,0",
		 (modem_type == Mt_class2_0) ? "+FCC" : "+FDCC",
		 fine, (max/2400) -1 );
    }
    
    if ( mdm_command( buf, fd ) == ERROR )
    {
	if ( max > 9600 )
	    return fax_set_fdcc( fd, fine, 9600, min );
	else
	    return ERROR;
    }

    if ( min >= 2400 )
    {
	if ( modem_type == Mt_class2_0 )
	    sprintf( buf, "AT+FMS=%d", (min/2400) -1 );
	else
	    sprintf( buf, "AT+FMINSP=%d", (min/2400) -1 );

	if ( mdm_command( buf, fd ) == ERROR )
	{
	    lprintf( L_WARN, "+FMINSP command failed, ignoring" );
	}
    }
    return NOERROR;
}

/* set modem flow control (for fax mode only)
 *
 * right now, this works only for class 2.0 faxing. Class 2 has
 * no idea of a common flow control command.
 * If hw_flow is set, use RTS/CTS, otherwise, use Xon/Xoff.
 */

int fax_set_flowcontrol _P2( (fd, hw_flow), int fd, int hw_flow )
{
    if ( modem_type == Mt_class2_0 )
    {
	if ( hw_flow )
	{
	    if ( mdm_command( "AT+FLO=2", fd ) == NOERROR ) return NOERROR;
	    lprintf( L_WARN, "modem doesn't like +FLO=2; using Xon/Xoff" );
	}
	return mdm_command( "AT+FLO=1", fd );
    }
    return NOERROR;
}


/* byte swap table used for sending (yeah. Because Rockwell screwed
 * up *that* completely in class 2, we have to have different tables
 * for sending and receiving. Bah.)
 */
unsigned char fax_send_swaptable[256];

/* set up bit swap table */

static 
void fax_init_swaptable _P2( (direct, byte_tab),
			      int direct, unsigned char byte_tab[] )
{
int i;
    if ( direct ) for ( i=0; i<256; i++ ) byte_tab[i] = i;
    else
      for ( i=0; i<256; i++ )
	     byte_tab[i] = ( ((i & 0x01) << 7) | ((i & 0x02) << 5) |
			     ((i & 0x04) << 3) | ((i & 0x08) << 1) |
			     ((i & 0x10) >> 1) | ((i & 0x20) >> 3) |
			     ((i & 0x40) >> 5) | ((i & 0x80) >> 7) );
}

/* set modem bit order, and initialize bit swap table accordingly */

int faxmodem_bit_order = 0;

int fax_set_bor _P2( (fd, bor), int fd, int bor )
{
    char buf[20];
#ifdef CLASS1
    if ( modem_type == Mt_class1 )
		return fax1_set_bor( fd, bor );
#endif

    faxmodem_bit_order = bor;

    fax_init_swaptable( faxmodem_bit_order & 1, fax_send_swaptable );
    
    if ( modem_type == Mt_class2_0 )
        sprintf( buf, "AT+FBO=%d", bor );
    else
        sprintf( buf, "AT+FBOR=%d", bor );

    return mdm_command( buf, fd );
}


/* find out the type of modem connected
 *
 * controlled by the "mclass" parameter ("auto", "cls2", "c2.0", "data")
 */

Modem_type fax_get_modem_type _P2( (fd, mclass), int fd, char * mclass )
{
int rc;
char *mc;

    /* data modem? unknown mclass? handle as "auto" (for sendfax) */
    if ( strcmp( mclass, "cls2" ) != 0 &&
	 strcmp( mclass, "c2.0" ) != 0 &&
	 strcmp( mclass, "auto1") != 0 &&
	 strcmp( mclass, "cls1" ) != 0 )
    {
	mclass = "auto";
    }

    /* auto-identify via ATI code */
    if ( strcmp( mclass, "auto" ) == 0 )
    {
	if ( mdm_identify( fd ) != NOERROR )  		/* error? */
			    { mclass = "auto1"; }	/* try auto1 */
    }

    /* "auto1" is a variant of auto-identify, using AT+FCLASS=?
     */
    if ( strcmp( mclass, "auto1" ) == 0 )
    {
	mc = mdm_get_idstring( "AT+FCLASS=?", 1, fd );

	lprintf( L_MESG, "available modem classes: %s", mc );

	if      ( strstr( mc, "2.1" ) != NULL ) { modem_type = Mt_class2_1; }
	else if ( strstr( mc, "2.0" ) != NULL ) { modem_type = Mt_class2_0; }
	else if ( strstr( mc, "2" ) != NULL )   { modem_type = Mt_class2; }
    }

    if ( modem_type != Mt_unknown )
    {
	/* set up modem accordingly */
	switch( modem_type )
	{
	    case Mt_class2_0: 
		rc=mdm_command( "AT+FCLASS=2.0", fd ); 
		break;
	    case Mt_class2:
		rc=mdm_command( "AT+FCLASS=2", fd ); 
		break;
	    default:
		rc=NOERROR;
		break;
	}
	if ( rc == NOERROR ) return modem_type;
    }


    /* not auto-identify, or initialization failed -> try "old way" 
     */

    /* first of all, check for 2.0 */
    if ( strcmp( mclass, "auto" ) == 0 ||
	 strcmp( mclass, "c2.0" ) == 0 )
    {
	if ( mdm_command( "AT+FCLASS=2.0", fd ) == SUCCESS )
	{
	    return Mt_class2_0;
	}
    }

#ifdef CLASS1
    /* if explicitely requested, do class 1 (EXPERIMENTAL) */
    if ( strcmp( mclass, "cls1" ) == 0 )
    {
	if ( mdm_command( "AT+FCLASS=1", fd ) == SUCCESS )
	{
	    return Mt_class1;
	}
    }
#endif

    /* not a 2.0 modem (or not allowed to check),
       simply *try* class 2, nothing to loose */

    if ( mdm_command( "AT+FCLASS=2", fd ) == SUCCESS )
    {
	return Mt_class2;
    }

    /* failed. Assume data modem */

    return Mt_data;
}			/* end fax_get_modem_type() */


/* identify unknown modem via ATI code
 *
 * *very* preliminary - I'm experimenting...
 */

int mdm_identify _P1( (fd), int fd )
{
    char * l, *p;
    char * mis = NULL;		/* more verbose modem ID string */

    modem_type=Mt_unknown;

    /* try ATI first, ATI<n> later to sub-divide results
     */
    l = mdm_get_idstring( "ATI", 1, fd );
    lprintf( L_NOISE, "mdm_identify: string '%s'", l );
    
    if ( strcmp( l, "<ERROR>" ) == 0 ) 
    {
	lprintf( L_WARN, "mdm_identify: can't get modem ID" );
	return ERROR;
    }

    /* all-numerical? */
    p = l;
    while( isdigit(*p) || isspace(*p) ) p++;

    if ( *p == '\0' )		/* all-numeric */
    {
	int mid = atoi(l);	/* numerical modem ID... */

	switch(mid)
	{
	  case 0:		/* empty string */
	    lprintf( L_MESG, "got no modem ID. Hagenuk Speed Dragon?" );
	    mis = mdm_get_idstring( "ATI0", 1, fd );
	    break;
	  case 1496:
	    lprintf( L_MESG, "ZyXEL 1496 detected" ); 
	    modem_type=Mt_class2_0;
	    mis = mdm_get_idstring( "ATI1", 2, fd );
	    break;
	  case 2864:
	    lprintf( L_MESG, "ZyXEL 2864(D) detected" );
	    modem_type=Mt_class2_0;
	    mis = mdm_get_idstring( "ATI1", 2, fd );
	    break;
	  case 28641:
	  case 28642:
	    lprintf( L_MESG, "ZyXEL 2864I(D) detected" );
	    modem_type=Mt_class2_0;
	    mis = mdm_get_idstring( "ATI1", 2, fd );
	    break;
	  case 33604:
	    lprintf( L_MESG, "ZyXEL U-336E detected" );
	    modem_type=Mt_class2_0;
	    mis = mdm_get_idstring( "ATI1", 2, fd );
	    break;
	  case 1281:
	  case 1291:
	  case 1293:
	    lprintf( L_MESG, "ZyXEL Omni.NET detected" );
	    modem_type=Mt_data;				/* has no fax mode */
	    mis = mdm_get_idstring( "ATI1", 1, fd );
	    break;
	  case 1292:
	    lprintf( L_MESG, "ZyXEL Omni.NET LCD+M detected" );
	    modem_type=Mt_class2;			/* rockwell based */
	    mis = mdm_get_idstring( "ATI1", 1, fd );
	    break;
	  case 1500:
	  case 1501:
	    lprintf( L_MESG, "ZyXEL Omni 56K (Plus) detected" );
	    modem_type=Mt_class2_0;
	    mis = mdm_get_idstring( "ATI1", 2, fd );
	    break;
	  case 1503:
	    lprintf( L_MESG, "ZyXEL U-90E (?) detected" );
	    modem_type=Mt_class2_0;
	    mis = mdm_get_idstring( "ATI1", 2, fd );
	    break;
	  case 1444:
	    lprintf( L_MESG, "USR Courier/Sportster v32bis detected (assuming non-fax capable)" );
	    modem_type=Mt_data;
	    break;
	  case 1445:
	    lprintf( L_MESG, "USR Courier/Sportster v32bis detected (buggy fax implementation)" );
	    modem_type=Mt_class2_0;
	    modem_quirks |= MQ_USR_FMINSP | MQ_FPS_NOT_HEX;
	    break;
	  case 2886:
	  case 3361:
	  case 3362:
	  case 3366:
	  case 3367:
	    lprintf( L_MESG, "USR Courier/Sportster V.34(+) detected" );
	    modem_type=Mt_class2_0;
	    modem_quirks |= MQ_FPS_NOT_HEX;
	    mis = mdm_get_idstring( "ATI3", 1, fd );
	    break;
	  case 5601:
	  case 5607:
	    lprintf( L_MESG, "USR Courier/Sportster 56k detected" );
	    modem_type=Mt_class2_0;
	    modem_quirks |= MQ_FPS_NOT_HEX;
	    mis = mdm_get_idstring( "ATI3", 1, fd );
	    break;
	  case 6401:
	    lprintf( L_MESG, "USR I-Modem detected" );
	    modem_type=Mt_class2_0;
	    modem_quirks |= MQ_FPS_NOT_HEX;
	    mis = mdm_get_idstring( "ATI3", 1, fd );
	    break;
	  case 62:	/* sure? */
	  case 962:
	    lprintf( L_MESG, "Dr. Neuhaus Smarty detected (?)" );
	    modem_type=Mt_class2;	/* now do ATI9! */
	    modem_quirks |= MQ_NEED2;
	    mis = mdm_get_idstring( "ATI9", 1, fd );
	    break;
          case 932:	/* Thomas Schuett, info@thomas-schuett.de */
	    lprintf( L_MESG, "Zoom MX/S detected" );
	    modem_type=Mt_class2;
	    modem_quirks |= MQ_NEED2;
	    mis = mdm_get_idstring( "ATI3", 1, fd );
	    break;	      
	  case 961:
	    lprintf( L_MESG, "Zoltrix 14400 faxmodem detected (?)" );
	    modem_type=Mt_class2;
	    mis = mdm_get_idstring( "ATI4", 1, fd );
	    break;
	  case 144:     /* UMC 1440 baud modem (not sure) */
	    lprintf( L_MESG, "UMC92144EF modem detected(?)" );
	    modem_type=Mt_class2;
	    mis = mdm_get_idstring( "ATI4", 1, fd );
	    modem_quirks |= MQ_NEED2;
	    break;
	  case 184:	/* sure? */
	    lprintf( L_MESG, "Telebit FastBlazer detected" );
	    modem_type=Mt_data;
	    break;
	  case 149: /* sure? */
	    lprintf( L_MESG, "Intel 14.4E/400e detected (??)" );
	    modem_type=Mt_unknown;
	    break;
	  case 247: /* use ATI2 for further distinction */
	    lprintf( L_MESG, "Multitech MT1432BA/MT1932ZDX/MT2834ZDX detected" );
	    modem_type=Mt_class2_0;
	    mis = mdm_get_idstring( "ATI2", 1, fd );
	    modem_quirks |= MQ_FBOR_OK;
	    break;
	  case 251: /* sure? */
	    lprintf( L_MESG, "Discovery 2400 AM detected" );
	    modem_type=Mt_data;
	    break;
	  case 288: /* Fred Wendorf */
	    lprintf( L_MESG, "Trust Communicator 28 K8 detected" );
	    modem_type=Mt_class2;
	    modem_quirks |= MQ_NEED2;
	    break;
	  case 641: /* sure? */
	    lprintf( L_MESG, "ELSA MicroLink ISDN/TLpro detected" );
	    modem_type=Mt_data;
	    mis = mdm_get_idstring( "ATI3", 1, fd );
	    break;
	  case 643:	/* ATI6/ATI3 for model/firmware info */
	    lprintf( L_MESG, "ELSA MicroLink ISDN/TLV.34 detected" );
	    modem_type=Mt_class2_0;
	    mis = mdm_get_idstring( "ATI3", 1, fd );
	    break;
	  case 645:	/* ATI6/ATI3 for model/firmware info */
	    lprintf( L_MESG, "ELSA MicroLink Internet II detected" );
	    modem_type=Mt_class2_0;
	    mis = mdm_get_idstring( "ATI3", 1, fd );
	    break;
	  case 282:	/* ATI6/ATI3 for model/firmware info */
	    lprintf( L_MESG, "ELSA MicroLink 28.8/56K series detected" );
	    modem_type=Mt_class2_0;
	    mis = mdm_get_idstring( "ATI3", 1, fd );
	    break;
	  case 140:	/* ATI6/ATI3 for model/firmware info */
	    lprintf( L_MESG, "ELSA MicroLink 14.4TQ series detected" );
	    modem_type=Mt_class2_0;
	    mis = mdm_get_idstring( "ATI3", 1, fd );
	    break;
	  case 249:
	  case 14400: /* further distinction necessary (ATI3,4,6)! */
	  case 28800:
	  case 33600:
	  case 56000:
	    lprintf( L_MESG, "Generic Rockwell modem (%d)", mid );
	    modem_type=Mt_class2;
	    modem_quirks |= MQ_NO_LQC;
	    mis = mdm_get_idstring( "ATI3", 1, fd );
	    if ( mid == 28800 && mis[0] == '\0' )	/* no ATI3 code */
	    {
		lprintf( L_MESG, "Sounds more like Dr.Neuhaus Cybermod" );
		modem_quirks |= MQ_NEED2;
	    }
	    else					/* "Version 6.00" */
	      if ( mid == 28800 && strncmp( mis, "Version", 7 ) == 0 )
	    {
		lprintf( L_MESG, "Could be a Hayes Optima/Accura modem" );
	        mis = mdm_get_idstring( "ATI7", 2, fd );
		modem_quirks |= MQ_NEED2;
		break;
	    }
	    mis = mdm_get_idstring( "ATI4", 1, fd );
	    break;
	  case 2884:
	    lprintf( L_MESG, "sounds like a Microcom DeskPorte Fast+" );
	    modem_type=Mt_class2_0;
	    modem_quirks |= MQ_NO_LQC;		/* +FPS: broken */
	    mis = mdm_get_idstring( "ATI3", 1, fd );
	    break;
	  case 336:				/* one report only */
	    lprintf( L_MESG, "could be a CompuTime RalleyCom 336" );
	    break;
	  case 242:				/* one report only */
	    lprintf( L_MESG, "could be a Tornado III FM-144VBIS" );
	    modem_type=Mt_class2;
	    modem_quirks |= MQ_NO_XON;
	    break;
	  default:
	    lprintf( L_MESG, "unknown numerical modem id %d", mid );
	    break;
	}
    }
    else		/* non-numeric modem id string */
    {
	lprintf( L_MESG, "non-numeric ID string: '%s'", l );

	/* "Elink 310 Version 1.25" */
	/* "Elink 34-3 P1 Version 1.64" */
	if ( strncmp( l, "Elink", 5 ) == 0 )
	{
	    lprintf( L_MESG, "Elink detected" );
	    if ( strncmp( l+6, "34-3" , 4 ) == 0 )
		modem_type=Mt_class2;
	    else
		modem_type=Mt_data;
	}
	else if ( strncmp( l, "Eicon ISDN Modem", 16 ) == 0 )
	{
	    lprintf( L_MESG, "Diehl/Eicon ISDN (assuming DIVA card with class 2 fax)" );
	    modem_type=Mt_class2;
	}
	else if ( strncmp( l, "Linux ISDN", 10 ) == 0 )
	{
	    lprintf( L_MESG, "ISDN4Linux detected" );
	    modem_type=Mt_data;
	}
	/* got this from bruce@hn.pl.net */
	else if ( strncmp( l, "1.03", 4 ) == 0 )
	{
	    lprintf( L_MESG, "Ellcon 14.4+Voice detected" );
	    modem_type=Mt_data;
	}
	/* got this from Matt Atkins, matta@cl-sys.com */
	else if ( strncmp( l, "1.0", 3 ) == 0 )
	{
	    lprintf( L_MESG, "Cirrus Logic Communicator 56 detected" );
	    modem_type=Mt_unknown;
	    mis = mdm_get_idstring( "ATI3", 1, fd );
	}
	/* got this from Andreas Muck, <andi@koala.rhein-neckar.de>
	 * and Frank Damgaard <frda@post3.tele.dk>
	 */
	else if ( strncmp( l, "5607A", 5 ) == 0 ||
	          strncmp( l, "5607B", 5 ) == 0 )
	{
	    lprintf( L_MESG, "USR Courier/Sportster V90 (national variant?) detected" );
	    modem_type=Mt_class2_0;
	    modem_quirks |= MQ_FPS_NOT_HEX;
	    mis = mdm_get_idstring( "ATI3", 1, fd );
	}
	/* grrr, another one of those - Bill Nugent <whn@topelo.lopi.com> */
	else if ( strncmp( l, "MT5600ZDXV", 10 ) == 0 )
	{
	    lprintf( L_MESG, "Multitech MT5600ZDXV detected" );
	    modem_type=Mt_class2;
	}
	/* and yet another one :-( - Nokia, sigh */
	else if ( strncmp( l, "Nokia ", 6 ) == 0 )
	{
	    lprintf( L_MESG, "Nokia GSM telephone detected" );
	    modem_type=Mt_class2_0;
	    mis = mdm_get_idstring( "ATI3", 1, fd );
	}
	/* and yet another one - will they never end? Xavier Roche */
	else if ( strncmp( l, "LT V.90", 7 ) == 0 )
	{
	    lprintf( L_MESG, "Multitech MT5634Z internal detected" );
	    modem_type=Mt_class2;
	    modem_quirks |= MQ_NEED2;
	}
	else if ( strncmp( l, "LT V.92", 7 ) == 0 )	/* gert */
	{
	    lprintf( L_MESG, "Multitech MT5634ZBA-V92 detected" );
	    modem_type=Mt_class2_0;
	    modem_quirks |= MQ_FPS_NOT_HEX;
	}
    }

    if ( mis != NULL ) 
	lprintf( L_MESG, "additional info: '%s'", mis );
    if ( modem_quirks )
	lprintf( L_MESG, "modem quirks: %04x", modem_quirks );

    return NOERROR;
}
