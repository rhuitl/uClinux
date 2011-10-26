#ident "$Id: class1.c,v 4.3 1998/01/22 07:28:47 gert Exp $ Copyright (c) Gert Doering"

/* class1.c
 *
 * High-level functions to handle class 1 fax -- 
 * state machines for fax phase A, B, C, D. Error recovery.
 *
 * Usese library functions in class1lib.c, faxlib.c and modem.c
 */

#ifdef CLASS1

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

#include "mgetty.h"
#include "fax_lib.h"
#include "tio.h"
#include "class1.h"

enum T30_phases { Phase_A, Phase_B, Phase_C, Phase_D, Phase_E } fax1_phase;

int fax1_dial_and_phase_AB _P2( (dial_cmd,fd),  char * dial_cmd, int fd )
{
char * p;			/* modem response */
uch framebuf[FRAMESIZE];
int first;

    /* send dial command */
    if ( fax_send( dial_cmd, fd ) == ERROR )
    {
	fax_hangup = TRUE; fax_hangup_code = FHUP_ERROR;
	return ERROR;
    }

    /* wait for ERROR/NO CARRIER/CONNECT */
    signal( SIGALRM, fax1_sig_alarm );
    alarm(FAX_RESPONSE_TIMEOUT);

    while( !fax_hangup )
    {
        p = mdm_get_line ( fd );

	if ( p == NULL )
	    { lprintf( L_ERROR, "fax1_dial: hard error dialing out" );
	      fax_hangup = TRUE; fax_hangup_code = FHUP_ERROR; break; }

	lprintf( L_NOISE, "fax1_dial: string '%s'", p );

	if ( strcmp( p, "ERROR" ) == 0 ||
	     strcmp( p, "NO CARRIER" ) == 0 )
	    { fax_hangup = TRUE; fax_hangup_code = FHUP_ERROR; break; }

	if ( strcmp( p, "NO DIALTONE" ) == 0 ||
	     strcmp( p, "NO DIAL TONE" ) == 0 )
	    { fax_hangup = TRUE; fax_hangup_code = FHUP_NODIAL; break; }

	if ( strcmp( p, "BUSY" ) == 0 )
	    { fax_hangup = TRUE; fax_hangup_code = FHUP_BUSY; break; }

        if ( strcmp( p, "CONNECT" ) == 0 )		/* gotcha! */
	    { break; }
    }

    alarm(0);
    if ( fax_hangup ) return ERROR;

    /* now start fax negotiation (receive CSI, DIS, send DCS)
     * read all incoming frames until FINAL bit is set
     */
    first=TRUE;
    do
    {
	if ( fax1_receive_frame( fd, first? 0:3, 30, &framebuf ) == ERROR )
	{
	    /*!!!! try 3 times! (flow diagram from T.30 / T30_T1 timeout) */
	    fax_hangup = TRUE; fax_hangup_code = 11; return ERROR;
	}
	switch ( framebuf[1] )		/* FCF */
	{
	    case T30_CSI: fax1_copy_id( framebuf ); break;
	    case T30_NSF: break;
	    case T30_DIS: fax1_parse_dis( framebuf ); break;
	    default:
	        lprintf( L_WARN, "unexpected frame type 0x%02x", framebuf[1] );
	}
	first=FALSE;
    }
    while( ( framebuf[0] & T30_FINAL ) == 0 );

    /* send local id frame (TSI) */
    fax1_send_idframe( fd, T30_TSI|0x01 );

    /* send DCS */
    if ( fax1_send_dcs( fd, 14400 ) == ERROR )
    {
        fax_hangup = TRUE; fax_hangup_code = 10; return ERROR;
    }

    fax1_phase = Phase_B;			/* Phase A done */

    return NOERROR;
}


/* fax1_send_page
 *
 * send a page of G3 data
 * - if phase is "B", include sending of TCF and possibly 
 *   baud rate stepdown and repeated transmission of DCS.
 * - if phase is "C", directly send page data
 */

int fax1_send_page _P5( (g3_file, bytes_sent, tio, ppm, fd),
		        char * g3_file, int * bytes_sent, TIO * tio,
		        Post_page_messages ppm, int fd )
{
uch framebuf[FRAMESIZE];
char * line;
char cmd[40];
char dleetx[] = { DLE, ETX };
char rtc[] = { 0x00, 0x08, 0x80, 0x00, 0x08, 0x80, 0x00, 0x08 };
int g3fd, r, w, rx;
#define CHUNK 512
char buf[CHUNK], wbuf[CHUNK];

    /* if we're in T.30 phase B, send training frame (TCF) now...
     * don't forget delay (75ms +/- 20ms)!
     */
    if ( fax1_phase == Phase_B )
    {
        char train[150];
	int i, num;

	sprintf( cmd, "AT+FTS=8;+FTM=%d", dcs_btp->c_long );
	fax_send( cmd, fd );

	line = mdm_get_line( fd );
	if ( line != NULL && strcmp( line, cmd ) == 0 )
		line = mdm_get_line( fd );

	if ( line == NULL || strcmp( line, "CONNECT" ) != 0 )
	{
	    lprintf( L_ERROR, "fax1_send_page: unexpected response 1: '%s'", line );
	    fax_hangup = TRUE; fax_hangup_code = 20; return ERROR;
	}

	/* send data for training (1.5s worth) */

	num = (dcs_btp->speed/8)*1.5;
	lprintf( L_NOISE, "fax1_send_page: send %d bytes training (TCF)", num );
	memset( train, 0, sizeof(train));

	for( i=0; i<num; i+=sizeof(train))
		write( fd, train, sizeof(train) );
	write( fd, dleetx, 2 );

	line = mdm_get_line( fd );
	if ( line == NULL || strcmp( line, "OK" ) != 0 )
	{
	    lprintf( L_ERROR, "fax1_send_page: unexpected response 2: '%s'", line );
	    fax_hangup = TRUE; fax_hangup_code = 20; return ERROR;
	}

	/* receive frame - FTT or CFR */
	/*!!! return code! */
	fax1_receive_frame( fd, 3, 30, &framebuf );

	if ( ( framebuf[0] & T30_FINAL ) == 0 ||
	     framebuf[1] != T30_CFR )
	{
	    lprintf( L_ERROR, "fax1_receive_frame: failed to train" );
	    /*!!! try 3 times! */
	    fax_hangup = TRUE; fax_hangup_code = 27;
	    return ERROR;
	}

	/* phase B done, go to phase C */
	fax1_phase = Phase_C;
    }

    if ( fax1_phase != Phase_C )
    {
        lprintf( L_ERROR, "fax1_send_page: internal error: not Phase C" );
	fax_hangup = TRUE; fax_hangup_code = FHUP_ERROR;
	return ERROR;
    }

    r=0;w=0;
    g3fd = open( g3_file, O_RDONLY );
    if ( g3fd < 0 )
    {
        lprintf( L_ERROR, "fax1_send_page: can't open '%s'", g3_file );
	/*!!! do something smart here... */
	fax_hangup = TRUE; fax_hangup_code = FHUP_ERROR;
	fax1_send_dcn( fd );
	return ERROR;
    }

    /* Phase C: send page data with high-speed carrier
     */
    sprintf( cmd, "AT+FTM=%d", dcs_btp->c_short );
    fax_send( cmd, fd );

    line = mdm_get_line( fd );
    if ( line != NULL && strcmp( line, cmd ) == 0 )
	    line = mdm_get_line( fd );

    if ( line == NULL || strcmp( line, "CONNECT" ) != 0 )
    {
	lprintf( L_ERROR, "fax1_send_page: unexpected response 3: '%s'", line );
	fax_hangup = TRUE; fax_hangup_code = 40; return ERROR;
    }

    lprintf( L_NOISE, "send page data" );

    /* read page data from file, invert byte order, 
     * insert padding bits (if scan line time > 0), 
     * at end-of-file, add RTC
     */
    /*!!!! padding, one-line-at-a-time, watch out for sizeof(wbuf)*/
    /*!!!! digifax header!*/
    rx=0; r=0; w=0;
    do
    {
        if ( rx >= r )			/* buffer empty, read more */
	{
	    r = read( g3fd, buf, CHUNK );
	    if ( r < 0 )
	    {
	    	lprintf( L_ERROR, "fax1_send_page: error reading '%s'", g3_file );
		break;
	    }
	    if ( r == 0 ) break;
	    lprintf( L_JUNK, "read %d", r );
	    rx = 0;
	}
	wbuf[w] = buf[rx++];
	if ( wbuf[w] == DLE ) wbuf[++w] = DLE;
	w++;

	/*!! zero-counting, bitpadding! */
	if ( w >= sizeof(wbuf)-2 )
	{
	    if ( w != write( fd, wbuf, w ) )
	    {
	        lprintf( L_ERROR, "fax1_send_page: can't write %d bytes", w );
		break;
	    }
	    lprintf( L_JUNK, "write %d", w );
	    w=0;
	}
    }
    while(r>0);
    close(g3fd);

    /*!!! ERROR HANDLING!! */
    /*!!! PARANOIA: alarm()!! */
    /* end of page: RTC */
    write( fd, rtc, sizeof(rtc) );
    /* end of data: DLE ETX */
    write( fd, dleetx, 2 );

    line = mdm_get_line( fd );
    if ( line == NULL || strcmp( line, "OK" ) != 0 )
    {
	lprintf( L_ERROR, "fax1_send_page: unexpected response 3a: '%s'", line );
	fax_hangup = TRUE; fax_hangup_code = 40; return ERROR;
    }


    /* now send end-of-page frame (MPS/EOM/EOP) and get pps */

    fax1_phase = Phase_D;
    lprintf( L_MESG, "page data sent, sending end-of-page frame (C->D)" );
    sprintf( cmd, "AT+FTS=8;+FTH=3" );
    fax_send( cmd, fd );

    line = mdm_get_line( fd );
    if ( line != NULL && strcmp( line, cmd ) == 0 )
	    line = mdm_get_line( fd );

    if ( line == NULL || strcmp( line, "CONNECT" ) != 0 )
    {
        if ( strcmp( line, "OK" ) == 0 ) goto tryanyway;
	lprintf( L_ERROR, "fax1_send_page: unexpected response 4: '%s'", line );
	fax_hangup = TRUE; fax_hangup_code = 50; return ERROR;
    }

    /* some modems seemingly can't handle AT+FTS=8;+FTH=3 (returning 
     * "OK" instead of "CONNECT"), so send AT+FTH=3 again for those.
     */
tryanyway:

    framebuf[0] = 0xff;
    framebuf[1] = 0x03 | T30_FINAL;
    switch( ppm )
    {
        case pp_eom: framebuf[2] = T30_EOM | fax1_dis; break;
	case pp_eop: framebuf[2] = T30_EOP | fax1_dis; break;
	case pp_mps: framebuf[2] = T30_MPS | fax1_dis; break;
    }

    fax1_send_frame( fd, strcmp(line, "OK")==0? 3:0 , framebuf, 3 );

    /* get MPS/RTP/RTN code */
    fax1_receive_frame( fd, 3, 30, framebuf );

    /*!!! T.30 flow chart... */

    switch( framebuf[1] )
    {
        case T30_MCF:		/* page good */
		fax_page_tx_status = 1; break;
	case T30_RTN:		/* retrain / negative */
		fax_page_tx_status = 2; fax1_phase = Phase_B; break;
	case T30_RTP:		/* retrain / positive */
		fax_page_tx_status = 3; fax1_phase = Phase_B; break;
	case T30_PIN:		/* procedure interrupt */
		fax_page_tx_status = 4; break;
	case T30_PIP:
		fax_page_tx_status = 5; break;
	default:
		lprintf( L_ERROR, "fax1_transmit_page: unexpected frame" );
		fax_hangup = TRUE; fax_hangup_code = 53; 
		fax1_send_dcn(fd); break;
    }

    fax_hangup = TRUE; fax_hangup_code = 50;
    return ERROR;
}

#endif /* CLASS 1 */
