#ident "$Id: logname.c,v 4.9 2003/08/17 10:38:36 gert Exp $ Copyright (c) Gert Doering"

/* logname.c
 *
 * print 'login:' prompt, handling eventual escape sequence substitutions
 *
 * read login name, detect incoming PPP frames and FIDO startup sequences
 */


#include <stdio.h>
#include "syslibs.h"
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <time.h>
#include <ctype.h>
#ifndef sunos4
#include <sys/ioctl.h>
#endif

#ifndef ENOENT
#include <errno.h>
#endif

#include "mgetty.h"
#include "policy.h"
#include "tio.h"
#include "mg_utmp.h"

#include <sys/utsname.h>

extern char * Device;				/* mgetty.c */

/* ln_escape_prompt()
 *
 * substitute all "known" escapes, e.g. "\n" and "\t", plus some
 * private extentions (@, \D and \T for system name, date, and time)
 *
 * The caller has to free() the string returned
 *
 * If the resulting string would be too long, it's silently truncated.
 */

int strappnd _P2((s1,s2), char * s1, char * s2 )
{
    strcpy( s1, s2 );
    return strlen( s1 );
}

char * ln_escape_prompt _P1( (ep), char * ep )
{
#define MAX_PROMPT_LENGTH 300
    static char * p = NULL;
    int    i;
    static struct utsname un;
    static boolean un_cached = FALSE;

    if ( p == NULL ) p = malloc( MAX_PROMPT_LENGTH );
    if ( p == NULL ) return ep;

    if ( ! un_cached )
    {
	uname( &un );
	un_cached = TRUE;
    }

    i = 0;
    
    while ( *ep != 0 && i < MAX_PROMPT_LENGTH-4 )
    {
	if ( *ep == '@' )		/* system name */
	{
#ifdef SYSTEM
	    if ( sizeof( SYSTEM ) + i > MAX_PROMPT_LENGTH ) break;
	    i += strappnd( &p[i], SYSTEM );
#else
	    if ( strlen( un.nodename ) +1 +i > MAX_PROMPT_LENGTH ) break;
	    i += strappnd( &p[i], un.nodename );
#endif		/* !SYSTEM */
	}
	else if ( *ep != '\\' ) p[i++] = *ep;
	else		/* *ep == '\\' */
	{
	    ep++;
	    switch ( *ep )
	    {
	      case 'n': p[i++] = '\n'; break;
	      case 'r': p[i++] = '\r'; break;
	      case 'g': p[i++] = '\007'; break;
	      case 'b': p[i++] = '\010'; break;
	      case 'v': p[i++] = '\013'; break;
	      case 'f': p[i++] = '\f'; break;
	      case 't': p[i++] = '\t'; break;
	      case 's':					/* Operating System */
		    if ( i + strlen(un.sysname) +1 > MAX_PROMPT_LENGTH ) break;
		    i += strappnd( &p[i], un.sysname );
		    break;
	      case 'm':					/* machine arch. */
		    if ( i + strlen(un.machine) +1 > MAX_PROMPT_LENGTH ) break;
		    i += strappnd( &p[i], un.machine );
		    break;
	      case 'R':					/* OS release */
		    if ( i + strlen(un.release) +1 > MAX_PROMPT_LENGTH ) break;
		    i += strappnd( &p[i], un.release );
		    break;
	      case 'V':					/* OS version */
		    if ( i + strlen(un.version) +1 > MAX_PROMPT_LENGTH ) break;
		    i += strappnd( &p[i], un.version );
		    break;
	      case 'Y':					/* Caller ID */
		{
		extern char * CallerId;
		    if ( i + strlen(CallerId) +1 > MAX_PROMPT_LENGTH ) break;
		    i += strappnd( &p[i], CallerId );
		    break;
		}
	      case 'P':					/* port name */
	      case 'L':					/* tty line */
		{
		    if ( i + strlen(Device) +1 > MAX_PROMPT_LENGTH ) break;
		    i += strappnd( &p[i], Device );
		    break;
		}
	      case 'C':					/* ctime */
		{
		    time_t ti = time(NULL);
		    char * h = ctime( &ti );
		    if ( strlen(h) +1 +i > MAX_PROMPT_LENGTH ) break;
		    i += strappnd( &p[i], h ) -1;
		    break;
		}
	      case 'I':
		{
		    if ( strlen(Connect) +1 +i > MAX_PROMPT_LENGTH ) break;
		    i += strappnd( &p[i], Connect);
		    break;
		}
	      case 'N':					/* numer of */
	      case 'U':					/* users */
		{
		    sprintf( &p[i], "%d", get_current_users() );
		    i = strlen(p);
		    break;
		}
	      case 'S':					/* port speed */
		{					/* ugly, I know. */
		    TIO temp_t;
		    tio_get( 0, &temp_t );
		    sprintf( &p[i], "%d", tio_get_speed( &temp_t ) );
		    i = strlen(p);
		}
		break;
	      case 'D':			/* fallthrough */
	      case 'T':
		if ( i + 30 > MAX_PROMPT_LENGTH )
		{
		    i += strappnd( &p[i], "(x)" ); break;
		}
		else
		{
		    time_t ti = time( NULL );
		    struct tm * tm = localtime( &ti );

		    if ( tm == NULL ) break;

		    if ( *ep == 'D' )
		        sprintf( &p[i], "%d/%d/%d", tm->tm_mon+1,
				 tm->tm_mday, tm->tm_year + 1900 );
		    else
		        sprintf( &p[i], "%02d:%02d:%02d", tm->tm_hour,
				 tm->tm_min, tm->tm_sec );
		    i = strlen(p);
		}
		break;
	      default:		/* not a recognized string */
		if ( isdigit( *ep ) )		/* "\01234" */
		{
		    char * help;
		    p[i++] = strtol( ep, &help, 0 );
		    ep = help-1;
		}
		else p[i++] = *ep;
	    }			/* end switch( char after '\\' ) */
	}			/* end if ( char is '\\' ) */
	ep++;
    }				/* end while ( char to copy, p not full ) */

    p[i] = 0;			/* terminate string */
    
    if ( *ep != 0 )
    {
	lprintf( L_WARN, "ln_escape_prompt: input line too long - data truncated" );
    }

    return p;
}

/* return TRUE if all letters found in the string are uppercase
 */

#ifdef DO_LCUC_MAP
boolean ln_all_upper _P1( (string), char * string )
{
    int i;
    boolean uc = FALSE;

    for ( i=0; string[i] != 0; i++ )
    {
	if ( string[i] == '\377' ) return FALSE;	/* **EMSI_INQ */
	if ( islower( string[i] ) ) return FALSE;
	if ( isupper( string[i] ) ) uc = TRUE;
    }
    if ( ! uc )		/* no letters at all */
 	return FALSE;	/* -> counted as lowercase */

    return TRUE;
}
#endif
	

/* set_env_var( var, string )
 *
 * create an environment entry "VAR=string"
 */
void set_env_var _P2( (var,string), char * var, char * string )
{
    char * v;
    v = malloc( strlen(var) + strlen(string) + 2 );
    if ( v == NULL )
        lprintf( L_ERROR, "set_env_var: cannot malloc" );
    else
    {
	sprintf( v, "%s=%s", var, string );
	lprintf( L_NOISE, "setenv: '%s'", v );
	if ( putenv( v ) != 0 )
	    lprintf( L_ERROR, "putenv failed" );
    }
}

static int timeouts = 0;
static RETSIGTYPE getlog_timeout(SIG_HDLR_ARGS)
{
    signal( SIGALRM, getlog_timeout );

    lprintf( L_WARN, "getlogname: timeout" );
    timeouts++;
}

/* getlogname()
 *
 * read the login name into "char buf[]", maximum length "maxsize".
 * depending on the key that the input was finished (\r vs. \n), mapping
 * of cr->nl is set in "TIO * tio" (with tio_set_cr())
 *
 * If ENV_TTYPROMPT is set, do not read anything
 */

int getlogname _P6( (prompt, tio, buf, maxsize, max_login_time, do_fido),
		    char * prompt, TIO * tio, char * buf,
		    int maxsize, int max_login_time, boolean do_fido )
{
    int	 i, r;
    char ch;
    TIO  tio_save;
    char *  final_prompt;

#ifdef AUTO_PPP
    static int ppp_level = 0, ppp_escaped = 0;
    char   ppp_ch;
#endif
    
    /* read character by character! */
    tio_save = *tio;
    tio_mode_raw( tio );
    tio_set( STDIN, tio );

    final_prompt = ln_escape_prompt( prompt );

#ifdef ENV_TTYPROMPT
    printf( "\r\n%s", final_prompt );
    tio_mode_sane( tio, FALSE );
    tio_map_cr( tio, TRUE );
    tio_set( STDIN, tio );
    buf[0] = 0;
    set_env_var( "TTYPROMPT", final_prompt );
    return 0;
#else			/* !ENV_TTYPROMPT */

    if ( max_login_time > 0 )
    {
	signal( SIGALRM, getlog_timeout );
	alarm( max_login_time );
    }

  newlogin:
#ifdef FIDO
    /* send EMSI Request for FIDO (if desired) */
    if ( do_fido )
        printf( "**EMSI_REQA77E\r\021              \r" );
  newlogin_noemsi:
#endif

    printf( "\r\n%s", final_prompt );

    if ( ferror( stdin ) )
    {
	lprintf( L_ERROR, "getlogname: error writing prompt" );
    }

    /* print logfile msg, showing all compiled-in options */
#ifdef FIDO
# ifdef AUTO_PPP
    lprintf( L_NOISE, "getlogname (FIDO AUTO_PPP), read:" );
# else
    lprintf( L_NOISE, "getlogname (FIDO), read:" );
# endif
#else /* !FIDO */
# ifdef AUTO_PPP
    lprintf( L_NOISE, "getlogname (AUTO_PPP), read:" );
# else
    lprintf( L_NOISE, "getlogname (no opts), read:" );
# endif
#endif

    i = 0;
	    
    do
    {
	if ( ( r = read( STDIN, &ch, 1 ) ) != 1 )
	{
	    if ( r == 0 )				/* EOF/HUP/^D */
	    {
		lprintf( L_MESG, "getlogname: got EOF, exiting" );
		exit(0);
	    }
	    
	    if ( errno != EINTR ) exit(0);		/* HUP/^D/timeout */

	    if ( timeouts <= 1 )			/* first timeout */
	    {
		printf( "\r\n\07\r\nHey! Please login now. You have one minute left\r\n" );
		alarm(60);
	    }
	    else					/* second */
	    {
		printf( "\r\n\07\r\nYour login time (%d minutes) ran out. Goodbye.\r\n",
		       (max_login_time / 60)+1 );
		
		sleep(3);		/* give message time to xmit */
		lprintf( L_AUDIT, "failed dev=%s, pid=%d, login time out",
			 Device, getpid() );
		exit(0);		/* bye bye... */
	    }
	    ch = CKILL;			/* timeout #1 -> clear input */
	}

	lputc( L_NOISE, ch );				/* logging */

#ifdef FIDO
	if ( ch == (char) TSYNC )
	{
	    strcpy( buf, "\377tsync" ); i=6; ch='\r'; 
	}
	else if ( ch == (char) YOOHOO )
	{
	    strcpy( buf, "\377yoohoo" ); i=7; ch='\r';
	}
#endif
#ifdef AUTO_PPP
        /* Accept the following sequences as start of PPP packet:
           PPP_FRAME, PPP_STATION, PPP_ESCAPE, PPP_CONTROL_ESCAPED (normal)
           PPP_FRAME, PPP_STATION, PPP_CONTROL           (deviant from RFC)
        
           Odds are pretty low of hitting this by accident.
           See RFC1662 for more information.

	   Contributed by Erik 'PPP' Olson, <eriko@wrq.com>.

	   Fix by okir@caldera.de: Recognize any escape sequence
	   (some pppd's also escape the 'all stations' byte (0xFF)).
         */

        ppp_ch = ch;
        if (ppp_escaped) {
                ppp_ch = PPP_UNESCAPE(ch);
                ppp_escaped = 0;
        }
        if (ppp_ch == (char) PPP_ESCAPE) {
            ppp_escaped = 1;
        } else if (ppp_ch == (char) PPP_FRAME) {
            ppp_level = 1;
        } else if (ppp_ch == (char) PPP_STATION && ppp_level == 1) {
            ppp_level = 2;
        } else if (ppp_ch == (char) PPP_CONTROL && ppp_level == 2) {
            ppp_level = 3;
        } else if (ppp_ch == (char) PPP_LCP_HI && ppp_level == 3) {
            ppp_level = 4;
        } else if (ppp_ch == (char) PPP_LCP_LOW && ppp_level == 4)
        {
            strcpy (buf, "/AutoPPP/");
            i=9;
            ch = '\r';

	    /* the following is a hack... - if pppd startup is slow, and the
	     * caller sends its PPP frames fast, they get echoed, and will
	     * confuse the "loop detection" of some clients. So we switch
	     * the saved tio to raw mode, which will be "restored" soon.
	     */
	    tio_mode_raw( &tio_save );
        } else {
            ppp_level = 0;
	    ppp_escaped = 0;
        }
#endif
        
#ifdef JANUS
	/* ignore ^X as first character, some JANUS programs send it first
	   to skip the usual bbs banner
	   oli@rhein-main.de,  941217 */
	if ( i == 0 && ch == 0x18 )
	    continue; 
#endif

	/* ignore [00] and [01] bytes - seem to be spuriously generated
	 * when dialing into a ZyXEL 2864DI with X.75 (sometimes)
	 */
	if ( ch == 0 || ch == 1 ) continue;

	ch = ch & 0x7f;					/* strip to 7 bit */

	if ( ch == CQUIT ) exit(0);
	if ( ch == CEOF )
	{
            if ( i == 0 ) exit(0); else continue;
	}

	if ( ch == CKILL || ch == 03 /*^C*/ ) goto newlogin;

	/* ignore XON/XOFF characters */
	
	if ( ch == CSTART || ch == CSTOP ) continue;

	/* since some OSes use backspace and others DEL -> accept both */

	if ( ch == 0x7f /*DEL*/ || ch == 0x08 /*BS*/ || ch == CERASE )
	{
	    if ( i > 0 )
	    {
		fputs( "\b \b", stdout );
		i--;
	    }
	}
	else
	  if ( ch != 27 )				/* not <ESC> */
	{
	    putc( ch, stdout );
	    
	    if ( i >= maxsize ||			/* buffer full, */
		 ( ch == ' ' && i == 0 ) || 		/* leading ' ' */
		 ( ch == '-' && i == 0 ) )		/* or '-' */
		fputs( "\b \b", stdout );		/* -> ignore */
	    else
		buf[i++] = ch;
	    if ( i >= 7 && strncmp( &buf[i-7], "**EMSI_", 7 ) == 0 )
	    {
#ifdef FIDO
		lprintf( L_NOISE, "got EMSI signature" );
		strcpy( buf, "\377**EMSI_" ); i=8; break;
#else
		lprintf( L_MESG, "incoming fido call, but no FIDO support" );
#endif
	    }
	}
    }
    while ( ch != '\n' && ch != '\r' );

#ifdef FIDO
    if ( strncmp( buf, "\377**EMSI_", 8 ) == 0 )
    {				/* read up to final \r */
	while ( ch != '\r' )
	{
	    if ( read( STDIN, &ch, 1 ) != 1 )
	    {
		lprintf( L_ERROR, "logname/FIDO: read error" );
		exit(0);
	    }
	    if ( i < maxsize) buf[i++] = ch;
	    if ( i >= 15 &&
		 strncmp( buf, "\377**EMSI_INQC816", 15 ) == 0 )
	    {
		 ch = buf[i++] = '\r';
	    }
	}
	
	/* log EMSI packets that are not EMSI_INQ (e.g. EMSI_DAT) */
	if ( strncmp( buf, "\377**EMSI_INQ", 11 ) != 0 )
	{
	    buf[i-1] = 0;
	    lprintf( L_MESG, "non-INQ EMSI packet: '%.15s...', length %d",
		              buf+1, i-1 );
	    if ( strncmp( buf, "\377**EMSI_CLI", 11 ) == 0 )
	    {
		lprintf( L_MESG, "got EMSI_CLI packet, re-read login name" );
		goto newlogin_noemsi;
	    }
	}
    }
#endif
	
    alarm(0);

    buf[--i] = 0;

    *tio = tio_save;

#ifdef JANUS
    /* change JANUS to janus */
    if( strcmp(buf,"JANUS") == 0 )
	strcpy(buf,"janus");
#endif

    /* for modems that are misconfigured and do not raise/lower DCD
       properly, check for some standard modem error codes now
     */

    if( strcmp(buf,"NO CARRIER") == 0 ||
        strcmp(buf,"ERROR") == 0 )
    {
	lprintf( L_AUDIT, "failed dev=%s, pid=%d, got modem error '%s'",
                 Device, getpid(), buf );
	exit(0);
    }

    /* check whether all letters entered were uppercase, if yes, tell
       user to try again with l/c, if it's all uppercase again on the
       second try, enable UC<->LC mapping
       (this is mainly for full historic compatibility - off by default)
       */

#ifdef DO_LCUC_MAP
    if ( ln_all_upper( buf ) )
    {
    static boolean was_all_uc = FALSE;

	if ( !was_all_uc )	/* first time */
	{
	    printf("\r\n\nIf your terminal supports lower case letter, please\r\n");
	    printf("use them. Login again, using lower case if possible\r\n\n");
	    was_all_uc = TRUE;
	    return -1;
	}
	else			/* second time */
	{
	    for ( i=0; buf[i] != 0; i++ )
	        if ( isupper( buf[i] ) ) buf[i] = tolower(buf[i]);
	    tio_map_uclc( tio, TRUE );
	    lprintf( L_MESG, "login name all uppercase, set IUCLC OLCUC" );
	}
    }
#endif

    /* set CR/LF mapping according to the character the input was
       ended with
       */
    
    if ( ch == '\n' )
    {
	tio_map_cr( tio, FALSE );
	fputc( '\r', stdout );
    }
    else
    {
	tio_map_cr( tio, TRUE );
	fputc( '\n', stdout );
	lprintf( L_NOISE, "input finished with '\\r', setting ICRNL ONLCR" );
    }

    tio_set( STDIN, tio );

    if ( i == 0 ) return -1;
    else return 0;
#endif			/* !ENV_TTYPROMPT */
}
