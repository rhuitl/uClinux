#ident "@(#)cnd.c	$Id: cnd.c,v 4.25 2004/07/17 15:55:57 gert Exp $ Copyright (c) 1993 Gert Doering/Chris Lewis"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <unistd.h>
#include "syslibs.h"

#include "policy.h"
#include "mgetty.h"
#include "config.h"

char *Connect = "";
char *CallerId = "none";
char *CallTime = "";
char *CallName = "";
char *CalledNr = "";			/* dialed number [ISDN MSN] */
/* the next few are for Rockwell */
char *CallDate = "";
char *CallMsg1 = "";
char *CallMsg2 = "";

/* those are for Rockwell "CONNECT" messages */
static char * cnd_carrier = "";
static char * cnd_protocol= "";

struct cndtable {
    char *string;
    char **variable;
};

struct cndtable cndtable[] =
{
    /* for the ELSA MicroLink/TLV.34: "RING;08912345;08765, ATS153=6 */
    {"RING;",			&CallerId},

    {"RING"},			/* speedups */
    {"OK"},			/* speedups */
    {"CONNECT ",		&Connect},

    /* ZyXEL 1496 */
    {"CALLER NAME: ",		&CallName},
    {"CALLER NUMBER: ",		&CallerId},
    {"TIME: ",			&CallTime},
    {"REASON FOR NO CALLER NUMBER: ",	&CallerId},
    {"REASON FOR NO CALLER NAME: ",	&CallName},

    /* isdn4linux (2.4.10 or patched) - Jan Oberlaender, mindriot@gmx.net */
    {"CALLED NUMBER: ",		&CalledNr},

    /* for the ZyXEL 2864(D)I: "FM:xxx TO:yyy" */
    {"FM:",			&CallerId},

    /* those are for rockwell-based modems insisting on a multi-line
       message "CARRIER ... / PROTOCOL ... / CONNECT" */
    {"CARRIER ",		&cnd_carrier},
    {"PROTOCOL: ",		&cnd_protocol},

    /* ELSA does it similarily (if AT+MR=1 is set) */
    {"+MCR: ",		&cnd_carrier},
    {"+MRR: ",		&cnd_protocol},

    /* those are for Rockwell Caller ID */
    {"DATE = ",                 &CallDate},
    {"TIME = ",			&CallTime},
    {"NMBR = ",			&CallerId},
    {"NAME = ",			&CallName},
    {"MESG = ",			&CallMsg1},
    {"MESG = ",			&CallMsg2},

    /* some Rockwell chips intro the Caller ID as follows */
    /* (contributed by Edmund Bacon, ebacon@onesystem.com) */
    {"DDN_NMBR= ",		&CallerId},

    /* The Digi DataFire RAS reports this different again... */
    /* (reported by Akiko Takahashi <takahashi@sdcinc.co.jp>) */
    /* also for the Zoom 2949L, K C Yuen <ykc@kernelhk.com> */
    /* also used by ELSA MicroLink Office <gert@greenie.muc.de> */
    {"DATE=",			&CallDate},
    {"TIME=",			&CallTime},
    {"NMBR=",			&CallerId},
    {"NAME=",			&CallName},

    /* yet another incompatible modem... */
    {"CALLER'S NUMBER: ",	&CallerId},

    /* Kortex Adaptix 56000 (Quercia Michel, quercia@cal.enst.fr) */
    {"NBR=",			&CallerId},

    /* Russian USR Courier V.everything hackware, Alexey Promokhov */
    {"CallerID: ",		&CallerId},

    /* Swedish Telia/ZyXEL Omni 52k - Torulf Lundgren, torulf@upsys.se */
    {"Diverting number:",       &CallerId},

    /* FALCOM A2D gsm modem - Andreas Barth, debian bug */
    {"+CLIP: ",			&CallerId},

    {NULL}
};
    

void
cndfind _P1((str), char *str)
{
    struct cndtable *cp;
    register int len;
    register char *p;

    /* strip off blanks */
    
    while (*str && isspace(*str)) str++;
    p = str + strlen(str) - 1;
    while(p >= str && isspace(*p))
	*p-- = '\0';

    lprintf(L_JUNK, "CND: %s", str);

    /* The ELINK 301 ISDN modem can send us the caller ID if it is
       asked for it with AT\O. The CID will simply get sent on a single
       line consisting only of digits. So, if we get a line starting
       with a digit, let's assume that it's the CID...
     */
    if ( isdigit(*str) )
    {
	CallerId = p = strdup(str);
	while( isdigit(*p) ) p++;
	*p = 0;
	lprintf( L_NOISE, "CND: ELink caller ID: '%s'", CallerId );
	return;
    }

    for (cp = cndtable; cp->string; cp++)
    {
	len = strlen(cp->string);
	if (strncmp(cp->string, str, len) == 0)
	{
	    if (!cp->variable)
		return;

	    /* special case: Rockwell sends *two* MESG=... lines */
	    if (cp->variable == &CallMsg1 && CallMsg1[0] != 0)
		continue;

	    /* special case for CONNECT on Rockwell-Based modems */
	    if ( ( cnd_carrier[0] != 0 || cnd_protocol[0] != 0 ) &&
		 strncmp( str, "CONNECT ", 8 ) == 0 )
	    {
		*(cp->variable) = malloc( strlen(str) - len +
		                  strlen( cnd_carrier ) +
				  strlen( cnd_protocol ) + 5 );
		sprintf( *(cp->variable), "%s/%s %s",
			 str+len, cnd_carrier, cnd_protocol );
	    }
	    else	/* normal case */
	    {
		*(cp->variable) = p = malloc(strlen(str) - len + 1);
		(void) strcpy(*(cp->variable), str+len);

		/* nuke quotes and non-printable characters (some of this 
		 * stuff is passed to shell commands and environment vars)
		 */
		while( *p != '\0' )
		{ 
		    if ( *p == '\'' || *p == '\"' || !isprint(*p) ) *p = ' ';
		    p++;
		}
	    }
	    lprintf(L_JUNK, "CND: found: %s", *(cp->variable));
	    return;
	}
    }
}

/* process Rockwell-style caller ID. Weird */

void process_rockwell_mesg _P0 (void)
{
    int length = 0;
    int loop;
    char *p;

  /* In Canada, Bell Canada has come up with a fairly
     odd method of encoding the caller_id into MESG fields.
     With Supra caller ID (Rockwell), these come out as follows:

     MESG = 030735353531323132

     The first two bytes seem to mean nothing. The second
     two bytes are a hex number representing the phone number
     length. The phone number begins with the digit 3, then
     each digit of the phone number. Each digit of the phone
     number is preceeded by the character '3'.

     NB: I'm not sure whether this is Bell's or Rockwell's folly. I'd
     prefer to blaim Rockwell. gert
   */

    if ( CallMsg1[0] == 0) return;

    if ( (CallMsg1[0] != '0') || (CallMsg1[1] != '3')) return;

    /* Get the length of the number */
    CallMsg1[4] = '\0';
    sscanf( &CallMsg1[2], "%x", &length);

    lprintf(L_JUNK, "CND: number length: %d",length);
      
    /* Allocate space for the new number */
    p = CallerId = malloc(length + 1);
    
    /* Get the phone number only and put it into CallerId */
    for (loop = 5; loop <= (3 + length*2); loop += 2)
    {
	*p = CallMsg1[loop];
	p++;
    }  
    *p = 0;
      
    lprintf(L_JUNK, "CND: caller ID: %s", CallerId);
}

/* lookup Caller ID in CNDFILE, decide upon answering or not */

int cndlookup _P0 (void)
{
    int match = 1;
#ifdef CNDFILE
    FILE *cndfile;
    char buf[BUFSIZ];
    
    cndfile = fopen( makepath( CNDFILE, CONFDIR ), "r");
    if ( cndfile == NULL ) return(1);

    process_rockwell_mesg();		/* parse ugly rockwell msg */

    lprintf(L_JUNK, "CND: check no: '%s'", CallerId );

    while (fgets(buf, sizeof(buf), cndfile)) {
	register char *p = buf, *p2;
	while(isspace(*p)) p++;
	if (*p == '#' || *p == '\n')
	    continue;
	while( (p2 = strtok(p, " \t\n,")) != NULL )
	{
	    match = (*p2 != '!');

	    if (!match)
		p2++;

	    lprintf(L_JUNK, "CND: check vs: %s", p2);

	    if (strcmp(p2, "all") == 0)
		goto leave;
	    if (strncmp(p2, CallerId, strlen(p2)) == 0)
		goto leave;

	    p = NULL;
	}
    }
    match = 1;
  leave:
    fclose(cndfile);
#endif
    return(match);
}

/* check Caller ID via external program call */
int cnd_call _P3((name, tty, dist_ring),
		 char * name, char * tty, int dist_ring )
{
    char * program;
    int rc;

    program = malloc( strlen(name) + strlen(tty) + 
		      strlen( CallerId ) + strlen( CalledNr ) +
		      strlen( CallName ) +
		      sizeof( CONSOLE ) + 50 );
    if ( program == NULL )
	    { lprintf( L_ERROR, "cnd_call: can't malloc" ); return 0; }

    sprintf( program, "%s %s '%s' '%s' %d '%s' >%s 2>&1 </dev/null", name,
		      tty, CallerId, CallName, dist_ring, CalledNr, CONSOLE );
    lprintf( L_NOISE, "CND: program \"%s\"", program );

    rc = system(program);

    if ( rc < 0 )
    { lprintf( L_ERROR, "cnd_call: system failed" ); free(program); return 0; }

    lprintf( L_NOISE, "CND: rc=0x%x", rc );
    free(program);

    return rc>>8;
}
