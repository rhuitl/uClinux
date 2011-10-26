#ident "$Id: conf_mg.c,v 4.15 2001/01/27 16:22:37 gert Exp $ Copyright (c) Gert Doering"

/* conf_mg.c
 *
 * configuration defaults / configuration reading code for mgetty
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "mgetty.h"
#include "policy.h"
#include "syslibs.h"
#include "tio.h"

#include "config.h"
#include "conf_mg.h"

extern char * mgetty_version;		/* mgetty.c/version.h */

#ifndef MODEM_CHECK_TIME
# define MODEM_CHECK_TIME -1		/* no check */
#endif

#if defined(FAX_USRobotics) && !defined(FAX_RECV_SWITCHBD)
#define FAX_RECV_SWITCHBD 19200
#endif

#ifndef FAX_RECV_SWITCHBD
#define FAX_RECV_SWITCHBD 0		/* no switching */
#endif

#ifndef FAX_FILE_MODE
#define FAX_FILE_MODE	-1		/* controlled by umask */
#endif

/* initialize the modem - MODEM_INIT_STRING defined in policy.h
 */
static char * def_init_chat_seq[] = { "",
			    "\\dATQ0V1H0", "OK",
			    MODEM_INIT_STRING, "OK",
                            NULL };

/* "force init" the modem (DLE ETX for voice modems, +++ATH0 for all others)
 */
static char * def_force_init_chat_seq[] = { "",
			    "\\d\020\03\\d\\d\\d+++\\d\\d\\d\r\\dATQ0V1H0", 
			    "OK", NULL };

/* default way to answer the phone...
 */
static char * def_answer_chat_seq[] =
			    { "", "ATA", "CONNECT", "\\c", "\n", NULL };

/* this is the default configuration...
 */

struct conf_data_mgetty c = {
	{ "speed", {DEFAULT_PORTSPEED}, CT_INT, C_PRESET },
	{ "switchbd", {FAX_RECV_SWITCHBD}, CT_INT, C_PRESET },
	{ "direct", {FALSE}, CT_BOOL, C_PRESET },
	{ "blocking", {FALSE}, CT_BOOL, C_PRESET },

	{ "port-owner", {(p_int) DEVICE_OWNER}, CT_STRING, C_PRESET },
#ifdef DEVICE_GROUP
	{ "port-group", {(p_int) DEVICE_GROUP}, CT_STRING, C_PRESET },
#else
	{ "port-group", {0}, CT_STRING, C_EMPTY },
#endif
	{ "port-mode", {FILE_MODE}, CT_INT, C_PRESET },

	{ "toggle-dtr", {TRUE}, CT_BOOL, C_PRESET },
	{ "toggle-dtr-waittime", {500}, CT_INT, C_PRESET },
	{ "need-dsr", {FALSE}, CT_BOOL, C_PRESET },
	{ "data-only", {FALSE}, CT_BOOL, C_PRESET },
	{ "fax-only", {FALSE}, CT_BOOL, C_PRESET },
	{ "modem-type", {(p_int) DEFAULT_MODEMTYPE}, CT_STRING, C_PRESET },
	{ "modem-quirks", {0}, CT_INT, C_EMPTY },
	{ "init-chat", {0}, CT_CHAT, C_EMPTY },
	{ "force-init-chat", {0}, CT_CHAT, C_EMPTY },
	{ "post-init-chat", {0}, CT_CHAT, C_EMPTY },
	{ "data-flow", {DATA_FLOW}, CT_FLOWL, C_PRESET },
	{ "fax-send-flow", {FAXSEND_FLOW}, CT_FLOWL, C_PRESET },
	{ "fax-rec-flow", {FAXREC_FLOW}, CT_FLOWL, C_PRESET },

	{ "modem-check-time", {MODEM_CHECK_TIME}, CT_INT, C_PRESET },
	{ "rings", {1}, CT_INT, C_PRESET },
	{ "msn-list", {(p_int) NULL}, CT_CHAT, C_EMPTY },
	{ "get-cnd-chat", {0}, CT_CHAT, C_EMPTY },
	{ "cnd-program", {(p_int) NULL}, CT_STRING, C_EMPTY },
	{ "answer-chat", {0}, CT_CHAT, C_EMPTY },
	{ "answer-chat-timeout", {80}, CT_INT, C_PRESET },
	{ "autobauding", {FALSE}, CT_BOOL, C_PRESET },

	{ "ringback", {FALSE}, CT_BOOL, C_PRESET },
	{ "ringback-time", {30}, CT_INT, C_PRESET },

	{ "ignore-carrier", {FALSE}, CT_BOOL, C_PRESET },
	{ "issue-file", {(p_int)"/etc/issue"}, CT_STRING, C_PRESET },
	{ "prompt-waittime", {500}, CT_INT, C_PRESET },
	{ "login-prompt", {(p_int) LOGIN_PROMPT}, CT_STRING, C_PRESET },
#ifdef MAX_LOGIN_TIME
	{ "login-time", {MAX_LOGIN_TIME}, CT_INT, C_PRESET },
#else
	{ "login-time", {0}, CT_INT, C_EMPTY },
#endif
	{ "fido-send-emsi", {TRUE}, CT_BOOL, C_PRESET },

#ifdef LOGIN_CFG_FILE
	{ "login-conf-file", {(p_int) LOGIN_CFG_FILE}, CT_STRING, C_PRESET },
#else
	{ "login-conf-file", {0}, CT_STRING, C_EMPTY },
#endif

	{ "fax-id", {(p_int)FAX_STATION_ID}, CT_STRING, C_PRESET },
	{ "fax-min-speed", {0}, CT_INT, C_PRESET },
	{ "fax-max-speed", {14400}, CT_INT, C_PRESET },
	{ "fax-server-file", {0}, CT_STRING, C_EMPTY },
	{ "diskspace", {MINFREESPACE}, CT_INT, C_PRESET },
#ifdef MAIL_TO
	{ "notify", {(p_int)MAIL_TO}, CT_STRING, C_PRESET },
#else
	{ "notify", {0, CT_STRING}, C_EMPTY },
#endif
	{ "fax-owner", {(p_int)FAX_IN_OWNER}, CT_STRING, C_PRESET },
#ifdef FAX_IN_GROUP
	{ "fax-group", {(p_int)FAX_IN_GROUP}, CT_STRING, C_PRESET },
#else
	{ "fax-group", {0}, CT_STRING, C_EMPTY },
#endif
	{ "fax-mode", {FAX_FILE_MODE}, CT_INT, C_PRESET },
#ifdef __STDC__
	{ "fax-spool-in", {(p_int) FAX_SPOOL_IN ":/tmp"}, CT_STRING, C_PRESET },
#else
	{ "fax-spool-in", {(p_int) FAX_SPOOL_IN}, CT_STRING, C_PRESET },
#endif

	{ "debug", {LOG_LEVEL}, CT_INT, C_PRESET },
	
	{ "statistics-chat", {0}, CT_CHAT, C_EMPTY },
	{ "statistics-file", {0}, CT_STRING, C_EMPTY },
	{ "gettydefs", {(p_int)GETTYDEFS_DEFAULT_TAG}, CT_STRING, C_PRESET },
	{ "term", {0}, CT_STRING, C_EMPTY },

	{ NULL, {0}, CT_STRING, C_EMPTY }};

/*
 *	exit_usage() - exit with usage display
 */

void exit_usage _P1((code), int code )
{
#ifdef USE_GETTYDEFS
    lprintf( L_FATAL, "Usage: mgetty [-x debug] [-s speed] [-r] line [gettydefentry]" );
#else
    lprintf( L_FATAL, "Usage: mgetty [-x debug] [-s speed] [-r] line" );
#endif
    exit(code);
}

int mgetty_parse_args _P2( (argc,argv), int argc, char ** argv )
{
int opt;
#ifdef USE_GETTYDEFS
extern boolean verbose;
#endif

    /* sanity check:
     * make sure that structs-in-struct can be handled exactly as if
     * packed in array (get_config relies on it!)
     */
conf_data c_a[2];
    if ( ( (char *)&c_a[1] - (char *)&c_a[0] )  != 
	 ( (char *)&c.switchbd - (char *)&c.speed ) )
    {
	fprintf( stderr, "ERROR: config table size mixup. contact author\n" );
	exit(99);
    }

    /* initialize a few things that can't be done statically */
    c.init_chat.d.p = (void *) def_init_chat_seq;
    c.init_chat.flags = C_PRESET;

    c.force_init_chat.d.p = (void *) def_force_init_chat_seq;
    c.force_init_chat.flags = C_PRESET;

    c.answer_chat.d.p = (void *) def_answer_chat_seq;
    c.answer_chat.flags = C_PRESET;


    /* get command line arguments */

    /* some magic done by the command's name */
    if ( strcmp( get_basename( argv[0] ), "getty" ) == 0 )
    {
	conf_set_bool( &c.blocking, TRUE );
	conf_set_bool( &c.direct_line, TRUE );
    }

    while ((opt = getopt(argc, argv, "c:x:s:rp:n:R:i:DC:FS:k:m:I:baV")) != EOF)
    {
	switch (opt)
	{
	  case 'c':			/* check */
#ifdef USE_GETTYDEFS
	    verbose = TRUE;
	    dumpgettydefs(optarg);
	    exit(0);
#else
	    lprintf( L_FATAL, "gettydefs not supported\n");
	    exit_usage(2);
#endif
	  case 'k':			/* kbytes free on disk */
	    conf_set_int( &c.diskspace, atol(optarg) );
	    break;
	  case 'x':			/* log level */
	    conf_set_int( &c.debug, atoi(optarg) );
	    log_set_llevel( c_int(debug) );
	    break;
	  case 's':			/* port speed */
	    conf_set_int( &c.speed, atoi(optarg) );
	    break;
	  case 'r':			/* direct line (nullmodem) */
	    conf_set_int( &c.direct_line, TRUE );
	    break;
	  case 'p':			/* login prompt */
	    conf_set_string( &c.login_prompt, optarg );
	    break;
	  case 'n':			/* ring counter */
	    conf_set_int( &c.rings_wanted, atoi(optarg) );
	    break;
	  case 'R':			/* ringback timer */
	    conf_set_bool( &c.ringback, TRUE );
	    conf_set_int( &c.ringback_time, atoi(optarg) );
	    break;
	  case 'i':			/* use different issue file */
	    conf_set_string( &c.issue_file, optarg );
	    break;
	  case 'D':			/* switch off fax */
	    conf_set_bool( &c.data_only, TRUE );
	    break;
	  case 'F':			/* switch off data-mode (security!) */
	    conf_set_bool( &c.fax_only, TRUE );
	    break;
	  case 'C':			/* set modem mode (fax/data) */
	    conf_set_string( &c.modem_type, optarg );
	    break;
	  case 'S':			/* fax poll file to send */
	    conf_set_string( &c.fax_server_file, optarg );
	    break;
	  case 'I':			/* local station ID */
	    conf_set_string( &c.station_id, optarg);
	    break;
	  case 'b':			/* open port in blocking mode */
	    conf_set_bool( &c.blocking, TRUE );
	    break;
	  case 'a':			/* autobauding */
	    conf_set_bool( &c.autobauding, TRUE );
	    break;
	  case 'm':			/* modem init sequence */
	    c.init_chat.flags = C_OVERRIDE;
	    c.init_chat.d.p = conf_get_chat( optarg );
	    break;
	  case 'V':			/* show version number */
	    printf("\nmgetty+sendfax by Gert Doering\n%s\n\n",
		    mgetty_version);
	    printf("log file written to '");
	    printf(LOG_PATH, "<ttyX>");
#ifdef MGETTY_CONFIG
            printf("'\nconfig file read from '%s", 
			makepath( MGETTY_CONFIG, CONFDIR ));
#endif
	    printf("'\n\n");
	    exit(0);
	  case '?':
	    exit_usage(2);
	    break;
	}
    }

    return NOERROR;
}


/* get mgetty configuration from file (if configured)
 */
void mgetty_get_config _P1( (port), char * port )
{
#ifdef MGETTY_CONFIG
    lprintf( L_NOISE, "reading configuration data for port '%s'", port );
    get_config( makepath( MGETTY_CONFIG, CONFDIR ),
		(conf_data *)&c, "port", port );
#else
    lprintf( L_NOISE, "not reading config file, not configured" );
#endif

    /* tell log subsystem about new log level */
    log_set_llevel( c_int(debug) );

    /* tell getdisk.c about desired disk space (in kbytes) */
    minfreespace = c_int(diskspace);

    /* sanity checks */
    if ( tio_check_speed( c_int(speed) ) < 0 )
    {
	lprintf( L_FATAL, "invalid port speed: %d", c_int(speed));
	exit_usage(2);
    }
    if ( c_isset(switchbd) && c_int(switchbd) != 0 && !c_bool(data_only) &&
	 tio_check_speed( c_int(switchbd) ) < 0 )
    {
	lprintf( L_FATAL, "invalid fax reception switch speed: %d",
		 c_int(switchbd) );
	exit_usage(2);
    }

    if ( c_int(rings_wanted) == 0 ) conf_set_int( &c.rings_wanted, 1 );

    if ( c_int(ringback_time) < 30 ) conf_set_int( &c.ringback_time, 30);

    if ( c_int(modem_check_time) >= 0 &&
	 c_int(modem_check_time) < 900 )
    {
	lprintf( L_NOISE, "increasing modem_check_time to 900 sec." );
	conf_set_int( &c.modem_check_time, 900 );
    }

    if ( c_isset(modem_quirks) )
    {
        lprintf( L_NOISE, "set modem_quirks: 0x%04x", c_int(modem_quirks));
	modem_quirks = c_int(modem_quirks);
    }
}
