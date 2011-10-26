#ident "%W% %E% Copyright (c) Gert Doering"

/* conf_cb.c
 *
 * configuration defaults / configuration reading code for callback tool
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "mgetty.h"
#include "policy.h"
#include "syslibs.h"
#include "tio.h"

#include "config.h"
#include "conf_cb.h"

extern char * mgetty_version;		/* mgetty.c/version.h */

/* initialize the modem - MODEM_INIT_STRING defined in policy.h
 */
static char * def_init_chat_seq[] = { "",
			    "ATQ0V1H0", "OK",
			    "AT+FCLASS=0", "OK",
                            NULL };

/* this is the default configuration...
 */

struct conf_data_mgetty c = {
	{ "dialout-devices", {(p_int)FAX_MODEM_TTYS}, CT_STRING, C_PRESET },
	{ "dialout-devices", {0}, CT_STRING, C_IGNORE },
	{ "delay", {20}, CT_INT, C_PRESET },
	{ "delay-randomize", {10}, CT_INT, C_PRESET },
	{ "retry-time", {30}, CT_INT, C_PRESET },
	{ "max-time", {600}, CT_INT, C_PRESET },

	{ "modem-init", {0}, CT_CHAT, C_PRESET },
	{ "speed", {DEFAULT_PORTSPEED}, CT_INT, C_PRESET },
	{ "dial-prefix", {(p_int) FAX_DIAL_PREFIX}, CT_STRING, C_PRESET },
	{ "autobauding", {FALSE}, CT_BOOL, C_PRESET },
	{ "prompt-waittime", {300}, CT_INT, C_PRESET },

	{ "", {FALSE}, CT_BOOL, C_PRESET },		/* nodetach */
	{ "debug", {LOG_LEVEL}, CT_INT, C_PRESET },
	{ NULL, {0}, CT_STRING, C_EMPTY }};

/*
 *	exit_usage() - exit with usage display
 */

void exit_usage _P1((code), int code )
{
    fprintf( stderr, "Usage: callback [-x <debug level>] [-V] [-l <modem lines>] [-m <initstring>]\n       [-s <speed>] [-d] [-S] [phone number(s)...]\n");
    exit(code);
}

int callback_parse_args _P2( (argc,argv), int argc, char ** argv )
{
int opt;

    /* sanity check:
     * make sure that structs-in-struct can be handled exactly as if
     * packed in array (get_config relies on it!)
     */
conf_data c_a[2];
    if ( ( (char *)&c_a[1] - (char *)&c_a[0] )  != 
	 ( (char *)&c.ttys_0 - (char *)&c.ttys ) )
    {
	fprintf( stderr, "ERROR: config table size mixup. contact author\n" );
	exit(99);
    }

    /* initialize a few things that can't be done statically */
    c.modem_init.d.p = (void *) def_init_chat_seq;
    c.modem_init.flags = C_PRESET;

#if 0
    c.answer_chat.d.p = (void *) def_answer_chat_seq;
    c.answer_chat.flags = C_PRESET;
#endif

    /* get command line arguments */

    while ((opt = getopt(argc, argv, "x:s:am:l:SdV")) != EOF)
    {
	switch (opt)
	{
	  case 'x':			/* log level */
	    conf_set_int( &c.debug, atoi(optarg) );
	    log_set_llevel( c_int(debug) );
	    break;
	  case 's':			/* port speed */
	    conf_set_int( &c.speed, atoi(optarg) );
	    break;
	  case 'a':			/* autobauding */
	  /*!!! FIXME: not implemented */
	    conf_set_bool( &c.autobauding, TRUE );
	    break;
	  case 'm':			/* modem init sequence */
	    c.modem_init.flags = C_OVERRIDE;
	    c.modem_init.d.p = conf_get_chat( optarg );
	    break;
	  case 'l':	/* set device(s) to use */
	    if ( optarg[0] == '/' &&
		 strncmp( optarg, "/dev/", 5 ) != 0 )
	    {
		fprintf( stderr, "%s: -l: device must be located in /dev!\n",
		                 argv[0]);
		exit(1);
	    }
	    conf_set_string( &c.ttys, optarg );
	    break;
	  case 'S':	/* unconditionally use *this* line for call back */
	    conf_set_string( &c.ttys, ttyname(0) );
	    lprintf( L_MESG, "using stdin for dial out, tty=%s", c_string(ttys));
	    break;
	  case 'd':	/* debug mode: don't detach from tty */
	    conf_set_bool( &c.nodetach, TRUE );
	    lprintf( L_MESG, "debug mode active" );
	    break;
	  case 'V':	/* show version number */
	    printf("\nmgetty+sendfax by Gert Doering\n%s\n\n",
		    mgetty_version);
	    printf("log file written to '");
	    printf(LOG_PATH, "callback" );
	    printf("'\n\n");
	    exit(0);
	  case '?':
	    exit_usage(2);
	    break;
	}
    }

    return NOERROR;
}


/* get callback configuration from file (defaults are used if it doesn't exist)
 */
void callback_get_config _P1( (port), char * port )
{
#ifdef CALLBACK_CONFIG
    if ( port == NULL )
    {
	lprintf( L_NOISE, "reading default configuration" );
	get_config( makepath( CALLBACK_CONFIG, CONFDIR ),
		    (conf_data *)&c, "port", NULL );
    }
    else
    {
	lprintf( L_NOISE, "reading specific data for port '%s'", port );
	get_config( makepath( CALLBACK_CONFIG, CONFDIR ),
		    ((conf_data *)&c)+1, "port", port );
    }
#else
    lprintf( L_NOISE, "not reading config file, not configured" );
#endif

    /* tell log subsystem about new log level */
    log_set_llevel( c_int(debug) );

    /* sanity checks */
    if ( tio_check_speed( c_int(speed) ) < 0 )
    {
	lprintf( L_FATAL, "invalid port speed: %d", c_int(speed));
	exit_usage(2);
    }

    /*!!! further checks required? */
}
