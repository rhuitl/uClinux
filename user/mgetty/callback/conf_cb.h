#ident "%W% %E% Copyright (c) 1994 Gert Doering"

/* all (dynamic) callback configuration is contained in this structure.
 * It is initialized and loaded in conf_cb.c and accessed from callback.c
 */

extern struct conf_data_mgetty {
    struct conf_data
        ttys,				/* ttys */
        ttys_0,				/* for second pass, "ignore" */
	delay,				/* min. delay before first call */
	delay_rand,			/* add random time 0...dr to delay */
        retry_time,			/* time between two dialup attempts */
        max_retry_time,			/* how long to try altogether */

        modem_init,			/* modem initialization */
        speed,				/* port speed */
        dial_prefix,			/* ATDT0WP... */
	autobauding,			/* change baud rate to CONNECT "xxx" */
	prompt_waittime,		/* pause [in ms] after CONNECT */

	nodetach,			/* don't fork() */
        debug,				/* debugging */
	end_of_config; } c;

int callback_parse_args _PROTO(( int argc, char ** argv ));
void callback_get_config _PROTO(( char * port ));
