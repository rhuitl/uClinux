#ident "$Id: conf_sf.h,v 4.5 1999/02/24 16:05:36 gert Exp $ Copyright (c) 1994 Gert Doering"

/* all (dynamic) sendfax configuration is contained in this structure.
 * It is initialized and loaded in conf_sf.c and accessed from sendfax.c
 */

extern struct conf_data_sendfax {
    struct conf_data
	ttys,
        ttys_0,				/* for "ignore" */
	modem_init,
	modem_handshake,
	modem_type,
	modem_quirks,
	fax_send_flow,
	fax_rec_flow,
	max_tries,
        max_tries_ctd,
	speed,
	switchbd,
	open_delay,
	ignore_carrier,
	dial_prefix,
	station_id,
	poll_dir,
	normal_res,
	fax_min_speed,
	fax_max_speed,
	debug,
	verbose,
	fax_poll_wanted,	/* cli only (-p) */
	fax_page_header,
	use_stdin,		/* cli only (-S) */
        rename_files,		/* cli only (-r) */
        acct_handle,		/* cli only (-A) */
	end_of_config; } c;

int sendfax_parse_args _PROTO(( int argc, char ** argv ));
void sendfax_get_config _PROTO(( char * port ));
