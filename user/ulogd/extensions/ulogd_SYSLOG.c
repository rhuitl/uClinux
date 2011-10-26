/* ulogd_SYSLOG.c, Version $Revision: 681 $
 *
 * ulogd output target for real syslog() logging
 *
 * This target produces a syslog entries identical to the LOG target.
 *
 * (C) 2003 by Harald Welte <laforge@gnumonks.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id: ulogd_SYSLOG.c 681 2005-02-09 17:19:58Z laforge $
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include "printpkt.h"

#ifndef SYSLOG_FACILITY_DEFAULT
#define SYSLOG_FACILITY_DEFAULT	"LOG_KERN"
#endif

#ifndef SYSLOG_LEVEL_DEFAULT 
#define SYSLOG_LEVEL_DEFAULT "LOG_NOTICE"
#endif

static config_entry_t facility_ce = { 
	.key = "facility", 
	.type = CONFIG_TYPE_STRING, 
	.options = CONFIG_OPT_NONE, 
	.u = { .string = SYSLOG_FACILITY_DEFAULT } 
};

static config_entry_t level_ce = { 
	.next = &facility_ce, 
	.key = "level", 
	.type = CONFIG_TYPE_INT,
	.options = CONFIG_OPT_NONE, 
	.u = { .string = SYSLOG_LEVEL_DEFAULT }
};

static int syslog_level, syslog_facility;

static int _output_syslog(ulog_iret_t *res)
{
	static char buf[4096];
	
	printpkt_print(res, buf, 0);
	syslog(syslog_level|syslog_facility, buf);

	return 0;
}
		
static int syslog_init(void)
{
	/* FIXME: error handling */
	config_parse_file("SYSLOG", &level_ce);

	if (!strcmp(facility_ce.u.string, "LOG_DAEMON"))
		syslog_facility = LOG_DAEMON;
	else if (!strcmp(facility_ce.u.string, "LOG_KERN"))
		syslog_facility = LOG_KERN;
	else if (!strcmp(facility_ce.u.string, "LOG_LOCAL0"))
		syslog_facility = LOG_LOCAL0;
	else if (!strcmp(facility_ce.u.string, "LOG_LOCAL1"))
		syslog_facility = LOG_LOCAL1;
	else if (!strcmp(facility_ce.u.string, "LOG_LOCAL2"))
		syslog_facility = LOG_LOCAL2;
	else if (!strcmp(facility_ce.u.string, "LOG_LOCAL3"))
		syslog_facility = LOG_LOCAL3;
	else if (!strcmp(facility_ce.u.string, "LOG_LOCAL4"))
		syslog_facility = LOG_LOCAL4;
	else if (!strcmp(facility_ce.u.string, "LOG_LOCAL5"))
		syslog_facility = LOG_LOCAL5;
	else if (!strcmp(facility_ce.u.string, "LOG_LOCAL6"))
		syslog_facility = LOG_LOCAL6;
	else if (!strcmp(facility_ce.u.string, "LOG_LOCAL7"))
		syslog_facility = LOG_LOCAL7;
	else if (!strcmp(facility_ce.u.string, "LOG_USER"))
		syslog_facility = LOG_USER;
	else {
		ulogd_log(ULOGD_FATAL, "unknown facility '%s'\n",
			  facility_ce.u.string);
		exit(2);
	}

	if (!strcmp(level_ce.u.string, "LOG_EMERG"))
		syslog_level = LOG_EMERG;
	else if (!strcmp(level_ce.u.string, "LOG_ALERT"))
		syslog_level = LOG_ALERT;
	else if (!strcmp(level_ce.u.string, "LOG_CRIT"))
		syslog_level = LOG_CRIT;
	else if (!strcmp(level_ce.u.string, "LOG_ERR"))
		syslog_level = LOG_ERR;
	else if (!strcmp(level_ce.u.string, "LOG_WARNING"))
		syslog_level = LOG_WARNING;
	else if (!strcmp(level_ce.u.string, "LOG_NOTICE"))
		syslog_level = LOG_NOTICE;
	else if (!strcmp(level_ce.u.string, "LOG_INFO"))
		syslog_level = LOG_INFO;
	else if (!strcmp(level_ce.u.string, "LOG_DEBUG"))
		syslog_level = LOG_DEBUG;
	else {
		ulogd_log(ULOGD_FATAL, "unknown level '%s'\n",
			facility_ce.u.string);
		exit(2);
	}

	openlog("ulogd", LOG_NDELAY|LOG_PID, syslog_facility);

	return 0;
}

static void syslog_fini(void)
{
	closelog();
}

static ulog_output_t syslog_op = { 
	.name = "syslog", 
	.init = &syslog_init,
	.fini = &syslog_fini,
	.output = &_output_syslog
};


void _init(void)
{
	if (printpkt_init())
		ulogd_log(ULOGD_ERROR, "can't resolve all keyhash id's\n");

	register_output(&syslog_op);
}
