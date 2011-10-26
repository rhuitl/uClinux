/* ulogd_SYSLOG.c, Version $Revision: 6386 $
 *
 * ulogd output target for real syslog() logging
 *
 * This target produces a syslog entries identical to the LOG target.
 *
 * (C) 2003-2005 by Harald Welte <laforge@gnumonks.org>
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
 * $Id: ulogd_output_SYSLOG.c 6386 2006-01-08 23:37:51Z /C=DE/ST=Berlin/L=Berlin/O=Netfilter Project/OU=Development/CN=laforge/emailAddress=laforge@netfilter.org $
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>

#ifndef SYSLOG_FACILITY_DEFAULT
#define SYSLOG_FACILITY_DEFAULT	"LOG_KERN"
#endif

#ifndef SYSLOG_LEVEL_DEFAULT 
#define SYSLOG_LEVEL_DEFAULT "LOG_NOTICE"
#endif

static struct ulogd_key syslog_inp[] = {
	{ 
		.type = ULOGD_RET_STRING,
		.name = "print", 
	},
};

static struct config_keyset syslog_kset = { 
	.num_ces = 2,
	.ces = {
		{
		.key = "facility", 
		.type = CONFIG_TYPE_STRING, 
		.options = CONFIG_OPT_NONE, 
		.u = { .string = SYSLOG_FACILITY_DEFAULT } 
		},
		{ 
		.key = "level", 
		.type = CONFIG_TYPE_STRING,
		.options = CONFIG_OPT_NONE, 
		.u = { .string = SYSLOG_LEVEL_DEFAULT }
		},
	},
};

struct syslog_instance {
	int syslog_level;
	int syslog_facility;
};

static int _output_syslog(struct ulogd_pluginstance *upi)
{
	struct syslog_instance *li = (struct syslog_instance *) &upi->private;
	struct ulogd_key *res = upi->input.keys;

	if (res[0].u.source->flags & ULOGD_RETF_VALID)
		syslog(li->syslog_level | li->syslog_facility, "%s",
				(char *)res[0].u.source->u.value.ptr);

	return 0;
}
		
static int syslog_configure(struct ulogd_pluginstance *pi,
			    struct ulogd_pluginstance_stack *stack)
{
	int syslog_facility, syslog_level;
	char *facility, *level;

	/* FIXME: error handling */
	config_parse_file(pi->id, pi->config_kset);

	facility = pi->config_kset->ces[0].u.string;
	level = pi->config_kset->ces[1].u.string;

	if (!strcmp(facility, "LOG_DAEMON"))
		syslog_facility = LOG_DAEMON;
	else if (!strcmp(facility, "LOG_KERN"))
		syslog_facility = LOG_KERN;
	else if (!strcmp(facility, "LOG_LOCAL0"))
		syslog_facility = LOG_LOCAL0;
	else if (!strcmp(facility, "LOG_LOCAL1"))
		syslog_facility = LOG_LOCAL1;
	else if (!strcmp(facility, "LOG_LOCAL2"))
		syslog_facility = LOG_LOCAL2;
	else if (!strcmp(facility, "LOG_LOCAL3"))
		syslog_facility = LOG_LOCAL3;
	else if (!strcmp(facility, "LOG_LOCAL4"))
		syslog_facility = LOG_LOCAL4;
	else if (!strcmp(facility, "LOG_LOCAL5"))
		syslog_facility = LOG_LOCAL5;
	else if (!strcmp(facility, "LOG_LOCAL6"))
		syslog_facility = LOG_LOCAL6;
	else if (!strcmp(facility, "LOG_LOCAL7"))
		syslog_facility = LOG_LOCAL7;
	else if (!strcmp(facility, "LOG_USER"))
		syslog_facility = LOG_USER;
	else {
		ulogd_log(ULOGD_FATAL, "unknown facility '%s'\n",
			  facility);
		return -EINVAL;
	}

	if (!strcmp(level, "LOG_EMERG"))
		syslog_level = LOG_EMERG;
	else if (!strcmp(level, "LOG_ALERT"))
		syslog_level = LOG_ALERT;
	else if (!strcmp(level, "LOG_CRIT"))
		syslog_level = LOG_CRIT;
	else if (!strcmp(level, "LOG_ERR"))
		syslog_level = LOG_ERR;
	else if (!strcmp(level, "LOG_WARNING"))
		syslog_level = LOG_WARNING;
	else if (!strcmp(level, "LOG_NOTICE"))
		syslog_level = LOG_NOTICE;
	else if (!strcmp(level, "LOG_INFO"))
		syslog_level = LOG_INFO;
	else if (!strcmp(level, "LOG_DEBUG"))
		syslog_level = LOG_DEBUG;
	else {
		ulogd_log(ULOGD_FATAL, "unknown level '%s'\n",
			  level);
		return -EINVAL;
	}

	return 0;
}

static void syslog_fini(void)
{
	closelog();
}
static int syslog_start(struct ulogd_pluginstance *pi)
{
	openlog("ulogd", LOG_NDELAY|LOG_PID, LOG_DAEMON);

	return 0;
}

static struct ulogd_plugin syslog_plugin = {
	.name = "SYSLOG",
	.input = {
		.keys = syslog_inp,
		.num_keys = ARRAY_SIZE(syslog_inp),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.config_kset	= &syslog_kset,
	.priv_size	= sizeof(struct syslog_instance),
	
	.configure	= &syslog_configure,
	.start		= &syslog_start,
	.interp		= &_output_syslog,
	.version	= ULOGD_VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&syslog_plugin);
}
