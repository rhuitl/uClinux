/* ulogd_LOGEMU.c, Version $Revision: 6386 $
 *
 * ulogd output target for syslog logging emulation
 *
 * This target produces a file which looks the same like the syslog-entries
 * of the LOG target.
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
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
 * $Id: ulogd_output_LOGEMU.c 6386 2006-01-08 23:37:51Z /C=DE/ST=Berlin/L=Berlin/O=Netfilter Project/OU=Development/CN=laforge/emailAddress=laforge@netfilter.org $
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>

#ifndef HOST_NAME_MAX
#warning this libc does not define HOST_NAME_MAX
#define HOST_NAME_MAX	(255+1)
#endif

#ifndef ULOGD_LOGEMU_DEFAULT
#define ULOGD_LOGEMU_DEFAULT	"/var/log/ulogd.syslogemu"
#endif

#ifndef ULOGD_LOGEMU_SYNC_DEFAULT
#define ULOGD_LOGEMU_SYNC_DEFAULT	0
#endif

static char hostname[HOST_NAME_MAX+1];

static struct ulogd_key logemu_inp[] = {
	{ 
		.type = ULOGD_RET_STRING,
		.name = "print", 
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_KEYF_OPTIONAL,
		.name = "oob.time.sec",
	},
};

static struct config_keyset logemu_kset = {
	.num_ces = 2,
	.ces = {
		{
			.key 	 = "file",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u	 = { .string = ULOGD_LOGEMU_DEFAULT },
		},
		{
			.key	 = "sync",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u	 = { .value = ULOGD_LOGEMU_SYNC_DEFAULT },
		},
	},
};

struct logemu_instance {
	FILE *of;
};

static int _output_logemu(struct ulogd_pluginstance *upi)
{
	struct logemu_instance *li = (struct logemu_instance *) &upi->private;
	struct ulogd_key *res = upi->input.keys;

	if (res[0].u.source->flags & ULOGD_RETF_VALID) {
		char *timestr;
		char *tmp;
		time_t now;

		if (res[1].u.source && (res[1].u.source->flags & ULOGD_RETF_VALID))
			now = (time_t) res[1].u.source->u.value.ui32;
		else
			now = time(NULL);

		timestr = ctime(&now) + 4;
		if ((tmp = strchr(timestr, '\n')))
			*tmp = '\0';

		fprintf(li->of, "%.15s %s %s", timestr, hostname,
				res[0].u.source->u.value.ptr);

		if (upi->config_kset->ces[1].u.value) 
			fflush(li->of);
	}

	return 0;
}

static void signal_handler_logemu(struct ulogd_pluginstance *pi, int signal)
{
	struct logemu_instance *li = (struct logemu_instance *) &pi->private;

	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "syslogemu: reopening logfile\n");
		fclose(li->of);
		li->of = fopen(pi->config_kset->ces[0].u.string, "a");
		if (!li->of) {
			ulogd_log(ULOGD_ERROR, "can't reopen syslogemu: %s\n",
				  strerror(errno));
		}
		break;
	default:
		break;
	}
}
		

static int start_logemu(struct ulogd_pluginstance *pi)
{
	struct logemu_instance *li = (struct logemu_instance *) &pi->private;
	char *tmp;

	ulogd_log(ULOGD_DEBUG, "starting logemu\n");

#ifdef DEBUG_LOGEMU
	li->of = stdout;
#else
	ulogd_log(ULOGD_DEBUG, "opening file: %s\n",
		  (char *)pi->config_kset->ces[0].u.string);
	li->of = fopen(pi->config_kset->ces[0].u.string, "a");
	if (!li->of) {
		ulogd_log(ULOGD_FATAL, "can't open syslogemu: %s\n", 
			  strerror(errno));
		return errno;
	}		
#endif

	if (gethostname(hostname, sizeof(hostname)) < 0) {
		ulogd_log(ULOGD_FATAL, "can't gethostname(): %s\n",
			  strerror(errno));
		return -EINVAL;
	}

	/* truncate hostname */
	if ((tmp = strchr(hostname, '.')))
		*tmp = '\0';

	return 0;
}

static int fini_logemu(struct ulogd_pluginstance *pi) {
	struct logemu_instance *li = (struct logemu_instance *) &pi->private;

	if (li->of != stdout)
		fclose(li->of);

	return 0;
}

static int configure_logemu(struct ulogd_pluginstance *pi,
			    struct ulogd_pluginstance_stack *stack)
{
	/* FIXME: error handling */
	ulogd_log(ULOGD_DEBUG, "parsing config file section %s\n", pi->id);
	config_parse_file(pi->id, pi->config_kset);

	return 0;
}

static struct ulogd_plugin logemu_plugin = { 
	.name = "LOGEMU",
	.input = {
		.keys = logemu_inp,
		.num_keys = ARRAY_SIZE(logemu_inp),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.config_kset 	= &logemu_kset,
	.priv_size 	= sizeof(struct logemu_instance),

	.configure	= &configure_logemu,
	.start	 	= &start_logemu,
	.stop	 	= &fini_logemu,

	.interp 	= &_output_logemu, 
	.signal 	= &signal_handler_logemu,
	.version	= ULOGD_VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&logemu_plugin);
}
