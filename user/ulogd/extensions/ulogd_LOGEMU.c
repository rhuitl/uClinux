/* ulogd_LOGEMU.c, Version $Revision: 699 $
 *
 * ulogd output target for syslog logging emulation
 *
 * This target produces a file which looks the same like the syslog-entries
 * of the LOG target.
 *
 * (C) 2000-2001 by Harald Welte <laforge@gnumonks.org>
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
 * $Id: ulogd_LOGEMU.c 699 2005-02-14 16:12:49Z laforge $
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include "printpkt.c"

#ifndef ULOGD_LOGEMU_DEFAULT
#define ULOGD_LOGEMU_DEFAULT	"/var/log/ulogd.syslogemu"
#endif

#ifndef ULOGD_LOGEMU_SYNC_DEFAULT
#define ULOGD_LOGEMU_SYNC_DEFAULT	0
#endif

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

static config_entry_t syslogf_ce = { 
	.key = "file", 
	.type = CONFIG_TYPE_STRING, 
	.options = CONFIG_OPT_NONE, 
	.u = { .string = ULOGD_LOGEMU_DEFAULT }
};

static config_entry_t syslsync_ce = { 
	.next = &syslogf_ce, 
	.key = "sync", 
	.type = CONFIG_TYPE_INT, 
	.options = CONFIG_OPT_NONE, 
	.u = { .value = ULOGD_LOGEMU_SYNC_DEFAULT }
};

static FILE *of = NULL;

static int _output_logemu(ulog_iret_t *res)
{
	static char buf[4096];

	printpkt_print(res, buf, 1);

	fprintf(of, "%s", buf);

	if (syslsync_ce.u.value) 
		fflush(of);

	return 0;
}

static void signal_handler_logemu(int signal)
{
	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "syslogemu: reopening logfile\n");
		fclose(of);
		of = fopen(syslogf_ce.u.string, "a");
		if (!of) {
			ulogd_log(ULOGD_FATAL, "can't open syslogemu: %s\n",
				strerror(errno));
			exit(2);
		}
		break;
	default:
		break;
	}
}
		

static int init_logemu(void) {
	/* FIXME: error handling */
	config_parse_file("LOGEMU", &syslsync_ce);

#ifdef DEBUG_LOGEMU
	of = stdout;
#else
	of = fopen(syslogf_ce.u.string, "a");
	if (!of) {
		ulogd_log(ULOGD_FATAL, "can't open syslogemu: %s\n", 
			strerror(errno));
		exit(2);
	}		
#endif
	if (printpkt_init()) {
		ulogd_log(ULOGD_ERROR, "can't resolve all keyhash id's\n");
	}

	return 1;
}

static void fini_logemu(void) {
	if (of != stdout)
		fclose(of);
}

static ulog_output_t logemu_op = { 
	.name = "syslogemu",
	.init = &init_logemu,
	.fini = &fini_logemu,
	.output = &_output_logemu, 
	.signal = &signal_handler_logemu,
};

void _init(void)
{
	register_output(&logemu_op);
}
