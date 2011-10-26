/* vi: set sw=4 ts=4: */
/*
 * Mini syslogd implementation for busybox
 *
 * Copyright (C) 1999-2003 by Erik Andersen <andersen@codepoet.org>
 *
 * Copyright (C) 2000 by Karl M. Hegbloom <karlheg@debian.org>
 *
 * "circular buffer" Copyright (C) 2001 by Gennady Feldman <gfeldman@gena01.com>
 *
 * Maintainer: Gennady Feldman <gfeldman@gena01.com> as of Mar 12, 2001
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <paths.h>
#include <signal.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <config/autoconf.h>

#include "busybox.h"
#include "syslogd.h"

static int last_time;
static int alarm_time;

/* Global config handle */
static syslogd_config_t *syslogd_config;

typedef struct {
	FILE *ph;
	int count;
	int remaining;
} email_info_t;

static void domailtime(int sig ATTRIBUTE_UNUSED)
{
	syslogd_target_t *target;

	time_t now = time(0);
	int delta = now - last_time;

	last_time = now;

	debug_printf("domailtime: delta=%d", delta);

	for (target = syslogd_config->local.common.next; target; target = target->next) {
		if (target->target == SYSLOG_TARGET_EMAIL) {
			syslogd_email_config_t *email = (syslogd_email_config_t *)target;
			email_info_t *info = (email_info_t *)target->priv;

			if (info && info->ph && info->count && email->delay) {
				if (info->remaining <= delta) {
					pclose(info->ph);
					info->ph = 0;
					info->count = 0;
					info->remaining = email->delay;
				}
				else {
					info->remaining -= delta;
				}
			}
		}
	}
	debug_printf("domailtime: done");

	alarm(alarm_time);
}

void init_email_targets(syslogd_config_t *config)
{
	syslogd_target_t *target;
	syslogd_config = config;

	/* Do we have any email targets with a delay? */
	for (target = config->local.common.next; target; target = target->next) {
		if (target->target == SYSLOG_TARGET_EMAIL) {
			syslogd_email_config_t *email = (syslogd_email_config_t *)target;
			if (email->delay && email->common.level != LOG_NONE) {
				/* Check to see if we have hit any delay time every 15 seconds */
				alarm_time = 15;
				break;

			}
		}
	}
}

void shutdown_email_targets(syslogd_config_t *config)
{
	syslogd_target_t *target;

	if (alarm_time) {
		alarm(0);
	}

	for (target = config->local.common.next; target; target = target->next) {
		if (target->target == SYSLOG_TARGET_EMAIL) {
			email_info_t *info = (email_info_t *)target->priv;
			if (info->ph) {
				pclose(info->ph);
			}
		}
	}
}

void log_email_message(syslogd_email_config_t *email, const char *msg)
{
	email_info_t *info;

	/* Create our private info if needed */
	if (!email->common.priv) {
		email->common.priv = info = malloc(sizeof(*info));

		info->ph = 0;
		info->count = 0;
		info->remaining = email->delay;

		/* And start our timer if needed */
		if (alarm_time) {
			last_time = time(0);
			signal(SIGALRM, domailtime);
			alarm(alarm_time);
		}
	}
	else {
		info = (email_info_t *)email->common.priv;
	}

	if (!info->ph) {
		char buf[999];

		if (!email->fromhost) {
			char myname[200];
			if (gethostname(myname, sizeof(myname)-1) < 0) {
				strcpy(myname, "unknownhost");
			}
			else {
				myname[sizeof(myname)-1] = '\0';
			}
			email->fromhost = strdup(myname);
		}
		snprintf(buf, sizeof(buf),
			"/bin/mail -R -s syslog_%s -S %s -H %s %s%s %s%s %s",
				syslogd_config->local_hostname,
				email->server,
				email->fromhost,
				email->from ? "-f " : "", email->from ?: "",
				email->sender ? "-N " : "", email->sender ?: "",
				email->addr);

		debug_printf("mail line is: '%s'", buf);

		info->ph = popen(buf, "w");
	} else {
		/*fprintf(info->ph, "\n========\n\n");*/
	}

	fprintf(info->ph, "%s", msg);

	info->count++;
	/* Now decide if we are done based on frequency */
	if (email->freq > 0 && info->count >= email->freq) {
		pclose(info->ph);
		info->ph = 0;
		info->count = 0;
		info->remaining = email->delay;
	}
}
