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

#define MIN_ERRMSG_INTERVAL 300

typedef struct {
	struct sockaddr_in saremote;	/* sockaddr representing hostname, port */
} remote_info_t;

/* udp socket for logging to remote host */
static int remote_socket = -1;

void init_remote_targets(syslogd_config_t *config ATTRIBUTE_UNUSED)
{
}

void shutdown_remote_targets(syslogd_config_t *config ATTRIBUTE_UNUSED)
{
}

void log_remote_message(syslogd_remote_config_t *remote, const char *msg)
{
	remote_info_t *info;

	debug_printf("log_remote_message(remote=%p, msg=%s)", remote, msg);
	debug_printf("host=%s", remote->host);

	if (remote_socket == -1) {
		remote_socket = socket(AF_INET, SOCK_DGRAM, 0);
		if (remote_socket < 0) {
			bb_perror_msg_and_die("syslogd: cannot create socket");
		}
	}

	if (!remote->common.priv) {
		struct hostent *hostinfo = 0;

		if (remote->host) {
			debug_printf("Getting ip address for server: %s", remote->host);

			hostinfo = xgethostbyname(remote->host);

			debug_printf("Got hostinfo=%p", hostinfo);
		}

		if (!hostinfo || !hostinfo->h_addr_list) {
			debug_printf("Disabling remote target because we couldn't resolve %s", remote->host);
			remote->common.level = LOG_NONE;
			return;
		}

		debug_printf("Allocating priv");

		remote->common.priv = info = malloc(sizeof(*info));

		memset(&info->saremote, 0, sizeof(info->saremote));

		debug_printf("Creating socket");

		debug_printf("Setting up saremote");

		info->saremote.sin_family = AF_INET;
		debug_printf("%s:%d", __FILE__, __LINE__);
		info->saremote.sin_addr = *(struct in_addr *) *hostinfo->h_addr_list;
		debug_printf("%s:%d", __FILE__, __LINE__);
		info->saremote.sin_port = htons(remote->port);
		debug_printf("%s:%d", __FILE__, __LINE__);
	}
	else {
		debug_printf("%s:%d", __FILE__, __LINE__);
		info = (remote_info_t *)remote->common.priv;
	}
		debug_printf("%s:%d", __FILE__, __LINE__);

	for (;;) {
		debug_printf("%s:%d", __FILE__, __LINE__);
		if (-1 == sendto(remote_socket, msg, strlen(msg), 0, (struct sockaddr *)&info->saremote, sizeof(info->saremote))) {
			time_t now;
			static time_t last_message_time = 0;
		debug_printf("%s:%d", __FILE__, __LINE__);

			if (errno == EINTR) {
		debug_printf("%s:%d", __FILE__, __LINE__);
				continue;
			}
		debug_printf("%s:%d", __FILE__, __LINE__);

			/*
			 * Throttle these messages so that we don't get one after
			 * every message if the network is down
			 */
			now = time(0);
			if (now - last_message_time > MIN_ERRMSG_INTERVAL) {
				debug_printf("syslogd: cannot write to remote file handle on %s:%d - %m\n",
					remote->host, remote->port);

				debug_printf("host=%s", remote->host);
				debug_printf("port=%d", remote->port);

				syslog_local_message("syslogd: cannot write to remote file handle on %s:%d - %m\n",
					remote->host, remote->port);
				last_message_time = now;
			}
		}
		debug_printf("%s:%d", __FILE__, __LINE__);
		break;
	}
}
