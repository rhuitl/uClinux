/*  ulogd_LOCAL.c, Version 0.3
 *
 *  ulogd interpreter plugin for: - local time of packet
 *                                - hostname of localhost
 *
 *  (C) 2001-2002 by Florent AIDE <faide@alphacent.com>
 *  with the help of Moez MKADMI <moez.mka@voila.fr>
 *  shamelessly ripped from Harald Welte
 *
 *  2002 extended by Martin Kaehmer <teg@mompl.org>
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
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <ulogd/ulogd.h>

#ifdef DEBUG_LOCAL
#define DEBUGP(x) ulogd_log(ULOGD_DEBUG, x)
#else
#define DEBUGP(format, args...)
#endif


static char hostname[255];

static ulog_iret_t *_interp_local(ulog_interpreter_t *ip,
                                  ulog_packet_msg_t *pkt)
{
	struct timeval tv;
	ulog_iret_t *ret = ip->result;

	/* Get date */
	gettimeofday(&tv, NULL);

	/* put date */
	ret[0].value.ui32 = (unsigned long) tv.tv_sec;
	ret[0].flags |= ULOGD_RETF_VALID;

	ret[1].value.ptr = hostname;
	ret[1].flags |= ULOGD_RETF_VALID;

	return ret;
}

static ulog_iret_t local_rets[] = {
	{ .type = ULOGD_RET_UINT32, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "local.time",
	},
	{ .type = ULOGD_RET_STRING, 
	  .flags = ULOGD_RETF_NONE, 
	  .key = "local.hostname",
	},
};

static ulog_interpreter_t local_ip[] = { 
    { NULL, "local", 0, &_interp_local, 2, local_rets },
    { NULL, "", 0, NULL, 0, NULL },
};

static void _local_reg_ip(void)
{
	ulog_interpreter_t *ip = local_ip;
	ulog_interpreter_t *p;

	for (p = ip; p->interp; p++)
		register_interpreter(p);
}

void _init(void)
{
	/* get hostname */
	char *tmp;
	if (gethostname(hostname, sizeof(hostname)) < 0) {
		ulogd_log(ULOGD_FATAL, "can't gethostname(): %s\n",
			  strerror(errno));
		exit(2);
	}
	/* strip off everything after first '.' */
	if ((tmp = strchr(hostname, '.')))
		*tmp = '\0';

	_local_reg_ip();
}
