/* $Id: signal-handler.c,v 1.3 2001-06-22 03:32:53 davidm Exp $
 *
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>
 *
 * Dhcpcd is an RFC1541 compliant DHCP client daemon.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <sys/types.h>
#include <net/if.h>
#include <signal.h>
#include <unistd.h>
#include "dhcp.h"
#include "if.h"
#include "signal-handler.h"
#include "error-handler.h"
#include "client.h"

pid_t ComFilePid = 0;

static void sigHandler();
static int SigStat;

extern u_long ServerInaddr;

void
signalSetup()
{
	signal(SIGTERM, sigHandler);
	signal(SIGINT, sigHandler);
	signal(SIGHUP, sigHandler);
	signal(SIGALRM, sigHandler);
}

void
addSignal(int sig)
{
	signal(sig, sigHandler);
}

static void
sigHandler(int sig)
{
	int errnoOrg;

	SigStat  = sig;
	errnoOrg = errno;

	switch ( sig ) {
#if 0
	  case SIGCHLD:
		if ( ComFilePid != 0 ) {
			if ( waitpid(ComFilePid, NULL, 0) == ComFilePid ) {
				signal(SIGCHLD, SIG_IGN);
			}
		}
		break;
#endif
	  case SIGINT:
	  case SIGTERM:
		if ( Ifbuf.addr != 0 ) {
			sendDhcpDecline(DHCP_RELEASE, ServerInaddr, Ifbuf.addr);
		}
		/* To ensure DHCPRELEASE msg is sent. It takes a little time
		 * to send a DHCPRELEASE msg in case the server's MAC address
		 * is cached out because the host has to wait for the ARP reply from
		 * the server. So do not make the interface down too quickly.
		 */
		sleep(5);
		ifDown(&Ifbuf);
		die(3);
	  default:
		break;
	}
}


