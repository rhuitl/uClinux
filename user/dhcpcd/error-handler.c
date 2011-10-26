/* $Id: error-handler.c,v 1.1.1.1 1999-11-22 03:47:59 christ Exp $
 *
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>
 *
 * Dhcpcd is an RFC2131 and RFC1541 compliant DHCP client daemon.
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

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include "error-handler.h"

#define MAXLINE 1024

int DebugFlag;

static void	errorPrint(int flag, const char *fmt, va_list ap);
static void	sendLog(int flag, int priority, const char *fmt, va_list ap);


static void
errorPrint(int flag, const char *fmt, va_list ap)
{
	int		errnoOrg;
	char	buf[MAXLINE];

	errnoOrg = errno;
	vsprintf(buf, fmt, ap);
	if ( flag ) {
		sprintf(buf+strlen(buf), ": %s", strerror(errnoOrg));
	}
	strcat(buf, "\n");
	fflush(stdout);			/* in case stdout and stderr are the same */
	fputs(buf, stderr);
	fflush(NULL);			/* flushes all stdio output streams */
}

void
errSysExit(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	errorPrint(1, fmt, ap);
	va_end(ap);
	die(1);
}

void
errSysRet(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	errorPrint(1, fmt, ap);
	va_end(ap);
}

void
errQuit(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	errorPrint(0, fmt, ap);
	va_end(ap);
	die(1);
}


void
errMsg(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	errorPrint(0, fmt, ap);
	va_end(ap);
}

static void
sendLog(int flag, int priority, const char *fmt, va_list ap)
{
	int  errnoOrg;
	char buf[MAXLINE];

	errnoOrg = errno;
	vsprintf(buf, fmt, ap);
	if ( flag ) {
		sprintf(buf+strlen(buf), ": %s", strerror(errnoOrg));
	}
	if ( DebugFlag ) {
		strcat(buf, "\n");
		fflush(stdout);
		fputs(buf, stderr);
		fflush(NULL);
	} else {
		syslog(priority, buf);
	}
}

void
logOpen(const char *ident, int option, int facility)
{
	if ( !DebugFlag ) {
		openlog(ident, option, facility);
	}
}

void
logSysExit(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sendLog(1, LOG_ERR, fmt, ap);
	va_end(ap);
	closelog();
	die(2);
}

void
logSysRet(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sendLog(1, LOG_ERR, fmt, ap);
	va_end(ap);
}

void
logQuit(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sendLog(0, LOG_ERR, fmt, ap);
	va_end(ap);
	closelog();
	die(2);
}

void
logRet(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sendLog(0, LOG_ERR, fmt, ap);
	va_end(ap);
}
