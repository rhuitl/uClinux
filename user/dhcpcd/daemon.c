#if 0
/* $Id: daemon.c,v 1.1.1.1 1999-11-22 03:47:59 christ Exp $
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

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "error-handler.h"
#include "daemon.h"

#ifdef OPEN_MAX
	static int OpenMax = OPEN_MAX;
#else
	static int OpenMax = 0;
#endif

#define OPEN_MAX_GUESS 256

void
daemonInit(const char *pidfile)
{
	char s[10];
	pid_t pid;
	int   fd;
	int   i;

	if ( (pid = fork() ) < 0 )
	{
		errSysExit("fork (daemonInit)");
	} else if ( pid != 0 ) {
		/* parent saves pid into *pidfile, and goes bye-bye
		 */
		if ( pidfile != NULL ) {
			if ( (fd = creat(pidfile,
							 S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0 ) {
				logSysRet("creat (daemonInit)");
				return;
			}
			sprintf(s, "%d\n", pid);
			if ( write(fd, s, strlen(s)) < 0 ) {
				logSysRet("write (daemonInit)");
			}
			close(fd);
		}
		die(0);
	}
	/* child continues
	 */
	setsid();
	chdir("/");
	umask(0);

	for ( i = 0; i < openMax(); ++i ) {
		close(i);
	}
}


int
openMax()
{
	if ( OpenMax == 0 ) {
		errno = 0;
		if ( (OpenMax = sysconf(_SC_OPEN_MAX)) < 0 ) {
			if ( errno == 0 ) {
				OpenMax = OPEN_MAX_GUESS; /* it's indeterminate */
			} else {
				errSysExit("sysconf (openMax)");
			}
		}
	}
	return OpenMax;
}

void
killCurProc(char *pidfile)
{
	int fd;
	int len;
	int pid;
	char pidStr[8];

	if ( (fd = open(pidfile, O_RDONLY)) < 0 ) {
		errSysExit("open (killCurProc) %s", pidfile);
	}
	if ( (len = read(fd, pidStr, 8)) < 0 ) {
		errSysExit("read (killCurProc)");
	}
	pidStr[len] = '\0';
	pid = atoi(pidStr);
	if ( kill(pid, SIGTERM) < 0 ) {
		if ( unlink(pidfile) < 0 ) {
			errSysRet("unlink (killCurProc)");
		}
		errSysExit("kill (killCurProc) pid %d", pid);
	}
	errMsg("Process (pid %d) has been successfully terminated", pid);
	if ( unlink(pidfile) < 0 ) {
		errSysExit("unlink (killCurProc)");
	}
	die(0);
}
#endif
