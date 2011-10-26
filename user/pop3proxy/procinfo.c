
/*

    File: procinfo.c

    Copyright (C) 2005  Wolfgang Zekoll  <wzk@quietsche-entchen.de>
  
    This software is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
  
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
  
    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <ctype.h>
#include <signal.h>
#include <wait.h>
#include <errno.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <syslog.h>
#include <sys/time.h>



#include "lib.h"
#include "ip-lib.h"
#include "pop3.h"
#include "procinfo.h"


char	varprefix[40] =		"POP3_";

char	statdir[200] =		"";
char	sessiondir[200] =	"";

procinfo_t pi;


int init_procinfo(char *vp)
{
	memset(&pi, 0, sizeof(procinfo_t));
	if (vp != NULL)
		copy_string(varprefix, vp, sizeof(varprefix));

	return (0);
}

FILE *getstatfp(void)
{
	if (*statdir == 0)
		return (NULL);

	if (*pi.statfile == 0) {
		snprintf(pi.statfile, sizeof(pi.statfile) - 2, "%s/%s-%05d.stat",
				statdir, program, getpid());
		if ((pi.statfp = fopen(pi.statfile, "w")) == NULL) {
			printerror(0, "-INFO", "can't open statfile %s, error= %s",
					pi.statfile, strerror(errno));
			}
		}

	return (pi.statfp);
}



int setvar(char *var, char *value)
{
	char	varname[200];

	snprintf (varname, sizeof(varname) - 2, "%s%s", varprefix, var);
	setenv(varname, value != NULL? value: "", 1);

	return (0);
}

int setnumvar(char *var, unsigned long val)
{
	char	strval[40];

	snprintf (strval, sizeof(strval) - 2, "%lu", val);
	setvar(var, strval);

	return (0);
}


char *setpidfile(char *pidfile)
{
	if (pidfile == NULL  ||  *pidfile == 0)
		snprintf (pi.pidfile, sizeof(pi.pidfile) - 2, "/var/run/%s.pid", program);
	else
		copy_string(pi.pidfile, pidfile, sizeof(pi.pidfile));

	return (pi.pidfile);
}


void exithandler(void)
{
	if (debug != 0)
		printerror(0, "+DEBUG", "exithandler mainpid= %u, statfile= %s", pi.mainpid, pi.statfile);

	if (pi.mainpid == getpid()) {
		if (*pi.pidfile != 0) {
			if (unlink(pi.pidfile) != 0) {
				printerror(0, "-ERR", "can't unlink pidfile %s, error= %s",
						pi.pidfile, strerror(errno));
				}
			}
		}

	if (pi.statfp != NULL) {
		rewind(pi.statfp);
		fprintf (pi.statfp, "\n");
		fclose (pi.statfp);

		if ((pi.statfp = fopen(pi.statfile, "w")) != NULL) {
			fprintf (pi.statfp, "%s", "");
			fclose (pi.statfp);
			}
		}

	if (*pi.statfile != 0) {
		if (unlink(pi.statfile) != 0) {
			printerror(0, "-ERR", "can't unlink statfile %s, error= %s",
					pi.statfile, strerror(errno));
			}
		}

	return;
}


