/*****************************************************************************/

/*
 *	gettyd.c -- simple getty to support dial in PPP.
 *
 *	(C) Copyright 1999, Greg Ungerer (gerg@snapgear.com).
 *	(C) Copyright 2000, Lineo Inc. (www.lineo.com)
 */

/*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/termios.h>
#include <sys/wait.h>

#include "gettyd.h"

/*****************************************************************************/

#ifdef EMBED
#define	PPPD		"/bin/pppd"
#else
#define	PPPD		"/usr/sbin/pppd"
#endif

/*****************************************************************************/

void usage(int rc)
{
	printf("usage: gettyd <device> [<device>...]\n");
	exit(rc);
}

/*****************************************************************************/

int creatpidfile()
{
	FILE	*f;
	pid_t	pid;
	char	*pidfile = "/var/run/gettyd.pid";

	pid = getpid();
	if ((f = fopen(pidfile, "w")) == NULL) {
		/* Oh well... */
		return(-1);
	}
	fprintf(f, "%d\n", pid);
	fclose(f);
	return(0);
}

/*****************************************************************************/

/*
 *	Spawn all those lines that are not running.
 */

void spawn(struct line *lines)
{
	char	*sp, *bp;
	pid_t	pid;
	int	i;

	for (i = 0; (lines[i].device != NULL); i++) {
		if (lines[i].pid != 0)
			continue;

		/* Find base device name */
		if (lines[i].device[0] == '/') {
			for (bp = sp = lines[i].device; (bp != NULL); ) {
				sp = bp + 1;
				bp = strchr(sp, '/');
			}
		}

		pid = vfork();
		if (pid < 0) {
			syslog(LOG_ERR, "vfork()=%d failed!  errno=%d",
				pid, errno);
			return;
		}
		if (pid == 0) {
			execl(PPPD, PPPD, "nodetach", lines[i].device, (char *) 0);
			/* Exec() failed...!! */
			exit(errno);
		}
		lines[i].pid = pid;
	}
}

/*****************************************************************************/

static int gotterm;

void term_handler(int signum)
{
	gotterm = 1;
}

/*****************************************************************************/

int main(int argc, char *argv[])
{
	struct line	dialin[16];
	pid_t		pid;
	int		i, nrdevs, status;
	struct		sigaction sa;

	if ((argc <= 1) || (argc > (sizeof(dialin) / sizeof(struct line))))
		usage(1);

	memset(&dialin, 0, sizeof(dialin));

	openlog("gettyd", 0, 0);
	for (i = 0, nrdevs = argc - 1; (i < nrdevs); i++) {
		dialin[i].device = argv[i+1];
		syslog(LOG_INFO, "setting up dialin on %s", dialin[i].device);
	}

	/* Disconnect from the real world */
	setpgrp();
	creatpidfile();

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, NULL);

	for (;;) {
		spawn(&dialin[0]);
		sleep(1);

		status = 0;
		if ((pid = wait(&status)) < 0 || gotterm) {
			for (i = 0; (i < nrdevs); i++)
				if (dialin[i].pid != 0)
					kill(dialin[i].pid, SIGTERM);
			exit(1);
		}

		for (i = 0; (i < nrdevs); i++) {
			if (dialin[i].pid == pid) {
				dialin[i].pid = 0;
				break;
			}
		}
	}
}

/*****************************************************************************/
