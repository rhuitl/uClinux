/* kill.c
 *
 * Copyright (c) 1993 by David I. Bell
 * Copyright (C) 1999, Rt-Control Inc.
 * Copyright (C) 2000  Lineo, Inc.  (www.lineo.com) 
 *
 * Permission is granted to use, distribute, or modify this source,
 * provided that this copyright notice remains intact.
 *
 */
 
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <utime.h>
#include <errno.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifndef isdecimal
#define isdecimal(X) ((X) >= '0' && (X) <= '9' ? 1 : 0)
#endif

int
main(argc, argv)
	char	**argv;
{
	char	*cp;
	int	sig;
	int	pid;

	sig = SIGTERM;

	if (argv[1][0] == '-') {
		cp = &argv[1][1];
		if (strcmp(cp, "HUP") == 0)
			sig = SIGHUP;
		else if (strcmp(cp, "INT") == 0)
			sig = SIGINT;
		else if (strcmp(cp, "QUIT") == 0)
			sig = SIGQUIT;
		else if (strcmp(cp, "ILL") == 0)
			sig = SIGILL;
		else if (strcmp(cp, "TRAP") == 0)
			sig = SIGTRAP;
		else if (strcmp(cp, "ABRT") == 0)
			sig = SIGABRT;
		else if (strcmp(cp, "IOT") == 0)
			sig = SIGIOT;
		else if (strcmp(cp, "BUS") == 0)
			sig = SIGBUS;
		else if (strcmp(cp, "FPE") == 0)
			sig = SIGFPE;
		else if (strcmp(cp, "KILL") == 0)
			sig = SIGKILL;
		else if (strcmp(cp, "USR1") == 0)
			sig = SIGUSR1;
		else if (strcmp(cp, "SEGV") == 0)
			sig = SIGSEGV;
		else if (strcmp(cp, "USR2") == 0)
			sig = SIGUSR2;
		else if (strcmp(cp, "PIPE") == 0)
			sig = SIGPIPE;
 		else if (strcmp(cp, "ALRM") == 0)
			sig = SIGALRM;
 		else if (strcmp(cp, "TERM") == 0)
			sig = SIGTERM;
 		else if (strcmp(cp, "STKFLT") == 0)
			sig = SIGSTKFLT;
 		else if (strcmp(cp, "CHLD") == 0)
			sig = SIGCHLD;
		else if (strcmp(cp, "CONT") == 0)
			sig = SIGCONT;
		else if (strcmp(cp, "STOP") == 0)
			sig = SIGSTOP;
		else if (strcmp(cp, "TSTP") == 0)
			sig = SIGTSTP;
 		else if (strcmp(cp, "TTIN") == 0)
			sig = SIGTTIN;
 		else if (strcmp(cp, "TTOU") == 0)
			sig = SIGTTOU;
 		else if (strcmp(cp, "URG") == 0)
			sig = SIGURG;
 		else if (strcmp(cp, "PWR") == 0)
			sig = SIGPWR;
		else {
			sig = 0;
			while (isdecimal(*cp))
				sig = sig * 10 + *cp++ - '0';

			if (*cp) {
				write(2, "Unknown signal\n", strlen("Unknown signal\n"));
				exit(1);
			}
		}
		argc--;
		argv++;
	}

	while (argc-- > 1) {
		cp = *++argv;
		pid = 0;
		while (isdecimal(*cp))
			pid = pid * 10 + *cp++ - '0';

		if (*cp) {
			write(2, "Non-numeric pid\n", strlen("Non-numeric pid\n"));
			exit(1);
		}

		if (kill(pid, sig) < 0)
			perror(*argv);
	}
	return 0;
}
