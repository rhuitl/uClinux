/*
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <stdio.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>

libc_hidden_proto(_exit)
libc_hidden_proto(wait4)
libc_hidden_proto(execl)
libc_hidden_proto(signal)
libc_hidden_proto(vfork)

/* uClinux-2.0 has vfork, but Linux 2.0 doesn't */
#include <sys/syscall.h>
#ifndef __NR_vfork
# define vfork fork	
libc_hidden_proto(fork)
#endif

extern __typeof(system) __libc_system;
int __libc_system(const char *command)
{
	int wait_val, pid;
	__sighandler_t save_quit, save_int, save_chld;

	if (command == 0)
		return 1;

	save_quit = signal(SIGQUIT, SIG_IGN);
	save_int = signal(SIGINT, SIG_IGN);
	save_chld = signal(SIGCHLD, SIG_DFL);

	if ((pid = vfork()) < 0) {
		signal(SIGQUIT, save_quit);
		signal(SIGINT, save_int);
		signal(SIGCHLD, save_chld);
		return -1;
	}
	if (pid == 0) {
		signal(SIGQUIT, SIG_DFL);
		signal(SIGINT, SIG_DFL);
		signal(SIGCHLD, SIG_DFL);

		execl("/bin/sh", "sh", "-c", command, (char *) 0);
		_exit(127);
	}
	/* Signals are not absolutly guarenteed with vfork */
	signal(SIGQUIT, SIG_IGN);
	signal(SIGINT, SIG_IGN);

#if 0
	__printf("Waiting for child %d\n", pid);
#endif

	if (wait4(pid, &wait_val, 0, 0) == -1)
		wait_val = -1;

	signal(SIGQUIT, save_quit);
	signal(SIGINT, save_int);
	signal(SIGCHLD, save_chld);
	return wait_val;
}
weak_alias(__libc_system,system)
