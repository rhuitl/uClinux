#include "system.h"
#include "watchdog.h"

#include <stdio.h>
#include <unistd.h>

int run_bg_process(const char* filename, char* const args[])
{
	// Disable the watchdog. File handle inheritance creates another
	// watchdog client, but we cannot close the handle between vfork() and
	// exec() as we could when using fork().
	// TODO find a way to keep the watchdog running all the time
	watchdog_close(0);

	int pid;
	switch(pid = vfork()) {
	case -1:
		/* Couldn't fork */
		perror("vfork failed\n");
		watchdog_open();
		return -1;

	case 0:
	/* Child */

#ifdef NEED_SIGNAL_HANDLERS
            /* Try installing with signal handlers as in sash.c, just in case! */
            printf("vfork: installing signal handlers\n");
            signal(SIGINT, SIG_DFL);
            signal(SIGQUIT, SIG_DFL);
            signal(SIGCHLD, SIG_DFL);
#endif

		//printf("vfork: Child executing\n");
		execv(filename, args);

		/* If we reach here the exec failed */
		perror("vfork: Child failed to exec");
		_exit(-1);

	default:
		/* Parent */
		//printf("vfork: parent: PID=%d\n", pid);
		watchdog_open();
		return pid;
	}
}
