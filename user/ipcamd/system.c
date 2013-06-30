/*
This file is part of ipcamd, an embedded web server for IP cameras.

Copyright (c) 2011-2013, Robert Huitl <robert@huitl.de>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

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
