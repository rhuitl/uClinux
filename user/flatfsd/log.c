#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "flatfs.h"

void vlogd(int bg, const char *cmd, const char *arg)
{
	pid_t pid;

	pid = vfork();
	if (pid < 0)
		return;
	else if (pid == 0) {
		execl("/bin/logd", "/bin/logd", cmd, arg, NULL);
		_exit(1);
	}
	else if (!bg) {
		int status;

		while (waitpid(pid, &status, 0) == -1 && errno == EINTR);
	}
}

void logd(const char *cmd, const char *format, ...)
{
	va_list ap;
	char *arg;

	if (format) {
		va_start(ap, format);
		vasprintf(&arg, format, ap);
		va_end(ap);

		vlogd(0, cmd, arg);
		free(arg);
	} else
		vlogd(0, cmd, NULL);
}
