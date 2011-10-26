/* Simple backwards compat code to exec old version */

#ifndef CONFIG_NO_BACKWARDS_COMPAT

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <asm/unistd.h>

extern long create_module(const char *, size_t);

#include "testing.h"

static void exec_old(const char *progname, char *argv[])
{
	char *sep;
	pid_t pid;
	char ascii_pid[32];
	char pathname[strlen(argv[0])+1];
	char oldname[strlen(progname) + strlen(argv[0]) + sizeof(".old")];

	memset(pathname, 0, strlen(argv[0])+1);
	sep = strrchr(argv[0], '/');
	if (sep)
		memcpy(pathname, argv[0], sep - argv[0]+1);
	sprintf(oldname, "%s%s.old", pathname, progname);

	/* Recursion detection: we need an env var since we can't
	   change argv[0] (as older modutils uses it to determine
	   behavior).  We *can* recurse in the case of old-style
	   pre-install etc. commands, so make sure pid is exactly the
	   same. */
	pid = getpid();
	snprintf(ascii_pid, sizeof(ascii_pid), "%lu", (unsigned long)pid);
	if (strcmp(getenv("MODULE_RECURSE") ?: "", ascii_pid) == 0) {
		fprintf(stderr, "WARNING: %s: I am not the old version!\n",
			oldname);
		return;
	}
	setenv("MODULE_RECURSE", ascii_pid, 1);

	execvp(oldname, argv);
	fprintf(stderr,
		"Kernel requires old %s, but couldn't run %s: %s\n",
		progname, oldname, strerror(errno));
	exit(2);
}

static void try_old_version(const char *progname, char *argv[])
{
	errno = 0;
	if (create_module(NULL, 0) >= 0 /* Uh oh, what have I just done? */
	    || errno != ENOSYS)
		exec_old(progname, argv);
}
#else /* CONFIG_NO_BACKWARDS_COMPAT */
static inline void try_old_version(const char *progname, char *argv[])
{
}
#endif /* !CONFIG_NO_BACKWARDS_COMPAT */
