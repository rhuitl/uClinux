/* vi: set sw=4 ts=4: */
/*
 * Copyright 1989 - 1994, Julianne Frances Haugh
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Julianne F. Haugh nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY JULIE HAUGH AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL JULIE HAUGH OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Separated from setup.c.  --marekm
 */

#include "tinylogin.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

static void addenv_mail(const char *maildir, const char *mailfile)
{
	char *buf;

	buf = xmalloc(strlen(maildir) + strlen(mailfile) + 2);
	sprintf(buf, "%s/%s", maildir, mailfile);
	addenv("MAIL", buf);
	free(buf);
}

/*
 *	change to the user's home directory
 *	set the HOME, SHELL, MAIL, PATH, and LOGNAME or USER environmental
 *	variables.
 */

extern void setup_env(struct passwd *info)
{

	/*
	 * Change the current working directory to be the home directory
	 * of the user.  It is a fatal error for this process to be unable
	 * to change to that directory.  There is no "default" home
	 * directory.
	 *
	 * We no longer do it as root - should work better on NFS-mounted
	 * home directories.  Some systems default to HOME=/, so we make
	 * this a configurable option.  --marekm
	 */

	if (chdir(info->pw_dir) == -1) {
		if (chdir("/") == -1) {
			fprintf(stderr, "Unable to cd to \"%s\"", info->pw_dir);
			syslog(LOG_WARNING,
				   "unable to cd to `%s' for user `%s'\n",
				   info->pw_dir, info->pw_name);
			closelog();
			exit(1);
		}
		puts("No directory, logging in with HOME=/");
		info->pw_dir = "/";
	}

	/*
	 * Create the HOME environmental variable and export it.
	 */

	addenv("HOME", info->pw_dir);

	/*
	 * Create the SHELL environmental variable and export it.
	 */

	if (info->pw_shell == (char *) 0 || !*info->pw_shell)
		info->pw_shell = "/bin/sh";

	addenv("SHELL", info->pw_shell);

	/*
	 * Create the PATH environmental variable and export it.
	 */

	if (info->pw_uid == 0)
		addenv("PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL);
	else
		addenv("PATH=/bin:/usr/bin", NULL);

	/*
	 * Export the user name.  For BSD derived systems, it's "USER", for
	 * all others it's "LOGNAME".  We set both of them.
	 */

	addenv("USER", info->pw_name);
	addenv("LOGNAME", info->pw_name);

	addenv_mail("/var/spool/mail", info->pw_name);
}
