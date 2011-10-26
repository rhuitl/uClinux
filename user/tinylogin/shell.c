/* vi: set sw=4 ts=4: */
/*
 * Copyright 1989 - 1991, Julianne Frances Haugh
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

#include "tinylogin.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

//extern char **newenvp;
//extern size_t newenvc;

static char *Basename(char *str)
{
	char *cp = strrchr(str, '/');

	return cp ? cp + 1 : str;
}


/*
 * shell - execute the named program
 *
 *	shell begins by trying to figure out what argv[0] is going to
 *	be for the named process.  The user may pass in that argument,
 *	or it will be the last pathname component of the file with a
 *	'-' prepended.  The first attempt is to just execute the named
 *	file.  If the errno comes back "ENOEXEC", the file is assumed
 *	at first glance to be a shell script.  The first two characters
 *	must be "#!", in which case "/bin/sh" is executed to process
 *	the file.  If all that fails, give up in disgust ...
 */

extern void shell(char *file, char *arg)
{
	char arg0[1024];
	int err;

	if (file == (char *) 0)
		exit(1);

	/*
	 * The argv[0]'th entry is usually the path name, but
	 * for various reasons the invoker may want to override
	 * that.  So, we determine the 0'th entry only if they
	 * don't want to tell us what it is themselves.
	 */

	if (arg == (char *) 0) {
		snprintf(arg0, sizeof arg0, "-%s", Basename(file));
		arg = arg0;
	}

	/*
	 * First we try the direct approach.  The system should be
	 * able to figure out what we are up to without too much
	 * grief.
	 */

	//execle (file, arg, (char *) 0, newenvp);
	execl(file, arg, (char *) 0);
	err = errno;

	/*
	 * Obviously something is really wrong - I can't figure out
	 * how to execute this stupid shell, so I might as well give
	 * up in disgust ...
	 */

	snprintf(arg0, sizeof arg0, "Cannot execute %s", file);
	errno = err;
	perror(arg0);
	exit(1);
}
