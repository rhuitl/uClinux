/*
 * Copyright 2004,2006 Red Hat, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of the
 * GNU Lesser General Public License, in which case the provisions of the
 * LGPL are required INSTEAD OF the above restrictions.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "../config.h"

#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xstr.h"

/* A simple (hopefully) helper which creates a file using mkstemp() and a
 * supplied pattern, attempts to set the ownership of that file, stores
 * whatever it reads from stdin in that file, and then prints the file's name
 * on stdout.
 *
 * While all of this can be done directly by pam_krb5, we need to do it after
 * an exec() to have the file created with the proper context if we're running
 * in an SELinux environment, so the helper is used.  To simplify debugging and
 * maintenance, use of this helper is not conditionalized. */

int
main(int argc, const char **argv)
{
	char *filename, *p;
	long long uid, gid;
	gid_t current_gid;
	int fd;
	char c;

	/* We're not intended to be set*id! */
	if ((getuid() != geteuid()) || (getgid() != getegid())) {
		return 1;
	}

	/* One, two, or three arguments.  No more, no less, else we bail. */
	if ((argc < 2) || (argc > 4)) {
		return 2;
	}

	/* We'll need a writable string for use as the template. */
	filename = xstrdup(argv[1]);
	if (filename == NULL) {
		return 3;
	}

	/* If the filename didn't end with XXXXXX, our job is to remove it. */
	if (strlen(filename) > 6) {
		p = filename + strlen(filename) - 6;
		if (strcmp(p, "XXXXXX") != 0) {
			if (unlink(filename) == 0) {
				goto success;
			} else {
				return 4;
			}
		}
	}

	/* Parse the UID, if given. */
	if (argc > 2) {
#ifdef HAVE_STRTOLL
		uid = strtoll(argv[2], &p, 0);
#else
		uid = strtol(argv[2], &p, 0);
#endif
		if ((p == NULL) || (*p != '\0')) {
			return 5;
		}
	} else {
		uid = getuid();
	}

	/* Parse the GID, if given. */
	if (argc > 3) {
#ifdef HAVE_STRTOLL
		gid = strtoll(argv[3], &p, 0);
#else
		gid = strtol(argv[3], &p, 0);
#endif
		if ((p == NULL) || (*p != '\0')) {
			return 6;
		}
	} else {
		gid = getgid();
	}

	/* Attempt to drop supplemental groups and become the given user (if
	 * one was given).  Note that this may all fail if we're unprivileged,
	 * and that is expressly allowed (we're mainly here to do the open(),
	 * anything else is "gravy". */
	current_gid = getgid();
	if (getuid() == 0) {
		setgroups(0, &current_gid);
	}
	if (getgid() != gid) {
		setregid(gid, gid);
	}
	if (getuid() != uid) {
		setreuid(uid, uid);
	}

	/* Create a temporary file. */
	fd = mkstemp(filename);
	if (fd == -1) {
		return 7;
	}

	/* Copy stdin to the file and then close it.  Slowest copy EVER. */
	while (read(STDIN_FILENO, &c, 1) == 1) {
		if (write(fd, &c, 1) != 1) {
			break;
		}
	}
	close(fd);

success:
	/* Tell our caller what the name of the file and bail. */
	if (write(STDOUT_FILENO, filename,
		  strlen(filename)) != (ssize_t) strlen(filename)) {
		return 8;
	}
	if (isatty(STDOUT_FILENO)) {
		if (write(STDOUT_FILENO, "\n", 1) != 1) {
			return 8;
		}
	}
	return 0;
}
