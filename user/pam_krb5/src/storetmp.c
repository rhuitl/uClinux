/*
 * Copyright 2004,2006,2009 Red Hat, Inc.
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
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "storetmp.h"

ssize_t
_pam_krb5_write_with_retry(int fd, const unsigned char *buffer, ssize_t len)
{
	ssize_t length, ret;
	fd_set fds;
	length = 0;
	while (len > length) {
		ret = write(fd, buffer + length, len - length);
		switch (ret) {
		case 0:
			return length;
			break;
		case -1:
			switch (errno) {
			case EINTR:
			case EAGAIN:
				FD_ZERO(&fds);
				FD_SET(fd, &fds);
				select(fd + 1, NULL, &fds, &fds, NULL);
				if (FD_ISSET(fd, &fds)) {
					continue;
				}
				break;
			}
			return length;
			break;
		default:
			length += ret;
			break;
		}
	}
	return length;
}

ssize_t
_pam_krb5_read_with_retry(int fd, unsigned char *buffer, ssize_t len)
{
	ssize_t length, ret;
	fd_set fds;
	length = 0;
	while (len > length) {
		ret = read(fd, buffer + length, len - length);
		switch (ret) {
		case 0:
			return length;
			break;
		case -1:
			switch (errno) {
			case EINTR:
			case EAGAIN:
				FD_ZERO(&fds);
				FD_SET(fd, &fds);
				select(fd + 1, &fds, NULL, &fds, NULL);
				if (FD_ISSET(fd, &fds)) {
					continue;
				}
				break;
			}
			return length;
			break;
		default:
			length += ret;
			break;
		}
	}
	return length;
}

/* Use a helper to store the given data in a new file with a name which is
 * based on the given pattern. */
static int
_pam_krb5_storetmp_data(const unsigned char *data, ssize_t data_len,
			const char *pattern, uid_t uid, gid_t gid,
			char *outfile, size_t outfile_len)
{
	int i;
	int inpipe[2], outpipe[2], dummy[3];
	char uidstr[100], gidstr[100];
	pid_t child;
	struct sigaction saved_sigchld_handler, saved_sigpipe_handler;
	struct sigaction ignore_handler, default_handler;
	for (i = 0; i < 3; i++) {
		dummy[i] = open("/dev/null", O_RDONLY);
	}
	if (pipe(inpipe) == -1) {
		for (i = 0; i < 3; i++) {
			close(dummy[i]);
		}
		return -1;
	}
	if (pipe(outpipe) == -1) {
		for (i = 0; i < 3; i++) {
			close(dummy[i]);
		}
		close(inpipe[0]);
		close(inpipe[1]);
		return -1;
	}
	/* Set signal handlers here.  We used to do it later, but that turns
	 * out to be a race if the child decides to exit immediately. */
	memset(&default_handler, 0, sizeof(default_handler));
	default_handler.sa_handler = SIG_DFL;
	if (sigaction(SIGCHLD, &default_handler, &saved_sigchld_handler) != 0) {
		close(inpipe[0]);
		close(inpipe[1]);
		close(outpipe[0]);
		close(outpipe[1]);
		return -1;
	}
	memset(&ignore_handler, 0, sizeof(ignore_handler));
	ignore_handler.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &ignore_handler, &saved_sigpipe_handler) != 0) {
		sigaction(SIGCHLD, &saved_sigchld_handler, NULL);
		close(inpipe[0]);
		close(inpipe[1]);
		close(outpipe[0]);
		close(outpipe[1]);
		return -1;
	}
	switch (child = fork()) {
	case -1:
		sigaction(SIGCHLD, &saved_sigchld_handler, NULL);
		sigaction(SIGPIPE, &saved_sigpipe_handler, NULL);
		for (i = 0; i < 3; i++) {
			close(dummy[i]);
		}
		close(inpipe[0]);
		close(inpipe[1]);
		close(outpipe[0]);
		close(outpipe[1]);
		return -1;
		break;
	case 0:
		/* We're the child. */
		close(inpipe[1]);
		close(outpipe[0]);
		for (i = 0; i < sysconf(_SC_OPEN_MAX); i++) {
			if ((i != inpipe[0]) && (i != outpipe[1])) {
				close(i);
			}
		}
		dup2(outpipe[1], STDOUT_FILENO);
		dup2(inpipe[0], STDIN_FILENO);
#ifdef HAVE_LONG_LONG
		snprintf(uidstr, sizeof(uidstr), "%llu",
			 (unsigned long long) uid);
		snprintf(gidstr, sizeof(gidstr), "%llu",
			 (unsigned long long) gid);
#else
		snprintf(uidstr, sizeof(uidstr), "%lu", (unsigned long) uid);
		snprintf(gidstr, sizeof(gidstr), "%lu", (unsigned long) gid);
#endif
		if ((strlen(uidstr) > sizeof(uidstr) - 2) ||
		    (strlen(gidstr) > sizeof(gidstr) - 2)) {
			_exit(-1);
		}
		if (uid == 0) {
			setgroups(0, NULL);
		}
		/* Now, attempt to assume the desired uid/gid pair.  Note that
		 * if we're not root, this is allowed to fail. */
		if ((gid != getgid()) || (gid != getegid())) {
			setregid(gid, gid);
		}
		if ((uid != getuid()) || (uid != geteuid())) {
			setreuid(uid, uid);
		}
		execl(PKGSECURITYDIR "/pam_krb5_storetmp", "pam_krb5_storetmp",
		      pattern, uidstr, gidstr, NULL);
		_exit(-1);
		break;
	default:
		/* parent */
		for (i = 0; i < 3; i++) {
			close(dummy[i]);
		}
		close(inpipe[0]);
		close(outpipe[1]);
		if (_pam_krb5_write_with_retry(inpipe[1],
					       data, data_len) == data_len) {
			close(inpipe[1]);
			memset(outfile, '\0', outfile_len);
			_pam_krb5_read_with_retry(outpipe[0],
						  (unsigned char*) outfile,
						  outfile_len - 1);
			outfile[outfile_len - 1] = '\0';
		} else {
			close(inpipe[1]);
			memset(outfile, '\0', outfile_len);
		}
		close(outpipe[0]);
		waitpid(child, NULL, 0);
		sigaction(SIGCHLD, &saved_sigchld_handler, NULL);
		sigaction(SIGPIPE, &saved_sigpipe_handler, NULL);
		if (strlen(outfile) >= strlen(pattern)) {
			return 0;
		} else {
			return -1;
		}
		break;
	}
	abort(); /* not reached */
}

int
_pam_krb5_storetmp_file(const char *infile, const char *pattern,
			void **copy, size_t *copy_len,
			uid_t uid, gid_t gid, char *outfile, size_t outfile_len)
{
	struct stat st;
	int fd, ret;
	unsigned char *buf;
	if (strlen(infile) > outfile_len - 1) {
		return -1;
	}
	fd = open(infile, O_RDONLY);
	if (fd == -1) {
		return -1;
	}
	if (fstat(fd, &st) == -1) {
		close(fd);
		return -1;
	}
	if (st.st_size > 0x100000) {
		close(fd);
		return -1;
	}
	buf = malloc(st.st_size);
	if (buf == NULL) {
		close(fd);
		return -1;
	}
	if (_pam_krb5_read_with_retry(fd, buf, st.st_size) != st.st_size) {
		free(buf);
		close(fd);
		return -1;
	}
	close(fd);
	if (copy != NULL) {
		*copy = malloc(st.st_size);
		memcpy(*copy, buf, st.st_size);
		if (copy_len != NULL) {
			*copy_len = st.st_size;
		}
	}
	ret = _pam_krb5_storetmp_data(buf, st.st_size, pattern, uid, gid,
				      outfile, outfile_len);
	free(buf);
	return ret;
}

int
_pam_krb5_storetmp_delete(const char *file)
{
	char *buf;
	unsigned char empty[] = "";
	int ret;

	buf = malloc(strlen(file) + 1);
	if (buf == NULL) {
		return -1;
	}
	memset(buf, 0, strlen(file) + 1);
	ret = _pam_krb5_storetmp_data(empty, 0, file, -1, -1,
				      buf, strlen(file) + 1);
	free(buf);

	return ret;
}
