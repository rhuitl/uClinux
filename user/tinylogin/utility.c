/* vi: set sw=4 ts=4: */
/*
 * Utility routines.
 *
 * Copyright (C) tons of folks.  Tracking down who wrote what
 * isn't something I'm going to worry about...  If you wrote something
 * here, please feel free to acknowledge your work.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */

#include "tinylogin.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <stdarg.h>

const char *memory_exhausted = "memory exhausted\n";

extern void usage(const char *usage)
{
	fprintf(stderr, "TinyLogin v%s (%s) multi-call binary -- GPL2\n\n",
			TLG_VER, TLG_BT);
	fprintf(stderr, "Usage: %s\n", usage);
	exit(EXIT_FAILURE);
}

static void verror_msg(const char *s, va_list p)
{
	fflush(stdout);
	fprintf(stderr, "%s: ", applet_name);
	vfprintf(stderr, s, p);
	fflush(stderr);
}

extern void error_msg(const char *s, ...)
{
	va_list p;

	va_start(p, s);
	verror_msg(s, p);
	va_end(p);
}

extern void error_msg_and_die(const char *s, ...)
{
	va_list p;

	va_start(p, s);
	verror_msg(s, p);
	va_end(p);
	exit(EXIT_FAILURE);
}

static void vperror_msg(const char *s, va_list p)
{
	fflush(stdout);
	fprintf(stderr, "%s: ", applet_name);
	if (s && *s) {
		vfprintf(stderr, s, p);
		fputs(": ", stderr);
	}
	fprintf(stderr, "%s\n", strerror(errno));
	fflush(stderr);
}

extern void perror_msg(const char *s, ...)
{
	va_list p;

	va_start(p, s);
	vperror_msg(s, p);
	va_end(p);
}

extern void perror_msg_and_die(const char *s, ...)
{
	va_list p;

	va_start(p, s);
	vperror_msg(s, p);
	va_end(p);
	exit(EXIT_FAILURE);
}


#if defined TLG_LOGIN || defined TLG_SULOGIN || defined TLG_PASSWD
extern char *pw_encrypt(const char *clear, const char *salt)
{
	static char cipher[128];
	char *cp;

#ifdef TLG_FEATURE_MD5_PASSWORDS
	if (strncmp(salt, "$1$", 3) == 0) {
		return md5_crypt(clear);
	}
#endif
#ifdef TLG_FEATURE_SHA1_PASSWORDS
	if (strncmp(salt, "$2$", 3) == 0) {
		return sha1_crypt(clear);
	}
#endif
	cp = (char *) crypt(clear, salt);
	/* if crypt (a nonstandard crypt) returns a string too large,
	   truncate it so we don't overrun buffers and hope there is
	   enough security in what's left */
	if (strlen(cp) > CRYPT_EP_SIZE) {
		cp[CRYPT_EP_SIZE + 1] = 0;
	}
	strcpy(cipher, cp);
	return cipher;
}
#endif

extern void *xmalloc(size_t size)
{
	void *ptr = malloc(size);

	if (!ptr)
		error_msg_and_die(memory_exhausted);
	return ptr;
}

extern char *xstrdup(const char *s)
{
	char *t;

	if (s == NULL)
		return NULL;

	t = strdup(s);

	if (t == NULL)
		error_msg_and_die(memory_exhausted);

	return t;
}



/* END CODE */
