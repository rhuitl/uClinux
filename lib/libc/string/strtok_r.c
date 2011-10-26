/* Copyright (C) 1991 Free Software Foundation, Inc.
This file is part of the GNU C Library.

The GNU C Library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

The GNU C Library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

/*
 * Modified by Manuel Novoa III     Mar 1, 2001
 *
 * Converted original strtok.c code of strtok to __strtok_r.
 * Cleaned up logic and reduced code size.
 */

#include <string.h>

char *strtok_r(char *s, const char *delim, char **save_ptr)
{
	char *token;

	token = 0;					/* Initialize to no token. */

	if (s == 0) {				/* If not first time called... */
		s = *save_ptr;			/* restart from where we left off. */
	}
	
	if (s != 0) {				/* If not finished... */
		*save_ptr = 0;

		s += strspn(s, delim);	/* Skip past any leading delimiters. */
		if (*s != '\0') {		/* We have a token. */
			token = s;
			*save_ptr = strpbrk(token, delim); /* Find token's end. */
			if (*save_ptr != 0) {
				/* Terminate the token and make SAVE_PTR point past it.  */
				*(*save_ptr)++ = '\0';
			}
		}
	}

	return token;
}
