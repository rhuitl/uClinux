/* vi: set sw=4 ts=4: */
/*
 * Copyright 1989 - 1992, Julianne Frances Haugh
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * NEWENVP_STEP must be a power of two.  This is the number
 * of (char *) pointers to allocate at a time, to avoid using
 * realloc() too often.
 */
#define NEWENVP_STEP 16

size_t newenvc = 0;
char **newenvp = NULL;

static char *const forbid[] = {
	"ENV=",
	"BASH_ENV=",				/* GNU creeping featurism strikes again... */
	"HOME=",
	"IFS=",
	"LD_",						/* anything with the LD_ prefix */
	"PATH=",
	"SHELL=",
	(char *) 0
};


/*
 * initenv() must be called once before using addenv().
 */
extern void initenv()
{
	newenvp = (char **) xmalloc(NEWENVP_STEP * sizeof(char *));

	*newenvp = NULL;
}


extern void addenv(const char *string, const char *value)
{
	char *cp, *newstring;
	size_t i;
	size_t n;

	if (value) {
		newstring = xmalloc(strlen(string) + strlen(value) + 2);
		sprintf(newstring, "%s=%s", string, value);
	} else {
		newstring = xstrdup(string);
	}

	/*
	 * Search for a '=' character within the string and if none is found
	 * just ignore the whole string.
	 */

	cp = strchr(newstring, '=');
	if (!cp) {
		free(newstring);
		return;
	}

	n = (size_t) (cp - newstring);

	for (i = 0; i < newenvc; i++) {
		if (strncmp(newstring, newenvp[i], n) == 0 &&
			(newenvp[i][n] == '=' || newenvp[i][n] == '\0'))
			break;
	}

	if (i < newenvc) {
		free(newenvp[i]);
		newenvp[i] = newstring;
		return;
	}

	newenvp[newenvc++] = newstring;

	/*
	 * Check whether newenvc is a multiple of NEWENVP_STEP.
	 * If so we have to resize the vector.
	 * the expression (newenvc & (NEWENVP_STEP - 1)) == 0
	 * is equal to    (newenvc %  NEWENVP_STEP) == 0
	 * as long as NEWENVP_STEP is a power of 2.
	 */

	if ((newenvc & (NEWENVP_STEP - 1)) == 0) {
		char **__newenvp;
		size_t newsize;

		/*
		 * If the resize operation succeds we can
		 * happily go on, else print a message.
		 */

		newsize = (newenvc + NEWENVP_STEP) * sizeof(char *);

		__newenvp = (char **) realloc(newenvp, newsize);

		if (__newenvp) {
			/*
			 * If this is our current environment, update
			 * environ so that it doesn't point to some
			 * free memory area (realloc() could move it).
			 */
			if (environ == newenvp)
				environ = __newenvp;
			newenvp = __newenvp;
		} else {
			fprintf(stderr, "Environment overflow\n");
			free(newenvp[--newenvc]);
		}
	}

	/*
	 * The last entry of newenvp must be NULL
	 */

	newenvp[newenvc] = NULL;
}


/*
 * set_env - copy command line arguments into the environment
 */
extern void set_env(int argc, char *const *argv)
{
	int noname = 1;
	char variable[1024];
	char *cp;

	for (; argc > 0; argc--, argv++) {
		if (strlen(*argv) >= sizeof variable)
			continue;			/* ignore long entries */

		if (!(cp = strchr(*argv, '='))) {
			snprintf(variable, sizeof variable, "L%d", noname++);
			addenv(variable, *argv);
		} else {
			char *const *p;

			for (p = forbid; *p; p++)
				if (strncmp(*argv, *p, strlen(*p)) == 0)
					break;

			if (*p) {
				strncpy(variable, *argv, cp - *argv);
				variable[cp - *argv] = '\0';
				printf("You may not change $%s\n", variable);
				continue;
			}

			addenv(*argv, NULL);
		}
	}
}
