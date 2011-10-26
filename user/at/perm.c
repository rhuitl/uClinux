/* 
 *  perm.c - check user permission for at(1)
 *  Copyright (C) 1994  Thomas Koenig
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* System Headers */

#include <sys/types.h>

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include <pwd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Local headers */

#include "privs.h"
#include "at.h"

/* Macros */

#define MAXUSERID 10

/* Structures and unions */


/* File scope variables */

static char rcsid[] = "$Id: perm.c,v 1.4 1997/03/12 19:36:06 ig25 Exp $";

/* Function declarations */

static int check_for_user(FILE * fp, const char *name);

/* Local functions */

static int 
check_for_user(FILE * fp, const char *name)
{
    char *buffer;
    size_t len;
    int found = 0;

    len = strlen(name);
    buffer = mymalloc(len + 2);

    while (fgets(buffer, len + 2, fp) != NULL) {
	if ((strncmp(name, buffer, len) == 0) &&
	    (buffer[len] == '\n')) {
	    found = 1;
	    break;
	}
    }
    fclose(fp);
    free(buffer);
    return found;
}
/* Global functions */
int 
check_permission()
{
    FILE *fp;
    uid_t uid = geteuid();
    struct passwd *pentry;

    if (uid == 0)
	return 1;

    if ((pentry = getpwuid(uid)) == NULL) {
	perror("Cannot access user database");
	exit(EXIT_FAILURE);
    }
    PRIV_START

	fp = fopen(ETCDIR "/at.allow", "r");

    PRIV_END

    if (fp != NULL) {
	return check_for_user(fp, pentry->pw_name);
    } else {

	PRIV_START

	    fp = fopen(ETCDIR "/at.deny", "r");

	PRIV_END

	if (fp != NULL) {
	    return !check_for_user(fp, pentry->pw_name);
	}
	perror("at.deny");
    }
    return 0;
}
