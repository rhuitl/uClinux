/*
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include "dirstream.h"

libc_hidden_proto(memcpy)
libc_hidden_proto(readdir)
libc_hidden_proto(opendir)
libc_hidden_proto(closedir)
libc_hidden_proto(qsort)

int scandir(const char *dir, struct dirent ***namelist, 
	int (*selector) (const struct dirent *),
	int (*compar) (const void *, const void *))
{
    DIR *dp = opendir (dir);
    struct dirent *current;
    struct dirent **names = NULL;
    size_t names_size = 0, pos;
    int save;

    if (dp == NULL)
	return -1;

    save = errno;
    __set_errno (0);

    pos = 0;
    while ((current = readdir (dp)) != NULL)
	if (selector == NULL || (*selector) (current))
	{
	    struct dirent *vnew;
	    size_t dsize;

	    /* Ignore errors from selector or readdir */
	    __set_errno (0);

	    if (unlikely(pos == names_size))
	    {
		struct dirent **new;
		if (names_size == 0)
		    names_size = 10;
		else
		    names_size *= 2;
		new = (struct dirent **) realloc (names, names_size * sizeof (struct dirent *));
		if (new == NULL)
		    break;
		names = new;
	    }

	    dsize = &current->d_name[_D_ALLOC_NAMLEN (current)] - (char *) current;
	    vnew = (struct dirent *) malloc (dsize);
	    if (vnew == NULL)
		break;

	    names[pos++] = (struct dirent *) memcpy (vnew, current, dsize);
	}

    if (unlikely(errno != 0))
    {
	save = errno;
	closedir (dp);
	while (pos > 0)
	    free (names[--pos]);
	free (names);
	__set_errno (save);
	return -1;
    }

    closedir (dp);
    __set_errno (save);

    /* Sort the list if we have a comparison function to sort with.  */
    if (compar != NULL)
	qsort (names, pos, sizeof (struct dirent *), compar);
    *namelist = names;
    return pos;
}
