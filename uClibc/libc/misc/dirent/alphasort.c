/*
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <dirent.h>
#include <string.h>
#include "dirstream.h"

libc_hidden_proto(strcmp)

int alphasort(const void * a, const void * b)
{
    return strcmp ((*(const struct dirent **) a)->d_name,
	    (*(const struct dirent **) b)->d_name);
}

