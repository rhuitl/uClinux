/*
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <_lfs_64.h>

#include <dirent.h>
#include <string.h>
#include "dirstream.h"

libc_hidden_proto(strcmp)

int alphasort64(const void * a, const void * b)
{
    return strcmp ((*(const struct dirent64 **) a)->d_name,
	    (*(const struct dirent64 **) b)->d_name);
}
