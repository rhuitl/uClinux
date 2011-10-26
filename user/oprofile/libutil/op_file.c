/**
 * @file op_file.c
 * Useful file management helpers
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author John Levon
 * @author Philippe Elie
 */

#include <sys/stat.h>
#include <unistd.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

#include "op_file.h"
#include "op_libiberty.h"

int op_file_readable(char const * file)
{
	struct stat st;
	return !stat(file, &st) && S_ISREG(st.st_mode) && !access(file, R_OK);
}


time_t op_get_mtime(char const * file)
{
	struct stat st;

	if (stat(file, &st))
		return 0;

	return st.st_mtime;
}


int create_dir(char const * dir)
{
	if (mkdir(dir, 0755)) {
		/* FIXME: Does not verify existing is a dir */
		if (errno == EEXIST)
			return 0;
		return errno;
	}

	return 0;
}


int create_path(char const * path)
{
	int ret = 0;

	char * str = xstrdup(path);

	char * pos = str[0] == '/' ? str + 1 : str;

	for ( ; (pos = strchr(pos, '/')) != NULL; ++pos) {
		*pos = '\0';
		ret = create_dir(str);
		*pos = '/';
		if (ret)
			break;
	}

	free(str);
	return ret;
}
