/* df.c:
 *
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>,
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "sash.h"

#include <linux/autoconf.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/vfs.h>

#include <sys/stat.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <linux/major.h>
#ifdef __UC_LIBC__
#include <linux/types.h>
#endif
#include <sys/time.h>
#include <sys/param.h>
#include <errno.h>

void
do_df(int argc, char * argv[])
{
	char * name;
	struct statfs stbuf;

#if 0
	fclose(stdin);
#endif

	if (argc<2)
		name = "/";
	else
		name = argv[1];
	
	if (statfs(name, &stbuf) == -1) {
		printf("Unable to get disk space of %s: %s\n", name, strerror(errno));
		return;
	}
	
	printf("Total Kbytes: %ld\n", (stbuf.f_bsize / 256) * (stbuf.f_blocks / 4));
	printf("Free  Kbytes: %ld\n", (stbuf.f_bsize / 256) * (stbuf.f_bfree / 4));
	printf("Total  nodes: %ld\n", stbuf.f_files);
	printf("Free   nodes: %ld\n", stbuf.f_ffree);
}

