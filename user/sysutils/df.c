/* df.c:
 *
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>
 * Copyright (C) 1999  D. Jeff Dionne     <jeff@lineo.ca>
 * Copyright (C) 2000  Lineo, Inc.  (www.lineo.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>

int
main(int argc, char * argv[])
{
	char * name;
	struct statfs stbuf;
	
	fclose(stdin);
	
	
	if (argc<2)
		name = "/";
	else
		name = argv[1];
	
	if (statfs(name, &stbuf) == -1) {
		printf("Unable to get disk space of %s: %s\n", name, strerror(errno));
		exit(1);
	}
	
	printf("Total bytes: %ld\n", stbuf.f_bsize * stbuf.f_blocks);
	printf("Free bytes: %ld\n", stbuf.f_bsize * stbuf.f_bfree);
	printf("Total nodes: %ld\n", stbuf.f_files);
	printf("Free nodes: %ld\n", stbuf.f_ffree);
	exit(0);
}

