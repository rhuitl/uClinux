/* free.c:
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

#include <sys/stat.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>

void
do_free(argc, argv)
	char	**argv;
{
	int i;
	FILE * f;
	char buf[256];

	f = fopen("/proc/meminfo", "r");
	
	if (!f) {
		perror("Unable to open /proc/meminfo: ");
		return;
	}
	
	for(i=0;i<3;i++) {
		fgets(buf, 250, f);
		fputs(buf, stdout);
	}
	
	fclose(f);
}

