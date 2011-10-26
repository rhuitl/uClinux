/* free.c:
 *
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>,
 * Copyright (C) 1999  D. Jeff Dionne     <jeff@lineo.ca>
 * Copyright (C) 2000  Lineo, Inc.  (www.lineo.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

char buf[256];

int
main(argc, argv)
	char	**argv;
{
	int i;
	FILE * f;
        	
	f = fopen("/proc/meminfo", "r");
	
	if (!f) {
		perror("Unable to open /proc/meminfo: ");
		exit(1);
	}
	
	for(i=0;i<3;i++) {
		fgets(buf, 250, f);
		fputs(buf, stdout);
	}
	
	fclose(f);
	exit(0);
}

