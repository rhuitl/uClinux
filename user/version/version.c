/* version.c: Identify version of kernel, and read RCS keywords
 *
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>,
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "compile.h"
#include "version.h"

#include <sys/utsname.h>

char result[4096];

int main(int argc, char *argv[]) {
	int i;
	struct utsname n;
	memset(&n, 0, sizeof(n));
	uname(&n);
	
	if (argc < 2) {

		printf("%s release %s, build %s\n", n.sysname, n.release, n.version);
		printf("%s release %s, build %s\n", TOOLCHAIN_NAME, TOOLCHAIN_RELEASE, TOOLCHAIN_VERSION);
		
		exit(0);
	}

	for (i=1; i<argc; i++) {
		FILE * f = fopen(argv[i], "r");
		int state = 0;
		int pos = 0;
		int c;
		
		if (!f) {
			fprintf(stderr, "Unable to read %s\n", argv[i]);
			continue;
		}
		printf("\n%s:\n", argv[i]);
		
		
		while ((c = fgetc(f)) != EOF) {

			result[pos++] = c;
			if (pos>=sizeof(result))
				pos = sizeof(result)-1;
			
			if (c == 0) {
				pos = 0;
				state = 0;
			}

			switch (state) {
			case 0:
				if (c == '$')
					state = 1;
				else
					pos=0;
				break;
				
			case 1:
				if (isdigit(c) || isalpha(c) || (c=='_')) {
					state = 2;
				} else {
					pos = 0;
					state = 0;
				}
				break;

			case 4:
				if (c == '$') {
					result[pos++] = 0;
					printf("\t%s\n", result);
					pos = 0;
					state = 0;
					break;
				}
				else {
					state = 3;
					/* fallthrough */
				}
			case 3:
				if (c == ' ')
					state = 4;
				break;
			
			case 2:
				if (c == ':')
					state = 3;
				else if (isdigit(c) || isalpha(c) || (c=='_')) {
					state = 2;
				} else {
					pos = 0;
					state = 0;
				}
				break;
			
			}
		
		}
		
	}

	return 0;
}

