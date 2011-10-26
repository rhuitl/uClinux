///
///	@file 	bldout.cpp
/// @brief 	Format build output
///
///	usage:  bldout [-c contIndent] [-i indent] [-w width] file ...
///
////////////////////////////////////////////////////////////////////////////////
//
//	Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
//	The latest version of this code is available at http://www.mbedthis.com
//
//	This software is open source; you can redistribute it and/or modify it 
//	under the terms of the GNU General Public License as published by the 
//	Free Software Foundation; either version 2 of the License, or (at your 
//	option) any later version.
//
//	This program is distributed WITHOUT ANY WARRANTY; without even the 
//	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
//	See the GNU General Public License for more details at:
//	http://www.mbedthis.com/downloads/gplLicense.html
//	
//	This General Public License does NOT permit incorporating this software 
//	into proprietary programs. If you are unable to comply with the GPL, a 
//	commercial license for this software and support services are available
//	from Mbedthis Software at http://www.mbedthis.com
//
////////////////////////////////// Includes ////////////////////////////////////

#include	<ctype.h>
#include	<stdlib.h>
#include	<stdio.h>
#include	<string.h>
#if !_WIN32
	#include	<unistd.h>
#endif
#include	"getopt.h"

////////////////////////////////// Defines /////////////////////////////////////

#define MAX_BUF				(4 * 4096)
#define DEFAULT_WIDTH		76					// Maximum column width
#define DEFAULT_INDENT		4					// Indent continuation lines
#define DEFAULT_CONT_INDENT	8					// Indent continuation lines

////////////////////////////////// Defines /////////////////////////////////////

static int contIndent;
static int indent;
static int width;

////////////////////////////// Forward Declarations ////////////////////////////

static void format(FILE *fp);

///////////////////////////////////// Code /////////////////////////////////////

int main(int argc, char *argv[])
{
	FILE	*fp;
	int		n, c, errflag;

	errflag = 0;
	contIndent = DEFAULT_CONT_INDENT;
	indent = DEFAULT_INDENT;
	width = DEFAULT_WIDTH;

	while ((c = getopt(argc, argv, "?c:i:w:")) != EOF) {
		switch(c) {
		case 'c':
			contIndent = atoi(optarg);
			break;

		case 'i':
			indent = atoi(optarg);
			break;

		case 'w':
			width = atoi(optarg);
			break;
	
		default:
			errflag++;
			break;
		}
	}
	if (errflag) {
		fprintf(stderr, 
			"%s: usage: [-c contIndent] [-i indent] [-w width] files....\n", 
			argv[0]);
		exit(2);
	}

	if (optind >= argc) {
		format(stdin);

	} else for (n = optind; n < argc; n++) {
		fp = fopen(argv[n], "r");
		if (fp == NULL) {
			fprintf(stderr, "Can't open %s\n", argv[n]);
			exit(3);
		}
		format(fp);
		fclose(fp);
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

static void format(FILE *fp)
{
	char	inBuf[MAX_BUF], outBuf[MAX_BUF];
	char	*start, *end, *cp;
	int		i, nbytes, col, len;

	len = 0;
	col = indent;
	memset(outBuf, ' ', sizeof(outBuf));

	while (! feof(fp)) {
		inBuf[MAX_BUF - 1] = '\0';
		if (fgets(inBuf, sizeof(inBuf) - 1, fp) == 0) {
			break;
		}
		len = strlen(inBuf);
		if (inBuf[len - 1] == '\n') {
			len--;
			inBuf[len] = '\0';
		}
		start = inBuf;
		end = &inBuf[len];

		while (start < end) {
			while (*start && isspace(*start)) {
				start++;
			}
			cp = start;
			while (*cp && ! isspace(*cp)) {
				cp++;
			}
			nbytes = (cp - start);
			if ((col + nbytes) > width) {
				printf("%s \\\n", outBuf);
				col = 0;
				for (i = 0; i < contIndent; i++) {
					outBuf[col++] = ' ';
				}

			} else {
				if (col > indent) {
					outBuf[col++] = ' ';
				}
			}
			memcpy(&outBuf[col], start, nbytes);
			col += nbytes;
			outBuf[col] = '\0';
			start += nbytes;
		}
	}
	if (col > 0) {
		printf("%s\n", outBuf);
	}
}

////////////////////////////////////////////////////////////////////////////////

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
