/*
 *  md5sum.c
 *  September 2008 David Wu <www.ArcturusNetworks.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 1, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include "md5.h"

FILE *infile = NULL;
#define BUFFERSIZE 65536
char buf[BUFFERSIZE];

int main (int argc, char *argv[])
{
	unsigned int       i;
	unsigned int       n = 0;
	struct MD5Context  md5c;
	unsigned char      digest[16];

	/* Open input and output files: ******************************/

	if(argc > 2){
		printf("Usage: %s file\n", argv[0]);
		return 1;
	}

	if (argc == 1)
		infile = stdin;
	else
		infile = fopen (argv[1], "r");

	if (infile == NULL) {
		fprintf (stderr, "FATAL: could not open %s\n", argv[1]);
		exit(1);
	}

	/* Initialize MD5 module: */
	MD5Init(&md5c);

	/* read and do MD5: */
	while (!feof(infile)) {
		n = fread (buf, 1, BUFFERSIZE, infile);
		MD5Update (&md5c, buf, n);
	}
	/* save MD5: */
	MD5Final (digest, &md5c);

	if (infile != stdin)
		fclose (infile);

        for (i = 0; i < 16; i++) { 
                        printf("%02x", digest[i]);
        }
	printf("\n");

	return (0);
}
