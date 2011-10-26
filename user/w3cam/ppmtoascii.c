/*
 * ppmtoascii
 *
 * Copyright (C) 1998 Rasca, Berlin
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

/* char map[] =
	"   ,,''`//--))(("
	"__..::;;<<>>ii++"
	"rrccuuoorrzzeebb"
	"qqddffqqqzzuuw$$"
	"mmm***###hhnnn%%"
	"nnmm=====[[[]]{}"
	"VVVVYYXXirrrrrrr"
	"xxxxyyyyggggffff"
	"HHHHHHHHHHHHHHHH"
	"IILLNNPPUUTTRRRR"
	"iirreeaabbtttttt"
	"ddffzzuuwwHHHHHH"
	"GGGGGGhhrrrrssuu"
	"PPOOOQQQEEEEFFFF"
	"***###VVVVYYZZZX"
	"OOOXXXMMMM@@@@@@"
; */

char map[] =
	"       `````````"
	"____----....++++"
	"rrccuuoorrzzeebb"
	"qqddffqqqzzuuw$$"
	"mmmaaaaaahhnnn%%"
	"nnmm=====[[[]]{}"
	"VVVVYYXXirrrrrrr"
	"xxxxyyyyggggffff"
	"HHHHHHHHHHHHHHHH"
	"IILLNNPPUUTTRRRR"
	"iirreeaabbtttttt"
	"ddffzzuuwwHHHHHH"
	"GGGGGGhhrrrrssuu"
	"PPOOOQQQEEEEFFFF"
	"***###VVVVYYZZZX"
	"OOOXXXMMMM@@@@@@"
;

int
main (int argc, char *argv[])
{
#define BUFFSIZE 1024
	int c, i, val;
	FILE *fp;
	char buff[BUFFSIZE];
	int verbose = 0;
	int width = 0, height =0;
	int maxval = 0;
	unsigned char *image;

	while ((c = getopt (argc, argv, "v")) != EOF) {
		switch (c) {
			case 'v':
				verbose++;
				break;
			default:
				break;
		}
	}
	if (argc == optind) {
		fp = stdin;
	} else {
		fp = fopen (argv[argc-1], "rb");
		if (!fp)
			return (1);
	}
	fgets (buff, BUFFSIZE, fp);
	if (strncmp (buff, "P6", 2) != 0) {
		fprintf (stderr, "input is not a raw ppm file\n");
		return (2);
	}
	fgets (buff, BUFFSIZE, fp);
	sscanf (buff, "%d %d", &width, &height);
	fgets (buff, BUFFSIZE, fp);
	sscanf (buff, "%d", &maxval);
	if (width == 0 ||
		height ==0 ||
		maxval ==0) {
		fprintf (stderr, "input is not a raw ppm file\n");
		return (3);
	}
	if (verbose)
		fprintf (stderr, "width=%d height=%d maxval=%d\n", width,height,maxval);
	image = malloc (width * height);
	if (!image) {
		perror (argv[0]);
		return (4);
	}
	for (i = 0; i < width * height; i++) {
		fread (buff, 1, 3, fp);
		val = buff[0] + buff[1] + buff[2];
		image[i] = ~((unsigned char )(val / 3));
	}
	for (i = 0; i < height; i++) {
		int w;
		for (w = 0; w < width; w++) {
			printf ("%c", (unsigned char) map[(unsigned char )(image[(i*width)+w])]);
		}
		printf ("\n");
	}
	return (0);
}

