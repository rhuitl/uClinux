/*
 * Copyright (C) 1991,1992 Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 *
 * This file is part of NASE A60.
 * 
 * NASE A60 is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * NASE A60 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with NASE A60; see the file COPYING.  If not, write to the Free
 * Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * chenums.c:					oct '90
 * Erik Schoenfelder
 *
 * change enums to defines. (ugly hack)
 *
 * enum definition must be of this type (at the beginning of the line):
 *	 	enum foo_bar {
 * 			nase,
 * 			gna,
 * 			fred
 * 		};
 * will produce:
 * 		#define foo_bar int
 * 		#define nase 0
 * 		#define gna 1
 * 		#define fred 2
 * 
 * use:  chenums  <file> ...
 * 	 (and use carefully; save the originals and examine the changes)
 *
 * do not forget to compile the changed sources with something like:
 * 	-Denum=''
 */

#include <stdio.h>


/* magic for the enums start and end: */
#define ESTART		"enum "
#define EEND		"}"


#define TMPAPP	".TMP"
#define BLEN	4096

static char buf [BLEN];


static void
doit (in, out)
FILE *in, *out;
{
	char *ptr;
	int i;

	fprintf (stderr, "  onk - will change enums!\n");

	/* change header: */

	/* skip to enum name: */
	ptr = buf + strlen (ESTART);
	for (; *ptr == ' ' || *ptr == '\t'; ptr++)
		continue;

	fprintf (out, "#define ");
		
	/* scan enum name: */
	for (; *ptr != ' ' && *ptr != '\t' && *ptr != '\n' &&
	     *ptr != ','; ptr++)
		fputc (*ptr, out);
	
		fprintf (out, " int\n");

	/* change the enums itself: */

	for (i=0; fgets (buf, BLEN, in); i++) {

		if (! strncmp (EEND, buf, strlen (EEND)))
			break;

		/* skip white: */
		for (ptr=buf; *ptr == ' ' || *ptr == '\t'; ptr++)
			continue;

		fprintf (out, "#define ");
		
		/* scan enum definition: */
		for (; *ptr != ' ' && *ptr != '\t' && *ptr != '\n' &&
		     *ptr != ','; ptr++)
			fputc (*ptr, out);

		fprintf (out, " %d\n", i);
	}
	fprintf (stderr, "  onk - %d defines created.\n", i);
}


int
main (argc, argv)
int argc;
char *argv[];
{
	int i;
	char *infname;
	char *tfname[1024];

	FILE *in, *out;
	if (argc < 2) {
		fprintf (stderr, "use:  chenums  <file> ...\n");
		exit (-1);
	}

	for (i=1; i<argc; i++) {

		infname = argv[i];
		fprintf (stderr, "working for `%s':\n", infname);

		sprintf (tfname, "%s%s", infname, TMPAPP);

		/* copy: */

		fprintf (stderr, "  copying `%s' to `%s' ...\n",
			 infname, tfname);

		if (! (in = fopen (infname, "r"))) {
			fprintf (stderr, "cannot read from `%s'\n", infname);
			exit (-1);
		}

		if (! (out = fopen (tfname, "w"))) {
			fprintf (stderr, "cannot write to `%s'\n", tfname);
			exit (-1);
		}

		while (fgets (buf, BLEN, in))
			fputs (buf, out);

		fclose (in);
		fclose (out);

		/* copy back: */

		fprintf (stderr, "  scanning `%s' (output to `%s') ...\n",
			 tfname, infname);

		if (! (in = fopen (tfname, "r"))) {
			fprintf (stderr, "cannot read from `%s'\n", tfname);
			exit (-1);
		}

		if (! (out = fopen (infname, "w"))) {
			fprintf (stderr, "cannot write to `%s'\n", infname);
			exit (-1);
		}

		while (fgets (buf, BLEN, in)) {
			if (! strncmp (ESTART, buf, strlen (ESTART)))
				doit (in, out);
			else
				fputs (buf, out);
		}

		fclose (in);
		fclose (out);

		fprintf (stderr, "  `%s' done.\n", infname);
	}

	return 0;
}
