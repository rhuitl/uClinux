/*
 * Main interpreter module that can handle one language: Algol 60
 *
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
 */

/*
 * main.c:						aug '90
 *
 * the main module for the Algol 60 interpreter.
 */

#include "comm.h"
#include "a60.h"
#include "version.h"
#include "eval.h"
#include "run.h"
#include "util.h"
#include "mkc.h"


/* be verbose: */
int verbose;

/* be verbose on check pass: */
int cverbose;

/* be verbose when creating/compiling c-code: */
int make_c_verbose;

/* xa60 is being used: sent output of stderr to stdout and disallow input: */
int run_with_xa60;

/* name of the input file: */
char *infname;

/* file to read from; (used by yylex ()): */
FILE *infile;

/* name of the outputfile (used for c-output): */
char *outfname;

/* name of the outputfile (used for redirecton of stdout): */
static char *termfname;

/* append the output to outfname: */
static int append_output;

/* warn about uncheckable conditions; runtime errors may occur. */
int rwarn;

/* verbose debug (if compiled with YYDEBUG enable parser debugging). */
int do_debug;

/* print debug info on memory allocation and release. */
int do_memdebug;

/* print the parse tree (only useful for debugging) : */
static int do_dump;

/* print trace information: */
int trace;

/* don't execute the fun: */
static int norun;

/* don't check the tree (inplicite norun): */
static int nocheck;

/*
 * look for strict (pedantic) rra60 conformace:
 * (skip whites in input, except in strings)
 */
int strict_a60;

/* and following strict_a60: scan in this manner: */
int scan_strict;

/* print a memory statistics summary: */
int do_memstat;

#ifndef EMBED
/* create c-output: */
int make_cout;

/* create c-output and compile: */
int make_bin;
#endif

/* root of the parse tree: */
TREE *rtree;

#ifdef ATARI
/*
 * the magic way to set the runtime stacksize (for use with gcc).
 */
long _stksize = 100000l;
#endif


/*
 * onk - what you're doing; give a hint and exit.
 */

static void
usage ()
{
	fprintf (stderr, "\nuse:  a60 [options] [file]\n");
	fprintf (stderr, "options are:\n");
	fprintf (stderr, "\t-V         print version and exit\n");
	fprintf (stderr, "\t-v         be verbose\n");
	fprintf (stderr, "\t-t         turn tracing on\n");
	fprintf (stderr, "\t-n         do not execute (parse and check only)\n");
	fprintf (stderr, "\t-i         do not check (parse only)\n");
	fprintf (stderr, "\t-Wr        warn about runtime decisions\n");
	fprintf (stderr, "\t-strict    follow strict a60 conventions\n");
#ifndef EMBED
	fprintf (stderr, "\t-c         create c output\n");
	fprintf (stderr, "\t-C         create and compile c output\n");
	fprintf (stderr, "\t-o <file>  output file; used with -c or -C\n");
#endif
	fprintf (stderr, "\t> <file>   send terminal output to <file>\n");
	fprintf (stderr, "\t>> <file>  append terminal output to <file>\n");
#ifdef unix
	fprintf (stderr, "\t-X         a60 is run from xa60\n");
#endif
#ifdef DEBUG
	fprintf (stderr, "\t-d         turn debug on\n");
	fprintf (stderr, "\t-d[admp]   turn selected debug on\n");
	fprintf (stderr, "\t-D         dump the parse tree\n");
#endif /* ! DEBUG */
#ifdef MEMORY_STATISTICS
	fprintf (stderr, "\t-m         print memory statistics\n");
#endif /* MEMORY_STATISTICS */

	exit (-1);
}


static void
usage_err (s)
char *s;
{
	fprintf (stderr, "commandline error: %s\n", s);
	usage ();
}


/*
 * print the header: version and copyright:
 */

static void
print_header ()
{
	fprintf (stderr, " %s\n", VERSION);
	fprintf (stderr,
 " Copyright (C) 1991,1992 Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)\n");
	fprintf (stderr,
 " The NASE A60 interpreter is free software.  See the file COPYING for\n");
	fprintf (stderr, " copying permission.\n");
}


/*
 * examine the string for verbose info;
 */

static void
select_verbose (s)
char *s;
{
	while (s && *s) {
		
		switch (*s) {
		case 'a':
			/* set all the flags: */
			verbose = 1;
			cverbose = 1;
			make_c_verbose = 1;
			break;
		case 'c':
			/* set check-pass verbositivity: */
			cverbose = 1;
			break;
		case 'C':
			/* set compilation verbositivity: */
			make_c_verbose = 1;
			break;
		case 'v':
			/* set common verbositivity: */
			verbose = 1;
			break;
		default:
			fprintf (stderr, "hint: verboseflag `%c' ignored.\n",
				 *s);
		}
		s++;
	}
}


#ifdef DEBUG
/*
 * examine the string for debug info;
 */

static void
select_debug (s)
char *s;
{
	while (s && *s) {

		switch (*s) {
		case 'a':
			/* set all the flags: */
			do_debug = 1;
			do_memdebug = 1;
			verbose = 1;
			trace = 1;
#ifdef PARSEDEBUG
			yydebug = 1;
#endif
			break;
		case 'd':
			do_debug = 1;
			break;
		case 'm':
			do_memdebug = 1;
			break;
		case 'p':
#ifndef PARSEDEBUG
			fprintf (stderr,
		"parser debugging not avail.\n");
#else
			yydebug = 1;
#endif
			break;
		default:
			if (verbose)
				fprintf (stderr, "debugflag `%c' ignored.\n",
					 *s);
		}
		s++;
	}
}
#endif /* DEBUG */


/*
 * parse all the arguments; initialize the flags.
 */

static void
parse_args(argc, argv)
int argc;
char *argv[];
{
	do_dump = verbose = 0;
	infname = (char *) 0;
	rwarn = trace = do_memstat = 0;
#ifndef EMBED
	make_cout = 0;
	make_bin = 0;
#endif
	nocheck = norun = 0;
	outfname = (char *) 0;
	termfname = (char *) 0;
	append_output = 0;
	make_c_verbose = 0;
	run_with_xa60 = 0;
	scan_strict = 0;
	strict_a60 = 0;

	do_debug = do_memdebug = 0;

	while(++argv, --argc > 0) {

		if((*argv)[0] == '-' && ! (*argv)[2]) {
			switch((*argv)[1]) {
#ifndef EMBED
			case 'o':
				if (argc < 2)
					usage_err ("incomplete option `-o'");
				++argv, --argc;
				outfname = *argv;
				break;
#endif
			case 'v':
				verbose = 1;
				print_header ();
				break;
			case 'V':
				print_header ();
				exit (0);
				/* never reached */
				break;
			case 'h':
				usage ();
				break;
			case 'D':
				do_dump = 1;
				break;
			case 'd':
#ifdef DEBUG
				do_debug = 1;
#else /* ! DEBUG */
				fprintf (stderr, "hint: debug not avail.\n");
#endif /* ! DEBUG */
				break;
			case 'm':
#ifdef MEMORY_STATISTICS
				do_memstat = 1;
#else /* ! MEMORY_STATISTICS */
				fprintf (stderr,
		"hint: memory statistics not avail.\n");
#endif /* ! MEMORY_STATISTICS */
				break;
			case 't':
				trace = 1;
				break;
			case 'n':
				norun = 1;
				break;
			case 'i':
				nocheck = norun = 1;
				break;
#ifndef EMBED
			case 'c':
				make_cout = 1;
				norun = 1;
				break;
			case 'C':
				make_cout = 1;
				norun = 1;
				make_bin = 1;
				break;
#endif
			case 'X':
#ifdef unix
				if (run_with_xa60)
					usage ();
				if (dup2 (fileno (stdout),
					  fileno (stderr)) < 0)
					xabort ("internal error: dup2");
				run_with_xa60 = 1;
#else /* ! unix */
				fprintf (stderr,
			"hint: -X option not avail.\n");
#endif /* ! unix */
				break;
			default:
				usage();
			}
		}
		else {
			if (! strcmp (*argv, "-Wr")) {
				rwarn = 1;
			}
			else if (! strncmp (*argv, ">>", 2)) {
				if (! argv[0][2] && argc < 2)
					usage_err ("incomplete option `>>'");
				append_output = 1;
				if (! argv[0][2]) {
					++argv, --argc;
					termfname = *argv;
				}
				else
					termfname = *argv+2;
			}
			else if (! strncmp (*argv, ">", 1)) {
				if (! argv[0][1] && argc < 2)
					usage_err ("incomplete option `>'");
				if (! argv[0][1]) {
					++argv, --argc;
					termfname = *argv;
				}
				else
					termfname = *argv+1;
			}
			else if (! strncmp (*argv, "-d", 2)) {
#ifdef DEBUG
				select_debug ((*argv)+2);
#else /* ! DEBUG */
				fprintf (stderr, "hint: debug not avail.\n");
#endif /* ! DEBUG */
			}
			else if (! strncmp (*argv, "-v", 2)) {
				select_verbose ((*argv)+2);
			}
			else if (! strcmp (*argv, "-strict")) {
				strict_a60 = 1;
				scan_strict = 1;
			}
			else {
				if (infname) {
					usage_err (
				"input file already specified");
				}
				infname = *argv;
			}
		}
	}

	if (! infname)
		infname = "-";
}


/*
 * print the number of errors found and exit.
 */

static void
nerror_exit (n)
int n;
{
	fprintf (stderr, "%d error%s found.\n", n, (n == 1) ? "" : "s");
	
	if (do_dump) {
		printf ("\n Tree dump:\n\n");
		print_tree (rtree);
	}

	if (verbose)
		fprintf (stderr, "bye.\n");
	
	exit (n);
}


/*
 * M A I N : 
 */

int
main(argc, argv)
int argc;
char *argv[];
{
#ifdef MEMORY_STATISTICS
	STACK_STAT_INIT;
#endif /* MEMORY_STATISTICS */

	if (verbose)
		fprintf (stderr, "Hi\n");

	parse_args (argc, argv);

	if (termfname) {
		/* redirect stdout to <termfname>: */
		char *filemode;
		if (append_output)
			filemode = "a";
		else
			filemode = "w";
		if (stdout != freopen (termfname, filemode, stdout)) {
			fprintf (stderr, 
				"cannot open `%s' for output - ignored.\n",
				termfname);
		}
	}

	/*
	 * now, let's examine the input medium:
	 */

	if (! strcmp (infname, "-")) {
		infname = "<stdin>";
		infile = stdin;
	}
	else
		infile = fopen (infname, "r");

	if (! infile) {
		int len = strlen (infname) + 10;	/* 4 or 5 - gna */
		char *tmp = NTALLOC(len, char);
		sprintf (tmp, "%s.a60", infname);
		infile = fopen (tmp, "r");
		if (! infile) {
			fprintf (stderr,
				 "cannot open file `%s' for reading.\n", 
				 infname);
			exit (-1);
		}
		else
			infname = tmp;
	}
	

	if (verbose) 
		fprintf (stderr, "reading from `%s'\n", infname);

	init_lex ();
	
	if (yyparse ()) {
		if (! nerrors)
			nerrors++;
	}

	if (nerrors) {
		nerror_exit (nerrors);
		/* never reached */
	}

	if ((nocheck || nerrors) && do_dump) {
		printf ("\n Parse-Tree dump:\n\n");
		print_tree (rtree);
	}

	if (nocheck)
		return say_goodbye (0);

	if (check_tree () != 0) {
		nerror_exit (cerrors);
		/* never reached */
	}

	if (verbose)
		fprintf (stderr, "no error found.\n");
	
	if (do_dump) {
		printf ("\n Tree dump:\n\n");
		print_tree (rtree);
	}
#ifndef EMBED
	if (make_cout) {
		make_c ();
		return say_goodbye (0);
	}
#endif

	if (! norun && rtree) {
		init_evalst ();
		interpret ();
	}

	return say_goodbye (0);
}

/* end of main.c */
