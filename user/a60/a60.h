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
 * a60.h:						aug '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 */

#ifndef A60_H_HOOK
#define A60_H_HOOK

#include "tree.h"

#ifdef __STDC__
# define P(x)  x
#else
# define P(x)  ()
#endif


/* struct for passing type and own flag. */
typedef struct own_and_type {
	ENUM type_tag type;
	int own;
} OWNTYPE;


/*
 * the waste of globals...
 */

extern FILE *infile;
extern char *infname;
extern char *outfname;
extern TREE *rtree;
extern int verbose;
extern int cverbose;
extern int strict_a60;		/* strict a60 usage */
extern int scan_strict;		/* scan in a strict manner */
extern int run_with_xa60;	/* force some actions for xa60 */
extern int rwarn;		/* warn about runtime decisions */
extern int trace;
extern int lineno;
extern int nerrors;		/* parse errors (first pass) */
extern int cerrors;		/* check errors (second pass) */
extern int yydebug;
extern int do_debug;		/* general debug flag */
extern int do_memdebug;		/* mem allocaton debug flag */
extern int do_memstat;
#ifndef EMBED
extern int make_bin;
#endif

extern int yylex ();
extern int yyparse();

/** extern int get_keyword P((char *)); **/

extern int check_tree P((void));
extern void check P((struct _tree *));

extern void yyerror P((char *s));
extern void yywarning P((char *s));
#ifndef VPRINTF_MISSING
extern void a60_error P((char *, int, char *, ...));
#else
extern void a60_error ();
#endif

#undef P

#endif /* A60_H_HOOK */
