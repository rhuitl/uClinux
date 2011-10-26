
/*  A Bison parser, made from ql_y.y
    by GNU Bison version 1.28  */

#define YYBISON 1  /* Identify Bison output.  */

#define	TOK_BREAK	257
#define	TOK_CASE	258
#define	TOK_DEF	259
#define	TOK_DEFAULT	260
#define	TOK_LENGTH	261
#define	TOK_MULTI	262
#define	TOK_RECOVER	263
#define	TOK_ABORT	264
#define	TOK_ID	265
#define	TOK_INCLUDE	266
#define	TOK_STRING	267

#line 1 "ql_y.y"

/* ql.y - Q.2931 data structures description language */

/* Written 1995-1997 by Werner Almesberger, EPFL-LRC */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

#include "common.h"
#include "qgen.h"
#include "file.h"


#define MAX_TOKEN 256
#define DEFAULT_NAMELIST_FILE "default.nl"


FIELD *def = NULL;
static STRUCTURE *structures = NULL;
static const char *abort_id; /* indicates abort flag */


static NAME_LIST *get_name_list(const char *name)
{
    static NAME_LIST *name_lists = NULL;
    FILE *file;
    NAME_LIST *list;
    NAME *last,*this;
    char line[MAX_TOKEN+1];
    char path[PATH_MAX+1];
    char *start,*here,*walk;
    int searching,found;

    for (list = name_lists; list; list = list->next)
	if (list->list_name == name) return list;
    sprintf(path,"%s.nl",name);
    if (!(file = fopen(path,"r")) && !(file = fopen(strcpy(path,
      DEFAULT_NAMELIST_FILE),"r"))) yyerror("can't open list file");
    list = alloc_t(NAME_LIST);
    list->list_name = name;
    list->list = last = NULL;
    list->id = -1;
    list->next = name_lists;
    name_lists = list;
    searching = 1;
    found = 0;
    while (fgets(line,MAX_TOKEN,file)) {
	for (start = line; *start && isspace(*start); start++);
	if (!*start || *start == '#') continue;
	if ((here = strchr(start,'\n'))) *here = 0;
	for (walk = strchr(start,0)-1; walk > start && isspace(*walk); walk--)
	    *walk = 0;
	if (*start == ':') {
	    if (!(searching = strcmp(start+1,name)))
		if (found) yyerror("multiple entries");
		else found = 1;
	    continue;
	}
	if (searching) continue;
	if (!(here = strchr(start,'='))) yyerror("invalid name list");
	*here++ = 0;
	for (walk = here-2; walk > start && isspace(*walk); walk--)
	    *walk = 0;
	while (*here && isspace(*here)) here++;
	this = alloc_t(NAME);
	this->value = stralloc(start);
	this->name = stralloc(here);
	this->next = NULL;
	if (last) last->next = this;
	else list->list = this;
	last = this;
    }
    (void) fclose(file);
    if (!found) yyerror("no symbol list entry found");
    return list;
}


static FIELD *copy_block(FIELD *orig_field)
{
    FIELD *copy,**new_field;

    copy = NULL;
    new_field = &copy;
    while (orig_field) {
	*new_field = alloc_t(FIELD);
	**new_field = *orig_field;
	if (orig_field->value) {
	    (*new_field)->value = alloc_t(VALUE);
	    *(*new_field)->value = *orig_field->value;
	    switch (orig_field->value->type) {
		case vt_length:
		    (*new_field)->value->block =
		      copy_block(orig_field->value->block);
		    break;
		case vt_case:
		case vt_multi:
		    {
			TAG *orig_tag,**new_tag;

			new_tag = &(*new_field)->value->tags;
			for (orig_tag = orig_field->value->tags; orig_tag;
			  orig_tag = orig_tag->next) {
			    VALUE_LIST *orig_value,**new_value;

			    *new_tag = alloc_t(TAG);
			    **new_tag = *orig_tag;
			    new_value = &(*new_tag)->more;
			    for (orig_value = orig_tag->more; orig_value;
			      orig_value = orig_value->next) {
				*new_value = alloc_t(VALUE_LIST);
				**new_value = *orig_value;
				new_value = &(*new_value)->next;
			    }
			    (*new_tag)->block = copy_block(orig_tag->block);
			    new_tag = &(*new_tag)->next;
			}
		    }
	    }
	}
	if (orig_field->structure)
	    yyerror("sorry, can't handle nested structures");
	new_field = &(*new_field)->next;
	orig_field = orig_field->next;
    }
    return copy;
}



#line 139 "ql_y.y"
typedef union {
    const char *str;
    int num;
    FIELD *field;
    VALUE *value;
    VALUE_LIST *list;
    TAG *tag;
    NAME_LIST *nlist;
} YYSTYPE;
#include <stdio.h>

#ifndef __cplusplus
#ifndef __STDC__
#define const
#endif
#endif



#define	YYFINAL		86
#define	YYFLAG		-32768
#define	YYNTBASE	23

#define YYTRANSLATE(x) ((unsigned)(x) <= 267 ? yytranslate[x] : 47)

static const char yytranslate[] = {     0,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,    21,    18,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,    22,     2,    17,
    14,    19,     2,    20,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,    15,     2,    16,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     1,     3,     4,     5,     6,
     7,     8,     9,    10,    11,    12,    13
};

#if YYDEBUG != 0
static const short yyprhs[] = {     0,
     0,     4,     5,     8,     9,    12,    17,    18,    21,    23,
    27,    30,    31,    34,    40,    41,    43,    47,    53,    54,
    57,    59,    60,    63,    64,    67,    69,    74,    79,    83,
    84,    87,    88,    90,    91,    97,    98,   105,   106,   112,
   113,   120,   121,   124,   125
};

static const short yyrhs[] = {    24,
    25,    29,     0,     0,    12,    24,     0,     0,    25,    26,
     0,     5,    11,    14,    29,     0,     0,    28,    29,     0,
    11,     0,    15,    30,    16,     0,    10,    11,     0,     0,
    31,    30,     0,    32,    11,    40,    17,    33,     0,     0,
     3,     0,    18,    35,    19,     0,    35,    34,    36,    19,
    37,     0,     0,    20,    35,     0,    11,     0,     0,    21,
    11,     0,     0,    14,    38,     0,    11,     0,     4,    15,
    41,    16,     0,     8,    15,    43,    16,     0,    39,     7,
    29,     0,     0,     9,    11,     0,     0,    13,     0,     0,
     6,    11,    45,    46,    29,     0,     0,    11,    45,    46,
    29,    42,    41,     0,     0,     6,    11,    45,    46,    27,
     0,     0,    11,    45,    46,    27,    44,    43,     0,     0,
    22,    11,     0,     0,    21,    11,    46,     0
};

#endif

#if YYDEBUG != 0
static const short yyrline[] = { 0,
   163,   175,   176,   184,   185,   188,   202,   207,   212,   231,
   236,   243,   247,   254,   278,   282,   288,   301,   318,   322,
   329,   339,   343,   350,   354,   360,   367,   374,   380,   390,
   394,   400,   404,   410,   414,   431,   437,   454,   458,   474,
   480,   497,   501,   507,   511
};
#endif


#if YYDEBUG != 0 || defined (YYERROR_VERBOSE)

static const char * const yytname[] = {   "$","error","$undefined.","TOK_BREAK",
"TOK_CASE","TOK_DEF","TOK_DEFAULT","TOK_LENGTH","TOK_MULTI","TOK_RECOVER","TOK_ABORT",
"TOK_ID","TOK_INCLUDE","TOK_STRING","'='","'{'","'}'","'<'","'-'","'>'","'@'",
"','","':'","all","includes","structures","structure","rep_block","@1","block",
"fields","field","opt_break","field_cont","opt_pos","decimal","opt_more","opt_val",
"value","opt_recover","opt_name_list","tags","@2","rep_tags","@3","opt_id","list", NULL
};
#endif

static const short yyr1[] = {     0,
    23,    24,    24,    25,    25,    26,    28,    27,    29,    29,
    29,    30,    30,    31,    32,    32,    33,    33,    34,    34,
    35,    36,    36,    37,    37,    38,    38,    38,    38,    39,
    39,    40,    40,    41,    41,    42,    41,    43,    43,    44,
    43,    45,    45,    46,    46
};

static const short yyr2[] = {     0,
     3,     0,     2,     0,     2,     4,     0,     2,     1,     3,
     2,     0,     2,     5,     0,     1,     3,     5,     0,     2,
     1,     0,     2,     0,     2,     1,     4,     4,     3,     0,
     2,     0,     1,     0,     5,     0,     6,     0,     5,     0,
     6,     0,     2,     0,     3
};

static const short yydefact[] = {     2,
     2,     4,     3,     0,     0,     0,     9,    12,     5,     1,
     0,    11,    16,     0,    12,     0,     0,    10,    13,    32,
     6,    33,     0,     0,    21,     0,    14,    19,     0,     0,
    22,    17,    20,     0,     0,    23,    24,    30,    18,     0,
     0,     0,    26,    25,     0,    34,    38,    31,     0,     0,
    42,     0,     0,    42,     0,    29,    42,     0,    44,    27,
    42,    44,    28,    44,    43,     0,     0,    44,     7,     0,
    44,    36,     7,    40,     0,    35,    45,    34,    39,    38,
     8,    37,    41,     0,     0,     0
};

static const short yydefgoto[] = {    84,
     2,     4,     9,    74,    75,    10,    14,    15,    16,    27,
    31,    28,    35,    39,    44,    45,    23,    52,    78,    55,
    80,    59,    67
};

static const short yypact[] = {    -8,
    -8,-32768,-32768,    -4,     3,    17,-32768,    -1,-32768,-32768,
    20,-32768,-32768,    21,    -1,    22,    11,-32768,-32768,    23,
-32768,-32768,    24,    -3,-32768,    27,-32768,    15,    25,    27,
    26,-32768,-32768,    28,    29,-32768,    31,     9,-32768,    34,
    36,    32,-32768,-32768,    33,    18,    19,-32768,    11,    35,
    30,    38,    44,    30,    40,-32768,    30,    46,    39,-32768,
    30,    39,-32768,    39,-32768,    48,    11,    39,-32768,    11,
    39,-32768,-32768,-32768,    11,-32768,-32768,    18,-32768,    19,
-32768,-32768,-32768,    42,    61,-32768
};

static const short yypgoto[] = {-32768,
    62,-32768,-32768,   -11,-32768,   -17,    49,-32768,-32768,-32768,
-32768,     1,-32768,-32768,-32768,-32768,-32768,   -13,-32768,   -14,
-32768,   -38,   -59
};


#define	YYLAST		66


static const short yytable[] = {    21,
     5,    13,    69,     1,    70,     6,     7,    25,    73,   -15,
     8,    77,    40,    11,    26,    62,    41,    42,    64,    43,
     6,     7,    68,    50,    53,     8,    29,    12,    51,    54,
    33,    56,    20,    17,    30,    22,    18,    25,    36,    49,
    24,    85,    48,    32,    38,    57,    34,    37,    46,    72,
    47,    58,    76,    60,    61,    63,    65,    81,    71,    66,
    86,    79,     3,    19,    82,    83
};

static const short yycheck[] = {    17,
     5,     3,    62,    12,    64,    10,    11,    11,    68,    11,
    15,    71,     4,    11,    18,    54,     8,     9,    57,    11,
    10,    11,    61,     6,     6,    15,    26,    11,    11,    11,
    30,    49,    11,    14,    20,    13,    16,    11,    11,     7,
    17,     0,    11,    19,    14,    11,    21,    19,    15,    67,
    15,    22,    70,    16,    11,    16,    11,    75,    11,    21,
     0,    73,     1,    15,    78,    80
};
/* -*-C-*-  Note some compilers choke on comments on `#line' lines.  */
#line 3 "/usr/lib/bison.simple"
/* This file comes from bison-1.28.  */

/* Skeleton output parser for bison,
   Copyright (C) 1984, 1989, 1990 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* This is the parser code that is written into each bison parser
  when the %semantic_parser declaration is not specified in the grammar.
  It was written by Richard Stallman by simplifying the hairy parser
  used when %semantic_parser is specified.  */

#ifndef YYSTACK_USE_ALLOCA
#ifdef alloca
#define YYSTACK_USE_ALLOCA
#else /* alloca not defined */
#ifdef __GNUC__
#define YYSTACK_USE_ALLOCA
#define alloca __builtin_alloca
#else /* not GNU C.  */
#if (!defined (__STDC__) && defined (sparc)) || defined (__sparc__) || defined (__sparc) || defined (__sgi) || (defined (__sun) && defined (__i386))
#define YYSTACK_USE_ALLOCA
#include <alloca.h>
#else /* not sparc */
/* We think this test detects Watcom and Microsoft C.  */
/* This used to test MSDOS, but that is a bad idea
   since that symbol is in the user namespace.  */
#if (defined (_MSDOS) || defined (_MSDOS_)) && !defined (__TURBOC__)
#if 0 /* No need for malloc.h, which pollutes the namespace;
	 instead, just don't use alloca.  */
#include <malloc.h>
#endif
#else /* not MSDOS, or __TURBOC__ */
#if defined(_AIX)
/* I don't know what this was needed for, but it pollutes the namespace.
   So I turned it off.   rms, 2 May 1997.  */
/* #include <malloc.h>  */
 #pragma alloca
#define YYSTACK_USE_ALLOCA
#else /* not MSDOS, or __TURBOC__, or _AIX */
#if 0
#ifdef __hpux /* haible@ilog.fr says this works for HPUX 9.05 and up,
		 and on HPUX 10.  Eventually we can turn this on.  */
#define YYSTACK_USE_ALLOCA
#define alloca __builtin_alloca
#endif /* __hpux */
#endif
#endif /* not _AIX */
#endif /* not MSDOS, or __TURBOC__ */
#endif /* not sparc */
#endif /* not GNU C */
#endif /* alloca not defined */
#endif /* YYSTACK_USE_ALLOCA not defined */

#ifdef YYSTACK_USE_ALLOCA
#define YYSTACK_ALLOC alloca
#else
#define YYSTACK_ALLOC malloc
#endif

/* Note: there must be only one dollar sign in this file.
   It is replaced by the list of actions, each action
   as one case of the switch.  */

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		-2
#define YYEOF		0
#define YYACCEPT	goto yyacceptlab
#define YYABORT 	goto yyabortlab
#define YYERROR		goto yyerrlab1
/* Like YYERROR except do call yyerror.
   This remains here temporarily to ease the
   transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */
#define YYFAIL		goto yyerrlab
#define YYRECOVERING()  (!!yyerrstatus)
#define YYBACKUP(token, value) \
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    { yychar = (token), yylval = (value);			\
      yychar1 = YYTRANSLATE (yychar);				\
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    { yyerror ("syntax error: cannot back up"); YYERROR; }	\
while (0)

#define YYTERROR	1
#define YYERRCODE	256

#ifndef YYPURE
#define YYLEX		yylex()
#endif

#ifdef YYPURE
#ifdef YYLSP_NEEDED
#ifdef YYLEX_PARAM
#define YYLEX		yylex(&yylval, &yylloc, YYLEX_PARAM)
#else
#define YYLEX		yylex(&yylval, &yylloc)
#endif
#else /* not YYLSP_NEEDED */
#ifdef YYLEX_PARAM
#define YYLEX		yylex(&yylval, YYLEX_PARAM)
#else
#define YYLEX		yylex(&yylval)
#endif
#endif /* not YYLSP_NEEDED */
#endif

/* If nonreentrant, generate the variables here */

#ifndef YYPURE

int	yychar;			/*  the lookahead symbol		*/
YYSTYPE	yylval;			/*  the semantic value of the		*/
				/*  lookahead symbol			*/

#ifdef YYLSP_NEEDED
YYLTYPE yylloc;			/*  location data for the lookahead	*/
				/*  symbol				*/
#endif

int yynerrs;			/*  number of parse errors so far       */
#endif  /* not YYPURE */

#if YYDEBUG != 0
int yydebug;			/*  nonzero means print parse trace	*/
/* Since this is uninitialized, it does not stop multiple parsers
   from coexisting.  */
#endif

/*  YYINITDEPTH indicates the initial size of the parser's stacks	*/

#ifndef	YYINITDEPTH
#define YYINITDEPTH 200
#endif

/*  YYMAXDEPTH is the maximum size the stacks can grow to
    (effective only if the built-in stack extension method is used).  */

#if YYMAXDEPTH == 0
#undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
#define YYMAXDEPTH 10000
#endif

/* Define __yy_memcpy.  Note that the size argument
   should be passed with type unsigned int, because that is what the non-GCC
   definitions require.  With GCC, __builtin_memcpy takes an arg
   of type size_t, but it can handle unsigned int.  */

#if __GNUC__ > 1		/* GNU C and GNU C++ define this.  */
#define __yy_memcpy(TO,FROM,COUNT)	__builtin_memcpy(TO,FROM,COUNT)
#else				/* not GNU C or C++ */
#ifndef __cplusplus

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
__yy_memcpy (to, from, count)
     char *to;
     char *from;
     unsigned int count;
{
  register char *f = from;
  register char *t = to;
  register int i = count;

  while (i-- > 0)
    *t++ = *f++;
}

#else /* __cplusplus */

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
__yy_memcpy (char *to, char *from, unsigned int count)
{
  register char *t = to;
  register char *f = from;
  register int i = count;

  while (i-- > 0)
    *t++ = *f++;
}

#endif
#endif

#line 217 "/usr/lib/bison.simple"

/* The user can define YYPARSE_PARAM as the name of an argument to be passed
   into yyparse.  The argument should have type void *.
   It should actually point to an object.
   Grammar actions can access the variable by casting it
   to the proper pointer type.  */

#ifdef YYPARSE_PARAM
#ifdef __cplusplus
#define YYPARSE_PARAM_ARG void *YYPARSE_PARAM
#define YYPARSE_PARAM_DECL
#else /* not __cplusplus */
#define YYPARSE_PARAM_ARG YYPARSE_PARAM
#define YYPARSE_PARAM_DECL void *YYPARSE_PARAM;
#endif /* not __cplusplus */
#else /* not YYPARSE_PARAM */
#define YYPARSE_PARAM_ARG
#define YYPARSE_PARAM_DECL
#endif /* not YYPARSE_PARAM */

/* Prevent warning if -Wstrict-prototypes.  */
#ifdef __GNUC__
#ifdef YYPARSE_PARAM
int yyparse (void *);
#else
int yyparse (void);
#endif
#endif

int
yyparse(YYPARSE_PARAM_ARG)
     YYPARSE_PARAM_DECL
{
  register int yystate;
  register int yyn;
  register short *yyssp;
  register YYSTYPE *yyvsp;
  int yyerrstatus;	/*  number of tokens to shift before error messages enabled */
  int yychar1 = 0;		/*  lookahead token as an internal (translated) token number */

  short	yyssa[YYINITDEPTH];	/*  the state stack			*/
  YYSTYPE yyvsa[YYINITDEPTH];	/*  the semantic value stack		*/

  short *yyss = yyssa;		/*  refer to the stacks thru separate pointers */
  YYSTYPE *yyvs = yyvsa;	/*  to allow yyoverflow to reallocate them elsewhere */

#ifdef YYLSP_NEEDED
  YYLTYPE yylsa[YYINITDEPTH];	/*  the location stack			*/
  YYLTYPE *yyls = yylsa;
  YYLTYPE *yylsp;

#define YYPOPSTACK   (yyvsp--, yyssp--, yylsp--)
#else
#define YYPOPSTACK   (yyvsp--, yyssp--)
#endif

  int yystacksize = YYINITDEPTH;
  int yyfree_stacks = 0;

#ifdef YYPURE
  int yychar;
  YYSTYPE yylval;
  int yynerrs;
#ifdef YYLSP_NEEDED
  YYLTYPE yylloc;
#endif
#endif

  YYSTYPE yyval;		/*  the variable used to return		*/
				/*  semantic values from the action	*/
				/*  routines				*/

  int yylen;

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Starting parse\n");
#endif

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss - 1;
  yyvsp = yyvs;
#ifdef YYLSP_NEEDED
  yylsp = yyls;
#endif

/* Push a new state, which is found in  yystate  .  */
/* In all cases, when you get here, the value and location stacks
   have just been pushed. so pushing a state here evens the stacks.  */
yynewstate:

  *++yyssp = yystate;

  if (yyssp >= yyss + yystacksize - 1)
    {
      /* Give user a chance to reallocate the stack */
      /* Use copies of these so that the &'s don't force the real ones into memory. */
      YYSTYPE *yyvs1 = yyvs;
      short *yyss1 = yyss;
#ifdef YYLSP_NEEDED
      YYLTYPE *yyls1 = yyls;
#endif

      /* Get the current used size of the three stacks, in elements.  */
      int size = yyssp - yyss + 1;

#ifdef yyoverflow
      /* Each stack pointer address is followed by the size of
	 the data in use in that stack, in bytes.  */
#ifdef YYLSP_NEEDED
      /* This used to be a conditional around just the two extra args,
	 but that might be undefined if yyoverflow is a macro.  */
      yyoverflow("parser stack overflow",
		 &yyss1, size * sizeof (*yyssp),
		 &yyvs1, size * sizeof (*yyvsp),
		 &yyls1, size * sizeof (*yylsp),
		 &yystacksize);
#else
      yyoverflow("parser stack overflow",
		 &yyss1, size * sizeof (*yyssp),
		 &yyvs1, size * sizeof (*yyvsp),
		 &yystacksize);
#endif

      yyss = yyss1; yyvs = yyvs1;
#ifdef YYLSP_NEEDED
      yyls = yyls1;
#endif
#else /* no yyoverflow */
      /* Extend the stack our own way.  */
      if (yystacksize >= YYMAXDEPTH)
	{
	  yyerror("parser stack overflow");
	  if (yyfree_stacks)
	    {
	      free (yyss);
	      free (yyvs);
#ifdef YYLSP_NEEDED
	      free (yyls);
#endif
	    }
	  return 2;
	}
      yystacksize *= 2;
      if (yystacksize > YYMAXDEPTH)
	yystacksize = YYMAXDEPTH;
#ifndef YYSTACK_USE_ALLOCA
      yyfree_stacks = 1;
#endif
      yyss = (short *) YYSTACK_ALLOC (yystacksize * sizeof (*yyssp));
      __yy_memcpy ((char *)yyss, (char *)yyss1,
		   size * (unsigned int) sizeof (*yyssp));
      yyvs = (YYSTYPE *) YYSTACK_ALLOC (yystacksize * sizeof (*yyvsp));
      __yy_memcpy ((char *)yyvs, (char *)yyvs1,
		   size * (unsigned int) sizeof (*yyvsp));
#ifdef YYLSP_NEEDED
      yyls = (YYLTYPE *) YYSTACK_ALLOC (yystacksize * sizeof (*yylsp));
      __yy_memcpy ((char *)yyls, (char *)yyls1,
		   size * (unsigned int) sizeof (*yylsp));
#endif
#endif /* no yyoverflow */

      yyssp = yyss + size - 1;
      yyvsp = yyvs + size - 1;
#ifdef YYLSP_NEEDED
      yylsp = yyls + size - 1;
#endif

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Stack size increased to %d\n", yystacksize);
#endif

      if (yyssp >= yyss + yystacksize - 1)
	YYABORT;
    }

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Entering state %d\n", yystate);
#endif

  goto yybackup;
 yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* yyresume: */

  /* First try to decide what to do without reference to lookahead token.  */

  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* yychar is either YYEMPTY or YYEOF
     or a valid token in external form.  */

  if (yychar == YYEMPTY)
    {
#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Reading a token: ");
#endif
      yychar = YYLEX;
    }

  /* Convert token to internal form (in yychar1) for indexing tables with */

  if (yychar <= 0)		/* This means end of input. */
    {
      yychar1 = 0;
      yychar = YYEOF;		/* Don't call YYLEX any more */

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Now at end of input.\n");
#endif
    }
  else
    {
      yychar1 = YYTRANSLATE(yychar);

#if YYDEBUG != 0
      if (yydebug)
	{
	  fprintf (stderr, "Next token is %d (%s", yychar, yytname[yychar1]);
	  /* Give the individual parser a way to print the precise meaning
	     of a token, for further debugging info.  */
#ifdef YYPRINT
	  YYPRINT (stderr, yychar, yylval);
#endif
	  fprintf (stderr, ")\n");
	}
#endif
    }

  yyn += yychar1;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != yychar1)
    goto yydefault;

  yyn = yytable[yyn];

  /* yyn is what to do for this token type in this state.
     Negative => reduce, -yyn is rule number.
     Positive => shift, yyn is new state.
       New state is final state => don't bother to shift,
       just return success.
     0, or most negative number => error.  */

  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrlab;

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Shift the lookahead token.  */

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Shifting token %d (%s), ", yychar, yytname[yychar1]);
#endif

  /* Discard the token being shifted unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  *++yyvsp = yylval;
#ifdef YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  /* count tokens shifted since error; after three, turn off error status.  */
  if (yyerrstatus) yyerrstatus--;

  yystate = yyn;
  goto yynewstate;

/* Do the default action for the current state.  */
yydefault:

  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;

/* Do a reduction.  yyn is the number of a rule to reduce with.  */
yyreduce:
  yylen = yyr2[yyn];
  if (yylen > 0)
    yyval = yyvsp[1-yylen]; /* implement default value of the action */

#if YYDEBUG != 0
  if (yydebug)
    {
      int i;

      fprintf (stderr, "Reducing via rule %d (line %d), ",
	       yyn, yyrline[yyn]);

      /* Print the symbols being reduced, and their result.  */
      for (i = yyprhs[yyn]; yyrhs[i] > 0; i++)
	fprintf (stderr, "%s ", yytname[yyrhs[i]]);
      fprintf (stderr, " -> %s\n", yytname[yyr1[yyn]]);
    }
#endif


  switch (yyn) {

case 1:
#line 165 "ql_y.y"
{
	    STRUCTURE *walk;

	    def = yyvsp[0].field;
	    for (walk = structures; walk; walk = walk->next)
		if (!walk->instances)
		    fprintf(stderr,"unused structure: %s\n",walk->id);
	;
    break;}
case 3:
#line 177 "ql_y.y"
{
	    to_c("#%s\n",yyvsp[-1].str);
	    to_test("#%s\n",yyvsp[-1].str);
	    if (dump) to_dump("#%s\n",yyvsp[-1].str);
	;
    break;}
case 6:
#line 190 "ql_y.y"
{
	    STRUCTURE *n;

	    n = alloc_t(STRUCTURE);
	    n->id = yyvsp[-2].str;
	    n->block = yyvsp[0].field;
	    n->instances = 0;
	    n->next = structures;
	    structures = n;
	;
    break;}
case 7:
#line 203 "ql_y.y"
{
	    abort_id = NULL;
	;
    break;}
case 8:
#line 207 "ql_y.y"
{
	    yyval.field = yyvsp[0].field;
	;
    break;}
case 9:
#line 214 "ql_y.y"
{
	    STRUCTURE *walk;

	    for (walk = structures; walk; walk = walk->next)
		if (walk->id == yyvsp[0].str) break;
	    if (!walk) yyerror("no such structure");
	    walk->instances++;
	    yyval.field = alloc_t(FIELD);
	    yyval.field->id = NULL;
	    yyval.field->name_list = NULL;
	    yyval.field->value = NULL;
	    yyval.field->brk = 0;
	    yyval.field->structure = walk;
	    yyval.field->my_block = copy_block(walk->block);
	    yyval.field->next = NULL;
	    abort_id = NULL;
	;
    break;}
case 10:
#line 232 "ql_y.y"
{
	    yyval.field = yyvsp[-1].field;
	    abort_id = NULL;
	;
    break;}
case 11:
#line 237 "ql_y.y"
{
	    yyval.field = NULL;
	    abort_id = yyvsp[0].str;
	;
    break;}
case 12:
#line 244 "ql_y.y"
{
	    yyval.field = NULL;
	;
    break;}
case 13:
#line 248 "ql_y.y"
{
	    yyval.field = yyvsp[-1].field;
	    yyvsp[-1].field->next = yyvsp[0].field;
	;
    break;}
case 14:
#line 256 "ql_y.y"
{
	    TAG *walk;

	    yyval.field = yyvsp[0].field;
	    yyval.field->name_list = yyvsp[-2].nlist;
	    yyval.field->brk = yyvsp[-4].num;
	    yyval.field->id = yyvsp[-3].str;
	    if (yyval.field->var_len == -2) {
		if (*yyval.field->id == '_') yyerror("var-len field must be named");
	    }
	    else if (*yyval.field->id == '_' && !yyval.field->value)
		    yyerror("unnamed fields must have value");
	    if (*yyval.field->id == '_' && yyval.field->value && yyval.field->value->type == vt_case)
		for (walk = yyval.field->value->tags; walk; walk = walk->next)
		    if (walk->more)
			yyerror("value list only allowed in named case "
			  "selections");
	    if (*yyval.field->id != '_' && yyval.field->value && yyval.field->value->type == vt_multi)
		yyerror("multi selectors must be unnamed");
	;
    break;}
case 15:
#line 279 "ql_y.y"
{
	    yyval.num = 0;
	;
    break;}
case 16:
#line 283 "ql_y.y"
{
	    yyval.num = 1;
	;
    break;}
case 17:
#line 290 "ql_y.y"
{
	    yyval.field = alloc_t(FIELD);
	    yyval.field->size = yyvsp[-1].num;
	    yyval.field->var_len = -2; /* hack */
	    if (yyvsp[-1].num & 7) yyerror("var-len field must have integral size");
	    yyval.field->pos = 0;
	    yyval.field->flush = 1;
	    yyval.field->value = NULL;
	    yyval.field->structure = NULL;
	    yyval.field->next = NULL;
	;
    break;}
case 18:
#line 302 "ql_y.y"
{
	    yyval.field = alloc_t(FIELD);
	    yyval.field->size = yyvsp[-4].num;
	    yyval.field->var_len = -1;
	    yyval.field->pos = yyvsp[-3].num;
	    yyval.field->flush = !yyvsp[-2].num;
	    if (yyval.field->pos == -1)
		if (yyval.field->size & 7)
		    yyerror("position required for small fields");
		else yyval.field->pos = 0;
	    yyval.field->value = yyvsp[0].value;
	    yyval.field->structure = NULL;
	    yyval.field->next = NULL;
	;
    break;}
case 19:
#line 319 "ql_y.y"
{
	    yyval.num = -1;
	;
    break;}
case 20:
#line 323 "ql_y.y"
{
	    yyval.num = yyvsp[0].num-1;
	    if (yyval.num < 0 || yyval.num > 7) yyerror("invalid position");
	;
    break;}
case 21:
#line 331 "ql_y.y"
{
	    char *end;

	    yyval.num = strtoul(yyvsp[0].str,&end,10);
	    if (*end) yyerror("no a decimal number");
	;
    break;}
case 22:
#line 340 "ql_y.y"
{
	    yyval.num = 0;
	;
    break;}
case 23:
#line 344 "ql_y.y"
{
	    if (strcmp(yyvsp[0].str,"more")) yyerror("\"more\" expected");
	    yyval.num = 1;
	;
    break;}
case 24:
#line 351 "ql_y.y"
{
	    yyval.value = NULL;
	;
    break;}
case 25:
#line 355 "ql_y.y"
{
	    yyval.value = yyvsp[0].value;
	;
    break;}
case 26:
#line 362 "ql_y.y"
{
	    yyval.value = alloc_t(VALUE);
	    yyval.value->type = vt_id;
	    yyval.value->id = yyvsp[0].str;
	;
    break;}
case 27:
#line 368 "ql_y.y"
{
	    yyval.value = alloc_t(VALUE);
	    yyval.value->type = vt_case;
	    yyval.value->id = NULL;
	    yyval.value->tags = yyvsp[-1].tag;
	;
    break;}
case 28:
#line 375 "ql_y.y"
{
	    yyval.value = alloc_t(VALUE);
	    yyval.value->type = vt_multi;
	    yyval.value->tags = yyvsp[-1].tag;
	;
    break;}
case 29:
#line 381 "ql_y.y"
{
	    yyval.value = alloc_t(VALUE);
	    yyval.value->type = vt_length;
	    yyval.value->recovery = yyvsp[-2].str;
	    yyval.value->block = yyvsp[0].field;
	    yyval.value->abort_id = abort_id;
	;
    break;}
case 30:
#line 391 "ql_y.y"
{
	    yyval.str = NULL;
	;
    break;}
case 31:
#line 395 "ql_y.y"
{
	    yyval.str = yyvsp[0].str;
	;
    break;}
case 32:
#line 401 "ql_y.y"
{
	    yyval.nlist = NULL;
	;
    break;}
case 33:
#line 405 "ql_y.y"
{
	    yyval.nlist = get_name_list(yyvsp[0].str);
	;
    break;}
case 34:
#line 411 "ql_y.y"
{
	    yyval.tag = NULL;
	;
    break;}
case 35:
#line 415 "ql_y.y"
{
	    yyval.tag = alloc_t(TAG);
	    yyval.tag->deflt = 1;
	    if (yyvsp[-2].str) {
		yyval.tag->id = yyvsp[-3].str;
		yyval.tag->value = yyvsp[-2].str;
	    }
	    else {
		yyval.tag->id = NULL;
		yyval.tag->value = yyvsp[-3].str;
	    }
	    yyval.tag->more = yyvsp[-1].list;
	    yyval.tag->block = yyvsp[0].field;
	    yyval.tag->next = NULL;
	    yyval.tag->abort_id = abort_id;
	;
    break;}
case 36:
#line 432 "ql_y.y"
{
	    yyval.tag = alloc_t(TAG);
	    yyval.tag->abort_id = abort_id;
	;
    break;}
case 37:
#line 437 "ql_y.y"
{
	    yyval.tag = yyvsp[-1].tag;
	    yyval.tag->deflt = 0;
	    if (yyvsp[-4].str) {
		yyval.tag->id = yyvsp[-5].str;
		yyval.tag->value = yyvsp[-4].str;
	    }
	    else {
		yyval.tag->id = NULL;
		yyval.tag->value = yyvsp[-5].str;
	    }
	    yyval.tag->more = yyvsp[-3].list;
	    yyval.tag->block = yyvsp[-2].field;
	    yyval.tag->next = yyvsp[0].tag;
	;
    break;}
case 38:
#line 455 "ql_y.y"
{
	    yyval.tag = NULL;
	;
    break;}
case 39:
#line 459 "ql_y.y"
{
	    yyval.tag = alloc_t(TAG);
	    yyval.tag->deflt = 1;
	    if (yyvsp[-2].str) {
		yyval.tag->id = yyvsp[-3].str;
		yyval.tag->value = yyvsp[-2].str;
	    }
	    else {
		yyval.tag->id = NULL;
		yyval.tag->value = yyvsp[-3].str;
	    }
	    yyval.tag->more = yyvsp[-1].list;
	    yyval.tag->block = yyvsp[0].field;
	    yyval.tag->next = NULL;
	;
    break;}
case 40:
#line 475 "ql_y.y"
{
	    yyval.tag = alloc_t(TAG);
	    yyval.tag->abort_id = abort_id;
	;
    break;}
case 41:
#line 480 "ql_y.y"
{
	    yyval.tag = yyvsp[-1].tag;
	    yyval.tag->deflt = 0;
	    if (yyvsp[-4].str) {
		yyval.tag->id = yyvsp[-5].str;
		yyval.tag->value = yyvsp[-4].str;
	    }
	    else {
		yyval.tag->id = NULL;
		yyval.tag->value = yyvsp[-5].str;
	    }
	    yyval.tag->more = yyvsp[-3].list;
	    yyval.tag->block = yyvsp[-2].field;
	    yyval.tag->next = yyvsp[0].tag;
	;
    break;}
case 42:
#line 498 "ql_y.y"
{
	    yyval.str = NULL;
	;
    break;}
case 43:
#line 502 "ql_y.y"
{
	    yyval.str = yyvsp[0].str;
	;
    break;}
case 44:
#line 508 "ql_y.y"
{
	    yyval.list = NULL;
	;
    break;}
case 45:
#line 512 "ql_y.y"
{
	    yyval.list = alloc_t(VALUE_LIST);
	    yyval.list->value = yyvsp[-1].str;
	    yyval.list->next = yyvsp[0].list;
	;
    break;}
}
   /* the action file gets copied in in place of this dollarsign */
#line 543 "/usr/lib/bison.simple"

  yyvsp -= yylen;
  yyssp -= yylen;
#ifdef YYLSP_NEEDED
  yylsp -= yylen;
#endif

#if YYDEBUG != 0
  if (yydebug)
    {
      short *ssp1 = yyss - 1;
      fprintf (stderr, "state stack now");
      while (ssp1 != yyssp)
	fprintf (stderr, " %d", *++ssp1);
      fprintf (stderr, "\n");
    }
#endif

  *++yyvsp = yyval;

#ifdef YYLSP_NEEDED
  yylsp++;
  if (yylen == 0)
    {
      yylsp->first_line = yylloc.first_line;
      yylsp->first_column = yylloc.first_column;
      yylsp->last_line = (yylsp-1)->last_line;
      yylsp->last_column = (yylsp-1)->last_column;
      yylsp->text = 0;
    }
  else
    {
      yylsp->last_line = (yylsp+yylen-1)->last_line;
      yylsp->last_column = (yylsp+yylen-1)->last_column;
    }
#endif

  /* Now "shift" the result of the reduction.
     Determine what state that goes to,
     based on the state we popped back to
     and the rule number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTBASE] + *yyssp;
  if (yystate >= 0 && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTBASE];

  goto yynewstate;

yyerrlab:   /* here on detecting error */

  if (! yyerrstatus)
    /* If not already recovering from an error, report this error.  */
    {
      ++yynerrs;

#ifdef YYERROR_VERBOSE
      yyn = yypact[yystate];

      if (yyn > YYFLAG && yyn < YYLAST)
	{
	  int size = 0;
	  char *msg;
	  int x, count;

	  count = 0;
	  /* Start X at -yyn if nec to avoid negative indexes in yycheck.  */
	  for (x = (yyn < 0 ? -yyn : 0);
	       x < (sizeof(yytname) / sizeof(char *)); x++)
	    if (yycheck[x + yyn] == x)
	      size += strlen(yytname[x]) + 15, count++;
	  msg = (char *) malloc(size + 15);
	  if (msg != 0)
	    {
	      strcpy(msg, "parse error");

	      if (count < 5)
		{
		  count = 0;
		  for (x = (yyn < 0 ? -yyn : 0);
		       x < (sizeof(yytname) / sizeof(char *)); x++)
		    if (yycheck[x + yyn] == x)
		      {
			strcat(msg, count == 0 ? ", expecting `" : " or `");
			strcat(msg, yytname[x]);
			strcat(msg, "'");
			count++;
		      }
		}
	      yyerror(msg);
	      free(msg);
	    }
	  else
	    yyerror ("parse error; also virtual memory exceeded");
	}
      else
#endif /* YYERROR_VERBOSE */
	yyerror("parse error");
    }

  goto yyerrlab1;
yyerrlab1:   /* here on error raised explicitly by an action */

  if (yyerrstatus == 3)
    {
      /* if just tried and failed to reuse lookahead token after an error, discard it.  */

      /* return failure if at end of input */
      if (yychar == YYEOF)
	YYABORT;

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Discarding token %d (%s).\n", yychar, yytname[yychar1]);
#endif

      yychar = YYEMPTY;
    }

  /* Else will try to reuse lookahead token
     after shifting the error token.  */

  yyerrstatus = 3;		/* Each real token shifted decrements this */

  goto yyerrhandle;

yyerrdefault:  /* current state does not do anything special for the error token. */

#if 0
  /* This is wrong; only states that explicitly want error tokens
     should shift them.  */
  yyn = yydefact[yystate];  /* If its default is to accept any token, ok.  Otherwise pop it.*/
  if (yyn) goto yydefault;
#endif

yyerrpop:   /* pop the current state because it cannot handle the error token */

  if (yyssp == yyss) YYABORT;
  yyvsp--;
  yystate = *--yyssp;
#ifdef YYLSP_NEEDED
  yylsp--;
#endif

#if YYDEBUG != 0
  if (yydebug)
    {
      short *ssp1 = yyss - 1;
      fprintf (stderr, "Error: state stack now");
      while (ssp1 != yyssp)
	fprintf (stderr, " %d", *++ssp1);
      fprintf (stderr, "\n");
    }
#endif

yyerrhandle:

  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yyerrdefault;

  yyn += YYTERROR;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != YYTERROR)
    goto yyerrdefault;

  yyn = yytable[yyn];
  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrpop;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrpop;

  if (yyn == YYFINAL)
    YYACCEPT;

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Shifting error token, ");
#endif

  *++yyvsp = yylval;
#ifdef YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  yystate = yyn;
  goto yynewstate;

 yyacceptlab:
  /* YYACCEPT comes here.  */
  if (yyfree_stacks)
    {
      free (yyss);
      free (yyvs);
#ifdef YYLSP_NEEDED
      free (yyls);
#endif
    }
  return 0;

 yyabortlab:
  /* YYABORT comes here.  */
  if (yyfree_stacks)
    {
      free (yyss);
      free (yyvs);
#ifdef YYLSP_NEEDED
      free (yyls);
#endif
    }
  return 1;
}
#line 518 "ql_y.y"
