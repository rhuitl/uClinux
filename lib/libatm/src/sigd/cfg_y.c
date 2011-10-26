
/*  A Bison parser, made from cfg_y.y
    by GNU Bison version 1.28  */

#define YYBISON 1  /* Identify Bison output.  */

#define	TOK_LEVEL	257
#define	TOK_DEBUG	258
#define	TOK_INFO	259
#define	TOK_WARN	260
#define	TOK_ERROR	261
#define	TOK_FATAL	262
#define	TOK_SIG	263
#define	TOK_UNI30	264
#define	TOK_UNI31	265
#define	TOK_UNI40	266
#define	TOK_Q2963_1	267
#define	TOK_SAAL	268
#define	TOK_VC	269
#define	TOK_IO	270
#define	TOK_MODE	271
#define	TOK_USER	272
#define	TOK_NET	273
#define	TOK_SWITCH	274
#define	TOK_VPCI	275
#define	TOK_ITF	276
#define	TOK_PCR	277
#define	TOK_TRACE	278
#define	TOK_POLICY	279
#define	TOK_ALLOW	280
#define	TOK_REJECT	281
#define	TOK_ENTITY	282
#define	TOK_DEFAULT	283
#define	TOK_NUMBER	284
#define	TOK_MAX_RATE	285
#define	TOK_DUMP_DIR	286
#define	TOK_LOGFILE	287
#define	TOK_QOS	288
#define	TOK_FROM	289
#define	TOK_TO	290
#define	TOK_ROUTE	291
#define	TOK_PVC	292

#line 1 "cfg_y.y"

/* cfg.y - configuration language */

/* Written 1995-1999 by Werner Almesberger, EPFL-LRC/ICA */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <ctype.h>
#include <limits.h>

#include "atm.h"
#include "atmd.h"

#include "proto.h"
#include "io.h"
#include "trace.h"
#include "policy.h"


static RULE *rule;
static SIG_ENTITY *curr_sig = &_entity;


static int hex2num(char digit)
{
    if (isdigit(digit)) return digit-'0';
    if (islower(digit)) return toupper(digit)-'A'+10;
    return digit-'A'+10;
}


static void put_address(char *address)
{
    char *mask;

    mask = strchr(address,'/');
    if (mask) *mask++ = 0;
    if (text2atm(address,(struct sockaddr *) &rule->addr,sizeof(rule->addr),
      T2A_SVC | T2A_WILDCARD | T2A_NAME | T2A_LOCAL) < 0) {
	yyerror("invalid address");
	return;
    }
    if (!mask) rule->mask = -1;
    else rule->mask = strtol(mask,NULL,10);
    add_rule(rule);
}


#line 53 "cfg_y.y"
typedef union {
    int num;
    char *str;
    struct sockaddr_atmpvc pvc;
} YYSTYPE;
#include <stdio.h>

#ifndef __cplusplus
#ifndef __STDC__
#define const
#endif
#endif



#define	YYFINAL		117
#define	YYFLAG		-32768
#define	YYNTBASE	41

#define YYTRANSLATE(x) ((unsigned)(x) <= 292 ? yytranslate[x] : 71)

static const char yytranslate[] = {     0,
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
     2,     2,    39,     2,    40,     2,     2,     2,     2,     2,
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
     7,     8,     9,    10,    11,    12,    13,    14,    15,    16,
    17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
    27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
    37,    38
};

#if YYDEBUG != 0
static const short yyprhs[] = {     0,
     0,     3,     4,     7,     8,    11,    14,    17,    20,    23,
    26,    29,    30,    35,    36,    40,    41,    44,    49,    52,
    54,    56,    58,    60,    62,    66,    67,    70,    72,    76,
    77,    80,    82,    86,    87,    90,    92,    96,    97,   100,
   102,   106,   107,   110,   113,   118,   120,   122,   124,   126,
   128,   131,   134,   137,   140,   143,   145,   147,   150,   152,
   154,   157,   158,   160,   162,   164,   166,   168,   170,   172,
   174,   176,   179,   180,   184,   186,   188,   190
};

static const short yyrhs[] = {    42,
    43,     0,     0,    44,    42,     0,     0,    45,    43,     0,
     3,    65,     0,     9,    50,     0,    14,    52,     0,    16,
    54,     0,     4,    56,     0,    25,    58,     0,     0,    28,
    38,    46,    47,     0,     0,    39,    48,    40,     0,     0,
    49,    48,     0,    21,    30,    22,    30,     0,    17,    66,
     0,    34,     0,    31,     0,    37,     0,    29,     0,    60,
     0,    39,    51,    40,     0,     0,    60,    51,     0,    61,
     0,    39,    53,    40,     0,     0,    61,    53,     0,    62,
     0,    39,    55,    40,     0,     0,    62,    55,     0,    63,
     0,    39,    57,    40,     0,     0,    63,    57,     0,    67,
     0,    39,    59,    40,     0,     0,    67,    59,     0,     3,
    65,     0,    21,    30,    22,    30,     0,    10,     0,    11,
     0,    12,     0,    13,     0,    19,     0,    17,    66,     0,
     3,    65,     0,     3,    65,     0,    15,    38,     0,    23,
    30,     0,    34,     0,    31,     0,     3,    65,     0,    32,
     0,    33,     0,    24,    64,     0,     0,    30,     0,     4,
     0,     5,     0,     6,     0,     7,     0,     8,     0,    18,
     0,    19,     0,    20,     0,     3,    65,     0,     0,    69,
    68,    70,     0,    26,     0,    27,     0,    35,     0,    36,
     0
};

#endif

#if YYDEBUG != 0
static const short yyrline[] = { 0,
    73,    77,    78,    81,    82,   105,   110,   111,   112,   113,
   114,   117,   138,   140,   141,   144,   145,   148,   153,   154,
   158,   162,   176,   182,   184,   187,   188,   191,   193,   196,
   197,   200,   202,   205,   206,   209,   211,   214,   215,   218,
   220,   223,   224,   227,   234,   238,   247,   256,   265,   274,
   279,   282,   290,   295,   299,   304,   308,   314,   319,   324,
   328,   334,   338,   344,   349,   353,   357,   361,   367,   372,
   376,   382,   387,   393,   395,   400,   406,   412
};
#endif


#if YYDEBUG != 0 || defined (YYERROR_VERBOSE)

static const char * const yytname[] = {   "$","error","$undefined.","TOK_LEVEL",
"TOK_DEBUG","TOK_INFO","TOK_WARN","TOK_ERROR","TOK_FATAL","TOK_SIG","TOK_UNI30",
"TOK_UNI31","TOK_UNI40","TOK_Q2963_1","TOK_SAAL","TOK_VC","TOK_IO","TOK_MODE",
"TOK_USER","TOK_NET","TOK_SWITCH","TOK_VPCI","TOK_ITF","TOK_PCR","TOK_TRACE",
"TOK_POLICY","TOK_ALLOW","TOK_REJECT","TOK_ENTITY","TOK_DEFAULT","TOK_NUMBER",
"TOK_MAX_RATE","TOK_DUMP_DIR","TOK_LOGFILE","TOK_QOS","TOK_FROM","TOK_TO","TOK_ROUTE",
"TOK_PVC","'{'","'}'","all","global","local","item","entity","@1","opt_options",
"options","option","sig","sig_items","saal","saal_items","io","io_items","debug",
"debug_items","policy","policy_items","sig_item","saal_item","io_item","debug_item",
"opt_trace_size","level","mode","policy_item","@2","action","direction", NULL
};
#endif

static const short yyr1[] = {     0,
    41,    42,    42,    43,    43,    44,    44,    44,    44,    44,
    44,    46,    45,    47,    47,    48,    48,    49,    49,    49,
    49,    49,    49,    50,    50,    51,    51,    52,    52,    53,
    53,    54,    54,    55,    55,    56,    56,    57,    57,    58,
    58,    59,    59,    60,    60,    60,    60,    60,    60,    60,
    60,    61,    62,    62,    62,    62,    62,    63,    63,    63,
    63,    64,    64,    65,    65,    65,    65,    65,    66,    66,
    66,    67,    68,    67,    69,    69,    70,    70
};

static const short yyr2[] = {     0,
     2,     0,     2,     0,     2,     2,     2,     2,     2,     2,
     2,     0,     4,     0,     3,     0,     2,     4,     2,     1,
     1,     1,     1,     1,     3,     0,     2,     1,     3,     0,
     2,     1,     3,     0,     2,     1,     3,     0,     2,     1,
     3,     0,     2,     2,     4,     1,     1,     1,     1,     1,
     2,     2,     2,     2,     2,     1,     1,     2,     1,     1,
     2,     0,     1,     1,     1,     1,     1,     1,     1,     1,
     1,     2,     0,     3,     1,     1,     1,     1
};

static const short yydefact[] = {     2,
     0,     0,     0,     0,     0,     0,     4,     2,    64,    65,
    66,    67,    68,     6,     0,    62,    59,    60,    38,    10,
    36,     0,    46,    47,    48,    49,     0,    50,     0,    26,
     7,    24,     0,    30,     8,    28,     0,     0,     0,    57,
    56,    34,     9,    32,     0,    75,    76,    42,    11,    40,
    73,     0,     1,     4,     3,    58,    63,    61,     0,    38,
    44,    69,    70,    71,    51,     0,     0,    26,    52,     0,
    30,    53,    54,    55,     0,    34,    72,     0,    42,     0,
    12,     5,    37,    39,     0,    25,    27,    29,    31,    33,
    35,    41,    43,    77,    78,    74,    14,    45,    16,    13,
     0,     0,    23,    21,    20,    22,     0,    16,    19,     0,
    15,    17,     0,    18,     0,     0,     0
};

static const short yydefgoto[] = {   115,
     7,    53,     8,    54,    97,   100,   107,   108,    31,    67,
    35,    70,    43,    75,    20,    59,    49,    78,    68,    71,
    76,    60,    58,    14,    65,    79,    80,    51,    96
};

static const short yypact[] = {    52,
   100,     1,    -3,    -1,    -2,     0,   -17,    52,-32768,-32768,
-32768,-32768,-32768,-32768,   100,   -18,-32768,-32768,    25,-32768,
-32768,   100,-32768,-32768,-32768,-32768,    60,-32768,   -15,    82,
-32768,-32768,   100,    14,-32768,-32768,   100,   -19,   -10,-32768,
-32768,    20,-32768,-32768,   100,-32768,-32768,    19,-32768,-32768,
-32768,   -14,-32768,   -17,-32768,-32768,-32768,-32768,    -9,    25,
-32768,-32768,-32768,-32768,-32768,     8,     2,    82,-32768,     4,
    14,-32768,-32768,-32768,     7,    20,-32768,    10,    19,   -30,
-32768,-32768,-32768,-32768,    22,-32768,-32768,-32768,-32768,-32768,
-32768,-32768,-32768,-32768,-32768,-32768,    21,-32768,    53,-32768,
    60,    23,-32768,-32768,-32768,-32768,    24,    53,-32768,    40,
-32768,-32768,    35,-32768,    67,    69,-32768
};

static const short yypgoto[] = {-32768,
    64,    27,-32768,-32768,-32768,-32768,   -35,-32768,-32768,    15,
-32768,     5,-32768,    12,-32768,    29,-32768,    -4,    83,    87,
    91,    95,-32768,    26,     9,    92,-32768,-32768,-32768
};


#define	YYLAST		110


static const short yytable[] = {    22,
    37,    33,    45,    15,    94,    95,    23,    24,    25,    26,
    52,    57,    38,    27,    66,    28,    33,    29,    73,    74,
    39,    45,    37,    81,    16,    46,    47,    15,    40,    85,
    83,    41,    17,    18,    38,    30,    42,    34,    48,    19,
    56,    86,    39,    88,    46,    47,    90,    61,    16,    92,
    40,    98,   110,    41,     1,     2,    17,    18,    69,    99,
     3,   113,    72,   111,   114,     4,   116,     5,   117,   101,
    77,    55,   112,   102,    93,    89,     6,    62,    63,    64,
    82,   103,    87,   104,    22,    32,   105,    91,    84,   106,
    36,    23,    24,    25,    26,    44,    21,    50,    27,     0,
    28,     0,    29,     9,    10,    11,    12,    13,     0,   109
};

static const short yycheck[] = {     3,
     3,     3,     3,     3,    35,    36,    10,    11,    12,    13,
    28,    30,    15,    17,    30,    19,     3,    21,    38,    30,
    23,     3,     3,    38,    24,    26,    27,     3,    31,    22,
    40,    34,    32,    33,    15,    39,    39,    39,    39,    39,
    15,    40,    23,    40,    26,    27,    40,    22,    24,    40,
    31,    30,    30,    34,     3,     4,    32,    33,    33,    39,
     9,    22,    37,    40,    30,    14,     0,    16,     0,    17,
    45,     8,   108,    21,    79,    71,    25,    18,    19,    20,
    54,    29,    68,    31,     3,     3,    34,    76,    60,    37,
     4,    10,    11,    12,    13,     5,     2,     6,    17,    -1,
    19,    -1,    21,     4,     5,     6,     7,     8,    -1,   101
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

case 5:
#line 83 "cfg_y.y"
{
	    if (!curr_sig->uni)
		curr_sig->uni =
#if defined(UNI30) || defined(DYNAMIC_UNI)
		  S_UNI30
#endif
#ifdef UNI31
		  S_UNI31
#ifdef ALLOW_UNI30
		  | S_UNI30
#endif
#endif
#ifdef UNI40
		  S_UNI40
#ifdef Q2963_1
		  | S_Q2963_1
#endif
#endif
		  ;
	;
    break;}
case 6:
#line 107 "cfg_y.y"
{
	    set_verbosity(NULL,yyvsp[0].num);
	;
    break;}
case 12:
#line 119 "cfg_y.y"
{
	    SIG_ENTITY *sig,**walk;

	    if (atmpvc_addr_in_use(_entity.signaling_pvc))
		yyerror("can't use  io vc  and  entity ...  in the same "
		  "configuration");
	    if (entities == &_entity) entities = NULL;
	    for (sig = entities; sig; sig = sig->next)
		if (atm_equal((struct sockaddr *) &sig->signaling_pvc,
		  (struct sockaddr *) &yyvsp[0].pvc,0,0))
		    yyerror("duplicate PVC address %d.%d.%d",S_PVC(sig));
	    curr_sig = alloc_t(SIG_ENTITY);
	    *curr_sig = _entity;
	    curr_sig->signaling_pvc = yyvsp[0].pvc;
	    curr_sig->next = NULL;
	    for (walk = &entities; *walk; walk = &(*walk)->next);
	    *walk = curr_sig;
	;
    break;}
case 18:
#line 150 "cfg_y.y"
{
	    enter_vpci(curr_sig,yyvsp[-2].num,yyvsp[0].num);
	;
    break;}
case 20:
#line 155 "cfg_y.y"
{
	    curr_sig->sig_qos = yyvsp[0].str;
	;
    break;}
case 21:
#line 159 "cfg_y.y"
{
	    curr_sig->max_rate = yyvsp[0].num;
	;
    break;}
case 22:
#line 163 "cfg_y.y"
{
	     struct sockaddr_atmsvc addr;
	     char *mask;

	    mask = strchr(yyvsp[0].str,'/');
	    if (mask) *mask++ = 0;
	    if (text2atm(yyvsp[0].str,(struct sockaddr *) &addr,sizeof(addr),
	    T2A_SVC | T2A_WILDCARD | T2A_NAME | T2A_LOCAL) < 0) {
		yyerror("invalid address");
		return;
	    }
	    add_route(curr_sig,&addr,mask ? strtol(mask,NULL,10) : INT_MAX);
	;
    break;}
case 23:
#line 177 "cfg_y.y"
{
	    add_route(curr_sig,NULL,0);
	;
    break;}
case 44:
#line 229 "cfg_y.y"
{
	    set_verbosity("UNI",yyvsp[0].num);
	    set_verbosity("KERNEL",yyvsp[0].num);
	    set_verbosity("SAP",yyvsp[0].num);
	;
    break;}
case 45:
#line 235 "cfg_y.y"
{
	    enter_vpci(curr_sig,yyvsp[-2].num,yyvsp[0].num);
	;
    break;}
case 46:
#line 239 "cfg_y.y"
{
#if defined(UNI30) || defined(ALLOW_UNI30) || defined(DYNAMIC_UNI)
	    if (curr_sig->uni & ~S_UNI31) yyerror("UNI mode is already set");
	    curr_sig->uni |= S_UNI30;
#else
	    yyerror("Sorry, not supported yet");
#endif
	;
    break;}
case 47:
#line 248 "cfg_y.y"
{
#if defined(UNI31) || defined(ALLOW_UNI30) || defined(DYNAMIC_UNI)
	    if (curr_sig->uni & ~S_UNI30) yyerror("UNI mode is already set");
	    curr_sig->uni |= S_UNI31;
#else
	    yyerror("Sorry, not supported yet");
#endif
	;
    break;}
case 48:
#line 257 "cfg_y.y"
{
#if defined(UNI40) || defined(DYNAMIC_UNI)
	    if (curr_sig->uni) yyerror("UNI mode is already set");
	    curr_sig->uni = S_UNI40;
#else
	    yyerror("Sorry, not supported yet");
#endif
	;
    break;}
case 49:
#line 266 "cfg_y.y"
{
#if defined(Q2963_1) || defined(DYNAMIC_UNI)
	    if (!(curr_sig->uni & S_UNI40)) yyerror("Incompatible UNI mode");
	    curr_sig->uni |= S_Q2963_1;
#else
	    yyerror("Sorry, not supported yet");
#endif
	;
    break;}
case 50:
#line 275 "cfg_y.y"
{
	    yywarn("sig net  is obsolete, please use  sig mode net  instead");
	    curr_sig->mode = sm_net;
	;
    break;}
case 52:
#line 284 "cfg_y.y"
{
	    set_verbosity("SSCF",yyvsp[0].num);
	    set_verbosity("SSCOP",yyvsp[0].num);
	;
    break;}
case 53:
#line 292 "cfg_y.y"
{
	    set_verbosity("IO",yyvsp[0].num);
	;
    break;}
case 54:
#line 296 "cfg_y.y"
{
	    curr_sig->signaling_pvc = yyvsp[0].pvc;
	;
    break;}
case 55:
#line 300 "cfg_y.y"
{
	    yywarn("io pcr  is obsolete, please use  io qos  instead");
	    curr_sig->sig_pcr = yyvsp[0].num;
	;
    break;}
case 56:
#line 305 "cfg_y.y"
{
	    curr_sig->sig_qos = yyvsp[0].str;
	;
    break;}
case 57:
#line 309 "cfg_y.y"
{
	    curr_sig->max_rate = yyvsp[0].num;
	;
    break;}
case 58:
#line 316 "cfg_y.y"
{
	    set_verbosity(NULL,yyvsp[0].num);
	;
    break;}
case 59:
#line 320 "cfg_y.y"
{
	    dump_dir = yyvsp[0].str;
	    if (!trace_size) trace_size = DEFAULT_TRACE_SIZE;
	;
    break;}
case 60:
#line 325 "cfg_y.y"
{
	    set_logfile(yyvsp[0].str);
	;
    break;}
case 61:
#line 329 "cfg_y.y"
{
	    trace_size = yyvsp[0].num;
	;
    break;}
case 62:
#line 335 "cfg_y.y"
{
	    yyval.num = DEFAULT_TRACE_SIZE;
	;
    break;}
case 63:
#line 339 "cfg_y.y"
{
	    yyval.num = yyvsp[0].num;
	;
    break;}
case 64:
#line 346 "cfg_y.y"
{
	    yyval.num = DIAG_DEBUG;
	;
    break;}
case 65:
#line 350 "cfg_y.y"
{
	    yyval.num = DIAG_INFO;
	;
    break;}
case 66:
#line 354 "cfg_y.y"
{
	    yyval.num = DIAG_WARN;
	;
    break;}
case 67:
#line 358 "cfg_y.y"
{
	    yyval.num = DIAG_ERROR;
	;
    break;}
case 68:
#line 362 "cfg_y.y"
{
	    yyval.num = DIAG_FATAL;
	;
    break;}
case 69:
#line 369 "cfg_y.y"
{
	    curr_sig->mode = sm_user;
	;
    break;}
case 70:
#line 373 "cfg_y.y"
{
	    curr_sig->mode = sm_net;
	;
    break;}
case 71:
#line 377 "cfg_y.y"
{
	    curr_sig->mode = sm_switch;
	;
    break;}
case 72:
#line 384 "cfg_y.y"
{
	    set_verbosity("POLICY",yyvsp[0].num);
	;
    break;}
case 73:
#line 388 "cfg_y.y"
{
	    rule = alloc_t(RULE);
	    rule->type = yyvsp[0].num;
	;
    break;}
case 75:
#line 397 "cfg_y.y"
{
	    yyval.num = ACL_ALLOW;
	;
    break;}
case 76:
#line 401 "cfg_y.y"
{
	    yyval.num = ACL_REJECT;
	;
    break;}
case 77:
#line 408 "cfg_y.y"
{
	    rule->type |= ACL_IN;
	    put_address(yyvsp[0].str);
	;
    break;}
case 78:
#line 413 "cfg_y.y"
{
	    rule->type |= ACL_OUT;
	    put_address(yyvsp[0].str);
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
#line 418 "cfg_y.y"
