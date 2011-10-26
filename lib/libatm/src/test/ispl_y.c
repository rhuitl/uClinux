
/*  A Bison parser, made from ispl_y.y
    by GNU Bison version 1.28  */

#define YYBISON 1  /* Identify Bison output.  */

#define	TOK_SEND	257
#define	TOK_WAIT	258
#define	TOK_RECEIVE	259
#define	TOK_HELP	260
#define	TOK_SET	261
#define	TOK_SHOW	262
#define	TOK_ECHO	263
#define	TOK_VCC	264
#define	TOK_LISTEN	265
#define	TOK_LISTEN_VCC	266
#define	TOK_REPLY	267
#define	TOK_PVC	268
#define	TOK_LOCAL	269
#define	TOK_QOS	270
#define	TOK_SVC	271
#define	TOK_BIND	272
#define	TOK_CONNECT	273
#define	TOK_ACCEPT	274
#define	TOK_REJECT	275
#define	TOK_OKAY	276
#define	TOK_ERROR	277
#define	TOK_INDICATE	278
#define	TOK_CLOSE	279
#define	TOK_ITF_NOTIFY	280
#define	TOK_MODIFY	281
#define	TOK_SAP	282
#define	TOK_IDENTIFY	283
#define	TOK_TERMINATE	284
#define	TOK_EOL	285
#define	TOK_VALUE	286
#define	TOK_VARIABLE	287

#line 1 "ispl_y.y"

/* isp.y - Internal Signaling Protocol test generator language */

/* Written 1997,1998 by Werner Almesberger, EPFL-ICA */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <atm.h>
#include <linux/atmsvc.h>

#include "isp.h"


static struct atmsvc_msg msg;



#line 25 "ispl_y.y"
typedef union {
    char *str;
    int num;
    enum atmsvc_msg_type type;
    VAR *var;
} YYSTYPE;
#include <stdio.h>

#ifndef __cplusplus
#ifndef __STDC__
#define const
#endif
#endif



#define	YYFINAL		67
#define	YYFLAG		-32768
#define	YYNTBASE	36

#define YYTRANSLATE(x) ((unsigned)(x) <= 287 ? yytranslate[x] : 52)

static const char yytranslate[] = {     0,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
    34,     2,    35,     2,     2,     2,     2,     2,     2,     2,
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
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     1,     3,     4,     5,     6,
     7,     8,     9,    10,    11,    12,    13,    14,    15,    16,
    17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
    27,    28,    29,    30,    31,    32,    33
};

#if YYDEBUG != 0
static const short yyprhs[] = {     0,
     0,     1,     4,     5,    10,    11,    15,    18,    23,    25,
    28,    30,    32,    34,    36,    38,    40,    42,    44,    46,
    48,    50,    52,    54,    56,    58,    59,    62,    66,    70,
    72,    73,    74,    78,    79,    82,    86,    90,    94,    96,
    98,   100,   102,   104,   106,   108,   110,   112,   114,   116
};

static const short yyrhs[] = {    -1,
    37,    36,     0,     0,     3,    40,    38,    41,     0,     0,
     5,    39,    44,     0,     4,    43,     0,     7,    50,    34,
    32,     0,     8,     0,     9,    32,     0,    49,     0,    31,
     0,    18,     0,    19,     0,    20,     0,    21,     0,    11,
     0,    22,     0,    23,     0,    24,     0,    25,     0,    26,
     0,    27,     0,    29,     0,    30,     0,     0,    42,    41,
     0,    48,    34,    51,     0,    48,    34,    32,     0,    32,
     0,     0,     0,    40,    45,    46,     0,     0,    47,    46,
     0,    50,    34,    48,     0,    48,    34,    51,     0,    48,
    34,    32,     0,    10,     0,    12,     0,    13,     0,    14,
     0,    15,     0,    16,     0,    17,     0,    28,     0,     6,
     0,    35,     0,    33,     0,    33,     0
};

#endif

#if YYDEBUG != 0
static const short yyrline[] = { 0,
    47,    48,    51,    58,    62,    68,    68,    72,    77,    87,
    92,   106,   109,   114,   118,   122,   126,   130,   134,   138,
   142,   146,   150,   154,   158,   164,   165,   168,   174,   181,
   192,   193,   198,   200,   201,   204,   209,   214,   221,   226,
   230,   234,   238,   242,   246,   250,   256,   258,   261,   270
};
#endif


#if YYDEBUG != 0 || defined (YYERROR_VERBOSE)

static const char * const yytname[] = {   "$","error","$undefined.","TOK_SEND",
"TOK_WAIT","TOK_RECEIVE","TOK_HELP","TOK_SET","TOK_SHOW","TOK_ECHO","TOK_VCC",
"TOK_LISTEN","TOK_LISTEN_VCC","TOK_REPLY","TOK_PVC","TOK_LOCAL","TOK_QOS","TOK_SVC",
"TOK_BIND","TOK_CONNECT","TOK_ACCEPT","TOK_REJECT","TOK_OKAY","TOK_ERROR","TOK_INDICATE",
"TOK_CLOSE","TOK_ITF_NOTIFY","TOK_MODIFY","TOK_SAP","TOK_IDENTIFY","TOK_TERMINATE",
"TOK_EOL","TOK_VALUE","TOK_VARIABLE","'='","'?'","all","command","@1","@2","type",
"values","value","number","opt_recv","@3","fields","field","field_type","help",
"new_var","old_var", NULL
};
#endif

static const short yyr1[] = {     0,
    36,    36,    38,    37,    39,    37,    37,    37,    37,    37,
    37,    37,    40,    40,    40,    40,    40,    40,    40,    40,
    40,    40,    40,    40,    40,    41,    41,    42,    42,    43,
    44,    45,    44,    46,    46,    47,    47,    47,    48,    48,
    48,    48,    48,    48,    48,    48,    49,    49,    50,    51
};

static const short yyr2[] = {     0,
     0,     2,     0,     4,     0,     3,     2,     4,     1,     2,
     1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
     1,     1,     1,     1,     1,     0,     2,     3,     3,     1,
     0,     0,     3,     0,     2,     3,     3,     3,     1,     1,
     1,     1,     1,     1,     1,     1,     1,     1,     1,     1
};

static const short yydefact[] = {     1,
     0,     0,     5,    47,     0,     9,     0,    12,    48,     1,
    11,    17,    13,    14,    15,    16,    18,    19,    20,    21,
    22,    23,    24,    25,     3,    30,     7,    31,    49,     0,
    10,     2,    26,    32,     6,     0,    39,    40,    41,    42,
    43,    44,    45,    46,     4,    26,     0,    34,     8,    27,
     0,    33,    34,     0,     0,    29,    50,    28,    35,     0,
     0,    38,    37,    36,     0,     0,     0
};

static const short yydefgoto[] = {    32,
    10,    33,    28,    25,    45,    46,    27,    35,    48,    52,
    53,    47,    11,    55,    58
};

static const short yypact[] = {    -3,
    16,   -25,-32768,-32768,   -24,-32768,   -10,-32768,-32768,    -3,
-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
-32768,-32768,-32768,-32768,-32768,-32768,-32768,    16,-32768,   -11,
-32768,-32768,    37,-32768,-32768,    -8,-32768,-32768,-32768,-32768,
-32768,-32768,-32768,-32768,-32768,    37,    -9,    -2,-32768,-32768,
   -15,-32768,    -2,    -4,    -1,-32768,-32768,-32768,-32768,   -13,
    37,-32768,-32768,-32768,    44,    48,-32768
};

static const short yypgoto[] = {    55,
-32768,-32768,-32768,    28,    11,-32768,-32768,-32768,-32768,     5,
-32768,   -32,-32768,    54,     0
};


#define	YYLAST		65


static const short yytable[] = {     1,
     2,     3,     4,     5,     6,     7,    26,    37,    29,    38,
    39,    40,    41,    42,    43,    54,    56,    57,    62,    57,
    54,    31,    36,    49,    51,    44,    12,     8,    64,    60,
    29,     9,    61,    13,    14,    15,    16,    17,    18,    19,
    20,    21,    22,    66,    23,    24,    37,    67,    38,    39,
    40,    41,    42,    43,    65,    34,    50,    59,    30,    63,
     0,     0,     0,     0,    44
};

static const short yycheck[] = {     3,
     4,     5,     6,     7,     8,     9,    32,    10,    33,    12,
    13,    14,    15,    16,    17,    48,    32,    33,    32,    33,
    53,    32,    34,    32,    34,    28,    11,    31,    61,    34,
    33,    35,    34,    18,    19,    20,    21,    22,    23,    24,
    25,    26,    27,     0,    29,    30,    10,     0,    12,    13,
    14,    15,    16,    17,     0,    28,    46,    53,     5,    60,
    -1,    -1,    -1,    -1,    28
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

case 3:
#line 53 "ispl_y.y"
{
	    memset(&msg,0,sizeof(msg));
	    msg.type = yyvsp[0].type;
	;
    break;}
case 4:
#line 58 "ispl_y.y"
{
	    send_msg(&msg);
	    if (verbose) dump_msg("SENT",&msg);
	;
    break;}
case 5:
#line 63 "ispl_y.y"
{
	    recv_msg(&msg);
	    if (!quiet) dump_msg("RECV",&msg);
	;
    break;}
case 7:
#line 69 "ispl_y.y"
{
	    sleep(yyvsp[0].num);
	;
    break;}
case 8:
#line 73 "ispl_y.y"
{
	    assign(yyvsp[-2].var,eval(vt_text,yyvsp[0].str));
	    free(yyvsp[0].str);
	;
    break;}
case 9:
#line 78 "ispl_y.y"
{
	    VAR *var;

	    for (var = variables; var; var = var->next) {
		printf("%s = ",var->name);
		print_value(var->value);
		putchar('\n');
	    }
	;
    break;}
case 10:
#line 88 "ispl_y.y"
{
	    printf("%s\n",yyvsp[0].str);
	    free(yyvsp[0].str);
	;
    break;}
case 11:
#line 93 "ispl_y.y"
{
	    fprintf(stderr,
"Commands:\n"
"  send msg_type [field=value|field=$var ...]\n"
"  receive [msg_type [field=value|field=$var|$var=field ...]]\n"
"  set $var=value\n"
"  show\n"
"  echo value\n"
"  help\n\n"
"msg_type: bind, connect, accept, reject, listen, okay, error, indicate,\n"
"          close, itf_notify, modify, identify, terminate\n"
"field: vcc, listen_vcc, reply, pvc, local, qos, svc, sap\n");
	;
    break;}
case 13:
#line 111 "ispl_y.y"
{
	    yyval.type = as_bind;
	;
    break;}
case 14:
#line 115 "ispl_y.y"
{
	    yyval.type = as_connect;
	;
    break;}
case 15:
#line 119 "ispl_y.y"
{
	    yyval.type = as_accept;
	;
    break;}
case 16:
#line 123 "ispl_y.y"
{
	    yyval.type = as_reject;
	;
    break;}
case 17:
#line 127 "ispl_y.y"
{
	    yyval.type = as_listen;
	;
    break;}
case 18:
#line 131 "ispl_y.y"
{
	    yyval.type = as_okay;
	;
    break;}
case 19:
#line 135 "ispl_y.y"
{
	    yyval.type = as_error;
	;
    break;}
case 20:
#line 139 "ispl_y.y"
{
	    yyval.type = as_indicate;
	;
    break;}
case 21:
#line 143 "ispl_y.y"
{
	    yyval.type = as_close;
	;
    break;}
case 22:
#line 147 "ispl_y.y"
{
	    yyval.type = as_itf_notify;
	;
    break;}
case 23:
#line 151 "ispl_y.y"
{
	    yyval.type = as_modify;
	;
    break;}
case 24:
#line 155 "ispl_y.y"
{
	    yyval.type = as_identify;
	;
    break;}
case 25:
#line 159 "ispl_y.y"
{
	    yyval.type = as_terminate;
	;
    break;}
case 28:
#line 170 "ispl_y.y"
{
	    cast(yyvsp[0].var,type_of(yyvsp[-2].num));
	    store(&msg,yyvsp[-2].num,yyvsp[0].var->value);
	;
    break;}
case 29:
#line 175 "ispl_y.y"
{
	    store(&msg,yyvsp[-2].num,eval(type_of(yyvsp[-2].num),yyvsp[0].str));
	    free(yyvsp[0].str);
	;
    break;}
case 30:
#line 183 "ispl_y.y"
{
	    char *end;

	    yyval.num = strtol(yyvsp[0].str,&end,10);
	    if (*end) yyerror("invalid number");
	    free(yyvsp[0].str);
	;
    break;}
case 32:
#line 194 "ispl_y.y"
{
	    if (msg.type != yyvsp[0].type) yyerror("wrong message type");
	;
    break;}
case 36:
#line 206 "ispl_y.y"
{
	    assign(yyvsp[-2].var,pick(&msg,yyvsp[0].num));
	;
    break;}
case 37:
#line 210 "ispl_y.y"
{
	    cast(yyvsp[0].var,type_of(yyvsp[-2].num));
	    check(pick(&msg,yyvsp[-2].num),yyvsp[0].var->value);
	;
    break;}
case 38:
#line 215 "ispl_y.y"
{
	    check(pick(&msg,yyvsp[-2].num),eval(type_of(yyvsp[-2].num),yyvsp[0].str));
	    free(yyvsp[0].str);
	;
    break;}
case 39:
#line 223 "ispl_y.y"
{
	    yyval.num = F_VCC;
	;
    break;}
case 40:
#line 227 "ispl_y.y"
{
	    yyval.num = F_LISTEN_VCC;
	;
    break;}
case 41:
#line 231 "ispl_y.y"
{
	    yyval.num = F_REPLY;
	;
    break;}
case 42:
#line 235 "ispl_y.y"
{
	    yyval.num = F_PVC;
	;
    break;}
case 43:
#line 239 "ispl_y.y"
{
	    yyval.num = F_LOCAL;
	;
    break;}
case 44:
#line 243 "ispl_y.y"
{
	    yyval.num = F_QOS;
	;
    break;}
case 45:
#line 247 "ispl_y.y"
{
	    yyval.num = F_SVC;
	;
    break;}
case 46:
#line 251 "ispl_y.y"
{
	    yyval.num = F_SAP;
	;
    break;}
case 49:
#line 263 "ispl_y.y"
{
	    yyval.var = lookup(yyvsp[0].str);
	    if (yyval.var) free(yyvsp[0].str);
	    else yyval.var = create_var(yyvsp[0].str);
	;
    break;}
case 50:
#line 272 "ispl_y.y"
{
	    yyval.var = lookup(yyvsp[0].str);
	    if (!yyval.var) yyerror("no such variable");
	    free(yyvsp[0].str);
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
#line 278 "ispl_y.y"
