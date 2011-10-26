
/*  A Bison parser, made from parsetime.y with Bison version GNU Bison version 1.22
  */

#define YYBISON 1  /* Identify Bison output.  */

#define	INT	258
#define	NOW	259
#define	AM	260
#define	PM	261
#define	NOON	262
#define	MIDNIGHT	263
#define	TEATIME	264
#define	SUN	265
#define	MON	266
#define	TUE	267
#define	WED	268
#define	THU	269
#define	FRI	270
#define	SAT	271
#define	TODAY	272
#define	TOMORROW	273
#define	NEXT	274
#define	MINUTE	275
#define	HOUR	276
#define	DAY	277
#define	WEEK	278
#define	MONTH	279
#define	YEAR	280
#define	JAN	281
#define	FEB	282
#define	MAR	283
#define	APR	284
#define	MAY	285
#define	JUN	286
#define	JUL	287
#define	AUG	288
#define	SEP	289
#define	OCT	290
#define	NOV	291
#define	DEC	292
#define	WORD	293

#line 1 "parsetime.y"

#include <time.h>
#include <stdlib.h>
#include <string.h>
#include "parsetime.h"

#define YYDEBUG 1

time_t currtime;
struct tm exectm;
static int isgmt;
static int time_only;

int add_date(int number, int period);

#line 17 "parsetime.y"
typedef union {
	char *	  	charval;
	int		intval;
} YYSTYPE;

#ifndef YYLTYPE
typedef
  struct yyltype
    {
      int timestamp;
      int first_line;
      int first_column;
      int last_line;
      int last_column;
      char *text;
   }
  yyltype;

#define YYLTYPE yyltype
#endif

#include <stdio.h>

#ifndef __cplusplus
#ifndef __STDC__
#define const
#endif
#endif



#define	YYFINAL		100
#define	YYFLAG		-32768
#define	YYNTBASE	47

#define YYTRANSLATE(x) ((unsigned)(x) <= 293 ? yytranslate[x] : 67)

static const char yytranslate[] = {     0,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,    45,     2,
     2,     2,    43,    39,    40,    41,    42,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,    44,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,    46,     2,     2,     2,     2,     2,     2,
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
     2,     2,     2,     2,     2,     1,     2,     3,     4,     5,
     6,     7,     8,     9,    10,    11,    12,    13,    14,    15,
    16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
    26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
    36,    37,    38
};

#if YYDEBUG != 0
static const short yyprhs[] = {     0,
     0,     2,     5,     8,    12,    15,    19,    21,    23,    26,
    29,    31,    33,    36,    40,    45,    48,    52,    57,    63,
    65,    67,    69,    72,    77,    79,    81,    83,    89,    95,
    99,   102,   106,   112,   116,   119,   122,   126,   128,   130,
   132,   134,   136,   138,   140,   142,   144,   146,   148,   150,
   152,   154,   156,   158,   160,   162,   164,   166,   168,   170,
   172,   174,   176,   178,   180,   182,   184,   186,   188,   190,
   192,   194,   196,   198,   200,   202,   204
};

static const short yyrhs[] = {    50,
     0,    50,    51,     0,    50,    52,     0,    50,    51,    52,
     0,    50,    53,     0,    50,    51,    53,     0,    48,     0,
    49,     0,    49,    52,     0,    49,    53,     0,     4,     0,
    55,     0,    55,    56,     0,    57,    66,    58,     0,    57,
    66,    58,    56,     0,    57,    59,     0,    57,    59,    56,
     0,    57,    66,    58,    59,     0,    57,    66,    58,    59,
    56,     0,     7,     0,     8,     0,     9,     0,    60,    62,
     0,    60,    62,    39,    63,     0,    64,     0,    17,     0,
    18,     0,    63,    40,    61,    40,    62,     0,    62,    41,
    61,    41,    63,     0,    62,    41,    61,     0,    62,    60,
     0,    62,    60,    63,     0,    61,    42,    62,    42,    63,
     0,    43,    65,    54,     0,    19,    54,     0,    19,    64,
     0,    40,    65,    54,     0,    20,     0,    21,     0,    22,
     0,    23,     0,    24,     0,    25,     0,     3,     0,    38,
     0,    55,     0,     3,     0,     5,     0,     6,     0,    26,
     0,    27,     0,    28,     0,    29,     0,    30,     0,    31,
     0,    32,     0,    33,     0,    34,     0,    35,     0,    36,
     0,    37,     0,     3,     0,     3,     0,     3,     0,    10,
     0,    11,     0,    12,     0,    13,     0,    14,     0,    15,
     0,    16,     0,     3,     0,    44,     0,    45,     0,    41,
     0,    46,     0,    39,     0
};

#endif

#if YYDEBUG != 0
static const short yyrline[] = { 0,
    39,    43,    44,    45,    46,    47,    48,    51,    52,    53,
    56,    59,    60,    61,    62,    63,    64,    65,    66,    67,
    72,    78,    85,    86,    87,    91,    92,    96,    97,    98,
    99,   100,   101,   104,   108,   112,   118,   124,   125,   126,
   127,   128,   129,   132,   157,   170,   173,   183,   184,   197,
   198,   199,   200,   201,   202,   203,   204,   205,   206,   207,
   208,   211,   225,   238,   261,   262,   263,   264,   265,   266,
   267,   270,   280,   281,   282,   283,   284
};

static const char * const yytname[] = {   "$","error","$illegal.","INT","NOW",
"AM","PM","NOON","MIDNIGHT","TEATIME","SUN","MON","TUE","WED","THU","FRI","SAT",
"TODAY","TOMORROW","NEXT","MINUTE","HOUR","DAY","WEEK","MONTH","YEAR","JAN",
"FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC","WORD","','",
"'-'","'.'","'/'","'+'","':'","'\\''","'h'","timespec","nowspec","now","time",
"date","increment","decrement","inc_period","hr24clock_hr_min","timezone_name",
"hr24clock_hour","minute","am_pm","month_name","month_number","day_number","year_number",
"day_of_week","inc_number","time_sep",""
};
#endif

static const short yyr1[] = {     0,
    47,    47,    47,    47,    47,    47,    47,    48,    48,    48,
    49,    50,    50,    50,    50,    50,    50,    50,    50,    50,
    50,    50,    51,    51,    51,    51,    51,    51,    51,    51,
    51,    51,    51,    52,    52,    52,    53,    54,    54,    54,
    54,    54,    54,    55,    56,    57,    58,    59,    59,    60,
    60,    60,    60,    60,    60,    60,    60,    60,    60,    60,
    60,    61,    62,    63,    64,    64,    64,    64,    64,    64,
    64,    65,    66,    66,    66,    66,    66
};

static const short yyr2[] = {     0,
     1,     2,     2,     3,     2,     3,     1,     1,     2,     2,
     1,     1,     2,     3,     4,     2,     3,     4,     5,     1,
     1,     1,     2,     4,     1,     1,     1,     5,     5,     3,
     2,     3,     5,     3,     2,     2,     3,     1,     1,     1,
     1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
     1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
     1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
     1,     1,     1,     1,     1,     1,     1
};

static const short yydefact[] = {     0,
    44,    11,    20,    21,    22,     7,     8,     1,    12,     0,
     0,     0,     0,     9,    10,    63,    65,    66,    67,    68,
    69,    70,    71,    26,    27,    50,    51,    52,    53,    54,
    55,    56,    57,    58,    59,    60,    61,     2,     3,     5,
     0,     0,     0,     0,    25,    45,    13,    48,    49,    77,
    75,    73,    74,    76,    16,     0,    38,    39,    40,    41,
    42,    43,    35,    36,    72,     0,     0,     4,     6,    63,
    23,     0,     0,    31,     0,    17,    47,    14,    37,    34,
     0,     0,    62,    30,    64,    32,     0,    15,    18,    24,
     0,     0,     0,    19,    33,    29,    28,     0,     0,     0
};

static const short yydefgoto[] = {    98,
     6,     7,     8,    38,    14,    15,    63,     9,    47,    10,
    78,    55,    41,    42,    43,    44,    45,    66,    56
};

static const short yypact[] = {     8,
-32768,-32768,-32768,-32768,-32768,-32768,   -14,    43,    -4,     4,
    80,     5,     5,-32768,-32768,   -12,-32768,-32768,-32768,-32768,
-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
-32768,-32768,-32768,-32768,-32768,-32768,-32768,   -14,-32768,-32768,
    10,    -6,    81,    -8,-32768,-32768,-32768,-32768,-32768,-32768,
-32768,-32768,-32768,-32768,     9,    48,-32768,-32768,-32768,-32768,
-32768,-32768,-32768,-32768,-32768,    -2,    -2,-32768,-32768,-32768,
    25,    10,    63,    64,    63,-32768,-32768,     1,-32768,-32768,
    64,    26,-32768,    41,-32768,-32768,    44,-32768,     9,-32768,
    64,    64,    10,-32768,-32768,-32768,-32768,    85,    87,-32768
};

static const short yypgoto[] = {-32768,
-32768,-32768,-32768,-32768,    -5,     6,   -42,-32768,   -51,-32768,
-32768,    11,    54,   -10,   -41,     7,    95,   106,-32768
};


#define	YYLAST		122


static const short yytable[] = {    71,
   -46,   -46,    39,    76,    11,    48,    49,    65,    48,    49,
     1,     2,    70,    40,     3,     4,     5,    57,    58,    59,
    60,    61,    62,    79,    80,    12,    88,   -64,    13,   -62,
    82,    75,    68,    46,   -46,    72,   -46,    94,    46,   -46,
   -46,   -46,    50,    69,    51,    16,    46,    52,    53,    54,
    77,    97,    17,    18,    19,    20,    21,    22,    23,    24,
    25,    11,    84,    81,    87,    83,    85,    91,    26,    27,
    28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
    86,    92,    12,    93,    99,    13,   100,    90,    89,    17,
    18,    19,    20,    21,    22,    23,    74,    95,    96,    57,
    58,    59,    60,    61,    62,    64,    26,    27,    28,    29,
    30,    31,    32,    33,    34,    35,    36,    37,    67,     0,
     0,    73
};

static const short yycheck[] = {    41,
     5,     6,     8,    55,    19,     5,     6,     3,     5,     6,
     3,     4,     3,     8,     7,     8,     9,    20,    21,    22,
    23,    24,    25,    66,    67,    40,    78,    40,    43,    42,
    72,    40,    38,    38,    39,    42,    41,    89,    38,    44,
    45,    46,    39,    38,    41,     3,    38,    44,    45,    46,
     3,    93,    10,    11,    12,    13,    14,    15,    16,    17,
    18,    19,    73,    39,    75,     3,     3,    42,    26,    27,
    28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
    74,    41,    40,    40,     0,    43,     0,    81,    78,    10,
    11,    12,    13,    14,    15,    16,    43,    91,    92,    20,
    21,    22,    23,    24,    25,    11,    26,    27,    28,    29,
    30,    31,    32,    33,    34,    35,    36,    37,    13,    -1,
    -1,    41
};
/* -*-C-*-  Note some compilers choke on comments on `#line' lines.  */
#line 3 "/usr/lib/bison.simple"

/* Skeleton output parser for bison,
   Copyright (C) 1984, 1989, 1990 Bob Corbett and Richard Stallman

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 1, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */


#ifndef alloca
#ifdef __GNUC__
#define alloca __builtin_alloca
#else /* not GNU C.  */
#if (!defined (__STDC__) && defined (sparc)) || defined (__sparc__) || defined (__sparc) || defined (__sgi)
#include <alloca.h>
#else /* not sparc */
#if defined (MSDOS) && !defined (__TURBOC__)
#include <malloc.h>
#else /* not MSDOS, or __TURBOC__ */
#if defined(_AIX)
#include <malloc.h>
 #pragma alloca
#else /* not MSDOS, __TURBOC__, or _AIX */
#ifdef __hpux
#ifdef __cplusplus
extern "C" {
void *alloca (unsigned int);
};
#else /* not __cplusplus */
void *alloca ();
#endif /* not __cplusplus */
#endif /* __hpux */
#endif /* not _AIX */
#endif /* not MSDOS, or __TURBOC__ */
#endif /* not sparc.  */
#endif /* not GNU C.  */
#endif /* alloca not defined.  */

/* This is the parser code that is written into each bison parser
  when the %semantic_parser declaration is not specified in the grammar.
  It was written by Richard Stallman by simplifying the hairy parser
  used when %semantic_parser is specified.  */

/* Note: there must be only one dollar sign in this file.
   It is replaced by the list of actions, each action
   as one case of the switch.  */

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		-2
#define YYEOF		0
#define YYACCEPT	return(0)
#define YYABORT 	return(1)
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
#define YYLEX		yylex(&yylval, &yylloc)
#else
#define YYLEX		yylex(&yylval)
#endif
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

/* Prevent warning if -Wstrict-prototypes.  */
#ifdef __GNUC__
int yyparse (void);
#endif

#if __GNUC__ > 1		/* GNU C and GNU C++ define this.  */
#define __yy_bcopy(FROM,TO,COUNT)	__builtin_memcpy(TO,FROM,COUNT)
#else				/* not GNU C or C++ */
#ifndef __cplusplus

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
__yy_bcopy (from, to, count)
     char *from;
     char *to;
     int count;
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
__yy_bcopy (char *from, char *to, int count)
{
  register char *f = from;
  register char *t = to;
  register int i = count;

  while (i-- > 0)
    *t++ = *f++;
}

#endif
#endif

#line 184 "/usr/lib/bison.simple"
int
yyparse()
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
	  return 2;
	}
      yystacksize *= 2;
      if (yystacksize > YYMAXDEPTH)
	yystacksize = YYMAXDEPTH;
      yyss = (short *) alloca (yystacksize * sizeof (*yyssp));
      __yy_bcopy ((char *)yyss1, (char *)yyss, size * sizeof (*yyssp));
      yyvs = (YYSTYPE *) alloca (yystacksize * sizeof (*yyvsp));
      __yy_bcopy ((char *)yyvs1, (char *)yyvs, size * sizeof (*yyvsp));
#ifdef YYLSP_NEEDED
      yyls = (YYLTYPE *) alloca (yystacksize * sizeof (*yylsp));
      __yy_bcopy ((char *)yyls1, (char *)yyls, size * sizeof (*yylsp));
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
#line 40 "parsetime.y"
{
			time_only = 1;
		    ;
    break;}
case 20:
#line 68 "parsetime.y"
{
			exectm.tm_hour = 12;
			exectm.tm_min = 0;
		    ;
    break;}
case 21:
#line 73 "parsetime.y"
{
			exectm.tm_hour = 0;
			exectm.tm_min = 0;
			add_date(1, DAY);
		    ;
    break;}
case 22:
#line 79 "parsetime.y"
{
			exectm.tm_hour = 16;
			exectm.tm_min = 0;
		    ;
    break;}
case 25:
#line 88 "parsetime.y"
{
		       add_date ((7 + yyvsp[0].intval - exectm.tm_wday) %7, DAY);
		   ;
    break;}
case 27:
#line 93 "parsetime.y"
{
			add_date(1, DAY);
		   ;
    break;}
case 34:
#line 105 "parsetime.y"
{
		        add_date(yyvsp[-1].intval, yyvsp[0].intval);
		    ;
    break;}
case 35:
#line 109 "parsetime.y"
{
			add_date(1, yyvsp[0].intval);
		    ;
    break;}
case 36:
#line 113 "parsetime.y"
{
			add_date ((7 + yyvsp[0].intval - exectm.tm_wday) %7, DAY);
		    ;
    break;}
case 37:
#line 119 "parsetime.y"
{
			add_date(-yyvsp[-1].intval, yyvsp[0].intval);
		    ;
    break;}
case 38:
#line 124 "parsetime.y"
{ yyval.intval = MINUTE ; ;
    break;}
case 39:
#line 125 "parsetime.y"
{ yyval.intval = HOUR ; ;
    break;}
case 40:
#line 126 "parsetime.y"
{ yyval.intval = DAY ; ;
    break;}
case 41:
#line 127 "parsetime.y"
{ yyval.intval = WEEK ; ;
    break;}
case 42:
#line 128 "parsetime.y"
{ yyval.intval = MONTH ; ;
    break;}
case 43:
#line 129 "parsetime.y"
{ yyval.intval = YEAR ; ;
    break;}
case 44:
#line 133 "parsetime.y"
{
			exectm.tm_min = -1;
			exectm.tm_hour = -1;
			if (strlen(yyvsp[0].charval) == 4) {
			    sscanf(yyvsp[0].charval, "%2d %2d", &exectm.tm_hour,
				&exectm.tm_min);
			}
			else {
			    sscanf(yyvsp[0].charval, "%d", &exectm.tm_hour);
			    exectm.tm_min = 0;
			}
			free(yyvsp[0].charval);

			if (exectm.tm_min > 60 || exectm.tm_min < 0) {
			    yyerror("Problem in minutes specification");
			    YYERROR;
			}
			if (exectm.tm_hour > 24 || exectm.tm_hour < 0) {
			    yyerror("Problem in minutes specification");
			    YYERROR;
		        }
		    ;
    break;}
case 45:
#line 158 "parsetime.y"
{
			if (strcasecmp(yyvsp[0].charval,"utc") == 0) {
			    isgmt = 1;
			}
			else {
			    yyerror("Only UTC timezone is supported");
			    YYERROR;
			}
			free(yyvsp[0].charval);
		    ;
    break;}
case 47:
#line 174 "parsetime.y"
{
			if (sscanf(yyvsp[0].charval, "%d", &exectm.tm_min) != 1) {
			    yyerror("Error in minute");
			    YYERROR;
		        }
			free(yyvsp[0].charval);
		    ;
    break;}
case 49:
#line 185 "parsetime.y"
{
			if (exectm.tm_hour > 12) {
			    yyerror("Hour too large for PM");
			    YYERROR;
			}
			else if (exectm.tm_hour < 12) {
			    exectm.tm_hour +=12;
			}
		    ;
    break;}
case 50:
#line 197 "parsetime.y"
{ exectm.tm_mon = 0; ;
    break;}
case 51:
#line 198 "parsetime.y"
{ exectm.tm_mon = 1; ;
    break;}
case 52:
#line 199 "parsetime.y"
{ exectm.tm_mon = 2; ;
    break;}
case 53:
#line 200 "parsetime.y"
{ exectm.tm_mon = 3; ;
    break;}
case 54:
#line 201 "parsetime.y"
{ exectm.tm_mon = 4; ;
    break;}
case 55:
#line 202 "parsetime.y"
{ exectm.tm_mon = 5; ;
    break;}
case 56:
#line 203 "parsetime.y"
{ exectm.tm_mon = 6; ;
    break;}
case 57:
#line 204 "parsetime.y"
{ exectm.tm_mon = 7; ;
    break;}
case 58:
#line 205 "parsetime.y"
{ exectm.tm_mon = 8; ;
    break;}
case 59:
#line 206 "parsetime.y"
{ exectm.tm_mon = 9; ;
    break;}
case 60:
#line 207 "parsetime.y"
{ exectm.tm_mon =10; ;
    break;}
case 61:
#line 208 "parsetime.y"
{ exectm.tm_mon =11; ;
    break;}
case 62:
#line 212 "parsetime.y"
{
			{
			    int mnum = -1;
			    sscanf(yyvsp[0].charval, "%d", &mnum);

			    if (mnum < 1 || mnum > 12) {
				yyerror("Error in month number");
				YYERROR;
			    }
			    exectm.tm_mon = mnum -1;
			    free(yyvsp[0].charval);
			}
		    ;
    break;}
case 63:
#line 226 "parsetime.y"
{
			exectm.tm_mday = -1;
			sscanf(yyvsp[0].charval, "%d", &exectm.tm_mday);
			if (exectm.tm_mday < 0 || exectm.tm_mday > 31)
			{
			    yyerror("Error in day of month");
			    YYERROR; 
			}
			free(yyvsp[0].charval);
		     ;
    break;}
case 64:
#line 239 "parsetime.y"
{ 
			{
			    int ynum;

			    if ( sscanf(yyvsp[0].charval, "%d", &ynum) != 1) {
				yyerror("Error in year");
				YYERROR;
			    }
			    if (ynum < 70) {
				ynum += 100;
			    }
			    else if (ynum > 1900) {
				ynum -= 1900;
			    }

			    exectm.tm_year = ynum ;
			    free(yyvsp[0].charval);
			}
		    ;
    break;}
case 65:
#line 261 "parsetime.y"
{ yyval.intval = 0; ;
    break;}
case 66:
#line 262 "parsetime.y"
{ yyval.intval = 1; ;
    break;}
case 67:
#line 263 "parsetime.y"
{ yyval.intval = 2; ;
    break;}
case 68:
#line 264 "parsetime.y"
{ yyval.intval = 3; ;
    break;}
case 69:
#line 265 "parsetime.y"
{ yyval.intval = 4; ;
    break;}
case 70:
#line 266 "parsetime.y"
{ yyval.intval = 5; ;
    break;}
case 71:
#line 267 "parsetime.y"
{ yyval.intval = 6; ;
    break;}
case 72:
#line 271 "parsetime.y"
{
			if (sscanf(yyvsp[0].charval, "%d", &yyval.intval) != 1) {
			    yyerror("Unknown increment");
			    YYERROR;
		        }
		        free(yyvsp[0].charval);
		    ;
    break;}
}
   /* the action file gets copied in in place of this dollarsign */
#line 465 "/usr/lib/bison.simple"

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
}
#line 287 "parsetime.y"



time_t parsetime(int, char **);

time_t
parsetime(int argc, char **argv)
{
    time_t exectime;

    my_argv = argv;
    currtime = time(NULL);
    exectm = *localtime(&currtime);
    exectm.tm_sec = 0;
    exectm.tm_isdst = -1;
    time_only = 0;
    if (yyparse() == 0) {
	exectime = mktime(&exectm);
	if (isgmt) {
	    exectime += timezone;
	    if (daylight) {
		exectime -= 3600;
	    }
	}
	if (time_only && (currtime > exectime)) {
	    exectime += 24*3600;
	}
        return exectime;
    }
    else {
	return 0;    
    }
}

#ifdef TEST_PARSER
int
main(int argc, char **argv)
{
    time_t res;
    res = parsetime(argc-1, &argv[1]);
    if (res > 0) {
	printf("%s",ctime(&res));
    }
    else {
	printf("Ooops...\n");
    }
    return 0;
}

#endif
int yyerror(char *s)
{
    if (last_token == NULL)
	last_token = "(empty)";
    fprintf(stderr,"%s. Last token seen: %s\n",s, last_token);
    return 0;
}

void
add_seconds(struct tm *tm, long numsec)
{
    time_t timeval;
    timeval = mktime(tm);
    timeval += numsec;
    *tm = *localtime(&timeval);
}

int
add_date(int number, int period)
{
    switch(period) {
    case MINUTE:
	add_seconds(&exectm , 60l*number);
	break;

    case HOUR:
	add_seconds(&exectm, 3600l * number);
	break;

    case DAY:
	add_seconds(&exectm, 24*3600l * number);
	break;

    case WEEK:
	add_seconds(&exectm, 7*24*3600l*number);
	break;

    case MONTH:
	{
	    int newmonth = exectm.tm_mon + number;
	    number = 0;
	    while (newmonth < 0) {
		newmonth += 12;
		number --;
	    }
	    exectm.tm_mon = newmonth % 12;
	    number += newmonth / 12 ;
	}
	if (number == 0) {
	    break;
	}
	/* fall through */

    case YEAR:
	exectm.tm_year += number;
	break;

    default:
	yyerror("Internal parser error");
	fprintf(stderr,"Unexpected case %d\n", period);
	abort();
    }
    return 0;
}
