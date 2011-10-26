
/*  A Bison parser, made from ftpcmd.y
    by GNU Bison version 1.28  */

#define YYBISON 1  /* Identify Bison output.  */

#define	A	257
#define	B	258
#define	C	259
#define	E	260
#define	F	261
#define	I	262
#define	L	263
#define	N	264
#define	P	265
#define	R	266
#define	S	267
#define	T	268
#define	SP	269
#define	CRLF	270
#define	COMMA	271
#define	USER	272
#define	PASS	273
#define	ACCT	274
#define	REIN	275
#define	QUIT	276
#define	PORT	277
#define	PASV	278
#define	TYPE	279
#define	STRU	280
#define	MODE	281
#define	RETR	282
#define	STOR	283
#define	APPE	284
#define	MLFL	285
#define	MAIL	286
#define	MSND	287
#define	MSOM	288
#define	MSAM	289
#define	MRSQ	290
#define	MRCP	291
#define	ALLO	292
#define	REST	293
#define	RNFR	294
#define	RNTO	295
#define	ABOR	296
#define	DELE	297
#define	CWD	298
#define	LIST	299
#define	NLST	300
#define	SITE	301
#define	STAT	302
#define	HELP	303
#define	NOOP	304
#define	MKD	305
#define	RMD	306
#define	PWD	307
#define	CDUP	308
#define	STOU	309
#define	SMNT	310
#define	SYST	311
#define	SIZE	312
#define	MDTM	313
#define	UMASK	314
#define	IDLE	315
#define	CHMOD	316
#define	LEXERR	317
#define	STRING	318
#define	NUMBER	319

#line 37 "ftpcmd.y"


#ifndef lint
static char sccsid[] = "@(#)ftpcmd.y	8.3 (Berkeley) 4/6/94";
#endif /* not lint */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/ftp.h>

#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#include <unistd.h>
#include <limits.h>
#ifdef HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif
/* Include glob.h last, because it may define "const" which breaks
   system headers on some platforms. */
#include <glob.h>

#include "extern.h"

#if ! defined (NBBY) && defined (CHAR_BIT)
#define NBBY CHAR_BIT
#endif

off_t restart_point;

static char cbuf[512];           /* Command Buffer.  */
static char *fromname;
static int cmd_type;
static int cmd_form;
static int cmd_bytesz;

struct tab
{
  const char	*name;
  short	token;
  short	state;
  short	implemented;	/* 1 if command is implemented */
  const char	*help;
};

extern struct tab cmdtab[];
extern struct tab sitetab[];
static char *copy         __P ((char *));
static void help          __P ((struct tab *, char *));
static struct tab *lookup __P ((struct tab *, char *));
static void sizecmd       __P ((char *));
static int yylex          __P ((void));
static void yyerror       __P ((const char *s));


#line 117 "ftpcmd.y"
typedef union {
	int	i;
	char   *s;
} YYSTYPE;
#include <stdio.h>

#ifndef __cplusplus
#ifndef __STDC__
#define const
#endif
#endif



#define	YYFINAL		210
#define	YYFLAG		-32768
#define	YYNTBASE	66

#define YYTRANSLATE(x) ((unsigned)(x) <= 319 ? yytranslate[x] : 81)

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
    27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
    37,    38,    39,    40,    41,    42,    43,    44,    45,    46,
    47,    48,    49,    50,    51,    52,    53,    54,    55,    56,
    57,    58,    59,    60,    61,    62,    63,    64,    65
};

#if YYDEBUG != 0
static const short yyprhs[] = {     0,
     0,     1,     4,     7,    12,    17,    23,    27,    32,    37,
    42,    47,    56,    62,    68,    74,    78,    84,    88,    94,
   100,   103,   109,   115,   118,   122,   128,   131,   136,   139,
   145,   151,   155,   159,   164,   171,   177,   185,   195,   200,
   208,   214,   217,   223,   229,   232,   235,   241,   246,   248,
   249,   251,   253,   265,   267,   269,   271,   273,   277,   279,
   283,   285,   287,   291,   294,   296,   298,   300,   302,   304,
   306,   308,   310,   312
};

static const short yyrhs[] = {    -1,
    66,    67,     0,    66,    68,     0,    18,    15,    69,    16,
     0,    19,    15,    70,    16,     0,    23,    80,    15,    72,
    16,     0,    24,    80,    16,     0,    25,    15,    74,    16,
     0,    26,    15,    75,    16,     0,    27,    15,    76,    16,
     0,    38,    15,    65,    16,     0,    38,    15,    65,    15,
    12,    15,    65,    16,     0,    28,    80,    15,    77,    16,
     0,    29,    80,    15,    77,    16,     0,    30,    80,    15,
    77,    16,     0,    46,    80,    16,     0,    46,    80,    15,
    64,    16,     0,    45,    80,    16,     0,    45,    80,    15,
    77,    16,     0,    48,    80,    15,    77,    16,     0,    48,
    16,     0,    43,    80,    15,    77,    16,     0,    41,    80,
    15,    77,    16,     0,    42,    16,     0,    44,    80,    16,
     0,    44,    80,    15,    77,    16,     0,    49,    16,     0,
    49,    15,    64,    16,     0,    50,    16,     0,    51,    80,
    15,    77,    16,     0,    52,    80,    15,    77,    16,     0,
    53,    80,    16,     0,    54,    80,    16,     0,    47,    15,
    49,    16,     0,    47,    15,    49,    15,    64,    16,     0,
    47,    15,    60,    80,    16,     0,    47,    15,    60,    80,
    15,    79,    16,     0,    47,    15,    62,    80,    15,    79,
    15,    77,    16,     0,    47,    15,    61,    16,     0,    47,
    15,    80,    61,    15,    65,    16,     0,    55,    80,    15,
    77,    16,     0,    57,    16,     0,    58,    80,    15,    77,
    16,     0,    59,    80,    15,    77,    16,     0,    22,    16,
     0,     1,    16,     0,    40,    80,    15,    77,    16,     0,
    39,    15,    71,    16,     0,    64,     0,     0,    64,     0,
    65,     0,    65,    17,    65,    17,    65,    17,    65,    17,
    65,    17,    65,     0,    10,     0,    14,     0,     5,     0,
     3,     0,     3,    15,    73,     0,     6,     0,     6,    15,
    73,     0,     8,     0,     9,     0,     9,    15,    71,     0,
     9,    71,     0,     7,     0,    12,     0,    11,     0,    13,
     0,     4,     0,     5,     0,    78,     0,    64,     0,    65,
     0,     0
};

#endif

#if YYDEBUG != 0
static const short yyrline[] = { 0,
   152,   153,   160,   164,   169,   175,   197,   202,   237,   249,
   261,   265,   269,   276,   283,   290,   295,   302,   307,   314,
   321,   325,   332,   345,   349,   354,   361,   365,   382,   386,
   393,   400,   405,   410,   414,   420,   430,   445,   459,   465,
   481,   488,   534,   551,   573,   578,   584,   595,   610,   614,
   618,   622,   626,   640,   644,   648,   655,   660,   665,   670,
   675,   679,   684,   690,   698,   702,   706,   713,   717,   721,
   728,   765,   769,   796
};
#endif


#if YYDEBUG != 0 || defined (YYERROR_VERBOSE)

static const char * const yytname[] = {   "$","error","$undefined.","A","B",
"C","E","F","I","L","N","P","R","S","T","SP","CRLF","COMMA","USER","PASS","ACCT",
"REIN","QUIT","PORT","PASV","TYPE","STRU","MODE","RETR","STOR","APPE","MLFL",
"MAIL","MSND","MSOM","MSAM","MRSQ","MRCP","ALLO","REST","RNFR","RNTO","ABOR",
"DELE","CWD","LIST","NLST","SITE","STAT","HELP","NOOP","MKD","RMD","PWD","CDUP",
"STOU","SMNT","SYST","SIZE","MDTM","UMASK","IDLE","CHMOD","LEXERR","STRING",
"NUMBER","cmd_list","cmd","rcmd","username","password","byte_size","host_port",
"form_code","type_code","struct_code","mode_code","pathname","pathstring","octal_number",
"check_login", NULL
};
#endif

static const short yyr1[] = {     0,
    66,    66,    66,    67,    67,    67,    67,    67,    67,    67,
    67,    67,    67,    67,    67,    67,    67,    67,    67,    67,
    67,    67,    67,    67,    67,    67,    67,    67,    67,    67,
    67,    67,    67,    67,    67,    67,    67,    67,    67,    67,
    67,    67,    67,    67,    67,    67,    68,    68,    69,    70,
    70,    71,    72,    73,    73,    73,    74,    74,    74,    74,
    74,    74,    74,    74,    75,    75,    75,    76,    76,    76,
    77,    78,    79,    80
};

static const short yyr2[] = {     0,
     0,     2,     2,     4,     4,     5,     3,     4,     4,     4,
     4,     8,     5,     5,     5,     3,     5,     3,     5,     5,
     2,     5,     5,     2,     3,     5,     2,     4,     2,     5,
     5,     3,     3,     4,     6,     5,     7,     9,     4,     7,
     5,     2,     5,     5,     2,     2,     5,     4,     1,     0,
     1,     1,    11,     1,     1,     1,     1,     3,     1,     3,
     1,     1,     3,     2,     1,     1,     1,     1,     1,     1,
     1,     1,     1,     0
};

static const short yydefact[] = {     1,
     0,     0,     0,     0,     0,    74,    74,     0,     0,     0,
    74,    74,    74,     0,     0,    74,    74,     0,    74,    74,
    74,    74,     0,    74,     0,     0,    74,    74,    74,    74,
    74,     0,    74,    74,     2,     3,    46,     0,    50,    45,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,    24,     0,     0,     0,     0,     0,    21,     0,
     0,    27,    29,     0,     0,     0,     0,     0,    42,     0,
     0,    49,     0,    51,     0,     0,     7,    57,    59,    61,
    62,     0,    65,    67,    66,     0,    69,    70,    68,     0,
     0,     0,     0,     0,    52,     0,     0,     0,     0,     0,
    25,     0,    18,     0,    16,     0,    74,     0,    74,     0,
     0,     0,     0,     0,    32,    33,     0,     0,     0,     4,
     5,     0,     0,     0,     0,     0,    64,     8,     9,    10,
    72,     0,    71,     0,     0,     0,    11,    48,     0,     0,
     0,     0,     0,     0,     0,    34,     0,    39,     0,     0,
     0,    28,     0,     0,     0,     0,     0,     0,     6,    56,
    54,    55,    58,    60,    63,    13,    14,    15,     0,    47,
    23,    22,    26,    19,    17,     0,     0,    36,     0,     0,
    20,    30,    31,    41,    43,    44,     0,     0,    35,    73,
     0,     0,     0,     0,     0,    37,     0,    40,     0,    12,
     0,     0,    38,     0,     0,     0,     0,    53,     0,     0
};

static const short yydefgoto[] = {     1,
    35,    36,    73,    75,    96,   123,   163,    82,    86,    90,
   132,   133,   191,    41
};

static const short yypact[] = {-32768,
    42,    -7,     8,    20,    24,-32768,-32768,    44,    59,    62,
-32768,-32768,-32768,    83,    89,-32768,-32768,    47,-32768,-32768,
-32768,-32768,    97,    98,    16,    99,-32768,-32768,-32768,-32768,
-32768,   100,-32768,-32768,-32768,-32768,-32768,    49,    53,-32768,
   103,   104,    70,     6,     7,   106,   107,   108,    54,    60,
   112,   113,-32768,   114,    39,    41,    87,   -46,-32768,   115,
    67,-32768,-32768,   117,   118,   119,   120,   122,-32768,   123,
   124,-32768,   125,-32768,   126,    69,-32768,   128,   129,-32768,
   -13,   130,-32768,-32768,-32768,   131,-32768,-32768,-32768,   132,
    76,    76,    76,    91,-32768,   133,    76,    76,    76,    76,
-32768,    76,-32768,    81,-32768,    93,-32768,   134,-32768,    90,
    76,   136,    76,    76,-32768,-32768,    76,    76,    76,-32768,
-32768,   137,   139,    48,    48,    60,-32768,-32768,-32768,-32768,
-32768,   140,-32768,   141,   142,   147,-32768,-32768,   144,   145,
   146,   148,   149,   150,   105,-32768,    95,-32768,   138,   152,
   154,-32768,   155,   156,   157,   158,   159,   111,-32768,-32768,
-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,   153,-32768,
-32768,-32768,-32768,-32768,-32768,   161,   116,-32768,   116,   121,
-32768,-32768,-32768,-32768,-32768,-32768,   162,   127,-32768,-32768,
   164,   163,   166,   135,   167,-32768,    76,-32768,   168,-32768,
   171,   143,-32768,   172,   151,   173,   160,-32768,   184,-32768
};

static const short yypgoto[] = {-32768,
-32768,-32768,-32768,-32768,   -77,-32768,    38,-32768,-32768,-32768,
   -92,-32768,     9,    17
};


#define	YYLAST		225


static const short yytable[] = {   134,
   135,   126,   106,   127,   139,   140,   141,   142,    37,   143,
    87,    88,    83,   107,   108,   109,    84,    85,   151,    89,
   153,   154,    38,    42,   155,   156,   157,    46,    47,    48,
    61,    62,    51,    52,    39,    54,    55,    56,    57,    40,
    60,   209,     2,    64,    65,    66,    67,    68,   165,    70,
    71,    95,   160,   100,   101,   102,   103,   161,    43,     3,
     4,   162,    53,     5,     6,     7,     8,     9,    10,    11,
    12,    13,    78,    44,   110,    79,    45,    80,    81,    14,
    15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
    25,    26,    27,    28,    29,    30,    31,    49,    32,    33,
    34,   104,   105,    50,   201,   136,   137,   145,   146,   177,
   178,    58,    72,    59,    63,    69,    74,    76,    94,    77,
    91,    92,    93,   147,    95,   149,    97,    98,    99,   111,
   112,   113,   114,   122,   115,   116,   117,   118,   119,   131,
   120,   121,   124,   125,   144,   128,   129,   130,   138,   148,
   150,   152,   179,   158,   159,   166,   167,   168,   169,   170,
   171,   172,   164,   173,   174,   175,   180,   188,   176,   181,
   182,   183,   184,   185,   186,   187,   189,   197,   194,   196,
   190,   198,   200,   210,   202,   193,   203,   192,   205,   207,
     0,   195,     0,     0,     0,     0,     0,     0,     0,   199,
     0,     0,     0,     0,     0,     0,     0,   204,     0,     0,
     0,     0,     0,     0,     0,   206,     0,     0,     0,     0,
     0,     0,     0,     0,   208
};

static const short yycheck[] = {    92,
    93,    15,    49,    81,    97,    98,    99,   100,    16,   102,
     4,     5,     7,    60,    61,    62,    11,    12,   111,    13,
   113,   114,    15,     7,   117,   118,   119,    11,    12,    13,
    15,    16,    16,    17,    15,    19,    20,    21,    22,    16,
    24,     0,     1,    27,    28,    29,    30,    31,   126,    33,
    34,    65,     5,    15,    16,    15,    16,    10,    15,    18,
    19,    14,    16,    22,    23,    24,    25,    26,    27,    28,
    29,    30,     3,    15,    58,     6,    15,     8,     9,    38,
    39,    40,    41,    42,    43,    44,    45,    46,    47,    48,
    49,    50,    51,    52,    53,    54,    55,    15,    57,    58,
    59,    15,    16,    15,   197,    15,    16,    15,    16,    15,
    16,    15,    64,    16,    16,    16,    64,    15,    65,    16,
    15,    15,    15,   107,    65,   109,    15,    15,    15,    15,
    64,    15,    15,    65,    16,    16,    15,    15,    15,    64,
    16,    16,    15,    15,    64,    16,    16,    16,    16,    16,
    61,    16,    15,    17,    16,    16,    16,    16,    12,    16,
    16,    16,   125,    16,    16,    16,    15,    15,    64,    16,
    16,    16,    16,    16,    16,    65,    16,    15,    17,    16,
    65,    16,    16,     0,    17,    65,    16,   179,    17,    17,
    -1,    65,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    65,
    -1,    -1,    -1,    -1,    -1,    -1,    -1,    65,    -1,    -1,
    -1,    -1,    -1,    -1,    -1,    65,    -1,    -1,    -1,    -1,
    -1,    -1,    -1,    -1,    65
};
/* -*-C-*-  Note some compilers choke on comments on `#line' lines.  */
#line 3 "/usr/share/bison/bison.simple"
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

#line 217 "/usr/share/bison/bison.simple"

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

case 2:
#line 154 "ftpcmd.y"
{
			if (fromname != NULL)
				free (fromname);
			fromname = (char *) 0;
			restart_point = (off_t) 0;
		;
    break;}
case 4:
#line 165 "ftpcmd.y"
{
			user(yyvsp[-1].s);
			free(yyvsp[-1].s);
		;
    break;}
case 5:
#line 170 "ftpcmd.y"
{
			pass(yyvsp[-1].s);
			memset (yyvsp[-1].s, 0, strlen (yyvsp[-1].s));
			free(yyvsp[-1].s);
		;
    break;}
case 6:
#line 176 "ftpcmd.y"
{
			usedefault = 0;
			if (pdata >= 0) {
				(void) close(pdata);
				pdata = -1;
			}
			if (yyvsp[-3].i) {
				if (memcmp (&his_addr.sin_addr,
					&data_dest.sin_addr,
					sizeof (data_dest.sin_addr)) == 0 &&
					ntohs (data_dest.sin_port) >
					IPPORT_RESERVED) {
					reply (200, "PORT command sucessful.");
				}
				else {
					memset (&data_dest, 0,
						sizeof (data_dest));
					reply(500, "Illegal PORT Command");
				}
			}
		;
    break;}
case 7:
#line 198 "ftpcmd.y"
{
			if (yyvsp[-1].i)
				passive();
		;
    break;}
case 8:
#line 203 "ftpcmd.y"
{
			switch (cmd_type) {

			case TYPE_A:
				if (cmd_form == FORM_N) {
					reply(200, "Type set to A.");
					type = cmd_type;
					form = cmd_form;
				} else
					reply(504, "Form must be N.");
				break;

			case TYPE_E:
				reply(504, "Type E not implemented.");
				break;

			case TYPE_I:
				reply(200, "Type set to I.");
				type = cmd_type;
				break;

			case TYPE_L:
#if defined (NBBY) && NBBY == 8
				if (cmd_bytesz == 8) {
					reply(200,
					    "Type set to L (byte size 8).");
					type = cmd_type;
				} else
					reply(504, "Byte size must be 8.");
#else /* NBBY == 8 */
				UNIMPLEMENTED for NBBY != 8
#endif /* NBBY == 8 */
			}
		;
    break;}
case 9:
#line 238 "ftpcmd.y"
{
			switch (yyvsp[-1].i) {

			case STRU_F:
				reply(200, "STRU F ok.");
				break;

			default:
				reply(504, "Unimplemented STRU type.");
			}
		;
    break;}
case 10:
#line 250 "ftpcmd.y"
{
			switch (yyvsp[-1].i) {

			case MODE_S:
				reply(200, "MODE S ok.");
				break;

			default:
				reply(502, "Unimplemented MODE type.");
			}
		;
    break;}
case 11:
#line 262 "ftpcmd.y"
{
			reply(202, "ALLO command ignored.");
		;
    break;}
case 12:
#line 266 "ftpcmd.y"
{
			reply(202, "ALLO command ignored.");
		;
    break;}
case 13:
#line 270 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				retrieve((char *) 0, yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		;
    break;}
case 14:
#line 277 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				store(yyvsp[-1].s, "w", 0);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		;
    break;}
case 15:
#line 284 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				store(yyvsp[-1].s, "a", 0);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		;
    break;}
case 16:
#line 291 "ftpcmd.y"
{
			if (yyvsp[-1].i)
				send_file_list(".");
		;
    break;}
case 17:
#line 296 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				send_file_list(yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		;
    break;}
case 18:
#line 303 "ftpcmd.y"
{
			if (yyvsp[-1].i)
				retrieve("/bin/ls -lgA", "");
		;
    break;}
case 19:
#line 308 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				retrieve("/bin/ls -lgA %s", yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		;
    break;}
case 20:
#line 315 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				statfilecmd(yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		;
    break;}
case 21:
#line 322 "ftpcmd.y"
{
			statcmd();
		;
    break;}
case 22:
#line 326 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				delete(yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		;
    break;}
case 23:
#line 333 "ftpcmd.y"
{
		    if (yyvsp[-3].i) {
			if (fromname) {
				renamecmd(fromname, yyvsp[-1].s);
				free(fromname);
				fromname = (char *) 0;
			} else {
				reply(503, "Bad sequence of commands.");
			}
		    }
		    free (yyvsp[-1].s);
		;
    break;}
case 24:
#line 346 "ftpcmd.y"
{
			reply(225, "ABOR command successful.");
		;
    break;}
case 25:
#line 350 "ftpcmd.y"
{
			if (yyvsp[-1].i)
				cwd(cred.homedir);
		;
    break;}
case 26:
#line 355 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				cwd(yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		;
    break;}
case 27:
#line 362 "ftpcmd.y"
{
			help(cmdtab, (char *) 0);
		;
    break;}
case 28:
#line 366 "ftpcmd.y"
{
			char *cp = yyvsp[-1].s;

			if (strncasecmp(cp, "SITE", 4) == 0) {
				cp = yyvsp[-1].s + 4;
				if (*cp == ' ')
					cp++;
				if (*cp)
					help(sitetab, cp);
				else
					help(sitetab, (char *) 0);
			} else
				help(cmdtab, yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
			    free (yyvsp[-1].s);
		;
    break;}
case 29:
#line 383 "ftpcmd.y"
{
			reply(200, "NOOP command successful.");
		;
    break;}
case 30:
#line 387 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				makedir(yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		;
    break;}
case 31:
#line 394 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				removedir(yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		;
    break;}
case 32:
#line 401 "ftpcmd.y"
{
			if (yyvsp[-1].i)
				pwd();
		;
    break;}
case 33:
#line 406 "ftpcmd.y"
{
			if (yyvsp[-1].i)
				cwd("..");
		;
    break;}
case 34:
#line 411 "ftpcmd.y"
{
			help(sitetab, (char *) 0);
		;
    break;}
case 35:
#line 415 "ftpcmd.y"
{
			help(sitetab, yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
			    free (yyvsp[-1].s);
		;
    break;}
case 36:
#line 421 "ftpcmd.y"
{
			int oldmask;

			if (yyvsp[-1].i) {
				oldmask = umask(0);
				(void) umask(oldmask);
				reply(200, "Current UMASK is %03o", oldmask);
			}
		;
    break;}
case 37:
#line 431 "ftpcmd.y"
{
			int oldmask;

			if (yyvsp[-3].i) {
				if ((yyvsp[-1].i == -1) || (yyvsp[-1].i > 0777)) {
					reply(501, "Bad UMASK value");
				} else {
					oldmask = umask(yyvsp[-1].i);
					reply(200,
					    "UMASK set to %03o (was %03o)",
					    yyvsp[-1].i, oldmask);
				}
			}
		;
    break;}
case 38:
#line 446 "ftpcmd.y"
{
			if (yyvsp[-5].i && (yyvsp[-1].s != NULL)) {
				if (yyvsp[-3].i > 0777)
					reply(501,
				"CHMOD: Mode value must be between 0 and 0777");
				else if (chmod(yyvsp[-1].s, yyvsp[-3].i) < 0)
					perror_reply(550, yyvsp[-1].s);
				else
					reply(200, "CHMOD command successful.");
			}
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		;
    break;}
case 39:
#line 460 "ftpcmd.y"
{
			reply(200,
			    "Current IDLE time limit is %d seconds; max %d",
				timeout, maxtimeout);
		;
    break;}
case 40:
#line 466 "ftpcmd.y"
{
		    	if (yyvsp[-4].i) {
			    if (yyvsp[-1].i < 30 || yyvsp[-1].i > maxtimeout) {
				reply (501,
			"Maximum IDLE time must be between 30 and %d seconds",
					maxtimeout);
			    } else {
				timeout = yyvsp[-1].i;
				(void) alarm((unsigned) timeout);
				reply(200,
					"Maximum IDLE time set to %d seconds",
					timeout);
			    }
			}
		;
    break;}
case 41:
#line 482 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				store(yyvsp[-1].s, "w", 1);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		;
    break;}
case 42:
#line 489 "ftpcmd.y"
{
		        const char *sys_type; /* Official rfc-defined os type.  */
			char *version = 0; /* A more specific type. */

#ifdef HAVE_UNAME
			struct utsname u;
			if (uname (&u) == 0) {
				version =
				  malloc (strlen (u.sysname)
					  + 1 + strlen (u.release) + 1);
				if (version)
					sprintf (version, "%s %s",
						 u.sysname, u.release);
		        }
#else
#ifdef BSD
			version = "BSD";
#endif
#endif

#ifdef unix
			sys_type = "UNIX";
#else
			sys_type = "UNKNOWN";
#endif

			if (version)
				reply(215, "%s Type: L%d Version: %s",
				      sys_type, NBBY, version);
			else
				reply(215, "%s Type: L%d", sys_type, NBBY);

#ifdef HAVE_UNAME
			if (version)
				free (version);
#endif
		;
    break;}
case 43:
#line 535 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				sizecmd(yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		;
    break;}
case 44:
#line 552 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL) {
				struct stat stbuf;
				if (stat(yyvsp[-1].s, &stbuf) < 0)
					reply(550, "%s: %s",
					    yyvsp[-1].s, strerror(errno));
				else if (!S_ISREG(stbuf.st_mode)) {
					reply(550, "%s: not a plain file.", yyvsp[-1].s);
				} else {
					struct tm *t;
					t = gmtime(&stbuf.st_mtime);
					reply(213,
					    "%04d%02d%02d%02d%02d%02d",
					    1900 + t->tm_year, t->tm_mon+1,
					    t->tm_mday, t->tm_hour, t->tm_min,
					    t->tm_sec);
				}
			}
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		;
    break;}
case 45:
#line 574 "ftpcmd.y"
{
			reply(221, "Goodbye.");
			dologout(0);
		;
    break;}
case 46:
#line 579 "ftpcmd.y"
{
			yyerrok;
		;
    break;}
case 47:
#line 585 "ftpcmd.y"
{
			restart_point = (off_t) 0;
			if (yyvsp[-3].i && yyvsp[-1].s) {
			    if (fromname != NULL)
				free (fromname);
			    fromname = renamefrom(yyvsp[-1].s);
			}
			if (fromname == (char *) 0 && yyvsp[-1].s)
			    free(yyvsp[-1].s);
		;
    break;}
case 48:
#line 596 "ftpcmd.y"
{
		    	if (fromname != NULL)
				free (fromname);
			fromname = (char *) 0;
			restart_point = yyvsp[-1].i;	/* XXX $3 is only "int" */
			reply(350,
			      (sizeof(restart_point) > sizeof(long)
			       ? "Restarting at %qd. %s"
			       : "Restarting at %ld. %s"), restart_point,
			    "Send STORE or RETRIEVE to initiate transfer.");
		;
    break;}
case 50:
#line 615 "ftpcmd.y"
{
			yyval.s = (char *)calloc(1, sizeof(char));
		;
    break;}
case 53:
#line 628 "ftpcmd.y"
{
			char *a, *p;

			a = (char *)&data_dest.sin_addr;
			a[0] = yyvsp[-10].i; a[1] = yyvsp[-8].i; a[2] = yyvsp[-6].i; a[3] = yyvsp[-4].i;
			p = (char *)&data_dest.sin_port;
			p[0] = yyvsp[-2].i; p[1] = yyvsp[0].i;
			data_dest.sin_family = AF_INET;
		;
    break;}
case 54:
#line 641 "ftpcmd.y"
{
			yyval.i = FORM_N;
		;
    break;}
case 55:
#line 645 "ftpcmd.y"
{
			yyval.i = FORM_T;
		;
    break;}
case 56:
#line 649 "ftpcmd.y"
{
			yyval.i = FORM_C;
		;
    break;}
case 57:
#line 656 "ftpcmd.y"
{
			cmd_type = TYPE_A;
			cmd_form = FORM_N;
		;
    break;}
case 58:
#line 661 "ftpcmd.y"
{
			cmd_type = TYPE_A;
			cmd_form = yyvsp[0].i;
		;
    break;}
case 59:
#line 666 "ftpcmd.y"
{
			cmd_type = TYPE_E;
			cmd_form = FORM_N;
		;
    break;}
case 60:
#line 671 "ftpcmd.y"
{
			cmd_type = TYPE_E;
			cmd_form = yyvsp[0].i;
		;
    break;}
case 61:
#line 676 "ftpcmd.y"
{
			cmd_type = TYPE_I;
		;
    break;}
case 62:
#line 680 "ftpcmd.y"
{
			cmd_type = TYPE_L;
			cmd_bytesz = NBBY;
		;
    break;}
case 63:
#line 685 "ftpcmd.y"
{
			cmd_type = TYPE_L;
			cmd_bytesz = yyvsp[0].i;
		;
    break;}
case 64:
#line 691 "ftpcmd.y"
{
			cmd_type = TYPE_L;
			cmd_bytesz = yyvsp[0].i;
		;
    break;}
case 65:
#line 699 "ftpcmd.y"
{
			yyval.i = STRU_F;
		;
    break;}
case 66:
#line 703 "ftpcmd.y"
{
			yyval.i = STRU_R;
		;
    break;}
case 67:
#line 707 "ftpcmd.y"
{
			yyval.i = STRU_P;
		;
    break;}
case 68:
#line 714 "ftpcmd.y"
{
			yyval.i = MODE_S;
		;
    break;}
case 69:
#line 718 "ftpcmd.y"
{
			yyval.i = MODE_B;
		;
    break;}
case 70:
#line 722 "ftpcmd.y"
{
			yyval.i = MODE_C;
		;
    break;}
case 71:
#line 729 "ftpcmd.y"
{
			/*
			 * Problem: this production is used for all pathname
			 * processing, but only gives a 550 error reply.
			 * This is a valid reply in some cases but not in others.
			 */
			if (cred.logged_in && yyvsp[0].s && *yyvsp[0].s == '~') {
				glob_t gl;
				int flags = GLOB_NOCHECK;

#ifdef GLOB_BRACE
				flags |= GLOB_BRACE;
#endif
#ifdef GLOB_QUOTE
				flags |= GLOB_QUOTE;
#endif
#ifdef GLOB_TILDE
				flags |= GLOB_TILDE;
#endif

				memset(&gl, 0, sizeof(gl));
				if (glob(yyvsp[0].s, flags, NULL, &gl) ||
				    gl.gl_pathc == 0) {
					reply(550, "not found");
					yyval.s = NULL;
				} else {
					yyval.s = strdup(gl.gl_pathv[0]);
				}
				globfree(&gl);
				free(yyvsp[0].s);
			} else
				yyval.s = yyvsp[0].s;
		;
    break;}
case 73:
#line 770 "ftpcmd.y"
{
			int ret, dec, multby, digit;

			/*
			 * Convert a number that was read as decimal number
			 * to what it would be if it had been read as octal.
			 */
			dec = yyvsp[0].i;
			multby = 1;
			ret = 0;
			while (dec) {
				digit = dec%10;
				if (digit > 7) {
					ret = -1;
					break;
				}
				ret += digit * multby;
				multby *= 8;
				dec /= 10;
			}
			yyval.i = ret;
		;
    break;}
case 74:
#line 797 "ftpcmd.y"
{
			if (cred.logged_in)
				yyval.i = 1;
			else {
				reply(530, "Please login with USER and PASS.");
				yyval.i = 0;
			}
		;
    break;}
}
   /* the action file gets copied in in place of this dollarsign */
#line 543 "/usr/share/bison/bison.simple"

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
#line 807 "ftpcmd.y"


#define	CMD	0	/* beginning of command */
#define	ARGS	1	/* expect miscellaneous arguments */
#define	STR1	2	/* expect SP followed by STRING */
#define	STR2	3	/* expect STRING */
#define	OSTR	4	/* optional SP then STRING */
#define	ZSTR1	5	/* SP then optional STRING */
#define	ZSTR2	6	/* optional STRING after SP */
#define	SITECMD	7	/* SITE command */
#define	NSTR	8	/* Number followed by a string */

struct tab cmdtab[] = {		/* In order defined in RFC 765 */
	{ "USER", USER, STR1, 1,	"<sp> username" },
	{ "PASS", PASS, ZSTR1, 1,	"<sp> password" },
	{ "ACCT", ACCT, STR1, 0,	"(specify account)" },
	{ "SMNT", SMNT, ARGS, 0,	"(structure mount)" },
	{ "REIN", REIN, ARGS, 0,	"(reinitialize server state)" },
	{ "QUIT", QUIT, ARGS, 1,	"(terminate service)", },
	{ "PORT", PORT, ARGS, 1,	"<sp> b0, b1, b2, b3, b4" },
	{ "PASV", PASV, ARGS, 1,	"(set server in passive mode)" },
	{ "TYPE", TYPE, ARGS, 1,	"<sp> [ A | E | I | L ]" },
	{ "STRU", STRU, ARGS, 1,	"(specify file structure)" },
	{ "MODE", MODE, ARGS, 1,	"(specify transfer mode)" },
	{ "RETR", RETR, STR1, 1,	"<sp> file-name" },
	{ "STOR", STOR, STR1, 1,	"<sp> file-name" },
	{ "APPE", APPE, STR1, 1,	"<sp> file-name" },
	{ "MLFL", MLFL, OSTR, 0,	"(mail file)" },
	{ "MAIL", MAIL, OSTR, 0,	"(mail to user)" },
	{ "MSND", MSND, OSTR, 0,	"(mail send to terminal)" },
	{ "MSOM", MSOM, OSTR, 0,	"(mail send to terminal or mailbox)" },
	{ "MSAM", MSAM, OSTR, 0,	"(mail send to terminal and mailbox)" },
	{ "MRSQ", MRSQ, OSTR, 0,	"(mail recipient scheme question)" },
	{ "MRCP", MRCP, STR1, 0,	"(mail recipient)" },
	{ "ALLO", ALLO, ARGS, 1,	"allocate storage (vacuously)" },
	{ "REST", REST, ARGS, 1,	"<sp> offset (restart command)" },
	{ "RNFR", RNFR, STR1, 1,	"<sp> file-name" },
	{ "RNTO", RNTO, STR1, 1,	"<sp> file-name" },
	{ "ABOR", ABOR, ARGS, 1,	"(abort operation)" },
	{ "DELE", DELE, STR1, 1,	"<sp> file-name" },
	{ "CWD",  CWD,  OSTR, 1,	"[ <sp> directory-name ]" },
	{ "XCWD", CWD,	OSTR, 1,	"[ <sp> directory-name ]" },
	{ "LIST", LIST, OSTR, 1,	"[ <sp> path-name ]" },
	{ "NLST", NLST, OSTR, 1,	"[ <sp> path-name ]" },
	{ "SITE", SITE, SITECMD, 1,	"site-cmd [ <sp> arguments ]" },
	{ "SYST", SYST, ARGS, 1,	"(get type of operating system)" },
	{ "STAT", STAT, OSTR, 1,	"[ <sp> path-name ]" },
	{ "HELP", HELP, OSTR, 1,	"[ <sp> <string> ]" },
	{ "NOOP", NOOP, ARGS, 1,	"" },
	{ "MKD",  MKD,  STR1, 1,	"<sp> path-name" },
	{ "XMKD", MKD,  STR1, 1,	"<sp> path-name" },
	{ "RMD",  RMD,  STR1, 1,	"<sp> path-name" },
	{ "XRMD", RMD,  STR1, 1,	"<sp> path-name" },
	{ "PWD",  PWD,  ARGS, 1,	"(return current directory)" },
	{ "XPWD", PWD,  ARGS, 1,	"(return current directory)" },
	{ "CDUP", CDUP, ARGS, 1,	"(change to parent directory)" },
	{ "XCUP", CDUP, ARGS, 1,	"(change to parent directory)" },
	{ "STOU", STOU, STR1, 1,	"<sp> file-name" },
	{ "SIZE", SIZE, OSTR, 1,	"<sp> path-name" },
	{ "MDTM", MDTM, OSTR, 1,	"<sp> path-name" },
	{ NULL,   0,    0,    0,	0 }
};

struct tab sitetab[] = {
	{ "UMASK", UMASK, ARGS, 1,	"[ <sp> umask ]" },
	{ "IDLE", IDLE, ARGS, 1,	"[ <sp> maximum-idle-time ]" },
	{ "CHMOD", CHMOD, NSTR, 1,	"<sp> mode <sp> file-name" },
	{ "HELP", HELP, OSTR, 1,	"[ <sp> <string> ]" },
	{ NULL,   0,    0,    0,	0 }
};

static struct tab *
lookup(p, cmd)
	struct tab *p;
	char *cmd;
{

	for (; p->name != NULL; p++)
		if (strcmp(cmd, p->name) == 0)
			return (p);
	return (0);
}

#include <arpa/telnet.h>

/*
 * getline - a hacked up version of fgets to ignore TELNET escape codes.
 */
char *
telnet_fgets(char *s, int n, FILE *iop)
{
	int c;
	register char *cs;

	cs = s;
/* tmpline may contain saved command from urgent mode interruption */
	for (c = 0; tmpline[c] != '\0' && --n > 0; ++c) {
		*cs++ = tmpline[c];
		if (tmpline[c] == '\n') {
			*cs++ = '\0';
			if (debug)
				syslog(LOG_DEBUG, "command: %s", s);
			tmpline[0] = '\0';
			return(s);
		}
		if (c == 0)
			tmpline[0] = '\0';
	}
	while ((c = getc(iop)) != EOF) {
		c &= 0377;
		if (c == IAC) {
		    if ((c = getc(iop)) != EOF) {
			c &= 0377;
			switch (c) {
			case WILL:
			case WONT:
				c = getc(iop);
				printf("%c%c%c", IAC, DONT, 0377&c);
				(void) fflush(stdout);
				continue;
			case DO:
			case DONT:
				c = getc(iop);
				printf("%c%c%c", IAC, WONT, 0377&c);
				(void) fflush(stdout);
				continue;
			case IAC:
				break;
			default:
				continue;	/* ignore command */
			}
		    }
		}
		*cs++ = c;
		if (--n <= 0 || c == '\n')
			break;
	}
	if (c == EOF && cs == s)
	    return (NULL);
	*cs++ = '\0';
	if (debug) {
		if (!cred.guest && strncasecmp("pass ", s, 5) == 0) {
			/* Don't syslog passwords */
			syslog(LOG_DEBUG, "command: %.5s ???", s);
		} else {
			register char *cp;
			register int len;

			/* Don't syslog trailing CR-LF */
			len = strlen(s);
			cp = s + len - 1;
			while (cp >= s && (*cp == '\n' || *cp == '\r')) {
				--cp;
				--len;
			}
			syslog(LOG_DEBUG, "command: %.*s", len, s);
		}
	}
	return (s);
}

void
toolong(int signo)
{
  (void)signo;
	reply(421,
	    "Timeout (%d seconds): closing control connection.", timeout);
	if (logging)
		syslog(LOG_INFO, "User %s timed out after %d seconds",
		    (cred.name ? cred.name : "unknown"), timeout);
	dologout(1);
}

static int
yylex()
{
	static int cpos, state;
	char *cp, *cp2;
	struct tab *p;
	int n;
	char c;

	for (;;) {
		switch (state) {

		case CMD:
			(void) signal(SIGALRM, toolong);
			(void) alarm((unsigned) timeout);
			if (telnet_fgets(cbuf, sizeof(cbuf)-1, stdin) == NULL) {
				reply(221, "You could at least say goodbye.");
				dologout(0);
			}
			(void) alarm(0);
#ifdef HAVE_SETPROCTITLE
			if (strncasecmp(cbuf, "PASS", 4) != NULL)
				setproctitle("%s: %s", proctitle, cbuf);
#endif /* HAVE_SETPROCTITLE */
			if ((cp = strchr(cbuf, '\r'))) {
				*cp++ = '\n';
				*cp = '\0';
			}
			if ((cp = strpbrk(cbuf, " \n")))
				cpos = cp - cbuf;
			if (cpos == 0)
				cpos = 4;
			c = cbuf[cpos];
			cbuf[cpos] = '\0';
			upper(cbuf);
			p = lookup(cmdtab, cbuf);
			cbuf[cpos] = c;
			if (p != 0) {
				if (p->implemented == 0) {
					nack(p->name);
					longjmp(errcatch,0);
					/* NOTREACHED */
				}
				state = p->state;
				yylval.s = p->name;
				return (p->token);
			}
			break;

		case SITECMD:
			if (cbuf[cpos] == ' ') {
				cpos++;
				return (SP);
			}
			cp = &cbuf[cpos];
			if ((cp2 = strpbrk(cp, " \n")))
				cpos = cp2 - cbuf;
			c = cbuf[cpos];
			cbuf[cpos] = '\0';
			upper(cp);
			p = lookup(sitetab, cp);
			cbuf[cpos] = c;
			if (p != 0) {
				if (p->implemented == 0) {
					state = CMD;
					nack(p->name);
					longjmp(errcatch,0);
					/* NOTREACHED */
				}
				state = p->state;
				yylval.s = p->name;
				return (p->token);
			}
			state = CMD;
			break;

		case OSTR:
			if (cbuf[cpos] == '\n') {
				state = CMD;
				return (CRLF);
			}
			/* FALLTHROUGH */

		case STR1:
		case ZSTR1:
		dostr1:
			if (cbuf[cpos] == ' ') {
				cpos++;
				state = state == OSTR ? STR2 : ++state;
				return (SP);
			}
			break;

		case ZSTR2:
			if (cbuf[cpos] == '\n') {
				state = CMD;
				return (CRLF);
			}
			/* FALLTHROUGH */

		case STR2:
			cp = &cbuf[cpos];
			n = strlen(cp);
			cpos += n - 1;
			/*
			 * Make sure the string is nonempty and \n terminated.
			 */
			if (n > 1 && cbuf[cpos] == '\n') {
				cbuf[cpos] = '\0';
				yylval.s = copy(cp);
				cbuf[cpos] = '\n';
				state = ARGS;
				return (STRING);
			}
			break;

		case NSTR:
			if (cbuf[cpos] == ' ') {
				cpos++;
				return (SP);
			}
			if (isdigit(cbuf[cpos])) {
				cp = &cbuf[cpos];
				while (isdigit(cbuf[++cpos]))
					;
				c = cbuf[cpos];
				cbuf[cpos] = '\0';
				yylval.i = atoi(cp);
				cbuf[cpos] = c;
				state = STR1;
				return (NUMBER);
			}
			state = STR1;
			goto dostr1;

		case ARGS:
			if (isdigit(cbuf[cpos])) {
				cp = &cbuf[cpos];
				while (isdigit(cbuf[++cpos]))
					;
				c = cbuf[cpos];
				cbuf[cpos] = '\0';
				yylval.i = atoi(cp);
				cbuf[cpos] = c;
				return (NUMBER);
			}
			switch (cbuf[cpos++]) {

			case '\n':
				state = CMD;
				return (CRLF);

			case ' ':
				return (SP);

			case ',':
				return (COMMA);

			case 'A':
			case 'a':
				return (A);

			case 'B':
			case 'b':
				return (B);

			case 'C':
			case 'c':
				return (C);

			case 'E':
			case 'e':
				return (E);

			case 'F':
			case 'f':
				return (F);

			case 'I':
			case 'i':
				return (I);

			case 'L':
			case 'l':
				return (L);

			case 'N':
			case 'n':
				return (N);

			case 'P':
			case 'p':
				return (P);

			case 'R':
			case 'r':
				return (R);

			case 'S':
			case 's':
				return (S);

			case 'T':
			case 't':
				return (T);

			}
			break;

		default:
			fatal("Unknown state in scanner.");
		}
		yyerror((char *) 0);
		state = CMD;
		longjmp(errcatch,0);
	}
}

void
upper(char *s)
{
	while (*s != '\0') {
		if (islower(*s))
			*s = toupper(*s);
		s++;
	}
}

static char *
copy(char *s)
{
	char *p;

	p = malloc((unsigned) strlen(s) + 1);
	if (p == NULL)
		fatal("Ran out of memory.");
	(void) strcpy(p, s);
	return (p);
}

static void
help(struct tab *ctab, char *s)
{
	struct tab *c;
	int width, NCMDS;
	const char *help_type;

	if (ctab == sitetab)
		help_type = "SITE ";
	else
		help_type = "";
	width = 0, NCMDS = 0;
	for (c = ctab; c->name != NULL; c++) {
		int len = strlen(c->name);

		if (len > width)
			width = len;
		NCMDS++;
	}
	width = (width + 8) &~ 7;
	if (s == 0) {
		int i, j, w;
		int columns, lines;

		lreply(214, "The following %scommands are recognized %s.",
		    help_type, "(* =>'s unimplemented)");
		columns = 76 / width;
		if (columns == 0)
			columns = 1;
		lines = (NCMDS + columns - 1) / columns;
		for (i = 0; i < lines; i++) {
			printf("   ");
			for (j = 0; j < columns; j++) {
				c = ctab + j * lines + i;
				printf("%s%c", c->name,
					c->implemented ? ' ' : '*');
				if (c + lines >= &ctab[NCMDS])
					break;
				w = strlen(c->name) + 1;
				while (w < width) {
					putchar(' ');
					w++;
				}
			}
			printf("\r\n");
		}
		(void) fflush(stdout);
		reply(214, "Direct comments to ftp-bugs@%s.", hostname);
		return;
	}
	upper(s);
	c = lookup(ctab, s);
	if (c == (struct tab *)0) {
		reply(502, "Unknown command %s.", s);
		return;
	}
	if (c->implemented)
		reply(214, "Syntax: %s%s %s", help_type, c->name, c->help);
	else
		reply(214, "%s%-*s\t%s; unimplemented.", help_type, width,
		    c->name, c->help);
}

static void
sizecmd(char *filename)
{
	switch (type) {
	case TYPE_L:
	case TYPE_I: {
		struct stat stbuf;
		if (stat(filename, &stbuf) < 0 || !S_ISREG(stbuf.st_mode))
			reply(550, "%s: not a plain file.", filename);
		else
			reply(213,
			      (sizeof (stbuf.st_size) > sizeof(long)
			       ? "%qu" : "%lu"), stbuf.st_size);
		break; }
	case TYPE_A: {
		FILE *fin;
		int c;
		off_t count;
		struct stat stbuf;
		fin = fopen(filename, "r");
		if (fin == NULL) {
			perror_reply(550, filename);
			return;
		}
		if (fstat(fileno(fin), &stbuf) < 0 || !S_ISREG(stbuf.st_mode)) {
			reply(550, "%s: not a plain file.", filename);
			(void) fclose(fin);
			return;
		}

		count = 0;
		while((c=getc(fin)) != EOF) {
			if (c == '\n')	/* will get expanded to \r\n */
				count++;
			count++;
		}
		(void) fclose(fin);

		reply(213, sizeof(count) > sizeof(long) ? "%qd" : "%ld",
		      count);
		break; }
	default:
		reply(504, "SIZE not implemented for Type %c.", "?AEIL"[type]);
	}
}

/* ARGSUSED */
static void
yyerror(const char *s)
{
  char *cp;

  (void)s;
  cp = strchr(cbuf,'\n');
  if (cp != NULL)
    *cp = '\0';
  reply(500, "'%s': command not understood.", cbuf);
}
