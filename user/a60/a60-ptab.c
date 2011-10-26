
/*  A Bison parser, made from a60-parse.y  */

#define YYBISON 1  /* Identify Bison output.  */

#define	TCOMMENT	258
#define	TTEN	259
#define	TBEGIN	260
#define	TEND	261
#define	TGOTO	262
#define	TFOR	263
#define	TDO	264
#define	TWHILE	265
#define	TSTEP	266
#define	TUNTIL	267
#define	TIF	268
#define	TTHEN	269
#define	TELSE	270
#define	TSWITCH	271
#define	TPROC	272
#define	TVALUE	273
#define	TCODE	274
#define	TTRUE	275
#define	TFALSE	276
#define	TINTEGER	277
#define	TREAL	278
#define	TBOOL	279
#define	TLABEL	280
#define	TOWN	281
#define	TARRAY	282
#define	TSTRING	283
#define	TPOW	284
#define	TDIV	285
#define	TASSIGN	286
#define	TLESS	287
#define	TNOTGREATER	288
#define	TEQUAL	289
#define	TNOTLESS	290
#define	TGREATER	291
#define	TNOTEQUAL	292
#define	TAND	293
#define	TOR	294
#define	TNOT	295
#define	TIMPL	296
#define	TEQUIV	297
#define	INUM	298
#define	RNUM	299
#define	NAME	300
#define	STRING	301
#define	UNARY	302

#line 37 "a60-parse.y"

#include "comm.h"
#include "a60.h"
#include "util.h"
#include "tree.h"
#include "run.h"
#include "bltin.h"


/* number of errors found. */
int nerrors = 0;

/* flag for unary minus parsed. */
int unary_minus = 0;

/* force code for parser debugging to be included: */
#ifdef PARSEDEBUG
#define YYDEBUG	1
#endif

/*** in future: #ifdef YYBISON ***/
#ifndef YYBYACC

#ifdef ALLOCA_MISSING
/*
 * if no alloca() call is avail, provide yyoverflow to catch bison
 * stack-expanding.
 * its somewhat confusing: yyoverflow is expected to be defined, but
 * used with ifdef'd parameters, so it has to be a function.
 * [see below the grammer for a60_yyoverflow ()]
 */

/* to be defined: */
#define yyoverflow 	a60_yyoverflow
/* forward: */
static void a60_yyoverflow ();
#endif /* ALLOCA_MISSING */
#endif /* ! YYBISON */


#line 85 "a60-parse.y"
typedef union {
	long itype;
	double rtype;
	char *str;
	TREE *tree;
	SYMTAB *sym;
	EXPR *expr;
	BOUND *bound;
	LHELM *lhelm;
	MINDEX *mindex;
	FORELM *forelm;
	FORSTMT *forstmt;
	OWNTYPE otype;
	ENUM type_tag typ;
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

#ifndef __STDC__
#define const
#endif



#define	YYFINAL		276
#define	YYFLAG		-32768
#define	YYNTBASE	59

#define YYTRANSLATE(x) ((unsigned)(x) <= 302 ? yytranslate[x] : 138)

static const char yytranslate[] = {     0,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,    55,
    56,    49,    47,    54,    48,     2,    50,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,    58,    57,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
    52,     2,    53,     2,     2,     2,     2,     2,     2,     2,
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
     2,     2,     2,     2,     2,     1,     2,     3,     4,     5,
     6,     7,     8,     9,    10,    11,    12,    13,    14,    15,
    16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
    26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
    36,    37,    38,    39,    40,    41,    42,    43,    44,    45,
    46,    51
};

#if YYDEBUG != 0
static const short yyprhs[] = {     0,
     0,     1,     2,     5,     7,     9,    11,    13,    15,    20,
    22,    26,    28,    33,    35,    40,    43,    45,    49,    53,
    57,    61,    65,    69,    73,    77,    81,    85,    88,    90,
    92,    95,    99,   103,   107,   111,   115,   119,   121,   123,
   125,   127,   129,   133,   135,   137,   142,   144,   146,   150,
   155,   157,   159,   161,   164,   166,   169,   173,   174,   178,
   179,   183,   187,   189,   192,   196,   198,   200,   202,   204,
   206,   208,   210,   213,   215,   217,   219,   221,   223,   226,
   228,   230,   233,   236,   239,   240,   242,   246,   249,   252,
   255,   259,   262,   265,   271,   273,   277,   279,   285,   289,
   292,   293,   297,   299,   303,   305,   310,   312,   314,   316,
   318,   320,   322,   324,   327,   329,   332,   334,   338,   340,
   342,   344,   347,   351,   353,   357,   362,   366,   368,   372,
   376,   381,   383,   387,   390,   391,   393,   395,   397,   401,
   407,   408,   410,   414,   419,   421,   423,   425,   428,   430,
   432,   434,   437,   438,   442,   444,   448,   449,   453,   455,
   459,   461,   464,   466,   468,   470,   473,   476,   478,   482,
   486
};

#endif

static const short yyrhs[] = {    -1,
     0,    60,    77,     0,    20,     0,    21,     0,    45,     0,
    46,     0,    62,     0,    62,    52,    65,    53,     0,    66,
     0,    65,    54,    66,     0,    68,     0,    62,    55,   105,
    56,     0,    69,     0,    98,    69,    15,    68,     0,    47,
    70,     0,    70,     0,    70,    49,    70,     0,    70,    50,
    70,     0,    70,    47,    70,     0,    70,    48,    70,     0,
    70,    29,    70,     0,    70,    30,    70,     0,    70,    42,
    70,     0,    70,    41,    70,     0,    70,    39,    70,     0,
    70,    38,    70,     0,    40,    70,     0,    71,     0,    72,
     0,    48,    72,     0,    70,    32,    70,     0,    70,    33,
    70,     0,    70,    34,    70,     0,    70,    35,    70,     0,
    70,    36,    70,     0,    70,    37,    70,     0,    43,     0,
   137,     0,    67,     0,    64,     0,    61,     0,    55,    69,
    56,     0,    68,     0,    75,     0,    98,    75,    15,    74,
     0,   135,     0,    76,     0,    55,    74,    56,     0,    62,
    52,    66,    53,     0,    78,     0,    79,     0,    80,     0,
   134,    78,     0,    81,     0,   134,    79,     0,    83,    57,
    85,     0,     0,     5,    82,    85,     0,     0,     5,    84,
   109,     0,    83,    57,   109,     0,     1,     0,    86,     6,
     0,    86,    57,    85,     0,    87,     0,    96,     0,    99,
     0,    88,     0,    79,     0,    78,     0,    89,     0,   134,
    88,     0,    90,     0,    94,     0,    95,     0,   103,     0,
     1,     0,    92,    91,     0,    68,     0,    93,     0,    92,
    93,     0,    64,    31,     0,     7,    74,     0,     0,    97,
     0,    97,    15,    86,     0,    98,    99,     0,   134,    96,
     0,    98,    87,     0,    13,    73,    14,     0,   100,    86,
     0,   134,    99,     0,     8,    64,    31,   101,     9,     0,
   102,     0,   101,    54,   102,     0,    68,     0,    68,    11,
    68,    12,    68,     0,    68,    10,    73,     0,    62,   104,
     0,     0,    55,   105,    56,     0,   108,     0,   105,   106,
   108,     0,    54,     0,    56,   107,    58,    55,     0,    45,
     0,    63,     0,    68,     0,   110,     0,   114,     0,   119,
     0,   121,     0,   111,   112,     0,   113,     0,    26,   113,
     0,    62,     0,   112,    54,    62,     0,    22,     0,    23,
     0,    24,     0,    27,   115,     0,   111,    27,   115,     0,
   116,     0,   115,    54,   116,     0,    62,    52,   117,    53,
     0,    62,    54,   116,     0,   118,     0,   117,    54,   118,
     0,    68,    58,    68,     0,    16,    62,    31,   120,     0,
    74,     0,   120,    54,    74,     0,   125,   123,     0,     0,
   113,     0,    86,     0,    19,     0,   122,    17,    62,     0,
   124,   131,    57,   129,   126,     0,     0,   127,     0,   128,
   130,    57,     0,   127,   128,   130,    57,     0,    28,     0,
   113,     0,    27,     0,   113,    27,     0,    25,     0,    16,
     0,    17,     0,   113,    17,     0,     0,    18,   130,    57,
     0,    62,     0,   130,    54,    62,     0,     0,    55,   132,
    56,     0,   133,     0,   132,   106,   133,     0,    62,     0,
   135,    58,     0,    62,     0,    43,     0,    43,     0,    47,
    43,     0,    48,    43,     0,    44,     0,    44,     4,   136,
     0,    43,     4,   136,     0,     4,   136,     0
};

#if YYDEBUG != 0
static const short yyrline[] = { 0,
   165,   171,   177,   196,   198,   206,   214,   226,   231,   241,
   246,   257,   269,   284,   286,   297,   299,   304,   306,   308,
   310,   312,   314,   316,   318,   320,   322,   324,   326,   333,
   342,   349,   351,   353,   355,   357,   359,   364,   370,   376,
   380,   402,   408,   412,   418,   419,   430,   437,   439,   444,
   456,   458,   463,   465,   474,   476,   485,   501,   506,   519,
   524,   528,   533,   538,   540,   554,   556,   558,   563,   565,
   567,   572,   574,   583,   585,   587,   589,   591,   599,   604,
   609,   611,   622,   630,   638,   646,   648,   653,   659,   667,
   676,   684,   692,   700,   710,   712,   723,   731,   741,   756,
   767,   769,   774,   776,   787,   789,   794,   799,   801,   809,
   811,   813,   815,   822,   833,   840,   850,   856,   872,   874,
   876,   884,   889,   897,   899,   907,   917,   932,   934,   945,
   958,   968,   970,   981,   990,   992,   997,   999,  1005,  1019,
  1033,  1035,  1040,  1045,  1054,  1056,  1058,  1060,  1062,  1064,
  1066,  1068,  1073,  1075,  1080,  1084,  1093,  1095,  1100,  1102,
  1110,  1122,  1134,  1136,  1148,  1150,  1152,  1157,  1159,  1161,
  1163
};

static const char * const yytname[] = {   "$","error","$illegal.","TCOMMENT",
"TTEN","TBEGIN","TEND","TGOTO","TFOR","TDO","TWHILE","TSTEP","TUNTIL","TIF",
"TTHEN","TELSE","TSWITCH","TPROC","TVALUE","TCODE","TTRUE","TFALSE","TINTEGER",
"TREAL","TBOOL","TLABEL","TOWN","TARRAY","TSTRING","TPOW","TDIV","TASSIGN","TLESS",
"TNOTGREATER","TEQUAL","TNOTLESS","TGREATER","TNOTEQUAL","TAND","TOR","TNOT",
"TIMPL","TEQUIV","INUM","RNUM","NAME","STRING","'+'","'-'","'*'","'/'","UNARY",
"'['","']'","','","'('","')'","';'","':'","a60program","@1","logical_val","identifier",
"string","variable","subscr_list","subscr_expr","func_desig","arith_expr","simple_expr",
"mix_expr","relation","mix_prim","bool_expr","design_expr","simp_dexpr","switch_des",
"program","block","comp_stmt","unlab_block","unlab_comp","@2","block_head","@3",
"comp_tail","stmt","uncond_stmt","basic_stmt","unlab_basic_stmt","assign_stmt",
"right_part","left_part_list","left_part","goto_stmt","dummy_stmt","cond_stmt",
"if_stmt","if_clause","for_stmt","for_clause","for_list","for_lelm","proc_stmt",
"act_parmpart","act_parmlist","parm_delim","letter_string","act_parm","decl",
"type_decl","loc_or_own","type_list","type","array_decl","array_list","array_seg",
"bound_pair_list","bound_pair","switch_decl","switch_list","proc_decl","pd_proc_type",
"pd_proc_body","pd_proc_hhead","pd_proc_head","pd_spec_part","pd_spec_idlist",
"pd_spec","pd_val_part","pd_ident_list","pd_form_parmpart","pd_form_parmlist",
"pd_form_parm","tlabel","label","signed_inum","real_value",""
};
#endif

static const short yyr1[] = {     0,
    59,    60,    59,    61,    61,    62,    63,    64,    64,    65,
    65,    66,    67,    68,    68,    69,    69,    70,    70,    70,
    70,    70,    70,    70,    70,    70,    70,    70,    70,    70,
    70,    71,    71,    71,    71,    71,    71,    72,    72,    72,
    72,    72,    72,    73,    74,    74,    75,    75,    75,    76,
    77,    77,    78,    78,    79,    79,    80,    82,    81,    84,
    83,    83,    83,    85,    85,    86,    86,    86,    87,    87,
    87,    88,    88,    89,    89,    89,    89,    89,    90,    91,
    92,    92,    93,    94,    95,    96,    96,    96,    96,    97,
    98,    99,    99,   100,   101,   101,   102,   102,   102,   103,
   104,   104,   105,   105,   106,   106,   107,   108,   108,   109,
   109,   109,   109,   110,   111,   111,   112,   112,   113,   113,
   113,   114,   114,   115,   115,   116,   116,   117,   117,   118,
   119,   120,   120,   121,   122,   122,   123,   123,   124,   125,
   126,   126,   127,   127,   128,   128,   128,   128,   128,   128,
   128,   128,   129,   129,   130,   130,   131,   131,   132,   132,
   133,   134,   135,   135,   136,   136,   136,   137,   137,   137,
   137
};

static const short yyr2[] = {     0,
     0,     0,     2,     1,     1,     1,     1,     1,     4,     1,
     3,     1,     4,     1,     4,     2,     1,     3,     3,     3,
     3,     3,     3,     3,     3,     3,     3,     2,     1,     1,
     2,     3,     3,     3,     3,     3,     3,     1,     1,     1,
     1,     1,     3,     1,     1,     4,     1,     1,     3,     4,
     1,     1,     1,     2,     1,     2,     3,     0,     3,     0,
     3,     3,     1,     2,     3,     1,     1,     1,     1,     1,
     1,     1,     2,     1,     1,     1,     1,     1,     2,     1,
     1,     2,     2,     2,     0,     1,     3,     2,     2,     2,
     3,     2,     2,     5,     1,     3,     1,     5,     3,     2,
     0,     3,     1,     3,     1,     4,     1,     1,     1,     1,
     1,     1,     1,     2,     1,     2,     1,     3,     1,     1,
     1,     2,     3,     1,     3,     4,     3,     1,     3,     3,
     4,     1,     3,     2,     0,     1,     1,     1,     3,     5,
     0,     1,     3,     4,     1,     1,     1,     2,     1,     1,
     1,     2,     0,     3,     1,     3,     0,     3,     1,     3,
     1,     2,     1,     1,     1,     2,     2,     1,     3,     3,
     2
};

static const short yydefact[] = {     2,
     0,    63,    58,   164,     6,   163,     3,    51,    52,    53,
    55,     0,     0,     0,     0,   135,     0,    54,    56,   162,
    78,     0,     0,     0,   101,     0,    71,    70,    59,     0,
    66,    69,    72,    74,     0,    81,    75,    76,    67,    86,
     0,    68,     0,    77,     0,     0,   119,   120,   121,     0,
     0,    61,   110,     0,   115,   111,   112,   113,     0,   157,
     0,    57,    62,     0,   163,    84,    45,    48,     0,    47,
     8,     0,     0,     4,     5,     0,    38,   168,     0,     0,
     0,    42,     8,    41,    40,    44,    14,    17,    29,    30,
     0,     0,    39,     0,     0,   100,    83,    64,     0,    41,
    80,    79,    82,     0,    90,    88,     0,    92,    73,    89,
    93,     0,   116,     0,   122,   124,     0,   117,   114,     0,
     0,     0,   138,   137,   134,     0,     0,     0,     0,   165,
     0,     0,   171,    28,     0,     0,    16,    31,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,    91,     0,     0,    10,
    12,     7,   108,   109,     0,   103,    65,    87,     0,     0,
     0,     0,   123,     0,   139,   161,     0,   159,   153,    49,
     0,     0,    97,     0,    95,   166,   167,   170,   169,    43,
     0,    22,    23,    32,    33,    34,    35,    36,    37,    27,
    26,    25,    24,    20,    21,    18,    19,     0,     9,     0,
   105,   102,     0,   132,   131,     0,     0,   128,   127,   125,
   118,   158,     0,     0,   141,    50,    46,     0,     0,    94,
     0,    13,    15,    11,   107,     0,   104,     0,     0,   126,
     0,   160,   155,     0,   150,   151,   149,   147,   145,   146,
   140,   142,     0,    99,     0,    96,     0,   133,   130,   129,
     0,   154,   152,   148,     0,     0,     0,   106,   156,     0,
   143,    98,   144,     0,     0,     0
};

static const short yydefgoto[] = {   274,
     1,    82,    83,   163,    84,   159,   160,    85,   161,    87,
    88,    89,    90,    91,    66,    67,    68,     7,    27,    28,
    10,    11,    15,    12,    16,    29,    30,    31,    32,    33,
    34,   102,    35,    36,    37,    38,    39,    40,    92,    42,
    43,   184,   185,    44,    96,   165,   213,   236,   166,    52,
    53,    54,   119,    55,    56,   115,   116,   217,   218,    57,
   215,    58,    59,   125,    60,    61,   251,   252,   253,   225,
   244,   122,   177,   178,    45,    14,   133,    93
};

static const short yypact[] = {    35,
    82,-32768,   336,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
-32768,    22,    82,   -10,    24,   235,   281,-32768,-32768,-32768,
    27,    92,    11,   302,    30,    44,-32768,-32768,-32768,    20,
-32768,-32768,-32768,-32768,   302,-32768,-32768,-32768,-32768,    97,
   135,-32768,    24,-32768,    24,    11,-32768,-32768,-32768,   100,
    11,-32768,-32768,    14,    77,-32768,-32768,-32768,    98,   108,
    57,-32768,-32768,    92,   101,-32768,-32768,-32768,   112,-32768,
   117,   143,   136,-32768,-32768,   145,   128,   178,   145,   191,
   335,-32768,    19,-32768,-32768,-32768,-32768,   359,-32768,-32768,
   173,   335,-32768,   302,   289,-32768,-32768,-32768,    24,    44,
-32768,-32768,-32768,    24,-32768,-32768,   135,-32768,-32768,-32768,
-32768,   168,-32768,    79,   148,-32768,    11,-32768,   151,    11,
    11,   159,-32768,-32768,-32768,   152,   302,   206,   302,-32768,
   183,   184,-32768,-32768,   136,   136,   359,-32768,   172,   289,
   145,   145,   145,   145,   145,   145,   145,   145,   145,   145,
   145,   145,   145,   145,   145,   145,-32768,   227,    85,-32768,
-32768,-32768,-32768,-32768,   104,-32768,-32768,-32768,    92,   302,
    11,    11,   148,    11,-32768,-32768,   105,-32768,   236,-32768,
   202,    92,   134,    18,-32768,-32768,-32768,-32768,-32768,-32768,
   140,-32768,   224,   200,   200,   200,   200,   200,   200,   337,
   425,   403,   381,    80,    80,   224,   224,   302,-32768,   302,
-32768,   211,   289,-32768,   209,   207,   144,-32768,-32768,-32768,
-32768,   211,    11,    11,   216,-32768,-32768,   302,   302,-32768,
   302,   211,-32768,-32768,-32768,   225,-32768,    92,   302,-32768,
   302,-32768,-32768,    36,-32768,-32768,-32768,-32768,-32768,    16,
-32768,   216,    11,-32768,   272,-32768,   230,-32768,-32768,-32768,
    11,-32768,-32768,-32768,    11,    42,   302,-32768,-32768,    47,
-32768,-32768,-32768,   290,   291,-32768
};

static const short yypgoto[] = {-32768,
-32768,-32768,    -1,-32768,   111,-32768,  -121,-32768,   -22,   -53,
   125,-32768,   212,    67,   -61,   231,-32768,-32768,     4,    10,
-32768,-32768,-32768,-32768,-32768,    -8,    -9,   255,   -27,-32768,
-32768,-32768,-32768,   264,-32768,-32768,   256,-32768,    -7,   -21,
-32768,-32768,    81,-32768,-32768,   171,   137,-32768,   103,   296,
-32768,-32768,-32768,   -49,-32768,   201,    53,-32768,    76,-32768,
-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,    68,-32768,
  -187,-32768,-32768,    96,     6,   -18,    78,-32768
};


#define	YYLAST		475


static const short yytable[] = {     6,
   113,    86,   126,    70,     8,   181,    13,    41,    62,    41,
     9,     6,   101,    25,    69,    25,    18,   109,    13,   106,
    65,    71,    19,   111,    21,    98,   230,   139,     3,   -85,
    22,    23,   263,   108,    -1,    41,    24,    41,   158,    25,
   117,    25,   264,    25,   112,    70,   107,    20,    18,   114,
    70,   124,   118,    41,    19,     5,    69,    21,     5,    25,
    -8,     3,    65,    22,    23,   266,     4,    65,     5,    24,
    94,   231,   164,   140,    97,   123,    99,   270,    17,   109,
   -85,    94,     2,   -63,    95,   111,     3,  -163,   234,   261,
   167,    41,   262,  -136,   168,   261,    41,    25,   271,     4,
   261,     5,    25,   273,    24,    25,   183,   214,   141,   142,
    18,   104,   107,   -85,   120,   114,    19,   164,   175,   176,
   227,    47,    48,    49,     4,    26,     5,    26,   155,   156,
   170,   135,   171,    72,     4,    21,     5,   209,   210,     3,
   -85,    22,    23,   228,   229,   100,    64,   216,    73,   -85,
    70,    26,   127,    26,     4,    26,     5,   211,   211,   212,
   222,    69,   121,    70,    74,    75,    64,    65,    94,   114,
   114,    26,   221,   129,    69,   250,   258,     4,   130,     5,
    65,   136,   131,   132,    76,   233,   157,    77,    78,     5,
   164,   -85,    80,   211,    73,   232,   240,   241,   169,    81,
   134,   172,   250,   137,   174,    86,   255,   180,   183,    26,
    74,    75,   188,   189,    26,   179,   259,    26,   216,    70,
   182,   176,   243,   219,   220,   186,   187,   190,   141,   142,
    69,   245,   246,    77,    78,     5,    65,    47,    48,    49,
   247,   208,   248,   249,   272,    81,   153,   154,   155,   156,
    46,   243,   141,   224,   226,   235,    47,    48,    49,   269,
    50,    51,   238,   243,   239,   192,   193,   194,   195,   196,
   197,   198,   199,   200,   201,   202,   203,   204,   205,   206,
   207,    21,   257,   267,   268,     3,   -85,    22,    23,   275,
   276,   138,    73,    24,   254,   105,    46,  -135,   103,   128,
   110,    24,    47,    48,    49,    73,    50,    51,    74,    75,
   191,   256,    63,   223,    24,   237,   260,   173,   242,   265,
     0,    74,    75,     4,     0,     5,     0,     0,    76,     0,
     0,    77,    78,     5,   162,    79,    80,   -85,    73,     0,
     0,    76,     0,    81,    77,    78,     5,     0,    79,    80,
     0,   -60,   -60,     0,    74,    75,    81,   -60,   -60,   -60,
     0,   -60,   -60,     0,     0,   141,   142,     0,   143,   144,
   145,   146,   147,   148,    76,     0,     0,    77,    78,     5,
     0,    79,    80,   153,   154,   155,   156,   141,   142,    81,
   143,   144,   145,   146,   147,   148,   149,   150,     0,   151,
   152,     0,     0,     0,     0,   153,   154,   155,   156,   141,
   142,     0,   143,   144,   145,   146,   147,   148,   149,   150,
     0,   151,     0,     0,     0,     0,     0,   153,   154,   155,
   156,   141,   142,     0,   143,   144,   145,   146,   147,   148,
   149,   150,     0,     0,     0,     0,     0,     0,     0,   153,
   154,   155,   156,   141,   142,     0,   143,   144,   145,   146,
   147,   148,   149,     0,     0,     0,     0,     0,     0,     0,
     0,   153,   154,   155,   156
};

static const short yycheck[] = {     1,
    50,    24,    64,    22,     1,   127,     1,    15,    17,    17,
     1,    13,    35,    15,    22,    17,    13,    45,    13,    41,
    22,    23,    13,    45,     1,     6,     9,    81,     5,     6,
     7,     8,    17,    43,     0,    43,    13,    45,    92,    41,
    27,    43,    27,    45,    46,    64,    41,    58,    45,    51,
    69,    61,    54,    61,    45,    45,    64,     1,    45,    61,
    31,     5,    64,     7,     8,   253,    43,    69,    45,    13,
    52,    54,    95,    55,    31,    19,    57,   265,    57,   107,
    57,    52,     1,    57,    55,   107,     5,    58,   210,    54,
    99,    99,    57,    17,   104,    54,   104,    99,    57,    43,
    54,    45,   104,    57,    13,   107,   129,   169,    29,    30,
   107,    15,   107,    57,    17,   117,   107,   140,   120,   121,
   182,    22,    23,    24,    43,    15,    45,    17,    49,    50,
    52,     4,    54,    23,    43,     1,    45,    53,    54,     5,
     6,     7,     8,    10,    11,    35,    55,   170,     4,    15,
   169,    41,    52,    43,    43,    45,    45,    54,    54,    56,
    56,   169,    55,   182,    20,    21,    55,   169,    52,   171,
   172,    61,   174,    31,   182,   225,   238,    43,    43,    45,
   182,     4,    47,    48,    40,   208,    14,    43,    44,    45,
   213,    57,    48,    54,     4,    56,    53,    54,    31,    55,
    76,    54,   252,    79,    54,   228,   229,    56,   231,    99,
    20,    21,   135,   136,   104,    57,   239,   107,   241,   238,
    15,   223,   224,   171,   172,    43,    43,    56,    29,    30,
   238,    16,    17,    43,    44,    45,   238,    22,    23,    24,
    25,    15,    27,    28,   267,    55,    47,    48,    49,    50,
    16,   253,    29,    18,    53,    45,    22,    23,    24,   261,
    26,    27,    54,   265,    58,   141,   142,   143,   144,   145,
   146,   147,   148,   149,   150,   151,   152,   153,   154,   155,
   156,     1,    58,    12,    55,     5,     6,     7,     8,     0,
     0,    80,     4,    13,   228,    41,    16,    17,    35,    69,
    45,    13,    22,    23,    24,     4,    26,    27,    20,    21,
   140,   231,    17,   177,    13,   213,   241,   117,   223,   252,
    -1,    20,    21,    43,    -1,    45,    -1,    -1,    40,    -1,
    -1,    43,    44,    45,    46,    47,    48,    57,     4,    -1,
    -1,    40,    -1,    55,    43,    44,    45,    -1,    47,    48,
    -1,    16,    17,    -1,    20,    21,    55,    22,    23,    24,
    -1,    26,    27,    -1,    -1,    29,    30,    -1,    32,    33,
    34,    35,    36,    37,    40,    -1,    -1,    43,    44,    45,
    -1,    47,    48,    47,    48,    49,    50,    29,    30,    55,
    32,    33,    34,    35,    36,    37,    38,    39,    -1,    41,
    42,    -1,    -1,    -1,    -1,    47,    48,    49,    50,    29,
    30,    -1,    32,    33,    34,    35,    36,    37,    38,    39,
    -1,    41,    -1,    -1,    -1,    -1,    -1,    47,    48,    49,
    50,    29,    30,    -1,    32,    33,    34,    35,    36,    37,
    38,    39,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    47,
    48,    49,    50,    29,    30,    -1,    32,    33,    34,    35,
    36,    37,    38,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
    -1,    47,    48,    49,    50
};
/* -*-C-*-  Note some compilers choke on comments on `#line' lines.  */
#line 3 "/usr/local/lib/bison.simple"

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
#if (!defined (__STDC__) && defined (sparc)) || defined (__sparc__)
#include <alloca.h>
#else /* not sparc */
#if defined (MSDOS) && !defined (__TURBOC__)
#include <malloc.h>
#else /* not MSDOS, or __TURBOC__ */
#if defined(_AIX)
#include <malloc.h>
 #pragma alloca
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

#line 169 "/usr/local/lib/bison.simple"
int
yyparse()
{
  register int yystate;
  register int yyn;
  register short *yyssp;
  register YYSTYPE *yyvsp;
  int yyerrstatus;	/*  number of tokens to shift before error messages enabled */
  int yychar1;		/*  lookahead token as an internal (translated) token number */

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
     so that they stay on the same level as the state stack.  */

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
      yyoverflow("parser stack overflow",
		 &yyss1, size * sizeof (*yyssp),
		 &yyvs1, size * sizeof (*yyvsp),
#ifdef YYLSP_NEEDED
		 &yyls1, size * sizeof (*yylsp),
#endif
		 &yystacksize);

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
  yyval = yyvsp[1-yylen]; /* implement default value of the action */

#if YYDEBUG != 0
  if (yydebug)
    {
      int i;

      fprintf (stderr, "Reducing via rule %d (line %d), ",
	       yyn, yyrline[yyn]);

      /* Print the symboles being reduced, and their result.  */
      for (i = yyprhs[yyn]; yyrhs[i] > 0; i++)
	fprintf (stderr, "%s ", yytname[yyrhs[i]]);
      fprintf (stderr, " -> %s\n", yytname[yyr1[yyn]]);
    }
#endif


  switch (yyn) {

case 1:
#line 167 "a60-parse.y"
{
		  rtree = 0;
		  yyerror ("no vaild input found");
	  ;
    break;}
case 2:
#line 172 "a60-parse.y"
{
		  open_new_scope ();
		  init_bltin ();
	  ;
    break;}
case 3:
#line 177 "a60-parse.y"
{
		  TREE *new = new_tree (t_block);
		  new->runme = run_block;
		  if (! current_scope)
			  xabort ("cannot recover from this error");
		  new->u.block = current_scope->block;
		  new->u.block->symtab = *current_scope->symtab;
		  new->u.block->nact = 
			  set_actidx (*current_scope->symtab);
		  new->u.block->stmt = yyvsp[0].tree;
		  new->next = 0;
		  rtree = new;
	  ;
    break;}
case 4:
#line 197 "a60-parse.y"
{ yyval.itype = 1; ;
    break;}
case 5:
#line 199 "a60-parse.y"
{ yyval.itype = 0; ;
    break;}
case 6:
#line 207 "a60-parse.y"
{ yyval.str = cleanup_identifier (yyvsp[0].str); ;
    break;}
case 7:
#line 215 "a60-parse.y"
{
		  EXPR *new = new_expr (e_string, ty_string);
		  new->u.string = yyvsp[0].str;
		  yyval.expr = new;
	  ;
    break;}
case 8:
#line 227 "a60-parse.y"
{
		  LHELM *new = make_var_ref (yyvsp[0].str, 1);
		  yyval.lhelm = new;
	  ;
    break;}
case 9:
#line 232 "a60-parse.y"
{
		  LHELM *new = make_var_ref (yyvsp[-3].str, 1);
		  if (new)
			  new->mindex = yyvsp[-1].mindex;
		  yyval.lhelm = new;
	  ;
    break;}
case 10:
#line 242 "a60-parse.y"
{
		  MINDEX *new = new_mindex (yyvsp[0].expr);
		  yyval.mindex = new;
	  ;
    break;}
case 11:
#line 247 "a60-parse.y"
{
		  MINDEX *new = new_mindex (yyvsp[0].expr);
		  MINDEX **i;
		  for (i = &(yyvsp[-2].mindex); *i; i = &(*i)->next);
		  *i = new;
		  yyval.mindex = yyvsp[-2].mindex;
	  ;
    break;}
case 12:
#line 258 "a60-parse.y"
{ yyval.expr = yyvsp[0].expr; ;
    break;}
case 13:
#line 270 "a60-parse.y"
{
		  EXPR *expr = new_expr (e_fcall, ty_unknown);
		  LHELM *new = make_var_ref (yyvsp[-3].str, 0);
		  if (new) {
			  new->u.fcall = new_funcall (new->sym, yyvsp[-1].expr);
			  expr->u.lhelm = new;
		  }
		  yyval.expr = expr;
	  ;
    break;}
case 14:
#line 285 "a60-parse.y"
{ yyval.expr = yyvsp[0].expr; ;
    break;}
case 15:
#line 287 "a60-parse.y"
{
		  EXPR *new = new_expr (e_condexpr, ty_unknown);
		  new->u.expr[0] = yyvsp[-3].expr;
		  new->u.expr[1] = yyvsp[-2].expr;
		  new->u.expr[2] = yyvsp[0].expr;
		  yyval.expr = new;
	  ;
    break;}
case 16:
#line 298 "a60-parse.y"
{ yyval.expr = yyvsp[0].expr; ;
    break;}
case 17:
#line 300 "a60-parse.y"
{ yyval.expr = yyvsp[0].expr; ;
    break;}
case 18:
#line 305 "a60-parse.y"
{ yyval.expr = new_xmix_expr (yyvsp[-2].expr, e_op_times, yyvsp[0].expr); ;
    break;}
case 19:
#line 307 "a60-parse.y"
{ yyval.expr = new_xmix_expr (yyvsp[-2].expr, e_op_rdiv, yyvsp[0].expr); ;
    break;}
case 20:
#line 309 "a60-parse.y"
{ yyval.expr = new_xmix_expr (yyvsp[-2].expr, e_op_plus, yyvsp[0].expr); ;
    break;}
case 21:
#line 311 "a60-parse.y"
{ yyval.expr = new_xmix_expr (yyvsp[-2].expr, e_op_minus, yyvsp[0].expr); ;
    break;}
case 22:
#line 313 "a60-parse.y"
{ yyval.expr = new_xmix_expr (yyvsp[-2].expr, e_op_pow, yyvsp[0].expr); ;
    break;}
case 23:
#line 315 "a60-parse.y"
{ yyval.expr = new_xmix_expr (yyvsp[-2].expr, e_op_idiv, yyvsp[0].expr); ;
    break;}
case 24:
#line 317 "a60-parse.y"
{ yyval.expr = new_xmix_expr (yyvsp[-2].expr, e_op_equiv, yyvsp[0].expr); ;
    break;}
case 25:
#line 319 "a60-parse.y"
{ yyval.expr = new_xmix_expr (yyvsp[-2].expr, e_op_impl, yyvsp[0].expr); ;
    break;}
case 26:
#line 321 "a60-parse.y"
{ yyval.expr = new_xmix_expr (yyvsp[-2].expr, e_op_or, yyvsp[0].expr); ;
    break;}
case 27:
#line 323 "a60-parse.y"
{ yyval.expr = new_xmix_expr (yyvsp[-2].expr, e_op_and, yyvsp[0].expr); ;
    break;}
case 28:
#line 325 "a60-parse.y"
{ yyval.expr = new_xmix_expr (yyvsp[0].expr, e_op_not, (EXPR *) 0); ;
    break;}
case 29:
#line 327 "a60-parse.y"
{
		  if (unary_minus)
			  unary_minus = 0,
			  yyerror ("unary `-' invalid in relation");
		  yyval.expr = yyvsp[0].expr;
	  ;
    break;}
case 30:
#line 334 "a60-parse.y"
{
		  if (unary_minus) {
			  unary_minus = 0;
			  yyval.expr = new_mix_expr (yyvsp[0].expr, e_op_neg, (EXPR *) 0);
		  }
		  else
			  yyval.expr = yyvsp[0].expr;
	  ;
    break;}
case 31:
#line 343 "a60-parse.y"
{
		  yyval.expr = new_mix_expr (yyvsp[0].expr, e_op_neg, (EXPR *) 0);
	  ;
    break;}
case 32:
#line 350 "a60-parse.y"
{ yyval.expr = new_xmix_expr (yyvsp[-2].expr, e_op_less, yyvsp[0].expr); ;
    break;}
case 33:
#line 352 "a60-parse.y"
{ yyval.expr = new_xmix_expr (yyvsp[-2].expr, e_op_notgreater, yyvsp[0].expr); ;
    break;}
case 34:
#line 354 "a60-parse.y"
{ yyval.expr = new_xmix_expr (yyvsp[-2].expr, e_op_equal, yyvsp[0].expr); ;
    break;}
case 35:
#line 356 "a60-parse.y"
{ yyval.expr = new_xmix_expr (yyvsp[-2].expr, e_op_notless, yyvsp[0].expr); ;
    break;}
case 36:
#line 358 "a60-parse.y"
{ yyval.expr = new_xmix_expr (yyvsp[-2].expr, e_op_greater, yyvsp[0].expr); ;
    break;}
case 37:
#line 360 "a60-parse.y"
{ yyval.expr = new_xmix_expr (yyvsp[-2].expr, e_op_notequal, yyvsp[0].expr); ;
    break;}
case 38:
#line 365 "a60-parse.y"
{
		  EXPR *new = new_expr (e_ival, ty_integer);
		  new->u.ival = yyvsp[0].itype;
		  yyval.expr = new;
	  ;
    break;}
case 39:
#line 371 "a60-parse.y"
{
		  EXPR *new = new_expr (e_rval, ty_real);
		  new->u.rval = yyvsp[0].rtype;
		  yyval.expr = new;
	  ;
    break;}
case 40:
#line 377 "a60-parse.y"
{
		  yyval.expr = yyvsp[0].expr;
	  ;
    break;}
case 41:
#line 381 "a60-parse.y"
{
		  EXPR *new;

		  if (! yyvsp[0].lhelm) {
			  new = (EXPR *) 0;
		  }
		  else {
			  new = new_expr (e_symbol, ty_unknown);
			  new->u.lhelm = yyvsp[0].lhelm;
			  
			  if (TIS_PROC(yyvsp[0].lhelm->sym->type)) {
				  LHELM *lhelm = yyvsp[0].lhelm;
				  new->tag = e_fcall;
				  lhelm->u.fcall = new_funcall (lhelm->sym,
								(EXPR *) 0);
				  new->u.lhelm = lhelm;
			  }
		  }

		  yyval.expr = new;
	  ;
    break;}
case 42:
#line 403 "a60-parse.y"
{
		  EXPR *new = new_expr (e_bool, ty_bool);
		  new->u.bool = yyvsp[0].itype;
		  yyval.expr = new;
	  ;
    break;}
case 43:
#line 409 "a60-parse.y"
{ yyval.expr = yyvsp[-1].expr; ;
    break;}
case 45:
#line 418 "a60-parse.y"
{ yyval.expr = yyvsp[0].expr; ;
    break;}
case 46:
#line 420 "a60-parse.y"
{
		  EXPR *new = new_expr (e_condexpr, ty_unknown);
		  new->u.expr[0] = yyvsp[-3].expr;
		  new->u.expr[1] = yyvsp[-2].expr;
		  new->u.expr[2] = yyvsp[0].expr;
		  yyval.expr = new;
	  ;
    break;}
case 47:
#line 431 "a60-parse.y"
{
		  SYMTAB *new = new_symbol (yyvsp[0].str, ty_label, s_undef);
		  EXPR *ex = new_expr (e_label, ty_label);
		  ex->u.label = new;
		  yyval.expr = ex;
	  ;
    break;}
case 48:
#line 438 "a60-parse.y"
{ yyval.expr = yyvsp[0].expr; ;
    break;}
case 49:
#line 440 "a60-parse.y"
{ yyval.expr = yyvsp[-1].expr; ;
    break;}
case 50:
#line 445 "a60-parse.y"
{
		  EXPR *ex = new_expr (e_switch, ty_switch);
		  ex->u.eswitch = new_eswitch (yyvsp[-3].str, yyvsp[-1].expr);
		  yyval.expr = ex;
	  ;
    break;}
case 51:
#line 457 "a60-parse.y"
{ yyval.tree = yyvsp[0].tree; ;
    break;}
case 52:
#line 459 "a60-parse.y"
{ yyval.tree = yyvsp[0].tree; ;
    break;}
case 53:
#line 464 "a60-parse.y"
{ yyval.tree = yyvsp[0].tree; ;
    break;}
case 54:
#line 466 "a60-parse.y"
{
		  TREE *p1 = yyvsp[-1].tree, *p2 = yyvsp[0].tree;
		  p1->next = p2;
		  yyval.tree = p1;
	  ;
    break;}
case 55:
#line 475 "a60-parse.y"
{ yyval.tree = yyvsp[0].tree; ;
    break;}
case 56:
#line 477 "a60-parse.y"
{
		  TREE *p1 = yyvsp[-1].tree, *p2 = yyvsp[0].tree;
		  p1->next = p2;
		  yyval.tree = p1;
	  ;
    break;}
case 57:
#line 486 "a60-parse.y"
{
		  TREE *new = new_tree (t_block);
		  new->runme = run_block;
		  new->u.block = current_scope->block;
		  /* new->u.block->symtab = current_scope->symtab; */
		  new->u.block->nact = 
			  set_actidx (*current_scope->symtab);
		  new->u.block->stmt = yyvsp[0].tree;
		  new->next = 0;
		  yyval.tree = new;
		  close_current_scope ();
	  ;
    break;}
case 58:
#line 502 "a60-parse.y"
{
		  open_new_scope ();
	  ;
    break;}
case 59:
#line 506 "a60-parse.y"
{
		  TREE *p = yyvsp[0].tree;
		  TREE *new = new_tree (t_block);
		  new->runme = run_block;
		  new->u.block = current_scope->block;
		  new->u.block->stmt = p;
		  new->next = 0;
		  close_current_scope ();
		  yyval.tree = new;
	  ;
    break;}
case 60:
#line 520 "a60-parse.y"
{
		  open_new_scope ();
	  ;
    break;}
case 61:
#line 524 "a60-parse.y"
{
		  SYMTAB *p = yyvsp[0].sym;
		  examine_and_append_symtab (current_scope->symtab, p);
	  ;
    break;}
case 62:
#line 529 "a60-parse.y"
{
		  SYMTAB *p = yyvsp[0].sym;
		  examine_and_append_symtab (current_scope->symtab, p);
	  ;
    break;}
case 63:
#line 534 "a60-parse.y"
{ /** yyerror ("declaration error"); **/ ;
    break;}
case 64:
#line 539 "a60-parse.y"
{ yyval.tree = yyvsp[-1].tree; ;
    break;}
case 65:
#line 541 "a60-parse.y"
{
		  if (! yyvsp[-2].tree) {
			  /* there was an error parsing stmt */
			  yyval.tree = yyvsp[0].tree;
		  }
		  else {
			  append_stmt (&(yyvsp[-2].tree)->next, yyvsp[0].tree, 0);
			  yyval.tree = yyvsp[-2].tree;
		  }
	  ;
    break;}
case 66:
#line 555 "a60-parse.y"
{ yyval.tree = yyvsp[0].tree; ;
    break;}
case 67:
#line 557 "a60-parse.y"
{ yyval.tree = yyvsp[0].tree; ;
    break;}
case 68:
#line 559 "a60-parse.y"
{ yyval.tree = yyvsp[0].tree; ;
    break;}
case 69:
#line 564 "a60-parse.y"
{ yyval.tree = yyvsp[0].tree; ;
    break;}
case 70:
#line 566 "a60-parse.y"
{ yyval.tree = yyvsp[0].tree; ;
    break;}
case 71:
#line 568 "a60-parse.y"
{ yyval.tree = yyvsp[0].tree; ;
    break;}
case 72:
#line 573 "a60-parse.y"
{ yyval.tree = yyvsp[0].tree; ;
    break;}
case 73:
#line 575 "a60-parse.y"
{
		  (yyvsp[-1].tree)->next = yyvsp[0].tree;
		  yyval.tree = yyvsp[-1].tree;

	  ;
    break;}
case 74:
#line 584 "a60-parse.y"
{ yyval.tree = yyvsp[0].tree; ;
    break;}
case 75:
#line 586 "a60-parse.y"
{ yyval.tree = yyvsp[0].tree; ;
    break;}
case 76:
#line 588 "a60-parse.y"
{ yyval.tree = yyvsp[0].tree; ;
    break;}
case 77:
#line 590 "a60-parse.y"
{ yyval.tree = yyvsp[0].tree; ;
    break;}
case 78:
#line 592 "a60-parse.y"
{ yyval.tree = 0; ;
    break;}
case 79:
#line 600 "a60-parse.y"
{ yyval.tree = new_assign_stmt (yyvsp[-1].lhelm, yyvsp[0].expr); ;
    break;}
case 80:
#line 605 "a60-parse.y"
{ yyval.expr = yyvsp[0].expr; ;
    break;}
case 81:
#line 610 "a60-parse.y"
{ yyval.lhelm = yyvsp[0].lhelm; ;
    break;}
case 82:
#line 612 "a60-parse.y"
{
		  LHELM **l = &(yyvsp[-1].lhelm);
		  for (; *l; l = &(*l)->next)
			  continue;
		  *l = yyvsp[0].lhelm;
		  yyval.lhelm = yyvsp[-1].lhelm;
	  ;
    break;}
case 83:
#line 623 "a60-parse.y"
{ yyval.lhelm = yyvsp[-1].lhelm; ;
    break;}
case 84:
#line 631 "a60-parse.y"
{ yyval.tree = new_goto_stmt (yyvsp[0].expr); ;
    break;}
case 85:
#line 639 "a60-parse.y"
{ yyval.tree = new_tree (t_dummy_stmt); ;
    break;}
case 86:
#line 647 "a60-parse.y"
{ yyval.tree = yyvsp[0].tree; ;
    break;}
case 87:
#line 649 "a60-parse.y"
{
		  (yyvsp[-2].tree)->u.ifstmt->telse = yyvsp[0].tree;
		  yyval.tree = yyvsp[-2].tree;
	  ;
    break;}
case 88:
#line 654 "a60-parse.y"
{
		  TREE *new = new_if_stmt (yyvsp[-1].expr);
		  new->u.ifstmt->tthen = yyvsp[0].tree;
		  yyval.tree = new;
	  ;
    break;}
case 89:
#line 660 "a60-parse.y"
{
		  (yyvsp[-1].tree)->next = yyvsp[0].tree;
		  yyval.tree = yyvsp[-1].tree;
	  ;
    break;}
case 90:
#line 668 "a60-parse.y"
{
		  TREE *new = new_if_stmt (yyvsp[-1].expr);
		  new->u.ifstmt->tthen = yyvsp[0].tree;
		  yyval.tree = new;
	  ;
    break;}
case 91:
#line 677 "a60-parse.y"
{ yyval.expr = yyvsp[-1].expr; ;
    break;}
case 92:
#line 685 "a60-parse.y"
{
		  TREE *new = new_tree (t_for_stmt);
		  new->runme = run_forstmt;
		  new->u.forstmt = yyvsp[-1].forstmt;
		  new->u.forstmt->stmt = yyvsp[0].tree;
		  yyval.tree = new;
	  ;
    break;}
case 93:
#line 693 "a60-parse.y"
{
		  (yyvsp[-1].tree)->next = yyvsp[0].tree;
		  yyval.tree = yyvsp[0].tree;
	  ;
    break;}
case 94:
#line 701 "a60-parse.y"
{
		  FORSTMT *new = TALLOC (FORSTMT);
		  new->lvar = yyvsp[-3].lhelm;
		  new->forelm = yyvsp[-1].forelm;
		  yyval.forstmt = new;
	  ;
    break;}
case 95:
#line 711 "a60-parse.y"
{ yyval.forelm = yyvsp[0].forelm; ;
    break;}
case 96:
#line 713 "a60-parse.y"
{
		  FORELM **fe = &(yyvsp[-2].forelm);
		  while (*fe)
			  fe = & (*fe)->next;
		  *fe = yyvsp[0].forelm;
		  yyval.forelm = yyvsp[-2].forelm;
	  ;
    break;}
case 97:
#line 724 "a60-parse.y"
{
		  FORELM *new = TALLOC (FORELM);
		  new->tag = fe_expr;
		  new->expr[0] = yyvsp[0].expr;
		  new->next = (FORELM *) 0;
		  yyval.forelm = new;
	  ;
    break;}
case 98:
#line 732 "a60-parse.y"
{
		  FORELM *new = TALLOC (FORELM);
		  new->tag = fe_until;
		  new->expr[0] = yyvsp[-4].expr;
		  new->expr[1] = yyvsp[-2].expr;
		  new->expr[2] = yyvsp[0].expr;
		  new->next = (FORELM *) 0;
		  yyval.forelm = new;
	  ;
    break;}
case 99:
#line 742 "a60-parse.y"
{
		  FORELM *new = TALLOC (FORELM);
		  new->tag = fe_while;
		  new->expr[0] = yyvsp[-2].expr;
		  new->expr[1] = yyvsp[0].expr;
		  new->next = (FORELM *) 0;
		  yyval.forelm = new;
	  ;
    break;}
case 100:
#line 757 "a60-parse.y"
{
		  TREE *new = new_tree (t_proc_stmt);
		  SYMTAB *sym = new_symbol (yyvsp[-1].str, ty_proc, s_undef);
		  new->runme = run_proc;
		  new->u.funcall = new_funcall (sym, yyvsp[0].expr);
		  yyval.tree = new;
	  ;
    break;}
case 101:
#line 768 "a60-parse.y"
{ yyval.expr = (EXPR *) 0; ;
    break;}
case 102:
#line 770 "a60-parse.y"
{ yyval.expr = yyvsp[-1].expr; ;
    break;}
case 103:
#line 775 "a60-parse.y"
{ yyval.expr = yyvsp[0].expr; ;
    break;}
case 104:
#line 777 "a60-parse.y"
{
		  EXPR **expr = &(yyvsp[-2].expr);
		  while (*expr)
			  expr = &(*expr)->next;
		  *expr = yyvsp[0].expr;
		  yyval.expr = yyvsp[-2].expr;
	  ;
    break;}
case 105:
#line 788 "a60-parse.y"
{ /* do nothing */ ;
    break;}
case 106:
#line 790 "a60-parse.y"
{ /* do nothing */ ;
    break;}
case 107:
#line 795 "a60-parse.y"
{ /* do nothing */ ;
    break;}
case 108:
#line 800 "a60-parse.y"
{ yyval.expr = yyvsp[0].expr; ;
    break;}
case 109:
#line 802 "a60-parse.y"
{ yyval.expr = yyvsp[0].expr; ;
    break;}
case 110:
#line 810 "a60-parse.y"
{ yyval.sym = yyvsp[0].sym; ;
    break;}
case 111:
#line 812 "a60-parse.y"
{ yyval.sym = yyvsp[0].sym; ;
    break;}
case 112:
#line 814 "a60-parse.y"
{ yyval.sym = yyvsp[0].sym; ;
    break;}
case 113:
#line 816 "a60-parse.y"
{ yyval.sym = yyvsp[0].sym; ;
    break;}
case 114:
#line 823 "a60-parse.y"
{
		  ENUM type_tag p1 = (yyvsp[-1].otype).type;
		  int own = (yyvsp[-1].otype).own;
		  SYMTAB *p2 = yyvsp[0].sym;
		  sym_all_type (p2, p1, own);
		  yyval.sym = p2;
	  ;
    break;}
case 115:
#line 834 "a60-parse.y"
{
		  OWNTYPE new;
		  new.type = yyvsp[0].typ;
		  new.own = 0;
		  yyval.otype = new;
	  ;
    break;}
case 116:
#line 841 "a60-parse.y"
{
		  OWNTYPE new;
		  new.type = yyvsp[0].typ;
		  new.own = 1;
		  yyval.otype = new;
	  ;
    break;}
case 117:
#line 851 "a60-parse.y"
{
		  SYMTAB *new = new_symbol (yyvsp[0].str, ty_unknown, s_defined);
		  new->block = current_scope->block;
		  yyval.sym = new;
	  ;
    break;}
case 118:
#line 857 "a60-parse.y"
{
		  if (find_in_symtab (yyvsp[-2].sym, yyvsp[0].str)) {
			  yyerror ("duplicate symbol");
			  yyval.sym = yyvsp[-2].sym;
		  }
		  else {
			  SYMTAB *new = new_symbol (yyvsp[0].str, ty_unknown, s_defined);
			  new->next = yyvsp[-2].sym;
			  new->block = current_scope->block;
			  yyval.sym = new;
		  }
	  ;
    break;}
case 119:
#line 873 "a60-parse.y"
{ yyval.typ = ty_integer; ;
    break;}
case 120:
#line 875 "a60-parse.y"
{ yyval.typ = ty_real; ;
    break;}
case 121:
#line 877 "a60-parse.y"
{ yyval.typ = ty_bool; ;
    break;}
case 122:
#line 885 "a60-parse.y"
{
		  sym_all_type (yyvsp[0].sym, TAR_TYPE(ty_real), 0);
		  yyval.sym = yyvsp[0].sym;
	  ;
    break;}
case 123:
#line 890 "a60-parse.y"
{
		  sym_all_type (yyvsp[0].sym, TAR_TYPE((yyvsp[-2].otype).type), (yyvsp[-2].otype).own);
		  yyval.sym = yyvsp[0].sym;
	  ;
    break;}
case 124:
#line 898 "a60-parse.y"
{ yyval.sym = yyvsp[0].sym; ;
    break;}
case 125:
#line 900 "a60-parse.y"
{
		  examine_and_append_symtab (&(yyvsp[-2].sym), yyvsp[0].sym);
		  yyval.sym = yyvsp[-2].sym;
	  ;
    break;}
case 126:
#line 908 "a60-parse.y"
{
		  SYMTAB *new = new_symbol (yyvsp[-3].str, ty_unknown, s_defined);
		  new->block = current_scope->block;
		  new->u.arr = TALLOC (ARRAY);
		  new->u.arr->bound = yyvsp[-1].bound;
		  new->u.arr->dim = num_bounds (yyvsp[-1].bound);
		  /** new->u.arr->val = 0; **/
		  yyval.sym = new;
	  ;
    break;}
case 127:
#line 918 "a60-parse.y"
{
		  SYMTAB *new = new_symbol (yyvsp[-2].str, ty_unknown, s_defined);
		  new->block = current_scope->block;
		  new->u.arr = TALLOC (ARRAY);
		  new->u.arr->bound = (yyvsp[0].sym)->u.arr->bound;
		  new->u.arr->dim = (yyvsp[0].sym)->u.arr->dim;
		  /** new->u.arr->val = 0; **/
		  new->next = yyvsp[0].sym;
		  yyval.sym = new;
		  
	  ;
    break;}
case 128:
#line 933 "a60-parse.y"
{ yyval.bound = yyvsp[0].bound; ;
    break;}
case 129:
#line 935 "a60-parse.y"
{
		  BOUND **b = &(yyvsp[-2].bound);
		  while (*b)
			  b = &(*b)->next;
		  *b = yyvsp[0].bound;
		  yyval.bound = yyvsp[-2].bound;
	  ;
    break;}
case 130:
#line 946 "a60-parse.y"
{
		  BOUND *new = TALLOC (BOUND);
		  new->low = yyvsp[-2].expr;
		  new->high = yyvsp[0].expr;
		  yyval.bound = new;
	  ;
    break;}
case 131:
#line 959 "a60-parse.y"
{
		  SYMTAB *new = new_symbol (yyvsp[-2].str, ty_switch, s_defined);
		  new->block = current_scope->block;
		  new->u.dexpr = yyvsp[0].expr;
		  yyval.sym = new;
	  ;
    break;}
case 132:
#line 969 "a60-parse.y"
{ yyval.expr = yyvsp[0].expr; ;
    break;}
case 133:
#line 971 "a60-parse.y"
{
		  append_expr (&(yyvsp[-2].expr), yyvsp[0].expr);
		  yyval.expr = yyvsp[-2].expr;
	  ;
    break;}
case 134:
#line 982 "a60-parse.y"
{
		  (yyvsp[-1].sym)->u.pproc->block->stmt = yyvsp[0].tree;
		  close_current_scope ();
		  yyval.sym = 0;
	  ;
    break;}
case 135:
#line 991 "a60-parse.y"
{ yyval.typ = ty_proc; ;
    break;}
case 136:
#line 993 "a60-parse.y"
{ yyval.typ = TPROC_TYPE(yyvsp[0].typ); ;
    break;}
case 137:
#line 998 "a60-parse.y"
{ yyval.tree = yyvsp[0].tree; ;
    break;}
case 138:
#line 1000 "a60-parse.y"
{ yyval.tree = (TREE *) 0; ;
    break;}
case 139:
#line 1006 "a60-parse.y"
{
		  SYMTAB *psym = new_symbol (yyvsp[0].str, yyvsp[-2].typ, s_defined);
		  PPROC *new = TALLOC (PPROC);
		  examine_and_append_symtab (current_scope->symtab, psym);
		  psym->block = current_scope->block;
		  psym->u.pproc = new;
		  open_new_scope ();
		  new->block = current_scope->block;
		  yyval.sym = psym;
	  ;
    break;}
case 140:
#line 1020 "a60-parse.y"
{
		  SYMTAB *psym = yyvsp[-4].sym;
		  examine_and_append_symtab (current_scope->symtab, yyvsp[-3].sym);
		  psym->u.pproc->nparm = num_symbols (yyvsp[-3].sym);
		  psym->u.pproc->block->nact = 
			  set_actidx (*current_scope->symtab);
		  replace_type (*current_scope->symtab, yyvsp[0].sym);
		  set_by_value (*current_scope->symtab, yyvsp[-1].sym);
		  yyval.sym = psym;
	  ;
    break;}
case 141:
#line 1034 "a60-parse.y"
{ yyval.sym = (SYMTAB *) 0; ;
    break;}
case 142:
#line 1036 "a60-parse.y"
{ yyval.sym = yyvsp[0].sym; ;
    break;}
case 143:
#line 1041 "a60-parse.y"
{
		  sym_all_type (yyvsp[-1].sym, yyvsp[-2].typ, 0);
		  yyval.sym = yyvsp[-1].sym;
	  ;
    break;}
case 144:
#line 1046 "a60-parse.y"
{
		  sym_all_type (yyvsp[-1].sym, yyvsp[-2].typ, 0);
		  examine_and_append_symtab (&(yyvsp[-3].sym), yyvsp[-1].sym);
		  yyval.sym = yyvsp[-3].sym;
	  ;
    break;}
case 145:
#line 1055 "a60-parse.y"
{ yyval.typ = ty_string; ;
    break;}
case 146:
#line 1057 "a60-parse.y"
{ yyval.typ = yyvsp[0].typ; ;
    break;}
case 147:
#line 1059 "a60-parse.y"
{ yyval.typ = ty_real_array; ;
    break;}
case 148:
#line 1061 "a60-parse.y"
{ yyval.typ = TAR_TYPE(yyvsp[-1].typ); ;
    break;}
case 149:
#line 1063 "a60-parse.y"
{ yyval.typ = ty_label; ;
    break;}
case 150:
#line 1065 "a60-parse.y"
{ yyval.typ = ty_switch; ;
    break;}
case 151:
#line 1067 "a60-parse.y"
{ yyval.typ = ty_proc; ;
    break;}
case 152:
#line 1069 "a60-parse.y"
{ yyval.typ = TPROC_TYPE(yyvsp[-1].typ); ;
    break;}
case 153:
#line 1074 "a60-parse.y"
{ yyval.sym = (SYMTAB *) 0; ;
    break;}
case 154:
#line 1076 "a60-parse.y"
{ yyval.sym = yyvsp[-1].sym; ;
    break;}
case 155:
#line 1081 "a60-parse.y"
{
		  yyval.sym = new_symbol (yyvsp[0].str, ty_unknown, s_byname);
	  ;
    break;}
case 156:
#line 1085 "a60-parse.y"
{
		  SYMTAB *new = new_symbol (yyvsp[0].str, ty_unknown, s_byname);
		  examine_and_append_symtab (&((yyvsp[-2].sym)->next), new);
		  yyval.sym = yyvsp[-2].sym;
	  ;
    break;}
case 157:
#line 1094 "a60-parse.y"
{ yyval.sym = (SYMTAB *) 0; ;
    break;}
case 158:
#line 1096 "a60-parse.y"
{ yyval.sym = yyvsp[-1].sym; ;
    break;}
case 159:
#line 1101 "a60-parse.y"
{ yyval.sym = yyvsp[0].sym; ;
    break;}
case 160:
#line 1103 "a60-parse.y"
{
		  examine_and_append_symtab (&(yyvsp[-2].sym), yyvsp[0].sym);
		  yyval.sym = yyvsp[-2].sym;
	  ;
    break;}
case 161:
#line 1111 "a60-parse.y"
{
		  SYMTAB *new = new_symbol (yyvsp[0].str, ty_unknown, s_byname);
		  new->block = current_scope->block;
		  yyval.sym = new;
	  ;
    break;}
case 162:
#line 1123 "a60-parse.y"
{
		  TREE *new = new_tree (t_label);
		  SYMTAB *s = new_symbol (yyvsp[-1].str, ty_label, s_defined);
		  s->block = current_scope->block;
		  new->u.symbol = s;
		  examine_and_append_symtab (current_scope->symtab, s);
		  yyval.tree = new;
	  ;
    break;}
case 163:
#line 1135 "a60-parse.y"
{ yyval.str = yyvsp[0].str; ;
    break;}
case 164:
#line 1137 "a60-parse.y"
{
		  char tmp[32];

		  sprintf(tmp, "%ld", yyvsp[0].itype);
		  yyval.str = xstrdup (tmp);
	  ;
    break;}
case 165:
#line 1149 "a60-parse.y"
{ yyval.itype = yyvsp[0].itype; ;
    break;}
case 166:
#line 1151 "a60-parse.y"
{ yyval.itype = yyvsp[0].itype; ;
    break;}
case 167:
#line 1153 "a60-parse.y"
{ yyval.itype = - (yyvsp[0].itype); ;
    break;}
case 168:
#line 1158 "a60-parse.y"
{ yyval.rtype = yyvsp[0].rtype; ;
    break;}
case 169:
#line 1160 "a60-parse.y"
{ yyval.rtype = (yyvsp[-2].rtype) * pow ((double) 10, (double) (yyvsp[0].itype)); ;
    break;}
case 170:
#line 1162 "a60-parse.y"
{ yyval.rtype = (double) (yyvsp[-2].itype) * pow ((double) 10, (double) (yyvsp[0].itype)); ;
    break;}
case 171:
#line 1164 "a60-parse.y"
{ yyval.rtype = pow ((double) 10, (double) (yyvsp[0].itype)); ;
    break;}
}
   /* the action file gets copied in in place of this dollarsign */
#line 440 "/usr/local/lib/bison.simple"

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
	  for (x = 0; x < (sizeof(yytname) / sizeof(char *)); x++)
	    if (yycheck[x + yyn] == x)
	      size += strlen(yytname[x]) + 15, count++;
	  msg = (char *) malloc(size + 15);
	  if (msg != 0)
	    {
	      strcpy(msg, "parse error");

	      if (count < 5)
		{
		  count = 0;
		  for (x = 0; x < (sizeof(yytname) / sizeof(char *)); x++)
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
#line 1167 "a60-parse.y"


/*** in future: #ifdef YYBISON ***/
#ifndef YYBYACC
/*
 * the yyoverflow function for use with bison to avoid use of alloca():
 */
#ifdef ALLOCA_MISSING
#ifdef YYLSP_NEEDED
static void
a60_yyoverflow (s, yyss1, size_yyss, yyvs1, size_yyvs, yyls1, size_yyls, yysp)
char *s;
short *yyss1;
int size_yyss;
YYSTYPE *yyvs1;
int size_yyvs;
YYLTYPE *yyls1;
int size_yyls;
int *yysp;
{
 	yyerror (s);
}
#else /* ! YYLSP_NEEDED */
static void
a60_yyoverflow (s, yyss1, size_yyss, yyvs1, size_yyvs, yysp)
char *s;
short *yyss1;
int size_yyss;
YYSTYPE *yyvs1;
int size_yyvs;
int *yysp;
{
 	yyerror (s);
}
#endif /* ! YYLSP_NEEDED */
#endif /* ALLOCA_MISSING */
#endif /* ! YYBISON */

/* end of a60-parse.y */
