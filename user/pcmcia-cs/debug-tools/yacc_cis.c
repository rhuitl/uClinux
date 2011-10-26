#ifndef lint
static char yysccsid[] = "@(#)yaccpar	1.9 (Berkeley) 02/21/93";
#endif
#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define yyclearin (yychar=(-1))
#define yyerrok (yyerrflag=0)
#define YYRECOVERING (yyerrflag!=0)
#define YYPREFIX "yy"
#line 2 "yacc_cis.y"
/*
 * yacc_cis.y 1.12 2000/11/15 01:11:16
 *
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.1 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License
 * at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and
 * limitations under the License. 
 *
 * The initial developer of the original code is David A. Hinds
 * <dahinds@users.sourceforge.net>.  Portions created by David A. Hinds
 * are Copyright (C) 1999 David A. Hinds.  All Rights Reserved.
 *
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU Public License version 2 (the "GPL"), in which
 * case the provisions of the GPL are applicable instead of the
 * above.  If you wish to allow the use of your version of this file
 * only under the terms of the GPL and not to allow others to use
 * your version of this file under the MPL, indicate your decision by
 * deleting the provisions above and replace them with the notice and
 * other provisions required by the GPL.  If you do not delete the
 * provisions above, a recipient may use your version of this file
 * under either the MPL or the GPL.
 */

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <math.h>

#include <pcmcia/cs_types.h>
#include <pcmcia/cs.h>
#include <pcmcia/cistpl.h>

#include "pack_cis.h"

/* If bison: generate nicer error messages */ 
#define YYERROR_VERBOSE 1
 
extern int current_lineno;

void yyerror(char *msg, ...);
static tuple_info_t *new_tuple(u_char type, cisparse_t *parse);

#line 65 "yacc_cis.y"
typedef union {
    char *str;
    u_long num;
    float flt;
    cistpl_power_t pwr;
    cisparse_t *parse;
    tuple_info_t *tuple;
} YYSTYPE;
#line 72 "y.tab.c"
#define STRING 257
#define NUMBER 258
#define FLOAT 259
#define VOLTAGE 260
#define CURRENT 261
#define SIZE 262
#define VERS_1 263
#define MANFID 264
#define FUNCID 265
#define CONFIG 266
#define CFTABLE 267
#define MFC 268
#define CHECKSUM 269
#define POST 270
#define ROM 271
#define BASE 272
#define LAST_INDEX 273
#define CJEDEC 274
#define AJEDEC 275
#define DEV_INFO 276
#define ATTR_DEV_INFO 277
#define NO_INFO 278
#define TIME 279
#define TIMING 280
#define WAIT 281
#define READY 282
#define RESERVED 283
#define VNOM 284
#define VMIN 285
#define VMAX 286
#define ISTATIC 287
#define IAVG 288
#define IPEAK 289
#define IDOWN 290
#define VCC 291
#define VPP1 292
#define VPP2 293
#define IO 294
#define MEM 295
#define DEFAULT 296
#define BVD 297
#define WP 298
#define RDYBSY 299
#define MWAIT 300
#define AUDIO 301
#define READONLY 302
#define PWRDOWN 303
#define BIT8 304
#define BIT16 305
#define LINES 306
#define RANGE 307
#define IRQ_NO 308
#define MASK 309
#define LEVEL 310
#define PULSE 311
#define SHARED 312
#define YYERRCODE 256
short yylhs[] = {                                        -1,
    0,    0,   18,   18,   19,   19,   17,   17,   17,   17,
   17,   17,   17,   17,   17,   17,   17,   12,   12,   12,
   13,   13,   13,    3,    3,    4,    5,    5,    5,   15,
   15,   16,   16,    6,    1,    1,    1,    1,    1,    1,
    1,    2,    2,   11,   11,   11,   11,    8,    8,    8,
    8,    8,    8,    9,    9,    9,    9,   10,   10,   10,
   10,   10,    7,    7,    7,    7,    7,    7,    7,    7,
    7,    7,    7,    7,    7,    7,    7,    7,   14,
};
short yylen[] = {                                         2,
    1,    2,    0,    2,    4,    5,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    5,    2,
    1,    5,    2,    2,    3,    4,    2,    2,    2,    3,
    4,    3,    4,    7,    2,    2,    2,    2,    2,    2,
    2,    0,    2,    2,    3,    3,    3,    5,    5,    2,
    2,    5,    2,    7,    7,    2,    2,    3,    4,    2,
    2,    2,    2,    2,    2,    2,    2,    2,    2,    2,
    2,    3,    3,    3,    1,    1,    1,    1,    6,
};
short yydefred[] = {                                      3,
    0,    0,   15,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   18,   21,    0,   10,    0,   12,    0,    0,
    0,    0,    0,    0,    0,   14,    0,    0,    4,    0,
   24,    0,   27,    0,   63,    3,    0,    0,    0,    0,
   28,   29,   44,   42,   42,   42,    0,    0,   64,   65,
   66,   67,   68,   69,   70,   71,    0,   50,   51,    0,
   53,    0,   56,   57,    0,   61,   60,   62,    0,    0,
    0,    0,   20,    0,   23,    0,    0,    0,    0,    0,
    0,    0,   30,   32,   25,    0,    0,    0,    0,    0,
   58,    0,    0,    0,    0,   45,   46,   47,    0,    0,
    0,    0,    3,   26,    0,    5,    0,    0,    0,    0,
    0,    0,    0,    0,   43,    0,    0,   59,    0,    0,
    0,    0,    0,   31,   33,    0,    0,    0,   35,   36,
   37,   38,   39,   40,   41,   48,    0,   52,   49,    0,
   19,   22,    6,    0,   79,    0,    0,   34,   54,   55,
};
short yydgoto[] = {                                       1,
  115,   86,   15,   16,   17,   18,   19,   20,   21,   22,
   23,   24,   25,   26,   27,   28,   29,    2,   30,
};
short yysindex[] = {                                      0,
    0, -224,    0, -248, -223, -212, -225, -210,  -69, -195,
 -194, -193,    0,    0,   22,    0, -261,    0, -272,  -44,
  -32, -305, -266, -245, -244,    0,   23,   24,    0,   26,
    0,   27,    0, -186,    0,    0,   28, -184, -183, -181,
    0,    0,    0,    0,    0,    0, -180, -179,    0,    0,
    0,    0,    0,    0,    0,    0, -254,    0,    0,   16,
    0, -178,    0,    0, -177,    0,    0,    0, -197, -196,
 -192, -191,    0, -190,    0, -174, -173,  -37, -168, -218,
 -122, -166,    0,    0,    0, -228, -228, -228,   48,   50,
    0, -164, -162,   53,   54,    0,    0,    0,   56,   57,
 -156, -155,    0,    0, -154,    0,   44, -153, -152, -151,
 -150, -149, -148, -147,    0, -143, -142,    0,   13, -141,
 -140, -139, -138,    0,    0, -107, -163, -137,    0,    0,
    0,    0,    0,    0,    0,    0,   55,    0,    0,   58,
    0,    0,    0, -133,    0, -131, -130,    0,    0,    0,
};
short yyrindex[] = {                                      0,
    0,  120,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  339,    0,  354,    0,  376,    1,
   49,   97,  146,  401,  424,    0,  451,  473,    0,  129,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  194,  242,  291,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
};
short yygindex[] = {                                      0,
    0,   -8,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  -34,    0,
};
#define YYTABLESIZE 750
short yytable[] = {                                      62,
   75,   81,  106,   91,   66,   67,   68,   43,   41,   42,
   31,   65,   72,   74,   69,   70,   71,  143,   44,   45,
   46,   47,   48,   49,   50,   51,   52,   53,   54,   55,
   56,    3,   73,   75,   32,   57,   87,   88,    4,    5,
    6,    7,    8,    9,   10,   33,   34,   35,   76,   11,
   12,   13,   14,   36,   92,  108,  109,  110,  111,  112,
  113,  114,   37,   38,   39,   40,   76,   77,  126,   78,
   79,   80,   82,   83,   84,   85,   93,   89,   90,   94,
   95,   96,   97,  101,  102,  103,   98,   99,  100,  104,
  105,  107,  116,  118,  117,  119,   77,  120,  121,  122,
  123,  124,  125,  127,  128,  138,  129,  130,  131,  144,
  132,  133,  134,  135,  136,  137,  139,  140,  146,    1,
  145,  147,  141,  142,  148,   75,  149,  150,    2,    0,
    0,    0,    0,    3,    0,    0,    0,    0,    0,    0,
    4,    5,    6,    7,    8,   78,   10,    0,    3,    0,
    0,   11,   12,   13,   14,    4,    5,    6,    7,    8,
    0,   10,    0,    0,    0,    0,   11,   12,   13,   14,
    0,    0,    0,   76,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   72,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   77,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   73,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   75,    0,    0,   58,
   59,   60,   61,   75,   75,   75,   75,   75,   75,   75,
   78,   63,   64,    0,   75,   75,   75,   75,    0,    0,
   75,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   74,   75,   75,   75,   75,   75,   75,   75,   75,   75,
   75,   75,   75,   75,   76,    0,    0,    0,   75,    0,
    0,   76,   76,   76,   76,   76,   76,   76,   72,    0,
    0,    0,   76,   76,   76,   76,    0,    0,   76,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    9,   76,
   76,   76,   76,   76,   76,   76,   76,   76,   76,   76,
   76,   76,   77,   11,    0,    0,   76,    0,    0,   77,
   77,   77,   77,   77,   77,   77,   73,    0,    0,    0,
   77,   77,   77,   77,    0,   13,   77,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   77,   77,   77,
   77,   77,   77,   77,   77,   77,   77,   77,   77,   77,
    7,   78,    0,    0,   77,    0,    0,    0,   78,   78,
   78,   78,   78,   78,   78,   74,    0,    0,    0,   78,
   78,   78,   78,    8,    0,   78,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   78,   78,   78,   78,
   78,   78,   78,   78,   78,   78,   78,   78,   78,   72,
   16,    0,    0,   78,    0,    0,   72,   72,   72,   72,
   72,   72,   72,    9,    0,    0,    0,   72,   72,   72,
   72,    0,   17,   72,    0,    0,    0,    0,   11,    0,
    0,    0,    0,    0,   72,   72,   72,   72,   72,   72,
   72,   72,   72,   72,   72,   72,   72,   73,    0,    0,
   13,   72,    0,    0,   73,   73,   73,   73,   73,   73,
   73,    0,    0,    0,    0,   73,   73,   73,   73,    0,
    0,   73,    0,    0,    0,    7,    0,    0,    0,    0,
    0,    0,   73,   73,   73,   73,   73,   73,   73,   73,
   73,   73,   73,   73,   73,    0,   74,    0,    8,   73,
    0,    0,    0,   74,   74,   74,   74,   74,   74,   74,
    0,    0,    0,    0,   74,   74,   74,   74,    0,    0,
   74,    0,    0,    0,    0,   16,    0,    0,    0,    0,
    0,   74,   74,   74,   74,   74,   74,   74,   74,   74,
   74,   74,   74,   74,    9,    0,    0,   17,   74,    0,
    0,    9,    9,    9,    9,    9,    9,    9,    0,   11,
    0,    0,    9,    9,    9,    9,   11,   11,   11,   11,
   11,   11,   11,    0,    0,    0,    0,   11,   11,   11,
   11,   13,    0,    0,    0,    0,    0,    0,   13,   13,
   13,   13,   13,   13,   13,    0,    0,    0,    0,   13,
   13,   13,   13,    0,    0,    0,    7,    0,    0,    0,
    0,    0,    0,    7,    7,    7,    7,    7,    7,    7,
    0,    0,    0,    0,    7,    7,    7,    7,    0,    8,
    0,    0,    0,    0,    0,    0,    8,    8,    8,    8,
    8,    8,    8,    0,    0,    0,    0,    8,    8,    8,
    8,    0,    0,    0,    0,    0,   16,    0,    0,    0,
    0,    0,    0,   16,   16,   16,   16,   16,   16,   16,
    0,    0,    0,    0,   16,   16,   16,   16,   17,    0,
    0,    0,    0,    0,    0,   17,   17,   17,   17,   17,
   17,   17,    0,    0,    0,    0,   17,   17,   17,   17,
};
short yycheck[] = {                                      44,
    0,   36,  125,  258,  310,  311,  312,  280,  270,  271,
  259,   44,  258,  258,  281,  282,  283,  125,  291,  292,
  293,  294,  295,  296,  297,  298,  299,  300,  301,  302,
  303,  256,  278,  278,  258,  308,   45,   46,  263,  264,
  265,  266,  267,  268,  269,  258,  272,  258,    0,  274,
  275,  276,  277,  123,  309,  284,  285,  286,  287,  288,
  289,  290,  258,  258,  258,   44,   44,   44,  103,   44,
   44,  258,   45,  258,  258,  257,   61,  258,  258,  258,
  258,  279,  279,  258,  258,  123,  279,  279,  279,  258,
  309,  258,   45,  258,   45,  258,    0,   45,   45,   44,
   44,  258,  258,  258,   61,   93,  260,  260,  260,  273,
  261,  261,  261,  261,  258,  258,  258,  258,   64,    0,
  258,   64,  262,  262,  258,  125,  258,  258,    0,   -1,
   -1,   -1,   -1,  256,   -1,   -1,   -1,   -1,   -1,   -1,
  263,  264,  265,  266,  267,    0,  269,   -1,  256,   -1,
   -1,  274,  275,  276,  277,  263,  264,  265,  266,  267,
   -1,  269,   -1,   -1,   -1,   -1,  274,  275,  276,  277,
   -1,   -1,   -1,  125,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,    0,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  125,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,    0,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  256,   -1,   -1,  304,
  305,  306,  307,  263,  264,  265,  266,  267,  268,  269,
  125,  304,  305,   -1,  274,  275,  276,  277,   -1,   -1,
  280,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
    0,  291,  292,  293,  294,  295,  296,  297,  298,  299,
  300,  301,  302,  303,  256,   -1,   -1,   -1,  308,   -1,
   -1,  263,  264,  265,  266,  267,  268,  269,  125,   -1,
   -1,   -1,  274,  275,  276,  277,   -1,   -1,  280,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,    0,  291,
  292,  293,  294,  295,  296,  297,  298,  299,  300,  301,
  302,  303,  256,    0,   -1,   -1,  308,   -1,   -1,  263,
  264,  265,  266,  267,  268,  269,  125,   -1,   -1,   -1,
  274,  275,  276,  277,   -1,    0,  280,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  291,  292,  293,
  294,  295,  296,  297,  298,  299,  300,  301,  302,  303,
    0,  256,   -1,   -1,  308,   -1,   -1,   -1,  263,  264,
  265,  266,  267,  268,  269,  125,   -1,   -1,   -1,  274,
  275,  276,  277,    0,   -1,  280,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  291,  292,  293,  294,
  295,  296,  297,  298,  299,  300,  301,  302,  303,  256,
    0,   -1,   -1,  308,   -1,   -1,  263,  264,  265,  266,
  267,  268,  269,  125,   -1,   -1,   -1,  274,  275,  276,
  277,   -1,    0,  280,   -1,   -1,   -1,   -1,  125,   -1,
   -1,   -1,   -1,   -1,  291,  292,  293,  294,  295,  296,
  297,  298,  299,  300,  301,  302,  303,  256,   -1,   -1,
  125,  308,   -1,   -1,  263,  264,  265,  266,  267,  268,
  269,   -1,   -1,   -1,   -1,  274,  275,  276,  277,   -1,
   -1,  280,   -1,   -1,   -1,  125,   -1,   -1,   -1,   -1,
   -1,   -1,  291,  292,  293,  294,  295,  296,  297,  298,
  299,  300,  301,  302,  303,   -1,  256,   -1,  125,  308,
   -1,   -1,   -1,  263,  264,  265,  266,  267,  268,  269,
   -1,   -1,   -1,   -1,  274,  275,  276,  277,   -1,   -1,
  280,   -1,   -1,   -1,   -1,  125,   -1,   -1,   -1,   -1,
   -1,  291,  292,  293,  294,  295,  296,  297,  298,  299,
  300,  301,  302,  303,  256,   -1,   -1,  125,  308,   -1,
   -1,  263,  264,  265,  266,  267,  268,  269,   -1,  256,
   -1,   -1,  274,  275,  276,  277,  263,  264,  265,  266,
  267,  268,  269,   -1,   -1,   -1,   -1,  274,  275,  276,
  277,  256,   -1,   -1,   -1,   -1,   -1,   -1,  263,  264,
  265,  266,  267,  268,  269,   -1,   -1,   -1,   -1,  274,
  275,  276,  277,   -1,   -1,   -1,  256,   -1,   -1,   -1,
   -1,   -1,   -1,  263,  264,  265,  266,  267,  268,  269,
   -1,   -1,   -1,   -1,  274,  275,  276,  277,   -1,  256,
   -1,   -1,   -1,   -1,   -1,   -1,  263,  264,  265,  266,
  267,  268,  269,   -1,   -1,   -1,   -1,  274,  275,  276,
  277,   -1,   -1,   -1,   -1,   -1,  256,   -1,   -1,   -1,
   -1,   -1,   -1,  263,  264,  265,  266,  267,  268,  269,
   -1,   -1,   -1,   -1,  274,  275,  276,  277,  256,   -1,
   -1,   -1,   -1,   -1,   -1,  263,  264,  265,  266,  267,
  268,  269,   -1,   -1,   -1,   -1,  274,  275,  276,  277,
};
#define YYFINAL 1
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 312
#if YYDEBUG
char *yyname[] = {
"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,"','","'-'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'='",0,0,"'@'",0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"']'",0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'{'",0,"'}'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"STRING","NUMBER","FLOAT","VOLTAGE","CURRENT","SIZE","VERS_1","MANFID","FUNCID",
"CONFIG","CFTABLE","MFC","CHECKSUM","POST","ROM","BASE","LAST_INDEX","CJEDEC",
"AJEDEC","DEV_INFO","ATTR_DEV_INFO","NO_INFO","TIME","TIMING","WAIT","READY",
"RESERVED","VNOM","VMIN","VMAX","ISTATIC","IAVG","IPEAK","IDOWN","VCC","VPP1",
"VPP2","IO","MEM","DEFAULT","BVD","WP","RDYBSY","MWAIT","AUDIO","READONLY",
"PWRDOWN","BIT8","BIT16","LINES","RANGE","IRQ_NO","MASK","LEVEL","PULSE",
"SHARED",
};
char *yyrule[] = {
"$accept : cis",
"cis : chain",
"cis : chain mfc",
"chain :",
"chain : chain tuple",
"mfc : MFC '{' chain '}'",
"mfc : mfc ',' '{' chain '}'",
"tuple : dev_info",
"tuple : attr_dev_info",
"tuple : vers_1",
"tuple : manfid",
"tuple : funcid",
"tuple : config",
"tuple : cftab",
"tuple : checksum",
"tuple : error",
"tuple : cjedec",
"tuple : ajedec",
"dev_info : DEV_INFO",
"dev_info : dev_info NUMBER TIME ',' SIZE",
"dev_info : dev_info NO_INFO",
"attr_dev_info : ATTR_DEV_INFO",
"attr_dev_info : attr_dev_info NUMBER TIME ',' SIZE",
"attr_dev_info : attr_dev_info NO_INFO",
"vers_1 : VERS_1 FLOAT",
"vers_1 : vers_1 ',' STRING",
"manfid : MANFID NUMBER ',' NUMBER",
"funcid : FUNCID NUMBER",
"funcid : funcid POST",
"funcid : funcid ROM",
"cjedec : CJEDEC NUMBER NUMBER",
"cjedec : cjedec ',' NUMBER NUMBER",
"ajedec : AJEDEC NUMBER NUMBER",
"ajedec : ajedec ',' NUMBER NUMBER",
"config : CONFIG BASE NUMBER MASK NUMBER LAST_INDEX NUMBER",
"pwr : VNOM VOLTAGE",
"pwr : VMIN VOLTAGE",
"pwr : VMAX VOLTAGE",
"pwr : ISTATIC CURRENT",
"pwr : IAVG CURRENT",
"pwr : IPEAK CURRENT",
"pwr : IDOWN CURRENT",
"pwrlist :",
"pwrlist : pwrlist pwr",
"timing : cftab TIMING",
"timing : timing WAIT TIME",
"timing : timing READY TIME",
"timing : timing RESERVED TIME",
"io : cftab IO NUMBER '-' NUMBER",
"io : io ',' NUMBER '-' NUMBER",
"io : io BIT8",
"io : io BIT16",
"io : io LINES '=' NUMBER ']'",
"io : io RANGE",
"mem : cftab MEM NUMBER '-' NUMBER '@' NUMBER",
"mem : mem ',' NUMBER '-' NUMBER '@' NUMBER",
"mem : mem BIT8",
"mem : mem BIT16",
"irq : cftab IRQ_NO NUMBER",
"irq : cftab IRQ_NO MASK NUMBER",
"irq : irq PULSE",
"irq : irq LEVEL",
"irq : irq SHARED",
"cftab : CFTABLE NUMBER",
"cftab : cftab DEFAULT",
"cftab : cftab BVD",
"cftab : cftab WP",
"cftab : cftab RDYBSY",
"cftab : cftab MWAIT",
"cftab : cftab AUDIO",
"cftab : cftab READONLY",
"cftab : cftab PWRDOWN",
"cftab : cftab VCC pwrlist",
"cftab : cftab VPP1 pwrlist",
"cftab : cftab VPP2 pwrlist",
"cftab : io",
"cftab : mem",
"cftab : irq",
"cftab : timing",
"checksum : CHECKSUM NUMBER '-' NUMBER '=' NUMBER",
};
#endif
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 500
#define YYMAXDEPTH 500
#endif
#endif
int yydebug;
int yynerrs;
int yyerrflag;
int yychar;
short *yyssp;
YYSTYPE *yyvsp;
YYSTYPE yyval;
YYSTYPE yylval;
short yyss[YYSTACKSIZE];
YYSTYPE yyvs[YYSTACKSIZE];
#define yystacksize YYSTACKSIZE
#line 391 "yacc_cis.y"

static tuple_info_t *new_tuple(u_char type, cisparse_t *parse)
{
    tuple_info_t *t = calloc(1, sizeof(tuple_info_t));
    t->type = type;
    t->parse = parse;
    t->next = NULL;
}

void yyerror(char *msg, ...)
{
    va_list ap;
    char str[256];

    va_start(ap, msg);
    sprintf(str, "error at line %d: ", current_lineno);
    vsprintf(str+strlen(str), msg, ap);
    fprintf(stderr, "%s\n", str);
    va_end(ap);
}

#ifdef DEBUG
void main(int argc, char *argv[])
{
    if (argc > 1)
	parse_cis(argv[1]);
}
#endif
#line 520 "y.tab.c"
#define YYABORT goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR goto yyerrlab
int
yyparse()
{
    register int yym, yyn, yystate;
#if YYDEBUG
    register char *yys;
    extern char *getenv();

    if (yys = getenv("YYDEBUG"))
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    yynerrs = 0;
    yyerrflag = 0;
    yychar = (-1);

    yyssp = yyss;
    yyvsp = yyvs;
    *yyssp = yystate = 0;

yyloop:
    if (yyn = yydefred[yystate]) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yyssp >= yyss + yystacksize - 1)
        {
            goto yyoverflow;
        }
        *++yyssp = yystate = yytable[yyn];
        *++yyvsp = yylval;
        yychar = (-1);
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;
#ifdef lint
    goto yynewerror;
#endif
yynewerror:
    yyerror("syntax error");
#ifdef lint
    goto yyerrlab;
#endif
yyerrlab:
    ++yynerrs;
yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yyssp, yytable[yyn]);
#endif
                if (yyssp >= yyss + yystacksize - 1)
                {
                    goto yyoverflow;
                }
                *++yyssp = yystate = yytable[yyn];
                *++yyvsp = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yyssp);
#endif
                if (yyssp <= yyss) goto yyabort;
                --yyssp;
                --yyvsp;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = (-1);
        goto yyloop;
    }
yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    yyval = yyvsp[1-yym];
    switch (yyn)
    {
case 1:
#line 84 "yacc_cis.y"
{ cis_root = yyvsp[0].tuple; }
break;
case 2:
#line 86 "yacc_cis.y"
{ cis_root = yyvsp[-1].tuple; }
break;
case 3:
#line 90 "yacc_cis.y"
{ yyval.tuple = NULL; }
break;
case 4:
#line 92 "yacc_cis.y"
{
		    if (yyvsp[-1].tuple == NULL) {
			yyval.tuple = yyvsp[0].tuple;
		    } else if (yyvsp[0].tuple == NULL) {
			yyval.tuple = yyvsp[-1].tuple;
		    } else {
			tuple_info_t *tail = yyvsp[-1].tuple;
			while (tail->next != NULL) tail = tail->next;
			tail->next = yyvsp[0].tuple;
			yyval.tuple = yyvsp[-1].tuple;
		    }
		}
break;
case 5:
#line 107 "yacc_cis.y"
{ mfc[nf++] = yyvsp[-1].tuple; }
break;
case 6:
#line 109 "yacc_cis.y"
{ mfc[nf++] = yyvsp[-1].tuple; }
break;
case 7:
#line 113 "yacc_cis.y"
{ yyval.tuple = new_tuple(CISTPL_DEVICE, yyvsp[0].parse); }
break;
case 8:
#line 115 "yacc_cis.y"
{ yyval.tuple = new_tuple(CISTPL_DEVICE_A, yyvsp[0].parse); }
break;
case 9:
#line 117 "yacc_cis.y"
{ yyval.tuple = new_tuple(CISTPL_VERS_1, yyvsp[0].parse); }
break;
case 10:
#line 119 "yacc_cis.y"
{ yyval.tuple = new_tuple(CISTPL_MANFID, yyvsp[0].parse); }
break;
case 11:
#line 121 "yacc_cis.y"
{ yyval.tuple = new_tuple(CISTPL_FUNCID, yyvsp[0].parse); }
break;
case 12:
#line 123 "yacc_cis.y"
{ yyval.tuple = new_tuple(CISTPL_CONFIG, yyvsp[0].parse); }
break;
case 13:
#line 125 "yacc_cis.y"
{ yyval.tuple = new_tuple(CISTPL_CFTABLE_ENTRY, yyvsp[0].parse); }
break;
case 14:
#line 127 "yacc_cis.y"
{ yyval.tuple = NULL; }
break;
case 15:
#line 129 "yacc_cis.y"
{ yyval.tuple = NULL; }
break;
case 16:
#line 131 "yacc_cis.y"
{ yyval.tuple = new_tuple(CISTPL_JEDEC_C, yyvsp[0].parse); }
break;
case 17:
#line 133 "yacc_cis.y"
{ yyval.tuple = new_tuple(CISTPL_JEDEC_A, yyvsp[0].parse); }
break;
case 18:
#line 137 "yacc_cis.y"
{ yyval.parse = calloc(1, sizeof(cisparse_t)); }
break;
case 19:
#line 139 "yacc_cis.y"
{
		    yyval.parse->device.dev[yyval.parse->device.ndev].type = yyvsp[-3].num;
		    yyval.parse->device.dev[yyval.parse->device.ndev].speed = yyvsp[-2].num;
		    yyval.parse->device.dev[yyval.parse->device.ndev].size = yyvsp[0].num;
		    yyval.parse->device.ndev++;
		}
break;
case 21:
#line 149 "yacc_cis.y"
{ yyval.parse = calloc(1, sizeof(cisparse_t)); }
break;
case 22:
#line 151 "yacc_cis.y"
{
		    yyval.parse->device.dev[yyval.parse->device.ndev].type = yyvsp[-3].num;
		    yyval.parse->device.dev[yyval.parse->device.ndev].speed = yyvsp[-2].num;
		    yyval.parse->device.dev[yyval.parse->device.ndev].size = yyvsp[0].num;
		    yyval.parse->device.ndev++;
		}
break;
case 24:
#line 161 "yacc_cis.y"
{
		    yyval.parse = calloc(1, sizeof(cisparse_t));
		    yyval.parse->version_1.major = yyvsp[0].flt;
		    yyvsp[0].flt -= floor(yyvsp[0].flt+0.01);
		    while (fabs(yyvsp[0].flt - floor(yyvsp[0].flt+0.5)) > 0.01) {
			yyvsp[0].flt *= 10;
		    }
		    yyval.parse->version_1.minor = yyvsp[0].flt+0.01;
		}
break;
case 25:
#line 171 "yacc_cis.y"
{
		    cistpl_vers_1_t *v = &yyval.parse->version_1;
		    u_int pos = 0;
		    if (v->ns) {
			pos = v->ofs[v->ns-1];
			pos += strlen(v->str+pos)+1;
		    }
		    v->ofs[v->ns] = pos;
		    strcpy(v->str+pos, yyvsp[0].str);
		    v->ns++;
		}
break;
case 26:
#line 185 "yacc_cis.y"
{
		    yyval.parse = calloc(1, sizeof(cisparse_t));
		    yyval.parse->manfid.manf = yyvsp[-2].num;
		    yyval.parse->manfid.card = yyvsp[0].num;
		}
break;
case 27:
#line 193 "yacc_cis.y"
{
		    yyval.parse = calloc(1, sizeof(cisparse_t));
		    yyval.parse->funcid.func = yyvsp[0].num;
		}
break;
case 28:
#line 198 "yacc_cis.y"
{ yyval.parse->funcid.sysinit |= CISTPL_SYSINIT_POST; }
break;
case 29:
#line 200 "yacc_cis.y"
{ yyval.parse->funcid.sysinit |= CISTPL_SYSINIT_ROM; }
break;
case 30:
#line 204 "yacc_cis.y"
{
		    yyval.parse = calloc(1, sizeof(cisparse_t));
		    yyval.parse->jedec.id[0].mfr = yyvsp[-1].num;
		    yyval.parse->jedec.id[0].info = yyvsp[0].num;
		    yyval.parse->jedec.nid = 1;
		}
break;
case 31:
#line 211 "yacc_cis.y"
{
		    yyval.parse->jedec.id[yyval.parse->jedec.nid].mfr = yyvsp[-1].num;
		    yyval.parse->jedec.id[yyval.parse->jedec.nid++].info = yyvsp[0].num;
		}
break;
case 32:
#line 218 "yacc_cis.y"
{
		    yyval.parse = calloc(1, sizeof(cisparse_t));
		    yyval.parse->jedec.id[0].mfr = yyvsp[-1].num;
		    yyval.parse->jedec.id[0].info = yyvsp[0].num;
		    yyval.parse->jedec.nid = 1;
		}
break;
case 33:
#line 225 "yacc_cis.y"
{
		    yyval.parse->jedec.id[yyval.parse->jedec.nid].mfr = yyvsp[-1].num;
		    yyval.parse->jedec.id[yyval.parse->jedec.nid++].info = yyvsp[0].num;
		}
break;
case 34:
#line 232 "yacc_cis.y"
{
		    yyval.parse = calloc(1, sizeof(cisparse_t));
		    yyval.parse->config.base = yyvsp[-4].num;
		    yyval.parse->config.rmask[0] = yyvsp[-2].num;
		    yyval.parse->config.last_idx = yyvsp[0].num;
		}
break;
case 35:
#line 241 "yacc_cis.y"
{
		    yyval.pwr.present = CISTPL_POWER_VNOM;
		    yyval.pwr.param[0] = yyvsp[0].num;
		}
break;
case 36:
#line 246 "yacc_cis.y"
{
		    yyval.pwr.present = CISTPL_POWER_VMIN;
		    yyval.pwr.param[0] = yyvsp[0].num;
		}
break;
case 37:
#line 251 "yacc_cis.y"
{
		    yyval.pwr.present = CISTPL_POWER_VMAX;
		    yyval.pwr.param[0] = yyvsp[0].num;
		}
break;
case 38:
#line 256 "yacc_cis.y"
{
		    yyval.pwr.present = CISTPL_POWER_ISTATIC;
		    yyval.pwr.param[0] = yyvsp[0].num;
		}
break;
case 39:
#line 261 "yacc_cis.y"
{
		    yyval.pwr.present = CISTPL_POWER_IAVG;
		    yyval.pwr.param[0] = yyvsp[0].num;
		}
break;
case 40:
#line 266 "yacc_cis.y"
{
		    yyval.pwr.present = CISTPL_POWER_IPEAK;
		    yyval.pwr.param[0] = yyvsp[0].num;
		}
break;
case 41:
#line 271 "yacc_cis.y"
{
		    yyval.pwr.present = CISTPL_POWER_IDOWN;
		    yyval.pwr.param[0] = yyvsp[0].num;
		}
break;
case 42:
#line 278 "yacc_cis.y"
{
		    yyval.pwr.present = 0;
		}
break;
case 43:
#line 282 "yacc_cis.y"
{
		    yyval.pwr.present |= 1<<(yyvsp[0].pwr.present);
		    yyval.pwr.param[yyvsp[0].pwr.present] = yyvsp[0].pwr.param[0];
		}
break;
case 48:
#line 295 "yacc_cis.y"
{
		    int n = yyval.parse->cftable_entry.io.nwin;
		    yyval.parse->cftable_entry.io.win[n].base = yyvsp[-2].num;
		    yyval.parse->cftable_entry.io.win[n].len = yyvsp[0].num-yyvsp[-2].num+1;
		    yyval.parse->cftable_entry.io.nwin++;
		}
break;
case 49:
#line 302 "yacc_cis.y"
{
		    int n = yyval.parse->cftable_entry.io.nwin;
		    yyval.parse->cftable_entry.io.win[n].base = yyvsp[-2].num;
		    yyval.parse->cftable_entry.io.win[n].len = yyvsp[0].num-yyvsp[-2].num+1;
		    yyval.parse->cftable_entry.io.nwin++;
		}
break;
case 50:
#line 309 "yacc_cis.y"
{ yyval.parse->cftable_entry.io.flags |= CISTPL_IO_8BIT; }
break;
case 51:
#line 311 "yacc_cis.y"
{ yyval.parse->cftable_entry.io.flags |= CISTPL_IO_16BIT; }
break;
case 52:
#line 313 "yacc_cis.y"
{ yyval.parse->cftable_entry.io.flags |= yyvsp[-1].num; }
break;
case 54:
#line 318 "yacc_cis.y"
{
		    int n = yyval.parse->cftable_entry.mem.nwin;
		    yyval.parse->cftable_entry.mem.win[n].card_addr = yyvsp[-4].num;
		    yyval.parse->cftable_entry.mem.win[n].host_addr = yyvsp[0].num;
		    yyval.parse->cftable_entry.mem.win[n].len = yyvsp[-2].num-yyvsp[-4].num+1;
		    yyval.parse->cftable_entry.mem.nwin++;
		}
break;
case 55:
#line 326 "yacc_cis.y"
{
		    int n = yyval.parse->cftable_entry.mem.nwin;
		    yyval.parse->cftable_entry.mem.win[n].card_addr = yyvsp[-4].num;
		    yyval.parse->cftable_entry.mem.win[n].host_addr = yyvsp[0].num;
		    yyval.parse->cftable_entry.mem.win[n].len = yyvsp[-2].num-yyvsp[-4].num+1;
		    yyval.parse->cftable_entry.mem.nwin++;
		}
break;
case 56:
#line 334 "yacc_cis.y"
{ yyval.parse->cftable_entry.io.flags |= CISTPL_IO_8BIT; }
break;
case 57:
#line 336 "yacc_cis.y"
{ yyval.parse->cftable_entry.io.flags |= CISTPL_IO_16BIT; }
break;
case 58:
#line 340 "yacc_cis.y"
{ yyval.parse->cftable_entry.irq.IRQInfo1 = (yyvsp[0].num & 0x0f); }
break;
case 59:
#line 342 "yacc_cis.y"
{
		    yyval.parse->cftable_entry.irq.IRQInfo1 = IRQ_INFO2_VALID;
		    yyval.parse->cftable_entry.irq.IRQInfo2 = yyvsp[0].num;
		}
break;
case 60:
#line 347 "yacc_cis.y"
{ yyval.parse->cftable_entry.irq.IRQInfo1 |= IRQ_PULSE_ID; }
break;
case 61:
#line 349 "yacc_cis.y"
{ yyval.parse->cftable_entry.irq.IRQInfo1 |= IRQ_LEVEL_ID; }
break;
case 62:
#line 351 "yacc_cis.y"
{ yyval.parse->cftable_entry.irq.IRQInfo1 |= IRQ_SHARE_ID; }
break;
case 63:
#line 355 "yacc_cis.y"
{
		    yyval.parse = calloc(1, sizeof(cisparse_t));
		    yyval.parse->cftable_entry.index = yyvsp[0].num;
		}
break;
case 64:
#line 360 "yacc_cis.y"
{ yyval.parse->cftable_entry.flags |= CISTPL_CFTABLE_DEFAULT; }
break;
case 65:
#line 362 "yacc_cis.y"
{ yyval.parse->cftable_entry.flags |= CISTPL_CFTABLE_BVDS; }
break;
case 66:
#line 364 "yacc_cis.y"
{ yyval.parse->cftable_entry.flags |= CISTPL_CFTABLE_WP; }
break;
case 67:
#line 366 "yacc_cis.y"
{ yyval.parse->cftable_entry.flags |= CISTPL_CFTABLE_RDYBSY; }
break;
case 68:
#line 368 "yacc_cis.y"
{ yyval.parse->cftable_entry.flags |= CISTPL_CFTABLE_MWAIT; }
break;
case 69:
#line 370 "yacc_cis.y"
{ yyval.parse->cftable_entry.flags |= CISTPL_CFTABLE_AUDIO; }
break;
case 70:
#line 372 "yacc_cis.y"
{ yyval.parse->cftable_entry.flags |= CISTPL_CFTABLE_READONLY; }
break;
case 71:
#line 374 "yacc_cis.y"
{ yyval.parse->cftable_entry.flags |= CISTPL_CFTABLE_PWRDOWN; }
break;
case 72:
#line 376 "yacc_cis.y"
{ yyval.parse->cftable_entry.vcc = yyvsp[0].pwr; }
break;
case 73:
#line 378 "yacc_cis.y"
{ yyval.parse->cftable_entry.vpp1 = yyvsp[0].pwr; }
break;
case 74:
#line 380 "yacc_cis.y"
{ yyval.parse->cftable_entry.vpp2 = yyvsp[0].pwr; }
break;
case 79:
#line 388 "yacc_cis.y"
{ yyval.parse = NULL; }
break;
#line 1054 "y.tab.c"
    }
    yyssp -= yym;
    yystate = *yyssp;
    yyvsp -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yyssp = YYFINAL;
        *++yyvsp = yyval;
        if (yychar < 0)
        {
            if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yyssp, yystate);
#endif
    if (yyssp >= yyss + yystacksize - 1)
    {
        goto yyoverflow;
    }
    *++yyssp = yystate;
    *++yyvsp = yyval;
    goto yyloop;
yyoverflow:
    yyerror("yacc stack overflow");
yyabort:
    return (1);
yyaccept:
    return (0);
}
