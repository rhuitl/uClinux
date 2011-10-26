/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton interface for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

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
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     T_IPV4_ADDR = 258,
     T_IPV4_IFACE = 259,
     T_PORT = 260,
     T_HASHSIZE = 261,
     T_HASHLIMIT = 262,
     T_MULTICAST = 263,
     T_PATH = 264,
     T_UNIX = 265,
     T_REFRESH = 266,
     T_IPV6_ADDR = 267,
     T_IPV6_IFACE = 268,
     T_IGNORE_UDP = 269,
     T_IGNORE_ICMP = 270,
     T_IGNORE_TRAFFIC = 271,
     T_BACKLOG = 272,
     T_GROUP = 273,
     T_LOG = 274,
     T_UDP = 275,
     T_ICMP = 276,
     T_IGMP = 277,
     T_VRRP = 278,
     T_TCP = 279,
     T_IGNORE_PROTOCOL = 280,
     T_LOCK = 281,
     T_STRIP_NAT = 282,
     T_BUFFER_SIZE_MAX_GROWN = 283,
     T_EXPIRE = 284,
     T_TIMEOUT = 285,
     T_GENERAL = 286,
     T_SYNC = 287,
     T_STATS = 288,
     T_RELAX_TRANSITIONS = 289,
     T_BUFFER_SIZE = 290,
     T_DELAY = 291,
     T_SYNC_MODE = 292,
     T_LISTEN_TO = 293,
     T_FAMILY = 294,
     T_RESEND_BUFFER_SIZE = 295,
     T_PERSISTENT = 296,
     T_NACK = 297,
     T_CHECKSUM = 298,
     T_WINDOWSIZE = 299,
     T_ON = 300,
     T_OFF = 301,
     T_REPLICATE = 302,
     T_FOR = 303,
     T_IFACE = 304,
     T_ESTABLISHED = 305,
     T_SYN_SENT = 306,
     T_SYN_RECV = 307,
     T_FIN_WAIT = 308,
     T_CLOSE_WAIT = 309,
     T_LAST_ACK = 310,
     T_TIME_WAIT = 311,
     T_CLOSE = 312,
     T_LISTEN = 313,
     T_IP = 314,
     T_PATH_VAL = 315,
     T_NUMBER = 316,
     T_STRING = 317
   };
#endif
/* Tokens.  */
#define T_IPV4_ADDR 258
#define T_IPV4_IFACE 259
#define T_PORT 260
#define T_HASHSIZE 261
#define T_HASHLIMIT 262
#define T_MULTICAST 263
#define T_PATH 264
#define T_UNIX 265
#define T_REFRESH 266
#define T_IPV6_ADDR 267
#define T_IPV6_IFACE 268
#define T_IGNORE_UDP 269
#define T_IGNORE_ICMP 270
#define T_IGNORE_TRAFFIC 271
#define T_BACKLOG 272
#define T_GROUP 273
#define T_LOG 274
#define T_UDP 275
#define T_ICMP 276
#define T_IGMP 277
#define T_VRRP 278
#define T_TCP 279
#define T_IGNORE_PROTOCOL 280
#define T_LOCK 281
#define T_STRIP_NAT 282
#define T_BUFFER_SIZE_MAX_GROWN 283
#define T_EXPIRE 284
#define T_TIMEOUT 285
#define T_GENERAL 286
#define T_SYNC 287
#define T_STATS 288
#define T_RELAX_TRANSITIONS 289
#define T_BUFFER_SIZE 290
#define T_DELAY 291
#define T_SYNC_MODE 292
#define T_LISTEN_TO 293
#define T_FAMILY 294
#define T_RESEND_BUFFER_SIZE 295
#define T_PERSISTENT 296
#define T_NACK 297
#define T_CHECKSUM 298
#define T_WINDOWSIZE 299
#define T_ON 300
#define T_OFF 301
#define T_REPLICATE 302
#define T_FOR 303
#define T_IFACE 304
#define T_ESTABLISHED 305
#define T_SYN_SENT 306
#define T_SYN_RECV 307
#define T_FIN_WAIT 308
#define T_CLOSE_WAIT 309
#define T_LAST_ACK 310
#define T_TIME_WAIT 311
#define T_CLOSE 312
#define T_LISTEN 313
#define T_IP 314
#define T_PATH_VAL 315
#define T_NUMBER 316
#define T_STRING 317




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 35 "read_config_yy.y"
{
	int		val;
	char		*string;
}
/* Line 1529 of yacc.c.  */
#line 178 "y.tab.h"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;

