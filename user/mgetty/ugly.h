#ident "$Id: ugly.h,v 4.2 2003/01/14 14:03:19 gert Exp $ Copyright (c) Gert Doering"

/* this module contains various macros that help you write function
 * prototypes that work both with ANSI-C and K&R C
 * macros written by Chris Lewis
 */

#ifdef __STDC__

#define	_PROTO(x)	x
#define _P0(x)		(x)
#define _P1(x,a1)	(a1)
#define _P2(x,a1,a2)	(a1,a2)
#define _P3(x,a1,a2,a3)	(a1,a2,a3)
#define _P4(x,a1,a2,a3,a4)	(a1,a2,a3,a4)
#define _P5(x,a1,a2,a3,a4,a5)	(a1,a2,a3,a4,a5)
#define _P6(x,a1,a2,a3,a4,a5,a6)	(a1,a2,a3,a4,a5,a6)
#define _P7(x,a1,a2,a3,a4,a5,a6,a7)	(a1,a2,a3,a4,a5,a6,a7)
#define _P8(x,a1,a2,a3,a4,a5,a6,a7,a8)	(a1,a2,a3,a4,a5,a6,a7,a8)
#define _P9(x,a1,a2,a3,a4,a5,a6,a7,a8,a9)	(a1,a2,a3,a4,a5,a6,a7,a8,a9)
#define _P10(x,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10)	(a1,a2,a3,a4,a5,a6,a7,a8,a9,a10)

#else

#define _PROTO(x)	()
#define _P0(x)		()
#define _P1(x,a1)	x a1;
#define _P2(x,a1,a2)	x a1;a2;
#define _P3(x,a1,a2,a3)	x a1;a2;a3;
#define _P4(x,a1,a2,a3,a4)	x a1;a2;a3;a4;
#define _P5(x,a1,a2,a3,a4,a5)	x a1;a2;a3;a4;a5;
#define _P6(x,a1,a2,a3,a4,a5,a6)	x a1;a2;a3;a4;a5;a6;
#define _P7(x,a1,a2,a3,a4,a5,a6,a7)	x a1;a2;a3;a4;a5;a6;a7;
#define _P8(x,a1,a2,a3,a4,a5,a6,a7,a8)	x a1;a2;a3;a4;a5;a6;a7;a8;
#define _P9(x,a1,a2,a3,a4,a5,a6,a7,a8,a9)	x a1;a2;a3;a4;a5;a6;a7;a8;a9;
#define _P10(x,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10)	x a1;a2;a3;a4;a5;a6;a7;a8;a9;a10;

#define const
#define volatile

/* <stdarg.h> and function(fmt,...) is incompatible with K&R protoypes */
#ifndef USE_VARARGS
#  define USE_VARARGS
#endif

#endif

