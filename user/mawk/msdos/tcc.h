
/********************************************
tcc.h
copyright 1994, Michael D. Brennan

This is a source file for mawk, an implementation of
the AWK programming language.

Mawk is distributed without warranty under the terms of
the GNU General Public License, version 2, 1991.
********************************************/

/* Turbo C under MSDOS */

/* $Log: tcc.h,v $
 * Revision 1.5  1995/08/20  17:14:13  mike
 * get size_t from <stddef.h>
 *
 * Revision 1.4  1995/01/08  21:48:00  mike
 * remove extra #endif
 *
 * Revision 1.3  1994/10/08  19:12:07  mike
 * SET_PROGNAME
 *
 * Revision 1.2  1994/10/08  18:49:29  mike
 * add MAX__INT etc
 *
 * Revision 1.1  1994/10/08  18:24:41  mike
 * moved from config directory
 *
*/

#ifndef   CONFIG_H
#define   CONFIG_H      1

#define   MSDOS                 1

#define SIZE_T_STDDEF_H		1

#define MAX__INT 0x7fff
#define MAX__LONG 0x7fffffff
#define HAVE_FAKE_PIPES  1

/*   strerror() used to not work because all the lines were
     terminated with \n -- if no longer true then this can go 
     away
     ??????????????
*/
#define NO_STRERROR	1

/* Turbo C float lib bungles comparison of NaNs  so we
   have to keep traps on */
#define  FPE_TRAPS_ON		1
#define  FPE_ZERODIVIDE		131
#define  FPE_OVERFLOW		132

/* how to test far pointers have the same segment */
#include <dos.h>
#define  SAMESEG(p,q)	(FP_SEG(p)==FP_SEG(q))

#if HAVE_REARGV
#define  SET_PROGNAME()  reargv(&argc,&argv) ; progname = argv[0]
#else
#define  SET_PROGNAME()  progname = "mawk"
#endif


#endif  /* CONFIG_H  */
