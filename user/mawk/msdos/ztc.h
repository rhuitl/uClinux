
/********************************************
ztc.h
copyright 1992-4, Michael D. Brennan

This is a source file for mawk, an implementation of
the AWK programming language.

Mawk is distributed without warranty under the terms of
the GNU General Public License, version 2, 1991.
********************************************/

/* Zortech C++ under MSDOS */

/* $Log: ztc.h,v $
 * Revision 1.3  1994/10/08  19:12:08  mike
 * SET_PROGNAME
 *
 * Revision 1.2  1994/10/08  18:49:30  mike
 * add MAX__INT etc
 *
 * Revision 1.1  1994/10/08  18:24:43  mike
 * moved from config directory
 *
 * Revision 1.1.1.1  1993/07/03  18:58:37  mike
 * move source to cvs
 *
 * Revision 1.1  1992/12/27  01:42:50  mike
 * Initial revision
 *
 * Revision 4.2.1  92/06/01  00:00:00  bmyers
 * create Zortech C++ version from Borland C++ version
 * ZTC has matherr function and no info for floating point exceptions.
 *
*/

/*
This might not work anymore under mawk 1.2
MDB 10/94
*/

#ifndef   CONFIG_H
#define   CONFIG_H      1

#define   MSDOS                 1

#define SIZE_T_HFILE <stddef.h>
#define MAX__INT 0x7fff
#define MAX__LONG 0x7fffffff
#define HAVE_FAKE_PIPES  1
/* contradicts comment above ??? */
#define   NO_MATHERR          1


#define  FPE_TRAPS_ON		1
#define  NOINFO_SIGFPE          1


/* how to test far pointers have the same segment */
#include <dos.h>
#define  SAMESEG(p,q)	(FP_SEG(p)==FP_SEG(q))

#if HAVE_REARGV
#define  SET_PROGNAME()  reargv(&argc,&argv) ; progname = argv[0]
#else
#define  SET_PROGNAME()  progname = "mawk"
#endif

#endif  /* CONFIG_H  */
