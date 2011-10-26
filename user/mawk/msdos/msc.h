
/********************************************
msc.h
copyright 1994, Michael D. Brennan

This is a source file for mawk, an implementation of
the AWK programming language.

Mawk is distributed without warranty under the terms of
the GNU General Public License, version 2, 1991.
********************************************/

/* Microsoft C 6.0A under MSDOS */

/*$Log: msc.h,v $
 *Revision 1.6  1996/07/28 21:46:16  mike
 *gnuish patch
 *
 * Revision 1.5  1995/08/20  17:44:38  mike
 * minor fixes to msc and lower case makefile names
 *
 * Revision 1.4  1995/01/08  21:50:43  mike
 * remove extra #endif
 *
 * Revision 1.3  1994/10/08  19:12:05  mike
 * SET_PROGNAME
 *
 * Revision 1.2  1994/10/08  18:49:28  mike
 * add MAX__INT etc
 *
 * Revision 1.1  1994/10/08  18:24:40  mike
 * moved from config directory
 *
*/

#ifndef   CONFIG_H
#define   CONFIG_H      1


#define   MSDOS_MSC		1
#define   MSDOS                 1

#define SIZE_T_STDDEF_H		1
#define MAX__INT 0x7fff
#define MAX__LONG 0x7fffffff
#define HAVE_FAKE_PIPES  1


#define   FPE_TRAPS_ON		1
#define   NOINFO_SIGFPE		1

/* how to test far pointers have the same segment */
#define SAMESEG(p,q) \
  (((unsigned long)(p)^(unsigned long)(q))<0x10000L)

#if HAVE_REARGV
#define  SET_PROGNAME()  reargv(&argc,&argv) ; progname = argv[0]
#else
#define  SET_PROGNAME()  progname = "mawk"
#ifdef OS2
# ifdef MSDOS
#  define DOS_STRING "dos+os2"
# else
#  define DOS_STRING "os2"
# endif
#endif
#endif

#endif  /* CONFIG_H  */
