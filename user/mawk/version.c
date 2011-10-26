
/********************************************
version.c
copyright 1991-95.  Michael D. Brennan

This is a source file for mawk, an implementation of
the AWK programming language.

Mawk is distributed without warranty under the terms of
the GNU General Public License, version 2, 1991.
********************************************/

/*$Log: version.c,v $
 *Revision 1.10  1996/07/28 21:47:07  mike
 *gnuish patch
 *
 * Revision 1.9  1996/02/01  04:44:15  mike
 * roll a beta version
 *
 * Revision 1.8  1995/08/20  17:40:45  mike
 * changed _stackavail to stackavail for MSC
 *
 * Revision 1.7  1995/06/10  17:04:10  mike
 * "largest field" replaced by "max NF"
 *
*/

#include "mawk.h"
#include "patchlev.h"

static char mawkid[] = MAWK_ID ;

#define	 VERSION_STRING	 \
  "mawk 1.3%s%s %s, Copyright (C) Michael D. Brennan\n\n"

/* If use different command line syntax for MSDOS
   mark that in VERSION	 */

#ifndef DOS_STRING
#if  MSDOS && ! HAVE_REARGV
#define DOS_STRING  "MsDOS"
#endif
#endif

#ifndef DOS_STRING
#define DOS_STRING	""
#endif

static char fmt[] = "%-14s%10lu\n" ;

/* print VERSION and exit */
void
print_version()
{

   printf(VERSION_STRING, PATCH_STRING, DOS_STRING, DATE_STRING) ;
   fflush(stdout) ;

   print_compiler_id() ;
   fprintf(stderr, "compiled limits:\n") ;
   fprintf(stderr, fmt, "max NF", (long) MAX_FIELD) ;
   fprintf(stderr, fmt, "sprintf buffer", (long) SPRINTF_SZ) ;
   print_aux_limits() ;
   exit(0) ;
}


/*
  Extra info for MSDOS.	 This code contributed by
  Ben Myers
*/

#ifdef __TURBOC__
#include <alloc.h>		/* coreleft() */
#define	 BORL
#endif

#ifdef __BORLANDC__
#include <alloc.h>		/* coreleft() */
#define	 BORL
#endif

#ifdef	BORL
extern unsigned _stklen = 16 * 1024U ;
 /*  4K of stack is enough for a user function call
       nesting depth of 75 so this is enough for 300 */
#endif

#ifdef _MSC_VER
#include <malloc.h>
#endif

#ifdef __ZTC__
#include <dos.h>		/* _chkstack */
#endif


int
print_compiler_id()
{

#ifdef	__TURBOC__
   fprintf(stderr, "MsDOS Turbo C++ %d.%d\n",
	   __TURBOC__ >> 8, __TURBOC__ & 0xff) ;
#endif

#ifdef __BORLANDC__
   fprintf(stderr, "MS-DOS Borland C++ __BORLANDC__ %x\n",
	   __BORLANDC__) ;
#endif

#ifdef _MSC_VER
   fprintf(stderr, "Microsoft C/C++ _MSC_VER %u\n", _MSC_VER) ;
#endif

#ifdef __ZTC__
   fprintf(stderr, "MS-DOS Zortech C++ __ZTC__ %x\n", __ZTC__) ;
#endif

   return 0 ;			 /*shut up */
}


int
print_aux_limits()
{
#ifdef BORL
   extern unsigned _stklen ;
   fprintf(stderr, fmt, "stack size", (unsigned long) _stklen) ;
   fprintf(stderr, fmt, "heap size", (unsigned long) coreleft()) ;
#endif

#ifdef _MSC_VER
   fprintf(stderr, fmt, "stack size", (unsigned long) stackavail()) ;
#endif

#ifdef __ZTC__
/* large memory model only with ztc */
   fprintf(stderr, fmt, "stack size??", (unsigned long) _chkstack()) ;
   fprintf(stderr, fmt, "heap size", farcoreleft()) ;
#endif

   return 0 ;
}
