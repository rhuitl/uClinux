
/********************************************
main.c
copyright 1991, Michael D. Brennan

This is a source file for mawk, an implementation of
the AWK programming language.

Mawk is distributed without warranty under the terms of
the GNU General Public License, version 2, 1991.
********************************************/

/* $Log: main.c,v $
 * Revision 1.4  1995/06/09  22:57:19  mike
 * parse() no longer returns on error
 *
 * Revision 1.3  1995/06/06  00:18:32  mike
 * change mawk_exit(1) to mawk_exit(2)
 *
 * Revision 1.2  1993/07/17  00:45:19  mike
 * indent
 *
 * Revision 1.1.1.1  1993/07/03	 18:58:16  mike
 * move source to cvs
 *
 * Revision 5.4	 1993/02/13  21:57:27  mike
 * merge patch3
 *
 * Revision 5.3	 1993/01/07  02:50:33  mike
 * relative vs absolute code
 *
 * Revision 5.2.1.1  1993/01/15	 03:33:44  mike
 * patch3: safer double to int conversion
 *
 * Revision 5.2	 1992/12/17  02:48:01  mike
 * 1.1.2d changes for DOS
 *
 * Revision 5.1	 1991/12/05  07:56:14  brennan
 * 1.1 pre-release
 *
*/



/*  main.c  */

#include "mawk.h"
#include "init.h"
#include "code.h"
#include "files.h"


short mawk_state ;		 /* 0 is compiling */
int exit_code ;

int
main(argc, argv)
int argc ; char **argv ;
{

   initialize(argc, argv) ;

   parse() ;

   mawk_state = EXECUTION ;
   execute(execution_start, eval_stack - 1, 0) ;
   /* never returns */
   return 0 ;
}

void
mawk_exit(x)
   int x ;
{
#if  HAVE_REAL_PIPES
   close_out_pipes() ;		 /* no effect, if no out pipes */
#else
#if  HAVE_FAKE_PIPES
   close_fake_pipes() ;
#endif
#endif

   exit(x) ;
}
