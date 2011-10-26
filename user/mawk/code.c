
/********************************************
code.c
copyright 1991-93, Michael D. Brennan

This is a source file for mawk, an implementation of
the AWK programming language.

Mawk is distributed without warranty under the terms of
the GNU General Public License, version 2, 1991.
********************************************/


/* $Log: code.c,v $
 * Revision 1.6  1995/06/18  19:42:13  mike
 * Remove some redundant declarations and add some prototypes
 *
 * Revision 1.5  1995/06/09  23:21:36  mike
 * make sure there is an execution block in case user defines function,
 * but no pattern-action pairs
 *
 * Revision 1.4  1995/03/08  00:06:22  mike
 * add a pointer cast
 *
 * Revision 1.3  1994/10/08  19:15:29  mike
 * remove SM_DOS
 *
 * Revision 1.2  1993/07/07  00:07:38  mike
 * more work on 1.2
 *
 * Revision 1.1.1.1  1993/07/03	 18:58:10  mike
 * move source to cvs
 *
 * Revision 5.4	 1993/01/14  13:11:11  mike
 * code2() -> xcode2()
 *
 * Revision 5.3	 1993/01/09  20:15:35  mike
 * code_pop checks if the resolve_list needs relocation
 *
 * Revision 5.2	 1993/01/07  02:50:33  mike
 * relative vs absolute code
 *
 * Revision 5.1	 1991/12/05  07:55:43  brennan
 * 1.1 pre-release
 *
*/

/*  code.c  */

#include "mawk.h"
#include "code.h"
#include "init.h"
#include "jmp.h"
#include "field.h"


static CODEBLOCK *PROTO(new_code, (void)) ;

CODEBLOCK active_code ;

CODEBLOCK *main_code_p, *begin_code_p, *end_code_p ;

INST *begin_start, *main_start, *end_start ;
unsigned begin_size, main_size ;

INST *execution_start = 0 ;


/* grow the active code */
void
code_grow()
{
   unsigned oldsize = code_limit - code_base ;
   unsigned newsize = PAGESZ + oldsize ;
   unsigned delta = code_ptr - code_base ;

   if (code_ptr > code_limit)  bozo("CODEWARN is too small") ;

   code_base = (INST *)
      zrealloc(code_base, INST_BYTES(oldsize),
	       INST_BYTES(newsize)) ;
   code_limit = code_base + newsize ;
   code_warn = code_limit - CODEWARN ;
   code_ptr = code_base + delta ;
}

/* shrinks executable code that's done to its final size */
INST *
code_shrink(p, sizep)
   CODEBLOCK *p ;
   unsigned *sizep ;
{

   unsigned oldsize = INST_BYTES(p->limit - p->base) ;
   unsigned newsize = INST_BYTES(p->ptr - p->base) ;
   INST *retval ;

   *sizep = newsize ;

   retval = (INST *) zrealloc(p->base, oldsize, newsize) ;
   ZFREE(p) ;
   return retval ;
}


/* code an op and a pointer in the active_code */
void
xcode2(op, ptr)
   int op ;
   PTR ptr ;
{
   register INST *p = code_ptr + 2 ;

   if (p >= code_warn)
   {
      code_grow() ;
      p = code_ptr + 2 ;
   }

   p[-2].op = op ;
   p[-1].ptr = ptr ;
   code_ptr = p ;
}

/* code two ops in the active_code */
void
code2op(x, y)
   int x, y ;
{
   register INST *p = code_ptr + 2 ;

   if (p >= code_warn)
   {
      code_grow() ;
      p = code_ptr + 2 ;
   }

   p[-2].op = x ;
   p[-1].op = y ;
   code_ptr = p ;
}

void
code_init()
{
   main_code_p = new_code() ;

   active_code = *main_code_p ;
   code1(_OMAIN) ;
}

/* final code relocation
   set_code() as in set concrete */
void
set_code()
{
   /* set the main code which is active_code */
   if (end_code_p || code_offset > 1)
   {
      int gl_offset = code_offset ;
      extern int NR_flag ;

      if (NR_flag)  code2op(OL_GL_NR, _HALT) ;
      else  code2op(OL_GL, _HALT) ;

      *main_code_p = active_code ;
      main_start = code_shrink(main_code_p, &main_size) ;
      next_label = main_start + gl_offset ;
      execution_start = main_start ;
   }
   else	 /* only BEGIN */
   {
      zfree(code_base, INST_BYTES(PAGESZ)) ;
      ZFREE(main_code_p) ;
   }

   /* set the END code */
   if (end_code_p)
   {
      unsigned dummy ;

      active_code = *end_code_p ;
      code2op(_EXIT0, _HALT) ;
      *end_code_p = active_code ;
      end_start = code_shrink(end_code_p, &dummy) ;
   }

   /* set the BEGIN code */
   if (begin_code_p)
   {
      active_code = *begin_code_p ;
      if (main_start)  code2op(_JMAIN, _HALT) ;
      else  code2op(_EXIT0, _HALT) ;
      *begin_code_p = active_code ;
      begin_start = code_shrink(begin_code_p, &begin_size) ;

      execution_start = begin_start ;
   }

   if ( ! execution_start )
   {
      /* program had functions but no pattern-action bodies */
      execution_start = begin_start = (INST*) zmalloc(2*sizeof(INST)) ;
      execution_start[0].op = _EXIT0 ;
      execution_start[1].op = _HALT  ;
   }
}

void
dump_code()
{
   fdump() ;			 /* dumps all user functions */
   if (begin_start)  
   { fprintf(stdout, "BEGIN\n") ; 
     da(begin_start, stdout) ; }
   if (end_start)  
   { fprintf(stdout, "END\n") ; 
     da(end_start, stdout) ; }
   if (main_start)  
   { fprintf(stdout, "MAIN\n") ; 
     da(main_start, stdout) ; }
}


static CODEBLOCK *
new_code()
{
   CODEBLOCK *p = ZMALLOC(CODEBLOCK) ;

   p->base = (INST *) zmalloc(INST_BYTES(PAGESZ)) ;
   p->limit = p->base + PAGESZ ;
   p->warn = p->limit - CODEWARN ;
   p->ptr = p->base ;

   return p ;
}

/* moves the active_code from MAIN to a BEGIN or END */

void
be_setup(scope)
   int scope ;
{
   *main_code_p = active_code ;

   if (scope == SCOPE_BEGIN)
   {
      if (!begin_code_p)  begin_code_p = new_code() ;
      active_code = *begin_code_p ;
   }
   else
   {
      if (!end_code_p)	end_code_p = new_code() ;
      active_code = *end_code_p ;
   }
}
