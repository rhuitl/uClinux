
/********************************************
print.c
copyright 1991-1993.  Michael D. Brennan

This is a source file for mawk, an implementation of
the AWK programming language.

Mawk is distributed without warranty under the terms of
the GNU General Public License, version 2, 1991.
********************************************/

/* $Log: print.c,v $
 * Revision 1.7  1996/09/18 01:04:36  mike
 * Check ferror() after print and printf.
 *
 * Revision 1.6  1995/10/13  16:56:45  mike
 * Some assumptions that int==long were still in do_printf -- now removed.
 *
 * Revision 1.5  1995/06/18  19:17:50  mike
 * Create a type Int which on most machines is an int, but on machines
 * with 16bit ints, i.e., the PC is a long.  This fixes implicit assumption
 * that int==long.
 *
 * Revision 1.4  1994/10/08  19:15:50  mike
 * remove SM_DOS
 *
 * Revision 1.3  1993/07/15  23:38:19  mike
 * SIZE_T and indent
 *
 * Revision 1.2	 1993/07/07  00:07:50  mike
 * more work on 1.2
 *
 * Revision 1.1.1.1  1993/07/03	 18:58:18  mike
 * move source to cvs
 *
 * Revision 5.6	 1993/02/13  21:57:30  mike
 * merge patch3
 *
 * Revision 5.5	 1993/01/01  21:30:48  mike
 * split new_STRING() into new_STRING and new_STRING0
 *
 * Revision 5.4.1.2  1993/01/20	 12:53:11  mike
 * d_to_l()
 *
 * Revision 5.4.1.1  1993/01/15	 03:33:47  mike
 * patch3: safer double to int conversion
 *
 * Revision 5.4	 1992/11/29  18:03:11  mike
 * when printing integers, convert doubles to
 * longs so output is the same on 16bit systems as 32bit systems
 *
 * Revision 5.3	 1992/08/17  14:23:21  brennan
 * patch2: After parsing, only bi_sprintf() uses string_buff.
 *
 * Revision 5.2	 1992/02/24  10:52:16  brennan
 * printf and sprintf() can now have more args than % conversions
 * removed HAVE_PRINTF_HD -- it was too obscure
 *
 * Revision 5.1	 91/12/05  07:56:22  brennan
 * 1.1 pre-release
 *
*/

#include "mawk.h"
#include "bi_vars.h"
#include "bi_funct.h"
#include "memory.h"
#include "field.h"
#include "scan.h"
#include "files.h"

static void PROTO(print_cell, (CELL *, FILE *)) ;
static STRING *PROTO(do_printf, (FILE *, char *, unsigned, CELL *)) ;
static void PROTO(bad_conversion, (int, char *, char *)) ;
static void PROTO(write_error,(void)) ;

/* prototyping fprintf() or sprintf() is a loser as ellipses will
   always cause problems with ansi compilers depending on what
   they've already seen,
   but we need them here and sometimes they are missing
*/

#ifdef NO_FPRINTF_IN_STDIO
int PROTO(fprintf, (FILE *, const char *,...)) ;
#endif
#ifdef NO_SPRINTF_IN_STDIO
int PROTO(sprintf, (char *, const char *,...)) ;
#endif

/* this can be moved and enlarged  by -W sprintf=num  */
char *sprintf_buff = string_buff ;
char *sprintf_limit = string_buff + SPRINTF_SZ ;

/* Once execute() starts the sprintf code is (belatedly) the only
   code allowed to use string_buff  */

static void
print_cell(p, fp)
   register CELL *p ;
   register FILE *fp ;
{
   int len ;

   switch (p->type)
   {
      case C_NOINIT:
	 break ;
      case C_MBSTRN:
      case C_STRING:
      case C_STRNUM:
	 switch (len = string(p)->len)
	 {
	    case 0:
	       break ;
	    case 1:
	       putc(string(p)->str[0], fp) ;
	       break ;

	    default:
	       fwrite(string(p)->str, 1, len, fp) ;
	 }
	 break ;

      case C_DOUBLE:
	 {
	    Int ival = d_to_I(p->dval) ;

	    /* integers print as "%[l]d" */
	    if ((double) ival == p->dval)  fprintf(fp, INT_FMT, ival) ;
	    else  fprintf(fp, string(OFMT)->str, p->dval) ;
	 }
	 break ;

      default:
	 bozo("bad cell passed to print_cell") ;
   }
}

/* on entry to bi_print or bi_printf the stack is:

   sp[0] = an integer k
       if ( k < 0 )  output is to a file with name in sp[-1]
       { so open file and sp -= 2 }

   sp[0] = k >= 0 is the number of print args
   sp[-k]   holds the first argument
*/

CELL *
bi_print(sp)
   CELL *sp ;			 /* stack ptr passed in */
{
   register CELL *p ;
   register int k ;
   FILE *fp ;

   k = sp->type ;
   if (k < 0)
   {
      /* k holds redirection */
      if ((--sp)->type < C_STRING)  cast1_to_s(sp) ;
      fp = (FILE *) file_find(string(sp), k) ;
      free_STRING(string(sp)) ;
      k = (--sp)->type ;
      /* k now has number of arguments */
   }
   else	 fp = stdout ;

   if (k)
   {
      p = sp - k ;		 /* clear k variables off the stack */
      sp = p - 1 ;
      k-- ;

      while (k > 0)
      {
	 print_cell(p,fp) ; print_cell(OFS,fp) ;
	 cell_destroy(p) ;
	 p++ ; k-- ;
      }

      print_cell(p, fp) ;  cell_destroy(p) ;
   }
   else
   {				/* print $0 */
      sp-- ;
      print_cell(&field[0], fp) ;
   }

   print_cell(ORS, fp) ;
   if (ferror(fp)) write_error() ;
   return sp ;
}

/*---------- types and defs for doing printf and sprintf----*/
#define	 PF_C		0	/* %c */
#define	 PF_S		1	/* %s */
#define	 PF_D		2	/* int conversion */
#define	 PF_F		3	/* float conversion */

/* for switch on number of '*' and type */
#define	 AST(num,type)	((PF_F+1)*(num)+(type))

/* some picky ANSI compilers go berserk without this */
#ifdef NO_PROTOS
typedef int (*PRINTER) () ;
#else
typedef int (*PRINTER) (PTR, const char *,...) ;
#endif

/*-------------------------------------------------------*/

static void
bad_conversion(cnt, who, format)
   int cnt ;
   char *who, *format ;
{
   rt_error("improper conversion(number %d) in %s(\"%s\")",
	    cnt, who, format) ;
}

/* the contents of format are preserved,
   caller does CELL cleanup

   This routine does both printf and sprintf (if fp==0)
*/
static STRING *
do_printf(fp, format, argcnt, cp)
   FILE *fp ;
   char *format ;
   unsigned argcnt ;		 /* number of args on eval stack */
   CELL *cp ;			 /* ptr to an array of arguments 
				    (on the eval stack) */
{
   char save ;
   char *p ;
#ifdef EMBED			/* Work around a compiler bug */
   volatile
#else
   register
#endif
   char *q = format ;
   register char *target ;
   int l_flag, h_flag ;		 /* seen %ld or %hd  */
   int ast_cnt ;
   int ast[2] ;
   Int Ival ;
   int num_conversion = 0 ;	 /* for error messages */
   char *who ;			 /*ditto*/
   int pf_type ;		 /* conversion type */
   PRINTER printer ;		 /* pts at fprintf() or sprintf() */

#ifdef	 SHORT_INTS
   char xbuff[256] ;		 /* splice in l qualifier here */
#endif

   if (fp == (FILE *) 0)	/* doing sprintf */
   {
      target = sprintf_buff ;
      printer = (PRINTER) sprintf ;
      who = "sprintf" ;
   }
   else	 /* doing printf */
   {
      target = (char *) fp ;	 /* will never change */
      printer = (PRINTER) fprintf ;
      who = "printf" ;
   }

   while (1)
   {
      if (fp)			/* printf */
      {
	 while (*q != '%') {
	    if (*q == 0)  {
	       if (ferror(fp)) write_error() ;
	       /* return is ignored */
	       return (STRING *) 0 ;
	    }
	    else  { putc(*q,fp) ; q++ ; }
	 }
      }
      else  /* sprintf */
      {
	 while (*q != '%')
	    if (*q == 0)
	    {
	       if (target > sprintf_limit)	/* damaged */
	       {
		  /* hope this works */
		  rt_overflow("sprintf buffer",
			      sprintf_limit - sprintf_buff) ;
	       }
	       else  /* really done */
	       {
		  STRING *retval ;
		  int len = target - sprintf_buff ;

		  retval = new_STRING0(len) ;
		  memcpy(retval->str, sprintf_buff, len) ;
		  return retval ;
	       }
	    }
	    else  *target++ = *q++ ;
      }


      /* *q == '%' */
      num_conversion++ ;

      if (*++q == '%')		/* %% */
      {
	 if (fp)  putc(*q, fp) ;
	 else  *target++ = *q ;

	 q++ ; continue ;
      }

      /* mark the '%' with p */
      p = (char *)q - 1 ;

      /* eat the flags */
      while (*q == '-' || *q == '+' || *q == ' ' ||
	     *q == '#' || *q == '0')
	 q++ ;

      ast_cnt = 0 ;
      if (*q == '*')
      {
	 if (cp->type != C_DOUBLE)  cast1_to_d(cp) ;
	 ast[ast_cnt++] = d_to_i(cp++->dval) ;
	 argcnt-- ; q++ ;
      }
      else
	 while (scan_code[*(unsigned char *) q] == SC_DIGIT)  q++ ;
      /* width is done */

      if (*q == '.')		/* have precision */
      {
	 q++ ;
	 if (*q == '*')
	 {
	    if (cp->type != C_DOUBLE)  cast1_to_d(cp) ;
	    ast[ast_cnt++] = d_to_i(cp++->dval) ;
	    argcnt-- ; q++ ;
	 }
	 else
	    while (scan_code[*(unsigned char *) q] == SC_DIGIT)	 q++ ;
      }

      if (argcnt <= 0)
	 rt_error("not enough arguments passed to %s(\"%s\")",
		  who, format) ;

      l_flag = h_flag = 0 ;

      if (*q == 'l')  { q++ ; l_flag = 1 ; }
      else if (*q == 'h')  { q++ ; h_flag = 1 ; }
      switch (*q++)
      {
	 case 's':
	    if (l_flag + h_flag)
	       bad_conversion(num_conversion, who, format) ;
	    if (cp->type < C_STRING)  cast1_to_s(cp) ;
	    pf_type = PF_S ;
	    break ;

	 case 'c':
	    if (l_flag + h_flag)
	       bad_conversion(num_conversion, who, format) ;

	    switch (cp->type)
	    {
	       case C_NOINIT:
		  Ival = 0 ;
		  break ;

	       case C_STRNUM:
	       case C_DOUBLE:
		  Ival =  d_to_I(cp->dval) ;
		  break ;

	       case C_STRING:
		  Ival = string(cp)->str[0] ;
		  break ;

	       case C_MBSTRN:
		  check_strnum(cp) ;
		  Ival = cp->type == C_STRING ?
		     string(cp)->str[0] : d_to_I(cp->dval) ;
		  break ;

	       default:
		  bozo("printf %c") ;
	    }

	    pf_type = PF_C ;
	    break ;

	 case 'd':
	 case 'o':
	 case 'x':
	 case 'X':
	 case 'i':
	 case 'u':
	    if (cp->type != C_DOUBLE)  cast1_to_d(cp) ;
	    Ival = d_to_I(cp->dval) ;
	    pf_type = PF_D ;
	    break ;

	 case 'e':
	 case 'g':
	 case 'f':
	 case 'E':
	 case 'G':
	    if (h_flag + l_flag)
	       bad_conversion(num_conversion, who, format) ;
	    if (cp->type != C_DOUBLE)  cast1_to_d(cp) ;
	    pf_type = PF_F ;
	    break ;

	 default:
	    bad_conversion(num_conversion, who, format) ;
      }

      save = *q ;
      *q = 0 ;

#ifdef	SHORT_INTS
      if (pf_type == PF_D)
      {
	 /* need to splice in long modifier */
	 strcpy(xbuff, p) ;

	 if (l_flag) /* do nothing */ ;
	 else
	 {
	    int k = q - p ;

	    if (h_flag)
	    {
	       Ival = (short) Ival ;
	       /* replace the 'h' with 'l' (really!) */
	       xbuff[k - 2] = 'l' ;
	       if (xbuff[k - 1] != 'd' && xbuff[k - 1] != 'i')
		  Ival &= 0xffff ;
	    }
	    else
	    {
	       /* the usual case */
	       xbuff[k] = xbuff[k - 1] ;
	       xbuff[k - 1] = 'l' ;
	       xbuff[k + 1] = 0 ;
	    }
	 }
      }
#endif

      /* ready to call printf() */
      switch (AST(ast_cnt, pf_type))
      {
	 case AST(0, PF_C):
	    (*printer) ((PTR) target, p, (int) Ival) ;
	    break ;

	 case AST(1, PF_C):
	    (*printer) ((PTR) target, p, ast[0], (int) Ival) ;
	    break ;

	 case AST(2, PF_C):
	    (*printer) ((PTR) target, p, ast[0], ast[1], (int) Ival) ;
	    break ;

	 case AST(0, PF_S):
	    (*printer) ((PTR) target, p, string(cp)->str) ;
	    break ;

	 case AST(1, PF_S):
	    (*printer) ((PTR) target, p, ast[0], string(cp)->str) ;
	    break ;

	 case AST(2, PF_S):
	    (*printer) ((PTR) target, p, ast[0], ast[1], string(cp)->str) ;
	    break ;

#ifdef	SHORT_INTS
#define FMT	xbuff		/* format in xbuff */
#else
#define FMT	p		/* p -> format */
#endif
	 case AST(0, PF_D):
	    (*printer) ((PTR) target, FMT, Ival) ;
	    break ;

	 case AST(1, PF_D):
	    (*printer) ((PTR) target, FMT, ast[0], Ival) ;
	    break ;

	 case AST(2, PF_D):
	    (*printer) ((PTR) target, FMT, ast[0], ast[1], Ival) ;
	    break ;

#undef	FMT


	 case AST(0, PF_F):
	    (*printer) ((PTR) target, p, cp->dval) ;
	    break ;

	 case AST(1, PF_F):
	    (*printer) ((PTR) target, p, ast[0], cp->dval) ;
	    break ;

	 case AST(2, PF_F):
	    (*printer) ((PTR) target, p, ast[0], ast[1], cp->dval) ;
	    break ;
      }
      if (fp == (FILE *) 0)
	 while (*target)  target++ ;
      *q = save ; argcnt-- ; cp++ ;
   }
}

CELL *
bi_printf(sp)
   register CELL *sp ;
{
   register int k ;
   register CELL *p ;
   FILE *fp ;

   k = sp->type ;
   if (k < 0)
   {
      /* k has redirection */
      if ((--sp)->type < C_STRING)  cast1_to_s(sp) ;
      fp = (FILE *) file_find(string(sp), k) ;
      free_STRING(string(sp)) ;
      k = (--sp)->type ;
      /* k is now number of args including format */
   }
   else	 fp = stdout ;

   sp -= k ;			 /* sp points at the format string */
   k-- ;

   if (sp->type < C_STRING)  cast1_to_s(sp) ;
   do_printf(fp, string(sp)->str, k, sp + 1);
   free_STRING(string(sp)) ;

   /* cleanup arguments on eval stack */
   for (p = sp + 1; k; k--, p++)  cell_destroy(p) ;
   return --sp ;
}

CELL *
bi_sprintf(sp)
   CELL *sp ;
{
   CELL *p ;
   int argcnt = sp->type ;
   STRING *sval ;

   sp -= argcnt ;		 /* sp points at the format string */
   argcnt-- ;

   if (sp->type != C_STRING)  cast1_to_s(sp) ;
   sval = do_printf((FILE *) 0, string(sp)->str, argcnt, sp + 1) ;
   free_STRING(string(sp)) ;
   sp->ptr = (PTR) sval ;

   /* cleanup */
   for (p = sp + 1; argcnt; argcnt--, p++)  cell_destroy(p) ;

   return sp ;
}


static void 
write_error()
{
   errmsg(errno, "write failure") ;
   mawk_exit(2) ;
}
