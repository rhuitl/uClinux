
/* missing.c */

/*$Log: missing.c,v $
 * Revision 1.2  1995/06/03  09:31:11  mike
 * handle strchr(s,0) correctly
 *
 **/

#include "nstd.h"


#ifdef	NO_STRCHR
char *
strchr(s, c)
   char *s ;
   int c ;
{
   if( c == 0 ) return s + strlen(s) ;

   while (*s)
   {
      if (*s == c)  return s ;
      s++ ;
   }
   return (char *) 0 ;
}

char *
strrchr(s, c)
   char *s ;
   int c ;
{
   char *ret = (char *) 0 ;

   if ( c == 0 ) return s + strlen(s) ;

   while (*s)
   {
      if (*s == c)  ret = s ;
      s++ ;
   }
   return ret ;
}
#endif /* NO_STRCHR */

#ifdef	 NO_STRERROR
extern int sys_nerr ;
extern char *sys_errlist[] ;
char *
strerror(n)
   int n ;
{
   return n > 0 & n < sys_nerr ? sys_errlist[n] : "" ;
}
#endif


#ifdef	NO_MEMCPY
PTR
memcpy(t, s, n)
   PTR t, s ;
   size_t n ;
{
   char *tt = t ;
   char *ss = s ;

   while (n > 0)
   {
      n-- ;
      *tt++ = *ss++ ;
   }
   return t ;
}

int
memcmp(t, s, n)
   PTR t, s ;
   size_t n ;
{
   char *tt = t ;
   char *ss = s ;

   while (n > 0)
   {
      if (*tt < *ss)  return -1 ;
      if (*tt > *ss)  return 1 ;
      tt++ ; ss++ ; n-- ;
   }
   return 0 ;
}

PTR
memset(t, c, n)
   PTR t ;
   int c ;
   size_t n ;
{
   char *tt = (char *) t ;

   while (n > 0)
   {
      n-- ;
      *tt++ = c ;
   }
   return t ;
}
#endif /* NO_MEMCPY */

#ifdef	NO_STRTOD

/* don't use this unless you really don't have strtod() because
   (1) its probably slower than your real strtod()
   (2) atof() may call the real strtod()
*/

double
strtod(s, endptr)
   const char *s ;
   char **endptr ;
{
   register unsigned char *p ;
   int flag ;
   double atof();

   if (endptr)
   {
      p = (unsigned char *) s ;

      flag = 0 ;
      while (*p == ' ' || *p == '\t')  p++ ;
      if (*p == '-' || *p == '+')  p++ ;
      while ( scan_code[*p] == SC_DIGIT ) { flag++ ; p++ ; }
      if (*p == '.')
      {
	 p++ ;
	 while ( scan_code[*p] == SC_DIGIT ) { flag++ ; p++ ; }
      }
      /* done with number part */
      if (flag == 0)
      {				/* no number part */
	 *endptr = s ; return 0.0 ; 
      }
      else  *endptr = (char *) p ;

      /* now look for exponent */
      if (*p == 'e' || *p == 'E')
      {
	 flag = 0 ;
	 p++ ;
	 if (*p == '-' || *p == '+')  p++ ;
	 while ( scan_code[*p] == SC_DIGIT ) { flag++ ; p++ ; }
	 if (flag)  *endptr = (char *) p ;
      }
   }
   return atof(s) ;
}
#endif /* no strtod() */

#ifdef	 NO_FMOD

#ifdef SW_FP_CHECK	/* this is V7 and XNX23A specific */

double
fmod(x, y)
   double x, y;
{
   double modf();
   double dtmp, ipart;

   clrerr() ;
   dtmp = x / y ;
   fpcheck() ;
   modf(dtmp, &ipart) ;
   return x - ipart * y ;
}

#else

double
fmod(x, y)
   double x, y;
{
   double modf();
   double ipart;

   modf(x / y, &ipart) ;
   return x - ipart * y ;
}

#endif
#endif /* NO_FMOD */
