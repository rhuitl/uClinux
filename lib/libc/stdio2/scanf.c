#include <stdio.h>
#include <ctype.h>
#include <string.h>

#ifdef __STDC__
#include <stdarg.h>
#define va_strt      va_start
#else
#include <varargs.h>
#define va_strt(p,i) va_start(p)
#endif

#ifdef L_scanf
#ifdef __STDC__
int scanf(const char * fmt, ...)
#else
int scanf(fmt, va_alist)
__const char *fmt;
va_dcl
#endif
{
  va_list ptr;
  int rv;
  va_strt(ptr, fmt);
  rv = vfscanf(stdin,fmt,ptr);
  va_end(ptr);
  return rv;
}
#endif

#ifdef L_sscanf
#ifdef __STDC__
int sscanf(const char * sp, const char * fmt, ...)
#else
int sscanf(sp, fmt, va_alist)
__const char * sp;
__const char *fmt;
va_dcl
#endif
{
static FILE  string[1] =
{
   {0, (char*)(unsigned) -1, 0, 0, (char*) (unsigned) -1, -1,
    _IOFBF | __MODE_READ}
};

  va_list ptr;
  int rv;
  va_strt(ptr, fmt);
  string->bufpos = (char *)sp;
  rv = vfscanf(string,fmt,ptr);
  va_end(ptr);
  return rv;
}
#endif

#ifdef L_fscanf
#ifdef __STDC__
int fscanf(FILE * fp, const char * fmt, ...)
#else
int fscanf(fp, fmt, va_alist)
FILE * fp;
__const char *fmt;
va_dcl
#endif
{
  va_list ptr;
  int rv;
  va_strt(ptr, fmt);
  rv = vfscanf(fp,fmt,ptr);
  va_end(ptr);
  return rv;
}
#endif

#ifdef L_vscanf
int vscanf(fmt, ap)
__const char *fmt;
va_list ap;
{
  return vfscanf(stdin,fmt,ap);
}
#endif

#ifdef L_vsscanf
int vsscanf(sp, fmt, ap)
__const char *sp;
__const char *fmt;
va_list ap;
{
static FILE  string[1] =
{
   {0, (char*)(unsigned) -1, 0, 0, (char*) (unsigned) -1, -1,
    _IOFBF | __MODE_READ}
};

  string->bufpos = (char *) sp;
  return vfscanf(string,fmt,ap);
}
#endif

#ifdef L_vfscanf

#if FLOATS
int _vfscanf_fp_ref = 1;
#else
int _vfscanf_fp_ref = 0;
#endif

/* #define	skip()	do{c=getc(fp); if (c<1) goto done;}while(isspace(c))*/

#define	skip()	while(isspace(c)) { usedcnt++; if ((c=getc(fp))<1) goto done; }

#if FLOATS
/* fp scan actions */
#define F_NADA	0	/* just change state */
#define F_SIGN	1	/* set sign */
#define F_ESIGN	2	/* set exponent's sign */
#define F_INT	3	/* adjust integer part */
#define F_FRAC	4	/* adjust fraction part */
#define F_EXP	5	/* adjust exponent part */
#define F_QUIT	6

#define NSTATE	8
#define FS_INIT		0	/* initial state */
#define FS_SIGNED	1	/* saw sign */
#define FS_DIGS		2	/* saw digits, no . */
#define FS_DOT		3	/* saw ., no digits */
#define FS_DD		4	/* saw digits and . */
#define FS_E		5	/* saw 'e' */
#define FS_ESIGN	6	/* saw exp's sign */
#define FS_EDIGS	7	/* saw exp's digits */

#define FC_DIG		0
#define FC_DOT		1
#define FC_E		2
#define FC_SIGN		3

/* given transition,state do what action? */
static unsigned char fp_do[][NSTATE] = {
	{F_INT,F_INT,F_INT,
	 F_FRAC,F_FRAC,
	 F_EXP,F_EXP,F_EXP},	/* see digit */
	{F_NADA,F_NADA,F_NADA,
	 F_QUIT,F_QUIT,F_QUIT,F_QUIT,F_QUIT},	/* see '.' */
	{F_QUIT,F_QUIT,
	 F_NADA,F_QUIT,F_NADA,
	 F_QUIT,F_QUIT,F_QUIT},	/* see e/E */
	{F_SIGN,F_QUIT,F_QUIT,F_QUIT,F_QUIT,
	 F_ESIGN,F_QUIT,F_QUIT},	/* see sign */
};
/* given transition,state what is new state? */
static unsigned char fp_ns[][NSTATE] = {
	{FS_DIGS,FS_DIGS,FS_DIGS,
	 FS_DD,FS_DD,
	 FS_EDIGS,FS_EDIGS,FS_EDIGS},	/* see digit */
	{FS_DOT,FS_DOT,FS_DD,
	 },	/* see '.' */
	{0,0,
	 FS_E,0,FS_E,
	},	/* see e/E */
	{FS_SIGNED,0,0,0,0,
	 FS_ESIGN,0,0},	/* see sign */
};
/* which states are valid terminators? */
static unsigned char fp_sval[NSTATE] = {
	0,0,1,0,1,0,0,1
};
#endif

int
vfscanf(fp, fmt, ap)
FILE *fp;
__const char *fmt;
va_list ap;
{
   long n;
   int c, width, lval, cnt = 0;
   int usedcnt = 0;
   int   store, neg, base, wide1, endnull, rngflag, c2;
   unsigned char *p;
   unsigned char delim[128], digits[17], *q;
#if FLOATS
   long  frac, expo;
   int   eneg, fraclen, fstate, trans;
   double fx, fp_scan();
#endif

   if (!*fmt)
      return (0);

   c = getc(fp);
   while (c > 0)
   {
      store = 0;
      if (*fmt == '%')
      {
	 n = 0;
	 width = -1;
	 wide1 = 1;
	 base = 10;
	 lval = (sizeof(long) == sizeof(int));
	 store = 1;
	 endnull = 1;
	 neg = -1;

	 strcpy(delim, "\011\012\013\014\015 ");
	 strcpy(digits, "0123456789ABCDEF");

	 if (fmt[1] == '*')
	 {
	    endnull = store = 0;
	    ++fmt;
	 }

	 while (isdigit(*++fmt))/* width digit(s) */
	 {
	    if (width == -1)
	       width = 0;
	    wide1 = width = (width * 10) + (*fmt - '0');
	 }
	 --fmt;
       fmtnxt:
	 ++fmt;
	 switch (*fmt)
	 {
	 case '*':
	    endnull = store = 0;
	    goto fmtnxt;

	 case 'l':		/* long data or long long data*/
	    if (*(fmt + 1) == 'l') {
	    	lval = 2;
	    	fmt++;
	    } else
	    	lval = 1;
	    goto fmtnxt;
	    
	 case 'L':		/* long long data */
	    lval = 2;
	    goto fmtnxt;

	 case 'H':
	 case 'h':		/* short data */
	    lval = 0;
	    goto fmtnxt;

	 case 'I':
	 case 'i':		/* any-base numeric */
	    base = 0;
	    goto numfmt;

	 case 'B':
	 case 'b':		/* unsigned binary */
	    base = 2;
	    goto numfmt;

	 case 'O':
	 case 'o':		/* unsigned octal */
	    base = 8;
	    goto numfmt;

	 case 'X':
	 case 'x':		/* unsigned hexadecimal */
	    base = 16;
	    goto numfmt;

	 case 'D':
	 case 'd':		/* SIGNED decimal */
	    neg = 0;
	    /* FALL-THRU */

	 case 'U':
	 case 'u':		/* unsigned decimal */
	  numfmt:skip();

/*
 * WARNING - I might have introduced a bug in removing the following 2 lines.
 * I don't know why they were there, but they definately appear to be broken.
 * As far as I can tell it implies that if the format char is a capital, or
 * then we should ignore the size of the variable.
 */
#if 0
	    if (isupper(*fmt))
	       lval = 1;
#endif /*0*/

	    if (!base)
	    {
	       base = 10;
	       neg = 0;
	       if (c == '%')
	       {
		  base = 2;
		  goto skip1;
	       }
	       else if (c == '0')
	       {
		  usedcnt++;
		  c = getc(fp);
		  if (c < 1)
		     goto savnum;
		  if ((c != 'x')
		      && (c != 'X'))
		  {
		     base = 8;
		     digits[8] = '\0';
		     goto zeroin;
		  }
		  base = 16;
		  goto skip1;
	       }
	    }

	    if ((neg == 0) && (base == 10)
		&& ((neg = (c == '-')) || (c == '+')))
	    {
	     skip1:
	       usedcnt++;
	       c = getc(fp);
	       if (c < 1)
		  goto done;
	    }

	    digits[base] = '\0';
	    p = ((unsigned char *)
		 strchr(digits, toupper(c)));

	    if ((!c || !p) && width)
	       goto done;

	    while (p && width-- && c)
	    {
	       n = (n * base) + (p - digits);
	       usedcnt++;
	       c = getc(fp);
	     zeroin:
	       p = ((unsigned char *)
		    strchr(digits, toupper(c)));
	    }
	  savnum:
	    if (store)
	    {
	       ++cnt;
	       if (neg == 1)
		  n = -n;
	    stash_it:
	       if (lval == 2)
		  *va_arg(ap, long long*) = n;
	       else if (lval == 1)
		  *va_arg(ap, long*) = n;
	       else
		  *va_arg(ap, short*) = n;
	    }
	    break;

	 case 'n':		/* Number of chars scanned thus far */
	    n = usedcnt;
	    goto stash_it;
	    
#if FLOATS
	 case 'e':		/* float */
	 case 'f':
	 case 'g':
	 case 'E':
	 case 'F':
	 case 'G':
	    skip();

	    if (isupper(*fmt) && lval == 0)
	       lval = 1;

	    fstate = FS_INIT;
	    neg = 0;
	    eneg = 0;
	    n = 0;
	    frac = 0;
	    expo = 0;
	    fraclen = 0;

	    while (c && width--)
	    {
	       if (c >= '0' && c <= '9')
		  trans = FC_DIG;
	       else if (c == '.')
		  trans = FC_DOT;
	       else if (c == '+' || c == '-')
		  trans = FC_SIGN;
	       else if (tolower(c) == 'e')
		  trans = FC_E;
	       else
		  goto fdone;

	       switch (fp_do[trans][fstate])
	       {
	       case F_SIGN:
		  neg = (c == '-');
		  break;
	       case F_ESIGN:
		  eneg = (c == '-');
		  break;
	       case F_INT:
		  n = 10 * n + (c - '0');
		  break;
	       case F_FRAC:
		  frac = 10 * frac + (c - '0');
		  fraclen++;
		  break;
	       case F_EXP:
		  expo = 10 * expo + (c - '0');
		  break;
	       case F_QUIT:
		  goto fdone;
	       }
	       fstate = fp_ns[trans][fstate];
	       usedcnt++;
	       c = getc(fp);
	    }

	  fdone:
	    if (!fp_sval[fstate])
	       goto done;
	    if (store)
	    {
	       fx = fp_scan(neg, eneg, n, frac, expo, fraclen);
	       if (lval == 2)
		  *va_arg(ap, long double *) = fx;
	       else if (lval == 1)
		  *va_arg(ap, double *) = fx;
	       else
		  *va_arg(ap, float *) = fx;
	       ++cnt;
	    }
	    break;
#else
	 case 'e':		/* float */
	 case 'f':
	 case 'g':
	 case 'E':
	 case 'F':
	 case 'G':
	 	fprintf(stderr, "LIBC:SCANF float not implemented");
	 	exit(-1);
#endif

	 case 'C':
	 case 'c':		/* character data */
	    width = wide1;
	    lval = endnull = 0;
	    delim[0] = '\0';
	    goto strproc;

	 case '[':		/* string w/ delimiter set */

	    /* get delimiters */
	    p = delim;

	    if (*++fmt == '^')
	    {
	       fmt++;
	       lval = 0;
	    }
	    else
	       lval = 1;

	    rngflag = 2;
	    if ((*fmt == ']') || (*fmt == '-'))
	    {
	       *p++ = *fmt++;
	       rngflag = 0;
	    }

	    while (*fmt != ']')
	    {
	       if (*fmt == '\0')
		  goto done;
	       switch (rngflag)
	       {
	       case 1:
		  c2 = *(p - 2);
		  if (c2 <= *fmt)
		  {
		     p -= 2;
		     while (c2 < *fmt)
			*p++ = c2++;
		     rngflag = 2;
		     break;
		  }
		  /* fall thru intentional */

	       case 0:
		  rngflag = (*fmt == '-');
		  break;

	       case 2:
		  rngflag = 0;
	       }

	       *p++ = *fmt++;
	    }

	    *p = '\0';
	    goto strproc;

	 case 'S':
	 case 's':		/* string data */
	    lval = 0;
	    skip();
	  strproc:
	    /* process string */
		if (store)
			p = va_arg(ap, unsigned char *);
		else
			p = NULL;

	    /* if the 1st char fails, match fails */
	    if (width)
	    {
	       q = ((unsigned char *)
		    strchr(delim, c));
	       if ((c < 1) || lval == (q==0))
	       {
		  if (endnull)
		     *p = '\0';
		  goto done;
	       }
	    }

	    for (;;)		/* FOREVER */
	    {
	       if (store)
		  *p++ = c;
	       usedcnt++;
	       if (((c = getc(fp)) < 1) ||
		   (--width == 0))
		  break;

	       q = ((unsigned char *)
		    strchr(delim, c));
	       if (lval == (q==0))
	          break;
	    }

	    if (store)
	    {
	       if (endnull)
		  *p = '\0';
	       ++cnt;
	    }
	    break;

	 case '\0':		/* early EOS */
	    --fmt;
	    /* FALL THRU */

	 default:
	    goto cmatch;
	 }
      }
      else if (isspace(*fmt))	/* skip whitespace */
      {
	 skip();
      }
      else
      {				/* normal match char */
       cmatch:
	 if (c != *fmt)
	    break;
         usedcnt++;
	 c = getc(fp);
      }

      if (!*++fmt)
	 break;
   }

 done:				/* end of scan */
   if ((c == EOF) && (cnt == 0))
      return (EOF);

   if( c != EOF )
      ungetc(c, fp);
   return (cnt);
}

#endif
