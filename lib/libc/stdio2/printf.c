/*
 * This file based on printf.c from 'Dlibs' on the atari ST  (RdeBath)
 *
 * 
 *    Dale Schumacher                         399 Beacon Ave.
 *    (alias: Dalnefre')                      St. Paul, MN  55104
 *    dal@syntel.UUCP                         United States of America
 *  "It's not reality that's important, but how you perceive things."
 */

/* Altered to use stdarg, made the core function vfnprintf.
 * Hooked into the stdio package using 'inside information'
 * Altered sizeof() assumptions, now assumes all integers except chars
 * will be either
 *  sizeof(xxx) == sizeof(long) or sizeof(xxx) == sizeof(short)
 *
 * -RDB
 */

#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifdef __STDC__
#include <stdarg.h>
#define va_strt      va_start
#else
#include <varargs.h>
#define va_strt(p,i) va_start(p)
#endif

#include "stdio.h"

extern int vfnprintf(FILE *op, size_t size, __const char *fmt, va_list ap);

#ifdef L_printf

#ifdef __STDC__
int printf(const char * fmt, ...)
#else
int printf(fmt, va_alist)
__const char *fmt;
va_dcl
#endif
{
  va_list ptr;
  int rv;

  va_strt(ptr, fmt);
  rv = vfnprintf(stdout,-1,fmt,ptr);
  va_end(ptr);
  return rv;
}
#endif

#ifdef L_sprintf
#ifdef __STDC__
int sprintf(char * sp, const char * fmt, ...)
#else
int sprintf(sp, fmt, va_alist)
char * sp;
__const char *fmt;
va_dcl
#endif
{
  FILE  string[1] = {
    {0, 0, (char*)(unsigned) -1, 0, (char*) (unsigned) -1, -1,
     _IOFBF | __MODE_WRITE} };

  va_list ptr;
  int rv;
  va_strt(ptr, fmt);
  string->bufpos = sp;
  rv = vfnprintf(string,-1,fmt,ptr);
  va_end(ptr);
  *(string->bufpos) = 0;
  return rv;
}
#endif

#ifdef L_snprintf
#ifdef __STDC__
int snprintf(char * sp, size_t size, const char * fmt, ...)
#else
int snprintf(sp, size, fmt, va_alist)
char * sp;
size_t size;
__const char *fmt;
va_dcl
#endif
{
  FILE  string[1] = {
    {0, 0, (char*)(unsigned) -1, 0, (char*) (unsigned) -1, -1,
     _IOFBF | __MODE_WRITE} };

  va_list ptr;
  int rv;
  va_strt(ptr, fmt);
  string->bufpos = sp;
  rv = vfnprintf(string,size,fmt,ptr);
  va_end(ptr);
  if (rv >= 0) {
  	if (rv < size)
	  sp[rv] = 0;
	else
	  rv = -1;
  }
  return rv;
}
#endif

#ifdef L_vsnprintf
int vsnprintf(sp, size, fmt, ap)
char * sp;
size_t size;
__const char *fmt;
va_list ap;
{
  FILE  string[1] = {
    {0, 0, (char*)(unsigned) -1, 0, (char*) (unsigned) -1, -1,
     _IOFBF | __MODE_WRITE} };

  va_list ptr;
  int rv;
  string->bufpos = sp;
  rv = vfnprintf(string,size,fmt,ap);
  if (rv >= 0) {
  	if (rv < size)
	  sp[rv] = 0;
	else
	  rv = -1;
  }
  return rv;
}
#endif

#ifdef L_asprintf
#ifdef __STDC__
int asprintf(char ** strp, const char * fmt, ...)
#else
int asprintf(strp, fmt, va_alist)
char ** strp;
__const char *fmt;
va_dcl
#endif
{
  va_list arg;
  int rv;

  va_strt(arg, fmt);
  rv = vasprintf(strp,fmt,arg);
  va_end(arg);
  return rv;
}
#endif

#ifdef L_vasprintf
int vasprintf(strp, fmt, ap)
char **strp;
__const char *fmt;
va_list ap;
{
        /* This implementation actually calls the printf machinery twice, but on
ly
         * only does one malloc.  This can be a problem though when custom print
f
         * specs or the %m specifier are involved because the results of the
         * second call might be different from the first. */
        int rv;

        rv = vsnprintf(NULL, 0, fmt, ap);
        return (((rv >= 0) && ((*strp = malloc(++rv)) != NULL))
                        ? vsnprintf(*strp, rv, fmt, ap)
                        : -1);
}
#endif

#ifdef L_fprintf
#ifdef __STDC__
int fprintf(FILE * fp, const char * fmt, ...)
#else
int fprintf(fp, fmt, va_alist)
FILE * fp;
__const char *fmt;
va_dcl
#endif
{
  va_list ptr;
  int rv;
  va_strt(ptr, fmt);
  rv = vfnprintf(fp,-1,fmt,ptr);
  va_end(ptr);
  return rv;
}
#endif

#ifdef L_vprintf
int vprintf(fmt, ap)
__const char *fmt;
va_list ap;
{
  return vfnprintf(stdout,-1,fmt,ap);
}
#endif

#ifdef L_vfprintf
int vfprintf(op, fmt, ap)
FILE *op;
__const char *fmt;
va_list ap;
{
  return vfnprintf(op,-1,fmt,ap);
}
#endif

#ifdef L_vsprintf
int vsprintf(sp, fmt, ap)
char * sp;
__const char *fmt;
va_list ap;
{
  FILE  string[1] = {
    {0, 0, (char*)(unsigned) -1, 0, (char*) (unsigned) -1, -1,
     _IOFBF | __MODE_WRITE} };

  int rv;
  string->bufpos = sp;
  rv = vfnprintf(string,-1,fmt,ap);
  *(string->bufpos) = 0;
  return rv;
}
#endif

#ifdef L_vfnprintf

#if FLOATS
int _vfprintf_fp_ref = 1;
#else
int _vfprintf_fp_ref = 0;
#endif

extern inline int
prtfld(FILE *op, char *buf, int len, int ljustf, char sign, char pad,
		int width, int preci, int buffer_mode, int maxlen, int numeric)
/*
 * Output the given field in the manner specified by the arguments. Return
 * the number of characters output.
 */
{
	int cnt = 0;

	if (maxlen == 0)
		return(0);

	if (!numeric) {
		sign = '\0';
		pad = ' ';
	} else if (*buf == '-')
		sign = *buf++;

	if (preci >= 0) {
		if (numeric) {
			if (pad == '0') preci = -1;
			else preci -= len;
			if (sign) {
				if (preci >= 0)	preci++;
				else		len++;
			}
		} else {
			if (len > preci)	/* limit max data width */
				len = preci;
			preci = -1;		/* Dealt with this for string case */
		}
	}

	if (width < len)	/* flexible field width or width overflow */
		width = len;

	/*
	* at this point: width = total field width len   = actual data width
	* (including possible sign character)
	*/
	width -= len;
	if (preci > 0)
		width -= preci;

	while (width>0 || len>0 || preci > 0) {
		char ch;
		if (!ljustf && width>0)	{	/* left padding */
			--width;
			if (len > 0 && sign && pad == '0')
				goto showsign;
			ch = pad;
		} else if (preci>0 && !ljustf) {/* numeric 0 padding */
			preci--;
			if (sign) goto showsign;
			ch = '0';
		} else if (len>0) {
			--len;
			if (sign) {
showsign:			ch = sign;	/* sign */
				sign = '\0';
			} else
				ch = *buf++;	/* main field */
		} else {
			ch = pad;		/* right padding */
			--width;
		}
		putc(ch, op);
		++cnt;
		if (maxlen != -1 && cnt >= maxlen)
			break;
		if( ch == '\n' && buffer_mode == _IOLBF ) fflush(op);
	}

	return (cnt);
}

int vfnprintf(FILE *op, size_t size, const char *fmt, va_list ap) {
int i, cnt = 0, ljustf, lval;
int   preci, dpoint, width, len, numeric;
char  pad, sign, radix, hash;
char *ptmp;
char  tmp[64], *ltostr(), *ultostr();
int buffer_mode;
long ltmp;
#if FLOATS
double dtmp;
#endif

   /* This speeds things up a bit for unbuffered */
   buffer_mode = (op->mode&__MODE_BUF);
   op->mode &= (~__MODE_BUF);

   while (*fmt)
   {
      if (*fmt == '%')
      {
         if( buffer_mode == _IONBF ) fflush(op);
	 numeric = 0;		/* Numeric type fields */
	 ljustf = 0;		/* left justify flag */
	 sign = '\0';		/* sign char & status */
	 pad = ' ';		/* justification padding char */
	 width = -1;		/* min field width */
	 dpoint = 0;		/* found decimal point */
	 preci = -1;		/* max data width */
	 radix = 10;		/* number base */
	 ptmp = tmp;		/* pointer to area to print */
	 hash = 0;
	 lval = (sizeof(int)==sizeof(long));	/* long value flaged */
fmtnxt:  for(i = 0;;)
	 {
	    const char c = *++fmt;
	    if(c < '0' || c > '9' ) break;
	    i = (i * 10) + (c - '0');
	    if (dpoint)
	       preci = i;
	    else if (!i && (pad == ' '))
	    {
	       pad = '0';
	       goto fmtnxt;
	    }
	    else
	       width = i;
	 }

	 switch (*fmt)
	 {
	 case '\0':		/* early EOS */
	    --fmt;
	    goto charout;

	 case '-':		/* left justification */
	    ljustf = 1;
	    goto fmtnxt;

	 case ' ':
	 case '+':		/* leading sign flag */
	    sign = *fmt;
	    goto fmtnxt;

	 case '*':		/* parameter width value */
	    i = va_arg(ap, int);
	    if (dpoint)
	       preci = i;
	    else
	       width = i;
	    goto fmtnxt;

	 case '.':		/* secondary width field */
	    dpoint = 1;
	    goto fmtnxt;

	 case 'l':		/* long data */
	    if (*(fmt + 1) == 'l') {
	    	lval = 2;
	    	fmt++;
	    } else
	    	lval = 1;
	    goto fmtnxt;

	 case 'L':		/* long long data */
	    lval = 2;
	    goto fmtnxt;

	 case 'h':		/* short data */
	    lval = 0;
	    goto fmtnxt;

	 case 'd':		/* Signed decimal */
	 case 'i':
	    if (lval == 2)	ltmp = (long)(va_arg(ap, long long));
	    else if (lval == 1)	ltmp = va_arg(ap, long);
	    else		ltmp = va_arg(ap, int);
	    ptmp = ltostr(ltmp, 10, 0);
print_number:
	    if (width < preci) width = preci;
	    numeric = 1;
	    goto printit;

	 case 'b':		/* Unsigned binary */
	    radix = 2;
	    goto usproc;

	 case 'o':		/* Unsigned octal */
	    radix = 8;
	    goto usproc;

	 case 'p':		/* Pointer */
	    if (sizeof(char *) == sizeof(long))			lval = 1;
	    else if (sizeof(char *) == sizeof(long long))	lval = 2;
	    else						lval = 0;
	    pad = '0';
	    width = 6;
	    preci = 8;
	    /* fall thru */

	 case 'x':		/* Unsigned hexadecimal */
	 case 'X':
	    radix = 16;
	    /* fall thru */

	 case 'u':		/* Unsigned decimal */
usproc:     if (lval == 2)	ltmp = (long)(va_arg(ap, long long));
	    else if (lval == 1)	ltmp = va_arg(ap, long);
	    else		ltmp = va_arg(ap, int);
	    ptmp = ultostr(ltmp, radix, (*fmt == 'X') ? 1 : 0);
	    if( hash && radix == 8 ) { width = strlen(ptmp)+1; pad='0'; }
	    goto print_number;

	 case '#':
	    hash=1;
	    goto fmtnxt;

	 case 'c':		/* Character */
	    ptmp[0] = va_arg(ap, int);
	    ptmp[1] = '\0';
	    goto print_str;
	
	 case 'm':
	    ptmp = ultostr(errno, radix, 0);
		goto print_number;

	 case 's':		/* String */
	    ptmp = va_arg(ap, char*);
print_str:  if (preci == -1 && dpoint) preci = 0;
printit:    len = strlen(ptmp);
	    cnt += prtfld(op, ptmp, len, ljustf,
			   sign, pad, width, preci, buffer_mode,
			   (size == -1) ? -1 : (size - cnt), numeric);
	    if (size != -1 && cnt >= size) {
	      cnt = -1;
	      goto get_out;
	    }
	    break;

#if FLOATS
	 case 'e':		/* float */
	 case 'f':
	 case 'g':
	 case 'E':
	 case 'G':
	    if (sizeof(double) == sizeof(long double) || lval < 2)
		    dtmp = va_arg(ap, double);
	    else
		    dtmp = (double)(va_arg(ap, long double));
	    gcvt(dtmp, preci, ptmp);
	    preci = -1;
	    goto print_number;
#else
	 case 'e':		/* float */
	 case 'f':
	 case 'g':
	 case 'E':
	 case 'G':
	 	fprintf(stderr, "LIBC:PRINTF float not implemented");
	 	exit(-1);
#endif

	 default:		/* unknown character */
	    goto charout;
	 }
      }
      else
      {
charout: putc(*fmt, op);	/* normal char out */
	 ++cnt;
	 if (size != -1 && cnt >= size) {
	   cnt = -1;
	   goto get_out;
	 }
         if( *fmt == '\n' && buffer_mode == _IOLBF ) fflush(op);
      }
      ++fmt;
   }
get_out:
   op->mode |= buffer_mode;
   if( buffer_mode == _IONBF ) fflush(op);
   if( buffer_mode == _IOLBF ) op->bufwrite = op->bufstart;
   return (cnt);
}
#endif
