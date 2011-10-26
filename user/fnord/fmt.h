#ifndef FMT_H
#define FMT_H

#include "str.h"

#define FMT_ULONG 40 /* enough space to hold 2^128 - 1 in decimal, plus \0 */
#define FMT_8LONG 44 /* enough space to hold 2^128 - 1 in octal, plus \0 */
#define FMT_XLONG 33 /* enough space to hold 2^128 - 1 in hexadecimal, plus \0 */
#define FMT_LEN ((char *) 0) /* convenient abbreviation */

/* The formatting routines do not append \0!
 * Use them like this: buf[fmt_ulong(buf,number)]=0; */

/* convert signed src integer -23 to ASCII '-','2','3', return length.
 * If dest is not NULL, write result to dest */
unsigned int fmt_long(char *dest,signed long src);

/* convert unsigned src integer 23 to ASCII '2','3', return length.
 * If dest is not NULL, write result to dest */
unsigned int fmt_ulong(char *dest,unsigned long src);

/* same for long long */
unsigned int fmt_ulonglong(char *dest,unsigned long long src);

/* convert unsigned src integer 0x23 to ASCII '2','3', return length.
 * If dest is not NULL, write result to dest */
unsigned int fmt_xlong(char *dest,unsigned long src);

/* convert unsigned src integer 023 to ASCII '2','3', return length.
 * If dest is not NULL, write result to dest */
unsigned int fmt_8long(char *dest,unsigned long src);

#define fmt_uint(dest,src) fmt_ulong(dest,src)
#define fmt_int(dest,src) fmt_long(dest,src)
#define fmt_xint(dest,src) fmt_xlong(dest,src)
#define fmt_8int(dest,src) fmt_8long(dest,src)

/* Like fmt_ulong, but prepend '0' while length is smaller than padto.
 * Does not truncate! */
unsigned int fmt_ulong0(char *,unsigned long src,unsigned int padto);

#define fmt_uint0(buf,src,padto) fmt_ulong0(buf,src,padto)

/* convert src double 1.7 to ASCII '1','.','7', return length.
 * If dest is not NULL, write result to dest */
unsigned int fmt_double(char *dest, double d,int max,int prec);

/* if src is negative, write '-' and return 1.
 * if src is positive, write '+' and return 1.
 * otherwise return 0 */
unsigned int fmt_plusminus(char *dest,int src);

/* if src is negative, write '-' and return 1.
 * otherwise return 0. */
unsigned int fmt_minus(char *dest,int src);

/* copy str to dest until \0 byte, return number of copied bytes. */
unsigned int fmt_str(char *dest,const char *src);

/* copy str to dest until \0 byte or limit bytes copied.
 * return number of copied bytes. */
unsigned int fmt_strn(char *dest,const char *src,unsigned int limit);

/* "foo" -> "  foo"
 * write padlen-srclen spaces, if that is >= 0.  Then copy srclen
 * characters from src.  Truncate only if total length is larger than
 * maxlen.  Return number of characters written. */
unsigned int fmt_pad(char* dest,const char* src,unsigned int srclen,unsigned int padlen,unsigned int maxlen);

/* "foo" -> "foo  "
 * append padlen-srclen spaces after dest, if that is >= 0.  Truncate
 * only if total length is larger than maxlen.  Return number of
 * characters written. */
unsigned int fmt_fill(char* dest,unsigned int srclen,unsigned int padlen,unsigned int maxlen);

#endif
