#ifndef SCAN_H
#define SCAN_H

#include <sys/cdefs.h>
#ifndef __pure__
#define __pure__
#endif

/* interpret src as ASCII decimal number, write number to dest and
 * return the number of bytes that were parsed */
extern unsigned int scan_ulong(const char *src,unsigned long *dest);

/* same, for long long */
extern unsigned int scan_ulonglong(const char *src,unsigned long long *dest);

/* interpret src as ASCII hexadecimal number, write number to dest and
 * return the number of bytes that were parsed */
extern unsigned int scan_xlong(const char *src,unsigned long *dest);

/* interpret src as ASCII octal number, write number to dest and
 * return the number of bytes that were parsed */
extern unsigned int scan_8long(const char *src,unsigned long *dest);

/* interpret src as signed ASCII decimal number, write number to dest
 * and return the number of bytes that were parsed */
extern unsigned int scan_long(const char *src,signed long *dest);

extern unsigned int scan_uint(const char *src,unsigned int *dest);
extern unsigned int scan_xint(const char *src,unsigned int *dest);
extern unsigned int scan_8int(const char *src,unsigned int *dest);
extern unsigned int scan_int(const char *src,signed int *dest);

extern unsigned int scan_ushort(const char *src,unsigned short *dest);
extern unsigned int scan_xshort(const char *src,unsigned short *dest);
extern unsigned int scan_8short(const char *src,unsigned short *dest);
extern unsigned int scan_short(const char *src,signed short *dest);

/* interpret src as double precision floating point number,
 * write number to dest and return the number of bytes that were parsed */
extern unsigned int scan_double(const char *in, double *dest);

/* if *src=='-', set *dest to -1 and return 1.
 * if *src=='+', set *dest to 1 and return 1.
 * otherwise set *dest to 1 return 0. */
extern unsigned int scan_plusminus(const char *src,signed int *dest);

/* return the highest integer n<=limit so that isspace(in[i]) for all 0<=i<=n */
extern unsigned int scan_whitenskip(const char *in,unsigned int limit) __pure__;

/* return the highest integer n<=limit so that !isspace(in[i]) for all 0<=i<=n */
extern unsigned int scan_nonwhitenskip(const char *in,unsigned int limit) __pure__;

/* return the highest integer n<=limit so that in[i] is element of
 * charset (ASCIIZ string) for all 0<=i<=n */
extern unsigned int scan_charsetnskip(const char *in,const char *charset,unsigned int limit) __pure__;

/* return the highest integer n<=limit so that in[i] is not element of
 * charset (ASCIIZ string) for all 0<=i<=n */
extern unsigned int scan_noncharsetnskip(const char *in,const char *charset,unsigned int limit) __pure__;

#endif
