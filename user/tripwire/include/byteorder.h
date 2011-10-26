#define BYTEORDER 0x4321
/* 
 * It is a *bad* idea to call a private macro by
 * a well known name that is actually a function on
 * some architectures.  So, I've prepended the
 * names with "bs_".
 * "bs" stands for "byte swapping";  No, really.
 */
#if BYTEORDER == 0x4321

#define bs_ntohl(x)
#define bs_htonl(x)
#else
#if ((BYTEORDER - 0x1111) & 0x444) || !(BYTEORDER & 0xf)
#define bs_ntohl(x)    fatal("Unknown BYTEORDER\n")
#define bs_htonl(x)    fatal("Unknown BYTEORDER\n")
#else
#define BYTEREVERSE(x)  {register unsigned char __t, \
		*__c = (unsigned char *) &(x); \
	__t = __c[3]; __c[3] = *__c; *__c++ = __t; \
	__t = *__c; *__c = __c[1]; *++__c = __t; }
#define bs_ntohl(x) BYTEREVERSE(x)
#define bs_htonl(x) BYTEREVERSE(x)
#endif
#endif


/* $Id: byteorder.h,v 1.1 2001-02-14 00:39:14 pauli Exp $

Then, wherever you use the value, replace:

i = ntohl(j);
 -with-
i = j;
bs_ntohl(i);

The resulting code will be faster that using a subroutine,
 especially if these routines are called often.

--spaf
*/
