/*
 * addresses to ASCII
 * Copyright (C) 1998, 1999  Henry Spencer.
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 * 
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 * RCSID $Id: addrtoa.c,v 1.6 1999/04/10 23:19:36 henry Exp $
 */
#include "internal.h"
#include "freeswan.h"

#define	NBYTES	4		/* bytes in an address */
#define	PERBYTE	4		/* three digits plus a dot or NUL */
#define	BUFLEN	(NBYTES*PERBYTE)

#if BUFLEN != ADDRTOA_BUF
#error	"ADDRTOA_BUF in freeswan.h inconsistent with addrtoa() code"
#endif

/*
 *	Fast implementation of conversion from byte to ASCII base 10.
 *	The normal ultoa() uses division and modulus which is _very_
 *	slow.
 */
inline size_t uctoa(unsigned long n, char *dst)
{
	char	*dp = dst;

	if (n >= 200) {
		*dp++ = '2';
		n -= 200;
	} else if (n >= 100) {
		*dp++ = '1';
		n -= 100;
	}

	/* This is loop un-rolled... */
	if (n >= 10) {
		if (n >= 90) {
			*dp++ = '9';
			n -= 90;
		} else if (n >= 80) {
			*dp++ = '8';
			n -= 80;
		} else if (n >= 70) {
			*dp++ = '7';
			n -= 70;
		} else if (n >= 60) {
			*dp++ = '6';
			n -= 60;
		} else if (n >= 50) {
			*dp++ = '5';
			n -= 50;
		} else if (n >= 40) {
			*dp++ = '4';
			n -= 40;
		} else if (n >= 30) {
			*dp++ = '3';
			n -= 30;
		} else if (n >= 20) {
			*dp++ = '2';
			n -= 20;
		} else {
			*dp++ = '1';
			n -= 10;
		}
	} else if (dp != dst) {
		*dp++ = '0';
	}

	*dp++ = '0' + n;
	*dp++ = 0;
	return(dp - dst);
}

/*
 - addrtoa - convert binary address to ASCII dotted decimal
 */
size_t				/* space needed for full conversion */
addrtoa(addr, format, dst, dstlen)
struct in_addr addr;
int format;			/* character */
char *dst;			/* need not be valid if dstlen is 0 */
size_t dstlen;
{
	unsigned long a = ntohl(addr.s_addr);
	int i;
	size_t n;
	unsigned long byte;
	char buf[BUFLEN];
	char *p;

	switch (format) {
	case 0:
		break;
	default:
		return 0;
		break;
	}

	p = buf;
	for (i = NBYTES-1; i >= 0; i--) {
		byte = (a >> (i*8)) & 0xff;
#if 1
		p += uctoa(byte, p);
#else
		p += ultoa(byte, 10, p, PERBYTE);
#endif
		if (i != 0)
			*(p-1) = '.';
	}
	n = p - buf;

	if (dstlen > 0) {
		if (n > dstlen)
			buf[dstlen - 1] = '\0';
		strcpy(dst, buf);
	}
	return n;
}
