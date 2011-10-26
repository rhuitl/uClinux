#ifndef		_DEBUG_H_
#define		_DEBUG_H_

#ifdef		DEBUG

#include	<stdio.h>
#include	"asx.h"

#define		DEBUG0(a)		\
			(void) printf ((a));	\
			(void) fflush (stdout)

#define		DEBUG1(a, b)		\
			(void) printf ((a), (b));	\
			(void) fflush (stdout)

#define		DEBUG2(a, b, c)		\
			(void) printf ((a), (b), (c));	\
			(void) fflush (stdout)

#define		DEBUG3(a, b, c, d)	\
			(void) printf ((a), (b), (c), (d)); \
			(void) fflush (stdout)

#define		DEBUGBYTES(b, n)		\
			{	\
			CIntfType	i;	\
			CBytePtrType	cp;	\
			cp = (CBytePtrType) (b);	\
			for (i = (CIntfType) (n); i > 0; i--) {	\
				printf ("%02.02X ", *cp++);	\
			}}

#define		DEBUGASN(a)	\
			(void) asxPrint ((a), (CUnsfType) 0); \
			(void) fflush (stdout)

#else		/*	DEBUG	*/

#define		DEBUG0(a)
#define		DEBUG1(a, b)
#define		DEBUG2(a, b, c)
#define		DEBUG3(a, b, c, d)
#define		DEBUGBYTES(b, n)
#define		DEBUGASN(a)

#
#endif		/*	DEBUG	*/

#endif		/*	_DEBUG_H_	*/
