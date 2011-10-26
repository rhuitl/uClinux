



#include	"ctypes.h"
#include	"debug.h"
#include	"vec.h"

#define			vecBlank(c)	\
				(((c) == (CCharType) ' ') ||	\
				((c) == (CCharType) '\t') ||	\
				((c) == (CCharType) '\n') ||	\
				((c) == (CCharType) '\r'))

CUnsfType		vecParse (CCharPtrType *vec, CUnsfType vlen, CCharPtrType text)
{
	CUnsfType		k;
	CCharType		c;
	CBoolType		intext;

	k = (CUnsfType) 0;
	intext = FALSE;

	while (((c = *text) != (CCharType) 0) && (k < vlen)) {
		if (vecBlank (c)) {
			if (intext) {
				*text = (CCharType) 0;
				intext = FALSE;
			}
		}
		else if (! intext) {
			*vec++ = text;
			intext = TRUE;
			k++;
		}
		text++;
	}

	return ((c != (CUnsfType) 0) ? (CUnsfType) 0 : k);
}

