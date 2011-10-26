

#include	"ctypes.h"
#include	"rdx.h"

#define		rdxDigit10(x)	\
		((((x) >= (CCharType) '0') && ((x) <= (CCharType) '9')) ? \
		(CIntfType) ((x) - (CCharType) '0') : (CIntfType) -1)

#define		rdxDigit08(x)	\
		((((x) >= (CCharType) '0') && ((x) <= (CCharType) '7')) ? \
		(CIntfType) ((x) - (CCharType) '0') : (CIntfType) -1)

CIntfType		rdxDecode10 (CUnslPtrType result, CCharPtrType s)
{

	CCharType	x;
	CIntfType	h;
	CUnslType	w;

	w = (CUnslType) 0;

	while (((x = *s++) != 0) && ((h = rdxDigit10 (x)) != -1)) {
		w = ((CUnslType) 10) * w + ((CUnslType) h);
	}

	*result = w;
	return ((h < (CIntfType) 0) ? h : (CIntfType) 0);
}


CIntfType		rdxDecode08 (CUnslPtrType result, CCharPtrType s)
{
	CCharType	x;
	CIntfType	h;
	CUnslType	w;

	w = (CUnslType) 0;

	while (((x = *s++) != 0) && ((h = rdxDigit08 (x)) != -1)) {
		w = (w << 3) + ((CUnslType) h);
	}

	*result = w;
	return ((h < (CIntfType) 0) ? h : (CIntfType) 0);
}


static	CIntfType	rdxDigit16 (CCharType x)
{
	if (x < (CCharType) '0') {
		return ((CIntfType) -1);
	}
	else if (x <= (CCharType) '9') {
		return ((CIntfType) (x - (CCharType) '0'));
	}
	else {
		x &= 0xDF;
		if ((x >= (CCharType) 'A') && (x <= (CCharType) 'F')) {
			return ((CIntfType) ((x - (CCharType) 'A') + 10));
		}
		else {
			return ((CIntfType) -1);
		}
	}
}


CIntfType		rdxDecode16 (CUnslPtrType result, CCharPtrType s)
{
	CCharType	x;
	CIntfType	h;
	CUnslType	w;

	w = (CUnslType) 0;

	while (((x = *s++) != 0) && ((h = rdxDigit16 (x)) != -1)) {
		w = (w << 4) + ((CUnslType) h);
	}

	*result = w;
	return ((h < (CIntfType) 0) ? h : (CIntfType) 0);
}


CIntfType		rdxDecodeAny (CUnslPtrType result, CCharPtrType s)
{
	CIntfType	status;

	if (s == (char *) 0) {
		result = 0;
	}
	else if (*s == '0') {
		s++;
		if (*s == 'x') {
			s++;
			status = rdxDecode16 (result, s);
		}
		else {
			status = rdxDecode08 (result, s);
		}
	}
	else {
		status = rdxDecode10 (result, s);
	}

	return (status);
}


CIntfType		rdxEncode10 (CCharPtrType s, CIntfType n, CUnslType x)
{
	CIntfType		k;
	CUnslType		quo;

	if (n <= (CIntfType) 0) {
		return ((CIntfType) -1);
	}
	else if (x < (CUnslType) 10) {
		*s++ = (CCharType) (x + '0');
		*s = (CCharType) 0;
		return ((CIntfType) 1);
	}
	else if ((k = rdxEncode10 (s, n - 1, (quo = x / (CUnslType) 10))) !=
		(CIntfType) -1) {
		s += k;
		*s++ = (CCharType) (x - (quo * (CUnslType) 10)) +
			(CCharType) '0';
		*s = (CCharType) 0;
		k++;
	}
	return (k);
}


CIntfType		rdxEncode08 (CCharPtrType s, CIntfType n, CUnslType x)
{
	CIntfType		k;

	if (n <= (CIntfType) 0) {
		return ((CIntfType) -1);
	}
	else if (x < (CUnslType) 8) {
		*s++ = (CCharType) (x + '0');
		*s = (CCharType) 0;
		return ((CIntfType) 1);
	}
	else if ((k = rdxEncode08 (s, n - 1, x >> 3)) !=
		(CIntfType) -1) {
		s += k;
		*s++ = (CCharType) (x & (CUnslType) 0x7) + (CCharType) '0';
		*s = (CCharType) 0;
		k++;
	}
	return (k);
}

