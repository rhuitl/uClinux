

#include	<ctype.h>

#include	"ctypes.h"
#include	"local.h"
#include	"debug.h"
#include	"smp.h"
#include	"smx.h"
#include	"oid.h"
#include	"asn.h"
#include	"rdx.h"

static	CCharPtrType		smxKindVector []	= {

	"None",
	"Integer",
	"OctetString",
	"IPAddr",
	"Opaque",
	"Counter",
	"Guage",
	"TimeTicks",
	"ObjectId",
	"Null",

};

static	CCharPtrType		smxErrorVector []	= {

	"noError",
	"tooBig",
	"noSuchName",
	"badValue",
	"readOnly",
	"genErr"
};

SmpErrorType		smxTextToError (CCharPtrType s)
{
	CIntfType		i;

	for (i = (CIntfType) smpErrorNone;
		((i != (CIntfType) smpErrorGeneric) &&
		(strcmp (smxErrorVector [ i ], s) != 0)); i++);
	return ((strcmp (smxErrorVector [ i ], s) != 0) ? smpErrorNone :
		(SmpErrorType) i);
}

CCharPtrType		smxErrorToText (SmpErrorType error)
{
	return (smxErrorVector [ (CIntfType) error ]);
}

SmpKindType		smxTextToKind (CCharPtrType s)
{
	CIntfType		i;

	for (i = (CIntfType) smpKindNone; ((i != (CIntfType) smpKindNull) &&
		(strcmp (smxKindVector [ i ], s) != 0)); i++);
	return ((strcmp (smxKindVector [ i ], s) != 0) ? smpKindNone :
		(SmpKindType) i);
}

CCharPtrType		smxKindToText (SmpKindType kind)
{
	return (smxKindVector [ (CIntfType) kind ]);
}

CIntfType		smxObjectIdToText (CCharPtrType text, CIntfType n, CBytePtrType value, CIntfType m)
{
	return (oidDecode (text, n, value, m));
}

CIntfType		smxTextToObjectId (CBytePtrType value, CIntfType m, CCharPtrType text)
{
	return (oidEncode (value, m, text));
}

CIntfType		smxOctetStringToText (CCharPtrType text, CIntfType n, CBytePtrType value, CIntfType m)
{
	CIntfType		s;
	CIntfType		k;
	CByteType		c;

	if (m > n) {
		return ((CIntfType) -1);
	}

	if (n > 0) {
		*text++ = (CCharType) '"';
	}

	for (s = n - 1; ((s > 0) && (m > 0)); m--) {
		c = (CByteType) *value++;
		if (isprint ((int) c)) {
			*text++ = (CCharType) c;
			s--;
		}
		else {
			*text++ = (CCharType) 0134;
			s--;
			if ((k = rdxEncode08 (text, s, (CUnslType) c)) <
				(CIntfType) 0) {
				s = (CIntfType) -1;
			}
			else {
				text += k;
				s -= k;
			}
		}
	}

	if (m > 0) {
		s = (CIntfType) -1;
	}
	else if (s > (CIntfType) 0) {
		*text++ = (CCharType) '"';
		s--;
		*text = (CCharType) 0;
		s = n - s;
	}
	else {
		s = (CIntfType) -1;
	}
	return (s);
}

CIntfType		smxTextToOctetString (CBytePtrType value, CIntfType m, CCharPtrType text)
{
	CIntfType		k;

	if ((k = (CIntfType) strlen (text)) > m) {
		k = (CIntfType) -1;
	}
	else {
		(void) strcpy ((char *) value, (char *) text);
	}
	return (k);
}

CIntfType		smxTextToIPAddr (CBytePtrType value, CIntfType m, CCharPtrType text)
{
	CCharType		c;
	CCharType		num [ 32 ];
	CCharPtrType		np;
	CUnslType		octet;
	CIntfType		nn;

	if (m < (CIntfType) 4) {
		return ((CIntfType) -1);
	}

	np = num;
	nn = (CIntfType) 32;

	for (m = (CIntfType) 3; ((c = *text) != (CCharType) 0) &&
		(m > (CIntfType) 0); text++) {
		if (c != (CCharType) '.') {
			if (nn > (CIntfType) 0) {
				nn--;
				*np++ = c;
			}
			else {
				m = (CIntfType) -1;
			}
		}
		else {
			*np = (CCharType) 0;
			np = num;
			nn = (CIntfType) 32;
			if (rdxDecodeAny (& octet, num) < (CIntfType) 0) {
				m = (CIntfType) -1;
			}
			else if (octet > (CUnslType) 0xFF) {
				m = (CIntfType) -1;
			}
			else {
				*value++ = (CByteType) octet;
				m--;
			}
		}
	}

	if (m != (CIntfType) 0) {
		m = (CIntfType) -1;
	}
	else if (c == (CCharType) 0) {
		m = (CIntfType) -1;
	}
	else if (rdxDecodeAny (& octet, text) < (CIntfType) 0) {
		m = (CIntfType) -1;
	}
	else if (octet > (CUnslType) 0xFF) {
		m = (CIntfType) -1;
	}
	else {
		*value++ = (CByteType) octet;
		m = (CIntfType) 4;
	}

	return (m);
}

CIntfType		smxIPAddrToText (CCharPtrType text, CIntfType n, CBytePtrType value, CIntfType m)
{
	CIntfType		k;
	CIntfType		s;

	if (m != (CIntfType) 4) {
		return ((CIntfType) -1);
	}

	for (s = n; ((m != (CIntfType) 0) && (s > (CIntfType) 0)); m--) {
		k = rdxEncode10 (text, n, (CUnslType) *value++);
		if (k < (CIntfType) 0) {
			s = (CIntfType) -1;
		}
		else {
			s -= k;
			text += k;
			*text++ = (CCharType) '.';
			s--;
		}
	}

	if (s >= (CIntfType) 0) {
		if (n > (CIntfType) 0) {
			s++;
			*(--text) = (CCharType) 0;
		}
		s = n - s;
	}
	else {
		s = (CIntfType) -1;
	}
	return (s);
}

CIntfType		smxTextToCounter (CUnslPtrType value, CCharPtrType text)
{
	return (rdxDecodeAny (value, text));
}

CIntfType		smxCounterToText (CCharPtrType text, CIntfType n, CUnslType value)
{
	return (rdxEncode10 (text, n, value));
}

CIntfType		smxGuageToText (CCharPtrType text, CIntfType n, CUnslType value)
{
	return (rdxEncode10 (text, n, value));
}

CIntfType		smxTextToGuage (CUnslPtrType value, CCharPtrType text)
{
	return (rdxDecodeAny (value, text));
}

CIntfType		smxTextToInteger (CIntlPtrType value, CCharPtrType text)
{
	CIntfType		status;
	CBoolType		hassign;

	if (text == (CCharPtrType) 0) {
		return ((CIntfType) -1);
	}

	hassign = FALSE;
	if (*text == (CCharType) '-') {
		text++;
		hassign = TRUE;
	}
	status = rdxDecodeAny ((CUnslPtrType) value, text);
	if (hassign) {
		*value = (- *value);
	}
	return (status);
}

CIntfType		smxIntegerToText (CCharPtrType text, CIntfType n, CIntlType value)
{
	CIntfType		s;
	CIntfType		k;

	s = (CIntfType) 0;
	if (value < 0) {
		if (n <= 0) {
			k = (CIntfType) -1;
		}
		else {
			*text++ = (CCharType) '-';
			n--;
			s++;
			value = (- value);
		}
	}

	if (n <= 0) {
		k = (CIntfType) -1;
	}
	else if ((k = rdxEncode10 (text, n, (CUnslType) value)) <
		(CIntfType) 0) {
		k = (CIntfType) -1;
	}
	else {
		k += s;
	}

	return (k);
}

CIntfType		smxValueToText (CCharPtrType text, CIntfType n, SmpBindPtrType bind)
{
	CIntfType		k;

	DEBUG2 ("smxValueToText: Kind %d Len %d\n",
		bind->smpBindKind, bind->smpBindValueLen);
	switch (bind->smpBindKind) {

	case smpKindInteger:
		DEBUG0 ("smxValueToText 0\n");
		if (bind->smpBindValueLen >
			(SmpLengthType) sizeof (CIntlType)) {
			DEBUG0 ("smxValueToText 1\n");
			if (n > (CIntfType) strlen ("OVERFLOW")) {
				(void) strcpy ((char *) text, "OVERFLOW");
			}
			else {
				k = (CIntfType) -1;
			}
		}
		else {
			DEBUG0 ("smxValueToText 2\n");
			k = smxIntegerToText (text, n, (CIntlType)
				bind->smpBindNumber);
		}
		break;
	
	case smpKindCounter:
	case smpKindGuage:
	case smpKindTimeTicks:
		DEBUG0 ("smxValueToText 3\n");
		if (asnNegative ((CBytePtrType) bind->smpBindValue,
			(AsnLengthType) bind->smpBindValueLen)) {
			DEBUG0 ("smxValueToText 4\n");
			if (n > (CIntfType) strlen ("NEGATIVE")) {
				(void) strcpy ((char *) text, "NEGATIVE");
			}
			else {
				k = (CIntfType) -1;
			}
		}
		else if ((bind->smpBindValueLen >
			(SmpLengthType) sizeof (CUnslType)) &&
			(*((CBytePtrType) bind->smpBindValue) !=
			(CByteType) 0)) {
			DEBUG0 ("smxValueToText 5\n");
			if (n > (CIntfType) strlen ("OVERFLOW")) {
				(void) strcpy ((char *) text,
					"OVERFLOW");
			}
			else {
				k = (CIntfType) -1;
			}
		}
		else {
			DEBUG0 ("smxValueToText 6\n");
			k = smxCounterToText (text, n, (CUnslType)
				bind->smpBindNumber);
		}
		break;
	
	case smpKindObjectId:
		k = smxObjectIdToText (text, n,
			(CBytePtrType) bind->smpBindValue,
			(CIntfType) bind->smpBindValueLen);
		break;

	case smpKindOctetString:
		k = smxOctetStringToText (text, n,
			(CBytePtrType) bind->smpBindValue,
			(CIntfType) bind->smpBindValueLen);
		break;

	case smpKindIPAddr:
		k = smxIPAddrToText (text, n,
			(CBytePtrType) bind->smpBindValue,
			(CIntfType) bind->smpBindValueLen);
		break;

	case smpKindNone:
	case smpKindOpaque:
	case smpKindNull:
	default:
		k = (CIntfType) -1;
		break;

	}
	return (k);
}

CIntfType		smxTextToValue (SmpBindPtrType bind, CCharPtrType text)
{
	CIntfType		k;

	switch (bind->smpBindKind) {

	case smpKindInteger:
		k = smxTextToInteger ((CIntlPtrType) & bind->smpBindNumber,
			text);
		bind->smpBindValueLen = (SmpLengthType) 0;
		bind->smpBindValue = (CBytePtrType) 0;
		break;
	
	case smpKindCounter:
		k = smxTextToCounter ((CUnslPtrType) & bind->smpBindNumber,
			text);
		bind->smpBindValueLen = (SmpLengthType) 0;
		bind->smpBindValue = (CBytePtrType) 0;
		break;
	
	case smpKindGuage:
		k = smxTextToCounter ((CUnslPtrType) & bind->smpBindNumber,
			text);
		bind->smpBindValueLen = (SmpLengthType) 0;
		bind->smpBindValue = (CBytePtrType) 0;
		break;
	
	case smpKindObjectId:
		k = smxTextToObjectId ((CBytePtrType) bind->smpBindValue,
			(CIntfType) bind->smpBindValueLen, text);
		bind->smpBindValueLen = (SmpLengthType) k;
		bind->smpBindNumber = (SmpNumberType) 0;
		break;

	case smpKindOctetString:
		k = smxTextToOctetString ((CBytePtrType) bind->smpBindValue,
			(CIntfType) bind->smpBindValueLen, text);
		bind->smpBindValueLen = (SmpLengthType) k;
		bind->smpBindNumber = (SmpNumberType) 0;
		break;

	case smpKindIPAddr:
		k = smxTextToIPAddr ((CBytePtrType) bind->smpBindValue,
			(CIntfType) bind->smpBindValueLen, text);
		bind->smpBindValueLen = (SmpLengthType) k;
		bind->smpBindNumber = (SmpNumberType) 0;
		break;

	case smpKindNone:
	case smpKindNull:
	case smpKindOpaque:
	default:
		k = (CIntfType) -1;
		break;

	}
	return (k);
}

