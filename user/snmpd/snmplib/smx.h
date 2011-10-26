#ifndef		_SMX_H_
#define		_SMX_H_

#include	"ctypes.h"
#include	"smp.h"

CCharPtrType		smxErrorToText (SmpErrorType error);
SmpErrorType		smxTextToError (CCharPtrType s);

CCharPtrType		smxKindToText (SmpKindType kind);
SmpKindType		smxTextToKind (CCharPtrType s);

CIntfType		smxValueToText (CCharPtrType text, CIntfType n, SmpBindPtrType bind);
CIntfType		smxTextToValue (SmpBindPtrType bind, CCharPtrType text);

#define			smxNameToText(text, n, name, m)	\
				(smxObjectIdToText ((text), (n), (name), (m)))
#define			smxTextToName(name, m, text)	\
				(smxObjectIdToText ((name), (m), (text)))

CIntfType		smxIPAddrToText (CCharPtrType text, CIntfType n, CBytePtrType value, CIntfType m);
CIntfType		smxTextToIPAddr (CBytePtrType value, CIntfType m, CCharPtrType text);

CIntfType		smxOctetStringToText (CCharPtrType text, CIntfType n, CBytePtrType value, CIntfType m);
CIntfType		smxTextToOctetString (CBytePtrType value, CIntfType m, CCharPtrType text);

CIntfType		smxObjectIdToText (CCharPtrType text, CIntfType n, CBytePtrType value, CIntfType m);
CIntfType		smxTextToObjectId (CBytePtrType value, CIntfType m, CCharPtrType text);

CIntfType		smxIntegerToText (CCharPtrType text, CIntfType n, CIntlType value);
CIntfType		smxTextToInteger (CIntlPtrType value, CCharPtrType text);

CIntfType		smxCounterToText (CCharPtrType text, CIntfType n, CUnslType value);
CIntfType		smxTextToCounter (CUnslPtrType value, CCharPtrType text);

CIntfType		smxGuageToText (CCharPtrType text, CIntfType n, CUnslType value);
CIntfType		smxTextToGuage (CUnslPtrType value, CCharPtrType text);

#endif		/*	_SMX_H_		*/
