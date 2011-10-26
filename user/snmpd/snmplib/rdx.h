#ifndef		_RDX_H_
#define		_RDX_H_

#include	"ctypes.h"

CIntfType		rdxDecode10 (CUnslPtrType result, CCharPtrType s);
CIntfType		rdxDecode08 (CUnslPtrType result, CCharPtrType s);
CIntfType		rdxDecode16 (CUnslPtrType result, CCharPtrType s);
CIntfType		rdxDecodeAny (CUnslPtrType result, CCharPtrType s);

CIntfType		rdxEncode10 (CCharPtrType s, CIntfType n, CUnslType x);
CIntfType		rdxEncode08 (CCharPtrType s, CIntfType n, CUnslType x);

#endif		/*	_RDX_H_		*/
