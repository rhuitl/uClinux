#ifndef		_OID_H_
#define		_OID_H_

#include	"ctypes.h"

CIntfType		oidDecode (CCharPtrType result, CIntfType m, CBytePtrType oid, CIntfType n);
CIntfType		oidEncode (CBytePtrType oid, CIntfType n, CCharPtrType text);

#endif		/*	_OID_H_		*/
