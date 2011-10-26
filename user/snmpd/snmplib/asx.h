#ifndef		_ASX_H_
#define		_ASX_H_

#include	"ctypes.h"
#include	"error.h"
#include	"asn.h"

typedef		ErrStatusType		AsxStatusType;

AsxStatusType	asxPrint (AsnIdType asn, CUnsfType level);
CBytePtrType	asxTypeToLabel (AsnTypeType type);
CVoidType	asxInit (void);

#endif		/*	_ASX_H_	*/
