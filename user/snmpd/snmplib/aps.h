#ifndef		_APS_H_
#define		_APS_H_


#include	"ctypes.h"
#include	"error.h"
#include	"asn.h"

typedef		ErrStatusType		ApsStatusType;

typedef		CUnswType		ApsIdType;

typedef		CBytePtrType		ApsNameType;

typedef		CUnswType		ApsGoodiesType;

typedef		CBoolType		(*ApsVerifyFnType) (AsnIdType asn);

typedef		AsnIdType		(*ApsEncodeFnType) (ApsIdType aps, AsnIdType asn);

typedef		AsnIdType		(*ApsDecodeFnType) (ApsIdType aps, AsnIdType asn);

ApsStatusType	apsScheme (ApsNameType name, ApsVerifyFnType verifyFn, ApsEncodeFnType encodeFn, ApsDecodeFnType decodeFn);
ApsIdType	apsNew (ApsNameType name, ApsNameType scheme, ApsGoodiesType goodies);
ApsIdType	apsFree (ApsIdType s);
ApsIdType	apsVerify (AsnIdType asn);
AsnIdType	apsEncode (ApsIdType aps, AsnIdType asn);
AsnIdType	apsDecode (ApsIdType aps, AsnIdType asn);
CVoidType	apsInit (void);

#endif		/*	_APS_H_	*/
