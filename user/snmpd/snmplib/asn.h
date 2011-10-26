#ifndef		_ASN_H_
#define		_ASN_H_

#include	"ctypes.h"

typedef		CUnswType		AsnIdType;

typedef		CUnswType		AsnLanguageType;

typedef		CUnslType		AsnTagType;

typedef		CIntsType		AsnLengthType;

#define		asnLengthIndef		((AsnLengthType) -1)

typedef		CUnssType		AsnIndexType;

typedef		CIntlType		AsnNumberType;

typedef		enum			AsnStatusTag {

		asnStatusOk,
		asnStatusAccept,
		asnStatusReject,
		asnStatusBad

		}			AsnStatusType;

typedef		enum			AsnClassTag {

		asnClassUniversal,
		asnClassApplication,
		asnClassContext,
		asnClassPrivate

		}			AsnClassType;

typedef		enum			AsnTypeTag {

		asnTypeNone,
		asnTypeInteger,
		asnTypeOctetString,
		asnTypeObjectId,
		asnTypeSequence,
		asnTypeSequenceOf,
		asnTypeNull,
		asnTypeAny

		}			AsnTypeType;

CVoidType	asnInit (void);

AsnIdType	asnNew (AsnLanguageType language);
AsnIdType	asnUnsl (AsnClassType cls, AsnTagType tag, CUnslType value);
AsnIdType	asnIntl (AsnClassType cls, AsnTagType tag, CIntlType value);
AsnIdType	asnOctetString (AsnClassType cls, AsnTagType tag, CBytePtrType value, AsnLengthType n);
AsnIdType	asnObjectId (AsnClassType cls, AsnTagType tag, CBytePtrType value, AsnLengthType n);
AsnIdType	asnSequence (AsnClassType cls, AsnTagType tag, AsnTypeType type);

AsnStatusType	asnDecode (AsnIdType asn, CByteType x);
AsnStatusType	asnAppend (AsnIdType head, AsnIdType item);
AsnLengthType	asnEncode (AsnIdType asn, CBytePtrType cp, AsnLengthType n);

AsnNumberType	asnNumber (CBytePtrType cp, AsnLengthType n);
AsnLengthType	asnContents (AsnIdType asn, CBytePtrType cp, AsnLengthType n);

#ifdef		INLINE

#include	<asndefs.h>

#define		asnTag(asn)		(asnTagDef (asn))
#define		asnType(asn)		(asnTypeDef (asn))
#define		asnClass(asn)		(asnClassDef (asn))
#define		asnLength(asn)		(asnLengthDef (asn))
#define		asnConstructor(asn)	(asnConstructorDef (asn))
#define		asnNegative(cp, n)	(asnNegativeDef(cp, n))
#define		asnNonZero(cp, n)	(asnNonZeroDef(cp, n))
#define		asnSons(asn)		(asnSonsDef (asn))
#define		asnComponent(asn, i)	(asnComponentDef (asn, i))
#define		asnFree(asn)		(asnFreeDef (asn))
#define		asnValue(asn)		(asnValueDef (asn))

#else		/*	INLINE	*/

AsnTypeType	asnType (AsnIdType asn);
AsnTagType	asnTag (AsnIdType asn);
AsnClassType	asnClass (AsnIdType asn);
AsnLengthType	asnLength (AsnIdType asn);
CBoolType	asnConstructor (AsnIdType asn);
CBoolType	asnNegative (CBytePtrType cp, AsnLengthType n);
CBoolType	asnNonZero (CBytePtrType cp, AsnLengthType n);
AsnIndexType	asnSons (AsnIdType asn);
AsnIdType	asnComponent (AsnIdType asn, AsnIndexType i);
AsnIdType	asnFree (AsnIdType asn);
CBytePtrType	asnValue (AsnIdType asn);

#endif		/*	INLINE	*/

#endif		/*	_ASN_H_	*/
