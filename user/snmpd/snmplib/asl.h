#ifndef		_ASL_H_
#define		_ASL_H_


#include        "asn.h"

typedef		CUnswType		AslIdType;

AslIdType	aslLanguage (AsnLanguageType language);
AslIdType	aslChoice (AslIdType n, CByteType x);
AslIdType	aslAny (AslIdType n, CByteType x);
CVoidType	aslInit (void);

#ifdef		INLINE

#include	"asldefs.h"

#define		aslSon(n)		aslSonDef(n)
#define		aslKind(n)		aslKindDef(n)
#define		aslMinLen(n)		aslMinLenDef(n)
#define		aslNext(n)		aslNextDef(n)

#else		/*	INLINE		*/

AsnTypeType	aslKind (AslIdType n);
AslIdType	aslSon (AslIdType n);
AslIdType	aslNext (AslIdType n);
AsnLengthType	aslMinLen (AslIdType n);

#endif		/*	INLINE		*/

#endif		/*	_ASL_H_		*/
