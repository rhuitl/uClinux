#ifndef		_MIX_H_
#define		_MIX_H_

#include	"ctypes.h"
#include	"error.h"
#include	"asn.h"
#include	"smp.h"
#include	"avl.h"

typedef		CUnswType		MixIdType;

typedef		CUnswType		MixCookieType;

typedef		CByteType		MixNameType;

typedef		MixNameType		*MixNamePtrType;

typedef		CUnsfType		MixLengthType;

typedef		MixLengthType		*MixLengthPtrType;

typedef		SmpErrorType		MixStatusType;

typedef		MixStatusType		(*MixReleaseOpType) (MixCookieType mix);

typedef		AsnIdType		(*MixNextOpType) (MixIdType mix, MixNamePtrType name, MixLengthPtrType namelenp);

typedef		AsnIdType		(*MixGetOpType) (MixIdType mix, MixNamePtrType name, MixLengthType namelen);

typedef		MixStatusType		(*MixSetOpType) (MixIdType mix, MixNamePtrType name, MixLengthType namelen, AsnIdType value);

typedef		MixStatusType		(*MixCreateOpType) (MixIdType mix, MixNamePtrType name, MixLengthType namelen, AsnIdType value);

typedef		MixStatusType		(*MixDestroyOpType) (MixIdType mix, AvlNamePtrType name, AvlLengthType namelen);

typedef		struct			MixOpsTag {

		MixReleaseOpType	mixOpsReleaseOp;
		MixCreateOpType		mixOpsCreateOp;
		MixDestroyOpType	mixOpsDestroyOp;
		MixNextOpType		mixOpsNextOp;
		MixGetOpType		mixOpsGetOp;
		MixSetOpType		mixOpsSetOp;

		}			MixOpsType;

typedef		MixOpsType		*MixOpsPtrType;

#define         mixValueAsnTag          ((AsnTagType) 0x99)
#define         mixValueAsnClass        (asnClassApplication)

#define         mixMaxPathLen        	(32)

CVoidType	mixInit (void);
MixIdType	mixNew (void);
MixIdType	mixFree (MixIdType mix);
AsnIdType	mixValue (MixOpsPtrType ops, MixCookieType cookie);

MixStatusType	mixCreate (MixIdType mix, MixNamePtrType name, MixLengthType namelen, AsnIdType value);
MixStatusType	mixDestroy (MixIdType mix, AvlNamePtrType name, AvlLengthType namelen);
MixStatusType	mixSet (MixIdType mix, MixNamePtrType name, MixLengthType namelen, AsnIdType value);
AsnIdType	mixNext (MixIdType mix, MixNamePtrType name, MixLengthPtrType namelenp);
AsnIdType	mixGet (MixIdType mix, MixNamePtrType name, MixLengthType namelen);

#endif		/*	_MIX_H_	*/
