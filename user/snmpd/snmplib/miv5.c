

#include	"ctypes.h"
#include	"error.h"
#include	"miv.h"
#include	"mix.h"
#include	"mis.h"
#include	"asn.h"

#define		mivNonZero(asn)		\
			asnNonZero (asnValue ((asn)), asnLength ((asn)))

#define		mivNumber(asn)		\
			asnNumber (asnValue ((asn)), asnLength ((asn)))


static	MixStatusType	mivRelease (MixCookieType mix)
{
	mix = mix;
	return (smpErrorGeneric);
}


static	MixStatusType	mivNoSet (MixCookieType mix, MixNamePtrType name, MixLengthType namelen, AsnIdType value)
{
	mix = mix;
	name = name;
	namelen = namelen;
	value = value;
	return (smpErrorReadOnly);
}

static	MixStatusType	mivCreate (MixCookieType mix, MixNamePtrType name, MixLengthType namelen, AsnIdType value)
{
	mix = mix;
	name = name;
	namelen = namelen;
	value = value;
	return (smpErrorGeneric);
}

static	MixStatusType	mivDestroy (MixCookieType mix, MixNamePtrType name, MixLengthType namelen)
{
	mix = mix;
	name = name;
	namelen = namelen;
	return (smpErrorGeneric);
}

static	MixStatusType	mivSet (MixCookieType mix, MixNamePtrType name, MixLengthType namelen, AsnIdType asn)
{
	MivStrPtrType		mp;
	AsnLengthType		k;

	mp = (MivStrPtrType) mix;
	if ((namelen != (MixLengthType) 1) ||
		(*name != (MixNameType) 0)) {
		return (smpErrorNoSuch);
	}
	else if (asnTag (asn) != (AsnTagType) 4) {
		return (smpErrorBadValue);
	}
	else if (asnClass (asn) != asnClassUniversal) {
		return (smpErrorBadValue);
	}
	else if ((k = asnLength (asn)) >= (AsnLengthType) mp->mivStrMaxLen) {
		return (smpErrorBadValue);
	}
	else {
		(void) asnContents (asn, mp->mivStrData, k);
		mp->mivStrLen = (CUnsfType) k;
		return (smpErrorNone);
	}
}

static	AsnIdType	mivGet (MixCookieType mix, MixNamePtrType name, MixLengthType namelen)
{
	MivStrPtrType		mp;

	if ((namelen != (MixLengthType) 1) ||
		(*name != (MixNameType) 0)) {
		return ((AsnIdType) 0);
	}
	else {
		mp = (MivStrPtrType) mix;
		return (asnOctetString (asnClassUniversal,
			(AsnTagType) 4, mp->mivStrData,
			(AsnLengthType) mp->mivStrLen));
	}
}

static	AsnIdType	mivNext (MixCookieType mix, MixNamePtrType name, MixLengthPtrType namelenp)
{
	MivStrPtrType		mp;

	if (*namelenp != (MixLengthType) 0) {
		return ((AsnIdType) 0);
	}
	else {
		*namelenp = (MixLengthType) 1;
		*name = (MixNameType) 0;
		mp = (MivStrPtrType) mix;
		return (asnOctetString (asnClassUniversal,
			(AsnTagType) 4, mp->mivStrData,
			(AsnLengthType) mp->mivStrLen));
	}
}

static	MixOpsType	mivOpsRW	= {

			mivRelease,
			mivCreate,
			mivDestroy,
			mivNext,
			mivGet,
			mivSet

			};

MisStatusType		mivStringRW (MixNamePtrType name, MixLengthType namelen, MivStrPtrType address)
{
	return (misExport (name, namelen, & mivOpsRW,
		(MixCookieType) address));
}

static	MixOpsType	mivOpsRO	= {

			mivRelease,
			mivCreate,
			mivDestroy,
			mivNext,
			mivGet,
			mivNoSet

			};

MisStatusType		mivStringRO (MixNamePtrType name, MixLengthType namelen, MivStrPtrType address)
{
	return (misExport (name, namelen, & mivOpsRO,
		(MixCookieType) address));
}

