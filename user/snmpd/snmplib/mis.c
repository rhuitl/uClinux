
#include	"ctypes.h"
#include	"error.h"
#include	"local.h"
#include	"mis.h"
#include	"mix.h"
#include	"avl.h"
#include	"aps.h"
#include	"asn.h"

static	MixIdType	misTree;
static	MisAccessType	misAccess;

MisStatusType		misExport (MixNamePtrType name, MixLengthType namelen, MixOpsPtrType ops, MixCookieType cookie)
{
	AsnIdType		value;

	if ((value = mixValue (ops, cookie)) == (AsnIdType) 0) {
		return (errBad);
	}
	else if (mixCreate (misTree, name, namelen, value) != smpErrorNone) {
		value = asnFree (value);
		return (errBad);
	}
	else {
		value = asnFree (value);
		return (errOk);
	}
}

MixIdType		misCommunityToMib (ApsIdType s)
{
	s = s;
	return (misTree);
}

MisAccessType		misCommunityToAccess (ApsIdType s)
{
	s = s;
	return (misAccess);
}

ApsIdType		misCommunityByName (CBytePtrType name)
{
	name = name;
	return ((ApsIdType) 0);
}

#ifdef		NOTDEF

static	MixStatusType	misRelease (cookie)

MixCookieType		cookie;

{
	cookie = cookie;
	return (smpErrorGeneric);
}

static	MixStatusType	misCreate (cookie, name, namelen, asn)

MixCookieType		cookie;
MixNamePtrType		name;
MixLengthType		namelen;
AsnIdType		asn;

{
	cookie = cookie;
	name = name;
	namelen = namelen;
	asn = asn;
	return (smpErrorGeneric);
}

static	MixStatusType	misDestroy (cookie, name, namelen)

MixCookieType		cookie;
MixNamePtrType		name;
MixLengthType		namelen;

{
	cookie = cookie;
	name = name;
	namelen = namelen;
	return (smpErrorGeneric);
}

static	AsnIdType	misGet (cookie, name, namelen)

MixCookieType		cookie;
MixNamePtrType		name;
MixLengthType		namelen;

{
	cookie = cookie;
	name = name;
	namelen = namelen;
	return ((AsnIdType) 0);
}

static	MixStatusType	misSet (cookie, name, namelen, asn)

MixCookieType		cookie;
MixNamePtrType		name;
MixLengthType		namelen;
AsnIdType		asn;

{
	cookie = cookie;
	name = name;
	namelen = namelen;
	asn = asn;
	return (smpErrorGeneric);
}

static	AsnIdType	misNext (cookie, name, namelenp)

MixCookieType		cookie;
MixNamePtrType		name;
MixLengthPtrType	namelenp;

{
	cookie = cookie;
	name = name;
	namelenp = namelenp;
	return ((AsnIdType) 0);
}

static	MixOpsType		misOps	= {

				misRelease,
				misCreate,
				misDestroy,
				misNext,
				misGet,
				misSet

				};

#endif		/*	NOTDEF	*/

CVoidType		misInit (void)
{
	misAccess = (MisAccessType) TRUE;
	misTree = mixNew ();
}
