

#include	"mix.h"
#include	"asn.h"
#include	"avl.h"
#include	"error.h"
#include	"ctypes.h"
#include	"debug.h"
#include	"local.h"

typedef		struct			MixRecTag {

		MixOpsPtrType		mixRecOps;
		MixCookieType		mixRecCookie;
		MixLengthType		mixRecLen;
		MixNamePtrType		mixRecName;

		}			MixRecType;

typedef		MixRecType		*MixRecPtrType;

#define		mixIdToPtr(m)		((MixRecPtrType) ((MixIdType) (m)))
#define		mixPtrToId(m)		((MixIdType) ((MixRecPtrType) (m)))

#define		mixCookieGet(m)		((mixIdToPtr(m))->mixRecCookie)
#define		mixCookieSet(m, c)	((mixIdToPtr(m))->mixRecCookie = (c))

#define		mixOpsGet(m)		((mixIdToPtr(m))->mixRecOps)
#define		mixOpsSet(m, c)		((mixIdToPtr(m))->mixRecOps = (c))

#define		mixLenGet(m)		((mixIdToPtr(m))->mixRecLen)
#define		mixLenSet(m, c)		((mixIdToPtr(m))->mixRecLen = (c))

#define		mixNameGet(m)		((mixIdToPtr(m))->mixRecName)
#define		mixNameSet(m, c)	((mixIdToPtr(m))->mixRecName = (c))

#define		mixOpRelease(m)		((mixOpsGet(m))->mixOpsReleaseOp)
#define		mixOpCreate(m)		((mixOpsGet(m))->mixOpsCreateOp)
#define		mixOpDestroy(m)		((mixOpsGet(m))->mixOpsDestroyOp)
#define		mixOpNext(m)		((mixOpsGet(m))->mixOpsNextOp)
#define		mixOpGet(m)		((mixOpsGet(m))->mixOpsGetOp)
#define		mixOpSet(m)		((mixOpsGet(m))->mixOpsSetOp)

#ifdef		DEBUG

static	AvlStatusType	mixPrint (AvlInfoType p)
{
	AvlLengthType		i;
	CBytePtrType		cp;

	printf ("<");
	if (p != (AvlInfoType) 0) {
		cp = (CBytePtrType) mixNameGet ((MixIdType) p);
		for (i = mixLenGet ((MixIdType) p); i != 0; i--) {
			printf ("%02.02X ", *cp++);
		}
	}
	printf (">");
	return (errOk);
}

#define		DEBUGMIXPRINT		mixPrint

#else		/*	DEBUG	*/

#define		DEBUGMIXPRINT		((AvlPrintFnType) 0)

#endif		/*	DEBUG	*/

CVoidType		mixInit (void)
{
}

static	AvlBalanceType	mixCmp (AvlInfoType p, AvlNamePtrType name, AvlLengthType namelen)
{
	MixLengthType		n;
	MixNamePtrType		cp;
	CIntfType		r;

	n = mixLenGet ((MixIdType) p);
	cp = mixNameGet ((MixIdType) p);
	r = (CIntfType) 0;
	if (namelen >= n) {
		while ((n-- != 0) && ((r = (CIntfType) *name++ -
			(CIntfType) *cp++) == 0));
	}
	else {
		while ((namelen-- != 0) && ((r = (CIntfType) *name++ -
			(CIntfType) *cp++) == 0));
		if (r == 0) {
			r = -1;
		}
	}

	if (r == 0) {
		return (avlDirBalanced);
	}
	else if (r < 0) {
		return (avlDirLeft);
	}
	else {
		return (avlDirRight);
	}
}

MixIdType		mixAlloc (void)
{
	MixRecPtrType		mp;

	if ((mp = (MixRecPtrType) malloc ((unsigned) sizeof (*mp))) !=
		(MixRecPtrType) 0) {
		return (mixPtrToId (mp));
	}
	else {
		return ((MixIdType) 0);
	}
}

MixIdType		mixNew (void)
{
	MixIdType		mix;
	AvlIdType		tree;

	if ((tree = avlNew (mixCmp, DEBUGMIXPRINT)) == (AvlIdType) 0) {
		return ((MixIdType) 0);
	}
	else if ((mix = mixAlloc ()) != (MixIdType) 0) {
		(void) mixOpsSet (mix, (MixOpsPtrType) 0);
		(void) mixCookieSet (mix, (MixCookieType) tree);
		(void) mixLenSet (mix, (MixLengthType) 0);
		(void) mixNameSet (mix, (MixNamePtrType) 0);
		return (mix);
	}
	else {
		tree = avlFree (tree);
		return ((MixIdType) 0);
	}
}

AsnIdType		mixValue (MixOpsPtrType ops, MixCookieType cookie)
{
	MixRecType		m;
	MixIdType		mix;

	mix = mixPtrToId (& m);
	(void) mixLenSet (mix, (MixLengthType) 0);
	(void) mixNameSet (mix, (MixNamePtrType) 0);
	(void) mixOpsSet (mix, ops);
	(void) mixCookieSet (mix, cookie);
	return (asnOctetString (mixValueAsnClass, mixValueAsnTag,
		(CBytePtrType) & m, (AsnLengthType) sizeof (m)));
}

MixIdType		mixFree (MixIdType mix)
{
	if (mix != (MixIdType) 0) {
		/*
		 *	For each node in AVL tree, invoke
		 *	mixOpRelease primitive. Then call avlFree ().
		 */
		free ((char *) (mixIdToPtr (mix)));
	}
	return ((MixIdType) 0);
}

static	MixStatusType	mixCreateNode (MixIdType mix, MixNamePtrType name, MixLengthType namelen, AsnIdType value)
{
	MixRecType		m;
	MixIdType		new;
	MixIdType		template;

	if (namelen == (MixLengthType) 0) {
		return (smpErrorGeneric);
	}
	if (value == (AsnIdType) 0) {
		return (smpErrorGeneric);
	}
	else if (asnClass (value) != mixValueAsnClass) {
		return (smpErrorGeneric);
	}
	else if (asnTag (value) != mixValueAsnTag) {
		return (smpErrorGeneric);
	}
	else if (asnContents (value, (CBytePtrType) & m,
		(AsnLengthType) sizeof (m)) !=
		(AsnLengthType) sizeof (m)) {
		return (smpErrorGeneric);
	}
	else if ((new = mixAlloc ()) == (MixIdType) 0) {
		return (smpErrorGeneric);
	}
	else if (avlInsert ((AvlIdType) mixCookieGet (mix),
		(AvlNamePtrType) name, (AvlLengthType) namelen,
		(AvlInfoType) new) != errOk) {
		new = mixFree (new);
		return (smpErrorGeneric);
	}
	else {
		template = mixPtrToId (& m);
		(void) mixOpsSet (new, mixOpsGet (template));
		(void) mixCookieSet (new, mixCookieGet (template));
		(void) mixLenSet (new, namelen);
		(void) mixNameSet (new, name);
		return (smpErrorNone);
	}
}

MixStatusType		mixCreate (MixIdType mix, MixNamePtrType name, MixLengthType namelen, AsnIdType value)
{
	AvlInfoType		info;

	if (mix == (MixIdType) 0) {
		return (smpErrorGeneric);
	}

	info = avlFind ((AvlIdType) mixCookieGet (mix),
		(AvlNamePtrType) name, (AvlLengthType) namelen);
	if (info == (AvlInfoType) 0) {
		return (mixCreateNode (mix, name, namelen, value));
	}
	else {
		return ((*mixOpCreate ((MixIdType) info))
			(mixCookieGet ((MixIdType) info),
			name + mixLenGet ((MixIdType) info),
			namelen - mixLenGet ((MixIdType) info), value));
	}
}

AsnIdType		mixNext (MixIdType mix, MixNamePtrType name, MixLengthPtrType namelenp)
{
	AvlInfoType		info;
	MixLengthType		newlen;
	AsnIdType		result;

	if (mix == (MixIdType) 0) {
		return ((AsnIdType) 0);
	}

	result = (AsnIdType) 0;
	info = avlFind ((AvlIdType) mixCookieGet (mix),
		(AvlNamePtrType) name, (AvlLengthType) *namelenp);
	if (info != (AvlInfoType) 0) {
		newlen = *namelenp - mixLenGet ((MixIdType) info);
		result = (*mixOpNext ((MixIdType) info))
			(mixCookieGet ((MixIdType) info),
			name + mixLenGet ((MixIdType) info), & newlen);
		if (result != (AsnIdType) 0) {
			*namelenp = newlen + mixLenGet ((MixIdType) info);
			return (result);
		}
	}

	do {
		info = avlCessor ((AvlIdType) mixCookieGet (mix),
			(AvlNamePtrType) name, (AvlLengthType) *namelenp);
		if (info != (AvlInfoType) 0) {
			*namelenp = mixLenGet ((MixIdType) info);
			(void) bcopy ((char *) mixNameGet ((MixIdType) info),
				(char *) name, (int) *namelenp);
			newlen = (AvlLengthType) 0;
			result = (*mixOpNext ((MixIdType) info))
				(mixCookieGet ((MixIdType) info),
				name + mixLenGet ((MixIdType) info),
				& newlen);
		}

	} while ((info != (AvlInfoType) 0) && (result == (AsnIdType) 0));

	if (info != (AvlInfoType) 0) {
		*namelenp += newlen;
	}

	return (result);
}


AsnIdType		mixGet (MixIdType mix, MixNamePtrType name, MixLengthType namelen)
{
	AvlInfoType		info;

	if (mix == (MixIdType) 0) {
		return ((AsnIdType) 0);
	}

	info = avlFind ((AvlIdType) mixCookieGet (mix),
		(AvlNamePtrType) name, (AvlLengthType) namelen);
	if (info == (AvlInfoType) 0) {
		return ((AsnIdType) 0);
	}
	else {
		return ((*mixOpGet ((MixIdType) info))
			(mixCookieGet ((MixIdType) info),
			name + mixLenGet ((MixIdType) info),
			namelen - mixLenGet ((MixIdType) info)));
	}
}


MixStatusType		mixSet (MixIdType mix, MixNamePtrType name, MixLengthType namelen, AsnIdType value)
{
	AvlInfoType		info;

	if (mix == (MixIdType) 0) {
		return (smpErrorGeneric);
	}

	info = avlFind ((AvlIdType) mixCookieGet (mix),
		(AvlNamePtrType) name, (AvlLengthType) namelen);
	if (info == (AvlInfoType) 0) {
		return (smpErrorNoSuch);
	}
	else {
		return ((*mixOpSet ((MixIdType) info))
			(mixCookieGet ((MixIdType) info),
			name + mixLenGet ((MixIdType) info),
			namelen - mixLenGet ((MixIdType) info),
			value));
	}
}

MixStatusType		mixDestroy (MixIdType mix, AvlNamePtrType name, AvlLengthType namelen)
{
	AvlInfoType		info;

	if (mix == (MixIdType) 0) {
		return (smpErrorGeneric);
	}

	info = avlFind ((AvlIdType) mixCookieGet (mix),
		(AvlNamePtrType) name, (AvlLengthType) namelen);
	if (info == (AvlInfoType) 0) {
		return (smpErrorNoSuch);
	}
	else {
		return ((*mixOpDestroy ((MixIdType) info))
			(mixCookieGet ((MixIdType) info),
			name + mixLenGet ((MixIdType) info),
			namelen - mixLenGet ((MixIdType) info)));
	}
}

