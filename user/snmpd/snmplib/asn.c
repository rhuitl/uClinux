

#include	"debug.h"
#include	"ctypes.h"
#include	"local.h"
#include	"asn.h"
#include	"asl.h"
#include	"asndefs.h"

#define		asnAreaSize		(4 * 1024)

#define		asnEventAlarm		((AsnEventType) 0x100)

static AsnStatusType		asnType0 (AsnPtrType ap, AsnEventType x);
static AsnStatusType		asnInteger0 (AsnPtrType ap, AsnEventType x);
static AsnStatusType		asnOctetString0 (AsnPtrType ap, AsnEventType x);
static AsnStatusType		asnObjectId0 (AsnPtrType ap, AsnEventType x);
static AsnStatusType		asnSeq (AsnPtrType ap, AsnEventType x);
static AsnStatusType		asnSeqOf (AsnPtrType ap, AsnEventType x);
static AsnStatusType		asnNull (AsnPtrType ap, AsnEventType x);

static	AsnParseFnType	*asnFnTbl [] = {

			asnType0,
			asnInteger0,
			asnOctetString0,
			asnObjectId0,
			asnSeq,
			asnSeqOf,
			asnNull,
			asnType0,

			};

#define		asnEntry(n)	\
		(asnFnTbl [ (int) (aslKind ((AslIdType) (n))) ])

static	AsnStatusType	asnPop (AsnPtrType ap)
{
	AsnDatumPtrType		dp;
	AsnDatumPtrType		pp;
	AsnIndexType		pd;

	DEBUG0 ("asnPop\n");
	dp = asnRootToPtr (ap);
	dp->asnDatumTotalLen += dp->asnDatumActualLen;
	dp->asnDatumAlarm = (AsnLengthType) 0;
	ap->asnWomb = aslNext (dp->asnDatumNode);
	pd = dp->asnDatumParent;
	if (pd != (AsnIndexType) 0) {
		pp = ap->asnArea + pd;
		ap->asnFn = asnEntry (pp->asnDatumNode);
		if (asnDatumIndefLengthGet (pp)) {
			pp->asnDatumActualLen += dp->asnDatumTotalLen;
		}
		pp->asnDatumUserLen += dp->asnDatumUserLen;
		pp->asnDatumSons += dp->asnDatumSons;
		if (pp->asnDatumMaxLen != asnLengthIndef) {
			pp->asnDatumMaxLen -= dp->asnDatumTotalLen;
		}
		ap->asnDatum = pd;
	}
	ap->asnParseLevel--;
	return (asnStatusOk);
}

static	AsnStatusType	asnPush (AsnPtrType ap, AslIdType node)
{
	AsnDatumPtrType		dp;
	AsnDatumPtrType		pp;
	AsnIndexType		dd;
	AsnIndexType		pd;

	DEBUG0 ("asnPush\n");
	if (ap->asnBytesLeft < sizeof (*dp)) {
		return (asnStatusBad);
	}
	else {
		ap->asnBytesLeft -= sizeof (*dp);
		dd = (--ap->asnDatumFree);
		dp = ap->asnArea + dd;
		ap->asnParseLevel++;
		pd = ap->asnDatum;
		pp = ap->asnArea + pd;
		pp->asnDatumSons++;
		dp->asnDatumMyself = ap->asnNewId++;
		dp->asnDatumSons = (AsnIndexType) 0;
		dp->asnDatumTotalLen = 0;
		dp->asnDatumActualLen = 0;
		dp->asnDatumUserLen = 0;
		dp->asnDatumAlarm = 0;
		dp->asnDatumFlags = (CUnssType) 0;
		dp->asnDatumValue = (AsnLengthType) 0;
		dp->asnDatumParent = pd;
		dp->asnDatumNode = node;
		dp->asnDatumMaxLen = pp->asnDatumMaxLen;
		if ((pp->asnDatumMaxLen != asnLengthIndef) &&
			(asnDatumIndefLengthGet (pp))) {
			dp->asnDatumMaxLen -= 2;
		}
		if (aslNext (pp->asnDatumNode) != (AslIdType) 0) {
			asnDatumMustMatchSet (dp, FALSE);
		}
		else {
			asnDatumMustMatchSet (dp, asnDatumMustMatchGet (pp));
		}
		ap->asnFn = asnEntry (dp->asnDatumNode);
		ap->asnDatum = dd;
		ap->asnWomb = (AslIdType) 0;
		return (asnStatusOk);
	}
}

static	AsnStatusType	asnInteger2 (AsnPtrType ap, AsnEventType x)
{
	if (x == asnEventAlarm) {
		DEBUG0 ("asnInteger2: 1\n");
		return (asnPop (ap));
	}
	else {
		DEBUG0 ("asnInteger2: 2\n");
		return (asnStatusOk);
	}
}


static	AsnStatusType	asnInteger1 (AsnPtrType ap, AsnEventType x)
{
	AsnDatumPtrType		dp;

	DEBUG1 ("asnInteger1: %02.02X\n", x);
	dp = asnRootToPtr (ap);
	DEBUG1 ("asnInteger1: %02.02X\n",
		*(((CBytePtrType) ap->asnArea) + dp->asnDatumValue));
	DEBUG1 ("asnInteger1: %d\n", dp->asnDatumValue);
	DEBUG1 ("asnInteger1: %08.08X\n", dp);
	if (x == asnEventAlarm) {
		DEBUG0 ("asnInteger1: 1\n");
		return (asnPop (ap));
	}
	else {
		if (*(((CBytePtrType) ap->asnArea) + dp->asnDatumValue) ==
			(CByteType) ((((CUnsfType) x) & 0x80) ? 0xFF : 0)) {
			DEBUG0 ("asnInteger1: 2\n");
			return (asnStatusReject);
		}
		else {
			ap->asnFn = asnInteger2;
			DEBUG0 ("asnInteger1: 3\n");
			return (asnStatusOk);
		}
	}
}


static	AsnStatusType	asnInteger0 (AsnPtrType ap, AsnEventType x)
{
	AsnDatumPtrType		dp;

	DEBUG1 ("asnInteger0: %02.02X\n", x);
	dp = asnRootToPtr (ap);
	DEBUG1 ("asnInteger1: %02.02X\n",
		*(((CBytePtrType) ap->asnArea) + dp->asnDatumValue));
	DEBUG1 ("asnInteger0: %d\n", dp->asnDatumValue);
	DEBUG1 ("asnInteger0: %08.08X\n", dp);
	dp->asnDatumUserLen = dp->asnDatumActualLen;
	DEBUG1 ("asnInteger1: %02.02X\n",
		*(((CBytePtrType) ap->asnArea) + dp->asnDatumValue));
	if (x == asnEventAlarm) {
		DEBUG0 ("asnInteger0: 1\n");
		return (asnStatusReject);
	}
	else {
		ap->asnFn = asnInteger1;
		DEBUG0 ("asnInteger0: 2\n");
		return (asnStatusOk);
	}
}

#define		asnOctetString1		asnInteger2

static	AsnStatusType	asnOctetString0 (AsnPtrType ap, AsnEventType x)
{
	AsnDatumPtrType		dp;

	dp = asnRootToPtr (ap);
	dp->asnDatumUserLen = dp->asnDatumActualLen;
	if (x == asnEventAlarm) {
		return (asnPop (ap));
	}
	else {
		ap->asnFn = asnOctetString1;
		return (asnStatusOk);
	}
}

static	AsnStatusType	asnObjectId1 (AsnPtrType ap, AsnEventType x)
{
	AsnDatumPtrType		dp;
	CUnsfType		w;

	DEBUG0 ("asnObjectId1 ");
	dp = asnRootToPtr (ap);
	if (x == asnEventAlarm) {
		w = (CUnsfType) *(((CBytePtrType) ap->asnArea) +
			(dp->asnDatumValue + dp->asnDatumActualLen - 1));
		DEBUG1 ("%02.02X ", w);
		if ((w & 0x80) != 0) {
			DEBUG0 ("0\n");
			return (asnStatusReject);
		}
		else {
			DEBUG0 ("1\n");
			return (asnPop (ap));
		}
	}
	else {
		DEBUG0 ("2\n");
		return (asnStatusOk);
	}
}


static	AsnStatusType	asnObjectId0 (AsnPtrType ap, AsnEventType x)
{
	AsnDatumPtrType		dp;

	DEBUG0 ("asnObjectId0 ");
	dp = asnRootToPtr (ap);
	dp->asnDatumUserLen = dp->asnDatumActualLen;
	if (x == asnEventAlarm) {
		DEBUG0 ("0\n");
		return (asnPop (ap));
	}
	else {
		ap->asnFn = asnObjectId1;
		DEBUG0 ("1\n");
		return (asnStatusOk);
	}
}

static	AsnStatusType	asnLenVerify (AsnDatumPtrType dp, AsnLengthType tlen)
{
	AslIdType		np;
	AslIdType		next;
	AsnLengthType		rlen;

	np = dp->asnDatumNode;

	DEBUG0 ("asnLenVerify ");
	DEBUG1 ("Max %d ", dp->asnDatumMaxLen);
	DEBUG1 ("Tot %d ", dp->asnDatumTotalLen);
	DEBUG1 ("Len %d ", tlen);
	DEBUG1 ("Min %d ", aslMinLen (np));

	switch ((int) aslKind (np)) {

	case asnTypeSequence:
		if (tlen < aslMinLen (aslSon (np))) {
			DEBUG0 ("0 ");
			return (asnStatusReject);
		}
		break;

	case asnTypeSequenceOf:
		if ((tlen != 0) &&
			(tlen < aslMinLen (aslSon (np)))) {
			DEBUG0 ("1 ");
			return (asnStatusReject);
		}
		break;

	default:
		if (tlen < aslMinLen (np)) {
			DEBUG0 ("5 ");
			return (asnStatusReject);
		}
		break;
	}

	next = aslNext (np);
	rlen = (next == (AslIdType) 0) ? 0 : aslMinLen (next);

	if ((dp->asnDatumMaxLen != asnLengthIndef) &&
		((dp->asnDatumTotalLen + tlen + rlen) >
		dp->asnDatumMaxLen)) {
		DEBUG0 ("2 ");
		return (asnStatusReject);
	}
	else if ((asnDatumMustMatchGet (dp)) && (next == (AslIdType) 0) &&
		(dp->asnDatumMaxLen != asnLengthIndef) &&
		((dp->asnDatumTotalLen + tlen) !=
		dp->asnDatumMaxLen)) {
		DEBUG0 ("3 ");
		return (asnStatusReject);
	}
	else {
		DEBUG0 ("4 ");
		return (asnStatusOk);
	}
}

static	AsnStatusType	asnLen1 (AsnPtrType ap, AsnEventType x)
{
	AsnDatumPtrType		dp;
	AslIdType		np;
	AsnLengthType		tlen;

	DEBUG0 ("asnLen1 ");
	if (x == asnEventAlarm) {
		DEBUG0 ("0\n");
		return (asnStatusReject);
	}

	dp = asnRootToPtr (ap);
	dp->asnDatumTotalLen++;
	np = dp->asnDatumNode;
	ap->asnLenCnt -= 8;
	tlen = (((AsnLengthType) x) << ap->asnLenCnt) |
		dp->asnDatumActualLen;
	DEBUG1 ("tlen %d ", tlen);
	DEBUG1 ("MaxLen %d ", dp->asnDatumMaxLen);
	DEBUG1 ("TotalLen %d ", dp->asnDatumTotalLen);
	DEBUG1 ("aslMinLen %d ", aslMinLen (np));
	if ((dp->asnDatumMaxLen != asnLengthIndef) &&
		((dp->asnDatumTotalLen + tlen) > dp->asnDatumMaxLen)) {
		DEBUG0 ("1\n");
		return (asnStatusReject);
	}

	if (ap->asnLenCnt == 0) {
		if (asnLenVerify (dp, tlen) == asnStatusReject) {
			DEBUG0 ("2\n");
			return (asnStatusReject);
		}
		else {
			if (dp->asnDatumMaxLen != asnLengthIndef) {
				dp->asnDatumMaxLen -= dp->asnDatumTotalLen;
			}
			ap->asnFn = asnEntry (np);
			dp->asnDatumAlarm = ap->asnSoFar + tlen;
			dp->asnDatumMaxLen = tlen;
			dp->asnDatumActualLen = tlen;
			dp->asnDatumCmd = aslKind (np);
			dp->asnDatumValue = ap->asnSoFar;
			ap->asnWomb = aslSon (np);
			DEBUG0 ("3\n");
			return (asnStatusOk);
		}
	}
	else {
		DEBUG0 ("4\n");
		dp->asnDatumActualLen = tlen;
		return (asnStatusOk);
	}
}

static	AsnStatusType	asnLen0 (AsnPtrType ap, AsnEventType x)
{
	AsnDatumPtrType		dp;
	AslIdType		np;
	AsnLengthType		tlen;
	CUnsfType		nlen;

	DEBUG0 ("asnLen0 ");
	if (x == asnEventAlarm) {
		DEBUG0 ("0\n");
		return (asnStatusReject);
	}

	/*
	 *	See ISO DIS 8825; section 6.3.3.2 (c)
	 */

	if (x == (AsnEventType) 0xFF) {
		DEBUG0 ("1\n");
		return (asnStatusReject);
	}

	dp = asnRootToPtr (ap);
	dp->asnDatumTotalLen++;
	np = dp->asnDatumNode;

	if (x < (AsnEventType) 0x80) {
		tlen = (AsnLengthType) x;
		if (asnLenVerify (dp, tlen) == asnStatusReject) {
			DEBUG0 ("2\n");
			return (asnStatusReject);
		}
		else {
			if (dp->asnDatumMaxLen != asnLengthIndef) {
				dp->asnDatumMaxLen -= dp->asnDatumTotalLen;
			}
			asnDatumMustMatchSet (dp, TRUE);
			dp->asnDatumAlarm = ap->asnSoFar + tlen;
			dp->asnDatumCmd = aslKind (np);
			dp->asnDatumValue = ap->asnSoFar;
			dp->asnDatumActualLen = tlen;
			dp->asnDatumMaxLen = tlen;
			ap->asnFn = asnEntry (np);
			ap->asnWomb = aslSon (np);
			DEBUG0 ("4\n");
			return (asnStatusOk);
		}
	}
	else if (x > (AsnEventType) 0x80) {
		nlen = ((CUnsfType) x) & 0x7F;
		if (nlen > sizeof (AsnLengthType)) {
			DEBUG0 ("5\n");
			return (asnStatusReject);
		}
		else if ((dp->asnDatumMaxLen != asnLengthIndef) &&
			((dp->asnDatumTotalLen + aslMinLen (np) +
			nlen) > dp->asnDatumMaxLen)) {
			DEBUG0 ("6\n");
			return (asnStatusReject);
		}
		else {
			asnDatumMustMatchSet (dp, TRUE);
			ap->asnLenCnt = (nlen << 3);
			ap->asnFn = asnLen1;
			DEBUG0 ("7\n");
			return (asnStatusOk);
		}
	}
	else if (asnDatumConstructorGet (dp)) {
		if (dp->asnDatumMaxLen != asnLengthIndef) {
			dp->asnDatumMaxLen -= (dp->asnDatumTotalLen);
		}
		asnDatumIndefLengthSet (dp, TRUE);
		dp->asnDatumCmd = aslKind (np);
		dp->asnDatumValue = ap->asnSoFar;
		ap->asnFn = asnEntry (np);
		ap->asnWomb = aslSon (np);
		DEBUG0 ("8\n");
		return (asnStatusOk);
	}
	else {
		DEBUG0 ("9\n");
		return (asnStatusReject);
	}
}

static	AsnStatusType	asnType1 (AsnPtrType ap, AsnEventType x)
{
	AsnDatumPtrType		dp;
	AslIdType		np;

	DEBUG0 ("asnType1\n");
	if (x == asnEventAlarm) {
		return (asnStatusReject);
	}

	dp = asnRootToPtr (ap);
	dp->asnDatumTotalLen++;
	np = dp->asnDatumNode;
	np = aslChoice (np, (CByteType) x);
	if (np == (AslIdType) 0) {
		return (asnStatusReject);
	}
	
	if ((dp->asnDatumMaxLen != asnLengthIndef) &&
		((dp->asnDatumTotalLen + aslMinLen (np)) >
		dp->asnDatumMaxLen)) {
		return (asnStatusReject);
	}

	dp->asnDatumNode = np;
	dp->asnDatumTag <<= 7;
	dp->asnDatumTag |= (x & 0x7F);
	ap->asnFn = (((CUnsbType) x & 0x80) == 0) ? asnType1 : asnLen0;
	return (asnStatusOk);
}

static	AsnStatusType	asnType0 (AsnPtrType ap, AsnEventType x)
{
	AsnDatumPtrType		dp;
	AslIdType		np;

	DEBUG0 ("asnType0\n");
	if ((x == asnEventAlarm) || (x == (AsnEventType) 0)) {
		return (asnStatusReject);
	}

	dp = asnRootToPtr (ap);
	dp->asnDatumTotalLen++;
	np = dp->asnDatumNode;
	DEBUG2 ("asnType0 dp %X np %X\n", dp, np);
	np = aslChoice (np, (CByteType) x);
	if (np == (AslIdType) 0) {
		return (asnStatusReject);
	}
	
	if ((dp->asnDatumMaxLen != asnLengthIndef) &&
		(aslMinLen (np) > dp->asnDatumMaxLen)) {
		return (asnStatusReject);
	}

	dp->asnDatumNode = np;
	dp->asnDatumClass = (AsnClassType) (x >> 6);
	if ((x & 0x20) != 0) {
		asnDatumConstructorSet (dp, TRUE);
	}
	else {
		asnDatumConstructorSet (dp, FALSE);
	}
	if ((x &= 0x1F) == 0x1F) {
		ap->asnFn = asnType1;
		dp->asnDatumTag = (AsnTagType) 0;
	}
	else {
		dp->asnDatumTag = (AsnTagType) x;
		ap->asnFn = asnLen0;
	}
	return (asnStatusOk);
}

static	AsnStatusType	asnNull (AsnPtrType ap, AsnEventType x)
{
	DEBUG0 ("asnNull\n");
	(asnRootToPtr(ap))->asnDatumUserLen = (AsnLengthType) 0;
	return ((x == asnEventAlarm) ? asnPop (ap) : asnStatusReject);
}

static	AsnStatusType	asnEOC1 (AsnPtrType ap, AsnEventType x)
{
	AsnDatumPtrType		dp;

	DEBUG0 ("asnEOC1\n");
	dp = asnRootToPtr (ap);
	if (x == (AsnEventType) 0) {
		dp->asnDatumTotalLen++;
		return (asnPop (ap));
	}
	else {
		return (asnStatusReject);
	}
}

static	AsnStatusType	asnSeq (AsnPtrType ap, AsnEventType x)
{
	AsnDatumPtrType		dp;
	AsnStatusType		status;

	DEBUG0 ("asnSeq ");
	dp = asnRootToPtr (ap);
	if (ap->asnWomb == (AslIdType) 0) {
		if (asnDatumIndefLengthGet (dp)) {
			if (x != (AsnEventType) 0) {
				DEBUG0 ("0\n");
				return (asnStatusReject);
			}
			else {
				dp->asnDatumTotalLen++;
				ap->asnFn = asnEOC1;
				DEBUG0 ("1\n");
				return (asnStatusOk);
			}
		}
		else if (x == asnEventAlarm) {
			DEBUG0 ("2\n");
			return (asnPop (ap));
		}
		else {
			DEBUG0 ("3\n");
			return (asnStatusReject);
		}
	}
	else {
		DEBUG0 ("4\n");
		status = asnPush (ap, ap->asnWomb);
		if (status == asnStatusOk) {
			status = (*(ap->asnFn)) (ap, x);
		}
		return (status);
	}
}

static	AsnStatusType	asnSeqOf (AsnPtrType ap, AsnEventType x)
{
	AsnDatumPtrType		dp;
	AsnStatusType		status;

	DEBUG0 ("asnSeqOf\n");
	dp = asnRootToPtr (ap);
	if (x == (AsnEventType) 0) {
		if (! asnDatumIndefLengthGet (dp)) {
			return (asnStatusReject);
		}
		else {
			ap->asnFn = asnEOC1;
			dp->asnDatumTotalLen++;
			return (asnStatusOk);
		}
	}
	else if (x == asnEventAlarm) {
		return (asnPop (ap));
	}
	else {
		status = asnPush (ap, aslSon (dp->asnDatumNode));
		if (status == asnStatusOk) {
			status = (*(ap->asnFn)) (ap, x);
		}
		return (status);
	}
}

AsnStatusType		asnDecode (AsnIdType asn, CByteType x)
{
	AsnPtrType		ap;
	AsnDatumPtrType		dp;

	if (asn == (AsnIdType) 0) {
		return (asnStatusBad);
	}

	dp = asnIdToPtr (asn);
	ap = asnPtrToRoot (dp);

	if (ap->asnStatus != asnStatusOk) {
		return (ap->asnStatus);
	}

	if (ap->asnBytesLeft-- == 0) {
		ap->asnStatus = asnStatusBad;
		return (ap->asnStatus);
	}

	((CBytePtrType) ap->asnArea) [ ap->asnSoFar++ ] = x;
	ap->asnStatus = (* (ap->asnFn)) (ap, (AsnEventType) x);
	dp = asnRootToPtr (ap);

	while ((ap->asnStatus == asnStatusOk) &&
		(dp->asnDatumAlarm == ap->asnSoFar)) {
		ap->asnStatus = (* (ap->asnFn)) (ap, asnEventAlarm);
		dp = asnRootToPtr (ap);
	}

	if ((ap->asnStatus == asnStatusOk) &&
		(ap->asnParseLevel == 0)) {
		DEBUG1 ("asnDecode bytesLeft %d\n", ap->asnBytesLeft);
		ap->asnStatus = asnStatusAccept;
	}

	return (ap->asnStatus);
}

CVoidType		asnInit (void)
{
}

static	AsnDatumPtrType	asnAlloc (AsnLengthType n)
{
	AsnPtrType		ap;
	AsnDatumPtrType		dp;
	AsnDatumPtrType		mp;
	AsnIndexType		k;
	AsnIndexType		h;

	h = (n / sizeof (AsnDatumType)) + 1;
	k = ((sizeof (AsnType) / sizeof (AsnDatumType)) + 1) + 1 + h;
	mp = (AsnDatumPtrType) malloc ((unsigned) (sizeof (AsnDatumType) * k));
	if (mp != (AsnDatumPtrType) 0) {
		dp = mp + h;
		ap = (AsnPtrType) (dp + 1);
		ap->asnArea = mp;
		ap->asnSize = k;
		ap->asnRefCnt = 1;
		ap->asnStatus = asnStatusAccept;
		ap->asnDatumFree = h;
		ap->asnBytesLeft = (AsnLengthType) h * sizeof (AsnDatumType);
		ap->asnDatum = h;
		ap->asnSoFar = (AsnLengthType) 0;
		ap->asnLenCnt = (CUnsfType) 0;
		ap->asnFn = (AsnParseFnType *) 0;
		ap->asnWomb = (AslIdType) 0;
		ap->asnLanguage = (AslIdType) 0;
		ap->asnNewId = (AsnIndexType) 1;
		ap->asnParseLevel = 1;
		dp->asnDatumParent = (AsnIndexType) 0;
		dp->asnDatumMyself = ap->asnNewId++;
		dp->asnDatumNode = (AslIdType) 0;
		dp->asnDatumSons = (AsnIndexType) 0;
		dp->asnDatumTotalLen = (AsnLengthType) 0;
		dp->asnDatumActualLen = (AsnLengthType) 0;
		dp->asnDatumUserLen = (AsnLengthType) 0;
		dp->asnDatumAlarm = asnLengthIndef;
		dp->asnDatumFlags = (CUnssType) 0;
		dp->asnDatumMaxLen = asnLengthIndef;
		dp->asnDatumCmd = asnTypeNone;
		dp->asnDatumTag = (AsnTagType) 0;
		dp->asnDatumValue = (AsnLengthType) 0;
		dp->asnDatumClass = asnClassUniversal;
	}
	return (dp);
}

static	AsnLengthType	asnEncodeTag (AsnDatumPtrType dp, CBytePtrType cp, AsnLengthType n)
{
	AsnLengthType		k;
	AsnLengthType		l;
	AsnTagType		w;
	CByteType		head;

	l = n;
	if (n != 0) {
		w = dp->asnDatumTag;
		head = (CByteType) (((asnDatumConstructorGet (dp)) ?
			0x20 : 0) |
			(((CByteType) dp->asnDatumClass) << 6));
		l = 1;
		if (w < (AsnTagType) 0x1F) {
			*cp = (CByteType) (w | head);
		}
		else {
			*cp = (head | 0x1F);
			for (k = 0; w != 0; w >>= 7) {
				k++;
			}
			l += k;
			if (l > n) {
				l = 0;
			}
			else {
				w = dp->asnDatumTag;
				cp += k;
				*cp-- = ((CByteType) w & 0x7F);
				for (; k != 0; k--) {
					w >>= 7;
					*cp-- = ((CByteType) w & 0x7F) | 0x80;
				}
			}
		}
	}
	return (l);
}

static	AsnLengthType	asnEncodeLength (AsnDatumPtrType dp, CBytePtrType cp, AsnLengthType n)
{
	AsnLengthType		l;
	AsnLengthType		w;
	AsnLengthType		k;

	w = dp->asnDatumActualLen;
	if (w > 127) {
		for (k = 1; ((w >>= 8) != 0); k++);
		l = k + 1;
		if (l > n) {
			n = 0;
		}
		else {
			n = l;
			*cp = (CByteType) k | 0x80;
			cp += k;
			for (w = dp->asnDatumActualLen; k != 0; k--) {
				*cp-- = (CByteType) w & 0xFF;
				w >>= 8;
			}
		}
	}
	else if (n != 0) {
		*cp = (CByteType) w;
		n = 1;
	}
	return (n);
}

AsnLengthType		asnEncode (AsnIdType asn, CBytePtrType cp, AsnLengthType n)
{
	AsnPtrType		pp;
	AsnDatumPtrType		dp;
	AsnLengthType		k;
	AsnLengthType		r;

	if (asn == (AsnIdType) 0) {
		return ((AsnLengthType) -1);
	}

	dp = asnIdToPtr (asn);
	pp = asnPtrToRoot (dp);
	if (pp->asnStatus != asnStatusAccept) {
		return ((AsnLengthType) -1);
	}

	if ((k = asnEncodeTag (dp, cp, n)) == 0) {
		return ((AsnLengthType) -1);
	}

	r = k;
	n -= k;
	cp += k;
	if ((k = asnEncodeLength (dp, cp, n)) == 0) {
		return ((AsnLengthType) -1);
	}

	r += k;
	n -= k;
	cp += k;
	k = dp->asnDatumActualLen;
	if (k > n) {
		return ((AsnLengthType) -1);
	}

	(void) bcopy (((char *) (pp->asnArea)) +
		dp->asnDatumValue, (char *) cp, (int) k);
	r += k;
	return (r);
}

#ifndef		INLINE

AsnIdType		asnFree (AsnIdType asn)
{
	return (asnFreeDef (asn));
}

AsnIdType		asnComponent (AsnIdType asn, AsnIndexType i)
{
	return (asnComponentDef (asn, i));
}

AsnTagType		asnTag (AsnIdType asn)
{
	return (asnTagDef (asn));
}

AsnTypeType		asnType (AsnIdType asn)
{
	return (asnTypeDef (asn));
}

AsnLengthType		asnLength (AsnIdType asn)
{
	return (asnLengthDef (asn));
}

CBoolType		asnConstructor (AsnIdType asn)
{
	return (asnConstructorDef (asn));
}

CBoolType		asnNegative (CBytePtrType cp, AsnLengthType n)
{
	return (asnNegativeDef (cp, n));
}

CBoolType		asnNonZero (CBytePtrType cp, AsnLengthType n)
{
	return (asnNonZeroDef (cp, n));
}

AsnClassType		asnClass (AsnIdType asn)
{
	return (asnClassDef (asn));
}

AsnIndexType		asnSons (AsnIdType asn)
{
	return (asnSonsDef (asn));
}

CBytePtrType		asnValue (AsnIdType asn)
{
	return (asnValueDef (asn));
}

#endif		/*	INLINE		*/

AsnLengthType		asnContents (AsnIdType asn, CBytePtrType cp, AsnLengthType n)
{
	AsnDatumPtrType		dp;
	CBytePtrType		bp;
	AsnLengthType		sofar;
	AsnLengthType		len;
	CUnsfType		i;

	if (asn == (AsnIdType) 0) {
		return ((AsnLengthType) -1);
	}
	dp = asnIdToPtr (asn);
	sofar = (AsnLengthType) 0;
	bp = (CBytePtrType) (asnPtrToRoot (dp)->asnArea);
	for (i = dp->asnDatumSons + 1; (i != 0) && (sofar <= n); i--) {
		if (! asnDatumConstructorGet (dp)) {
			len = dp->asnDatumActualLen;
			sofar += len;
			if (sofar <= n) {
				(void) bcopy ((char *)
					(bp + dp->asnDatumValue),
					(char *) cp, (int) len);
				cp += len;
			}
		}
		dp--;
	}

	if (sofar > n) {
		return ((AsnLengthType) -1);
	}
	else {
		return (sofar);
	}
}

AsnNumberType		asnNumber (CBytePtrType cp, AsnLengthType n)
{
	AsnNumberType		r;

	if (n > 0) {
		n--;
		r = (AsnNumberType) *((CIntbPtrType) cp);
		cp++;
	}
	while (n-- > 0) {
		r <<= 8;
		r |= (AsnNumberType) *cp++;
	}
	return (r);
}

static	AsnIdType	asnPrim (AsnClassType class, AsnTagType tag, AsnTypeType type, CBytePtrType value, AsnLengthType n)
{
	AsnDatumPtrType		dp;

	dp = asnAlloc (n);
	if (dp != (AsnDatumPtrType) 0) {
		dp->asnDatumActualLen = n;
		dp->asnDatumUserLen = dp->asnDatumActualLen;
		dp->asnDatumClass = class;
		dp->asnDatumTag = tag;
		dp->asnDatumCmd = type;
		dp->asnDatumValue = (AsnLengthType) 0;
		bcopy ((char *) value, (char *) (asnPtrToRoot (dp))->asnArea,
			(int) n);
	}
	return (asnPtrToId (dp));
}

AsnIdType		asnUnsl (AsnClassType class, AsnTagType tag, CUnslType value)
{
	CBytePtrType		bp;
	CByteType		buf [ (sizeof (value) + 1) ];
	AsnLengthType		n;

	bp = buf + sizeof (value) + 1;
	n = (AsnLengthType) 0;
	
	do {
		bp--;
		*bp = (CByteType) (value & 0xFF);
		value >>= 8;
		n++;
	} while (value != (CUnslType) 0);

	if ((*bp & (CByteType) 0x80) != (CByteType) 0) {
		n++;
		bp--;
		*bp = (CByteType) 0;
	}
	return (asnPrim (class, tag, asnTypeInteger, bp, n));
}

AsnIdType		asnIntl (AsnClassType class, AsnTagType tag, CIntlType value)
{
	CBytePtrType		bp;
	CByteType		buf [ (sizeof (value)) ];
	AsnLengthType		n;

	if (value >= (CIntlType) 0) {
		return (asnUnsl (class, tag, (CUnslType) value));
	}

	bp = buf + sizeof (value);
	n = (AsnLengthType) 0;
	
	do {
		bp--;
		*bp = (CByteType) (value & 0xFF);
		value >>= 8;
		n++;
	} while (value != (CIntlType) -1);

	if ((*bp & (CByteType) 0x80) == (CByteType) 0) {
		n++;
		bp--;
		*bp = (CByteType) -1;
	}
	return (asnPrim (class, tag, asnTypeInteger, bp, n));
}

AsnIdType		asnOctetString (AsnClassType class, AsnTagType tag, CBytePtrType value, AsnLengthType n)
{
	return (asnPrim (class, tag, asnTypeOctetString, value, n));
}

AsnIdType		asnObjectId (AsnClassType class, AsnTagType tag, CBytePtrType value, AsnLengthType n)
{
	if (((CUnsfType) *(value + (int) (n - 1))) & 0x80) {
		return ((AsnIdType) 0);
	}
	else {
		return (asnPrim (class, tag, asnTypeObjectId, value, n));
	}
}

AsnIdType		asnSequence (AsnClassType class, AsnTagType tag, AsnTypeType type)
{
	AsnDatumPtrType		dp;

	dp = asnAlloc ((AsnLengthType) asnAreaSize);
	if (dp != (AsnDatumPtrType) 0) {
		dp->asnDatumTotalLen = (AsnLengthType) 0;
		dp->asnDatumActualLen = (AsnLengthType) 0;
		dp->asnDatumCmd = type;
		dp->asnDatumClass = class;
		dp->asnDatumTag = tag;
		asnDatumConstructorSet (dp, TRUE);
		dp->asnDatumValue = (AsnLengthType) 0;
	}
	return (asnPtrToId (dp));
}

AsnStatusType		asnAppend (AsnIdType head, AsnIdType item)
{
	AsnDatumPtrType		dp;
	AsnDatumPtrType		pp;
	AsnPtrType		ip;
	AsnPtrType		hp;
	AsnLengthType		free;
	AsnLengthType		offset;
	AsnLengthType		adjust;
	AsnLengthType		bytespace;
	AsnLengthType		datumspace;
	AsnIndexType		sons;
	AsnIndexType		i;
	AsnIndexType		pd;
	CBytePtrType		cp;

	DEBUG0 ("asnAppend:\nhead:\n");
	DEBUGASN (head);
	DEBUG0 ("item:\n");
	DEBUGASN (item);
	if ((head == (AsnIdType) 0) || (item == (AsnIdType) 0)) {
		return (asnStatusBad);
	}

	pp = asnIdToPtr (head);
	dp = asnIdToPtr (item);
	hp = asnPtrToRoot (pp);
	ip = asnPtrToRoot (dp);

	if ((hp->asnStatus != asnStatusAccept) ||
		(ip->asnStatus != asnStatusAccept)) {
		return (asnStatusBad);
	}

	if (! asnDatumConstructorGet (pp)) {
		return (asnStatusBad);
	}

	if (pp->asnDatumParent != (AsnIndexType) 0) {
		return (asnStatusBad);
	}

	free = hp->asnBytesLeft;
	sons = dp->asnDatumSons + 1;
	datumspace = sizeof (AsnDatumType) * sons;
	if (free < datumspace) {
		return (asnStatusBad);
	}
	free -= datumspace;
	offset = 0;
	cp = ((CBytePtrType) hp->asnArea) + pp->asnDatumTotalLen;
	bytespace = asnEncodeTag (dp, cp, free);
	if (bytespace == 0) {
		return (asnStatusBad);
	}

	free -= bytespace;
	offset += bytespace;
	cp += bytespace;
	bytespace = asnEncodeLength (dp, cp, free);
	if (bytespace == 0) {
		return (asnStatusBad);
	}

	free -= bytespace;
	if (free < dp->asnDatumActualLen) {
		return (asnStatusBad);
	}
	free -= dp->asnDatumActualLen;
	cp += bytespace;
	offset += bytespace;
	(void) bcopy ((char *) (((CBytePtrType) ip->asnArea) +
		dp->asnDatumValue), (char *) cp, (int) dp->asnDatumActualLen);
	hp->asnBytesLeft = free;
	pp->asnDatumSons += sons;
	pp->asnDatumTotalLen += offset;
	adjust = pp->asnDatumTotalLen - dp->asnDatumValue;
	pp->asnDatumTotalLen += dp->asnDatumActualLen;
	pp->asnDatumActualLen += (dp->asnDatumActualLen + offset);
	pp->asnDatumUserLen += dp->asnDatumUserLen;
	pd = hp->asnDatum;
	for (i = sons; i != 0; i--) {
		pp = hp->asnArea + (--hp->asnDatumFree);
		*pp = *dp--;
		pp->asnDatumValue += adjust;
		pp->asnDatumMyself = hp->asnNewId++;
		pp->asnDatumParent = pd;
	}

	DEBUG0 ("result:\n");
	DEBUGASN (head);
	return (asnStatusOk);
}

AsnIdType		asnNew (AsnLanguageType language)
{
	AsnPtrType		ap;
	AsnDatumPtrType		dp;
	AslIdType		np;

	np = aslLanguage (language);
	if (np == (AslIdType) 0) {
		return ((AsnIdType) 0);
	}

	DEBUG0 ("asnNew");
	dp = asnAlloc ((AsnLengthType) asnAreaSize);
	if (dp != (AsnDatumPtrType) 0) {
		ap = asnPtrToRoot (dp);
		ap->asnStatus = asnStatusOk;
		ap->asnFn = asnEntry (np);
		ap->asnLanguage = np;
		ap->asnParseLevel = 1;
		DEBUG1 (" dp %X", dp);
		dp->asnDatumNode = (AslIdType) np;
	}
	DEBUG0 ("\n");
	return (asnPtrToId (dp));
}

