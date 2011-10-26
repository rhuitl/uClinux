#include	"stdio.h"
#include	"ctypes.h"
#include	"debug.h"
#include	"asn.h"
#include	"asx.h"

#define			asxBufSize		(512)

CVoidType		asxInit (void)
{
}

static	CUnsfType	asxTab (CUnsfType level)
{
	while (level-- != 0) {
		printf ("\t");
	}
	return (level);
}

CBytePtrType		asxTypeToLabel (AsnTypeType type)
{
	char		*result;

	switch (type) {
	
	case asnTypeInteger:
		result = "INTEGER";
		break;

	case asnTypeOctetString:
		result = "OCTETSTRING";
		break;

	case asnTypeObjectId:
		result = "OBJECTIDENTIFIER";
		break;

	case asnTypeNull:
		result = "NULL";
		break;

	case asnTypeSequence:
		result = "SEQUENCE";
		break;

	case asnTypeSequenceOf:
		result = "SEQUENCE OF";
		break;

	default:
		result = "??";
		break;
	}

	return ((CBytePtrType) result);
}

AsxStatusType		asxPrint (AsnIdType asn, CUnsfType level)
{
	if (asn == (AsnIdType) 0) {
		return (errOk);
	}
	(void) asxTab (level);
	printf ("[ ");
	switch (asnClass (asn)) {
	
	case asnClassUniversal:
		printf ("U");
		break;

	case asnClassContext:
		printf ("C");
		break;

	case asnClassApplication:
		printf ("A");
		break;

	case asnClassPrivate:
		printf ("P");
		break;

	default:
		printf ("?");
		break;
	}
	printf (" %ld ] %s {\n", asnTag (asn),
		asxTypeToLabel (asnType (asn)));
	switch (asnType (asn)) {

	case asnTypeInteger:
	case asnTypeOctetString:
	case asnTypeObjectId:
		{
			CByteType		buf [ asxBufSize ];
			CBytePtrType		cp;
			AsnLengthType		n;

			cp = buf;
			(void) asxTab (level + 1);
			for (n = asnContents (asn, buf, asxBufSize); n > 0;
				n--) {
				printf (" %02X", *cp++);
			}
			printf ("\n");
		}
		break;

	case asnTypeSequence:
	case asnTypeSequenceOf:
		{
			AsnIndexType		i;
			AsnIdType		item;

			item = (AsnIdType) 0;
			for (i =  1;  i <= asnSons (asn);
				item = asnFree (item)) {
				item = asnComponent (asn, i);
				(void) asxPrint (item, level + 1);
				i += (asnSons (item) + 1);
			}
		}
		break;

	default:
		break;
	}

	(void) asxTab (level);
	printf ("}\n");
	return (errOk);
}

