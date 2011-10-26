
#include	"ctypes.h"
#include	"debug.h"
#include	"asn.h"
#include	"asl.h"
#include	"asldefs.h"

#define		aslNodeNil	((AslIdType) 0)

#define		aslNode(n)	(aslPtrToId (& aslNodes [ (n) ]))

#define		aslNodeDef(t,s,n,v)	\
		{ \
		(t), \
		(CUnswType) (s), \
		(AsnLengthType) (n), \
		(v) \
		}
		
static	AslNodeType	aslNodes []	=	{

/*	0	*/
		aslNodeDef (asnTypeNone, "\60", 20, aslNode (1)),
/*	1	*/
		aslNodeDef (asnTypeSequence, aslNode (2), 20, aslNodeNil),
/*	2	*/
		aslNodeDef (asnTypeNone, "\2", 18, aslNode (3)),
/*	3	*/
		aslNodeDef (asnTypeInteger, aslNodeNil, 1, aslNode (4)),
/*	4	*/
		aslNodeDef (asnTypeNone, "\4", 15, aslNode (5)),
/*	5	*/
		aslNodeDef (asnTypeOctetString, aslNodeNil, 0, aslNode (6)),
/*	6	*/
		aslNodeDef (asnTypeNone, "\240\241\242\243\244", 13,
			aslNode (7)),
/*	7	*/
		aslNodeDef (asnTypeSequence, aslNode (12), 12, aslNodeNil),
/*	8	*/
		aslNodeDef (asnTypeSequence, aslNode (12), 12, aslNodeNil),
/*	9	*/
		aslNodeDef (asnTypeSequence, aslNode (12), 12, aslNodeNil),
/*	10	*/
		aslNodeDef (asnTypeSequence, aslNode (12), 12, aslNodeNil),
/*	11	*/
		aslNodeDef (asnTypeSequence, aslNode (35), 16, aslNodeNil),
/*	12	*/
		aslNodeDef (asnTypeNone, "\2", 11, aslNode (13)),
/*	13	*/
		aslNodeDef (asnTypeInteger, aslNodeNil, 1, aslNode (14)),
/*	14	*/
		aslNodeDef (asnTypeNone, "\2", 8, aslNode (15)),
/*	15	*/
		aslNodeDef (asnTypeInteger, aslNodeNil, 1, aslNode (16)),
/*	16	*/
		aslNodeDef (asnTypeNone, "\2", 5, aslNode (17)),
/*	17	*/
		aslNodeDef (asnTypeInteger, aslNodeNil, 1, aslNode (18)),
/*	18	*/
		aslNodeDef (asnTypeNone, "\60", 2, aslNode (19)),
/*	19	*/
		aslNodeDef (asnTypeSequenceOf, aslNode (20), 0, aslNodeNil),
/*	20	*/
		aslNodeDef (asnTypeNone, "\60", 0, aslNode (21)),
/*	21	*/
		aslNodeDef (asnTypeSequence, aslNode (22), 4, aslNode (20)),
/*	22	*/
		aslNodeDef (asnTypeNone, "\6", 4, aslNode (23)),
/*	23	*/
		aslNodeDef (asnTypeObjectId, aslNodeNil, 0, aslNode (24)),
/*	24	*/
		aslNodeDef (asnTypeNone, "\2\4\5\6\100\101\102\103\104\44",
			2, aslNode (25)),
/*	25	*/
		aslNodeDef (asnTypeInteger, aslNodeNil, 1, aslNodeNil),
/*	26	*/
		aslNodeDef (asnTypeOctetString, aslNodeNil, 0, aslNodeNil),
/*	27	*/
		aslNodeDef (asnTypeNull, aslNodeNil, 0, aslNodeNil),
/*	28	*/
		aslNodeDef (asnTypeObjectId, aslNodeNil, 0, aslNodeNil),
/*	29	*/
		aslNodeDef (asnTypeOctetString, aslNodeNil, 4, aslNodeNil),
/*	30	*/
		aslNodeDef (asnTypeInteger, aslNodeNil, 1, aslNodeNil),
/*	31	*/
		aslNodeDef (asnTypeInteger, aslNodeNil, 1, aslNodeNil),
/*	32	*/
		aslNodeDef (asnTypeInteger, aslNodeNil, 0, aslNodeNil),
/*	33	*/
		aslNodeDef (asnTypeOctetString, aslNodeNil, 0, aslNodeNil),
/*	34	*/
		aslNodeDef (asnTypeSequenceOf, aslNode (45), 0, aslNodeNil),
/*	35	*/
		aslNodeDef (asnTypeNone, "\6", 14, aslNode (36)),
/*	36	*/
		aslNodeDef (asnTypeObjectId, aslNodeNil, 0, aslNode (37)),
/*	37	*/
		aslNodeDef (asnTypeNone, "\100", 12, aslNode (38)),
/*	38	*/
		aslNodeDef (asnTypeOctetString, aslNodeNil, 4, aslNode (39)),
/*	39	*/
		aslNodeDef (asnTypeNone, "\2", 10, aslNode (40)),
/*	40	*/
		aslNodeDef (asnTypeInteger, aslNodeNil, 1, aslNode (41)),
/*	41	*/
		aslNodeDef (asnTypeNone, "\2", 7, aslNode (42)),
/*	42	*/
		aslNodeDef (asnTypeInteger, aslNodeNil, 1, aslNode (43)),
/*	43	*/
		aslNodeDef (asnTypeNone, "\103", 4, aslNode (44)),
/*	44	*/
		aslNodeDef (asnTypeInteger, aslNodeNil, 1, aslNode (18)),
/*	45	*/
		aslNodeDef (asnTypeNone, "\4\44", 0, aslNode (46)),
/*	46	*/
		aslNodeDef (asnTypeOctetString, aslNodeNil, 0, aslNodeNil),
/*	47	*/
		aslNodeDef (asnTypeSequenceOf, aslNode (45), 0, aslNodeNil),

		};

CVoidType		aslInit (void)
{
}

AslIdType  		aslChoice (AslIdType n, CByteType x)
{
        CIntfType               i;
        CBytePtrType            cp;

	DEBUG0 ("aslChoice ");
	cp = (CBytePtrType) ((aslIdToPtr(n))->aslNodeStuff);
	if (x == 0) {
		DEBUG0 ("0\n");
        	return ((*cp != x) ? (AslIdType) 0 :
			aslPtrToId ((aslIdToPtr
			((aslIdToPtr (n))->aslNodeNext))));
	}
	else {
		DEBUG0 ("1\n");
		i = 0;
		while ((*cp) && (*cp != x)) {
			cp++;
			i++;
		}
        	return ((*cp) ? aslPtrToId ((aslIdToPtr
			((aslIdToPtr (n))->aslNodeNext)) + i) : (AslIdType) 0);
	}
}

AslIdType  		aslAny (AslIdType n, CByteType x)
{
	AslNodePtrType		np;


	np = aslIdToPtr (n);
        if (x < 9) {
                np += (int) x;
        }
        else if (x == 0x24) {
                np += 10;
        }
        else if (x == 0x25) {
                np += 11;
        }
        else if (x > 0x20) {
                np += 12;
        }
        else {
                np += 4;
        }

	return (aslPtrToId (np));
}

AslIdType	aslLanguage (AsnLanguageType language)
{
	language = language;
	return (aslNode (0));
}

#ifndef		INLINE

AslIdType	aslSon (AslIdType n)
{
	return (aslSonDef (n));
}


AslIdType	aslNext (AslIdType n)
{
	return (aslNextDef (n));
}


AsnLengthType	aslMinLen (AslIdType n)
{
	return (aslMinLenDef (n));
}


AsnTypeType	aslKind (AslIdType n)
{
	return (aslKindDef (n));
}

#endif		/*	INLINE	*/

