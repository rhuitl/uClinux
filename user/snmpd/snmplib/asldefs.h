#ifndef		_ASLDEFS_H_
#define		_ASLDEFS_H_


#include	"ctypes.h"
#include	"asl.h"
#include	"asn.h"

typedef         struct                  AslNodeTag {

                AsnTypeType          	aslNodeKind;
                CUnswType               aslNodeStuff;
                AsnLengthType		aslNodeMinLen;
		AslIdType		aslNodeNext;

                }                       AslNodeType;

typedef         AslNodeType             *AslNodePtrType;

/*
extern		AslNodeType	aslNodeTable [];

#define		aslIdToPtr(n)	\
			(& (aslNodeTbl [ ((AslIdType)(n)) ]))
*/

#define		aslIdToPtr(n)	\
			((AslNodePtrType) ((AslIdType)(n)))

#define		aslPtrToId(n)	\
			((AslIdType) ((AslNodePtrType) (n)))

#define		aslKindDef(n)	((aslIdToPtr (n))->aslNodeKind)
#define		aslMinLenDef(n)	\
		((AsnLengthType) (aslIdToPtr (n))->aslNodeMinLen)
#define		aslNextDef(n)	\
		((AslIdType) ((aslIdToPtr (n))->aslNodeNext))
#define		aslSonDef(n)	\
		((AslIdType) ((aslIdToPtr (n))->aslNodeStuff))

#endif		/*	_ASLDEFS_H_	*/
