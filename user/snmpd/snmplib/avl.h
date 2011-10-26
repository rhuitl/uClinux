#ifndef		_AVL_H_
#define		_AVL_H_

#include	"ctypes.h"
#include	"error.h"

typedef		ErrStatusType		AvlStatusType;

typedef		CUnswType		AvlIdType;

typedef		enum			AvlBalanceTag {

		avlDirBalanced,
		avlDirLeft,
		avlDirRight

		}			AvlBalanceType;

typedef		CUnswType		AvlInfoType;

typedef		CByteType		AvlNameType;

typedef		AvlNameType		*AvlNamePtrType;

typedef		CUnsfType		AvlLengthType;

typedef		AvlBalanceType		(*AvlCmpFnType) (AvlInfoType p, AvlNamePtrType name, AvlLengthType namelen);

typedef		AvlStatusType		(*AvlPrintFnType) (AvlInfoType p);

AvlIdType	avlNew (AvlCmpFnType cmpFn, AvlPrintFnType printFn);
AvlIdType	avlFree (AvlIdType p);
AvlStatusType	avlInsert (AvlIdType head, AvlNamePtrType name, AvlLengthType namelen, AvlInfoType info);
AvlStatusType	avlRemove (AvlIdType head, AvlNamePtrType name, AvlLengthType namelen);
AvlInfoType	avlFind (AvlIdType head, AvlNamePtrType name, AvlLengthType namelen);
AvlInfoType	avlCessor (AvlIdType head, AvlNamePtrType name, AvlLengthType namelen);
CVoidType	avlInit (void);

#endif		/*	_AVL_H_	*/
