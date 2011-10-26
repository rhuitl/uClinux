#ifndef		_MIS_H_
#define		_MIS_H_

#include	"ctypes.h"
#include	"error.h"
#include	"mix.h"
#include	"aps.h"

typedef		ErrStatusType		MisStatusType;

typedef		CBoolType		MisAccessType;

CVoidType	misInit (void);
MisStatusType	misExport (MixNamePtrType name, MixLengthType namelen, MixOpsPtrType ops, MixCookieType cookie);
MisAccessType	misCommunityToAccess (ApsIdType s);
MixIdType	misCommunityToMib (ApsIdType s);
ApsIdType	misCommunityByName (CBytePtrType name);

#endif		/*	_MIS_H_	*/
