#ifndef		_MIV_H_
#define		_MIV_H_

#include	"ctypes.h"
#include	"mix.h"
#include	"mis.h"

typedef		struct			MivStrTag {

		CUnsfType		mivStrMaxLen;
		CUnsfType		mivStrLen;
		CBytePtrType		mivStrData;

		}			MivStrType;

typedef		MivStrType		*MivStrPtrType;

MisStatusType	mivIntlRW (MixNamePtrType name, MixLengthType namelen, CIntlPtrType address);
MisStatusType	mivIntlRO (MixNamePtrType name, MixLengthType namelen, CIntlPtrType address);

MisStatusType	mivUnslRW (MixNamePtrType name, MixLengthType namelen, CUnslPtrType address);
MisStatusType	mivUnslRO (MixNamePtrType name, MixLengthType namelen, CUnslPtrType address);

MisStatusType	mivCounterRW (MixNamePtrType name, MixLengthType namelen, CUnslPtrType address);
MisStatusType	mivCounterRO (MixNamePtrType name, MixLengthType namelen, CUnslPtrType address);

MisStatusType	mivGuageRW (MixNamePtrType name, MixLengthType namelen, CUnslPtrType address);
MisStatusType	mivGuageRO (MixNamePtrType name, MixLengthType namelen, CUnslPtrType address);

MisStatusType	mivTicksRW (MixNamePtrType name, MixLengthType namelen, CUnslPtrType address);
MisStatusType	mivTicksRO (MixNamePtrType name, MixLengthType namelen, CUnslPtrType address);

MisStatusType	mivStringRW (MixNamePtrType name, MixLengthType namelen, MivStrPtrType address);
MisStatusType	mivStringRO (MixNamePtrType name, MixLengthType namelen, MivStrPtrType address);

MisStatusType	mivIPAddrRW (MixNamePtrType name, MixLengthType namelen, CBytePtrType address);
MisStatusType	mivIPAddrRO (MixNamePtrType name, MixLengthType namelen, CBytePtrType address);

MisStatusType	mivObjectIdRW (MixNamePtrType name, MixLengthType namelen, MivStrPtrType address);
MisStatusType	mivObjectIdRO (MixNamePtrType name, MixLengthType namelen, MivStrPtrType address);

#endif		/*	_MIV_H_	*/
