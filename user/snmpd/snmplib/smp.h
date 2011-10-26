#ifndef		_SMP_H_
#define		_SMP_H_

#include	"ctypes.h"
#include	"error.h"
#include	"aps.h"

typedef		CUnswType		SmpIdType;

typedef		CUnswType		SmpSocketType;

typedef		ErrStatusType		SmpStatusType;

typedef		enum			SmpErrorTag {

		smpErrorNone,
		smpErrorTooBig,
		smpErrorNoSuch,
		smpErrorBadValue,
		smpErrorReadOnly,
		smpErrorGeneric

		}			SmpErrorType;

typedef		enum			SmpCommandTag {

		smpCommandGet,
		smpCommandNext,
		smpCommandRsp,
		smpCommandSet,
		smpCommandTrap

		}			SmpCommandType;

typedef		enum			SmpKindTag {

		smpKindNone,
		smpKindInteger,
		smpKindOctetString,
		smpKindIPAddr,
		smpKindOpaque,
		smpKindCounter,
		smpKindGuage,
		smpKindTimeTicks,
		smpKindObjectId,
		smpKindNull

		}			SmpKindType;


typedef		enum			SmpTrapTag {

		smpTrapColdStart,
		smpTrapWarmStart,
		smpTrapLinkDown,
		smpTrapLinkUp,
		smpTrapAuthenticationFailure,
		smpTrapEgpNeighborLoss,
		smpTrapEnterpriseSpecific

		}			SmpTrapType;

typedef		CIntlType		SmpSequenceType;

typedef		CUnssType		SmpIndexType;

typedef		CUnsfType		SmpLengthType;

typedef		CBytePtrType		SmpNameType;

typedef		CBytePtrType		SmpValueType;

typedef		CUnslType		SmpNumberType;

typedef		struct			SmpBindTag {

		SmpLengthType		smpBindNameLen;
		SmpNameType		smpBindName;
		SmpKindType		smpBindKind;
		SmpLengthType		smpBindValueLen;
		SmpValueType		smpBindValue;
		SmpNumberType		smpBindNumber;

		}			SmpBindType;

typedef		SmpBindType		*SmpBindPtrType;

typedef		struct			SmpRequestTag {

		SmpCommandType		smpRequestCmd;
		ApsIdType		smpRequestCommunity;
		SmpSequenceType		smpRequestId;
		SmpErrorType		smpRequestError;
		SmpIndexType		smpRequestIndex;
		SmpLengthType		smpRequestEnterpriseLen;
		SmpNameType		smpRequestEnterprise;
		SmpLengthType		smpRequestAgentLen;
		SmpValueType		smpRequestAgent;
		SmpTrapType		smpRequestGenericTrap;
		SmpNumberType		smpRequestSpecificTrap;
		SmpNumberType		smpRequestTimeStamp;
		SmpIndexType		smpRequestCount;
		SmpBindPtrType		smpRequestBinds;

		}			SmpRequestType;

typedef		SmpRequestType		*SmpRequestPtrType;

typedef		SmpStatusType		(*SmpHandlerType) (SmpIdType smp, SmpRequestPtrType req);

typedef		SmpStatusType		(*SmpSendFnType) (SmpSocketType udp, CBytePtrType bp, CIntfType n);

SmpIdType		smpNew (SmpSocketType peer, SmpSendFnType sendFn, SmpHandlerType upcall);
SmpIdType		smpFree (SmpIdType smp);

CVoidType		smpInit (void);
SmpStatusType		smpInput (SmpIdType smp, CByteType x);
SmpStatusType		smpRequest (SmpIdType smp, SmpRequestPtrType req);

#endif		/*	_SMP_H_	*/
