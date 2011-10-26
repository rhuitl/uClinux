

#include	<stdio.h>
#include	<netdb.h>
#include	<unistd.h>

#include	"ctypes.h"
#include	"error.h"
#include	"local.h"
#include	"icmp_vars.h"
#include	"mix.h"
#include	"mis.h"
#include	"asn.h"

#define ICMP_MAXTYPE 25

static	CUnslType		icmpAddr;
static	char			*icmpXlate = "\3\13\14\4\5\10\0\15\16\21\22";

struct ip_mib
{
 	unsigned long	IpForwarding;
 	unsigned long	IpDefaultTTL;
 	unsigned long	IpInReceives;
 	unsigned long	IpInHdrErrors;
 	unsigned long	IpInAddrErrors;
 	unsigned long	IpForwDatagrams;
 	unsigned long	IpInUnknownProtos;
 	unsigned long	IpInDiscards;
 	unsigned long	IpInDelivers;
 	unsigned long	IpOutRequests;
 	unsigned long	IpOutDiscards;
 	unsigned long	IpOutNoRoutes;
 	unsigned long	IpReasmTimeout;
 	unsigned long	IpReasmReqds;
 	unsigned long	IpReasmOKs;
 	unsigned long	IpReasmFails;
 	unsigned long	IpFragOKs;
 	unsigned long	IpFragFails;
 	unsigned long	IpFragCreates;
};
 
 
struct icmp_mib
{
 	unsigned long	IcmpInMsgs;
 	unsigned long	IcmpInErrors;
  	unsigned long	IcmpInDestUnreachs;
 	unsigned long	IcmpInTimeExcds;
 	unsigned long	IcmpInParmProbs;
 	unsigned long	IcmpInSrcQuenchs;
 	unsigned long	IcmpInRedirects;
 	unsigned long	IcmpInEchos;
 	unsigned long	IcmpInEchoReps;
 	unsigned long	IcmpInTimestamps;
 	unsigned long	IcmpInTimestampReps;
 	unsigned long	IcmpInAddrMasks;
 	unsigned long	IcmpInAddrMaskReps;
 	unsigned long	IcmpOutMsgs;
 	unsigned long	IcmpOutErrors;
 	unsigned long	IcmpOutDestUnreachs;
 	unsigned long	IcmpOutTimeExcds;
 	unsigned long	IcmpOutParmProbs;
 	unsigned long	IcmpOutSrcQuenchs;
 	unsigned long	IcmpOutRedirects;
 	unsigned long	IcmpOutEchos;
 	unsigned long	IcmpOutEchoReps;
 	unsigned long	IcmpOutTimestamps;
 	unsigned long	IcmpOutTimestampReps;
 	unsigned long	IcmpOutAddrMasks;
 	unsigned long	IcmpOutAddrMaskReps;
};
 
struct tcp_mib
{
 	unsigned long	TcpRtoAlgorithm;
 	unsigned long	TcpRtoMin;
 	unsigned long	TcpRtoMax;
 	unsigned long	TcpMaxConn;
 	unsigned long	TcpActiveOpens;
 	unsigned long	TcpPassiveOpens;
 	unsigned long	TcpAttemptFails;
 	unsigned long	TcpEstabResets;
 	unsigned long	TcpCurrEstab;
 	unsigned long	TcpInSegs;
 	unsigned long	TcpOutSegs;
 	unsigned long	TcpRetransSegs;
};
 
struct udp_mib
{
 	unsigned long	UdpInDatagrams;
 	unsigned long	UdpNoPorts;
 	unsigned long	UdpInErrors;
 	unsigned long	UdpOutDatagrams;
};


static	AsnIdType	icmpRetrieve (CIntfType item)
{
struct icmp_mib icmpstat;
	AsnIdType		asnresult;
	//CIntfType		i;
   	unsigned long	result;
        FILE *in;
        char line [1024];

  in = fopen ("/proc/net/snmp", "r");
  if (! in)
	{
    	printf("icmpRetrieve() Error opening /proc/net/snmp\n");	
	return 0;
	}

  while (line == fgets (line, 1024, in))
    {
      if (26 == sscanf (line,
"Icmp: %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
   &icmpstat.IcmpInMsgs, &icmpstat.IcmpInErrors, &icmpstat.IcmpInDestUnreachs, 
   &icmpstat.IcmpInTimeExcds, &icmpstat.IcmpInParmProbs, &icmpstat.IcmpInSrcQuenchs,
   &icmpstat.IcmpInRedirects, &icmpstat.IcmpInEchos, &icmpstat.IcmpInEchoReps, 
   &icmpstat.IcmpInTimestamps, &icmpstat.IcmpInTimestampReps, &icmpstat.IcmpInAddrMasks,
   &icmpstat.IcmpInAddrMaskReps, &icmpstat.IcmpOutMsgs, &icmpstat.IcmpOutErrors,
   &icmpstat.IcmpOutDestUnreachs, &icmpstat.IcmpOutTimeExcds, 
   &icmpstat.IcmpOutParmProbs, &icmpstat.IcmpOutSrcQuenchs, &icmpstat.IcmpOutRedirects,
   &icmpstat.IcmpOutEchos, &icmpstat.IcmpOutEchoReps, &icmpstat.IcmpOutTimestamps, 
   &icmpstat.IcmpOutTimestampReps, &icmpstat.IcmpOutAddrMasks,
   &icmpstat.IcmpOutAddrMaskReps))
	break;
    }
  fclose (in);

  switch (item-1){
    case ICMPINMSGS: 
	result=icmpstat.IcmpInMsgs;
	break;
    case ICMPINERRORS: 
	result=icmpstat.IcmpInErrors;
	break;
    case ICMPINDESTUNREACHS: 
	result=icmpstat.IcmpInDestUnreachs;
	break;
    case ICMPINTIMEEXCDS: 
	result=icmpstat.IcmpInTimeExcds;
	break;
    case ICMPINPARMPROBS: 
	result=icmpstat.IcmpInParmProbs;
	break;
    case ICMPINSRCQUENCHS: 
	result=icmpstat.IcmpInSrcQuenchs;
 	break;
    case ICMPINREDIRECTS: 
	result=icmpstat.IcmpInRedirects;
 	break;
    case ICMPINECHOS: 
	result=icmpstat.IcmpInEchos;
 	break;
    case ICMPINECHOREPS: 
	result=icmpstat.IcmpInEchoReps;
 	break;
    case ICMPINTIMESTAMPS: 
	result=icmpstat.IcmpInTimestamps;
  	break;
   case ICMPINTIMESTAMPREPS:  
	result=icmpstat.IcmpInTimestampReps;
  	break;
   case ICMPINADDRMASKS:  
	result=icmpstat.IcmpInAddrMasks;
  	break;
   case ICMPINADDRMASKREPS:  
	result=icmpstat.IcmpInAddrMaskReps;
 	break;
    case ICMPOUTMSGS:  
	result=icmpstat.IcmpOutMsgs;
 	break;
    case ICMPOUTERRORS:  
	result=icmpstat.IcmpOutErrors;
  	break;
   case ICMPOUTDESTUNREACHS:  
	result=icmpstat.IcmpOutDestUnreachs;
  	break;
   case ICMPOUTTIMEEXCDS:  
	result=icmpstat.IcmpOutTimeExcds;
 	break;
    case ICMPOUTPARMPROBS:  
	result=icmpstat.IcmpOutParmProbs;
 	break;
    case ICMPOUTSRCQUENCHS:  
	result=icmpstat.IcmpOutSrcQuenchs;
  	break;
   case ICMPOUTREDIRECTS:  
	result=icmpstat.IcmpOutRedirects;
 	break;
    case ICMPOUTECHOS:  
	result=icmpstat.IcmpOutEchos;
 	break;
    case ICMPOUTECHOREPS:  
	result=icmpstat.IcmpOutEchoReps;
 	break;
    case ICMPOUTTIMESTAMPS:  
	result=icmpstat.IcmpOutTimestamps;
 	break;
    case ICMPOUTTIMESTAMPREPS:  
	result=icmpstat.IcmpOutTimestampReps;
 	break;
    case ICMPOUTADDRMASKS:  
	result=icmpstat.IcmpOutAddrMasks;
 	break;
    case ICMPOUTADDRMASKREPS:  
	result=icmpstat.IcmpOutAddrMaskReps;
 	break;
    default:
	break;
	}		
	
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,
			result);
	return (asnresult);
}

static	MixStatusType	icmpRelease (MixCookieType cookie)
{
	cookie = cookie;
	return (smpErrorGeneric);
}

static	MixStatusType	icmpCreate (MixCookieType cookie, MixNamePtrType name, MixLengthType namelen, AsnIdType asn)
{
	cookie = cookie;
	name = name;
	namelen = namelen;
	asn = asn;
	return (smpErrorGeneric);
}

static	MixStatusType	icmpDestroy (MixCookieType cookie, MixNamePtrType name, MixLengthType namelen)
{
	cookie = cookie;
	name = name;
	namelen = namelen;
	return (smpErrorGeneric);
}

static	AsnIdType	icmpGet (MixCookieType cookie, MixNamePtrType name, MixLengthType namelen)
{
	CIntfType		item;

	cookie = cookie;
	if ((namelen != (MixLengthType) 2) ||
		((item = (CIntfType) *name) < (CIntfType) 1) ||
		(item > (CIntfType) (ICMP_MAXTYPE+1)) || (*(name + 1) != (MixNameType) 0)) {
		return ((AsnIdType) 0);
	}
	else {
		return (icmpRetrieve (item));
	}
}

static	MixStatusType	icmpSet (MixCookieType cookie, MixNamePtrType name, MixLengthType namelen, AsnIdType asn)
{
	cookie = cookie;
	name = name;
	namelen = namelen;
	asn = asn;
	return (smpErrorReadOnly);
}

static	AsnIdType	icmpNext (MixCookieType cookie, MixNamePtrType name, MixLengthPtrType namelenp)
{
	CIntfType		item;

	cookie = cookie;
	if (*namelenp == (MixLengthType) 0) {
		*namelenp = (MixLengthType) 2;
		*name++ = (MixNameType) 1;
		*name = (MixNameType) 0;
		return (icmpRetrieve ((CIntfType) 1));
	}
	else if (*namelenp == (MixLengthType) 1) {
		if ((item = (CIntfType) *name) <= (CIntfType) (ICMP_MAXTYPE+1)) {
			*namelenp = (MixLengthType) 2;
			*(++name) = (MixNameType) 0;
			return (icmpRetrieve (item));
		}
		else {
			return ((AsnIdType) 0);
		}
	}
	else if ((item = (CIntfType) *name) < (CIntfType) (ICMP_MAXTYPE+1)) {
		*namelenp = (MixLengthType) 2;
		*name++ = (MixNameType) (++item);
		*name = (MixNameType) 0;
		return (icmpRetrieve (item));
	}
	else {
		return ((AsnIdType) 0);
	}
}

static	MixOpsType	icmpOps = {

			icmpRelease,
			icmpCreate,
			icmpDestroy,
			icmpNext,
			icmpGet,
			icmpSet

			};

CVoidType		icmpInit (void)
{
unsigned long result;
int icmpcount;
 FILE *in;
struct icmp_mib icmpstat;

  char line [1024];
 

in = fopen ("/proc/net/snmp", "r");

  if (! in)
    return;

  while (line == fgets (line, 1024, in))
    {
      if (26 == sscanf (line,
"Icmp: %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
   &icmpstat.IcmpInMsgs, &icmpstat.IcmpInErrors, &icmpstat.IcmpInDestUnreachs, 
   &icmpstat.IcmpInTimeExcds, &icmpstat.IcmpInParmProbs, &icmpstat.IcmpInSrcQuenchs,
   &icmpstat.IcmpInRedirects, &icmpstat.IcmpInEchos, &icmpstat.IcmpInEchoReps, 
   &icmpstat.IcmpInTimestamps, &icmpstat.IcmpInTimestampReps, &icmpstat.IcmpInAddrMasks,
   &icmpstat.IcmpInAddrMaskReps, &icmpstat.IcmpOutMsgs, &icmpstat.IcmpOutErrors,
   &icmpstat.IcmpOutDestUnreachs, &icmpstat.IcmpOutTimeExcds, 
   &icmpstat.IcmpOutParmProbs, &icmpstat.IcmpOutSrcQuenchs, &icmpstat.IcmpOutRedirects,
   &icmpstat.IcmpOutEchos, &icmpstat.IcmpOutEchoReps, &icmpstat.IcmpOutTimestamps, 
   &icmpstat.IcmpOutTimestampReps, &icmpstat.IcmpOutAddrMasks,
   &icmpstat.IcmpOutAddrMaskReps))
	break;
    }
  fclose (in);

	
for(icmpcount = 0;icmpcount <= ICMPOUTADDRMASKREPS;icmpcount++)
		{	
switch (icmpcount)
	{
     case ICMPINMSGS: 
	result=icmpstat.IcmpInMsgs;
	break;
    case ICMPINERRORS: 
	result=icmpstat.IcmpInErrors;
	break;
    case ICMPINDESTUNREACHS: 
	result=icmpstat.IcmpInDestUnreachs;
	break;
    case ICMPINTIMEEXCDS: 
	result=icmpstat.IcmpInTimeExcds;
	break;
    case ICMPINPARMPROBS: 
	result=icmpstat.IcmpInParmProbs;
	break;
    case ICMPINSRCQUENCHS: 
	result=icmpstat.IcmpInSrcQuenchs;
 	break;
    case ICMPINREDIRECTS: 
	result=icmpstat.IcmpInRedirects;
 	break;
    case ICMPINECHOS: 
	result=icmpstat.IcmpInEchos;
 	break;
    case ICMPINECHOREPS: 
	result=icmpstat.IcmpInEchoReps;
 	break;
    case ICMPINTIMESTAMPS: 
	result=icmpstat.IcmpInTimestamps;
  	break;
   case ICMPINTIMESTAMPREPS:  
	result=icmpstat.IcmpInTimestampReps;
  	break;
   case ICMPINADDRMASKS:  
	result=icmpstat.IcmpInAddrMasks;
  	break;
   case ICMPINADDRMASKREPS:  
	result=icmpstat.IcmpInAddrMaskReps;
 	break;
    case ICMPOUTMSGS:  
	result=icmpstat.IcmpOutMsgs;
 	break;
    case ICMPOUTERRORS:  
	result=icmpstat.IcmpOutErrors;
  	break;
   case ICMPOUTDESTUNREACHS:  
	result=icmpstat.IcmpOutDestUnreachs;
  	break;
   case ICMPOUTTIMEEXCDS:  
	result=icmpstat.IcmpOutTimeExcds;
 	break;
    case ICMPOUTPARMPROBS:  
	result=icmpstat.IcmpOutParmProbs;
 	break;
    case ICMPOUTSRCQUENCHS:  
	result=icmpstat.IcmpOutSrcQuenchs;
  	break;
   case ICMPOUTREDIRECTS:  
	result=icmpstat.IcmpOutRedirects;
 	break;
    case ICMPOUTECHOS:  
	result=icmpstat.IcmpOutEchos;
 	break;
    case ICMPOUTECHOREPS:  
	result=icmpstat.IcmpOutEchoReps;
 	break;
    case ICMPOUTTIMESTAMPS:  
	result=icmpstat.IcmpOutTimestamps;
 	break;
    case ICMPOUTTIMESTAMPREPS:  
	result=icmpstat.IcmpOutTimestampReps;
 	break;
    case ICMPOUTADDRMASKS:  
	result=icmpstat.IcmpOutAddrMasks;
 	break;
    case ICMPOUTADDRMASKREPS:  
	result=icmpstat.IcmpOutAddrMaskReps;
 	break;
    default:
	break;
	}
	
	icmpAddr = (CUnslType) result;
		(void) misExport ((MixNamePtrType) "\53\6\1\2\1\5",
			(MixLengthType) 6, & icmpOps, (MixCookieType) 0);
	}


}

