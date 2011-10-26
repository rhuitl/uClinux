

#include	<stdio.h>
#include	<netdb.h>
#include	<unistd.h>

#include	"ctypes.h"
#include	"error.h"
#include	"local.h"
#include	"ip_vars.h"
#include	"mix.h"
#include	"mis.h"
#include	"asn.h"

#define IP_MAXTYPE 18

static	CUnslType		ipAddr;
 
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


static	AsnIdType	ipRetrieve (CIntfType item)
{
struct ip_mib ipstat;
	AsnIdType		asnresult;
        FILE *in;
        char line [1024];
	
  in = fopen ("/proc/net/snmp", "r");
  if (! in)
	{
    	printf("ipRetrieve() Error opening /proc/net/snmp\n");	
	return 0;
	}

  while (line == fgets (line, 1024, in))
    {
       if ((IP_MAXTYPE+1) == sscanf (line,   
	"Ip: %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
     &ipstat.IpForwarding, &ipstat.IpDefaultTTL, &ipstat.IpInReceives, 
     &ipstat.IpInHdrErrors, &ipstat.IpInAddrErrors, &ipstat.IpForwDatagrams, 
     &ipstat.IpInUnknownProtos, &ipstat.IpInDiscards, &ipstat.IpInDelivers, 
     &ipstat.IpOutRequests, &ipstat.IpOutDiscards, &ipstat.IpOutNoRoutes, 
     &ipstat.IpReasmTimeout, &ipstat.IpReasmReqds, &ipstat.IpReasmOKs, 
     &ipstat.IpReasmFails, &ipstat.IpFragOKs, &ipstat.IpFragFails, 
     &ipstat.IpFragCreates))
	break;
    }
  fclose (in);

  switch (item-1){
   case IPFORWARDING: 
	asnresult = asnUnsl (asnClassUniversal, (AsnTagType) 2,ipstat.IpForwarding);
	break;
    case IPDEFAULTTTL: 
	asnresult = asnUnsl (asnClassUniversal, (AsnTagType) 2,ipstat.IpDefaultTTL);
	break;
    case IPINRECEIVES: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,ipstat.IpInReceives);
	break;
    case IPINHDRERRORS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,ipstat.IpInHdrErrors);
	break;
    case IPINADDRERRORS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,ipstat.IpInAddrErrors);
	break;
    case IPFORWDATAGRAMS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,ipstat.IpForwDatagrams);
	break;
    case IPINUNKNOWNPROTOS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,ipstat.IpInUnknownProtos);
	break;
    case IPINDISCARDS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,ipstat.IpInDiscards);
	break;
    case IPINDELIVERS:
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,ipstat.IpInDelivers);
	break;
    case IPOUTREQUESTS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,ipstat.IpOutRequests);
	break;
    case IPOUTDISCARDS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,ipstat.IpOutDiscards);
	break;
    case IPOUTNOROUTES: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,ipstat.IpOutNoRoutes);
	break;
    case IPREASMTIMEOUT: 
	asnresult = asnUnsl (asnClassUniversal, (AsnTagType) 2,ipstat.IpReasmTimeout);
	break;
    case IPREASMREQDS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,ipstat.IpReasmReqds);
	break;
    case IPREASMOKS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,ipstat.IpReasmOKs);
	break;
    case IPREASMFAILS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,ipstat.IpReasmFails);
	break;
    case IPFRAGOKS:
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,ipstat.IpFragOKs);
	break;
    case IPFRAGFAILS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,ipstat.IpFragFails);
	break;
    case IPFRAGCREATES: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,ipstat.IpFragCreates);
	break;
   default:
	break;
	}
	
	return (asnresult);
}

static	MixStatusType	ipRelease (MixCookieType cookie)
{
	cookie = cookie;
	return (smpErrorGeneric);
}

static	MixStatusType	ipCreate (MixCookieType cookie, MixNamePtrType name, MixLengthType namelen, AsnIdType asn)
{
	cookie = cookie;
	name = name;
	namelen = namelen;
	asn = asn;
	return (smpErrorGeneric);
}

static	MixStatusType	ipDestroy (MixCookieType cookie, MixNamePtrType name, MixLengthType namelen)
{
	cookie = cookie;
	name = name;
	namelen = namelen;
	return (smpErrorGeneric);
}

static	AsnIdType	ipGet (MixCookieType cookie, MixNamePtrType name, MixLengthType namelen)
{
	CIntfType		item;

	cookie = cookie;
	if ((namelen != (MixLengthType) 2) ||
		((item = (CIntfType) *name) < (CIntfType) 1) ||
		(item > (CIntfType) (IP_MAXTYPE+1)) || (*(name + 1) != (MixNameType) 0)) {
		return ((AsnIdType) 0);
	}
	else {
		return (ipRetrieve (item));
	}
}

static	MixStatusType	ipSet (MixCookieType cookie, MixNamePtrType name, MixLengthType namelen, AsnIdType asn)
{
	cookie = cookie;
	name = name;
	namelen = namelen;
	asn = asn;
	return (smpErrorReadOnly);
}

static	AsnIdType	ipNext (MixCookieType cookie, MixNamePtrType name, MixLengthPtrType namelenp)
{
	CIntfType		item;

	cookie = cookie;
	if (*namelenp == (MixLengthType) 0) {
		*namelenp = (MixLengthType) 2;
		*name++ = (MixNameType) 1;
		*name = (MixNameType) 0;
		return (ipRetrieve ((CIntfType) 1));
	}
	else if (*namelenp == (MixLengthType) 1) {
		if ((item = (CIntfType) *name) <= (CIntfType) (IP_MAXTYPE+1)) {
			*namelenp = (MixLengthType) 2;
			*(++name) = (MixNameType) 0;
			return (ipRetrieve (item));
		}
		else {
			return ((AsnIdType) 0);
		}
	}
	else if ((item = (CIntfType) *name) < (CIntfType) (IP_MAXTYPE+1)) {
		*namelenp = (MixLengthType) 2;
		*name++ = (MixNameType) (++item);
		*name = (MixNameType) 0;
		return (ipRetrieve (item));
	}
	else {
		return ((AsnIdType) 0);
	}
}

static	MixOpsType	ipOps = {

			ipRelease,
			ipCreate,
			ipDestroy,
			ipNext,
			ipGet,
			ipSet

			};

CVoidType		ipInit (void)
{
unsigned long result;
int ipcount;
 FILE *in;
struct ip_mib ipstat;

  char line [1024];

in = fopen ("/proc/net/snmp", "r");


  if (! in)
    return;

  while (line == fgets (line, 1024, in))
    {
      if (19 == sscanf (line,   
	"Ip: %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
     &ipstat.IpForwarding, &ipstat.IpDefaultTTL, &ipstat.IpInReceives, 
     &ipstat.IpInHdrErrors, &ipstat.IpInAddrErrors, &ipstat.IpForwDatagrams, 
     &ipstat.IpInUnknownProtos, &ipstat.IpInDiscards, &ipstat.IpInDelivers, 
     &ipstat.IpOutRequests, &ipstat.IpOutDiscards, &ipstat.IpOutNoRoutes, 
     &ipstat.IpReasmTimeout, &ipstat.IpReasmReqds, &ipstat.IpReasmOKs, 
     &ipstat.IpReasmFails, &ipstat.IpFragOKs, &ipstat.IpFragFails, 
     &ipstat.IpFragCreates))
    break;
    }
  fclose (in);

	
for(ipcount = 0;ipcount <= IP_MAXTYPE;ipcount++)
		{	
 switch (ipcount){
   case IPFORWARDING: 
	result=ipstat.IpForwarding;
	break;
    case IPDEFAULTTTL: 
	result=ipstat.IpDefaultTTL;
	break;
    case IPINRECEIVES: 
	result=ipstat.IpInReceives;
	break;
    case IPINHDRERRORS: 
	result=ipstat.IpInHdrErrors;
	break;
    case IPINADDRERRORS: 
	result=ipstat.IpInAddrErrors;
	break;
    case IPFORWDATAGRAMS: 
	result=ipstat.IpForwDatagrams;
	break;
    case IPINUNKNOWNPROTOS: 
	result=ipstat.IpInUnknownProtos;
	break;
    case IPINDISCARDS: 
	result=ipstat.IpInDiscards;
	break;
    case IPINDELIVERS:
	result=ipstat.IpInDelivers;
	break;
    case IPOUTREQUESTS: 
	result=ipstat.IpOutRequests;
	break;
    case IPOUTDISCARDS: 
	result=ipstat.IpOutDiscards;
	break;
    case IPOUTNOROUTES: 
	result=ipstat.IpOutNoRoutes;
	break;
    case IPREASMTIMEOUT: 
	result=ipstat.IpReasmTimeout;
	break;
    case IPREASMREQDS: 
	result=ipstat.IpReasmReqds;
	break;
    case IPREASMOKS: 
	result=ipstat.IpReasmOKs;
	break;
    case IPREASMFAILS: 
	result=ipstat.IpReasmFails;
	break;
    case IPFRAGOKS:
	result=ipstat.IpFragOKs;
	break;
    case IPFRAGFAILS: 
	result=ipstat.IpFragFails;
	break;
    case IPFRAGCREATES: 
	result=ipstat.IpFragCreates;
	break;
     default:
	break;
	}		
	
	ipAddr = (CUnslType) result;
		(void) misExport ((MixNamePtrType) "\53\6\1\2\1\4",
			(MixLengthType) 6, & ipOps, (MixCookieType) 0);
}
}

