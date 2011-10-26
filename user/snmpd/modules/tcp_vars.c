

#include	<stdio.h>
#include	<netdb.h>
#include	<unistd.h>

#include	"ctypes.h"
#include	"error.h"
#include	"local.h"
#include	"tcp_vars.h"
#include	"mix.h"
#include	"mis.h"
#include	"asn.h"

#define TCP_MAXTYPE 11

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
        unsigned long   TcpInErrs;
        unsigned long   TcpOutRsts;
};

static	CUnslType		tcpAddr;
 
static	AsnIdType	tcpRetrieve (CIntfType item)
{
struct tcp_mib tcpstat;
	AsnIdType		asnresult;
        FILE *in;
        char line [1024];

  in = fopen ("/proc/net/snmp", "r");
  if (! in)
	{
    	printf("tcpRetrieve() Error opening /proc/net/snmp\n");	
	return 0;
	}

  while (line == fgets (line, 1024, in))
    {
      if (12 == sscanf (line, "Tcp: %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
		&tcpstat.TcpRtoAlgorithm,&tcpstat.TcpRtoMin,&tcpstat.TcpRtoMax, &tcpstat.TcpMaxConn,
	&tcpstat.TcpActiveOpens,&tcpstat.TcpPassiveOpens,&tcpstat.TcpAttemptFails,
	&tcpstat.TcpEstabResets,&tcpstat.TcpCurrEstab, &tcpstat.TcpInSegs,
	&tcpstat.TcpOutSegs,&tcpstat.TcpRetransSegs))
	break;
    }
  fclose (in);

	
  switch (item)
	{
    case TCPRTOALGORITHM: 
	asnresult = asnUnsl (asnClassUniversal, (AsnTagType) 2,tcpstat.TcpRtoAlgorithm);
	break;
    case TCPRTOMIN: 
	asnresult = asnUnsl (asnClassUniversal, (AsnTagType) 2,tcpstat.TcpRtoMin);
	break;
    case TCPRTOMAX: 
	asnresult = asnUnsl (asnClassUniversal, (AsnTagType) 2,tcpstat.TcpRtoMax);
	break;
    case TCPMAXCONN: 
	asnresult = asnUnsl (asnClassUniversal, (AsnTagType) 2,tcpstat.TcpMaxConn);
	break;
    case TCPACTIVEOPENS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,tcpstat.TcpActiveOpens);
	break;
    case TCPPASSIVEOPENS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,tcpstat.TcpPassiveOpens);
	break;
    case TCPATTEMPTFAILS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,tcpstat.TcpAttemptFails);
	break;
    case TCPESTABRESETS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,tcpstat.TcpEstabResets);
	break;
    case TCPCURRESTAB: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 2,tcpstat.TcpCurrEstab);
	break;
    case TCPINSEGS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,tcpstat.TcpInSegs);
	break;
    case TCPOUTSEGS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,tcpstat.TcpOutSegs);
	break;
    case TCPRETRANSSEGS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,tcpstat.TcpRetransSegs);
	break;
    default:
	break;
	}	
	
return (asnresult);
}

static	MixStatusType	tcpRelease (MixCookieType cookie)
{
	cookie = cookie;
	return (smpErrorGeneric);
}

static	MixStatusType	tcpCreate (MixCookieType cookie, MixNamePtrType name, MixLengthType namelen, AsnIdType asn)
{
	cookie = cookie;
	name = name;
	namelen = namelen;
	asn = asn;
	return (smpErrorGeneric);
}

static	MixStatusType	tcpDestroy (MixCookieType cookie, MixNamePtrType name, MixLengthType namelen)
{
	cookie = cookie;
	name = name;
	namelen = namelen;
	return (smpErrorGeneric);
}

static	AsnIdType	tcpGet (MixCookieType cookie, MixNamePtrType name, MixLengthType namelen)
{
	CIntfType		item;

	cookie = cookie;
	if ((namelen != (MixLengthType) 2) ||
		((item = (CIntfType) *name) < (CIntfType) 1) ||
		(item > (CIntfType) (TCP_MAXTYPE+1)) || (*(name + 1) != (MixNameType) 0)) {
		return ((AsnIdType) 0);
	}
	else {
		return (tcpRetrieve (item));
	}
}

static	MixStatusType	tcpSet (MixCookieType cookie, MixNamePtrType name, MixLengthType namelen, AsnIdType asn)
{
	cookie = cookie;
	name = name;
	namelen = namelen;
	asn = asn;
	return (smpErrorReadOnly);
}

static	AsnIdType	tcpNext (MixCookieType cookie, MixNamePtrType name, MixLengthPtrType namelenp)
{
	CIntfType		item;

	cookie = cookie;
	if (*namelenp == (MixLengthType) 0) {
		*namelenp = (MixLengthType) 2;
		*name++ = (MixNameType) 1;
		*name = (MixNameType) 0;
		return (tcpRetrieve ((CIntfType) 1));
	}
	else if (*namelenp == (MixLengthType) 1) {
		if ((item = (CIntfType) *name) <= (CIntfType) (TCP_MAXTYPE+1)) {
			*namelenp = (MixLengthType) 2;
			*(++name) = (MixNameType) 0;
			return (tcpRetrieve (item));
		}
		else {
			return ((AsnIdType) 0);
		}
	}
	else if ((item = (CIntfType) *name) < (CIntfType) (TCP_MAXTYPE+1)) {
		*namelenp = (MixLengthType) 2;
		*name++ = (MixNameType) (++item);
		*name = (MixNameType) 0;
		return (tcpRetrieve (item));
	}
	else {
		return ((AsnIdType) 0);
	}
}

static	MixOpsType	tcpOps = {

			tcpRelease,
			tcpCreate,
			tcpDestroy,
			tcpNext,
			tcpGet,
			tcpSet

			};

CVoidType		tcpInit (void)
{
unsigned long result;
int tcpcount;
 FILE *in;
struct tcp_mib tcpstat;

  char line [1024];
 
in = fopen ("/proc/net/snmp", "r");


  if (! in)
    return;

  while (line == fgets (line, 1024, in))
    {
     if (12 == sscanf (line, "Tcp: %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
	&tcpstat.TcpRtoAlgorithm,&tcpstat.TcpRtoMin,&tcpstat.TcpRtoMax, &tcpstat.TcpMaxConn,
	&tcpstat.TcpActiveOpens,&tcpstat.TcpPassiveOpens,&tcpstat.TcpAttemptFails,
	&tcpstat.TcpEstabResets,&tcpstat.TcpCurrEstab, &tcpstat.TcpInSegs,
	&tcpstat.TcpOutSegs,&tcpstat.TcpRetransSegs))
	break;
    }
  fclose (in);

	
for(tcpcount = 1;tcpcount <= TCP_MAXTYPE;tcpcount++)
		{	
 switch (tcpcount){
    case TCPRTOALGORITHM: 
	result=tcpstat.TcpRtoAlgorithm;
	break;
    case TCPRTOMIN: 
	result=tcpstat.TcpRtoMin;
	break;
    case TCPRTOMAX: 
	result=tcpstat.TcpRtoMax;
	break;
    case TCPMAXCONN: 
	result=tcpstat.TcpMaxConn;
	break;
    case TCPACTIVEOPENS: 
	result=tcpstat.TcpActiveOpens;
	break;
    case TCPPASSIVEOPENS: 
	result=tcpstat.TcpPassiveOpens;
	break;
    case TCPATTEMPTFAILS: 
	result=tcpstat.TcpAttemptFails;
	break;
    case TCPESTABRESETS: 
	result=tcpstat.TcpEstabResets;
	break;
    case TCPCURRESTAB: 
	result=tcpstat.TcpCurrEstab;
	break;
    case TCPINSEGS: 
	result=tcpstat.TcpInSegs;
	break;
    case TCPOUTSEGS: 
	result=tcpstat.TcpOutSegs;
	break;
    case TCPRETRANSSEGS: 
	result=tcpstat.TcpRetransSegs;
	break;
    default:
	break;
	}		
	
	tcpAddr = (CUnslType) result;
		(void) misExport ((MixNamePtrType) "\53\6\1\2\1\6",
			(MixLengthType) 6, & tcpOps, (MixCookieType) 0);
	}


}

