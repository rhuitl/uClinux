

//#include	<sys/types.h>
#include	<stdio.h>
#include	<netdb.h>
#include	<unistd.h>

#include	"ctypes.h"
#include	"error.h"
#include	"local.h"
#include	"udp_vars.h"
#include	"mix.h"
#include	"mis.h"
#include	"asn.h"

#define UDP_MAXTYPE 3

static	CUnslType		udpAddr;
 
 
struct udp_mib
{
 	unsigned long	UdpInDatagrams;
 	unsigned long	UdpNoPorts;
 	unsigned long	UdpInErrors;
 	unsigned long	UdpOutDatagrams;
};


static	AsnIdType	udpRetrieve (CIntfType item)
{
struct udp_mib udpstat;
	AsnIdType		asnresult;
   	unsigned long	result;
        FILE *in;
        char line [1024];

  in = fopen ("/proc/net/snmp", "r");
  if (! in)
	{
    	printf("udpRetrieve() Error opening /proc/net/snmp\n");	
	return 0;
	}

  while (line == fgets (line, 1024, in))
    {
      if (4 == sscanf (line, "Udp: %lu %lu %lu %lu\n",
			&udpstat.UdpInDatagrams, &udpstat.UdpNoPorts,
			&udpstat.UdpInErrors, &udpstat.UdpOutDatagrams))
	break;
    }
  fclose (in);
  switch (item-1){
    case UDPINDATAGRAMS: 
	result=udpstat.UdpInDatagrams;
	break;
    case UDPNOPORTS: 
	result=udpstat.UdpNoPorts;
	break;
    case UDPINERRORS: 
	result=udpstat.UdpInErrors;
	break;
    case UDPOUTDATAGRAMS: 
	result=udpstat.UdpOutDatagrams;
	break;
    default:
	break;
	}		
	
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,
			result);
	return (asnresult);
}

static	MixStatusType	udpRelease (MixCookieType cookie)
{
	cookie = cookie;
	return (smpErrorGeneric);
}

static	MixStatusType	udpCreate (MixCookieType cookie, MixNamePtrType name, MixLengthType namelen, AsnIdType asn)
{
	cookie = cookie;
	name = name;
	namelen = namelen;
	asn = asn;
	return (smpErrorGeneric);
}

static	MixStatusType	udpDestroy (MixCookieType cookie, MixNamePtrType name, MixLengthType namelen)
{
	cookie = cookie;
	name = name;
	namelen = namelen;
	return (smpErrorGeneric);
}

static	AsnIdType	udpGet (MixCookieType cookie, MixNamePtrType name, MixLengthType namelen)
{
	CIntfType		item;

	cookie = cookie;
	if ((namelen != (MixLengthType) 2) ||
		((item = (CIntfType) *name) < (CIntfType) 1) ||
		(item > (CIntfType) (UDP_MAXTYPE+1)) || (*(name + 1) != (MixNameType) 0)) {
		return ((AsnIdType) 0);
	}
	else {
		return (udpRetrieve (item));
	}
}

static	MixStatusType	udpSet (MixCookieType cookie, MixNamePtrType name, MixLengthType namelen, AsnIdType asn)
{
	cookie = cookie;
	name = name;
	namelen = namelen;
	asn = asn;
	return (smpErrorReadOnly);
}

static	AsnIdType	udpNext (MixCookieType cookie, MixNamePtrType name, MixLengthPtrType namelenp)
{
	CIntfType		item;


	cookie = cookie;
	if (*namelenp == (MixLengthType) 0) {
		*namelenp = (MixLengthType) 2;
		*name++ = (MixNameType) 1;
		*name = (MixNameType) 0;
		return (udpRetrieve ((CIntfType) 1));
	}
	else if (*namelenp == (MixLengthType) 1) {
		if ((item = (CIntfType) *name) <= (CIntfType) (UDP_MAXTYPE+1)) {
			*namelenp = (MixLengthType) 2;
			*(++name) = (MixNameType) 0;
			return (udpRetrieve (item));
		}
		else {
			return ((AsnIdType) 0);
		}
	}
	else if ((item = (CIntfType) *name) < (CIntfType) (UDP_MAXTYPE+1)) {
		*namelenp = (MixLengthType) 2;
		*name++ = (MixNameType) (++item);
		*name = (MixNameType) 0;
		return (udpRetrieve (item));
	}
	else {
		return ((AsnIdType) 0);
	}
}

static	MixOpsType	udpOps = {

			udpRelease,
			udpCreate,
			udpDestroy,
			udpNext,
			udpGet,
			udpSet

			};

CVoidType		udpInit (void)
{
unsigned long result;
int udpcount;
 FILE *in;
struct udp_mib udpstat;

  char line [1024];
 
in = fopen ("/proc/net/snmp", "r");


  if (! in)
    return;

  while (line == fgets (line, 1024, in))
    {
       if (4 == sscanf (line, "Udp: %lu %lu %lu %lu\n",
			&udpstat.UdpInDatagrams, &udpstat.UdpNoPorts,
			&udpstat.UdpInErrors, &udpstat.UdpOutDatagrams))
	break;
    }
  fclose (in);

	
for(udpcount = 0;udpcount <= UDP_MAXTYPE;udpcount++)
		{	
 switch (udpcount){
    case UDPINDATAGRAMS: 
	result=udpstat.UdpInDatagrams;
	break;
    case UDPNOPORTS: 
	result=udpstat.UdpNoPorts;
	break;
    case UDPINERRORS: 
	result=udpstat.UdpInErrors;
	break;
    case UDPOUTDATAGRAMS: 
	result=udpstat.UdpOutDatagrams;
	break;
    default:
	break;
	}		
	
	udpAddr = (CUnslType) result;
		(void) misExport ((MixNamePtrType) "\53\6\1\2\1\7",
			(MixLengthType) 6, & udpOps, (MixCookieType) 0);
	}


}

