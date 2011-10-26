
#include <net/if.h>
#include	<stdio.h>
#include	<netdb.h>
#include	<unistd.h>
#include	<time.h>

#include	"ctypes.h"
#include	"error.h"
#include	"local.h"
#include	"iface_vars.h"
#include	"mix.h"
#include	"mis.h"
#include	"asn.h"

#define IFACE_MAXTYPE 1
#define IFACE_MAXTYPE21 22
static	CUnslType ifaceAddr;

struct ifnet {
	char	*if_name;		/* name, e.g. ``en1'' or ``lo'' */
  /* 	short	if_unit;		/ * sub-unit for lower level driver */
	short	if_mtu;			/* maximum transmission unit */
	short	if_flags;		/* up/down, broadcast, etc. */
	int	if_metric;		/* routing metric (external only) */
	char    if_hwaddr [6];		/* ethernet address */
	int	if_type;		/* interface type: 1=generic,
					   28=slip, ether=6, loopback=24,
					   7=802.3, 23=ppp */
	int	if_speed;		/* interface speed: in bits/sec */

	struct sockaddr if_addr;	/* interface's address */
	struct sockaddr ifu_broadaddr;	/* broadcast address */
	struct sockaddr ia_subnetmask; 	/* interface's mask */

	struct	ifqueue {
		int	ifq_len;
		int	ifq_drops;
	} if_snd;			/* output queue */

        /* ibytes and obytes added for cmu snmp linux v3.4: */
        unsigned long if_ibytes;	/* # of bytes received */
        unsigned long if_obytes;	/* # of bytes sent */

        unsigned long if_ipackets;	/* packets received on interface */
	unsigned long if_opackets;	/* packets sent on interface */

	unsigned long if_ierrors;	/* input errors on interface */
	unsigned long if_oerrors;	/* output errors on interface */

        /* note: collisions are filled but not used */
	unsigned long if_collisions;	/* collisions on csma interfaces */

	unsigned long if_idrop;		/* discard on input */
	unsigned long if_odrop;		/* discard on output */
/* end statistics */
	struct	ifnet *if_next;
};

struct mib_ifEntry {
    long    ifIndex;	    /* index of this interface	*/
    char    ifDescr[32];    /* english description of interface	*/
    long    ifType;	    /* network type of device	*/
    long    ifMtu;	    /* size of largest packet in bytes	*/
    u_long  ifSpeed;	    /* bandwidth in bits/sec	*/
    u_char  ifPhysAddress[11];	/* interface's address */
    u_char  PhysAddrLen;    /* length of physAddr */
    long    ifAdminStatus;  /* desired state of interface */
    long    ifOperStatus;   /* current operational status */
    u_long  ifLastChange;   /* value of sysUpTime when current state entered */
    u_long  ifInOctets;	    /* number of octets received on interface */
    u_long  ifInUcastPkts;  /* number of unicast packets delivered */
    u_long  ifInNUcastPkts; /* number of broadcasts or multicasts */
    u_long  ifInDiscards;   /* number of packets discarded with no error */
    u_long  ifInErrors;	    /* number of packets containing errors */
    u_long  ifInUnknownProtos;	/* number of packets with unknown protocol */
    u_long  ifOutOctets;    /* number of octets transmitted */
    u_long  ifOutUcastPkts; /* number of unicast packets sent */
    u_long  ifOutNUcastPkts;/* number of broadcast or multicast pkts */
    u_long  ifOutDiscards;  /* number of packets discarded with no error */
    u_long  ifOutErrors;    /* number of pkts discarded with an error */
    u_long  ifOutQLen;	    /* number of packets in output queue */
};


static int
Interface_Scan_Get_Count(void)
{
        static int Interface_Count=0;
	static time_t last = 0;
	time_t now = time ((time_t *) 0);
	
	/* allow the counter only be valid for some seconds: */
	if (last + 2 < now) {
	  last = now;
	  Interface_Count = 3;
	}

	if (! Interface_Count) 
		{
	    while (0) 
			{
			Interface_Count++;
	    		}
		}
	return Interface_Count;
}

static	AsnIdType	ifaceRetrieve (CIntfType item)
{
    int	interface;
    int result, count;
	struct ifnet ifnet;
	struct mib_ifEntry ifacestat;
	AsnIdType		asnresult;

   count = Interface_Scan_Get_Count();

//printf("ifaceRetrieve (item=%d) num of interfaces = %d\n",item,count);    
	
    //for(interface = 1; interface <= count; interface++)
	//{
	//printf("ifaceRetrieve (item=%d) num of interfaces = %d\n",item,count);    
	//}

switch (item)
	{
    case IFNUMBER: 
	asnresult = asnUnsl (asnClassUniversal, (AsnTagType) 2, 3);
	break;
    default:
	break;
	}
#if 0
  switch (item)
	{
    case IFINDEX: 
	asnresult = asnUnsl (asnClassUniversal, (AsnTagType) 2, interface);
	break;
    case IFDESCR: 
	asnresult = asnUnsl (asnClassUniversal, (AsnTagType) 4, 0);
	break;
    case IFTYPE: 
	asnresult = asnUnsl (asnClassUniversal, (AsnTagType) 2, ifnet.if_type);
	break;
    case IFMTU: 
	asnresult = asnUnsl (asnClassUniversal, (AsnTagType) 2, ifnet.if_mtu);
	break;
    case IFSPEED: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 2, ifnet.if_speed);
	break;
    case IFPHYSADDRESS: 
	asnresult = asnUnsl (asnClassUniversal, (AsnTagType) 4, 0 );
	break;
    case IFADMINSTATUS: 
	    asnresult = asnUnsl (asnClassUniversal, (AsnTagType) 2,ifnet.if_flags & IFF_RUNNING ? 1 : 2 );
	break;
    case IFOPERSTATUS: 
	    asnresult = asnUnsl (asnClassUniversal, (AsnTagType) 2, ifnet.if_flags & IFF_UP ? 1 : 2);
	break;
    case IFLASTCHANGE: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 3,0);
	break;
    case IFINOCTETS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,ifnet.if_ibytes);
	break;
    case IFINUCASTPKTS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,ifnet.if_ipackets);
	break;
    case IFINNUCASTPKTS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,0);
	break;
     case IFINDISCARDS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,0);
	break;
    case IFINERRORS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,ifnet.if_ierrors);
	break;
    case IFINUNKNOWNPROTOS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,0);
	break;
    case IFOUTOCTETS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,ifnet.if_obytes);
	break;
    case IFOUTUCASTPKTS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,ifnet.if_opackets);
	break;
    case IFOUTNUCASTPKTS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,0);
	break;
    case IFOUTDISCARDS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,0);
	break;
    case IFOUTERRORS: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 1,ifnet.if_oerrors);
	break;
    case IFOUTQLEN: 
	asnresult = asnUnsl (asnClassApplication, (AsnTagType) 2,0);
	break;
    case IFSPECIFIC: 
	  asnresult = asnUnsl (asnClassUniversal, (AsnTagType) 6,0);
	break;
   default:
	break;
	}
#endif		
return (asnresult);
}

static	MixStatusType	ifaceRelease (MixCookieType cookie)
{
	cookie = cookie;
	return (smpErrorGeneric);
}

static	MixStatusType	ifaceCreate (MixCookieType cookie, MixNamePtrType name, MixLengthType namelen, AsnIdType asn)
{
	//printf("ifaceCreate ()\n");    
	cookie = cookie;
	name = name;
	namelen = namelen;
	asn = asn;
	return (smpErrorGeneric);
}

static	MixStatusType	ifaceDestroy (MixCookieType cookie, MixNamePtrType name, MixLengthType namelen)
{
	//printf("ifaceDestroy ()\n");    
	cookie = cookie;
	name = name;
	namelen = namelen;
	return (smpErrorGeneric);
}

static	AsnIdType	ifaceGet (MixCookieType cookie, MixNamePtrType name, MixLengthType namelen)
{
	CIntfType		item;
	//printf("ifaceGet ()\n");    

	cookie = cookie;
	if ((namelen != (MixLengthType) 2) ||
		((item = (CIntfType) *name) < (CIntfType) 1) ||
		(item > (CIntfType) (IFACE_MAXTYPE+1)) || (*(name + 1) != (MixNameType) 0)) {
		return ((AsnIdType) 0);
	}
	else {
		return (ifaceRetrieve (item));
	}
}

static	MixStatusType	ifaceSet (MixCookieType cookie, MixNamePtrType name, MixLengthType namelen, AsnIdType asn)
{
	//printf("ifaceSet ()\n");    
	cookie = cookie;
	name = name;
	namelen = namelen;
	asn = asn;
	return (smpErrorReadOnly);
}

static	AsnIdType	ifaceNext (MixCookieType cookie, MixNamePtrType name, MixLengthPtrType namelenp)
{
	CIntfType		item;
	//printf("ifaceNext ()\n");    

	cookie = cookie;
	if (*namelenp == (MixLengthType) 0) {
		*namelenp = (MixLengthType) 2;
		*name++ = (MixNameType) 1;
		*name = (MixNameType) 0;
		return (ifaceRetrieve ((CIntfType) 1));
	}
	else if (*namelenp == (MixLengthType) 1) {
		if ((item = (CIntfType) *name) <= (CIntfType) (IFACE_MAXTYPE)) {
			*namelenp = (MixLengthType) 2;
			*(++name) = (MixNameType) 0;
			return (ifaceRetrieve (item));
		}
		else {
			return ((AsnIdType) 0);
		}
	}
	else if ((item = (CIntfType) *name) < (CIntfType) (IFACE_MAXTYPE)) {
		*namelenp = (MixLengthType) 2;
		*name++ = (MixNameType) (++item);
		*name = (MixNameType) 0;
		return (ifaceRetrieve (item));
	}
	else {
		return ((AsnIdType) 0);
	}
}

static	MixOpsType	ifaceOps = {

			ifaceRelease,
			ifaceCreate,
			ifaceDestroy,
			ifaceNext,
			ifaceGet,
			ifaceSet

			};

CVoidType		ifaceInit (void)
{
unsigned long result;
int ifacecount;
 FILE *in;
struct mib_ifEntry ifacestat;

  char line [1024];
 

for(ifacecount = 1;ifacecount <= IFACE_MAXTYPE;ifacecount++)
		{	
	//printf("ifacInit ()ifacecount=%d\n",ifacecount);    
 switch (ifacecount)
	{
    case IFNUMBER: 
	result=3;
	break;
    default:
	break;
	}
	ifaceAddr = (CUnslType) result;
		(void) misExport ((MixNamePtrType) "\53\6\1\2\1\2",
			(MixLengthType) 8, & ifaceOps, (MixCookieType) 0);
}
#if 0
for(ifacecount = 1;ifacecount <= IFACE_MAXTYPE21;ifacecount++)
		{	
 switch (ifacecount){
    case IFINDEX: 
	result=0;
	break;
    case IFDESCR: 
	result=0;
	break;
    case IFTYPE: 
	result=0;
	break;
    case IFMTU: 
	result=0;
	break;
    case IFSPEED: 
	result=0;
	break;
    case IFPHYSADDRESS: 
	result=0;
	break;
    case IFADMINSTATUS: 
	result=0;
	break;
    case IFOPERSTATUS: 
	result=0;
	break;
    case IFLASTCHANGE: 
	result=0;
	break;
    case IFINOCTETS: 
	result=0;
	break;
    case IFINUCASTPKTS: 
	result=0;
	break;
    case IFINNUCASTPKTS: 
	result=0;
	break;
    case IFINDISCARDS: 
	result=0;
	break;
    case IFINERRORS: 
	result=0;
	break;
    case IFINUNKNOWNPROTOS: 
	result=0;
	break;
    case IFOUTOCTETS: 
	result=0;
	break;
    case IFOUTUCASTPKTS: 
	result=0;
	break;
    case IFOUTNUCASTPKTS: 
	result=0;
	break;
    case IFOUTDISCARDS: 
	result=0;
	break;
    case IFOUTERRORS: 
	result=0;
	break;
    case IFOUTQLEN: 
	result=0;
	break;
    case IFSPECIFIC: 
	result=0;
	break;
    default:
	break;
	}		
	
	ifaceAddr = (CUnslType) result;
		(void) misExport ((MixNamePtrType) "\53\6\1\2\1\2\2\1",
			(MixLengthType) 8, & ifaceOps, (MixCookieType) 0);
	}
#endif

}

