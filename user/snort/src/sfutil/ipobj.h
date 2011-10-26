/*

	ipobj.h

	IP address encapsulation interface

	This module provides encapsulation of single IP ADDRESSes as objects,
	and collections of IP ADDRESSes as objects

        Interaction with this library should be done in HOST byte order.

*/
#ifndef IPOBJ_SNORT
#define IPOBJ_SNORT

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sflsq.h"

#ifdef WIN32
#define snprintf _snprintf
#endif


enum {
  NOFAMILY,
  IPV4_FAMILY,
  IPV6_FAMILY,
};

enum {
  IPV4_LEN=4,
  IPV6_LEN=16,
};

typedef struct {

  int family;
  unsigned char ip[IPV6_LEN];

}IPADDRESS ;


typedef struct {

  int family;
  unsigned char ip[IPV4_LEN];

}IPADDRESS4 ;

typedef struct {

  int family;
  unsigned char ip[IPV6_LEN];

}IPADDRESS6 ;

typedef struct {
   unsigned port_lo;
   unsigned port_hi;
}PORTRANGE;

typedef struct {
   SF_LIST port_list;
}PORTSET;

typedef struct {
   unsigned mask;
   unsigned ip;
   PORTSET  portset;
   int      notflag;
}CIDRBLOCK;

typedef struct {
   unsigned short mask[8];
   unsigned short ip[8];
   PORTSET        portset;
   int            notflag;
}CIDRBLOCK6;

typedef struct {

  int       family;
  SF_LIST   cidr_list;

}IPSET;

/*

	IP ADDRESS OBJECT
	
	This interface is meant to hide the differences between ipv4
	and ipv6.  The assumption is that when we get a raw address we
	can stuff it into a generic IPADDRESS.  When we need to test
	an IPADDRESS against a raw address we know the family opf the
	raw address.  It's either ipv4 or ipv6.

*/
int ip_familysize( int family );

int ip4_sprintx( char * s, int slen, void * ip4 );
int ip6_sprintx( char * s, int slen, void * ip6 );


IPADDRESS * ip_new   ( int family );
void        ip_free  ( IPADDRESS * p );
int         ip_family( IPADDRESS * p );
int         ip_size  ( IPADDRESS * p );
int         ip_set   ( IPADDRESS * ia, void * ip, int family );
int         ip_get   ( IPADDRESS * ia, void * ip, int family );
int         ip_equal ( IPADDRESS * ia, void * ip, int family );
int         ip_eq    ( IPADDRESS * ia, IPADDRESS * ib );
int         ip_sprint( char * s, int slen, IPADDRESS * p );
int         ip_fprint( FILE * fp, IPADDRESS * p );



/*

  IP ADDRESS SET OBJECTS

   
   Snort Accepts:

	IP-Address		192.168.1.1
	IP-Address/MaskBits	192.168.1.0/24
	IP-Address/Mask		192.168.1.0/255.255.255.0

   
   These can all be handled via the CIDR block notation : IP/MaskBits

   We use collections (lists) of cidr blocks to represent address blocks
   and indivdual addresses.    

   For a single IPAddress the implied Mask is 32 bits,or
   255.255.255.255, or 0xffffffff, or -1.
*/
IPSET * ipset_new     ( int family );
IPSET * ipset_copy    ( IPSET * ipset );
int     ipset_family  ( IPSET * ipset );
void    ipset_free    ( IPSET * ipset );
int     ipset_add     ( IPSET * ipset, void * ip, void * mask, void * port, int notflag, int family );
int     ipset_contains( IPSET * ipset, void * ip, void * port, int family );
int     ipset_print   ( IPSET * ipset );


/* helper functions -- all the sets work in host order   
*/
int      ip4_setparse(IPSET * ipset, char *ipstr);

#endif
