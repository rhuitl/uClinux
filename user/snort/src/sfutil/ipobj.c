/*

	ipobj.c

	IP address encapsulation interface

	This module provides encapsulation of single IP ADDRESSes as
	objects, and collections of IP ADDRESSes as objects


*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <ctype.h>

#include "ipobj.h"
#include "util.h"


/*
	UITLITY SUPPORT
*/
int  ip_familysize( int family )  /* Use with stack allocated structures */
{
    if( family == IPV4_FAMILY ) return IPV4_LEN;
    if( family == IPV6_FAMILY ) return IPV6_LEN;
    return 0;
}

int ip4_sprintx( char * s, int slen, void * ip4 )
{
     int  rc;
     unsigned char * ip = (unsigned char *) ip4;

     rc = SnortSnprintf(s, slen, "%d.%d.%d.%d", ip[3], ip[2], ip[1], ip[0]);

     if( rc != SNORT_SNPRINTF_SUCCESS )
         return -1;

     return 0;
}
int ip6_sprintx( char * s, int slen, void * ip6 )
{
     int  rc;
     unsigned short * ps = (unsigned short*) ip6;

     rc = SnortSnprintf(s, slen, "%.1x:%.1x:%.1x:%.1x:%.1x:%.1x:%.1x:%.1x",
                        ps[7], ps[6], ps[5], ps[4], ps[3], ps[2], ps[1], ps[0]);

     if( rc != SNORT_SNPRINTF_SUCCESS )
         return -1;

     return 0;
}


int ip_sprint( char * s, int slen, IPADDRESS * p )
{
     if( p->family == IPV4_FAMILY )
     {
        if( ip4_sprintx( s, slen, p->ip ) )
            return -1;  

	return 0;
     }     
     else if( p->family == IPV6_FAMILY )
     {
        if( ip6_sprintx( s, slen, p->ip ) )
            return -1;  

	return 0;
     }     
     return -1;
}

int ip_fprint( FILE * fp, IPADDRESS * p )
{
     int  stat;
     char s[256];

     stat = ip_sprint( s, sizeof(s), p );

     if( stat )
         return stat;

     fprintf(fp,"%s",s);

     return 0;
}

/*
	INIT FAMILY FOR IP ADDRESS
*/
static 
void ip_init ( IPADDRESS * p , int family )  /* Use with stack allocated structures */
{
   if( p )
   {
       p->family = family;
   }
}

/*
  ALLOCATE/CREATE IP ADDRESS
*/
IPADDRESS * ip_new ( int family )   /* Dynamic allocation */
{
   IPADDRESS * p = NULL;

   if( family == IPV4_FAMILY )
   {
     p = ( IPADDRESS * )malloc( sizeof(IPADDRESS) + IPV4_LEN - 1 );
     ip_init( p, family );
   }
   else if( family == IPV6_FAMILY )
   {
     p = ( IPADDRESS * )malloc( sizeof(IPADDRESS) + IPV6_LEN - 1 );
     ip_init( p, family );
   }
   return p;
}

/*
	FREE IP ADDRESS
*/
void ip_free ( IPADDRESS * p )
{
     if( p )
         free( p );
}
/*
	Get Address Family
*/
int ip_family( IPADDRESS * p )
{
     return p->family;
}

/*
	Get Address size - in bytes
*/
int ip_size( IPADDRESS * p )
{
    return ip_familysize( p->family ) ;
}

/*
	SET IP ADDRESS
*/
int ip_set( IPADDRESS * ia, void * ip, int family )
{
     if( !ia ) return -1;

     if( ia->family != family ) return -1;
           
     if(      family == IPV4_FAMILY ) memcpy(ia->ip,ip,IPV4_LEN);
     else if( family == IPV6_FAMILY ) memcpy(ia->ip,ip,IPV6_LEN);

     return 0;
}


/*
	GET IP ADDRESS
*/
int ip_get( IPADDRESS * ia, void * ip, int family )
{
     if( !ia ) return -1;

     if( ia->family != family )
         return -1;

     if(      family == IPV4_FAMILY ) memcpy(ip,ia->ip,IPV4_LEN);
     else if( family == IPV6_FAMILY ) memcpy(ip,ia->ip,IPV6_LEN);

     return 0;
}


/*
	TEST IP ADDRESS
*/
int ip_equal( IPADDRESS * ia, void * ip, int family )
{
     if( !ia ) return -1;

     if( ia->family != family )
         return 0;

     if( ia->family == IPV4_FAMILY )
     {
         if( memcmp(ip,ia->ip,IPV4_LEN) == 0 ) 
             return 1;
     }
     else if( ia->family == IPV6_FAMILY )
     {
         if( memcmp(ip,ia->ip,IPV6_LEN) == 0 ) 
             return 1;
     }
     return 0;
}

int ip_eq( IPADDRESS * ia, IPADDRESS * ib )
{
     if( !ia ) return -1;
     if( !ib ) return -1;

     if( ia->family != ib->family )
         return 0; /* nope */

     if( ia->family == IPV4_FAMILY )
     {
         if( memcmp(ib->ip,ia->ip,IPV4_LEN) == 0 ) 
             return 1;
     }
     else if( ia->family ==  IPV6_FAMILY )
     {
         if( memcmp(ib->ip,ia->ip,IPV6_LEN) == 0 ) 
             return 1;
     }
     return 0;
}


/*


   IP COLLECTION INTERFACE

   
   Snort Accepts:

	IP-Address		192.168.1.1
	IP-Address/MaskBits	192.168.1.0/24
	IP-Address/Mask		192.168.1.0/255.255.255.0

   
   These can all be handled via the CIDR block notation : IP/MaskBits

   We use collections (lists) of cidr blocks to represent address blocks
   and indivdual addresses.    

   For a single IPAddress the implied Mask is 32 bits,or 255.255.255.255, or 0xffffffff, or -1.

*/

static 
void ipset_init( IPSET * ipc )
{
   if( ipc )
   {
     ipc->family = IPV4_FAMILY;  
     sflist_init( &ipc->cidr_list );
   }
}
static 
void ipset6_init( IPSET * ipc )
{
   if( ipc )
   {
     ipc->family = IPV6_FAMILY;  
     sflist_init( &ipc->cidr_list );
   }
}

IPSET * ipset_new( int family )
{
   IPSET * p = (IPSET *)malloc( sizeof(IPSET));

   if( family == IPV4_FAMILY )
   {
     ipset_init( p );
   }
   else
   {
     ipset6_init( p );
   }
   
   return p;
}

IPSET * ipset_copy( IPSET *ipsp )
{
   int family;
   IPSET * newset = NULL;
   CIDRBLOCK *cbp;
   CIDRBLOCK6 *cbp6;

   if(ipsp)
   {
       family = ipset_family( ipsp );
       newset = ipset_new(family) ;
   
       if( family == IPV4_FAMILY )
       {
           for(cbp =(CIDRBLOCK*)sflist_first( &ipsp->cidr_list );
               cbp !=NULL;
               cbp =(CIDRBLOCK*)sflist_next( &ipsp->cidr_list ) )
           {
               ipset_add(newset, &cbp->ip, &cbp->mask, &cbp->portset, cbp->notflag, family);
           }
           
       }
       else
       {
           for(cbp6 =(CIDRBLOCK6*)sflist_first( &ipsp->cidr_list );
               cbp6 !=NULL;
               cbp6 =(CIDRBLOCK6*)sflist_next( &ipsp->cidr_list ) )
           {
               ipset_add(newset, &cbp6->ip, &cbp6->mask, &cbp6->portset, cbp6->notflag, family);
           }

       }
   }

   return newset;
}


void ipset_free( IPSET * ipc )
{
   if( ipc )
   {
     if( ipc->family == IPV4_FAMILY )
     {
       CIDRBLOCK *p = (CIDRBLOCK *) sflist_first(&ipc->cidr_list);       
       while ( p )
       {
         sflist_free(&p->portset.port_list);
         p = (CIDRBLOCK *) sflist_next(&ipc->cidr_list);
       }
     }
     else if( ipc->family == IPV6_FAMILY )
     {
       CIDRBLOCK6 *p = (CIDRBLOCK6 *) sflist_first(&ipc->cidr_list);       
       while ( p )
       {
         sflist_free(&p->portset.port_list);
         p = (CIDRBLOCK6 *) sflist_next(&ipc->cidr_list);
       }
     }
     sflist_free( &ipc->cidr_list );
     free( ipc );
   }
}
int ipset_family( IPSET * ipset )
{
    return ipset->family;	
}
/* 
	The user must know what kind of address he's adding, 
        and the family of the IPSET
*/
int ipset_add( IPSET * ipc, void * vip, void * vmask, void *vport, int notflag , int family )
{

    if( !ipc ) return -1;

    if( ipc->family != family )
    {
	return -1;
    }

    if( ipc->family == IPV4_FAMILY )
    {
        unsigned * ip=(unsigned*)vip;
        unsigned * mask=(unsigned*)vmask;
        PORTSET  * portset = (PORTSET *) vport;
        CIDRBLOCK *p = (CIDRBLOCK*)malloc( sizeof(CIDRBLOCK) );
        if(!p) return -1;

        p->mask    = *mask;
        p->ip      = *ip & *mask;
        p->portset = *portset;
        p->notflag = notflag;

        if( notflag )sflist_add_head( &ipc->cidr_list, p ); // test NOT items 1st
        else         sflist_add_tail( &ipc->cidr_list, p );
    }
    else if( ipc->family == IPV6_FAMILY )
    {
        int i;
        unsigned short * ips = (unsigned short *)vip;
        PORTSET  * portset = (PORTSET *) vport;
        CIDRBLOCK6 *p6 = (CIDRBLOCK6*)malloc( sizeof(CIDRBLOCK6) );
        if(!p6) return -1;
            
        memcpy(p6->mask,vmask,IPV6_LEN);

        for(i=0;i<8;i++)
        {
            p6->ip[i] = (unsigned short)(ips[i] & p6->mask[i]);
        }

        p6->portset = *portset;
        p6->notflag = notflag;

        if( notflag ) sflist_add_head( &ipc->cidr_list, p6 ); // always test NOT items 1st
        else          sflist_add_tail( &ipc->cidr_list, p6 );
    }
    else return -1;

    return 0;
}

int ipset_contains( IPSET * ipc, void * ip, void *port, int family )
{
    PORTRANGE *pr;
    unsigned short portu;
        
    if( !ipc ) return 0;

    if( ipc->family != family )
    {
	return 0;
    }

    if ( port )
        portu = *((unsigned short *)port);
    else
        portu = 0;

    if( ipc->family == IPV4_FAMILY )
    {
        CIDRBLOCK * p;
        unsigned  * ipu = (unsigned*)ip;
        
        for(p =(CIDRBLOCK*)sflist_first( &ipc->cidr_list ); 
            p!=0;
            p =(CIDRBLOCK*)sflist_next( &ipc->cidr_list ) )
        {
            if( (p->mask & (*ipu)) == p->ip )
            {
                for( pr=(PORTRANGE*)sflist_first(&p->portset.port_list);
                    pr != 0;
                    pr=(PORTRANGE*)sflist_next(&p->portset.port_list) )
                {
                    /* 
                     *  If the matching IP has a wildcard port (pr->port_hi == 0 ) or
                     *  if the ports actually match.
                     */
                    if ( (pr->port_hi == 0)
                        || (portu >= pr->port_lo && portu <= pr->port_hi) )
                    {               
                        if( p->notflag )
                            return 0;
                        return 1;
                    }
                }
            }
        }
    }
    else if( ipc->family == IPV6_FAMILY )
    {
        CIDRBLOCK6     * p;
        unsigned short * ips = (unsigned short *)ip;
        unsigned short   mip[8];


        for(p = (CIDRBLOCK6*)sflist_first( &ipc->cidr_list );
	        p!= 0;
            p = (CIDRBLOCK6*)sflist_next( &ipc->cidr_list ) )
	    {           
               mip[0] = (unsigned short)(p->mask[0] & ips[0]);
               mip[1] = (unsigned short)(p->mask[1] & ips[1]);
               mip[2] = (unsigned short)(p->mask[2] & ips[2]);
               mip[3] = (unsigned short)(p->mask[3] & ips[3]);
               mip[4] = (unsigned short)(p->mask[4] & ips[4]);
               mip[5] = (unsigned short)(p->mask[5] & ips[5]);
               mip[6] = (unsigned short)(p->mask[6] & ips[6]);
               mip[7] = (unsigned short)(p->mask[7] & ips[7]);

            if( memcmp(mip,p->ip,IPV6_LEN) == 0 )
            {
                for( pr=(PORTRANGE*)sflist_first(&p->portset.port_list);
                    pr != 0;
                    pr=(PORTRANGE*)sflist_next(&p->portset.port_list) )
                {
                    /* 
                     * If the caller wants to match any port (portu == 0) or
                     *  if the matching IP has a wildcard port (pr->port_hi == 0 ) or
                     *  if the ports actually match.
                     */
                    if ( portu == 0 || pr->port_hi == 0
                        || (portu >= pr->port_lo && portu <= pr->port_hi) )
                    {               
                        if( p->notflag )
                            return 0;
                        return 1;
                    }
                }
            }
	    }
    }
    else
        return -1;

    return 0;
}


int ipset_print( IPSET * ipc )
{
    char ip_str[80], mask_str[80];
    PORTRANGE * pr;

    if( !ipc ) return 0;

    if( ipc->family == IPV4_FAMILY )
    {
        CIDRBLOCK * p;

        printf("IPSET-IPV4\n");

        for( p =(CIDRBLOCK*)sflist_first( &ipc->cidr_list );
	         p!=0;
             p =(CIDRBLOCK*)sflist_next( &ipc->cidr_list ) )
	    {
           ip4_sprintx(ip_str,  80, &p->ip);
           ip4_sprintx(mask_str,80, &p->mask);

           if( p->notflag )
   	           printf("CIDR BLOCK: !%s / %s", ip_str,mask_str);
	       else
   	           printf("CIDR BLOCK: %s / %s",  ip_str,mask_str);
           for( pr=(PORTRANGE*)sflist_first(&p->portset.port_list);
                pr != 0;
                pr=(PORTRANGE*)sflist_next(&p->portset.port_list) )
           {
                printf(" : %d", pr->port_lo);
                if ( pr->port_hi != pr->port_lo )
                    printf("-%d", pr->port_hi);
           }
           printf("\n");
	    }
    }
    else if( ipc->family == IPV6_FAMILY )
    {
        CIDRBLOCK6 * p;

        printf("IPSET-IPV6\n");

        for(p =(CIDRBLOCK6*)sflist_first( &ipc->cidr_list );
	        p!=0; p =(CIDRBLOCK6*)sflist_next( &ipc->cidr_list ) )
	    {
           ip6_sprintx(ip_str,  80,p->ip);
           ip6_sprintx(mask_str,80,p->mask);

           if( p->notflag )
   	           printf("CIDR BLOCK: !%s / %s", ip_str,mask_str);
	       else
   	           printf("CIDR BLOCK: %s / %s",  ip_str,mask_str); 
           for( pr=(PORTRANGE*)sflist_first(&p->portset.port_list);
                pr != 0;
                pr=(PORTRANGE*)sflist_next(&p->portset.port_list) )
           {
                printf(" : %d", pr->port_lo);
                if ( pr->port_hi != pr->port_lo )
                    printf("-%d", pr->port_hi);
           }
           printf("\n");
	    }
    }
    else return -1;


    return 0;
}


static 
void portset_init( PORTSET * portset )
{ 
    sflist_init(&portset->port_list);
}

static int portset_add(PORTSET * portset, unsigned port_lo, unsigned port_hi)
{
    PORTRANGE *p;

    if( !portset ) return -1;

    p = (PORTRANGE *) malloc( sizeof(PORTRANGE) );
    if(!p) return -1;

    p->port_lo = port_lo;
    p->port_hi = port_hi;
    
    sflist_add_tail(&portset->port_list, p );

    return 0;
}

/* parsing functions to help make life a bit easier */

/*
   Port string can be:
   25
   25 26
   25-28
   25 28-29
   25,26 27 30-35

   portset is a list of port ranges.  A port range can be a single port (25-25).
   */
static int port_parse(char *portstr, PORTSET *portset)
{
    unsigned port_lo = 0, port_hi = 0;
    char *p;
    char *pc;
    char *phi;
    
    p = portstr;

    /* Get first range in list */
    pc = strstr(portstr, " ");
    if ( !pc )
        pc = strstr(portstr, "\t");
    if ( pc ) 
        *pc = '\0';
    while ( p && *p )
    {
        while ( isspace(*p) )
            p++;

        if ( *p == 0 )
            break;

        /* Get high port */
        phi = strstr(p, "-");
        
        if ( phi )
        {
            *phi++ = '\0';
            port_lo = atoi(p);
            port_hi = atoi(phi);
        }
        else
        {
            port_hi = port_lo = atoi(p);            
        }

        portset_add(portset, port_lo, port_hi);

        if ( !pc )
        {
            p = NULL;
        }
        else
        {
            p = pc + 1;
            pc = strstr(p, " ");
            if ( !pc )
                pc = strstr(p, "\t");
        }
    }

    return 0;
}

/** 
 * Break an IP4 Address down into its components 
 * 
 * @param ipstr string to parse
 * @param use network order for return values (defaults to host order)
 * @param not_flag return value if the ip is negated
 * @param host ipv4 host argument
 * @param mask ipv4 mask argument
 * 
 * @return 0 on sucess, else failure parsing the address
 * @retval -3 \0 encountered prematurely
 * @retval -2 strdup failed
 * @retval -1 null argument
 * @retval -4 out of range for CIDR notation
 */

static int ip4_parse(char *ipstr, int network_order, int *not_flag, unsigned *host,
                                                unsigned *mask, PORTSET *portset)
{
    char *saved, *s_copy, *maskptr, *endp, *portptr = NULL;
    struct in_addr addrstuff;
    
    if(!ipstr || !not_flag || !host || !mask) 
        return -1;


    if(*ipstr == '\0')
        return -3;

    saved = s_copy = strdup(ipstr);
    
    if(!s_copy)
    {
        return -2;
    }
    else
    {
        while(isspace((int)*s_copy))
            s_copy++;

        if(*s_copy == '\0')
        {
            free(saved);
            return -3;
        }

        if(*s_copy == '!')
        {
            *not_flag = 1;
            s_copy++;

            if(*s_copy == '\0')
            {
                free(saved);
                return -3;
            }
        }
        else
        {
            *not_flag = 0;
        }
        
        if( (endp = strstr(s_copy, "]")) ) 
        {
            /* Removing trailing ']' */
            *endp = 0;
        }
        if( (endp = strstr(s_copy, ",")) ) 
        {
            /* Removing trailing ',' */
            *endp = 0;
        }

        portptr = strstr(s_copy, ":");

        maskptr = strstr(s_copy, "/");

      
        if(!maskptr)
        {
            /* assume this is a host */
            *mask = 0xFFFFFFFF;
        }
        else
        {
            *maskptr = '\0';
            maskptr++;
        }

        if(!portptr)
        {
            /* no port */
        }
        else
        {
            *portptr = '\0';
            portptr++;
        }

        if(!strncmp(s_copy, "0", 1) || !strncmp(s_copy, "0.0.0.0", 7))
        {
            *host = 0;
        }
        else if((addrstuff.s_addr = inet_addr(s_copy)) == -1)
        {
            if(!strncmp(s_copy, "255.255.255.255", 15))
            {
                addrstuff.s_addr = INADDR_BROADCAST;
            }
            else
            {
                /* invalid ip address! */
                free(saved);
                return -3;
            }
        }
        else
        {
            *host = ntohl(addrstuff.s_addr);
        }            
        
        if(maskptr)
        {
            if(*maskptr == '\0')
            {
                /* Nothing beyond the / -- no bits in CIDR */
                free(saved);
                return -3;
            }

            if(strstr(maskptr, "."))
            {
                if(!strncmp(maskptr, "0", 1) || !strncmp(maskptr, "0.0.0.0", 7))
                {
                    *mask = 0;
                }
                else if((addrstuff.s_addr = inet_addr(maskptr)) == -1)
                {
                    if(!strncmp(maskptr, "255.255.255.255", 15))
                    {
                        addrstuff.s_addr = INADDR_BROADCAST;
                    }
                    else
                    {
                        /* invalid ip address! */
                        free(saved);
                        return -3;
                    }
                }
                else
                {
                    memcpy(mask, &addrstuff.s_addr, sizeof(unsigned));
                }           
            }
            else
            {
                int blocksize = atoi(maskptr);
                int i;

                if(blocksize == 0)
                {
                    *mask = 0;
                }
                else if(blocksize < 1 || blocksize > 32)
                {
                    free(saved);
                    return -4;
                }
                else
                {
                    *mask = 0;
                    for(i=0;i<blocksize;i++)
                    {
                        (*mask) |= (1 << 31) >> i;
                    }
                }
            }
        }
        if(portptr)
        {            
            port_parse(portptr, portset);
        }
        else
        {
            /* Make sure we have at least one port range in list, but an invalid port range */
            portset_add(portset, 0, 0);
        }
    }

    /* convert the arguments by default */
    if(network_order)
    {
        *mask = htonl(*mask);
        *host = htonl(*host);	
    }
    
    free(saved);
    return 0;
}

int ip4_setparse(IPSET *ipset, char *ipstr) 
{
    char *s_copy, *startIP, *endIP;
    int parse_count = 0;
    int set_not_flag = 0;
    int item_not_flag;
    unsigned host, mask;
    PORTSET portset;

    s_copy = strdup(ipstr);

    if(!s_copy)
        return -2;

    if (*s_copy == '!')
    {
        set_not_flag = 1;
        s_copy++;
    }

    startIP = s_copy;

    while (startIP)
    {
        while (isspace((int)*startIP) || (*startIP == '[') ) 
        {
            startIP++;
        }
    
        if ((*startIP == ']') || (*startIP == '\0'))
            break;

        endIP = startIP;

        /* The following two loops and conditional address bug 30042 */
        /* Traverse the IP */
        while(isdigit((int)*endIP) || (*endIP == '.') || (*endIP == '/'))
        {
            endIP++;
        }
        
        /* Skip any whitespace after the IP or CIDR block */
        while(isspace((int)*endIP) || (*endIP == '[') || (*endIP == ']')) 
        {
            endIP++;
        }

        if(*endIP != ',' && *endIP)
        {
             FatalError("ip4_setparse: only commas are allowed as "
                         "delimiters in the IP list: %s\n", ipstr);
        }
        
        portset_init(&portset);

        if(ip4_parse(startIP, 0, &item_not_flag, &host, &mask, &portset) != 0)
        {
            free(s_copy);
            return -5;
        }

        if(ipset_add(ipset, &host, &mask, &portset,
                     (item_not_flag ^ set_not_flag), IPV4_FAMILY) != 0)
        {
            free(s_copy);
            return -6;
        }

        parse_count++;
    
        if(*endIP) 
        {
            endIP++;
        }
        
        startIP = endIP;
    }

    free(s_copy);

    if (!parse_count)
        return -7; 

    return 0;
}

#ifdef MAIN_IP

#include <time.h>

#ifndef WIN32
#define rand   random
#define srand srandom
#endif

#define MAXIP 100     

#include "sflsq.c"

void test_ip4_parsing(void)
{
    unsigned host, mask, not_flag;
    PORTSET  portset;
    char **curip;
    int ret;
    IPADDRESS *adp;                
    char *ips[] = { "138.26.1.24:25",
                    "1.1.1.1/255.255.255.0:444",
                    "1.1.1.1/16:25-28",
                    "1.1.1.1/255.255.255.255:25 27-29",
                    "z/24",
                    "0/0",
                    "0.0.0.0/0.0.0.0:25-26 28-29 31",
                    "0.0.0.0/0.0.2.0",
                    NULL };

    for(curip = ips; curip[0] != NULL; curip++)
    {
        
        portset_init(&portset);

        /* network byte order stuff */
        if((ret = ip4_parse(curip[0], 1, &not_flag, &host, &mask, &portset)) != 0)
        {
            fprintf(stderr, "Unable to parse %s with ret %d\n", curip[0], ret);
        }
        else
        {            
            printf("%c", not_flag ? '!' : ' ');            
            printf("%s/", inet_ntoa(*(struct in_addr *) &host));
            printf("%s", inet_ntoa(*(struct in_addr *) &mask));
            printf(" parsed successfully!\n");
        }

        /* host byte order stuff */
        if((ret = ip4_parse(curip[0], 0, &not_flag, &host, &mask, &portset)) != 0)
        {
            fprintf(stderr, "Unable to parse %s with ret %d\n", curip[0], ret);
        }
        else
        {
            adp = ip_new(IPV4_FAMILY);
            ip_set(adp, &host, IPV4_FAMILY);
            ip_fprint(stdout, adp);
            fprintf(stdout, "*****************\n");
            ip_free(adp);            
        }
    }

    return;
}


void test_ip4set_parsing(void)
{
    char **curip;
    int ret;
    char *ips[] = { "12.24.24.1/32,!24.24.24.1",
                    "[0.0.0.0/0.0.2.0,241.242.241.22]",
                    "138.26.1.24",
                    "1.1.1.1",
                    "1.1.1.1/16",
                    "1.1.1.1/255.255.255.255",
                    "z/24",
                    "0/0",
                    "0.0.0.0/0.0.0.0",
                    "0.0.0.0/0.0.2.0",                    
                    NULL };

    for(curip = ips; curip[0] != NULL; curip++)
    {
        IPSET *ipset = ipset_new(IPV4_FAMILY);
        
        /* network byte order stuff */
        if((ret = ip4_setparse(ipset, curip[0])) != 0)
        {
            ipset_free(ipset);
            fprintf(stderr, "Unable to parse %s with ret %d\n", curip[0], ret);
        }
        else
        {
            printf("-[%s]\n ", curip[0]);
            ipset_print(ipset);
            printf("---------------------\n ");
        }
    }

    return;
}

//  -----------------------------
void test_ip()
{
     int            i,k;
     IPADDRESS    * ipa[MAXIP];
     unsigned       ipaddress,ipx;
     unsigned short ipaddress6[8], ipx6[8];

     printf("IPADDRESS testing\n");

     srand( time(0) );

     for(i=0;i<MAXIP;i++)
     {
         if( i % 2 )
         {
             ipa[i]= ip_new(IPV4_FAMILY);
             ipaddress = rand() * rand();
             ip_set( ipa[i], &ipaddress, IPV4_FAMILY  );

             if( !ip_equal(ipa[i],&ipaddress, IPV4_FAMILY ) )
                 printf("error with ip_equal\n");

             ip_get( ipa[i], &ipx, IPV4_FAMILY );
               if( ipx != ipaddress )
                 printf("error with ip_get\n");

         }
         else
         {
             ipa[i]= ip_new(IPV6_FAMILY);

             for(k=0;k<8;k++) ipaddress6[k] = (char) (rand() % (1<<16)); 

             ip_set( ipa[i], ipaddress6, IPV6_FAMILY  );

             if( !ip_equal(ipa[i],&ipaddress6, IPV6_FAMILY ) )
                 printf("error with ip6_equal\n");

             ip_get( ipa[i], ipx6, IPV6_FAMILY  );

             for(k=0;k<8;k++)
               if( ipx6[k] != ipaddress6[k] )
                  printf("error with ip6_get\n");

         }

         printf("[%d] ",i);
         ip_fprint(stdout,ipa[i]);
         printf("\n");
     }

     printf("IP testing completed\n");
}



//  -----------------------------
void test_ipset()
{
     int      i,k;
     IPSET  * ipset, * ipset6;
     IPSET  * ipset_copyp, * ipset6_copyp;
     
     unsigned ipaddress, mask;
     unsigned short mask6[8];
     unsigned short ipaddress6[8];
     unsigned port_lo, port_hi;
     PORTSET        portset;

     printf("IPSET testing\n");

     ipset  = ipset_new(IPV4_FAMILY);
     ipset6 = ipset_new(IPV6_FAMILY);
     
     srand( time(0) );

     for(i=0;i<MAXIP;i++)
     {
         if( i % 2 )
         {
             ipaddress = rand() * rand();
             mask = 0xffffff00;
             port_lo = rand();
             port_hi = rand() % 5 + port_lo;
             portset_init(&portset);
             portset_add(&portset, port_lo, port_hi);

             ipset_add( ipset, &ipaddress, &mask, &portset, 0, IPV4_FAMILY ); //class C cidr blocks

             if( !ipset_contains( ipset, &ipaddress, &port_lo, IPV4_FAMILY ) )
                 printf("error with ipset_contains\n");
         }
         else
         {
             for(k=0;k<8;k++) ipaddress6[k] = (char) (rand() % (1<<16)); 

             for(k=0;k<8;k++) mask6[k] = 0xffff;

             port_lo = rand();
             port_hi = rand() % 5 + port_lo;
             portset_init(&portset);
             portset_add(&portset, port_lo, port_hi);

             ipset_add( ipset6, ipaddress6, mask6, &portset, 0, IPV6_FAMILY );

             if( !ipset_contains( ipset6, &ipaddress6, &port_lo, IPV6_FAMILY ) )
                 printf("error with ipset6_contains\n");
         }

     }

     ipset_copyp = ipset_copy( ipset );
     ipset6_copyp = ipset_copy( ipset6 );
     

     printf("-----IP SET-----\n");
     ipset_print( ipset );
     printf("\n");

     printf("-----IP SET6-----\n");
     ipset_print( ipset6 );
     printf("\n");

     printf("-----IP SET COPY -----\n");
     ipset_print( ipset_copyp );
     printf("\n");

     printf("-----IP SET6 COPY -----\n");
     ipset_print( ipset6_copyp );
     printf("\n");

     printf("IP set testing completed\n");
}


//  -----------------------------
int main( int argc, char ** argv )
{
  printf("ipobj \n");
  
  test_ip();

  test_ipset();

  test_ip4_parsing();

  test_ip4set_parsing();

  printf("normal pgm completion\n");

  return 0;
}

#endif

