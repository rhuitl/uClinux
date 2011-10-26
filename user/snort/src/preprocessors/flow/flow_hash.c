/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "flow_hash.h"
/**
 * @file   flow_hash.c
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Thu Jun 19 11:42:49 2003
 * 
 * @brief  hash function for FLOW keys
 * 
 * We can save a bit of work in the hash stage by having a hash
 * function that understands FLOWS better than hash(sizeof(FLOWKEY))
 */


/** 
 * hash function that implements sfhashfcn for only the portions
 * a Flowkey that are relevant
 * 
 * @param p 
 * @param d 
 * @param n 
 * 
 * @return the hash
 */
unsigned flowkey_hashfcn1( SFHASHFCN * p, unsigned char * d, int n)
{
    unsigned hash = p->seed;
    FLOWKEY *keyp = (FLOWKEY *) d;

    hash *= p->scale;
    hash += ((char *) &keyp->init_address)[0];
    hash *= p->scale;    
    hash += ((char *) &keyp->init_address)[1];
    hash *= p->scale;    
    hash += ((char *) &keyp->init_address)[2];
    hash *= p->scale;    
    hash += ((char *) &keyp->init_address)[3];

    hash *= p->scale;    
    hash += ((char *) &keyp->init_port)[0];    
    hash *= p->scale;    
    hash += ((char *) &keyp->init_port)[1];

    hash *= p->scale;
    hash += ((char *) &keyp->resp_address)[0];
    hash *= p->scale; 
    hash += ((char *) &keyp->resp_address)[1];
    hash *= p->scale;    
    hash += ((char *) &keyp->resp_address)[2];
    hash *= p->scale;    
    hash += ((char *) &keyp->resp_address)[3];

    hash *= p->scale;    
    hash += ((char *) &keyp->resp_port)[0];    
    hash *= p->scale;    
    hash += ((char *) &keyp->resp_port)[1];

    hash *= p->scale;
    hash += keyp->protocol;

    return hash ^ p->hardener;
}

/** 

* One that performs less calculations because it doesn't treat each
* byte of the entity as unique. This is probably less resistant to
* collisions but the hardener stages should be randomly chosen so that
* complexity attacks shouldn't succeed without a lot of prior knowledge
 * 
 * @param p 
 * @param d 
 * @param n 
 * 
 * @return the hash
 */
unsigned flowkey_hashfcn2( SFHASHFCN * p, unsigned char * d, int n)
{
    unsigned hash = p->seed;
    FLOWKEY *keyp = (FLOWKEY *) d;

    hash *= p->scale;
    hash += keyp->init_address;

    hash *= p->scale;    
    hash += keyp->init_port;
    
    hash *= p->scale;    
    hash += keyp->resp_address;

    hash *= p->scale;    
    hash += keyp->resp_port;
    
    hash *= p->scale;
    hash += keyp->protocol;

    return hash ^ p->hardener;
}
