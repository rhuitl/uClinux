#ifndef _FLOW_HASH_H
#define _FLOW_HASH_H

#include "sfhashfcn.h"
#include "flow.h"

/**
 * @file   flow_hash.h
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Thu Jun 19 11:42:49 2003
 * 
 * @brief  hash function for FLOW keys
 * 
 * We can save a bit of work in the hash stage by having a hash
 * function that understands FLOWS better than hash(sizeof(FLOWKEY))
 */

unsigned flowkey_hashfcn1( SFHASHFCN * p, unsigned char * d, int n);
unsigned flowkey_hashfcn2( SFHASHFCN * p, unsigned char * d, int n);

#endif /* _FLOW_HASH_H */
