/*
	sfhashfcn.h
*/
#ifndef SFHASHFCN_INCLUDE 
#define SFHASHFCN_INCLUDE 

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>


typedef struct _SFHASHFCN {

 unsigned seed;
 unsigned scale;
 unsigned hardener;
 unsigned (*hash_fcn)(struct _SFHASHFCN * p,
                      unsigned char *d,
                      int n );
 int      (*keycmp_fcn)( const void *s1,
                         const void *s2,
                         size_t n);
} SFHASHFCN;

SFHASHFCN * sfhashfcn_new( int nrows );
void sfhashfcn_free( SFHASHFCN * p );
unsigned sfhashfcn_hash( SFHASHFCN * p, unsigned char *d, int n );

int sfhashfcn_set_keyops( SFHASHFCN * p,
                          unsigned (*hash_fcn)( SFHASHFCN * p,
                                                unsigned char *d,
                                                int n),
                          int (*keycmp_fcn)( const void *s1,
                                             const void *s2,
                                             size_t n));



#endif
