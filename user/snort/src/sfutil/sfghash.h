/*
*
*  sfghash.h
*
*  generic hash table - stores and maps key + data pairs
*
*  Copyright (C) 2001 Marc A Norton
*
*/

#ifndef _SFGHASH_
#define _SFGHASH_

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sfhashfcn.h"

/*
*   ERROR DEFINES
*/
#define SFGHASH_NOMEM    -2
#define SFGHASH_ERR      -1
#define SFGHASH_OK        0
#define SFGHASH_INTABLE   1

/* 
*  Flags for ghash_new: userkeys 
*/
#define GH_COPYKEYS 0
#define GH_USERKEYS 1

/*
*   Generic HASH NODE
*/
typedef struct _sfghash_node
{
  struct _sfghash_node * next, * prev;

  void * key;   /* Copy of, or Pointer to, the Users key */
  void * data;  /* Pointer to the users data, this is never copied! */
     
} SFGHASH_NODE;

/*
*    Generic HASH table
*/
typedef struct _sfghash
{
  SFHASHFCN    * sfhashfcn;
  int          keysize;   /* bytes in key, if < 0 -> keys are strings */
  int          userkey;   /* user owns the key */

  SFGHASH_NODE ** table;  /* array of node ptr's */
  int             nrows;  /* # rows int the hash table use a prime number 211, 9871 */

  unsigned       count;  /* total # nodes in table */

  void         (*userfree)( void * );  

  int            crow;    // findfirst/next row in table
  SFGHASH_NODE * cnode; // findfirst/next node ptr

  int splay;

} SFGHASH, SFDICT;


/*
*   HASH PROTOTYPES
*/
SFGHASH * sfghash_new( int nrows, int keysize, int userkeys, void (*userfree)(void*p) );
void      sfghash_delete( SFGHASH * h );
int       sfghash_add ( SFGHASH * h, void * key, void * data );
int       sfghash_remove( SFGHASH * h, void * key);
int       sfghash_count( SFGHASH * h);
void    * sfghash_find( SFGHASH * h, void * key );
SFGHASH_NODE * sfghash_findfirst( SFGHASH * h );
SFGHASH_NODE * sfghash_findnext ( SFGHASH * h );

/*
*  ATOM PROTOTYPES  - A Global Hash of String+Data Pointers
*  this could be generalized to do a Global ptr to ptr map as well....
*  
*/
int    sfatom_setsize( int n );
int    sfatom_init();
int    sfatom_reset();
int    sfatom_add(char * str, void * data);
int    sfatom_remove(char * str);
int    sfatom_count();
void * sfatom_find(char * str);
SFGHASH_NODE * sfatom_findfirst();
SFGHASH_NODE * sfatom_findnext();

#endif

