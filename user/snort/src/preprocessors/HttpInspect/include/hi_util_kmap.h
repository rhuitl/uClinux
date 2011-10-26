/*
*   kmap.h
*
*   Keyword Trie based Map Table
*
*   Copyright(C) 2002 Marc A Norton
*
*/

#ifndef KTRIE_H
#define KTRIE_H

#define ALPHABET_SIZE 256


#ifdef WIN32

#ifndef inline 
#define inline __inline
#endif

#else

#define inline

#endif

/*
*
*/
typedef struct _keynode {

  struct  _keynode * next;

  unsigned char * key;
  int             nkey;
  void          * userdata;  /* data associated with this pattern */
  
} KEYNODE;

/*
*
*/
typedef struct _kmapnode {

  int      nodechar;  /* node character */

  struct  _kmapnode * sibling; 
  struct  _kmapnode * child; 

  KEYNODE * knode;

} KMAPNODE;

/*
*
*/
typedef struct _kmap {

  KMAPNODE * root[256];  /* KTrie nodes */

  KEYNODE  * keylist; // list of key+data pairs
  KEYNODE  * keynext; // findfirst/findnext node

  void      (*userfree)(void*p);  // fcn to free user data
 
  int        nchars; // # character nodes

  int        nocase;

} KMAP;

/*
*  PROTOTYPES
*/
KMAP * KMapNew ( void (*userfree)(void*p) );
void   KMapSetNoCase( KMAP * km, int flag );
int    KMapAdd ( KMAP * km, void * key, int ksize, void * userdata );
void * KMapFind( KMAP * km, void * key, int ksize );
void * KMapFindFirst( KMAP * km );
void * KMapFindNext ( KMAP * km );
KEYNODE * KMapFindFirstKey( KMAP * km );
KEYNODE * KMapFindNextKey ( KMAP * km );
void KMapDelete(KMAP *km);

#endif


