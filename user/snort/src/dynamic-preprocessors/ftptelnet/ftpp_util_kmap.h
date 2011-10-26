/*
 *   kmap.h
 *
 *   Keyword Trie based Map Table
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) 2005 Sourcefire Inc.
 *
 * Author: Marc A Norton
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


