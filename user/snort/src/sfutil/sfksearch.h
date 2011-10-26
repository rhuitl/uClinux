/*
*   ksearch.h
*
*   Trie based multi-pattern matcher
*
*
*  Copyright (C) 2001 Marc Norton
** Copyright (C) 2003 Sourcefire, Inc
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifndef KTRIE_H
#define KTRIE_H

#define ALPHABET_SIZE 256

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WIN32
#define inline __inline
#endif

/*
*
*/
typedef struct _ktriepattern {

  struct  _ktriepattern * next;  /* global list of all patterns */
  struct  _ktriepattern * mnext;  /* matching list of duplicate keywords */
  
  unsigned char * P;    /* no case */
  unsigned char * Pcase; /* case sensitive */
  int             n;
  int             nocase;
  void          * id;

} KTRIEPATTERN;


/*
*
*/
typedef struct _ktrienode {

  int     edge; /* character */

  struct  _ktrienode * sibling; 
  struct  _ktrienode * child; 

  KTRIEPATTERN *pkeyword; 

} KTRIENODE;



/*
*
*/
typedef struct {

  KTRIEPATTERN * patrn; /* List of patterns, built as they are added */

  
  KTRIENODE    * root[256];  /* KTrie nodes */
 
  int            memory;
  int            nchars;
  int            npats;
  int 		 duplicates;

  int            bcSize;
  unsigned short bcShift[256];  
 
} KTRIE_STRUCT;



KTRIE_STRUCT * KTrieNew();
int            KTrieAddPattern( KTRIE_STRUCT *ts, unsigned char * P, int n, int nocase,void*  id );
int            KTrieCompile(KTRIE_STRUCT * ts);
int            KTrieSearch( KTRIE_STRUCT * ts, unsigned char * T, 
               int n, int (*match)(void* id, int index,void* data),void *data );

#endif
