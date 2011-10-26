/*
** bnfa_search.h  
**
** Basic NFA based multi-pattern search using Aho_corasick construction,
** and compacted sparse storage.
**
** Version 3.0
**
** author: marc norton
** date:   12/21/05
** Copyright (C) 2005-2006 Sourcefire, Inc.
**
** LICENSE (GPL)
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version   of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 0 111-1307, USA.
**
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef BNFA_SEARCH_H
#define BNFA_SEARCH_H

/* debugging - allow printing the trie and nfa in list format */
/* #define ALLOW_LIST_PRINT */

/* debugging - enable full format */
/* #define ALLOW_NFA_FULL */


#ifdef WIN32

#ifdef inline
#undef inline
#endif

#define inline __inline

#else

/* for unix systems */
//#define UINT64 unsigned long long int

#endif

/*
*   DEFINES and Typedef's
*/
//#define SPARSE_FULL_STATE_0
#define BNFA_MAX_ALPHABET_SIZE          256     
#define BNFA_FAIL_STATE                 0xffffffff
#define BNFA_SPARSE_LINEAR_SEARCH_LIMIT 6

#define BNFA_SPARSE_MAX_STATE           0x00ffffff
#define BNFA_SPARSE_COUNT_SHIFT         24
#define BNFA_SPARSE_VALUE_SHIFT         24

#define BNFA_SPARSE_MATCH_BIT           0x80000000
#define BNFA_SPARSE_FULL_BIT            0x40000000
#define BNFA_SPARSE_COUNT_BITS          0x3f000000
#define BNFA_SPARSE_MAX_ROW_TRANSITIONS 0x3f

typedef  unsigned int   bnfa_state_t;


/*
*   Internal Pattern Representation
*/
typedef struct bnfa_pattern 
{      
    struct bnfa_pattern * next;

    unsigned char       * casepatrn; /* case specific */
    int                   n;         /* pattern len */ 
    int                   nocase;    /* nocase flag */
    void                * userdata;  /* ptr to users pattern data/info  */

} bnfa_pattern_t;

/*
*  List format transition node
*/
typedef struct bnfa_trans_node_s 
{
  bnfa_state_t               key;           
  bnfa_state_t               next_state;    
  struct bnfa_trans_node_s * next; 

} bnfa_trans_node_t;

/*
*  List format patterns 
*/
typedef struct bnfa_match_node_s 
{
  void                     * data;
  struct bnfa_match_node_s * next; 

} bnfa_match_node_t;


/*
*  Final storage type for the state transitions
*/
enum {
  BNFA_FULL,
  BNFA_SPARSE,
};

/*
*   Aho-Corasick State Machine Struct 
*/
typedef struct {
	int                bnfaFormat;
	int                bnfaAlphabetSize;

	unsigned           bnfaPatternCnt;
	bnfa_pattern_t     * bnfaPatterns;

	int                bnfaMaxStates;
	int                bnfaNumStates;
	int		           bnfaNumTrans;
	int                bnfaMatchStates;

	bnfa_trans_node_t  ** bnfaTransTable;

	bnfa_state_t       ** bnfaNextState;
	bnfa_match_node_t  ** bnfaMatchList;
	bnfa_state_t       * bnfaFailState;

	bnfa_state_t       * bnfaTransList;
   	int                bnfaForceFullZeroState;

	int 			   bnfa_memory;
	int 			   pat_memory;
	int 			   list_memory;
	int 			   queue_memory;
	int 			   nextstate_memory;
	int 			   failstate_memory;
	int 			   matchlist_memory;

}bnfa_struct_t;

/*
*   Prototypes
*/
bnfa_struct_t * bnfaNew ( void );
void			bnfaFree( bnfa_struct_t  * pstruct );

int bnfaAddPattern( bnfa_struct_t * pstruct, 
					unsigned char * pat, int patlen, int nocase, 
					void * userdata);

int bnfaCompile( bnfa_struct_t * pstruct );

unsigned bnfaSearch( bnfa_struct_t * pstruct, unsigned char * t, int tlen, 
					int (*match)( void * ptr, int index, void * sdata ),
					void * sdata,
					unsigned sindex );

void bnfaPrint(	bnfa_struct_t * pstruct); /* prints the nfa states-verbose!! */
void bnfaPrintInfo( bnfa_struct_t  * pstruct); /* print info on this search engine */

/* 
 * Summary - this tracks search engine information accross multiple instances of
 * search engines.  It helps in snort where we have many search engines, each using
 * rule grouping, to track total patterns, states, memory, etc...
 *
 */
void bnfaAccumInfo( bnfa_struct_t  * pstruct); /* add info to summary over multiple search engines */
void bnfaPrintSummary(); /* print current summary */
void bnfaInitSummary();  /* reset accumulator foir global summary over multiple engines */
#endif
