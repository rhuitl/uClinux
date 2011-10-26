/*
** $Id$
**
**  mpse.h       
**
** Copyright (C) 2002 Sourcefire,Inc
** Marc Norton <mnorton@sourcefire.com>
**
** Multi-Pattern Search Engine
**
**  Supports:
**
**    Modified Wu-Manber mwm.c/.h
**    Aho-Corasick - Deterministic Finite Automatum   
**    Keyword Trie with Boyer Moore Bad Character Shifts
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU Gener*
**
**
** Updates:
**
** man - 7/25/2002 - modified #defines for WIN32, and added uint64
**
*/

#ifndef _MPSE_H
#define _MPSE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "bitop.h"

/*
*   Move these defines to a generic Win32/Unix compatability file, 
*   there must be one somewhere...
*/
#ifndef CDECL 
#define CDECL 
#endif

#ifndef INLINE
#define INLINE inline
#endif

#ifndef UINT64
#define UINT64 unsigned long long
#endif


/*
*  Pattern Matching Methods 
*/
//#define MPSE_MWM      1
#define MPSE_AC       2
//#define MPSE_KTBM     3
#define MPSE_LOWMEM   4    
//#define MPSE_AUTO     5
#define MPSE_ACF      6 
#define MPSE_ACS      7 
#define MPSE_ACB      8 
#define MPSE_ACSB     9 
#define MPSE_AC_BNFA   10 

/*
** PROTOTYPES
*/
void * mpseNew( int method );
void   mpseFree( void * pv );

int  mpseAddPattern  ( void * pv, void * P, int m, 
     unsigned noCase,unsigned offset, unsigned depth,  void* ID, int IID );

int  mpsePrepPatterns  ( void * pv );

void mpseSetRuleMask   ( void *pv, BITOP * rm );

int  mpseSearch( void *pv, unsigned char * T, int n, 
     int ( *action )(void* id, int index, void *data), 
     void * data ); 

UINT64 mpseGetPatByteCount();
void   mpseResetByteCount();

int mpsePrintInfo( void * obj );
int mpsePrintSummary( );

#endif

