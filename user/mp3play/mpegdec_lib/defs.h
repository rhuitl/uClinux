/*------------------------------------------------------------------------------

    File    :   Defs.h

    Author  :   Stéphane TAVENARD

    (C) Copyright 1997-1997 Stéphane TAVENARD
        All Rights Reserved

    #Rev|   Date   |                      Comment
    ----|----------|--------------------------------------------------------
    0   |19/02/1997| Initial revision                                     ST
    1   |02/05/1998| Adapted to PPC                                       ST

    ------------------------------------------------------------------------

    Global definitions

------------------------------------------------------------------------------*/

#ifndef DEFS_H
#define DEFS_H

#ifdef PPC // #1
#include <exec/memory.h>
#include <dos/dos.h>
#define _NO_BOOL
#endif

#ifdef AMIGA
# include <dos/dos.h>
# ifndef ASM
#  ifdef _DCC
#   define REG(x) __ ## x
#   define ASM
#   define SAVEDS __geta4
#  else
#   define REG(x) register __ ## x
#   ifdef __MAXON__
#    define ASM
#    define SAVEDS
#   else
#    define ASM    __asm
#    define SAVEDS __saveds
#   endif
#  endif
# endif
#else
# ifndef _NO_BOOL
   typedef short BOOL;
# endif
# ifdef __GNUC__
#  define ASM
#  define SAVEDS
#  define REG(x)
# endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

typedef char  INT8;
typedef short INT16;
typedef long  INT32;
typedef unsigned char  UINT8;
typedef unsigned short UINT16;
typedef unsigned long  UINT32;

/*** Not sure that float is faster than double on ppc .... ***/
/*** And float seem to be buggy ... ***/

#ifdef PPC // #1 Begin
typedef double REAL;
#else
typedef float REAL;
#endif // #1 End


#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifdef LATTICE
#define FAR __far
#else
#define FAR
#endif

#ifdef PPC
#include <exec/types.h>
#include <exec/nodes.h>
#include <exec/lists.h>
#include <exec/memory.h>
#include <utility/tagitem.h>
#include <powerup/ppclib/interface.h>
#include <powerup/ppclib/message.h>
#include <powerup/ppclib/memory.h>
#include <powerup/ppclib/tasks.h>
#include <powerup/gcclib/powerup_protos.h>

#define malloc( s )  PPCAllocVec( s, MEMF_PUBLIC )
#define free( m )    PPCFreeVec( m )

#define memset( buf, c, n ) { register char *p = (char *)buf; register int i = n; while( i-- ) *p++ = c; }

//#define DEBUG

#ifdef DEBUG
extern BPTR  MyFile;
#define DP( m ) if( MyFile ) PPCWrite( MyFile, m, strlen( m ) )
void print_int( char *fmt, int value );
#define DPI( f, v ) print_int( f, v )
#else
#define DP( m )
#define DPI( f, v )
#endif

#endif

#endif /* DEFS_H */
