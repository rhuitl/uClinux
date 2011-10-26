/*
 * $Id: gost_t.h,v 1.1.1.1 2002/03/28 00:03:01 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This file contains declarations of GOST seed/pattern storage areas.
 *
 */

#ifndef GOST_T_INCLUDED
#define GOST_T_INCLUDED

/* Data structures */

extern unsigned char FARDATA seed[8][16];
extern unsigned char FARDATA pattern[4][256];

#endif
