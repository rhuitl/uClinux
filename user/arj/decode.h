/*
 * $Id: decode.h,v 1.1.1.1 2002/03/28 00:02:16 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in DECODE.C are declared here.
 *
 */

#ifndef DECODE_INCLUDED
#define DECODE_INCLUDED

/* Prototypes */

void fillbuf(int n);
void decode(int action);
void decode_f(int action);

#endif

