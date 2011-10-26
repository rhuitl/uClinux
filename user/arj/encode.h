/*
 * $Id: encode.h,v 1.1.1.1 2002/03/28 00:02:24 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in ENCODE.C are declared here.
 *
 */

#ifndef ENCODE_INCLUDED
#define ENCODE_INCLUDED

/* Prototypes */

void encode(int method);
void encode_f();

/* Forwarded from this module or ENC_ASM.ASM */

void putbits(int n, unsigned short x);

#endif

