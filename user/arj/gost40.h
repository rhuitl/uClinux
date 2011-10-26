/*
 * $Id: gost40.h,v 1.1.1.1 2002/03/28 00:03:01 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in GOST40.C are declared here.
 *
 *
 */

#ifndef GOST40_INCLUDED
#define GOST40_INCLUDED

/* Prototypes */

void gost40_init(unsigned char modifier);
void gost40_encode_stub(char *data, int len);
void gost40_decode_stub(char *data, int len);

#endif

