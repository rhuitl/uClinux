/*
 * $Id: gost_asm.h,v 1.1.1.1 2002/03/28 00:03:01 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Interface to the assembly module, GOST_ASM.ASM
 *
 */

#ifndef GOST_ASM_INCLUDED
#define GOST_ASM_INCLUDED

/* Prototypes */

unsigned long gost_term_32(unsigned long *src, unsigned long *dest, unsigned long *key);

#endif

