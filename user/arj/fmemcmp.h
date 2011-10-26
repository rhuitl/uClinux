/*
 * $Id: fmemcmp.h,v 1.1.1.1 2002/03/28 00:02:55 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in FMEMCMP.ASM are declared here.
 *
 */

#ifndef FMEMCMP_INCLUDED
#define FMEMCMP_INCLUDED

/* Prototypes */

int far_memcmp(char FAR *str1, char FAR *str2, int len);

#endif

