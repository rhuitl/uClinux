/*
 * $Id: gost.h,v 1.1.1.1 2002/03/28 00:02:55 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Prototypes of the functions and declarations of  data structures located in
 * GOST.C are stored here.
 *
 */

#ifndef GOST_INCLUDED
#define GOST_INCLUDED

/* Encryption-related constants */

#define GSH_BITS                  11    /* Used in bit shifts */
#define KEYGEN_ITERATIONS       2048    /* Number of key generation cycles */

/* Predefined patterns */

#define GOST_I_PAT_LO     0x01010101
#define GOST_I_PAT_HI     0x01010104

/* Prototypes */

void calc_gost_pattern();
unsigned long gost_term(unsigned long data);

#endif

