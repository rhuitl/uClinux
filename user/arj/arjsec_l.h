/*
 * $Id: arjsec_l.h,v 1.1.1.1 2002/03/28 00:01:19 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in ARJSEC_L.C are declared here.
 *
 */

#ifndef ARJSEC_L_INCLUDED
#define ARJSEC_L_INCLUDED

/* Prototypes */

int create_envelope(FILE *stream, unsigned long offset, int iter);

void arjsec_term(unsigned long *block, unsigned long *dest, int iter);
void arjsec_xor(unsigned long *dest, unsigned long *src);
void arjsec_newblock(unsigned long *dest);
void arjsec_invert(unsigned long *block);
void arjsec_crcterm(unsigned long *block, unsigned char c);
void arjsec_read(unsigned long *block, FILE *stream, unsigned long len);

void rev_arjsec_term(unsigned long *block, unsigned long *dest, int iter);
void arjsec_revert(unsigned long *block);

#endif

