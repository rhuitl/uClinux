/*
 * $Id: crc32.h,v 1.1.1.1 2002/03/28 00:02:10 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Interface to the CRC32 module.
 *
 */

#ifndef CRC32_INCLUDED
#define CRC32_INCLUDED

/* The following are externals exported from assembly-language routines: */

extern unsigned long crc32term;
#ifdef TILED
 extern unsigned short crc32tab_lo[256];
 extern unsigned short crc32tab_hi[256];
#else
 extern unsigned long crc32tab[256];
#endif

/* Platform-independent CRC macro */

#ifdef TILED
 #define get_crc32tab(i) ((((unsigned long)crc32tab_hi[i])<<16L)+(unsigned long)crc32tab_lo[i])
#else
 #define get_crc32tab(i) crc32tab[i]
#endif

/* Prototypes */

void build_crc32_table();
void crc32_for_block(char *block, unsigned int size);
void crc32_for_string(char *str);
unsigned long crc32_for_char(unsigned long crc32_term, unsigned char c);
unsigned long rev_crc32_for_char(unsigned long crc32_term, unsigned char c);
unsigned long afl_mul(unsigned long term, unsigned long multiplier);

#endif
