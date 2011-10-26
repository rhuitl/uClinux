/* shs2.h -- NIST secure hash standard */
/*
   Written 2 September 1992, Peter C. Gutmann,
   This implementation placed in the public domain.

   Transcribed 2 October 2001, John Coffman.

*/

#ifndef _SHS2_H
#define _SHS2_H

/*  Useful typedef's & defines */

typedef unsigned char BYTE;
typedef unsigned int  LONG;

/*  The SHS block size and message digest sizes, in bytes */

#define SHS_BLOCKSIZE      64
#define SHS_DIGESTSIZE     20

/*  The structure for storing SHS information */

typedef struct {
   LONG digest[5];         /* message digest */
   LONG countLo, countHi;  /* 64-bit bitcount */
   } SHS_INFO;

extern SHS_INFO shsInfo;

/*  Whether the machine is little-endian */

#ifdef BIG_ENDIAN
#undef BIG_ENDIAN
#endif
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN
#endif

void shsInit(void);
void shsUpdate(BYTE *buffer, int count);
void shsFinal(void);

#endif
/* end shs.h */

