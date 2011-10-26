/* shs2.c -- NIST proposed Secure Hash Standard
*/
/*
   Written 2 September 1992, Peter C. Gutmann,
   This implementation placed in the public domain.

   Transcribed 2 October 2001, John Coffman.
   Modified for FIPS PUB 180-1 (supercedes FIPS PUB 180)

*/

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>

#include "lilo.h"

#ifdef SHS_PASSWORDS

#include "shs2.h"

#define SHS_DEBUG  0
#define SHS_EXPAND 1

/*  The SHS f() - functions */

#define f1(x,y,z) ((x&y)|(~x&z))
#define f2(x,y,z) (x^y^z)
#define f3(x,y,z) ((x&y)|(x&z)|(y&z))
#define f4(x,y,z) (x^y^z)

/*  The SHS Mysterious Constants */

#define K1 0x5A827999L
#define K2 0x6ED9EBA1L
#define K3 0x8F1BBCDCL
#define K4 0xCA62C1D6L

/*  SHS initial values */

#define h0init 0x67452301L
#define h1init 0xEFCDAB89L
#define h2init 0x98BADCFEL
#define h3init 0x10325476L
#define h4init 0xC3D2E1F0L

/*  32-bit rotate -- uses shift kludge */

#define ROT(n,X) ((X<<n)|(X>>(32-n)))



/*  The initial expanding function */

#if SHS_EXPAND
#define expand(count) temp=W[count-3]^W[count-8]^W[count-14]^W[count-16], W[count]=ROT(1,temp)
#define w(t) W[t]
#else
#define w(t) (t<16?W[t]:(temp=W[(t+13)&15]^W[(t+8)&15]^W[(t+2)&15]^W[t&15],\
W[t&15]=ROT(1,temp)))
#endif

/*  The four SHS sub-rounds  */
#define subRound1(count) \
   temp = f1(B,C,D) + K1 + E + w(count) + ROT(5,A),\
   E = D,\
   D = C,\
   C = ROT(30,B),\
   B = A,\
   A = temp

#define subRound2(count) \
   temp = f2(B,C,D) + K2 + E + w(count) + ROT(5,A),\
   E = D,\
   D = C,\
   C = ROT(30,B),\
   B = A,\
   A = temp

#define subRound3(count) \
   temp = f3(B,C,D) + K3 + E + w(count) + ROT(5,A),\
   E = D,\
   D = C,\
   C = ROT(30,B),\
   B = A,\
   A = temp

#define subRound4(count) \
   temp = f4(B,C,D) + K4 + E + w(count) + ROT(5,A),\
   E = D,\
   D = C,\
   C = ROT(30,B),\
   B = A,\
   A = temp


SHS_INFO shsInfo;    /* global */
static
#if SHS_EXPAND
   LONG W[80];
#else
   LONG W[16];
#endif


/*  initialize the SHS values  */
void shsInit(void)
{
   shsInfo.digest[0] = h0init;
   shsInfo.digest[1] = h1init;
   shsInfo.digest[2] = h2init;
   shsInfo.digest[3] = h3init;
   shsInfo.digest[4] = h4init;

   shsInfo.countLo = shsInfo.countHi = 0L;
}


/*  perform the SHS transformation  */

static void shsTransform(void)
{
   int i;
   LONG A, B, C, D, E, temp;

/*  Step A.  Copy the data buffer into the work buffer */
/*  done  */
#if SHS_DEBUG>=1
   for (i=0; i<16; i++)  printf("W[%d] = %08lX\n", i, W[i]);
#endif

/*  Step B.  Expand the 16 words into 64 temporary data words */
#if SHS_EXPAND
   for (i=16; i<80; i++)  expand(i);
#endif

/*  Step C.  Set up first buffer */
   A = shsInfo.digest[0];
   B = shsInfo.digest[1];
   C = shsInfo.digest[2];
   D = shsInfo.digest[3];
   E = shsInfo.digest[4];

/*  Step D.  Serious mangling, divided into 4 sub-rounds */
   i = 0;
   for (; i<20; i++)  subRound1(i);
   for (; i<40; i++)  subRound2(i);
   for (; i<60; i++)  subRound3(i);
   for (; i<80; i++)  subRound4(i);

/*  Step E.  Build message digest */
   shsInfo.digest[0] += A;
   shsInfo.digest[1] += B;
   shsInfo.digest[2] += C;
   shsInfo.digest[3] += D;
   shsInfo.digest[4] += E;

}

#ifdef LITTLE_ENDIAN
static void byteReverse(LONG buffer[], int byteCount)
{
   int count;
   LONG value;

   byteCount /= sizeof(LONG);
   for (count=0; count<byteCount; count++) {
      value = (buffer[count]<<16) | (buffer[count]>>16);
      buffer[count] = ((value&0xff00ff00L)>>8)|((value&0x00ff00ffL)<<8);
   }
}
#endif


/*  Update SHS for a block of data */

void shsUpdate(BYTE *buffer, int count)
{
   int remain;

/* calculate index of space remaining in the work buffer */
   remain = shsInfo.countLo & (SHS_BLOCKSIZE-1);

/* update bitcount */
   if ( (shsInfo.countLo + (LONG)count) < shsInfo.countLo )
      shsInfo.countHi++;     /* carry into high bitcount */
   shsInfo.countLo += (LONG)count;

/* Process data in SHS_BLOCKSIZE chunks */
   while (count >= SHS_BLOCKSIZE-remain) {
      memcpy((BYTE*)&W+remain, buffer, SHS_BLOCKSIZE-remain);
#ifdef LITTLE_ENDIAN
      byteReverse(W, SHS_BLOCKSIZE);
#endif
      shsTransform();
      buffer += SHS_BLOCKSIZE-remain;
      count -= SHS_BLOCKSIZE-remain;
      remain = 0;
   }

/* Handle any remaining bytes of data */
   if (count) memcpy((BYTE*)&W+remain, buffer, count);
}


/*  Finalize the SHS function */
void shsFinal(void)
{
   int count;

/* Compute number of bytes mod 64 */
   count = shsInfo.countLo & (SHS_BLOCKSIZE-1);

/* Set the first char of padding to 0x80.  This is safe since there is
      always at least one byte free */
   ((BYTE*)W)[count++] = 0x80;

/* Pad out to 56 mod 64 */
   if (count > 56) {
      memset((BYTE*)W + count, 0, SHS_BLOCKSIZE-count);
#ifdef LITTLE_ENDIAN
      byteReverse(W, SHS_BLOCKSIZE);
#endif
      shsTransform ();

/* Now fill the next block with 56 bytes */
      memset( W, 0, SHS_BLOCKSIZE-8);
   }
   else { /* Pad block to 56 bytes */
      memset((BYTE*)W + count, 0, (SHS_BLOCKSIZE-8)-count);
   }
#ifdef LITTLE_ENDIAN
   byteReverse(W, SHS_BLOCKSIZE-8);
#endif
/* Append length in bits and transform */
   W[14] = (shsInfo.countHi<<3) + (shsInfo.countLo>>29);
   W[15] = shsInfo.countLo<<3;

   shsTransform ();
}
#endif	/* SHS_PASSWORDS */
/* end shs2.c */

