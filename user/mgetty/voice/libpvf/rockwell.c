/*
 *
 * rockwell.c
 *
 * Conversion subroutines for:
 *
 *  signed linear 16 bit audio words  <-->  Rockwell 2, 3, or 4 bit ADPCM
 *
 * -----------------------------------------------------------------------
 *
 * Floating point version by
 *  Torsten Duwe <duwe@informatik.uni-erlangen.de>
 *
 * very remotely derived from Rockwell's d.asm.
 * Converted to C and simplified by Torsten Duwe 1995
 *
 * -----------------------------------------------------------------------
 *
 * Floating point version was removed on Fri Jan 17 13:23:42 1997
 *
 * -----------------------------------------------------------------------
 *
 * Fixed point version
 *  by Peter Jaeckel <atmpj@ermine.ox.ac.uk> [1996-1997].
 *
 *
 *    Marc Eberhard dubbed this file the "Rocky Horror Picture Show".
 *    And he is right.
 *                      PJ, Tue Jan 14 17:04:13 1997
 *
 *
 * The fixed point version is a complete rewrite, I reused only some
 * tiny fragments of the floating point code.
 *
 * The fixed point version actually manages to get output that is
 * identical to that of the DOS executables distributed by Rockwell. It
 * is noticeably better than that of the floating point version.
 * Rockwell uses all sorts of dirty tricks in their fixed point code
 * which I don't necessarily understand as I am not an expert on
 * compression formats. Read the comments throughout the code for
 * further explanation.
 *
 * Technical Note : The compressor does not do any silence deletion
 * which is exactly what the Rockwell sources do as well. The
 * decompressor detects silence codewords and inserts the required
 * silence period if RV_HONOUR_SILENCE_CODEWORDS is defined. Otherwise,
 * the silence codeword and the following integer word determining the
 * length of the silence are just gobbled up as compressed data and may
 * lead to some temporarily increased noise level after that.
 *
 * The Rockwell sources were taken from http://www.nb.rockwell.com/ref/adpcm.html .
 *
 * Peter Jaeckel, Fri Jan 17 14:40:32 1997
 *
 * -----------------------------------------------------------------------
 *
 * $Id: rockwell.c,v 1.6 1999/03/16 09:59:20 marcs Exp $
 *
 */

#define RV_HONOUR_SILENCE_CODEWORDS

#include "../include/voice.h"

/*
   PJ:
   A first attempt to implement basically all that the original
   Rockwell D.ASM code does in C. I never had to deal with assembler
   before, so be lenient when you judge me, please...

   NB: The guts of this code are not very pretty to look at.

   RV_ stands for Rockwell Voice.

 */

#define RV_PNT98 32113        /* 0.98 */
#define RV_PNT012 393         /* 0.012 */
#define RV_PNT006 197         /* 0.006 */
#define RV_QDLMN 0x1F         /* QDLMN = IQDLMN = 2.87 mV. */
#define RV_DEMPCF 0x3333 /* 0.4 */
#define RV_PDEMPCF 0x3333     /* 0.4 */
#define RV_QORDER 8      /*  Total delay line length for the pole and zero delay lines */

/*
   Design Notes: Relation of QDataIndex to position in QData Buffer.
   the rotation is done by the QDataIndex.  This variable always
   points to the data to be multiplied by the coefficient a1.  The
   coefficients, a1..a2 and b1..b6, stay in the same relative
   position in the coefficient array. Updates to these values are
   done in place.  Illustration belows shows the value of QDataIndex
   and the Delay Line data in relation to the coefficient array.

   Position
   in Qdata  Start   2nd     3rd     4th
   -----------------------------------------
   0 a1      Y(n-1)  Y(n-2)  Q(n-1)  Q(n-2)
   1 a2      Y(n-2)  Q(n-1)  Q(n-2)  Q(n-3)
   2 b1      Q(n-1)  Q(n-2)  Q(n-3)  Q(n-4)
   3 b2      Q(n-2)  Q(n-3)  Q(n-4)  Q(n-5)
   4 b3      Q(n-3)  Q(n-4)  Q(n-5)  Q(n-6)
   5 b4      Q(n-4)  Q(n-5)  Q(n-6)  Y(n-1)
   6 b5      Q(n-5)  Q(n-6)  Y(n-1)  Y(n-2)
   7 b6      Q(n-6)  Y(n-1)  Y(n-2)  Q(n-1)
   -----------------------------------------
   QDataIndex   0       7       6       5
   -----------------------------------------
 */

static vgetty_s_int16 RV_pzTable[8];     /* Coefficient Table for the pole and zero linear predictor. */
                    /*     a1 a2 b1 b2 b3 b4 b5 b6      */
static vgetty_s_int16 RV_QdataIndex = 0; /*  Delay line pointer to the coefficient a1. */
static vgetty_s_int16 RV_Qdata[RV_QORDER];    /*  Delay line. */

#ifdef POSTFILTER        /*        DON'T USE THIS          */
     /*
     The POSTFILTER code is in Rockwell's original D.ASM, too.
     They too, don't use it in their distributed executables
     though. I have no idea under what circumstances it might be
     useful, I just left the code in here as I went through the
     effort of writing it before I realised that it appears to be
     useless here.
     */
static vgetty_s_int16 RV_QPdata[RV_QORDER];
static vgetty_s_int16 RV_QPPdata[RV_QORDER];
#endif

static vgetty_s_int16 RV_LastNu = 0;     /*  Last Nu value. */
static vgetty_s_int16 RV_Dempz = 0; /*  De-emphasis filter delay line (one element). */
static vgetty_s_int16 RV_NewQdata = 0;   /*  Adaptive quantizer output. */
static vgetty_s_int16 RV_NewAppData = 0; /* Temporay data storage */

/* ML2bps, ML3bps, and ML4bps are combined in mul[][], just like Torsten suggested */

static vgetty_s_int16 RV_mul[3][16] =
{              /*  Multiplier table to calculate new Nu for 2/3/4 BPS. */
  {0x3333, 0x199A, 0x199A, 0x3333},
  {0x3800, 0x2800, 0x1CCD, 0x1CCD, 0x1CCD, 0x1CCD, 0x2800, 0x3800},
  {0x4CCD, 0x4000, 0x3333, 0x2666, 0x1CCD, 0x1CCD, 0x1CCD, 0x1CCD, 0x1CCD, 0x1CCD, 0x1CCD, 0x1CCD, 0x2666, 0x3333, 0x4000, 0x4CCD}
};

/* Zeta2bps, Zeta3bps, and Zeta4bps are combined in Zeta[][],
   just like Torsten suggested */

static vgetty_u_int16 RV_Zeta[3][16] =
{                   /*  Multiplier table for 2/3/4 BPS to calculate inverse */
                    /*  quantizer output.  This number, index by the code */
                    /*  word, times Nu is the inverse quantizer output. */
  {0xCFAE, 0xF183, 0x0E7D, 0x3052},
  {0xBB23, 0xD4FE, 0xE7CF, 0xF828, 0x07D8, 0x1831, 0x2B02, 0x44DD},
  {0xA88B, 0xBDCB, 0xCC29, 0xD7CF, 0xE1D8, 0xEAFB, 0xF395, 0xFBE4, 0x041C, 0x0C6B, 0x1505, 0x1E28, 0x2831, 0x33C7, 0x4235, 0x5775}
};

static vgetty_s_int16 *RV_mul_p;
static vgetty_s_int16 *RV_Zeta_p;
static vgetty_u_int16 RV_silence_words[3] = {0x13ec, 0x23de, 0xc11c};
static vgetty_u_int16 RV_silence_word;

     /* Maximum limit for Nu.  Changes based on 2, 3, or 4 BPS selected.
        Initialization routine updates this value. */
static vgetty_s_int16 RV_QDelayMX = 0;
     /*  Array index by BPS-2 for updating QDelayMX */
static vgetty_s_int16 RV_QDelayTable[3] = {0x54C4,0x3B7A,0x2ED5}; /* 2.01V, 1.41V, 1.11V */

  /*
     Macro definitions used in the decompression, interpolation, and
     compression functions.
   */

static vgetty_s_int32 RV_max_local_int16,RV_min_local_int16;
static vgetty_s_int64 RV_max_local_int32,RV_min_local_int32;

#define RV_clip_16(a) ((a)<RV_min_local_int16?RV_min_local_int16:(a)>RV_max_local_int16?RV_max_local_int16:(a))
#define RV_clip_32(a) ((a)<RV_min_local_int32?RV_min_local_int32:(a)>RV_max_local_int32?RV_max_local_int32:(a))

#define HIWORD(x) (((vgetty_u_int32)x) >> 16)
#define LOWORD(x) ((vgetty_u_int32)(((unsigned int)x) & 0xffff))
#define LOBYTE(x) ((unsigned int)(((unsigned int)x) & 0xff))
#define RV_round_32_into_16(x) (vgetty_s_int16)((((vgetty_u_int32)x)>>16)+((((vgetty_u_int32)x)>>15)&0x0001))

 /* In order to stay as close as possible to the original assembler
    (a kludge, I know), we simulate the system's register(s) below    */

static vgetty_s_int16 RV_di;

  /*  Utilities.
     Routines that both the decompressor and the compressor use. */

  /*
     pzPred
     Linear predictor coefficient update routine.  Local to this module.
     Inputs:
     CX = Q(n), i.e. WORD PTR NewQData
     Output:   DI points to (QDataIndex+7)%8.
   */

static void RV_pzPred(vgetty_s_int16 cx){
/*
   A little explanation is required here. Rockwell uses 16bit
   integers to represent numbers in [-1,1). They take 0x8000 to be -1
   and 0x7fff to be 0.999969482, i.e. the ints -32768 to 32767 are
   normalised over 32768 into the required interval.  The product of
   two such numbers is supposed to be, again, in the range [-1,1).
   I know that this is mathematically incorrect, but that's how they
   do it, just read on.

   The "adjustment" that is mentioned in D.ASM can be understood by
   the following example: Assume you want to multiply -1 with -0.5. In
   integers, that's imul 0x8000, 0xc000 (I know, it does actulally
   require a register), i.e. -32768*-16384. The result is 0x20000000.
   They only want to keep a 16 bit result, thus they need to round.
   First, however, an adjustment for the moved decimal point is
   required. The upper 16 bit of 0x20000000 are 0x2000 which
   corresponds only to 8192/32768=0.25 ! Thus, all the bits need to be
   left shifted by one place and the result will be 0x4000 which
   correctly corresponds to 0.5 now. This confusion is due to the fact
   that the original two numbers in total have two bits representing
   two different signs and the result, which is again represented by a
   total of 32 bits, needs only one sign bit.  Thus, the result in 32
   bits has effectively one more data bit available than the total of
   the two multiplicands. The nature of integer arithmetics feeds that
   bit in from the left behind the sign bit. A consequence of this is
   that the two leftmost bits of the resulting 32 bit integer are
   always equal, apart from one case, namely 0x8000*0x8000, or
   -32768*-32768, which results in 0x40000000. Arithmetically, we
   would expect this to be decimal-point-adjusted to the 16 bit
   representation 0x7fff. The Rockwell assembler code, however, just
   maps this to 0x8000, i.e. -1, by ignoring the special case of
   0x8000*0x8000. This explains the cryptic warnings like

     ; Determine sign of Q(n) * Y(n-1)
     ;
     ; Do not change the sign determination method!

   in D.ASM. Personally, this is the first time ever I have seen
   anyone using arithmetics like -1 * -1 = -1 whilst -1 * -0.99 = 0.99 ;-).

   So, after this type of decimal-point-adjustment they then round off
   the lower 16 bit and just take the upper 16 to be the result.

 */
  static vgetty_s_int32 x,y;        /* local accumulator(s) */
  static vgetty_s_int16 di;
  static int i;

  di = RV_QdataIndex;

  /*  Calculate coefficients a1 a2 b1 b2 b3 b4 b5 b6 . */

  for (i = 0; i < 8; i++)
    {

      x = RV_pzTable[i] * ((vgetty_s_int32) RV_PNT98);
      x <<= 1; /*
             Rockwell-adjust for decimal point shift, then round off
             lower 16 bits to obtain a 16 bit representation of the
             result.
           */
      x = RV_round_32_into_16 (x);
                         /* cx contains the NewQdata=Q(n) */
      y = ((vgetty_s_int32) cx) * ((vgetty_s_int32) RV_Qdata[di]);
      y <<= 1;           /* Rockwell-adjust for decimal point shift. */
      y = RV_round_32_into_16 (y);
      x += (y < 0 ? -1 : 1) * (i < 2 ? RV_PNT012 : RV_PNT006);
      /* i<2 ? The a's get RV_PNT012. All b's get RV_PNT006. */
      /*
         The result of a multiplication needs adjusting & rounding.
         The result of an addition/subtraction needs clipping.
       */
      RV_pzTable[i] = RV_clip_16 (x);
      di++;
      di %= 8;
    }
}

/*

   Taken from D.ASM:

   Design Notes: Sum of Multiplications.

   Multiplications are 16-bit signed numbers producing a signed 32-bit
   result. The two operands are usually numbers less than one; this
   requires a 32-bit shift by the macro "adjust" to bring the decimal
   point in line.  The 32-bit addition is two 16-bit additions with
   carry.  The "clip" macro checks for overflow and limits the result of
   the addition to 0x7fffffff or 0x80000000 (for 32-bit results), or
   0x7fff or 0x8000 (for 16-bit results).  Note that the "clip" macro
   depends on the flags being set because of an addition; the 80x86
   processor does not update these flags because of a move operation.

 */

static vgetty_s_int32 RV_XpzCalc(vgetty_s_int16 cx){
  /*
     Linear pole and zero predictor calculate.  CX,BX register pair is the
     32 bit accumulator.  Local to this module.
     Input:   CX = Initial Value.  BX set to zero.
     Output:   CX,BX contains the result of the sum of products.
     Also, DI points to (QDataIndex+7)%8.
   */
  static vgetty_s_int32 x;          /* local accumulator */
  static vgetty_s_int64 sum;
  int i;

  RV_di = RV_QdataIndex;
  sum = ((vgetty_s_int32) cx) << 16;

  for (i = 0; i < 8; i++)
    {
      x = ((vgetty_s_int32) RV_pzTable[i]) * ((vgetty_s_int32) RV_Qdata[RV_di]);
      x <<= 1;           /* Rockwell-adjust for decimal point shift. */
      sum += x;
      sum = RV_clip_32 (sum);
      RV_di++;
      RV_di %= 8;
    }
  RV_di = (RV_QdataIndex + 7) % 8;
  return (vgetty_s_int32) sum;
}

static void RV_Reset(int bps){
  int i;
  vgetty_u_int16 tmp_int16 = 0;
  vgetty_u_int32 tmp_int32 = 0;

  tmp_int16 = ~tmp_int16;
  tmp_int16 >>= 1;
  RV_max_local_int16 =  tmp_int16;
  RV_min_local_int16 = tmp_int16;
  RV_min_local_int16 = -RV_min_local_int16;
  RV_min_local_int16--;
  tmp_int32 = ~tmp_int32;
  tmp_int32 >>= 1;
  RV_max_local_int32 = tmp_int32;
  RV_min_local_int32 = tmp_int32;
  RV_min_local_int32 = -RV_min_local_int32;
  RV_min_local_int32--;

  RV_QdataIndex = 0;
  for (i = 0; i < RV_QORDER; i++)
    {
      RV_Qdata[i] = 0;
#ifdef POSTFILTER
      RV_QPdata[i] = 0;
      RV_QPPdata[i] = 0;
#endif
    }
  RV_Dempz = 0;
  RV_NewQdata = 0;
  RV_NewAppData = 0;
  RV_LastNu = RV_QDLMN;
  RV_QDelayMX = RV_QDelayTable[bps-2];
  RV_silence_word = RV_silence_words[bps-2];
  RV_mul_p = RV_mul[bps-2];
  RV_Zeta_p = (vgetty_s_int16 *)RV_Zeta[bps-2];
}

#ifdef POSTFILTER

static vgetty_s_int16 RV_P8Table[6] =    /* Adaptive post filter number 1 coefficients */
{0x6666, 0x51eb, 0x4189, 0x346d, 0x29f1, 0x218e};
static vgetty_s_int16 RV_PM5Table[6] =   /* Adaptive post filter number 2 coefficients */
{0xc000, 0xe000, 0xf000, 0xf800, 0xfc00, 0xfe00};

static vgetty_s_int32 RV_App1Calc(vgetty_s_int16 cx){
  /*  Adaptive post filter number 1  */
  /*
     Load pointers to the predictor table and the pointer
     to the coefficient a1.
   */

  static vgetty_s_int32 x;          /* local accumulator */
  static vgetty_s_int64 sum;
  static vgetty_s_int16 di;
  int i;

  di = RV_QdataIndex;
  RV_NewAppData = cx;
  sum = 0;

  for (i = 0; i < 8; i++)
    {
      x = ((vgetty_s_int32) RV_pzTable[i]) * ((vgetty_s_int32) RV_P8Table[i]);
      x <<= 1; /*
             Rockwell-adjust for decimal point shift, then round off
             lower 16 bits to obtain a 16 bit representation of the
             result.
            */
      x = ((vgetty_s_int32)
        (RV_round_32_into_16 (x))) * ((vgetty_s_int32) RV_QPdata[di]);
      x <<= 1;           /* Rockwell-adjust for decimal point shift. */
      sum += x;
      sum = RV_clip_32 (sum);
      di++;
      di %= 8;
    }
  cx = HIWORD(sum);
  di = (RV_QdataIndex + 7) % 8;
  RV_QPdata[di] = cx;         /* drop b6, now a1 Qdata */
  di += 2;
  di %= 8;
  RV_QPdata[di] = RV_NewAppData;   /* drop a2, now b1 Qdata */
  return (vgetty_s_int32) sum;
}

static vgetty_s_int32 RV_App2Calc(vgetty_s_int16 cx){

  /*  Adaptive post filter number 2  */
  /*
     Load pointers to the predictor table and the pointer
     to the coefficient a1.
   */

  static vgetty_s_int32 x;          /* local accumulator */
  static vgetty_s_int64 sum;
  static vgetty_s_int16 di;
  int i;

  di = RV_QdataIndex;
  RV_NewAppData = cx;
  sum = 0;

  for (i = 0; i < 8; i++)
    {
      x = ((vgetty_s_int32) RV_pzTable[i]) * ((vgetty_s_int32) RV_PM5Table[i]);
      x <<= 1; /*
             Rockwell-adjust for decimal point shift, then round off
             lower 16 bits to obtain a 16 bit representation of the
             result.
           */
      x = ((vgetty_s_int32) RV_round_32_into_16 (x)) * ((vgetty_s_int32) RV_QPPdata[di]);
      x <<= 1;           /* Rockwell-adjust for decimal point shift. */
      sum += x;
      sum = RV_clip_32 (sum);
      di++;
      di %= 8;
    }
  cx = HIWORD(sum);
  di = (RV_QdataIndex + 7) % 8;
  RV_QPPdata[di] = cx;   /* drop b6, now a1 Qdata */
  di += 2;
  di %= 8;
  RV_QPPdata[di] = RV_NewAppData;  /* drop a2, now b1 Qdata */
  return (vgetty_s_int32) sum;
}

#endif

static vgetty_s_int16 RV_DecomOne(vgetty_s_int16 ax, vgetty_s_int16 bx){
/*
   RVDecomOne

   Decode a code word.  Local to this module.

   Inputs:
   AX = ML, adaptive multiplier for Nu.
   BX = Zeta, base inverse quantizer value, modified by Nu.
   Also, updates QdataIndex to (QdataIndex+7)%8 .
 */
  static vgetty_s_int16 si;
  static vgetty_s_int32 LastNu_bak;
  static vgetty_s_int32 x;          /* local accumulator */
  static vgetty_s_int64 sum;

  LastNu_bak = RV_LastNu;
  x = ((vgetty_s_int32) ax) * ((vgetty_s_int32) RV_LastNu);
  x <<= 1;               /* Rockwell-adjust for decimal point shift. */
                                        /* Round and Multiply by 4 */
  x = (RV_round_32_into_16 (x) * ((vgetty_s_int32)4));
  RV_LastNu = RV_clip_16 (x);
  if (RV_LastNu < RV_QDLMN)
    RV_LastNu = RV_QDLMN;
  else if (RV_LastNu > RV_QDelayMX)
    RV_LastNu = RV_QDelayMX;

  x = bx * LastNu_bak;   /* Zeta * LastNu */
  x <<= 1;               /* Rockwell-adjust for decimal point shift. */
  x = (RV_round_32_into_16 (x) * ((vgetty_s_int32)4));
  RV_NewQdata = RV_clip_16 (x);
  sum = RV_XpzCalc (RV_NewQdata);  /*  Compute (Xp+z)(n) + Q(n)  */
  si = HIWORD(sum);      /*  Y(n) done, save in SI for later */
#ifdef POSTFILTER
  sum = RV_App1Calc ((vgetty_s_int16)(HIWORD(sum)));
  sum = RV_App2Calc ((vgetty_s_int16)(HIWORD(sum)));
#endif
  /*  Use a de-emphasis filter on Y(n) to remove the effects */
  /*  of the emphasis filter used during compression. */
  x = RV_DEMPCF * RV_Dempz;
  x <<= 1;               /* Rockwell-adjust for decimal point shift. */
  sum += x;
  sum = RV_clip_32 (sum);
  RV_Dempz = HIWORD(sum);
      /*  Update predictor filter coefficients. */
  RV_pzPred (RV_NewQdata);
  RV_Qdata[RV_di] = si;  /*  drop b6, now a1 Qdata */
  /*  Update delay line at the a1(n) table entry position. */
  RV_QdataIndex = RV_di;
  RV_di += 2;
  RV_di %= 8;
  RV_Qdata[RV_di] = RV_NewQdata;   /*  drop a2, now b1 Qdata */
 return RV_Dempz;
}

                 /*          Compression!!         */

/* cd2x, cd3x, and cd4x are combined in cd[][], just like Torsten suggested */

static vgetty_s_int16 RV_cdx[3][16] =
{
  {0x1F69},
  {0x1005, 0x219A, 0x37F0},
  {0x0843, 0x10B8, 0x1996, 0x232B, 0x2DFC, 0x3B02, 0x4CD6}
};
static vgetty_s_int16 RV_cdx_length[3] = { 1,3,7 };
static vgetty_s_int16 *RV_cd;
static vgetty_s_int16 RV_cd_length;

static vgetty_s_int32 RV_ComOne(vgetty_s_int16 ax)
{
/*
   RVComOne

   Code a word into a bps bit codeword.  Local to this module.

   Inputs:
   AX = X(n)

 */
 int i;
 static vgetty_s_int16 adc16z1 = 0; /*         X(n-1)                 */
 static vgetty_s_int16 NewXpz = 0;  /*         Xp+z(n)                */
 static vgetty_s_int16 bx,cx,dx;
 static vgetty_s_int32 x, y;        /* local accumulator */
 static vgetty_s_int64 sum;

 sum = RV_XpzCalc ((vgetty_s_int16)0);   /*  Compute Xp+z(n)  */
 NewXpz = HIWORD(sum);
 x = ((vgetty_s_int32) adc16z1) * RV_PDEMPCF;
 x <<= 1;                  /* Rockwell-adjust for decimal point shift. */
 sum += x;
 sum = RV_clip_32 (sum);
 cx = HIWORD(sum);
               /* Optimise any of this at your own peril ! */
 x = cx;
 x -= ax;
 cx = RV_clip_16 (x);
 bx = cx;
 if (bx<0) bx = -bx;
 cx = -cx;
 adc16z1 = ax;
 y = RV_LastNu;          /*
                    Optimise any of this at your own peril !
                    Ideally, the important variables
                    here should all be declared volatile.
                    If you change any of this, your
                    optimiser might break it !
               */
 for (i=0;i<RV_cd_length;i++){
  x = ((vgetty_s_int32)RV_cd[i]) * y;
  x <<= 1;               /* Rockwell-adjust for decimal point shift. */
                                        /* Round and Multiply by 4 */
  x = (RV_round_32_into_16 (x) * ((vgetty_s_int32)4));
  dx = RV_clip_16 (x);
  if (bx<dx) break;
 }
 i++;
 if (cx<0){
  i -= RV_cd_length;
  i--;
  i = -i;
 } else i+= RV_cd_length;
 ax = i;
 x = ((vgetty_s_int32)RV_mul_p[i]) * y;
 x <<= 1;           /* Rockwell-adjust for decimal point shift. */
                                        /* Round and Multiply by 4 */
 x = (RV_round_32_into_16 (x) * ((vgetty_s_int32)4));
 RV_LastNu = RV_clip_16 (x);
 if (RV_LastNu < RV_QDLMN)
   RV_LastNu = RV_QDLMN;
 else if (RV_LastNu > RV_QDelayMX)
   RV_LastNu = RV_QDelayMX;
 /*            Make a new inverse quantizer value.          */
 x = ((vgetty_s_int32)RV_Zeta_p[i]) * y;
 x <<= 1;           /* Rockwell-adjust for decimal point shift. */
                                        /* Round and Multiply by 4 */
 x = (RV_round_32_into_16 (x) * ((vgetty_s_int32)4));
 cx = RV_clip_16 (x);
               /* Update predictor filter coefficients. */
 RV_pzPred (cx);
               /* Update delay line at the a1(n) table entry position. */
 RV_QdataIndex += 7;
 RV_QdataIndex %= 8;
 x = NewXpz;
 x += cx;
 RV_Qdata[RV_QdataIndex] = RV_clip_16 (x);   /* drop b6, now a1 Qdata. */
 RV_Qdata[(RV_QdataIndex+2)%8] = cx;         /* drop a2, now b1 Qdata. */
 return (vgetty_s_int32) ax;
}

#ifdef RV_HONOUR_SILENCE_CODEWORDS       /* Honour silence codewords and insert the requested silence */

static void put_silence(vgetty_s_int32 num_samples, FILE * out)
{
  /*      Write num_samples 16 bit ints of value 0    */
  num_samples *= 2;

  while (num_samples && (putc (0, out) != EOF))
    num_samples--;

  if (num_samples)
    {
      perror ("write silence");
      exit (1);
    }
}

static int getcodeword(FILE * in, vgetty_s_int32 *codeword){
 /*
    Rockwell modems always pass on 16bit ints in little-endian format.
    Therefore, we have to read the data the same way if we don't want
    to miss a silence codeword.
 */
  static int c;
  if ((c = getc (in)) == EOF) return 0;
  *codeword = c;
  if ((c = getc (in)) == EOF) return 8;
  *codeword |= (c<<8);
  return 16;
}

int rockwelltopvf (FILE *fd_in, FILE *fd_out, int nbits, pvf_header *header_out)
{
 vgetty_s_int32 w;        /* packed compressed codewords */
 int c;                  /* single compressed codeword  */
 vgetty_s_int32 mask=(1<<nbits)-1;    /* bitmask for the decompression */
 vgetty_s_int32 a = 0;         /* local accumulator */
 int valbits = 0;        /* number of bits valid in accumulator */

 /* The pvf header should have been written by now, start with the decompression */

 /* Reset the coefficient table for the pole and zero linear predictor. */
 for (w = 0; w < 8; w++) RV_pzTable[w] = 0;
 RV_Reset (nbits);
 /*
          The algorithm below (copied from Torsten Duwe's code)
          takes care of bit concatenation.
 */
 while ((c=getcodeword(fd_in,&w)))
  /*
      Not using the pvf library generic read_bits interface because
      Rockwell modems always pass on 16bit ints in little-endian format.
      Therefore, we have to read the data the same way if we don't want
      to miss a silence codeword.
  */
    {
      if (w == RV_silence_word)
     {
       getcodeword(fd_in,&w);
       put_silence (w, fd_out);
       RV_Reset (nbits);
       valbits = 0;
       continue;
     }
      a |= w<<valbits;
      valbits += c;
      while (valbits >= nbits)
     {
       c = a & mask;
       w = RV_DecomOne(RV_mul_p[c],RV_Zeta_p[c]);
       w <<= 8; /* The pvf routines expect a 24bit int */
       header_out->write_pvf_data(fd_out, w);
       a >>= nbits;
       valbits -= nbits;
     }
    }

  return(OK);
}

#else    /*  Silence codewords are just gobbled up as data */

int rockwelltopvf (FILE *fd_in, FILE *fd_out, int nbits, pvf_header *header_out)
{
 state_t s = init_state;
 int c;                  /* single compressed codeword or EOF */

 /* The pvf header should have been written by now, start with the decompression */

 /* Reset the coefficient table for the pole and zero linear predictor. */
 for (c = 0; c < 8; c++) RV_pzTable[c] = 0;
 RV_Reset (nbits);

 while ((c = read_bits_reverse(fd_in,&s,nbits)) != EOF)
  header_out->write_pvf_data(fd_out,  /* The pvf routines expect a 24bit int */
                    ((vgetty_s_int32)RV_DecomOne(RV_mul_p[c],RV_Zeta_p[c]))<<8 );

  return(OK);
}

#endif

int pvftorockwell (FILE *fd_in, FILE *fd_out, int nbits, pvf_header *header_in)
{
 state_t s = init_state;
 vgetty_s_int32 w;       /* uncompressed audio word */

 /* Reset the coefficient table for the pole and zero linear predictor. */
 for (w = 0; w < 8; w++) RV_pzTable[w] = 0;
 RV_Reset (nbits);
 RV_cd = RV_cdx[nbits-2];
 RV_cd_length = RV_cdx_length[nbits-2];

 /* The rmd header should have been written by now. Do the compression. */

 while (1)
  {
  w = header_in->read_pvf_data(fd_in);
  if (feof(fd_in))
    break;
  /* The pvf routines work on 24bit ints */
  write_bits_reverse(fd_out, &s, nbits, (int)RV_ComOne((vgetty_s_int16)(w>>8)) );
  }

 if (s.nleft > 0) write_bits_reverse(fd_out, &s, 8 - s.nleft, 0x00);

  return(OK);
}

/*
 * I borrowed this code from wav.c - it assumes the pvf is a certain size and
 * I'm not sure this is a good assumption -- Bill Nugent <whn@topelo.lopi.com>
 */

int rockwellpcmtopvf (FILE *fd_in, FILE *fd_out, int nbits, pvf_header *header_out)
{
  int d;
  /* 8 bit PCM */
  while ((d = getc(fd_in)) != EOF)
   {
    d -= 0x80;
    d <<= 16;
    header_out->write_pvf_data(fd_out, d);
  }
  return(OK);
}

int pvftorockwellpcm (FILE *fd_in, FILE *fd_out, int nbits, pvf_header *header_in)
{
  int data;
  /* 8 bit PCM */
          
   while((data = header_in->read_pvf_data(fd_in)) != EOF)
    {
      data >>=16;

      if   (data > 0x7f)
	data = 0x7f;

      if   (data < -0x80)
	data = -0x80;
      putc(data+0x80,fd_out);
  };

  return(OK);
}
