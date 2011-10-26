/*
 * zyxel-o56k.c
 *
 * Coverts voice messages between pvf file format and ADPCM variation
 * used in ZyXEL Omni 56K modem series. Note that claims in the modem
 * documentation that they support IMA ADPCM standard are incorrect
 * and this algorithm is definitely not IMA ADPCM (it stands very
 * close to the latter but uses different stepsize tables etc.).
 *
 * The code has been taken from "Digispeech ADPCM encoding/decoding
 * programs", version 1.0 (date created: Jan 16, 1992; date revised:
 * Jan 24, 1992).
 *
 * Copyright 1992 by Digispeech Inc.
 * Author: Yuhang Wu
 *
 * Modified for use with vgetty, Const Kaplinsky <const@ce.cctpu.edu.ru>
 *
 * $Id: zyxel-o56k.c,v 1.1 2000/07/22 10:01:01 marcs Exp $
 *
 */

#include "../include/voice.h"

#define BL 16380

/* ADPCM stepsize table */
static short stepsize[137] = {
    16,    17,    18,    19,    20,    22,    23,    24,    25,    27,
    28,    30,    32,    33,    35,    37,    39,    41,    44,    46,
    49,    51,    54,    57,    61,    64,    67,    71,    75,    79,
    84,    88,    93,    98,   104,   109,   116,   122,   129,   136,
   143,   151,   159,   168,   178,   187,   198,   209,   220,   232,
   245,   258,   273,   288,   304,   320,   338,   357,   376,   397,
   419,   442,   466,   492,   519,   548,   578,   609,   643,   678,
   716,   755,   797,   841,   887,   936,   987,  1041,  1099,  1159,
  1223,  1290,  1361,  1436,  1515,  1598,  1686,  1779,  1877,  1980,
  2089,  2204,  2325,  2453,  2588,  2731,  2881,  3039,  3207,  3383,
  3569,  3765,  3973,  4191,  4422,  4665,  4921,  5192,  5478,  5779,
  6097,  6432,  6786,  7159,  7553,  7968,  8407,  8869,  9357,  9872,
 10415, 10987, 11592, 12229, 12902, 13612, 14360, 15150, 15983, 16863,
 17790, 18769, 19801, 20890, 22039, 23251, 24530
};

/* Table of stepsize index */
static short indextbl[8]  = { -2, -2, -2, -2, 3, 9, 13, 16 };

/* functions */
static char encode_c (short Delta_N, short Dn);
static short decode_c (short Delta_N, char c);

int pvftozo56k (FILE *fd_in, FILE *fd_out, pvf_header *header_in)
{
/* variables */
  short i, j, k;        /* loop index   */
  short xn;             /* input sample      */
  short xn1;            /* signal estimate   */
  short Delta_N;        /* stepsize         */
  short Dn;             /* differential value */
  short stepindex;      /* index for stepsize table */
  char  codeword;       /* ADPCM codeword */
  short xni[5];         /* delayed speech samples */
  unsigned char c = 0;  /* ADPCM sample */
  unsigned char *xo;    /* output buffer */

/* memory allocation for output buffer */
  xo = (unsigned char *)calloc(BL,sizeof(unsigned char));
  if (xo == NULL)
    return ERROR;

/* initial conditions */
  xn1 = 0;
  Delta_N = 16;
  stepindex = 0;
  codeword = 0;
  xni[0] = xni[1] = xni[2] = xni[3] = xni[4] = 0;

/* loop until end of file */
  while (!feof (fd_in))
    {
      k = 0;
      for (j = 0; !feof (fd_in) && j < BL*2; j++)
	{
          xn = (short)(header_in->read_pvf_data(fd_in) >> 9);
          if (ferror (fd_in))
            break;

/* calculate a prediction of input sample */
	  xn1 = xni[1] + (xni[1] >> 3 ) + (xni[1] >> 4);
	  xn1 -= ( xni[2] >> 3 ) + ( xni[2] >> 6 );
	  xn1 -= ( xni[3] >> 1 ) - ( xni[3] >> 6 );
	  xn1 += ( xni[4] >> 2 );
	  if (xn1 < -16384) xn1 = -16384;
	    else if (xn1 >  16383) xn1 = 16383;

/* differential value calculation */
	  Dn = xn - xn1;

/* encode Dn relative to the current stepsize */
	  codeword = encode_c( Delta_N, Dn );

/* write ADPCM sample to output buffer */
	  if ( j%2 == 0 ) { c = 0x00F0 & ( codeword << 4 ); }
	    else { c += 0x000F & codeword; xo[k++] = c; }

/* decode ADPCM code value to reproduce Dn and accumulates an estimated xn
*/
	  xn1 += decode_c(Delta_N, codeword);
	  if (xn1 < -16384) xn1 = -16384;
	    else if (xn1 >  16383) xn1 = 16383;

/* shift predictor register */
	  for (i=1; i<4; i++) xni[i+1] = xni[i];  xni[1] = xn1;

/* stepsize adaptation */
	  stepindex += indextbl[ codeword&7 ];
	  if ( stepindex < 0 ) stepindex = 0;
	    else if ( stepindex > 136 )  stepindex = 136;
	  Delta_N = stepsize[stepindex];
	}
/* write ADPCM samples from output buffer to output file */
        if (fwrite(xo, 1, k, fd_out) != k) {
          free(xo);
          return ERROR;
        }
    }
  free(xo);
  if (ferror (fd_in))
    return ERROR;
  return OK;
}

int zo56ktopvf (FILE *fd_in, FILE *fd_out, pvf_header *header_out)
{
/* variables */
  short xn1;         /* signal estimate */
  short Delta_N;     /* stepsize               */
  short stepindex;   /* index for stepsize table */
  char  codeword;    /* ADPCM codeword */
  short i, j, k;     /* loop index */
  short xni[5];      /* delayed speech samples */
  short RL;          /* sample index */
  unsigned char *xn; /* input buffer */

/* initial conditions */
  xn1 = 0;
  Delta_N = 16;
  stepindex = 0;
  xni[0] = xni[1] = xni[2] = xni[3] = xni[4] = 0;

/* memory allocation for input buffer */
  xn = (unsigned char *)calloc(BL, sizeof(unsigned char));
  if (xn == NULL)
    return ERROR;

/* loop until end of file */
  while (!feof (fd_in))
    { RL = fread(xn, sizeof(unsigned char), BL, fd_in);

      for (j=0; j<RL; j++)
       {
	  for (k=0; k<2; k++)
	    {
/* extract ADPCM codeword from input buffer */
	      if ( k==0 ) codeword = 0x0F & (xn[j]>>4);
		else codeword = 0x0F & xn[j];

/*  calculate a prediction of the speech sample */
	      xn1 = xni[1] + (xni[1] >> 3 ) + (xni[1] >> 4);
	      xn1 -= ( xni[2] >> 3 ) + ( xni[2] >> 6 );
	      xn1 -= ( xni[3] >> 1 ) - ( xni[3] >> 6 );
	      xn1 += ( xni[4] >> 2 );
	      if (xn1 < -16384) xn1 = -16384;
		else if (xn1 >  16383) xn1 = 16383;

/* decode ADPCM code value to reproduce Dn and accumulates an estimated xn
*/
	      xn1 += decode_c(Delta_N, codeword);
	      if (xn1 < -16384) xn1 = -16384;
		else if (xn1 >  16383) xn1 = 16383;

/* shift prediction register */
	      for (i=1; i<4; i++) xni[i+1] = xni[i];  xni[1] = xn1;

/* stepsize adaptation */
	      stepindex += indextbl[ codeword&7 ];
	      if ( stepindex < 0 ) stepindex = 0;
		else if ( stepindex > 136 )  stepindex = 136;
	      Delta_N = stepsize[stepindex];

/* write reproduced sample to output file */
              header_out->write_pvf_data(fd_out, (int)xn1 << 9);
	    }
	 }
    }
  free(xn);
  if (ferror (fd_in))
    return ERROR;
  return OK;
}

/*
  function to encode the differential value and output an ADPCM codeword

  function return value:  char;  ADPCM codeword
*/

static char encode_c (short Delta_N, short Dn)

/*
   parameters:

     short Dn     :     input;  the differential value;
     short Delta_N:     input;  the stepsize;
*/

{ char c;
  c = 0;
  if ( Dn < 0 ) { c = 8; Dn = -Dn; }
  if ( Dn >= Delta_N ) { c += 4; Dn -= Delta_N; }
  if ( Dn >= (Delta_N>>1) ) { c += 2; Dn -= Delta_N>>1; }
  if ( Dn >= (Delta_N>>2) ) c += 1;
  return ( c );
}


/*
  function to calculate the differential value from an ADPCM codeword

  function return value:  short;  reproduced differential vale
*/

static short decode_c (short Delta_N, char c)

/*
   parameters:

     char  c      :     input;  the ADPCM codeword;
     short Delta_N:     input;  the stepsize;
*/

{  short b;
   b = Delta_N >> 3;
   b += (c&4) ? Delta_N : 0;
   b += (c&2) ? Delta_N >> 1 : 0;
   b += (c&1) ? Delta_N >> 2 : 0;
   return( (c&8) ? -b : b );
}

