/*
 * multitech.c
 *
 * Covert pvf <-> IMA ADPCM
 *
 * Modified for use with vgetty, Russell King (rmk@ecs.soton.ac.uk)
 *
 * $Id: multitech.c,v 1.3 1998/09/09 21:07:02 gert Exp $
 *
 */

#include "../include/voice.h"

/***********************************************************
Copyright 1992 by Stichting Mathematisch Centrum, Amsterdam, The
Netherlands.

                        All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the names of Stichting Mathematisch
Centrum or CWI not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior permission.

STICHTING MATHEMATISCH CENTRUM DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL STICHTING MATHEMATISCH CENTRUM BE LIABLE
FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

******************************************************************/

/*
** Intel/DVI ADPCM coder/decoder.
**
** The algorithm for this coder was taken from the IMA Compatability Project
** proceedings, Vol 2, Number 2; May 1992.
**
** Version 1.2, 18-Dec-92.
**
** Change log:
** - Fixed a stupid bug, where the delta was computed as
**   stepsize*code/4 in stead of stepsize*(code+0.5)/4.
** - There was an off-by-one error causing it to pick
**   an incorrect delta once in a blue moon.
** - The NODIVMUL define has been removed. Computations are now always done
**   using shifts, adds and subtracts. It turned out that, because the standard
**   is defined using shift/add/subtract, you needed bits of fixup code
**   (because the div/mul simulation using shift/add/sub made some rounding
**   errors that real div/mul don't make) and all together the resultant code
**   ran slower than just using the shifts all the time.
** - Changed some of the variable names to be more meaningful.
*/

#include "../include/adpcm.h"
#include <stdio.h> /*DBG*/

#ifndef __STDC__
#define signed
#endif

/* Intel ADPCM step variation table */
static int indexTable[16] = {
    -1, -1, -1, -1, 2, 4, 6, 8,
    -1, -1, -1, -1, 2, 4, 6, 8,
};

static int stepsizeTable[89] = {
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17,
    19, 21, 23, 25, 28, 31, 34, 37, 41, 45,
    50, 55, 60, 66, 73, 80, 88, 97, 107, 118,
    130, 143, 157, 173, 190, 209, 230, 253, 279, 307,
    337, 371, 408, 449, 494, 544, 598, 658, 724, 796,
    876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066,
    2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358,
    5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487, 12635, 13899,
    15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767
};

static void
adpcm_coder(indata, outdata, len, state)
    short indata[];
    char outdata[];
    int len;
    struct adpcm_state *state;
{
    short *inp;               /* Input buffer pointer */
    signed char *outp;        /* output buffer pointer */
    int val;             /* Current input sample value */
    int sign;            /* Current adpcm sign bit */
    int delta;           /* Current adpcm output value */
    int diff;            /* Difference between val and valprev */
    int step;            /* Stepsize */
    int valpred;         /* Predicted output value */
    int vpdiff;               /* Current change to valpred */
    int index;           /* Current step change index */
    int outputbuffer = 0;          /* place to keep previous 4-bit value */
    int bufferstep;      /* toggle between outputbuffer/output */

    outp = (signed char *)outdata;
    inp = indata;

    valpred = state->valprev;
    index = state->index;
    step = stepsizeTable[index];

    bufferstep = 1;

    for ( ; len > 0 ; len-- ) {
     val = *inp++;

     /* Step 1 - compute difference with previous value */
     diff = val - valpred;
     sign = (diff < 0) ? 8 : 0;
     if ( sign ) diff = (-diff);

     /* Step 2 - Divide and clamp */
     /* Note:
     ** This code *approximately* computes:
     **    delta = diff*4/step;
     **    vpdiff = (delta+0.5)*step/4;
     ** but in shift step bits are dropped. The net result of this is
     ** that even if you have fast mul/div hardware you cannot put it to
     ** good use since the fixup would be too expensive.
     */
     delta = 0;
     vpdiff = (step >> 3);

     if ( diff >= step ) {
         delta = 4;
         diff -= step;
         vpdiff += step;
     }
     step >>= 1;
     if ( diff >= step  ) {
         delta |= 2;
         diff -= step;
         vpdiff += step;
     }
     step >>= 1;
     if ( diff >= step ) {
         delta |= 1;
         vpdiff += step;
     }

     /* Step 3 - Update previous value */
     if ( sign )
       valpred -= vpdiff;
     else
       valpred += vpdiff;

     /* Step 4 - Clamp previous value to 16 bits */
     if ( valpred > 32767 )
       valpred = 32767;
     else if ( valpred < -32768 )
       valpred = -32768;

     /* Step 5 - Assemble value, update index and step values */
     delta |= sign;

     index += indexTable[delta];
     if ( index < 0 ) index = 0;
     if ( index > 88 ) index = 88;
     step = stepsizeTable[index];

     /* Step 6 - Output value */
     if ( bufferstep ) {
         outputbuffer = delta & 0x0f;
     } else {
         *outp++ = ((delta << 4) & 0xf0) | outputbuffer;
     }
     bufferstep = !bufferstep;
    }

    /* Output last step, if needed */
    if ( !bufferstep )
      *outp++ = outputbuffer;

    state->valprev = valpred;
    state->index = index;
}

static void
adpcm_decoder(indata, outdata, len, state)
    char indata[];
    short outdata[];
    int len;
    struct adpcm_state *state;
{
    signed char *inp;         /* Input buffer pointer */
    short *outp;         /* output buffer pointer */
    int sign;            /* Current adpcm sign bit */
    int delta;           /* Current adpcm output value */
    int step;            /* Stepsize */
    int valpred;         /* Predicted value */
    int vpdiff;               /* Current change to valpred */
    int index;           /* Current step change index */
    int inputbuffer = 0;      /* place to keep next 4-bit value */
    int bufferstep;      /* toggle between inputbuffer/input */

    outp = outdata;
    inp = (signed char *)indata;

    valpred = state->valprev;
    index = state->index;
    step = stepsizeTable[index];

    bufferstep = 0;

    for ( ; len > 0 ; len-- ) {

     /* Step 1 - get the delta value */
     if ( bufferstep ) {
         delta = (inputbuffer >> 4) & 0xf;
     } else {
         inputbuffer = *inp++;
         delta = inputbuffer & 0xf;
     }
     bufferstep = !bufferstep;

     /* Step 2 - Find new index value (for later) */
     index += indexTable[delta];
     if ( index < 0 ) index = 0;
     if ( index > 88 ) index = 88;

     /* Step 3 - Separate sign and magnitude */
     sign = delta & 8;
     delta = delta & 7;

     /* Step 4 - Compute difference and new predicted value */
     /*
     ** Computes 'vpdiff = (delta+0.5)*step/4', but see comment
     ** in adpcm_coder.
     */
     vpdiff = step;
     if ( delta & 4 ) vpdiff += step << 3;
     if ( delta & 2 ) vpdiff += step << 2;
     if ( delta & 1 ) vpdiff += step << 1;

     if ( sign )
       valpred -= vpdiff >> 3;
     else
       valpred += vpdiff >> 3;

     /* Step 5 - clamp output value */
     if ( valpred > 32767 )
       valpred = 32767;
     else if ( valpred < -32768 )
       valpred = -32768;

     /* Step 6 - Update step value */
     step = stepsizeTable[index];

     /* Step 7 - Output value */
     *outp++ = valpred;
    }

    state->valprev = valpred;
    state->index = index;
}

#define SAMPLES 512

static short  sbuffer[SAMPLES*2];
static char   cbuffer[SAMPLES/2];
static struct adpcm_state state;

int
pvftoimaadpcm (FILE *fd_in, FILE *fd_out, pvf_header *header_in)
{
  int i/*, j*/;

  while (!feof (fd_in)) {
    for (i = 0; !feof (fd_in) && i < SAMPLES; i++)
      sbuffer[i] = header_in->read_pvf_data(fd_in) >> 8;
    if (ferror (fd_in))
      break;

    adpcm_coder (sbuffer, cbuffer, i, &state);

    if (fwrite (cbuffer, 1, i / 2, fd_out) != i /2)
      return ERROR;
  }
  if (ferror (fd_in))
    return ERROR;
  return OK;
}

int
imaadpcmtopvf (FILE *fd_in, FILE *fd_out, pvf_header *header_out)
{
  int i, o/*, j*/;

  while (!feof (fd_in)) {
    i = fread (cbuffer, 1, SAMPLES / 2, fd_in);

    adpcm_decoder (cbuffer, sbuffer, i * 2, &state);

    for (o = 0; o < i * 2; o++)
      header_out->write_pvf_data(fd_out, sbuffer[o] << 8);

    if (ferror (fd_in))
      break;
  }
  if (ferror (fd_in))
    return ERROR;
  return OK;
}
