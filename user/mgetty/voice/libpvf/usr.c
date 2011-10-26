/*
 * usr.c
 *
 * Conversion pvf <--> USR GSM and ADPCM formats.
 *
 * $Id: usr.c,v 1.5 2001/12/22 19:44:09 marcs Exp $
 *
 */

#include "../include/voice.h"

/* Forward defs of the format-specific routines
 */
static int pvftousrgsm (FILE *fd_in, FILE *fd_out, pvf_header *header_in);
static int pvftousradpcm (FILE *fd_in, FILE *fd_out, pvf_header *header_in);
static int usrgsmtopvf (FILE *fd_in, FILE *fd_out, pvf_header *header_out);
static int usradpcmtopvf (FILE *fd_in, FILE *fd_out, pvf_header *header_out);

int pvftousr(FILE *fd_in, FILE *fd_out, int compression,
             pvf_header *header_in) {
  switch (compression) {
    case 1:
      return (pvftousrgsm(fd_in, fd_out, header_in));
    case 4:
      return (pvftousradpcm(fd_in, fd_out, header_in));
    default:
      return -1;
  }
}

int usrtopvf (FILE *fd_in, FILE *fd_out, int compression,
                     pvf_header *header_out) {
  switch (compression) {
    case 1:
      return (usrgsmtopvf(fd_in, fd_out, header_out));
    case 4:
      return (usradpcmtopvf(fd_in, fd_out, header_out));
    default:
      return -1;
  }
}

/*****************
 ** GSM SECTION **
 *****************/
#include "../libmgsm/gsm.h"

/* USR's GSM data format consists of 38-byte frames of data where the
 * first two bytes of the frame (usually "0xFE 0xFE" for valid data and
 * "0xB6 0xB6" for silence, and 3 bytes of trailer ("0x0 0xA5 0xA5") can
 * be discarded, giving 33 bytes of useful data.
 * Newer models can also generate frames with raw data (without the
 * trailing and leading bytes).
 * The decoding function tries to detect the frame type and pass the
 * 33 bytes of data to a garden variety GSM  decode process.
 * In my case, I used GSM 06.10 from Technische
 * Universitaet Berlin ftp://ftp.cs.tu-berlin.de/pub/local/kbs/tubmik/gsm/
 *
 * The pvftousrgsm function just generates the old type of frame 
 * since it can be played on both new and old models.
 */
unsigned char gsm_head[2] = { 0xfe, 0xfe };
unsigned char gsm_tail[3] = { 0x0, 0xa5, 0xa5 };

static int pvftousrgsm (FILE *fd_in, FILE *fd_out, pvf_header *header_in)
     {
     gsm             r;
     gsm_signal      s[ 160 ];
     gsm_frame       d;
     int             opt_fast = 0;
     int             opt_verbose = 0;
     int             opt_ltp_cut = 0;
     int             i;
     int             sample = 0;


     if (!(r = gsm_create())) {
       perror("gsm_create");
       return -1;
     }
     (void)gsm_option(r, GSM_OPT_FAST,       &opt_fast);
     (void)gsm_option(r, GSM_OPT_VERBOSE,    &opt_verbose);
     (void)gsm_option(r, GSM_OPT_LTP_CUT,    &opt_ltp_cut);

     /* GSM operates on frames of 160 samples each, so we may run up against
      * the end of the file and be forced to backfill with zeroes.
      */
     while (!feof(fd_in)) {
       for (i=0;i<160;i++) {
         sample = header_in->read_pvf_data(fd_in);
         if (feof(fd_in)) {
           memset((char *)(&s[i]), 0, sizeof(gsm_signal)*(160-i));
         } else {
           sample >>= 8;

           if (sample > 0x7fff)
             sample = 0x7fff;

           if (sample < -0x8000)
             sample = -0x8000;

           s[i] = sample;
         }
       }
       gsm_encode(r, s, d);
       fwrite((char *)gsm_head, 2, 1, fd_out);
       fwrite((char *)d, sizeof(d), 1, fd_out);
       fwrite((char *)gsm_tail, 3, 1, fd_out);
     }
     gsm_destroy(r);
     return(OK);
}

static int usrgsmtopvf (FILE *fd_in, FILE *fd_out, pvf_header *header_out)
     {
     unsigned char   inbuf[38];
     gsm             r;
     gsm_byte        *s;
     gsm_signal      d[ 160 ];
     int             opt_fast = 0;
     int             opt_verbose = 0;
     int i, sample, bytes2read, chunksread;

     if (!(r = gsm_create())) {
       perror("gsm_create");
       return -1;
     }

     (void)gsm_option(r, GSM_OPT_FAST,       &opt_fast);
     (void)gsm_option(r, GSM_OPT_VERBOSE,    &opt_verbose);

      /* 
       * read the first frame to see if it has an
       * header or is raw data
       */
      if ((chunksread=fread(inbuf, 33, 1, fd_in)) > 0) {
        if ((inbuf[0] == inbuf[1]) &&
            ((inbuf[0] == 0xfe) || (inbuf[0] == 0xb6))) {
          /* 
           * has an header 
           */
          fread(&inbuf[33], 5, 1, fd_in);
          s=&inbuf[2];
          bytes2read=38;
        } else
        {
          /*
           * raw data
           */
          s=&inbuf[0];
          bytes2read=33;
        }   
      } 
 
      while (chunksread > 0) {
 
       /* --- MNI_p/JoSch --->
        *   I don'n know how this (now redundant to leave libmgsm untouched
        *   -> see ../libmgsm/decode.c line 20) control for GSM_MAGIC
        *   works with other USR- modems. Do they realy produce wrong
        *   bytes so that it is necessary to control it?
        *   For my US Robotics Vi 28.8 Faxmodem (gr) with Personal Voice
        *   Mail (speed 33600) this seems to work.
        *   May be there is a modem-setting I don't know (I don't know
        *   any voice-settig-switches for this modem) that switches the
        *   modem to a workable compression. At this time this patch works
        *   for me until I get informations from the USR-Support.
        */

       if ((((*s >> 4) & 0x0F) != GSM_MAGIC) || (((*s >> 4) & 0x0F) != 0))
         *s |= (GSM_MAGIC << 4);

       /* <--- MNI_p/JoSch --- */

       if (gsm_decode(r, s, d)) {
         fprintf(stderr, "%s: bad frame in input\n", program_name);
         gsm_destroy(r);
         return(ERROR);
       }
       for (i=0;i<160;i++) {
         sample = d[i];
         if (sample > 0x7fff) {
           sample -= 0x10000;
         }
         header_out->write_pvf_data(fd_out, sample << 8);
       }
       chunksread=fread(inbuf, bytes2read, 1, fd_in);
     }
     return(OK);
}



/*******************
 ** ADPCM SECTION **
 *******************/

/* This ADPCM code was released by Sun Microsystems, Inc. to the public domain
 * as a part of the CCITT (International Telegraph and Telephone Consultative
 * Committee) reference implementation of the G.711, G.721 and G.723 voice
 * compression standards.
 *
 * The following files from the original distribution have been concatenated
 * in this section:
 *
 *        g72x.h          header file for g721.c, g723_24.c and g723_40.c
 *        g72x.c          common denominator of G.721 and G.723 ADPCM codes
 *        g721.c          CCITT G.721 32Kbps ADPCM coder (with g72x.c)
 *
 * Below this, the pvf conversion routines follow.
 */

/*
 * This source code is a product of Sun Microsystems, Inc. and is provided
 * for unrestricted use.  Users may copy or modify this source code without
 * charge.
 *
 * SUN SOURCE CODE IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING
 * THE WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 *
 * Sun source code is provided with no support and without any obligation on
 * the part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 *
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY THIS SOFTWARE
 * OR ANY PART THEREOF.
 *
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 *
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */

/*
 * g72x.h
 *
 * Header file for CCITT conversion routines.
 *
 */
#ifndef _G72X_H
#define   _G72X_H

#define   AUDIO_ENCODING_LINEAR    (3)  /* PCM 2's-complement (0-center) */

/*
 * The following is the definition of the state structure
 * used by the G.721/G.723 encoder and decoder to preserve their internal
 * state between successive calls.  The meanings of the majority
 * of the state structure fields are explained in detail in the
 * CCITT Recommendation G.721.  The field names are essentially indentical
 * to variable names in the bit level description of the coding algorithm
 * included in this Recommendation.
 */
struct g72x_state {
     long yl;  /* Locked or steady state step size multiplier. */
     short yu; /* Unlocked or non-steady state step size multiplier. */
     short dms;     /* Short term energy estimate. */
     short dml;     /* Long term energy estimate. */
     short ap; /* Linear weighting coefficient of 'yl' and 'yu'. */

     short a[2];    /* Coefficients of pole portion of prediction filter. */
     short b[6];    /* Coefficients of zero portion of prediction filter. */
     short pk[2];   /*
                * Signs of previous two samples of a partially
                * reconstructed signal.
                */
     short dq[6];   /*
                * Previous 6 samples of the quantized difference
                * signal represented in an internal floating point
                * format.
                */
     short sr[2];   /*
                * Previous 2 samples of the quantized difference
                * signal represented in an internal floating point
                * format.
                */
     char td;  /* delayed tone detect, new in 1988 version */
};

#endif /* !_G72X_H */
/*
 * This source code is a product of Sun Microsystems, Inc. and is provided
 * for unrestricted use.  Users may copy or modify this source code without
 * charge.
 *
 * SUN SOURCE CODE IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING
 * THE WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 *
 * Sun source code is provided with no support and without any obligation on
 * the part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 *
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY THIS SOFTWARE
 * OR ANY PART THEREOF.
 *
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 *
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */

/*
 * g72x.c
 *
 * Common routines for G.721 and G.723 conversions.
 */

static short power2[15] = {1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80,
               0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000};

/*
 * quan()
 *
 * quantizes the input val against the table of size short integers.
 * It returns i if table[i - 1] <= val < table[i].
 *
 * Using linear search for simple coding.
 */
static int
quan(
     int       val,
     short          *table,
     int       size)
{
     int       i;

     for (i = 0; i < size; i++)
          if (val < *table++)
               break;
     return (i);
}

/*
 * fmult()
 *
 * returns the integer product of the 14-bit integer "an" and
 * "floating point" representation (4-bit exponent, 6-bit mantessa) "srn".
 */
static int
fmult(
     int       an,
     int       srn)
{
     short          anmag, anexp, anmant;
     short          wanexp, /* wanmag, */ wanmant;
     short          retval;

     anmag = (an > 0) ? an : ((-an) & 0x1FFF);
     anexp = quan(anmag, power2, 15) - 6;
     anmant = (anmag == 0) ? 32 :
         (anexp >= 0) ? anmag >> anexp : anmag << -anexp;
     wanexp = anexp + ((srn >> 6) & 0xF) - 13;

     wanmant = (anmant * (srn & 077) + 0x30) >> 4;
     retval = (wanexp >= 0) ? ((wanmant << wanexp) & 0x7FFF) :
         (wanmant >> -wanexp);

     return (((an ^ srn) < 0) ? -retval : retval);
}

/*
 * g72x_init_state()
 *
 * This routine initializes and/or resets the g72x_state structure
 * pointed to by 'state_ptr'.
 * All the initial state values are specified in the CCITT G.721 document.
 */
static void
g72x_init_state(
     struct g72x_state *state_ptr)
{
     int       cnta;

     state_ptr->yl = 34816;
     state_ptr->yu = 544;
     state_ptr->dms = 0;
     state_ptr->dml = 0;
     state_ptr->ap = 0;
     for (cnta = 0; cnta < 2; cnta++) {
          state_ptr->a[cnta] = 0;
          state_ptr->pk[cnta] = 0;
          state_ptr->sr[cnta] = 32;
     }
     for (cnta = 0; cnta < 6; cnta++) {
          state_ptr->b[cnta] = 0;
          state_ptr->dq[cnta] = 32;
     }
     state_ptr->td = 0;
}

/*
 * predictor_zero()
 *
 * computes the estimated signal from 6-zero predictor.
 *
 */
static int
predictor_zero(
     struct g72x_state *state_ptr)
{
     int       i;
     int       sezi;

     sezi = fmult(state_ptr->b[0] >> 2, state_ptr->dq[0]);
     for (i = 1; i < 6; i++)            /* ACCUM */
          sezi += fmult(state_ptr->b[i] >> 2, state_ptr->dq[i]);
     return (sezi);
}
/*
 * predictor_pole()
 *
 * computes the estimated signal from 2-pole predictor.
 *
 */
static int
predictor_pole(
     struct g72x_state *state_ptr)
{
     return (fmult(state_ptr->a[1] >> 2, state_ptr->sr[1]) +
         fmult(state_ptr->a[0] >> 2, state_ptr->sr[0]));
}
/*
 * step_size()
 *
 * computes the quantization step size of the adaptive quantizer.
 *
 */
static int
step_size(
     struct g72x_state *state_ptr)
{
     int       y;
     int       dif;
     int       al;

     if (state_ptr->ap >= 256)
          return (state_ptr->yu);
     else {
          y = state_ptr->yl >> 6;
          dif = state_ptr->yu - y;
          al = state_ptr->ap >> 2;
          if (dif > 0)
               y += (dif * al) >> 6;
          else if (dif < 0)
               y += (dif * al + 0x3F) >> 6;
          return (y);
     }
}

/*
 * quantize()
 *
 * Given a raw sample, 'd', of the difference signal and a
 * quantization step size scale factor, 'y', this routine returns the
 * ADPCM codeword to which that sample gets quantized.  The step
 * size scale factor division operation is done in the log base 2 domain
 * as a subtraction.
 */
static int
quantize(
     int       d,   /* Raw difference signal sample */
     int       y,   /* Step size multiplier */
     short          *table,   /* quantization table */
     int       size)     /* table size of short integers */
{
     short          dqm; /* Magnitude of 'd' */
     short          exp; /* Integer part of base 2 log of 'd' */
     short          mant;     /* Fractional part of base 2 log */
     short          dl;  /* Log of magnitude of 'd' */
     short          dln; /* Step size scale factor normalized log */
     int       i;

     /*
      * LOG
      *
      * Compute base 2 log of 'd', and store in 'dl'.
      */
     dqm = abs(d);
     exp = quan(dqm >> 1, power2, 15);
     mant = ((dqm << 7) >> exp) & 0x7F; /* Fractional portion. */
     dl = (exp << 7) + mant;

     /*
      * SUBTB
      *
      * "Divide" by step size multiplier.
      */
     dln = dl - (y >> 2);

     /*
      * QUAN
      *
      * Obtain codword i for 'd'.
      */
     i = quan(dln, table, size);
     if (d < 0)               /* take 1's complement of i */
          return ((size << 1) + 1 - i);
     else if (i == 0)         /* take 1's complement of 0 */
          return ((size << 1) + 1); /* new in 1988 */
     else
          return (i);
}
/*
 * reconstruct()
 *
 * Returns reconstructed difference signal 'dq' obtained from
 * codeword 'i' and quantization step size scale factor 'y'.
 * Multiplication is performed in log base 2 domain as addition.
 */
static int
reconstruct(
     int       sign,     /* 0 for non-negative value */
     int       dqln,     /* G.72x codeword */
     int       y)   /* Step size multiplier */
{
     short          dql; /* Log of 'dq' magnitude */
     short          dex; /* Integer part of log */
     short          dqt;
     short          dq;  /* Reconstructed difference signal sample */

     dql = dqln + (y >> 2);   /* ADDA */

     if (dql < 0) {
          return ((sign) ? -0x8000 : 0);
     } else {       /* ANTILOG */
          dex = (dql >> 7) & 15;
          dqt = 128 + (dql & 127);
          dq = (dqt << 7) >> (14 - dex);
          return ((sign) ? (dq - 0x8000) : dq);
     }
}


/*
 * update()
 *
 * updates the state variables for each output code
 */
static void
update(
     int       code_size,     /* distinguish 723_40 with others */
     int       y,        /* quantizer step size */
     int       wi,       /* scale factor multiplier */
     int       fi,       /* for long/short term energies */
     int       dq,       /* quantized prediction difference */
     int       sr,       /* reconstructed signal */
     int       dqsez,         /* difference from 2-pole predictor */
     struct g72x_state *state_ptr) /* coder state pointer */
{
     int       cnt;
     short          mag, exp /* , mant */ ;  /* Adaptive predictor, FLOAT A */
     short          a2p = 0;       /* LIMC */
     short          a1ul;          /* UPA1 */
     short     /*   ua2, */ pks1;  /* UPA2 */
     short     /*   uga2a, */ fa1;
/*   short          uga2b; */
     char      tr;       /* tone/transition detector */
     short          ylint, thr2, dqthr;
     short          ylfrac, thr1;
     short          pk0;

     pk0 = (dqsez < 0) ? 1 : 0;    /* needed in updating predictor poles */

     mag = dq & 0x7FFF;       /* prediction difference magnitude */
     /* TRANS */
     ylint = state_ptr->yl >> 15;  /* exponent part of yl */
     ylfrac = (state_ptr->yl >> 10) & 0x1F;  /* fractional part of yl */
     thr1 = (32 + ylfrac) << ylint;          /* threshold */
     thr2 = (ylint > 9) ? 31 << 10 : thr1;   /* limit thr2 to 31 << 10 */
     dqthr = (thr2 + (thr2 >> 1)) >> 1; /* dqthr = 0.75 * thr2 */
     if (state_ptr->td == 0)       /* signal supposed voice */
          tr = 0;
     else if (mag <= dqthr)        /* supposed data, but small mag */
          tr = 0;             /* treated as voice */
     else                /* signal is data (modem) */
          tr = 1;

     /*
      * Quantizer scale factor adaptation.
      */

     /* FUNCTW & FILTD & DELAY */
     /* update non-steady state step size multiplier */
     state_ptr->yu = y + ((wi - y) >> 5);

     /* LIMB */
     if (state_ptr->yu < 544) /* 544 <= yu <= 5120 */
          state_ptr->yu = 544;
     else if (state_ptr->yu > 5120)
          state_ptr->yu = 5120;

     /* FILTE & DELAY */
     /* update steady state step size multiplier */
     state_ptr->yl += state_ptr->yu + ((-state_ptr->yl) >> 6);

     /*
      * Adaptive predictor coefficients.
      */
     if (tr == 1) {           /* reset a's and b's for modem signal */
          state_ptr->a[0] = 0;
          state_ptr->a[1] = 0;
          state_ptr->b[0] = 0;
          state_ptr->b[1] = 0;
          state_ptr->b[2] = 0;
          state_ptr->b[3] = 0;
          state_ptr->b[4] = 0;
          state_ptr->b[5] = 0;
     } else {            /* update a's and b's */
          pks1 = pk0 ^ state_ptr->pk[0];          /* UPA2 */

          /* update predictor pole a[1] */
          a2p = state_ptr->a[1] - (state_ptr->a[1] >> 7);
          if (dqsez != 0) {
               fa1 = (pks1) ? state_ptr->a[0] : -state_ptr->a[0];
               if (fa1 < -8191)    /* a2p = function of fa1 */
                    a2p -= 0x100;
               else if (fa1 > 8191)
                    a2p += 0xFF;
               else
                    a2p += fa1 >> 5;

               if (pk0 ^ state_ptr->pk[1])
                    /* LIMC */
                    if (a2p <= -12160)
                         a2p = -12288;
                    else if (a2p >= 12416)
                         a2p = 12288;
                    else
                         a2p -= 0x80;
               else if (a2p <= -12416)
                    a2p = -12288;
               else if (a2p >= 12160)
                    a2p = 12288;
               else
                    a2p += 0x80;
          }

          /* TRIGB & DELAY */
          state_ptr->a[1] = a2p;

          /* UPA1 */
          /* update predictor pole a[0] */
          state_ptr->a[0] -= state_ptr->a[0] >> 8;
          if (dqsez != 0) {
               if (pks1 == 0) {
                    state_ptr->a[0] += 192;
	       }
               else {
                    state_ptr->a[0] -= 192;
	       }
	  }

          /* LIMD */
          a1ul = 15360 - a2p;
          if (state_ptr->a[0] < -a1ul)
               state_ptr->a[0] = -a1ul;
          else if (state_ptr->a[0] > a1ul)
               state_ptr->a[0] = a1ul;

          /* UPB : update predictor zeros b[6] */
          for (cnt = 0; cnt < 6; cnt++) {
               if (code_size == 5)      /* for 40Kbps G.723 */
                    state_ptr->b[cnt] -= state_ptr->b[cnt] >> 9;
               else           /* for G.721 and 24Kbps G.723 */
                    state_ptr->b[cnt] -= state_ptr->b[cnt] >> 8;
               if (dq & 0x7FFF) {            /* XOR */
                    if ((dq ^ state_ptr->dq[cnt]) >= 0)
                         state_ptr->b[cnt] += 128;
                    else
                         state_ptr->b[cnt] -= 128;
               }
          }
     }

     for (cnt = 5; cnt > 0; cnt--)
          state_ptr->dq[cnt] = state_ptr->dq[cnt-1];
     /* FLOAT A : convert dq[0] to 4-bit exp, 6-bit mantissa f.p. */
     if (mag == 0) {
          state_ptr->dq[0] = (dq >= 0) ? 0x20 : 0xFC20;
     } else {
          exp = quan(mag, power2, 15);
          state_ptr->dq[0] = (dq >= 0) ?
              (exp << 6) + ((mag << 6) >> exp) :
              (exp << 6) + ((mag << 6) >> exp) - 0x400;
     }

     state_ptr->sr[1] = state_ptr->sr[0];
     /* FLOAT B : convert sr to 4-bit exp., 6-bit mantissa f.p. */
     if (sr == 0) {
          state_ptr->sr[0] = 0x20;
     } else if (sr > 0) {
          exp = quan(sr, power2, 15);
          state_ptr->sr[0] = (exp << 6) + ((sr << 6) >> exp);
     } else if (sr > -32768) {
          mag = -sr;
          exp = quan(mag, power2, 15);
          state_ptr->sr[0] =  (exp << 6) + ((mag << 6) >> exp) - 0x400;
     } else
          state_ptr->sr[0] = (unsigned short) 0xFC20;

     /* DELAY A */
     state_ptr->pk[1] = state_ptr->pk[0];
     state_ptr->pk[0] = pk0;

     /* TONE */
     if (tr == 1)        /* this sample has been treated as data */
          state_ptr->td = 0;  /* next one will be treated as voice */
     else if (a2p < -11776)   /* small sample-to-sample correlation */
          state_ptr->td = 1;  /* signal may be data */
     else                /* signal is voice */
          state_ptr->td = 0;

     /*
      * Adaptation speed control.
      */
     state_ptr->dms += (fi - state_ptr->dms) >> 5;          /* FILTA */
     state_ptr->dml += (((fi << 2) - state_ptr->dml) >> 7); /* FILTB */

     if (tr == 1)
          state_ptr->ap = 256;
     else if (y < 1536)                      /* SUBTC */
          state_ptr->ap += (0x200 - state_ptr->ap) >> 4;
     else if (state_ptr->td == 1)
          state_ptr->ap += (0x200 - state_ptr->ap) >> 4;
     else if (abs((state_ptr->dms << 2) - state_ptr->dml) >=
         (state_ptr->dml >> 3))
          state_ptr->ap += (0x200 - state_ptr->ap) >> 4;
     else
          state_ptr->ap += (-state_ptr->ap) >> 4;
}

/*
 * This source code is a product of Sun Microsystems, Inc. and is provided
 * for unrestricted use.  Users may copy or modify this source code without
 * charge.
 *
 * SUN SOURCE CODE IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING
 * THE WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 *
 * Sun source code is provided with no support and without any obligation on
 * the part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 *
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY THIS SOFTWARE
 * OR ANY PART THEREOF.
 *
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 *
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */

/*
 * g721.c
 *
 * Description:
 *
 * g721_encoder(), g721_decoder()
 *
 * These routines comprise an implementation of the CCITT G.721 ADPCM
 * coding algorithm.  Essentially, this implementation is identical to
 * the bit level description except for a few deviations which
 * take advantage of work station attributes, such as hardware 2's
 * complement arithmetic and large memory.  Specifically, certain time
 * consuming operations such as multiplications are replaced
 * with lookup tables and software 2's complement operations are
 * replaced with hardware 2's complement.
 *
 * The deviation from the bit level specification (lookup tables)
 * preserves the bit level performance specifications.
 *
 * As outlined in the G.721 Recommendation, the algorithm is broken
 * down into modules.  Each section of code below is preceded by
 * the name of the module which it is implementing.
 *
 */

static short qtab_721[7] = {-124, 80, 178, 246, 300, 349, 400};
/*
 * Maps G.721 code word to reconstructed scale factor normalized log
 * magnitude values.
 */
static short   _dqlntab[16] = {-2048, 4, 135, 213, 273, 323, 373, 425,
                    425, 373, 323, 273, 213, 135, 4, -2048};

/* Maps G.721 code word to log of scale factor multiplier. */
static short   _witab[16] = {-12, 18, 41, 64, 112, 198, 355, 1122,
                    1122, 355, 198, 112, 64, 41, 18, -12};
/*
 * Maps G.721 code words to a set of values whose long and short
 * term averages are computed and then compared to give an indication
 * how stationary (steady state) the signal is.
 */
static short   _fitab[16] = {0, 0, 0, 0x200, 0x200, 0x200, 0x600, 0xE00,
                    0xE00, 0x600, 0x200, 0x200, 0x200, 0, 0, 0};

/*
 * g721_encoder()
 *
 * Encodes the input vale of linear PCM, A-law or u-law data sl and returns
 * the resulting code. -1 is returned for unknown input coding value.
 */
static int
g721_encoder(
     int       sl,
     int       in_coding,
     struct g72x_state *state_ptr)
{
     short          sezi, se, sez;      /* ACCUM */
     short          d;             /* SUBTA */
     short          sr;            /* ADDB */
     short          y;             /* MIX */
     short          dqsez;              /* ADDC */
     short          dq, i;

     switch (in_coding) {     /* linearize input sample to 14-bit PCM */
     case AUDIO_ENCODING_LINEAR:
          sl >>= 2;           /* 14-bit dynamic range */
          break;
     default:
          return (-1);
     }

     sezi = predictor_zero(state_ptr);
     sez = sezi >> 1;
     se = (sezi + predictor_pole(state_ptr)) >> 1;     /* estimated signal */

     d = sl - se;                  /* estimation difference */

     /* quantize the prediction difference */
     y = step_size(state_ptr);          /* quantizer step size */
     i = quantize(d, y, qtab_721, 7);   /* i = ADPCM code */

     dq = reconstruct(i & 8, _dqlntab[i], y);     /* quantized est diff */

     sr = (dq < 0) ? se - (dq & 0x3FFF) : se + dq;     /* reconst. signal */

     dqsez = sr + sez - se;             /* pole prediction diff. */

     update(4, y, _witab[i] << 5, _fitab[i], dq, sr, dqsez, state_ptr);

     return (i);
}

/*
 * g721_decoder()
 *
 * Description:
 *
 * Decodes a 4-bit code of G.721 encoded data of i and
 * returns the resulting linear PCM, A-law or u-law value.
 * return -1 for unknown out_coding value.
 */
static int
g721_decoder(
     int       i,
     int       out_coding,
     struct g72x_state *state_ptr)
{
     short          sezi, sei, sez, se; /* ACCUM */
     short          y;             /* MIX */
     short          sr;            /* ADDB */
     short          dq;
     short          dqsez;

     i &= 0x0f;               /* mask to get proper bits */
     sezi = predictor_zero(state_ptr);
     sez = sezi >> 1;
     sei = sezi + predictor_pole(state_ptr);
     se = sei >> 1;           /* se = estimated signal */

     y = step_size(state_ptr);     /* dynamic quantizer step size */

     dq = reconstruct(i & 0x08, _dqlntab[i], y); /* quantized diff. */

     sr = (dq < 0) ? (se - (dq & 0x3FFF)) : se + dq;   /* reconst. signal */

     dqsez = sr - se + sez;             /* pole prediction diff. */

     update(4, y, _witab[i] << 5, _fitab[i], dq, sr, dqsez, state_ptr);

     switch (out_coding) {
     case AUDIO_ENCODING_LINEAR:
          return (sr << 2);   /* sr was 14-bit dynamic range */
     default:
          return (-1);
     }
}

static int
pack_output(
        unsigned                code,
        int                     bits,
     FILE*               fd_out)
{
        static unsigned int     out_buffer = 0;
        static int              out_bits = 0;
        unsigned char           out_byte;

        out_buffer |= (code << out_bits);
        out_bits += bits;
        if (out_bits >= 8) {
                out_byte = out_buffer & 0xff;
                out_bits -= 8;
                out_buffer >>= 8;
                fwrite(&out_byte, sizeof (char), 1, fd_out);
        }
        return (out_bits > 0);
}

static int
unpack_input(
        unsigned char           *code,
        int                     bits,
     FILE*               fd_in)
{
        static unsigned int     in_buffer = 0;
        static int              in_bits = 0;
        unsigned char           in_byte;

        if (in_bits < bits) {
                if (fread(&in_byte, sizeof (char), 1, fd_in) != 1) {
                        *code = 0;
                        return (-1);
                }
                in_buffer |= (in_byte << in_bits);
                in_bits += 8;
        }
        *code = in_buffer & ((1 << bits) - 1);
        in_buffer >>= bits;
        in_bits -= bits;
        return (in_bits > 0);
}

int pvftousradpcm (FILE *fd_in, FILE *fd_out, pvf_header *header_in)
     {
     struct g72x_state       state;
     int             r = 0;
     int             sample = 0;
     unsigned char   code = 0;



     g72x_init_state(&state);

     /* GSM operates on frames of 160 samples each, so we may run up against
      * the end of the file and be forced to backfill with zeroes.
      */
     while (!feof(fd_in)) {
       sample = header_in->read_pvf_data(fd_in);
       sample >>= 8;

       if (sample > 0x7fff)
         sample = 0x7fff;

       if (sample < -0x8000)
         sample = -0x8000;

       code = g721_encoder(sample, AUDIO_ENCODING_LINEAR, &state);
       r = pack_output(code, 4, fd_out);
     }
     while (r) {
       r = pack_output(0, 4, fd_out);
     }
     return(OK);
}

static int usradpcmtopvf (FILE *fd_in, FILE *fd_out, pvf_header *header_out)
     {
     int sample;
     struct g72x_state       state;
     unsigned char   code = 0;

     while (unpack_input(&code, 4, fd_in) >= 0) {
     sample = g721_decoder(code, AUDIO_ENCODING_LINEAR, &state);
        header_out->write_pvf_data(fd_out, sample << 8);
     }
     return(OK);
}
