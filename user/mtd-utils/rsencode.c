/*
 * Reed-Solomon ECC encoder.
 * ECC algorithm for M-systems disk on chip. We use the excellent Reed
 * Solmon code of Phil Karn (karn@ka9q.ampr.org) available under the
 * GNU GPL License. 
 *
 * This file based on code from Phil Karns package (reed-solomon-3.1.1)
 * and Fabrice Bellards docecc.c (in mtd/devices).
 *
 * 2002, Put together by Greg Ungerer (gerg@snapger.com)
 * (although PHil Karn and Fabrice Bellard did all the hard work!)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>

#define MM 10 /* Symbol size in bits */
#define KK 411 /* Number of data symbols per block */
#define B0 510 /* First root of generator polynomial, alpha form */
#define PRIM 1 /* power of alpha used to generate roots of generator poly */
#define	NN ((1 << MM) - 1)

typedef short dtype;

/* 1+x^3+x^10 */
static const int Pp[MM+1] = { 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1 };

/* This defines the type used to store an element of the Galois Field
 * used by the code. Make sure this is something larger than a char if
 * if anything larger than GF(256) is used.
 *
 * Note: unsigned char will work up to GF(256) but int seems to run
 * faster on the Pentium.
 */
typedef int gf;

/* No legal value in index form represents zero, so
 * we need a special value for this purpose
 */
#define A0	(NN)

/* generate GF(2**m) from the irreducible polynomial p(X) in Pp[0]..Pp[m]
   lookup tables:  index->polynomial form   alpha_to[] contains j=alpha**i;
                   polynomial form -> index form  index_of[j=alpha**i] = i
   alpha=2 is the primitive element of GF(2**m)
   HARI's COMMENT: (4/13/94) alpha_to[] can be used as follows:
        Let @ represent the primitive element commonly called "alpha" that
   is the root of the primitive polynomial p(x). Then in GF(2^m), for any
   0 <= i <= 2^m-2,
        @^i = a(0) + a(1) @ + a(2) @^2 + ... + a(m-1) @^(m-1)
   where the binary vector (a(0),a(1),a(2),...,a(m-1)) is the representation
   of the integer "alpha_to[i]" with a(0) being the LSB and a(m-1) the MSB. Thus for
   example the polynomial representation of @^5 would be given by the binary
   representation of the integer "alpha_to[5]".
                   Similarily, index_of[] can be used as follows:
        As above, let @ represent the primitive element of GF(2^m) that is
   the root of the primitive polynomial p(x). In order to find the power
   of @ (alpha) that has the polynomial representation
        a(0) + a(1) @ + a(2) @^2 + ... + a(m-1) @^(m-1)
   we consider the integer "i" whose binary representation with a(0) being LSB
   and a(m-1) MSB is (a(0),a(1),...,a(m-1)) and locate the entry
   "index_of[i]". Now, @^index_of[i] is that element whose polynomial 
    representation is (a(0),a(1),a(2),...,a(m-1)).
   NOTE:
        The element alpha_to[2^m-1] = 0 always signifying that the
   representation of "@^infinity" = 0 is (0,0,0,...,0).
        Similarily, the element index_of[0] = A0 always signifying
   that the power of alpha which has the polynomial representation
   (0,0,...,0) is "infinity".
 
*/

static void generate_gf(dtype *Alpha_to, dtype *Index_of)
{
  register int i, mask;

  mask = 1;
  Alpha_to[MM] = 0;
  for (i = 0; i < MM; i++) {
    Alpha_to[i] = mask;
    Index_of[Alpha_to[i]] = i;
    /* If Pp[i] == 1 then, term @^i occurs in poly-repr of @^MM */
    if (Pp[i] != 0)
      Alpha_to[MM] ^= mask;	/* Bit-wise EXOR operation */
    mask <<= 1;	/* single left-shift */
  }
  Index_of[Alpha_to[MM]] = MM;
  /*
   * Have obtained poly-repr of @^MM. Poly-repr of @^(i+1) is given by
   * poly-repr of @^i shifted left one-bit and accounting for any @^MM
   * term that may occur when poly-repr of @^i is shifted.
   */
  mask >>= 1;
  for (i = MM + 1; i < NN; i++) {
    if (Alpha_to[i - 1] >= mask)
      Alpha_to[i] = Alpha_to[MM] ^ ((Alpha_to[i - 1] ^ mask) << 1);
    else
      Alpha_to[i] = Alpha_to[i - 1] << 1;
    Index_of[Alpha_to[i]] = i;
  }
  Index_of[0] = A0;
  Alpha_to[NN] = 0;
}

static void gen_poly(dtype *Alpha_to, dtype *Index_of, dtype *gg)
{
    int i,j;

    gg[0] = 2;    /* primitive element alpha = 2  for GF(2**MM) */
    gg[1] = 1;    /* g(x) = (X+alpha) initially */
    for (i=2; i<=NN-KK; i++) {
    gg[i] = 1 ;
	for (j=i-1; j>0; j--)
	    if (gg[j] != 0)
		gg[j] = gg[j-1] ^ Alpha_to[(Index_of[gg[j]]+i)%NN];
	    else
		gg[j] = gg[j-1];
       gg[0] = Alpha_to[(Index_of[gg[0]]+i)%NN];     /* gg[0] can never be zero */
    }
    /* convert gg[] to index form for quicker encoding */
    for (i=0; i<=NN-KK; i++)
	gg[i] = Index_of[gg[i]];
}

static void rsencode(dtype *Alpha_to, dtype *Index_of, dtype *gg, gf *bb, dtype *data)
{
    int i,j;
    int feedback;

    for (i=0; i<NN-KK; i++)
	bb[i] = 0;

    for (i=KK-1; i>=0; i--) {
	feedback = Index_of[data[i]^bb[NN-KK-1]];
	if (feedback != -1) {
	    for (j=NN-KK-1; j>0; j--)
		if (gg[j] != -1)
		    bb[j] = bb[j-1] ^ Alpha_to[(gg[j]+feedback)%NN];
		else
		    bb[j] = bb[j-1];
	    bb[0] = Alpha_to[(gg[0]+feedback)%NN];
        } else {
	    for (j=NN-KK-1; j>0; j--)
		bb[j] = bb[j-1] ;
	    bb[0] = 0 ;
        }
    }
}

/* The DOC specific code begins here */

#define SECTOR_SIZE 512

/*
 * Generate the reed-solomon bytes for a sector of data.
 */
int doc_rsencode(unsigned char *sector, unsigned char *ecc)
{
    int parity, i, rc = 0;
    int pos, bitpos, nrbits1, nrbits2;
    dtype *Alpha_to, *Index_of, *gg, *data;
    gf *bb;

    /* init log and exp tables here to save memory. However, it is slower */
    Alpha_to = (dtype *) malloc((NN + 1) * sizeof(dtype));
    if (!Alpha_to)
        return(-1);
    
    Index_of = (dtype *) malloc((NN + 1) * sizeof(dtype));
    if (!Index_of) {
	rc = -1;
	goto alldone;
    }

    gg = (dtype *) malloc((NN - KK + 1) * sizeof(dtype));
    if (!gg) {
	rc = -1;
	goto alldone;
    }

    bb = (gf *) malloc((NN - KK + 1) * sizeof(gf));
    if (!bb) {
	rc = -1;
	goto alldone;
    }

    data = (dtype *) malloc(KK * sizeof(dtype));
    if (!data) {
	rc = -1;
	goto alldone;
    }

    generate_gf(Alpha_to, Index_of);
    gen_poly(Alpha_to, Index_of, gg);

    for (i = 0; (i < KK); i++) {
	data[i] = 0;
	pos = (i * MM) / 8;
	bitpos = (i * MM) % 8;
	nrbits1 = 8 - bitpos;
	nrbits2 = MM - nrbits1;
	if (pos < 512) {
		data[i] = (sector[pos] >> bitpos) & ((1 << nrbits1) - 1);
		if ((pos+1) < 512)
			data[i] |= (sector[pos+1] & ((1 << nrbits2) - 1)) << nrbits1;
	}
    }

    rsencode(Alpha_to, Index_of, gg, bb, data);

    ecc[0] = bb[0] & 0xff;
    ecc[1] = ((bb[0] >> 8) & 0x03) | ((bb[1] & 0x3f) << 2);
    ecc[2] = ((bb[1] >> 6) & 0x0f) | ((bb[2] & 0xf) << 4);
    ecc[3] = ((bb[2] >> 4) & 0x3f) | ((bb[3] & 0x3) << 6);
    ecc[4] = (bb[3] >> 2) & 0xff;
    ecc[5] = 0; /* FIXME: parity? */

alldone:
    if (data)
	free(data);
    if (bb)
	free(bb);
    if (gg)
	free(gg);
    if (Alpha_to)
	free(Alpha_to);
    if (Index_of)
	free(Index_of);
    return(rc);
}

