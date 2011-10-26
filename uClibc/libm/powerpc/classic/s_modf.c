/*******************************************************************************
**      File:   rndint.c
**
**      Contains: C source code for implementations of floating-point
**                functions which round to integral value or format, as
**                defined in header <fp.h>.  In particular, this file
**                contains implementations of functions rinttol, roundtol,
**                modf and modfl.  This file targets PowrPC or Power platforms.
**
**      Written by: A. Sazegari, Apple AltiVec Group
**	    Created originally by Jon Okada, Apple Numerics Group
**
**      Copyright: © 1992-2001 by Apple Computer, Inc., all rights reserved
**
**      Change History (most recent first):
**
**      13 Jul 01  ram  replaced --setflm calls with inline assembly
**      03 Mar 01  ali	first port to os x using gcc, added the crucial __setflm
**                      definition.
**				1. removed double_t, put in double for now.
**				2. removed iclass from nearbyint.
**				3. removed wrong comments intrunc.
**				4.
**      13 May 97  ali  made performance improvements in rint, rinttol, roundtol
**                      and trunc by folding some of the taligent ideas into this
**                      implementation.  nearbyint is faster than the one in taligent,
**                      rint is more elegant, but slower by %30 than the taligent one.
**      09 Apr 97  ali  deleted modfl and deferred to AuxiliaryDD.c
**      15 Sep 94  ali  Major overhaul and performance improvements of all functions.
**      20 Jul 94  PAF  New faster version
**      16 Jul 93  ali  Added the modfl function.
**      18 Feb 93  ali  Changed the return value of fenv functions
**                      feclearexcept and feraiseexcept to their new
**                      NCEG X3J11.1/93-001 definitions.
**      16 Dec 92  JPO  Removed __itrunc implementation to a
**                      separate file.
**      15 Dec 92  JPO  Added __itrunc implementation and modified
**                      rinttol to include conversion from double
**                      to long int format.  Modified roundtol to
**                      call __itrunc.
**      10 Dec 92  JPO  Added modf (double) implementation.
**      04 Dec 92  JPO  First created.
**
*******************************************************************************/

#include <limits.h>
#include <math.h>
#include <endian.h>

#define      SET_INVALID      0x01000000UL

typedef union
      {
      struct {
#if (__BYTE_ORDER == __BIG_ENDIAN)
        unsigned long int hi;
        unsigned long int lo;
#else
        unsigned long int lo;
        unsigned long int hi;
#endif
      } words;
      double dbl;
      } DblInHex;

static const unsigned long int signMask = 0x80000000ul;
static const double twoTo52      = 4503599627370496.0;
static const double doubleToLong = 4503603922337792.0;	            // 2^52
static const DblInHex TOWARDZERO = {{ 0x00000000, 0x00000001 }};


/*******************************************************************************
*                                                                              *
*     The function rinttol converts its double argument to integral value      *
*     according to the current rounding direction and returns the result in    *
*     long int format.  This conversion signals invalid if the argument is a   *
*     NaN or the rounded intermediate result is out of range of the            *
*     destination long int format, and it delivers an unspecified result in    *
*     this case.  This function signals inexact if the rounded result is       *
*     within range of the long int format but unequal to the operand.          *
*                                                                              *
*******************************************************************************/

long int rinttol ( double x )
      {
      register double y;
      DblInHex argument, OldEnvironment;
      unsigned long int xHead;
      register long int target;

      argument.dbl = x;
      target = ( argument.words.hi < signMask );        // flag positive sign
      xHead = argument.words.hi & 0x7ffffffful;         // high 32 bits of x

      if ( target )
/*******************************************************************************
*    Sign of x is positive.                                                    *
*******************************************************************************/
            {
            if ( xHead < 0x41dffffful )
                  {                                    // x is safely in long range
                  y = ( x + twoTo52 ) - twoTo52;       // round at binary point
                  argument.dbl = y + doubleToLong;     // force result into argument.words.lo
                  return ( ( long ) argument.words.lo );
                  }

		asm ("mffs %0" : "=f" (OldEnvironment.dbl));	// get environment

            if ( xHead > 0x41dffffful )
                  {                                    // x is safely out of long range
                  OldEnvironment.words.lo |= SET_INVALID;
			asm ("mtfsf 255,%0" : /*NULLOUT*/ : /*IN*/ "f" ( OldEnvironment.dbl ));
                  return ( LONG_MAX );
                  }

/*******************************************************************************
*     x > 0.0 and may or may not be out of range of long.                      *
*******************************************************************************/

            y = ( x + twoTo52 ) - twoTo52;             // do rounding
            if ( y > ( double ) LONG_MAX )
                  {                                    // out of range of long
                  OldEnvironment.words.lo |= SET_INVALID;
			asm ("mtfsf 255,%0" : /*NULLOUT*/ : /*IN*/ "f" ( OldEnvironment.dbl ));
                  return ( LONG_MAX );
                  }
            argument.dbl = y + doubleToLong;           // in range
            return ( ( long ) argument.words.lo );      // return result & flags
            }

/*******************************************************************************
*    Sign of x is negative.                                                    *
*******************************************************************************/
      if ( xHead < 0x41e00000ul )
            {                                          // x is safely in long range
            y = ( x - twoTo52 ) + twoTo52;
            argument.dbl = y + doubleToLong;
            return ( ( long ) argument.words.lo );
            }

	asm ("mffs %0" : "=f" (OldEnvironment.dbl));	// get environment

      if ( xHead > 0x41e00000ul )
            {                                          // x is safely out of long range
            OldEnvironment.words.lo |= SET_INVALID;
		asm ("mtfsf 255,%0" : /*NULLOUT*/ : /*IN*/ "f" ( OldEnvironment.dbl ));
            return ( LONG_MIN );
            }

/*******************************************************************************
*    x < 0.0 and may or may not be out of range of long.                       *
*******************************************************************************/

      y = ( x - twoTo52 ) + twoTo52;                   // do rounding
      if ( y < ( double ) LONG_MIN )
            {                                          // out of range of long
            OldEnvironment.words.lo |= SET_INVALID;
		asm ("mtfsf 255,%0" : /*NULLOUT*/ : /*IN*/ "f" ( OldEnvironment.dbl ));
            return ( LONG_MIN );
            }
      argument.dbl = y + doubleToLong;                       // in range
      return ( ( long ) argument.words.lo );           // return result & flags
      }

/*******************************************************************************
*                                                                              *
*     The function roundtol converts its double argument to integral format    *
*     according to the "add half to the magnitude and chop" rounding mode of   *
*     Pascal's Round function and FORTRAN's NINT function.  This conversion    *
*     signals invalid if the argument is a NaN or the rounded intermediate     *
*     result is out of range of the destination long int format, and it        *
*     delivers an unspecified result in this case.  This function signals      *
*     inexact if the rounded result is within range of the long int format but *
*     unequal to the operand.                                                  *
*                                                                              *
*******************************************************************************/

long int roundtol ( double x )
	{
	register double y, z;
	DblInHex argument, OldEnvironment;
	register unsigned long int xhi;
	register long int target;
	const DblInHex kTZ = {{ 0x0, 0x1 }};
	const DblInHex kUP = {{ 0x0, 0x2 }};

	argument.dbl = x;
	xhi = argument.words.hi & 0x7ffffffful;	        	// high 32 bits of x
	target = ( argument.words.hi < signMask );         	// flag positive sign

	if ( xhi > 0x41e00000ul )
/*******************************************************************************
*     Is x is out of long range or NaN?                                        *
*******************************************************************************/
		{
		asm ("mffs %0" : "=f" (OldEnvironment.dbl));	// get environment
		OldEnvironment.words.lo |= SET_INVALID;
		asm ("mtfsf 255,%0" : /*NULLOUT*/ : /*IN*/ "f" ( OldEnvironment.dbl ));
		if ( target )			              	// pin result
			return ( LONG_MAX );
		else
			return ( LONG_MIN );
		}

	if ( target )
/*******************************************************************************
*     Is sign of x is "+"?                                                     *
*******************************************************************************/
		{
		if ( x < 2147483647.5 )
/*******************************************************************************
*     x is in the range of a long.                                             *
*******************************************************************************/
			{
			y = ( x + doubleToLong ) - doubleToLong; 	// round at binary point
			if ( y != x )
				{		                    	// inexact case
				asm ("mffs %0" : "=f" (OldEnvironment.dbl));	// save environment
				asm ("mtfsf 255,%0" : /*NULLOUT*/ : /*IN*/ "f" ( kTZ.dbl )); // truncate rounding
				z = x + 0.5;		        	// truncate x + 0.5
				argument.dbl = z + doubleToLong;
				asm ("mtfsf 255,%0" : /*NULLOUT*/ : /*IN*/ "f" ( OldEnvironment.dbl ));
				return ( ( long ) argument.words.lo );
				}

			argument.dbl = y + doubleToLong;		// force result into argument.words.lo
			return ( ( long ) argument.words.lo ); 	// return long result
			}
/*******************************************************************************
*     Rounded positive x is out of the range of a long.                        *
*******************************************************************************/
		asm ("mffs %0" : "=f" (OldEnvironment.dbl));
		OldEnvironment.words.lo |= SET_INVALID;
		asm ("mtfsf 255,%0" : /*NULLOUT*/ : /*IN*/ "f" ( OldEnvironment.dbl ));
		return ( LONG_MAX );		              	// return pinned result
		}
/*******************************************************************************
*     x < 0.0 and may or may not be out of the range of a long.                *
*******************************************************************************/
	if ( x > -2147483648.5 )
/*******************************************************************************
*     x is in the range of a long.                                             *
*******************************************************************************/
		{
		y = ( x + doubleToLong ) - doubleToLong;	  	// round at binary point
		if ( y != x )
			{			                    	// inexact case
			asm ("mffs %0" : "=f" (OldEnvironment.dbl));	// save environment
			asm ("mtfsf 255,%0" : /*NULLOUT*/ : /*IN*/ "f" ( kUP.dbl )); // round up
			z = x - 0.5;		              	// truncate x - 0.5
			argument.dbl = z + doubleToLong;
			asm ("mtfsf 255,%0" : /*NULLOUT*/ : /*IN*/ "f" ( OldEnvironment.dbl ));
			return ( ( long ) argument.words.lo );
			}

		argument.dbl = y + doubleToLong;
		return ( ( long ) argument.words.lo );	  	//  return long result
		}
/*******************************************************************************
*     Rounded negative x is out of the range of a long.                        *
*******************************************************************************/
	asm ("mffs %0" : "=f" (OldEnvironment.dbl));
	OldEnvironment.words.lo |= SET_INVALID;
	asm ("mtfsf 255,%0" : /*NULLOUT*/ : /*IN*/ "f" ( OldEnvironment.dbl ));
	return ( LONG_MIN );			              	// return pinned result
	}

/*******************************************************************************
*     The modf family of functions separate a floating-point number into its   *
*     fractional and integral parts, returning the fractional part and writing *
*     the integral part in floating-point format to the object pointed to by a *
*     pointer argument.  If the input argument is integral or infinite in      *
*     value, the return value is a zero with the sign of the input argument.   *
*     The modf family of functions raises no floating-point exceptions. older  *
*     implemenation set the INVALID flag due to signaling NaN input.           *
*                                                                              *
*******************************************************************************/

/*******************************************************************************
*     modf is the double implementation.                                       *
*******************************************************************************/

libm_hidden_proto(modf)
double modf ( double x, double *iptr )
      {
      register double OldEnvironment, xtrunc;
      register unsigned long int xHead, signBit;
      DblInHex argument;

      argument.dbl = x;
      xHead = argument.words.hi & 0x7ffffffful;            // |x| high bit pattern
      signBit = ( argument.words.hi & 0x80000000ul );      // isolate sign bit
	  if (xHead == 0x7ff81fe0)
			signBit = signBit | 0;

      if ( xHead < 0x43300000ul )
/*******************************************************************************
*     Is |x| < 2.0^53?                                                         *
*******************************************************************************/
            {
            if ( xHead < 0x3ff00000ul )
/*******************************************************************************
*     Is |x| < 1.0?                                                            *
*******************************************************************************/
                  {
                  argument.words.hi = signBit;             // truncate to zero
                  argument.words.lo = 0ul;
                  *iptr = argument.dbl;
                  return ( x );
                  }
/*******************************************************************************
*     Is 1.0 < |x| < 2.0^52?                                                   *
*******************************************************************************/
			asm ("mffs %0" : "=f" (OldEnvironment));	// save environment
			// round toward zero
			asm ("mtfsf 255,%0" : /*NULLOUT*/ : /*IN*/ "f" ( TOWARDZERO.dbl ));
            if ( signBit == 0ul )                         // truncate to integer
                  xtrunc = ( x + twoTo52 ) - twoTo52;
            else
                  xtrunc = ( x - twoTo52 ) + twoTo52;
		// restore caller's env
		asm ("mtfsf 255,%0" : /*NULLOUT*/ : /*IN*/ "f" ( OldEnvironment ));
            *iptr = xtrunc;                               // store integral part
            if ( x != xtrunc )                            // nonzero fraction
                  return ( x - xtrunc );
            else
                  {                                       // zero with x's sign
                  argument.words.hi = signBit;
                  argument.words.lo = 0ul;
                  return ( argument.dbl );
                  }
            }

      *iptr = x;                                          // x is integral or NaN
      if ( x != x )                                       // NaN is returned
            return x;
      else
            {                                             // zero with x's sign
            argument.words.hi = signBit;
            argument.words.lo = 0ul;
            return ( argument.dbl );
            }
      }
libm_hidden_def(modf)
