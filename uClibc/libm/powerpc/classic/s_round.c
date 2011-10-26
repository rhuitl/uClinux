#include <limits.h>
#include <math.h>
#include <endian.h>

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

/*******************************************************************************
*                                                                              *
*     The function round rounds its double argument to integral value          *
*     according to the "add half to the magnitude and truncate" rounding of    *
*     Pascal's Round function and FORTRAN's ANINT function and returns the     *
*     result in double format.  This function signals inexact if an ordered    *
*     return value is not equal to the operand.                                *
*                                                                              *
*******************************************************************************/

libm_hidden_proto(round)
double round ( double x )
      {
      DblInHex argument, OldEnvironment;
      register double y, z;
      register unsigned long int xHead;
      register long int target;

      argument.dbl = x;
      xHead = argument.words.hi & 0x7fffffffUL;      // xHead <- high half of |x|
      target = ( argument.words.hi < signMask );     // flag positive sign

      if ( xHead < 0x43300000ul )
/*******************************************************************************
*     Is |x| < 2.0^52?                                                        *
*******************************************************************************/
            {
            if ( xHead < 0x3ff00000ul )
/*******************************************************************************
*     Is |x| < 1.0?                                                           *
*******************************************************************************/
                  {
			asm ("mffs %0" : "=f" (OldEnvironment.dbl));	// get environment
                  if ( xHead < 0x3fe00000ul )
/*******************************************************************************
*     Is |x| < 0.5?                                                           *
*******************************************************************************/
                        {
                        if ( ( xHead | argument.words.lo ) != 0ul )
                              OldEnvironment.words.lo |= 0x02000000ul;
				asm ("mtfsf 255,%0" : /*NULLOUT*/ : /*IN*/ "f" ( OldEnvironment.dbl ));
                        if ( target )
                              return ( 0.0 );
                        else
                              return ( -0.0 );
                        }
/*******************************************************************************
*     Is 0.5 ² |x| < 1.0?                                                      *
*******************************************************************************/
                  OldEnvironment.words.lo |= 0x02000000ul;
			asm ("mtfsf 255,%0" : /*NULLOUT*/ : /*IN*/ "f" ( OldEnvironment.dbl ));
                  if ( target )
                        return ( 1.0 );
                  else
                        return ( -1.0 );
                  }
/*******************************************************************************
*     Is 1.0 < |x| < 2.0^52?                                                   *
*******************************************************************************/
            if ( target )
                  {                                     // positive x
                  y = ( x + twoTo52 ) - twoTo52;        // round at binary point
                  if ( y == x )                         // exact case
                        return ( x );
                  z = x + 0.5;                          // inexact case
                  y = ( z + twoTo52 ) - twoTo52;        // round at binary point
                  if ( y > z )
                        return ( y - 1.0 );
                  else
                        return ( y );
                  }

/*******************************************************************************
*     Is x < 0?                                                                *
*******************************************************************************/
            else
                  {
                  y = ( x - twoTo52 ) + twoTo52;        // round at binary point
                  if ( y == x )
                        return ( x );
                  z = x - 0.5;
                  y = ( z - twoTo52 ) + twoTo52;        // round at binary point
                  if ( y < z )
                        return ( y + 1.0 );
                  else
                  return ( y );
                  }
            }
/*******************************************************************************
*      |x| >= 2.0^52 or x is a NaN.                                            *
*******************************************************************************/
      return ( x );
      }
libm_hidden_def(round)
