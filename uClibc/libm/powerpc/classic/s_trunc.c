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
*     The function trunc truncates its double argument to integral value       *
*     and returns the result in double format.  This function signals          *
*     inexact if an ordered return value is not equal to the operand.          *
*                                                                              *
*******************************************************************************/

libm_hidden_proto(trunc)
double trunc ( double x )
      {
	DblInHex argument,OldEnvironment;
	register double y;
	register unsigned long int xhi;
	register long int target;

	argument.dbl = x;
	xhi = argument.words.hi & 0x7fffffffUL;	      	// xhi <- high half of |x|
	target = ( argument.words.hi < signMask );	      	// flag positive sign

	if ( xhi < 0x43300000ul )
/*******************************************************************************
*     Is |x| < 2.0^53?                                                         *
*******************************************************************************/
		{
		if ( xhi < 0x3ff00000ul )
/*******************************************************************************
*     Is |x| < 1.0?                                                            *
*******************************************************************************/
			{
			if ( ( xhi | argument.words.lo ) != 0ul )
				{                             	// raise deserved INEXACT
				asm ("mffs %0" : "=f" (OldEnvironment.dbl));
				OldEnvironment.words.lo |= 0x02000000ul;
				asm ("mtfsf 255,%0" : /*NULLOUT*/ : /*IN*/ "f" ( OldEnvironment.dbl ));
				}
			if ( target )	                  	// return properly signed zero
				return ( 0.0 );
			else
				return ( -0.0 );
			}
/*******************************************************************************
*     Is 1.0 < |x| < 2.0^52?                                                   *
*******************************************************************************/
		if ( target )
			{
			y = ( x + twoTo52 ) - twoTo52;      	// round at binary point
			if ( y > x )
				return ( y - 1.0 );
			else
				return ( y );
			}

		else
			{
			y = ( x - twoTo52 ) + twoTo52;      	// round at binary point.
			if ( y < x )
				return ( y + 1.0 );
			else
				return ( y );
			}
		}
/*******************************************************************************
*      Is |x| >= 2.0^52 or x is a NaN.                                         *
*******************************************************************************/
	return ( x );
	}
libm_hidden_def(trunc)
