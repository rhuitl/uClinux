#include <limits.h>
#include <math.h>

/*******************************************************************************
*                                                                              *
*     The function nearbyint rounds its double argument to integral value      *
*     according to the current rounding direction and returns the result in    *
*     double format.  This function does not signal inexact.                   *
*                                                                              *
********************************************************************************
*                                                                              *
*     This function calls fabs and copysign.		                         *
*                                                                              *
*******************************************************************************/

static const double twoTo52      = 4503599627370496.0;

libm_hidden_proto(nearbyint)
double nearbyint ( double x )
      {
	double y;
	double OldEnvironment;

	y = twoTo52;

	asm ("mffs %0" : "=f" (OldEnvironment));	/* get the environement */

      if ( fabs ( x ) >= y )                          /* huge case is exact */
            return x;
      if ( x < 0 ) y = -y;                                   /* negative case */
      y = ( x + y ) - y;                                    /* force rounding */
      if ( y == 0.0 )                        /* zero results mirror sign of x */
            y = copysign ( y, x );
//	restore old flags
	asm ("mtfsf 255,%0" : /*NULLOUT*/ : /*IN*/ "f" ( OldEnvironment ));
      return ( y );
	}
libm_hidden_def(nearbyint)
