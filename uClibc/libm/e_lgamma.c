
/* @(#)e_lgamma.c 5.1 93/09/24 */
/*
 * ====================================================
 * Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
 *
 * Developed at SunPro, a Sun Microsystems, Inc. business.
 * Permission to use, copy, modify, and distribute this
 * software is freely granted, provided that this notice
 * is preserved.
 * ====================================================
 *
 */

/* __ieee754_lgamma(x)
 * Return the logarithm of the Gamma function of x.
 *
 * Method: call __ieee754_lgamma_r
 */

#include <math.h>
#include "math_private.h"

libm_hidden_proto(signgam)

#ifdef __STDC__
	//__private_extern__
	double attribute_hidden __ieee754_lgamma(double x)
#else
	double attribute_hidden __ieee754_lgamma(x)
	double x;
#endif
{
	return __ieee754_lgamma_r(x,&signgam);
}
