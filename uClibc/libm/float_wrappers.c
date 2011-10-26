/* vi: set sw=4 ts=4: */
/*
 * Wrapper functions implementing all the float math functions
 * defined by SuSv3 by actually calling the double version of
 * each function and then casting the result back to a float
 * to return to the user.
 *
 * Copyright (C) 2005 by Erik Andersen <andersen@uclibc.org>
 *
 * GNU Lesser General Public License version 2.1 or later.
 */

#include <math.h>
#include <complex.h>

/* For the time being, do _NOT_ implement these functions
 * that are defined by SuSv3 */
#undef L_exp2f         /*float       exp2f(float);*/
#undef L_fdimf         /*float       fdimf(float, float);*/
#undef L_fmaf          /*float       fmaf(float, float, float);*/
#undef L_fmaxf         /*float       fmaxf(float, float);*/
#undef L_fminf         /*float       fminf(float, float);*/
#undef L_log2f         /*float       log2f(float);*/
#undef L_nearbyintf    /*float       nearbyintf(float);*/
#undef L_nexttowardf   /*float       nexttowardf(float, long double);*/
#undef L_remquof       /*float       remquof(float, float, int *);*/
#undef L_scalblnf      /*float       scalblnf(float, long);*/
#undef L_tgammaf       /*float       tgammaf(float);*/
#undef L_truncf        /*float       truncf(float);*/

/* Implement the following, as defined by SuSv3 */
#if 0
float       acosf(float);
float       acoshf(float);
float       asinf(float);
float       asinhf(float);
float       atan2f(float, float);
float       atanf(float);
float       atanhf(float);
float       cbrtf(float);
float       ceilf(float);
float       copysignf(float, float);
float       cosf(float);
float       coshf(float);
float       erfcf(float);
float       erff(float);
float       expf(float);
float       expm1f(float);
float       fabsf(float);
float       floorf(float);
float       fmodf(float, float);
float       frexpf(float value, int *);
float       hypotf(float, float);
int         ilogbf(float);
float       ldexpf(float, int);
float       lgammaf(float);
long long   llroundf(float);
float       log10f(float);
float       log1pf(float);
float       logbf(float);
float       logf(float);
long        lroundf(float);
float       modff(float, float *);
float       nextafterf(float, float);
float       powf(float, float);
float       remainderf(float, float);
float       rintf(float);
float       roundf(float);
float       scalbnf(float, int);
float       sinf(float);
float       sinhf(float);
float       sqrtf(float);
float       tanf(float);
float       tanhf(float);
#endif


#ifdef L_acosf
libm_hidden_proto(acos)
float acosf (float x)
{
	return (float) acos( (double)x );
}
#endif


#ifdef L_acoshf
libm_hidden_proto(acosh)
float acoshf (float x)
{
	return (float) acosh( (double)x );
}
#endif


#ifdef L_asinf
libm_hidden_proto(asin)
float asinf (float x)
{
	return (float) asin( (double)x );
}
#endif


#ifdef L_asinhf
libm_hidden_proto(asinh)
float asinhf (float x)
{
	return (float) asinh( (double)x );
}
#endif


#ifdef L_atan2f
libm_hidden_proto(atan2)
float atan2f (float x, float y)
{
	return (float) atan2( (double)x, (double)y );
}
#endif


#ifdef L_atanf
libm_hidden_proto(atan)
float atanf (float x)
{
	return (float) atan( (double)x );
}
#endif


#ifdef L_atanhf
libm_hidden_proto(atanh)
float atanhf (float x)
{
	return (float) atanh( (double)x );
}
#endif


#ifdef L_cargf
libm_hidden_proto(carg)
float cargf (float complex x)
{
	return (float) carg( (double)x );
}
#endif


#ifdef L_cbrtf
libm_hidden_proto(cbrt)
float cbrtf (float x)
{
	return (float) cbrt( (double)x );
}
#endif


#ifdef L_ceilf
libm_hidden_proto(ceil)
float ceilf (float x)
{
	return (float) ceil( (double)x );
}
#endif


#ifdef L_copysignf
libm_hidden_proto(copysign)
float copysignf (float x, float y)
{
	return (float) copysign( (double)x, (double)y );
}
#endif


#ifdef L_cosf
libm_hidden_proto(cos)
float cosf (float x)
{
	return (float) cos( (double)x );
}
#endif


#ifdef L_coshf
libm_hidden_proto(cosh)
float coshf (float x)
{
	return (float) cosh( (double)x );
}
#endif


#ifdef L_erfcf
libm_hidden_proto(erfc)
float erfcf (float x)
{
	return (float) erfc( (double)x );
}
#endif


#ifdef L_erff
libm_hidden_proto(erf)
float erff (float x)
{
	return (float) erf( (double)x );
}
#endif


#ifdef L_exp2f
libm_hidden_proto(exp2)
float exp2f (float x)
{
	return (float) exp2( (double)x );
}
#endif


#ifdef L_expf
libm_hidden_proto(exp)
float expf (float x)
{
	return (float) exp( (double)x );
}
#endif


#ifdef L_expm1f
libm_hidden_proto(expm1)
float expm1f (float x)
{
	return (float) expm1( (double)x );
}
#endif


#ifdef L_fabsf
libm_hidden_proto(fabs)
float fabsf (float x)
{
	return (float) fabs( (double)x );
}
#endif


#ifdef L_fdimf
libm_hidden_proto(fdim)
float fdimf (float x, float y)
{
	return (float) fdim( (double)x, (double)y );
}
#endif


#ifdef L_floorf
libm_hidden_proto(floor)
float floorf (float x)
{
	return (float) floor( (double)x );
}
#endif


#ifdef L_fmaf
libm_hidden_proto(fma)
float fmaf (float x, float y, float z)
{
	return (float) fma( (double)x, (double)y, (double)z );
}
#endif


#ifdef L_fmaxf
libm_hidden_proto(fmax)
float fmaxf (float x, float y)
{
	return (float) fmax( (double)x, (double)y );
}
#endif


#ifdef L_fminf
libm_hidden_proto(fmin)
float fminf (float x, float y)
{
	return (float) fmin( (double)x, (double)y );
}
#endif


#ifdef L_fmodf
libm_hidden_proto(fmod)
float fmodf (float x, float y)
{
	return (float) fmod( (double)x, (double)y );
}
#endif


#ifdef L_frexpf
libm_hidden_proto(frexp)
float frexpf (float x, int *_exp)
{
	return (float) frexp( (double)x, _exp );
}
#endif


#ifdef L_hypotf
libm_hidden_proto(hypot)
float hypotf (float x, float y)
{
	return (float) hypot( (double)x, (double)y );
}
#endif


#ifdef L_ilogbf
libm_hidden_proto(ilogb)
int ilogbf (float x)
{
	return (int) ilogb( (double)x );
}
#endif


#ifdef L_ldexpf
libm_hidden_proto(ldexp)
float ldexpf (float x, int _exp)
{
	return (float) ldexp( (double)x, _exp );
}
#endif


#ifdef L_lgammaf
libm_hidden_proto(lgamma)
float lgammaf (float x)
{
	return (float) lgamma( (double)x );
}
#endif


#ifdef L_llrintf
libm_hidden_proto(llrint)
long long llrintf (float x)
{
	return (long long) llrint( (double)x );
}
#endif


#ifdef L_llroundf
libm_hidden_proto(llround)
long long llroundf (float x)
{
	return (long long) llround( (double)x );
}
#endif


#ifdef L_log10f
libm_hidden_proto(log10)
float log10f (float x)
{
	return (float) log10( (double)x );
}
#endif


#ifdef L_log1pf
libm_hidden_proto(log1p)
float log1pf (float x)
{
	return (float) log1p( (double)x );
}
#endif


#ifdef L_log2f
libm_hidden_proto(log2)
float log2f (float x)
{
	return (float) log2( (double)x );
}
#endif


#ifdef L_logbf
libm_hidden_proto(logb)
float logbf (float x)
{
	return (float) logb( (double)x );
}
#endif


#ifdef L_logf
libm_hidden_proto(log)
float logf (float x)
{
	return (float) log( (double)x );
}
#endif


#ifdef L_lrintf
libm_hidden_proto(lrint)
long lrintf (float x)
{
	return (long) lrint( (double)x );
}
#endif


#ifdef L_lroundf
libm_hidden_proto(lround)
long lroundf (float x)
{
	return (long) lround( (double)x );
}
#endif


#ifdef L_modff
libm_hidden_proto(modf)
float modff (float x, float *iptr)
{
	double y, result;
	result = modf ( x, &y );
	*iptr = (float)y;
	return (float) result;

}
#endif


#ifdef L_nearbyintf
libm_hidden_proto(nearbyint)
float nearbyintf (float x)
{
	return (float) nearbyint( (double)x );
}
#endif


#ifdef L_nextafterf
libm_hidden_proto(nextafter)
float nextafterf (float x, float y)
{
	return (float) nextafter( (double)x, (double)y );
}
#endif


#ifdef L_nexttowardf
libm_hidden_proto(nexttoward)
float nexttowardf (float x, long double y)
{
	return (float) nexttoward( (double)x, (double)y );
}
#endif


#ifdef L_powf
libm_hidden_proto(pow)
float powf (float x, float y)
{
	return (float) pow( (double)x, (double)y );
}
#endif


#ifdef L_remainderf
libm_hidden_proto(remainder)
float remainderf (float x, float y)
{
	return (float) remainder( (double)x, (double)y );
}
#endif


#ifdef L_remquof
libm_hidden_proto(remquo)
float remquof (float x, float y, int *quo)
{
	return (float) remquo( (double)x, (double)y, quo );
}
#endif


#ifdef L_rintf
libm_hidden_proto(rint)
float rintf (float x)
{
	return (float) rint( (double)x );
}
#endif


#ifdef L_roundf
libm_hidden_proto(round)
float roundf (float x)
{
	return (float) round( (double)x );
}
#endif


#ifdef L_scalblnf
libm_hidden_proto(scalbln)
float scalblnf (float x, long _exp)
{
	return (float) scalbln( (double)x, _exp );
}
#endif


#ifdef L_scalbnf
libm_hidden_proto(scalbn)
float scalbnf (float x, int _exp)
{
	return (float) scalbn( (double)x, _exp );
}
#endif


#ifdef L_sinf
libm_hidden_proto(sin)
float sinf (float x)
{
	return (float) sin( (double)x );
}
#endif


#ifdef L_sinhf
libm_hidden_proto(sinh)
float sinhf (float x)
{
	return (float) sinh( (double)x );
}
#endif


#ifdef L_sqrtf
libm_hidden_proto(sqrt)
float sqrtf (float x)
{
	return (float) sqrt( (double)x );
}
#endif


#ifdef L_tanf
libm_hidden_proto(tan)
float tanf (float x)
{
	return (float) tan( (double)x );
}
#endif


#ifdef L_tanhf
libm_hidden_proto(tanh)
float tanhf (float x)
{
	return (float) tanh( (double)x );
}
#endif


#ifdef L_tgammaf
libm_hidden_proto(tgamma)
float tgammaf (float x)
{
	return (float) tgamma( (double)x );
}
#endif


#ifdef L_truncf
libm_hidden_proto(trunc)
float truncf (float x)
{
	return (float) trunc( (double)x );
}
#endif
