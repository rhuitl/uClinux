/* Copyright (C) 1991, 1992 Free Software Foundation, Inc.
This file is part of the GNU C Library.

The GNU C Library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

The GNU C Library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

#ifdef	__GNUC__

#include <sys/cdefs.h>

__BEGIN_DECLS

#if 0 /* ndef CONFIG_COLDFIRE not sure these work for anything ! */

#ifdef	__NO_MATH_INLINES
#define	__m81_u(x)	__CONCAT(__,x)
#else
#define	__m81_u(x)	x
#define	__MATH_INLINES	1
#endif

extern double __infnan (int error);

#define	__inline_mathop2(func, op)					      \
  extern __inline __CONSTVALUE double                                         \
  __m81_u(func)(double __mathop_x) __CONSTVALUE2;                             \
  extern __inline __CONSTVALUE double					      \
  __m81_u(func)(double __mathop_x)               			      \
  {									      \
    double __result;							      \
    __asm("f" __STRING(op) "%.x %1, %0" : "=f" (__result) : "f" (__mathop_x));\
    return __result;							      \
  }
#define	__inline_mathop(op)		__inline_mathop2(op, op)

#define	__inline_mathopl(func, op)					      \
  extern __inline __CONSTVALUE long double				      \
  __m81_u(func)(long double __mathop_x) __CONSTVALUE2;			      \
  extern __inline __CONSTVALUE long double				      \
  __m81_u(func)(long double __mathop_x)		       			      \
  {									      \
    long double __result;						      \
    __asm("f" __STRING(op) "%.x %1, %0" : "=f" (__result) : "f" (__mathop_x));\
    return __result;							      \
  }

__inline_mathop(acos)
__inline_mathop(asin)
__inline_mathop(atan)
__inline_mathop(cos)
__inline_mathop(sin)
__inline_mathop(tan)
__inline_mathop(cosh)
__inline_mathop(sinh)
__inline_mathop(tanh)
__inline_mathop2(exp, etox)
__inline_mathop2(fabs, abs)
__inline_mathop(log10)
__inline_mathop2(log, logn)
__inline_mathop(sqrt)

/* long double versions */
__inline_mathopl(acosl, acos)
__inline_mathopl(asinl, asin)
__inline_mathopl(atanl, atan)
__inline_mathopl(cosl, cos)
__inline_mathopl(sinl, sin)
__inline_mathopl(tanl, tan)
__inline_mathopl(coshl, cosh)
__inline_mathopl(sinhl, sinh)
__inline_mathopl(tanhl, tanh)
__inline_mathopl(expl, etox)
__inline_mathopl(fabsl, abs)
__inline_mathopl(log2l, log2)
__inline_mathopl(log10l, log10)
__inline_mathopl(logl, logn)
__inline_mathopl(sqrtl, sqrt)

__inline_mathop2(__rint, int)
__inline_mathopl(__rintl, int)
__inline_mathop2(__expm1, etoxm1)
__inline_mathopl(__expm1l, etoxm1)

#ifdef	__USE_MISC
__inline_mathop2(rint, int)
__inline_mathop2(expm1, etoxm1)
__inline_mathop2(log1p, lognp1)
__inline_mathop(atanh)
__inline_mathopl(rintl, int)
__inline_mathopl(expm1l, etoxm1)
__inline_mathopl(log1pl, lognp1)
__inline_mathopl(atanhl, atanh)
#endif

extern __inline __CONSTVALUE double
__m81_u(__drem)(double __x, double __y) __CONSTVALUE2;
extern __inline __CONSTVALUE double
__m81_u(__drem)(double __x, double __y)
{
  double __result;
  __asm("frem%.x %1, %0" : "=f" (__result) : "f" (__y), "0" (__x));
  return __result;
}

extern __inline __CONSTVALUE double
__m81_u(ldexp)(double __x, int __e) __CONSTVALUE2;
extern __inline __CONSTVALUE double
__m81_u(ldexp)(double __x, int __e)
{
  double __result;
  double __double_e = (double) __e;
  __asm("fscale%.x %1, %0" : "=f" (__result) : "f" (__double_e), "0" (__x));
  return __result;
}

extern __inline __CONSTVALUE double
__m81_u(fmod)(double __x, double __y) __CONSTVALUE2;
extern __inline __CONSTVALUE double
__m81_u(fmod)(double __x, double __y)
{
  double __result;
  __asm("fmod%.x %1, %0" : "=f" (__result) : "f" (__y), "0" (__x));
  return __result;
}

extern __inline __CONSTVALUE double
__m81_u(atan2)(double __x, double __y) __CONSTVALUE2;
extern __inline __CONSTVALUE double
__m81_u(atan2)(double __x, double __y)
{
  double __result = 0.0;
  return __result;
}

extern __inline double
__m81_u(frexp)(double __value, int *__expptr);
extern __inline double
__m81_u(frexp)(double __value, int *__expptr)
{
  double __mantissa, __exponent;
  int __iexponent;
  if (__value == 0.0)
    {
      *__expptr = 0;
      return __value;
    }
  __asm("fgetexp%.x %1, %0" : "=f" (__exponent) : "f" (__value));
  __iexponent = (int) __exponent + 1;
  *__expptr = __iexponent;
  __asm("fscale%.l %2, %0" : "=f" (__mantissa)
	: "0" (__value), "dmi" (-__iexponent));
  return __mantissa;
}

extern __inline __CONSTVALUE double
__m81_u(floor)(double __x) __CONSTVALUE2;
extern __inline __CONSTVALUE double
__m81_u(floor)(double __x)
{
  double __result;
  unsigned long int __ctrl_reg;
  __asm __volatile__ ("fmove%.l %!, %0" : "=dm" (__ctrl_reg));
  /* Set rounding towards negative infinity.  */
  __asm __volatile__ ("fmove%.l %0, %!" : /* No outputs.  */ 
		      : "dmi" ((__ctrl_reg & ~0x10) | 0x20));
  /* Convert X to an integer, using -Inf rounding.  */
  __asm __volatile__ ("fint%.x %1, %0" : "=f" (__result) : "f" (__x));
  /* Restore the previous rounding mode.  */
  __asm __volatile__ ("fmove%.l %0, %!" : /* No outputs.  */
		      : "dmi" (__ctrl_reg));
  return __result;
}

extern __inline __CONSTVALUE double
__m81_u(pow)(double __x, double __y) __CONSTVALUE2;
extern __inline __CONSTVALUE double
__m81_u(pow)(double __x, double __y)
{
  double __result;
  if (__x == 0.0)
    {
      if (__y == 0.0)
	__result = __infnan (0);
      else
	__result = 0.0;
    }
  else if (__y == 0.0 || __x == 1.0)
    __result = 1.0;
  else if (__y == 1.0)
    __result = __x;
  else if (__y == 2.0)
    __result = __x * __x;
  else if (__x == 10.0)
    __asm("ftentox%.x %1, %0" : "=f" (__result) : "f" (__y));
  else if (__x == 2.0)
    __asm("ftwotox%.x %1, %0" : "=f" (__result) : "f" (__y));
  else if (__x < 0.0)
    {
      double __temp = __m81_u (__rint) (__y);
      if (__y == __temp)
	{
	  int i = (int) __y;
	  __result = __m81_u (exp) (__y * __m81_u (log) (-__x));
	  if (i & 1)
	    __result = -__result;
	}
      else
	__result = __infnan (0);
    }
  else
    __result = __m81_u(exp)(__y * __m81_u(log)(__x));
  return __result;
}

extern __inline __CONSTVALUE double
__m81_u(ceil)(double __x) __CONSTVALUE2;
extern __inline __CONSTVALUE double
__m81_u(ceil)(double __x)
{
  double __result;
  unsigned long int __ctrl_reg;
  __asm __volatile__ ("fmove%.l %!, %0" : "=dm" (__ctrl_reg));
  /* Set rounding towards positive infinity.  */
  __asm __volatile__ ("fmove%.l %0, %!" : /* No outputs.  */
		      : "dmi" (__ctrl_reg | 0x30));
  /* Convert X to an integer, using +Inf rounding.  */
  __asm __volatile__ ("fint%.x %1, %0" : "=f" (__result) : "f" (__x));
  /* Restore the previous rounding mode.  */
  __asm __volatile__ ("fmove%.l %0, %!" : /* No outputs.  */
		      : "dmi" (__ctrl_reg));
  return __result;
}

extern __inline double
__m81_u(modf)(double __value, double *__iptr);
extern __inline double
__m81_u(modf)(double __value, double *__iptr)
{
  double __modf_int;
  __asm ("fintrz%.x %1, %0" : "=f" (__modf_int) : "f" (__value));
  *__iptr = __modf_int;
  return __value - __modf_int;
}

extern __inline __CONSTVALUE int
__m81_u(__isinf)(double __value) __CONSTVALUE2;
extern __inline __CONSTVALUE int
__m81_u(__isinf)(double __value)
{
  /* There is no branch-condition for infinity,
     so we must extract and examine the condition codes manually.  */
  unsigned long int __fpsr;
  __asm("ftst%.x %1\n"
	"fmove%.l %/fpsr, %0" : "=dm" (__fpsr) : "f" (__value));
  return (__fpsr & (2 << (3 * 8))) ? (__value < 0 ? -1 : 1) : 0;
}

extern __inline __CONSTVALUE int
__m81_u(__isnan)(double __value) __CONSTVALUE2;
extern __inline __CONSTVALUE int
__m81_u(__isnan)(double __value)
{
  char __result;
  __asm("ftst%.x %1\n"
	"fsun %0" : "=dm" (__result) : "f" (__value));
  return __result;
}

/* long double versions */

extern __inline __CONSTVALUE long double
__m81_u(__dreml)(long double __x, long double __y) __CONSTVALUE2;
extern __inline __CONSTVALUE long double
__m81_u(__dreml)(long double __x, long double __y)
{
  long double __result;
  __asm("frem%.x %1, %0" : "=f" (__result) : "f" (__y), "0" (__x));
  return __result;
}

extern __inline __CONSTVALUE long double
__m81_u(ldexpl)(long double __x, int __e) __CONSTVALUE2;
extern __inline __CONSTVALUE long double
__m81_u(ldexpl)(long double __x, int __e)
{
  long double __result;
  long double __double_e = (long double) __e;
  __asm("fscale%.x %1, %0" : "=f" (__result) : "f" (__double_e), "0" (__x));
  return __result;
}

extern __inline __CONSTVALUE long double
__m81_u(fmodl)(long double __x, long double __y) __CONSTVALUE2;
extern __inline __CONSTVALUE long double
__m81_u(fmodl)(long double __x, long double __y)
{
  long double __result;
  __asm("fmod%.x %1, %0" : "=f" (__result) : "f" (__y), "0" (__x));
  return __result;
}

extern __inline long double
__m81_u(frexpl)(long double __value, int *__expptr);
extern __inline long double
__m81_u(frexpl)(long double __value, int *__expptr)
{
  long double __mantissa, __exponent;
  int __iexponent;
  if (__value == 0.0l)
    {
      *__expptr = 0;
      return __value;
    }
  __asm("fgetexp%.x %1, %0" : "=f" (__exponent) : "f" (__value));
  __iexponent = (int) __exponent + 1;
  *__expptr = __iexponent;
  __asm("fscale%.l %2, %0" : "=f" (__mantissa)
	: "0" (__value), "dmi" (-__iexponent));
  return __mantissa;
}

extern __inline __CONSTVALUE long double
__m81_u(floorl)(long double __x) __CONSTVALUE2;
extern __inline __CONSTVALUE long double
__m81_u(floorl)(long double __x)
{
  long double __result;
  unsigned long int __ctrl_reg;
  __asm __volatile__ ("fmove%.l %!, %0" : "=dm" (__ctrl_reg));
  /* Set rounding towards negative infinity.  */
  __asm __volatile__ ("fmove%.l %0, %!" : /* No outputs.  */ 
		      : "dmi" ((__ctrl_reg & ~0x10) | 0x20));
  /* Convert X to an integer, using -Inf rounding.  */
  __asm __volatile__ ("fint%.x %1, %0" : "=f" (__result) : "f" (__x));
  /* Restore the previous rounding mode.  */
  __asm __volatile__ ("fmove%.l %0, %!" : /* No outputs.  */
		      : "dmi" (__ctrl_reg));
  return __result;
}

extern long double __infnanl (int error);

extern __inline __CONSTVALUE long double
__m81_u(powl)(long double __x, long double __y) __CONSTVALUE2;
extern __inline __CONSTVALUE long double
__m81_u(powl)(long double __x, long double __y)
{
  long double __result;
  if (__x == 0.0L)
    {
      if (__y == 0.0L)
	__result = __infnanl (0);
      else
	__result = 0.0L;
    }
  else if (__y == 0.0L || __x == 1.0L)
    __result = 1.0L;
  else if (__y == 1.0L)
    __result = __x;
  else if (__y == 2.0L)
    __result = __x * __x;
  else if (__x == 10.0L)
    __asm("ftentox%.x %1, %0" : "=f" (__result) : "f" (__y));
  else if (__x == 2.0L)
    __asm("ftwotox%.x %1, %0" : "=f" (__result) : "f" (__y));
  else if (__x < 0.0L)
    {
      long double __temp = __m81_u (__rintl) (__y);
      if (__y == __temp)
	{
	  int i = (int) __y;
	  __result = __m81_u (expl) (__y * __m81_u (logl) (-__x));
	  if (i & 1)
	    __result = -__result;
	}
      else
	__result = __infnanl (0);
    }
  else
    __result = __m81_u(expl)(__y * __m81_u(logl)(__x));
  return __result;
}

extern __inline __CONSTVALUE long double
__m81_u(ceill)(long double __x) __CONSTVALUE2;
extern __inline __CONSTVALUE long double
__m81_u(ceill)(long double __x)
{
  long double __result;
  unsigned long int __ctrl_reg;
  __asm __volatile__ ("fmove%.l %!, %0" : "=dm" (__ctrl_reg));
  /* Set rounding towards positive infinity.  */
  __asm __volatile__ ("fmove%.l %0, %!" : /* No outputs.  */
		      : "dmi" (__ctrl_reg | 0x30));
  /* Convert X to an integer, using +Inf rounding.  */
  __asm __volatile__ ("fint%.x %1, %0" : "=f" (__result) : "f" (__x));
  /* Restore the previous rounding mode.  */
  __asm __volatile__ ("fmove%.l %0, %!" : /* No outputs.  */
		      : "dmi" (__ctrl_reg));
  return __result;
}

extern __inline long double
__m81_u(modfl)(long double __value, long double *__iptr);
extern __inline long double
__m81_u(modfl)(long double __value, long double *__iptr)
{
  long double __modf_int;
  __asm ("fintrz%.x %1, %0" : "=f" (__modf_int) : "f" (__value));
  *__iptr = __modf_int;
  return __value - __modf_int;
}

extern __inline __CONSTVALUE int
__m81_u(__isinfl)(long double __value) __CONSTVALUE2;
extern __inline __CONSTVALUE int
__m81_u(__isinfl)(long double __value)
{
  /* There is no branch-condition for infinity,
     so we must extract and examine the condition codes manually.  */
  unsigned long int __fpsr;
  __asm("ftst%.x %1\n"
	"fmove%.l %/fpsr, %0" : "=dm" (__fpsr) : "f" (__value));
  return (__fpsr & (2 << (3 * 8))) ? (__value < 0 ? -1 : 1) : 0;
}

extern __inline __CONSTVALUE int
__m81_u(__isnanl)(long double __value) __CONSTVALUE2;
extern __inline __CONSTVALUE int
__m81_u(__isnanl)(long double __value)
{
  char __result;
  __asm("ftst%.x %1\n"
	"fsun %0" : "=dm" (__result) : "f" (__value));
  return __result;
}

#else /* CONFIG_COLDFIRE */

#include <mathf.h>

#endif /* CONFIG_COLDFIRE */

__END_DECLS

#endif	/* GCC.  */
