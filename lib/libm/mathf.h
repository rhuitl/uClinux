#ifndef _MATH_H
#define _MATH_H

#ifndef _MCONF_H
typedef struct {
 float r;
 float i;
} cmplxf;

typedef struct {
 double r;
 double i;
} cmplx;
#endif

#ifdef mc6800
#include <bits/nan.h>
#include <bits/huge_val.h>
#include <float.h>
#endif

/* Double precision constants */
#define M_E		2.7182818284590452354	/* e */
#define M_LOG2E		1.4426950408889634074	/* log_2 e */
#define M_LOG10E	0.43429448190325182765	/* log_10 e */
#define M_LN2		0.69314718055994530942	/* log_e 2 */
#define M_LN10		2.30258509299404568402	/* log_e 10 */
#define M_PI		3.14159265358979323846	/* pi */
#define M_PI_2		1.57079632679489661923	/* pi/2 */
#define M_PI_4		0.78539816339744830962	/* pi/4 */
#define M_1_PI		0.31830988618379067154	/* 1/pi */
#define M_2_PI		0.63661977236758134308	/* 2/pi */
#define M_2_SQRTPI	1.12837916709551257390	/* 2/sqrt(pi) */
#define M_SQRT2		1.41421356237309504880	/* sqrt(2) */
#define M_SQRT1_2	0.70710678118654752440	/* 1/sqrt(2) */

/* Single precision constants */
#define M_Ef		2.7182818284f		/* e */
#define M_LOG2Ef	1.4426950408f		/* log_2 e */
#define M_LOG10Ef	0.43429448190f		/* log_10 e */
#define M_LN2f		0.69314718055f		/* log_e 2 */
#define M_LN10f		2.3025850929f		/* log_e 10 */
#define M_PIf 		3.1415926535f		/* pi */
#define M_PI_2f		1.5707963267f		/* pi/2 */
#define M_PI_4f		0.78539816339f		/* pi/4 */
#define M_1_PIf		0.31830988618f		/* 1/pi */
#define M_2_PIf		0.63661977236f		/* 2/pi */
#define M_2_SQRTPIf	1.1283791670f		/* 2/sqrt(pi) */
#define M_SQRT2f	1.4142135623f		/* sqrt(2) */
#define M_SQRT1_2f	0.70710678118f		/* 1/sqrt(2) */

/* Double precision routines */
extern double fmod(double, double);
extern double modf(double, double *);

extern double acosh ( double x );
extern int airy ( double x, double *ai, double *aip, double *bi, double *bip );
extern double asin ( double x );
extern double acos ( double x );
extern double asinh ( double xx );
extern double atan ( double x );
extern double atan2 ( double y, double x );
extern double atanh ( double x );
extern double bdtrc ( int k, int n, double p );
extern double bdtr ( int k, int n, double p );
extern double bdtri ( int k, int n, double y );
extern double beta ( double a, double b );
extern double lbeta ( double a, double b );
extern double btdtr ( double a, double b, double x );
extern double cbrt ( double x );
extern double chbevl ( double x, double array[], int n );
extern double chdtrc ( double df, double x );
extern double chdtr ( double df, double x );
extern double chdtri ( double df, double y );
extern void clog ( cmplx *z, cmplx *w );
extern void cexp ( cmplx *z, cmplx *w );
extern void csin ( cmplx *z, cmplx *w );
extern void ccos ( cmplx *z, cmplx *w );
extern void ctan ( cmplx *z, cmplx *w );
extern void ccot ( cmplx *z, cmplx *w );
extern void casin ( cmplx *z, cmplx *w );
extern void cacos ( cmplx *z, cmplx *w );
extern void catan ( cmplx *z, cmplx *w );
extern void csinh ( cmplx *z, cmplx *w );
extern void casinh ( cmplx *z, cmplx *w );
extern void ccosh ( cmplx *z, cmplx *w );
extern void cacosh ( cmplx *z, cmplx *w );
extern void ctanh ( cmplx *z, cmplx *w );
extern void catanh ( cmplx *z, cmplx *w );
extern void cpow ( cmplx *a, cmplx *z, cmplx *w );
extern void cadd ( cmplx *a, cmplx *b, cmplx *c );
extern void csub ( cmplx *a, cmplx *b, cmplx *c );
extern void cmul ( cmplx *a, cmplx *b, cmplx *c );
extern void cdiv ( cmplx *a, cmplx *b, cmplx *c );
extern void cmov ( void *a, void *b );
extern void cneg ( cmplx *a );
extern double cabs ( cmplx *z );
extern void csqrt ( cmplx *z, cmplx *w );
extern double hypot ( double x, double y );
extern double cosh ( double x );
extern double dawsn ( double xx );
extern int drand ( double *a );
extern double ei ( double x );
extern double ellie ( double phi, double m );
extern double ellik ( double phi, double m );
extern double ellpe ( double x );
extern int ellpj ( double u, double m, double *sn, double *cn, double *dn, double *ph );
extern double ellpk ( double x );
extern double exp ( double x );
extern double exp10 ( double x );
extern double exp2 ( double x );
extern double expn ( int n, double x );
extern double expx2 ( double x, int sign );
extern double fabs ( double x );
extern double fac ( int i );
extern double fdtrc ( int ia, int ib, double x );
extern double fdtr ( int ia, int ib, double x );
extern double fdtri ( int ia, int ib, double y );
extern int fresnl ( double xxa, double *ssa, double *cca );
extern double gamma ( double x );
extern double lgam ( double x );
extern double gdtr ( double a, double b, double x );
extern double gdtrc ( double a, double b, double x );
extern double hyp2f1 ( double a, double b, double c, double x );
extern double hyperg ( double a, double b, double x );
extern double hyp2f0 ( double a, double b, double x, int type, double *err );
extern double i0 ( double x );
extern double i0e ( double x );
extern double i1 ( double x );
extern double i1e ( double x );
extern double igami ( double, double );
extern double incbet ( double aa, double bb, double xx );
extern double incbi ( double aa, double bb, double yy0 );
extern double igamc ( double a, double x );
extern double igam ( double a, double x );
extern int signbit ( double x );
extern int isnan ( double x );
extern int isfinite ( double x );
extern double iv ( double v, double x );
extern double j0 ( double x );
extern double y0 ( double x );
extern double j1 ( double x );
extern double y1 ( double x );
extern double jn ( int n, double x );
extern double jv ( double n, double x );
extern double k0 ( double x );
extern double k0e ( double x );
extern double k1 ( double x );
extern double k1e ( double x );
extern double kn ( int nn, double x );
extern double smirnov ( int n, double e );
extern double kolmogorov ( double y );
extern double smirnovi ( int n, double p );
extern double kolmogi ( double p );
extern double log ( double x );
extern double log2 ( double x );
extern double log10 ( double x );
extern long lrand ( void );
extern double nbdtrc ( int k, int n, double p );
extern double nbdtr ( int k, int n, double p );
extern double nbdtri ( int k, int n, double p );
extern double ndtr ( double a );
extern double erfc ( double a );
extern double erf ( double x );
extern double ndtri ( double );
extern double pdtrc ( int k, double m );
extern double pdtr ( int k, double m );
extern double pdtri ( int k, double y );
extern double plancki ( double w, double T );
extern double planckc ( double w, double T );
extern double planckd ( double w, double T );
extern double planckw ( double T );
extern double polevl ( double x, double coef[], int N );
extern double p1evl ( double x, double coef[], int N );
extern void polatn ( double num[], double den[], double ans[], int nn );
extern void polsqt ( double pol[], double ans[], int nn );
extern void polsin ( double x[], double y[], int nn );
extern void polcos ( double x[], double y[], int nn );
extern double polylog ( int n, double x );
extern void polini ( int maxdeg );
extern void polprt ( double a[], int na, int d );
extern void polclr ( double *a, int n );
extern void polmov ( double *a, int na, double *b );
extern void polmul ( double a[], int na, double b[], int nb, double c[] );
extern void poladd ( double a[], int na, double b[], int nb, double c[] );
extern void polsub ( double a[], int na, double b[], int nb, double c[] );
extern int poldiv ( double a[], int na, double b[], int nb, double c[] );
extern void polsbt ( double a[], int na, double b[], int nb, double c[] );
extern double poleva ( double a[], int na, double x );
extern double pow ( double x, double y );
extern double powi ( double x, int nn );
extern double psi ( double x );
extern double rgamma ( double x );
extern double round ( double x );
extern int shichi ( double x, double *si, double *ci );
extern int sici ( double x, double *si, double *ci );
extern double sin ( double x );
extern double cos ( double x );
extern double radian ( double d, double m, double s );
extern double sindg ( double x );
extern double cosdg ( double x );
extern double sinh ( double x );
extern double spence ( double x );
extern double stdtr ( int k, double t );
extern double stdtri ( int k, double p );
extern double onef2 ( double a, double b, double c, double x, double *err );
extern double threef0 ( double a, double b, double c, double x, double *err );
extern double struve ( double v, double x );
extern double yv ( double v, double x );
extern double tan ( double x );
extern double cot ( double x );
extern double tandg ( double x );
extern double cotdg ( double x );
extern double tanh ( double x );
extern double log1p ( double x );
extern double expm1 ( double x );
extern double cosm1 ( double x );
extern double yn ( int n, double x );
extern double zeta ( double x, double q );
extern double zetac ( double x );
extern double sqrt ( double x );
extern double ceil ( double x );
extern double floor ( double x );
extern double frexp ( double x, int *pw2 );
extern double ldexp ( double x, int pw2 );
extern int sprec ( void );
extern int dprec ( void );
extern int ldprec ( void );
extern int mtherr ( char *name, int code );

/* Single precision routines */
extern float acosf ( float x );
extern float acoshf ( float xx );
extern int airyf ( float xx, float *ai, float *aip, float *bi, float *bip );
extern float asinf ( float xx );
extern float asinhf ( float xx );
extern float atan2f ( float y, float x );
extern float atanf ( float xx );
extern float atanhf ( float xx );
extern float bdtrcf ( int k, int n, float pp );
extern float bdtrf ( int k, int n, float pp );
extern float bdtrif ( int k, int n, float yy );
extern float betaf ( float aa, float bb );
extern float cabsf ( cmplxf *z );
extern void cacosf ( cmplxf *z, cmplxf *w );
extern void caddf ( cmplxf *a, cmplxf *b, cmplxf *c );
extern void casinf ( cmplxf *z, cmplxf *w );
extern void catanf ( cmplxf *z, cmplxf *w );
extern float cbrtf ( float xx );
extern void cchshf ( float xx, float *c, float *s );
extern void ccosf ( cmplxf *z, cmplxf *w );
extern void ccotf ( cmplxf *z, cmplxf *w );
extern void cdivf ( cmplxf *a, cmplxf *b, cmplxf *c );
extern float ceilf ( float x );
extern void cexpf ( cmplxf *z, cmplxf *w );
extern float chbevlf ( float x, float *array, int n );
extern float chdtrcf ( float dff, float xx );
extern float chdtrf ( float dff, float xx );
extern float chdtrif ( float dff, float yy );
extern void clogf ( cmplxf *z, cmplxf *w );
extern void cmovf ( short *a, short *b );
extern void cmulf ( cmplxf *a, cmplxf *b, cmplxf *c );
extern void cnegf ( cmplxf *a );
extern float cosdgf ( float xx );
extern float cosf ( float xx );
extern float coshf ( float xx );
extern float cotdgf ( float x );
extern float cotf ( float x );
extern void csinf ( cmplxf *z, cmplxf *w );
extern void csqrtf ( cmplxf *z, cmplxf *w );
extern void csubf ( cmplxf *a, cmplxf *b, cmplxf *c );
extern void ctanf ( cmplxf *z, cmplxf *w );
extern float ctansf ( cmplxf *z );
extern float dawsnf ( float xxx );
extern int dprec ( void );
extern float ellief ( float phia, float ma );
extern float ellikf ( float phia, float ma );
extern float ellpef ( float xx );
extern int ellpjf ( float uu, float mm, float *sn, float *cn, float *dn, float *ph );
extern float ellpkf ( float xx );
extern float erfcf ( float aa );
extern float erff ( float xx );
extern float exp10f ( float xx );
extern float exp2f ( float xx );
extern float expf ( float xx );
extern float expnf ( int n, float xx );
extern float facf ( int i );
extern float fdtrcf ( int ia, int ib, float xx );
extern float fdtrf ( int ia, int ib, int xx );
extern float fdtrif ( int ia, int ib, float yy );
extern float floorf ( float x );
extern void fresnlf ( float xxa, float *ssa, float *cca );
extern float frexpf ( float x, int *pw2 );
extern float gammaf ( float xx );
extern float gdtrcf ( float aa, float bb, float xx );
extern float gdtrf ( float aa, float bb, float xx );
extern float hyp2f0f ( float aa, float bb, float xx, int type, float *err );
extern float hyp2f1f ( float aa, float bb, float cc, float xx );
extern float hypergf ( float aa, float bb, float xx );
extern float i0ef ( float x );
extern float i0f ( float x );
extern float i1ef ( float xx );
extern float i1f ( float xx );
extern float igamcf ( float aa, float xx );
extern float igamf ( float aa, float xx );
extern float igamif ( float aa, float yy0 );
extern float incbetf ( float aaa, float bbb, float xxx );
extern float incbif ( float aaa, float bbb, float yyy0 );
extern float incbpsf ( float aa, float bb, float xx );
extern float ivf ( float v, float x );
extern float j0f ( float xx );
extern float j1f ( float xx );
extern float jnf ( int n, float xx );
extern float jvf ( float nn, float xx );
extern float k0ef ( float xx );
extern float k0f ( float xx );
extern float k1ef ( float xx );
extern float k1f ( float xx );
extern float knf ( int nnn, float xx );
extern float ldexpf ( float x, int pw2 );
extern int ldprec ( void );
extern float lgamf ( float xx );
extern float log10f ( float xx );
extern float log2f ( float xx );
extern float logf ( float xx );
extern int mtherr ( char *name, int code );
extern float nbdtrcf ( int k, int n, float pp );
extern float nbdtrf ( int k, int n, float pp );
extern float ndtrf ( float aa );
extern float ndtrif ( float yy0 );
extern float onef2f ( float aa, float bb, float cc, float xx, float *err );
extern float p1evlf ( float xx, float *coef, int N );
extern float pdtrcf ( int k, float mm );
extern float pdtrf ( int k, float mm );
extern float pdtrif ( int k, float yy );
extern void poladdf ( float a[], int na, float b[], int nb, float c[] );
extern void polclrf ( float *a, int n );
extern int poldivf ( float a[], int na, float b[], int nb, float c[] );
extern float polevaf ( float *a, int na, float xx );
extern float polevlf ( float xx, float *coef, int N );
extern void polinif ( int maxdeg );
extern void polmovf ( float *a, int na, float *b );
extern void polmulf ( float a[], int na, float b[], int nb, float c[] );
extern void polprtf ( float *a, int na, int d );
extern void polsbtf ( float a[], int na, float b[], int nb, float c[] );
extern void polsubf ( float a[], int na, float b[], int nb, float c[] );
extern float powf ( float x, float y );
extern float powif ( float x, int nn );
extern float psif ( float xx );
extern float redupif ( float xx );
extern float rgammaf ( float xx );
extern int shichif ( float xx, float *si, float *ci );
extern int sicif ( float xx, float *si, float *ci );
extern float sindgf ( float xx );
extern float sinf ( float xx );
extern float sinhf ( float xx );
extern float spencef ( float xx );
extern int sprec ( void );
extern float sqrtf ( float xx );
extern float stdtrf ( int k, float tt );
extern float struvef ( float vv, float xx );
extern float tandgf ( float x );
extern float tanf ( float x );
extern float tanhf ( float xx );
extern float threef0f ( float aa, float bb, float cc, float xx, float *err );
extern float y0f ( float xx );
extern float y1f ( float xx );
extern float ynf ( int nn, float xx );
extern float yvf ( float vv, float xx );
extern float zetacf ( float xx );
extern float zetaf ( float xx, float qq );

#define rint(x) ((double) ((int) ((x) + 0.5)))

#endif
