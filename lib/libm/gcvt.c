
#include "mathf.h"
#include <stdio.h>

#define PSH(X) (*(buf++)=(X))
#define PSH1(X) (*(buf--)=(X))
#define PEEK() buf[-1]
#define POP() *(--buf) = '\0'

#define PLUS 1
#define SPACE 2

#define fabs(x) ((x)<0 ? (-x) : (x))

/* FIXME: This file contains roundoff error */

#ifdef original_hacky_gcvt

char * gcvt(double f, size_t ndigit, char * buf)
{
  int i;
  int z;
  int flags = 0;
  int exp = 0;
  char *c = buf;

  if (f < 0.0f) {
    PSH('-');
    f = -f;
  } else {
    if (flags & PLUS) PSH('+');
    if (flags & SPACE) PSH(' ');
  }
  
  if (f) {
    while (f < 1.0f) {
      f *=10.0f;
      exp--;
    }

    while (f >= 10.0f) {
      f /=10.0f;
      exp++;
    }
  }

  while ((exp > 0) && (exp < 7)) {
	  PSH('0'+f);
	  z = f;
	  f -= z;
	  f *= 10.0f;
  	exp--;
  }

  PSH('0'+f);
  z = f;
  f -= z;
  f *= 10.0f;

  PSH('.');

  for (i=0;i<ndigit;i++) {
    PSH('0'+f);
    z = f;
    f -= z;
    f *= 10;
  }
  
  if (exp != 0) {
	  PSH('e');
	  if (exp < 0) {
	    PSH('-');
	    exp = -exp;
	  } else {
	    PSH('+');
	  }
	  
	  PSH('0'+exp/10%10);
	  PSH('0'+exp%10);

 }

  PSH(0);

  return c;
}

#else
char * gcvt(double f, size_t ndigit, char * buf)
{
  int i;
  unsigned long long z,k;
  int exp = 0;
  char *c = buf;
  double f2,t,scal;
  int   sign = 0;

  if((int)ndigit == -1)
    ndigit = 5;

  /* Unsigned long long only allows for 20 digits of precision
   * which is already more than double supports, so we limit the
   * digits to this.  long double might require an increase if it is ever
   * implemented.
   */
  if (ndigit > 20)
	  ndigit = 20;
  
  if (f < 0.0) {
    sign = 1;
    f = -f;
	 buf++;
  }

  scal = 1;
  for (i=ndigit; i>0; i--)
	  scal *= 10;
  k = f + 0.1 / scal;
  f2 = f - k;
  if (!f) {
    PSH('0');
    if(ndigit > 0)
      PSH('.');
    for (i=0;i<ndigit;i++)
      PSH('0');
  	   PSH(0);
  	 return c;
  }

  i = 1;
  while (f >= 10.0) {
  	f /= 10.0;
  	i++;
  }

  buf += i + ndigit + 1; 	

  PSH1(0);

  if(ndigit > 0) {	
	  t = f2 * scal;
	 z = t + 0.5;
    for (i = 0;i < ndigit;i++)
    {
      PSH1('0'+ (z % 10));
	   z /= 10;
    }
    PSH1('.');
  }
  else
    PSH1(0);

  do {
    PSH1('0'+ (k % 10));
    k /= 10;
  }while (k);

  if (sign)
    PSH1('-');
  return c;
}
#endif

