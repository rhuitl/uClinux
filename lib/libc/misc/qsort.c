/*
 * This file lifted in toto from 'Dlibs' on the atari ST  (RdeBath)
 *
 * 
 *    Dale Schumacher                         399 Beacon Ave.
 *    (alias: Dalnefre')                      St. Paul, MN  55104
 *    dal@syntel.UUCP                         United States of America
 *  "It's not reality that's important, but how you perceive things."
 */
#include <string.h>

char *_qbuf = 0;		/* pointer to storage for qsort() */

#define	PIVOT			((i+j)>>1)
#define moveitem(dst,src,size)	if(dst != src) memcpy(dst, src, size)

/* Define these macros to optimise sorts of 2 and 4 byte objects.
 * Setting these options increase the code size a little (200 bytes each)
 * but they also increase performance too.  Currently, the 4 byte optimisation
 * is included and the 2 byte one not.  This will cover sorting pointers
 * to structures efficiently.
 */
#undef OPTIMISE_2
#define OPTIMISE_4


#ifdef OPTIMISE_2
static  void
_wqsort(base, lo, hi, cmp)
short *base;
int lo;
int hi;
int (*cmp) (const void *, const void *);
{
   short   k;
   int i, j, t;
   short *p = &k;

   while (hi > lo)
   {
      i = lo;
      j = hi;
      t = PIVOT;
      *p = base[t];
      base[t] = base[i];
      base[i] = *p;
      while (i < j)
      {
	 while (((*cmp) ((base + j), p)) > 0)
	    --j;
	 base[i] = base[j];
	 while ((i < j) && (((*cmp) ((base + i), p)) <= 0))
	    ++i;
	 base[j] = base[i];
      }
      base[i] = *p;
      if ((i - lo) < (hi - i))
      {
	 _wqsort(base, lo, (i - 1), cmp);
	 lo = i + 1;
      }
      else
      {
	 _wqsort(base, (i + 1), hi, cmp);
	 hi = i - 1;
      }
   }
}
#endif
#ifdef OPTIMISE_4
static  void
_lqsort(base, lo, hi, cmp)
long *base;
int lo;
int hi;
int (*cmp) (const void *, const void *);
{
   long  k;
   int i, j, t;
   long *p = &k;

   while (hi > lo)
   {
      i = lo;
      j = hi;
      t = PIVOT;
      *p = base[t];
      base[t] = base[i];
      base[i] = *p;
      while (i < j)
      {
	 while (((*cmp) ((base + j), p)) > 0)
	    --j;
	 base[i] = base[j];
	 while ((i < j) && (((*cmp) ((base + i), p)) <= 0))
	    ++i;
	 base[j] = base[i];
      }
      base[i] = *p;
      if ((i - lo) < (hi - i))
      {
	 _lqsort(base, lo, (i - 1), cmp);
	 lo = i + 1;
      }
      else
      {
	 _lqsort(base, (i + 1), hi, cmp);
	 hi = i - 1;
      }
   }
}
#endif
static void
_nqsort(base, lo, hi, size, cmp)
char *base;
int lo;
int hi;
int size;
int (*cmp) (const void *, const void *);
{
   int i, j;
   char *p = _qbuf;

   while (hi > lo)
   {
      i = lo;
      j = hi;
      p = (base + size * PIVOT);
      moveitem(_qbuf, p, size);
      moveitem(p, (base + size * i), size);
      moveitem((base + size * i), _qbuf, size);
      p = _qbuf;
      while (i < j)
      {
	 while (((*cmp) ((base + size * j), p)) > 0)
	    --j;
	 moveitem((base + size * i), (base + size * j), size);
	 while ((i < j) && (((*cmp) ((base + size * i), p)) <= 0))
	    ++i;
	 moveitem((base + size * j), (base + size * i), size);
      }
      moveitem((base + size * i), p, size);
      if ((i - lo) < (hi - i))
      {
	 _nqsort(base, lo, (i - 1), size, cmp);
	 lo = i + 1;
      }
      else
      {
	 _nqsort(base, (i + 1), hi, size, cmp);
	 hi = i - 1;
      }
   }
}

void
qsort(base, num, size, cmp)
void *base;
int   num;
int   size;
int   (*cmp) (const void *, const void *);
{
   char  _qtemp[128];

   if (_qbuf == 0)
   {
      if (size > sizeof(_qtemp))/* records too large! */
	 return;
      _qbuf = _qtemp;
   }
#ifdef OPTIMISE_2
   if (size == 2)
      _wqsort(base, 0, num - 1, cmp);
   else
#endif
#ifdef OPTIMISE_4
   if (size == 4)
      _lqsort(base, 0, num - 1, cmp);
   else
#endif
   _nqsort(base, 0, num - 1, size, cmp);
   if (_qbuf == _qtemp)
      _qbuf = 0;
}
