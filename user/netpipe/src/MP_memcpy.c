/* This optimized memcpy requires gcc 3.x to be installed (needs xmmintrin.h) */

/*#define _INTEL */
#if defined (_INTEL)
#include <xmmintrin.h>
#else 
#include "xmmintrin.h"
#endif



#include <stdio.h>

/*construct a function that can do well on most bufferalignment */
#define LONGMSGSIZE (2.5*131072)    /* Long message size */    
/*#define BLOCKSIZE 131072 */
#define BLOCKSIZE  131072     /* Needs to be divisible by 16 */ 
#define PAGESIZE   4096
#define NUMPERPAGE 512        /* Number of elements fit in a page */
#define ALIGNMENT  16
/* #define P4 */

#if defined(P4)
#define CACHELINE     128     /* on Pentimum 4 */
#else
#define CACHELINE     32      /* on Pentimum 3 */
#endif

#define NTCOPY        1       /* Use nontemporal copy */
#define WACOPY        2       /* Write allocate copy  */ 
#define CBCOPY        3       /* 
                               * mixed copy, small message use  
                               * write allocate copy, and long   
                               * message use nontemporal copy
                               */ 

#define COPY_TYPE     CBCOPY
#define small_memcpy(dst,src,n) \
    { register unsigned long int dummy; \
    asm volatile ( \
      "rep; movsb\n\t" \
      :"=&D"(dst), "=&S"(src), "=&c"(dummy) \
      :"0" (dst), "1" (src),"2" (n) \
      : "memory");  }


extern int myproc; 
void ntcopy(void *dst, const void *src, int size); 
void memcpy_8(void *destination, const void *source, int nbytes);
void memcpy_16(void *destination, const void *source, int nbytes);

void MP_memcpy(void *dst, const void *src, int nbytes);

int intlog2(int i)
{
  float x = i;
  return (*(int*)&x >> 23) - 127;
}

/* 
 * This function optimize the memory copy if number of bytes
 * to transfer is not equal to 8   
 */
void memcpy_8(void *destination, const void *source, int nbytes)
{
  int nb_b4, nb_after;
  char *dest = (char *)destination, *src = (char *) source;

  nb_b4 = 8 - ((long int)src % 8);

  if( nb_b4 != 8 && nb_b4 <= nbytes) {  /* 
					 * Copy up to an 8-byte boundary first
                                         * considering that nbytes can be less
                                         * than nb_b4  
					 */
    memcpy( dest, src, nb_b4 );

    src += nb_b4;
    dest += nb_b4;
    nbytes -= nb_b4;

  }

  nb_after = nbytes % 8;
  nbytes -= nb_after;

  if( nbytes > 0 ) {      /* Copy the main data */

    memcpy( dest, src, nbytes );
  }

  if( nb_after > 0 ) {    /* Copy the last few bytes */

    src += nbytes;
    dest += nbytes;

    memcpy( dest, src, nb_after );

  }
}

void memcpy_16(void *destination, const void *source, int nbytes)
{
  int nb_b4, nb_after; 
  char *dest = (char *)destination, *src = (char *)source; 
 
  nb_b4 = 16 - ((int) dest % 16); 
  if (nb_b4 != 16 && nb_b4 <= nbytes) 
  { 
    memcpy(dest, src, nb_b4);
    src += nb_b4;
    dest += nb_b4;
    nbytes -= nb_b4; 
  } 

  /*memcpy(dest, src, nbytes);  */
  nb_after = nbytes % 16;
  nbytes -= nb_after;

  if ( nbytes > 0) {
    memcpy(dest, src, nbytes);
  } 

  if( nb_after > 0 ) {    
    src += nbytes;
    dest += nbytes;
    memcpy( dest, src, nb_after );
  }  
}

//#if defined(_INTEL)
void ntcopy(void *dst, const void *src, int size)
{
  int ii, jj, kk, N, delta, LEFT, blocksize, size1;

  double *a, *b;
  double temp;

  /* copy the first few bytes to make dest divisible by 8 */
  if (size <= ALIGNMENT)
  {
    memcpy(dst, (void *)src, size);  
    return;
  }

  delta = ((int)dst) & (ALIGNMENT - 1);
  if (delta != 0)
  {
    delta = ALIGNMENT - delta;
    size -= delta;
    memcpy(dst, (void *)src, delta);
  } 
  a = (double *)(src + delta);
  b = (double *)(dst + delta);
  N  = 2 * (size / 16);   /* number of doubles  */      
  LEFT = size % 16;  
  blocksize = N; 

  if (blocksize > BLOCKSIZE / 8)
    blocksize = BLOCKSIZE / 8;

  for (X3;;èi) 
  {
    if (N < blocksize) blocksize = N; 
    _mm_prefetch((char*)&a[0], _MM_HINT_NTA);
    /* prefetch a block of size blocksize */
    for (jj = 0; jj < blocksize; jj += NUMPERPAGE)  
    {
      /* prefetch one page of memory */  
      if (jj + NUMPERPAGE < blocksize ) 
      { 
        temp = a[jj + NUMPERPAGE]; /* TLB priming */
      }

      for (kk = jj + 16; kk < jj + NUMPERPAGE && kk < blocksize; kk += 16) {
        _mm_prefetch((char*)&a[kk], _MM_HINT_NTA);
      } 
    }

    if ( ((int) a) & (ALIGNMENT - 1) )
    {
      size1 = blocksize - blocksize % 16; 
      for (kk = 0; kk < size1; kk += 16) 
      {
        /* copy one cacheline (128 bytes) */  
        _mm_stream_ps((float*)&b[kk],
          _mm_loadu_ps((float*)&a[kk]));
        _mm_stream_ps((float*)&b[kk+2],
          _mm_loadu_ps((float*)&a[kk+2]));
        _mm_stream_ps((float*)&b[kk+4],
          _mm_loadu_ps((float*)&a[kk+4]));
        _mm_stream_ps((float*)&b[kk+6],
          _mm_loadu_ps((float*)&a[kk+6]));
        _mm_stream_ps((float*)&b[kk+8],
          _mm_loadu_ps((float*)&a[kk+8]));
        _mm_stream_ps((float*)&b[kk+10],
          _mm_loadu_ps((float*)&a[kk+10]));
        _mm_stream_ps((float*)&b[kk+12],
          _mm_loadu_ps((float*)&a[kk+12]));
        _mm_stream_ps((float*)&b[kk+14],
          _mm_loadu_ps((float*)&a[kk+14]));
      }

      for (kk = size1; kk <  blocksize; kk += 2)   
      {
        _mm_stream_ps((float*)&b[kk],
          _mm_loadu_ps((float*)&a[kk]));
      }
    }

    else 
    {
      size1 = blocksize - blocksize % 16;
      for (kk = 0; kk < size1; kk+=16) 
      {
        _mm_stream_ps((float*)&b[kk],
          _mm_load_ps((float*)&a[kk]));
        _mm_stream_ps((float*)&b[kk+2],
          _mm_load_ps((float*)&a[kk+2]));
        _mm_stream_ps((float*)&b[kk+4],
          _mm_load_ps((float*)&a[kk+4]));
        _mm_stream_ps((float*)&b[kk+6],
          _mm_load_ps((float*)&a[kk+6]));
        _mm_stream_ps((float*)&b[kk+8],
          _mm_load_ps((float*)&a[kk+8]));
        _mm_stream_ps((float*)&b[kk+10],
          _mm_load_ps((float*)&a[kk+10]));
        _mm_stream_ps((float*)&b[kk+12],
          _mm_load_ps((float*)&a[kk+12]));
        _mm_stream_ps((float*)&b[kk+14],
          _mm_load_ps((float*)&a[kk+14]));
      }
      for (kk = size1; kk < blocksize; kk += 2)
      {
        _mm_stream_ps((float*)&b[kk],
          _mm_load_ps((float*)&a[kk]));
      }
    } 
    /* finished copying one block  */
    a = a + blocksize;
    b = b + blocksize;
  } 
  _mm_sfence();

  
  if (LEFT > 0)
  {
    memcpy((char*)b, (char *)a, LEFT);  
    
  }
} 
//#endif

void  MP_memcpy(void *dst, const void *src, int nbytes) 
{
#if COPY_TYPE == WACOPY

  memcpy_16(dst, (void *)src, nbytes);

#elif COPY_TYPE == NTCOPY

  ntcopy(dst, src, nbytes); 

#elif COPY_TYPE == CBCOPY

  if (nbytes > LONGMSGSIZE)
    ntcopy(dst, src, nbytes);
  else
    memcpy_16(dst, src, nbytes);

#endif
}

 
