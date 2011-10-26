/*****************************************************************************/
/* "NetPIPE" -- Network Protocol Independent Performance Evaluator.          */
/* Copyright 1997, 1998 Iowa State University Research Foundation, Inc.      */
/*                                                                           */
/* This program is free software; you can redistribute it and/or modify      */
/* it under the terms of the GNU General Public License as published by      */
/* the Free Software Foundation.  You should have received a copy of the     */
/* GNU General Public License along with this program; if not, write to the  */
/* Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.   */
/*                                                                           */
/*     * memcpy.c           ---- single process memory copy                  */
/*****************************************************************************/
#include    "netpipe.h"
/*#undef SPLIT_MEMCPY*/

#ifdef USE_MP_MEMCPY
void MP_memcpy();
#endif


void Init(ArgStruct *p, int* pargc, char*** pargv)
{
  /* Print out message about results */

  printf("\n");
  printf("  *** Note about memcpy module results ***  \n");
  printf("\n");
  printf("The memcpy module is sensitive to the L1 and L2 cache sizes,\n" \
         "the size of the cache-lines, and the compiler.  The following\n" \
         "may help to interpret the results:\n" \
         "\n" \
         "* With cache effects and no perturbations (NPmemcpy -p 0),\n" \
         "    the plot will show 2 peaks.  The first peak is where data is\n" \
         "    copied from L1 cache to L1, peaking around half the L1 cache\n" \
         "    size.  The second peak is where data is copied from the L2 cache\n" \
         "    to L2, peaking around half the L2 cache size.  The curve then\n" \
         "    will drop off as messages are copied from RAM through the caches\n" \
         "    and back to RAM.\n" \
         "\n" \
         "* Without cache effects and no perturbations (NPmemcpy -I -p 0).\n" \
         "    Data always starts in RAM, and is copied through the caches\n" \
         "    up in L1, L2, or RAM depending on the message size.\n"\
         "\n" \
         "* Compiler effects (NPmemcpy)\n" \
         "    The memcpy() function in even current versions of glibc is\n"\
         "    poorly optimized.  Performance is great when the message size\n" \
         "    is divisible by 4 bytes, but other sizes revert to a byte-by-byte\n" \
         "    copy that can be 4-5 times slower.  This produces sharp peaks\n" \
         "    in the curve that are not seen using other compilers.\n" \
         );
  printf("\n");

  p->tr = 1;
  p->rcv = 0;
}

void Setup(ArgStruct *p)
{
}   

void Sync(ArgStruct *p)
{
}

void PrepareToReceive(ArgStruct *p)
{
}

void SendData(ArgStruct *p)
{
    int nbytes = p->bufflen, nleft;
    char *src = p->s_ptr, *dest = p->r_ptr;

#ifdef USE_MP_MEMCPY

    MP_memcpy(dest, src, nbytes);

#else

    memcpy(dest, src, nbytes);

#endif
}

void RecvData(ArgStruct *p)
{
    int nbytes = p->bufflen, nleft;
    char *src = p->s_ptr, *dest = p->r_ptr;

#ifdef USE_MP_MEMCPY

    MP_memcpy(src, dest, nbytes);

#else

    memcpy(src, dest, nbytes);

#endif
}

void SendTime(ArgStruct *p, double *t)
{
}

void RecvTime(ArgStruct *p, double *t)
{
}

void SendRepeat(ArgStruct *p, int rpt)
{
}

void RecvRepeat(ArgStruct *p, int *rpt)
{
}

void CleanUp(ArgStruct *p)
{
}



void Reset(ArgStruct *p)
{

}


void AfterAlignmentInit(ArgStruct *p)
{

}
