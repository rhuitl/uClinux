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
/*     * mpi.c              ---- MPI calls source                            */
/*****************************************************************************/
#include    "netpipe.h"
#include    <sndrcv.h>

void RCV_(long *type, void *buf, long *lenbuf, long *lenmes, long *nodesel, long *nodefrom, long *sync);
void SND_(long *type, void *buf, long *lenbuf, long *node, long *sync);

void Init(ArgStruct *p, int* pargc, char*** pargv)
{
    PBEGIN_(*pargc, *pargv);
}

void Setup(ArgStruct *p)
{
    long nprocs;

    nprocs      = NNODES_();
    p->prot.nid = NODEID_();
    {
        char s[255];
        gethostname(s,253);
        printf("%d: %s\n",p->prot.nid,s); fflush(stdout);
    }

    if (nprocs < 2)
    {
        printf("Need at least two processes, we have %d\n", nprocs); fflush(stdout);
        exit(-2);
    }

    p->tr = p->rcv = 0;
    if (p->prot.nid == 0) {
        p->tr = 1;
        p->prot.nbor = nprocs-1;
    } else if( p->prot.nid == nprocs-1 ) {
        p->rcv = 1;
        p->prot.nbor = 0;
    }
}

void Sync(ArgStruct *p)
{
    long type = MSGCHR;

    SYNCH_(&type);
}

void PrepareToReceive(ArgStruct *p)
{
        /*
          The TCGMSG interface doesn't have a method to pre-post
          a buffer for reception of data.
        */
}

void SendData(ArgStruct *p)
{
  long type = MSGCHR;
  long sync_snd = 0;
  long lbufflen = p->bufflen;
  
    SND_( &type, p->s_ptr, &lbufflen, &p->prot.nbor, &sync_snd);
}

void RecvData(ArgStruct *p)
{
  long lenmes;
  long nodefrom;
  long type = MSGCHR;
  long sync_rcv = 1;
  long lbufflen = p->bufflen;

    RCV_ ( &type, p->r_ptr, &lbufflen, &lenmes, &p->prot.nbor, &nodefrom, &sync_rcv) ;
}


void SendTime(ArgStruct *p, double *t)
{
   long ttype;
   long lenbuf;
   long sync_snd = 1;

   ttype = MSGDBL;
   lenbuf = sizeof(double);
   SND_( &ttype, t, &lenbuf, &p->prot.nbor, &sync_snd);
}

void RecvTime(ArgStruct *p, double *t)
{
   long lenmes;
   long nodefrom;
   long ttype;
   long lenbuf;
   long sync_rcv = 1;

   ttype = MSGDBL;
   lenbuf = sizeof(double);
   RCV_( &ttype, t, &lenbuf, &lenmes, &p->prot.nbor, &nodefrom, &sync_rcv);
}

void SendRepeat(ArgStruct *p, int n)
{
   long ttype;
   long lenbuf;
   long sync_snd = 1;

   ttype = MSGINT;
   lenbuf = sizeof(int);
   SND_( &ttype, &n, &lenbuf, &p->prot.nbor, &sync_snd);
}

void RecvRepeat(ArgStruct *p, int *n)
{
   long lenmes;
   long nodefrom;
   long ttype;
   long lenbuf;
   long sync_rcv = 1;

   ttype = MSGINT;
   lenbuf = sizeof(int);
   RCV_( &ttype, n, &lenbuf, &lenmes, &p->prot.nbor, &nodefrom, &sync_rcv);
}

void CleanUp(ArgStruct *p)
{
        PEND_();
}


void Reset(ArgStruct *p)
{

}


void AfterAlignmentInit(ArgStruct *p)
{

}
