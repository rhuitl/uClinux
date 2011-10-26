/* Netpipe module for mpi-2 one-sided communications by Adam Oline */
#define USE_VOLATILE_RPTR
#include "netpipe.h"
#include <mpi.h>

MPI_Win win;

void Init(ArgStruct *p, int* pargc, char*** pargv)
{
  p->prot.use_get = 0;  /* Default to put   */
  p->prot.no_fence = 0; /* Default to fence */

  MPI_Init(pargc, pargv);
}

void Setup(ArgStruct *p)
{
  int nprocs;

  MPI_Comm_rank(MPI_COMM_WORLD, &p->prot.iproc);

  MPI_Comm_size(MPI_COMM_WORLD, &nprocs);

  if ( nprocs < 2 )
    {
      printf("Need at least 2 processes, we have %d\n", nprocs);
      exit(-2);
    }

  {
    char s[255], *ptr;
    gethostname(s,253);
    if( s[0] != '.' ) {                 /* just print the base name */
      ptr = strchr( s, '.');
      if( ptr != NULL ) *ptr = '\0';
    }
    printf("%d: %s\n",p->prot.iproc,s);
    fflush(stdout);
  }

  /* TODO: Finish changing netpipe such that it can run with > 2 procs */
  /* 0 <--> (nprocs - 1)
   * 1 <--> (nprocs - 2)
   * ...
   */
 
  p->tr = p->rcv = 0;
  if (p->prot.iproc == 0) {
    p->tr = 1;
    p->prot.nbor = nprocs-1;
  } else if( p->prot.iproc == nprocs-1 ) {
    p->rcv = 1;
    p->prot.nbor = 0;
  }
}

void Sync(ArgStruct *p)
{
  MPI_Win_fence(0, win);
}

void PrepareToReceive(ArgStruct *p)
{

}

void SendData(ArgStruct *p)
{
  int buf_offset = 0;

  /* If we're limiting cache effects, then we need to calculate the offset
   * from the beginning of the memory pool
   */
  if( !p->cache )
    buf_offset = p->s_ptr - p->s_buff;

  if( p->prot.use_get )
    MPI_Get(p->s_ptr, p->bufflen, MPI_BYTE, p->prot.nbor, buf_offset, 
            p->bufflen, MPI_BYTE, win);
  else
    MPI_Put(p->s_ptr, p->bufflen, MPI_BYTE, p->prot.nbor, buf_offset, 
            p->bufflen, MPI_BYTE, win);

  if (p->prot.no_fence == 0)
    MPI_Win_fence(0, win);

}

void RecvData(ArgStruct *p)
{
  /* If user specified 'no fence' option on cmd line, then we try to bypass
   * the fence call by waiting for the last byte to arrive.  The MPI-2
   * standard does not require any data to be written locally until a
   * synchronization call (such as fence) occurs, however, so this may
   * hang, depending on the MPI-2 implementation.  Currently works with
   * MP_Lite .
   */
     
  if( p->prot.no_fence ) {
    
    /* The conditional in the comparison below is necessary because we are
     * always waiting for a 'b' to arrive if in no-cache mode, but in cache
     * mode the character we are waiting for depends on whether we are the
     * transmitter or receiver.  Adding a little complexity here helps
     * us avoid more complexity elsewhere with regard to the no-cache code.
     * We cannot use the same character all the time with cache mode due
     * to timing issues.
     */
    while(p->r_ptr[p->bufflen-1] != 'a' + (p->cache ? 1 - p->tr : 1) )
      sched_yield(); /* Since we made r_ptr volatile, we don't necessarily
                      * need to call a function here encourage the compiler
                      * to reload it */
    
    p->r_ptr[p->bufflen-1] = 'a' + (p->cache ? p->tr : 0);

  } else {

    MPI_Win_fence(0, win);

  }

}

void SendTime(ArgStruct *p, double *t)
{
  MPI_Send(t, 1, MPI_DOUBLE, p->prot.nbor, 2, MPI_COMM_WORLD);
}

void RecvTime(ArgStruct *p, double *t)
{
  MPI_Status status;
  
  MPI_Recv(t, 1, MPI_DOUBLE, p->prot.nbor, 2, MPI_COMM_WORLD, &status);
}

void SendRepeat(ArgStruct *p, int rpt)
{
  MPI_Send(&rpt, 1, MPI_INT, p->prot.nbor, 2, MPI_COMM_WORLD);
}

void RecvRepeat(ArgStruct *p, int *rpt)
{
  MPI_Status status;
  
  MPI_Recv(rpt, 1, MPI_INT, p->prot.nbor, 2, MPI_COMM_WORLD, &status);
}

void CleanUp(ArgStruct *p)
{
  MPI_Finalize();
}

void Reset(ArgStruct *p)
{

}

void AfterAlignmentInit(ArgStruct *p)
{
  /* After mallocs and alignment, we need to create MPI Window */

  MPI_Win_create(p->r_buff, p->bufflen, 1, NULL, MPI_COMM_WORLD, &win);
}

