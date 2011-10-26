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
/*     * MPI.c              ---- MPI calls source                            */
/*****************************************************************************/
#include    "netpipe.h"
#include    <mpi.h>

#ifdef BSEND
char *messbuff;
#define MAXBUFSIZE (10*1024*1024)
#endif


/* Initialize vars in Init() that may be changed by parsing the command args */

void Init(ArgStruct *p, int* pargc, char*** pargv)
{
  p->source_node = 0;  /* Default source node */

  MPI_Init(pargc, pargv);
}

void Setup(ArgStruct *p)
{
    int nprocs;

    MPI_Comm_rank(MPI_COMM_WORLD, &p->prot.iproc);
    MPI_Comm_size(MPI_COMM_WORLD, &nprocs);

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

    if (nprocs < 2)
    {
        printf("Need at least two processes (only given %d)\n", nprocs);
        exit(-2);
    }

    p->tr = p->rcv = 0;
    if( p->prot.iproc == 0 ) {
        p->tr = 1;
        p->prot.nbor = nprocs-1;
    } else if( p->prot.iproc == nprocs-1 ) {
        p->rcv = 1;
        p->prot.nbor = 0;
    }

       /* p->source_node may already have been set to -1 (MPI_ANY_SOURCE)
        * by specifying a -z on the command line.  If not, set the source
        * node normally. */

    if( p->source_node == 0 ) p->source_node = p->prot.nbor;

#ifdef BSEND
    messbuff = (char *)malloc(MAXBUFSIZE * sizeof(char));
    if (messbuff == NULL)
    {
        printf("Can't allocate for message buffer\n");
        exit(-1);
    }
    MPI_Buffer_attach(messbuff, MAXBUFSIZE);
    p->upper = MAXBUFSIZE;
#endif

    if( p->bidir ) {
        printf("MPI implementations do not have to guarantee message progress.\n");
        printf("You may need to run using -a to avoid locking up.\n\n");
    }
}   

void Sync(ArgStruct *p)
{
    MPI_Barrier(MPI_COMM_WORLD);
}

static int recvPosted = 0;
static MPI_Request recvRequest;

void PrepareToReceive(ArgStruct *p)
{
    /*
      Providing a buffer for reception of data in advance of
      the sender sending the data provides a major performance
      boost on some implementations of MPI, particularly shared
      memory implementations on the Cray T3E and Intel Paragon.
    */
    if (recvPosted)
    {
        printf("Can't prepare to receive: outstanding receive!\n");
        exit(-1);
    }
    MPI_Irecv(p->r_ptr, p->bufflen, MPI_BYTE,
    p->source_node, 1, MPI_COMM_WORLD, &recvRequest);
    recvPosted = -1;
}

void SendData(ArgStruct *p)
{
#ifdef BSEND
    MPI_Bsend(p->s_ptr, p->bufflen, MPI_BYTE, p->prot.nbor, 1, MPI_COMM_WORLD);
#else
   if(p->syncflag)
      MPI_Ssend(p->s_ptr,p->bufflen, MPI_BYTE, p->prot.nbor,1,MPI_COMM_WORLD);
   else
      MPI_Send(p->s_ptr, p->bufflen, MPI_BYTE, p->prot.nbor, 1, MPI_COMM_WORLD);
#endif
}

void RecvData(ArgStruct *p)
{
    MPI_Status status;
    if (recvPosted)
    {
        MPI_Wait(&recvRequest, &status);
        recvPosted = 0;
    }
    else
    {
        MPI_Recv(p->r_ptr, p->bufflen, MPI_BYTE, 
        p->source_node, 1, MPI_COMM_WORLD, &status);
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

    MPI_Recv(rpt, 1, MPI_INT, p->source_node, 2, MPI_COMM_WORLD, &status);
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

}

