/*  This module is basically the rewritten ARMCI module written by Xuehua
*/
#include <stdio.h>
#include <netinet/in.h>
#include <netdb.h>

#include <mpi.h>
#include "armci.h"
#define USE_VOLATILE_RPTR /* need for polling on receive buffer */
#include "netpipe.h"

extern double *pTime;
extern int    *pNrepeat;


int npes, mype;
int nbor_r_buff_offset;

struct mnode_t {
    void *ptrs[2];   /* Will only use 2 pointers */
    int nbytes;
    struct mnode_t* next;
};

/* Pointers to first element of the linked list */
struct mnode_t *m_first = 0;


void mlink_front(struct mnode_t* node) {
    if (m_first != 0) node->next = m_first;
    else node->next = 0;
    m_first = node;
}


struct mnode_t *mfind(void* ptr, struct mnode_t** prev) {
    struct mnode_t *p, *n;

    if (m_first != 0) {
        if (m_first->ptrs[mype] != ptr) {
            for (p=m_first, n=p->next; n != 0; p=n, n=n->next) {
                if (n->ptrs[mype] == ptr) {
                   *prev = p;
                   return n;
                }
            }
        }
        else {
            *prev = 0;
            return m_first;
        }
    }
    else {
        *prev = 0;
        return 0;
    }
    
    ARMCI_Error("Cannot find pointer in linked list", -1);
    
}


void* munlink(struct mnode_t *node, struct mnode_t *prev) {

    if (node != 0) {
        if (prev != 0) prev->next = node->next;
        else m_first = node->next;
    }

    return node;
}



void* armci_malloc(int nbytes) {
    struct mnode_t *node = malloc(sizeof(struct mnode_t));

    if (node == 0) {
        ARMCI_Error("Cannot allocate memory", -1);
    }

    ARMCI_Malloc(node->ptrs, nbytes);

    node->nbytes = nbytes;
    mlink_front(node);

    return node->ptrs[mype];
}


void armci_free(void* ptr) {
    struct mnode_t *n, *p;

    n = mfind(ptr, &p);
    if (n != 0) munlink(n, p);

    /* XXX if n = 0, then we have a problem */

    ARMCI_Free(ptr);
}


void* remote_ptr(void* local) {
    struct mnode_t *n, *p;

    n = mfind(local, &p);  /* ignore p */
    if (n != 0) {
        return n->ptrs[1-mype];
    }
    else {
        return 0;
    }
}

/* aro */
int is_host_local(char* hostname)
{
  struct hostent* hostinfo;
  char* addr;
  char buf[1024];
  char cmd[80];
  FILE* output;

  hostinfo = gethostbyname(hostname);

  if(hostinfo == NULL) {
    fprintf(stderr, "Could not resolve hostname [%s] to IP address", hostname);
    fprintf(stderr, "Reason: ");

    switch(h_errno)
      {
      case HOST_NOT_FOUND:
        printf("host not found\n");
        break;

      case NO_ADDRESS:
        printf("no IP address available\n");
        break;

      case NO_RECOVERY:
        printf("name server error\n");
        break;

      case TRY_AGAIN:
        printf("temporary error on name server, try again later\n");
        break;

      }

    return -1;
  }

  addr = (char*)inet_ntoa(*(struct in_addr *)hostinfo->h_addr_list[0]);

  sprintf(cmd, "/sbin/ifconfig | grep %s", addr);

  output = popen(cmd, "r");
   
  if(output == NULL) {
    fprintf(stderr, "running /sbin/ifconfig failed\n");
    return -1;
  }
  
  if(fgets(buf, 1024, output) == NULL) {
    pclose(output);
    return 0;
  } else {
    pclose(output);
    return 1;
  } 
}

void chop(char* s)
{
  int i;
  for(i=0; s[i]!='\0'; s++)
    if(s[i]=='\n')
      s[i]='\0';
    
}

void set_armci_hostname()
{
  char buf[1024];
  FILE* hostfile = fopen("armci_hosts", "r");

  if(hostfile == NULL)
    return;

  while(fgets(buf, 1024, hostfile) != NULL) {
    chop(buf);/* remove trailing newline */
    if(is_host_local(buf)==1) {
      fprintf(stderr,"Setting ARMCI_HOSTNAME=%s\n", buf);
      if(setenv("ARMCI_HOSTNAME", buf, 1)==-1)
      fprintf(stderr, "Insufficient space in environment\n");
    }
  }

  fclose(hostfile);

}

void Init(ArgStruct *p, int* pargc, char*** pargv)
{
    MPI_Init(pargc, pargv);
}

void Setup(ArgStruct *p) {
    int e;

    set_armci_hostname(); /* aro */
    ARMCI_Init(); /* aro */

    e = MPI_Comm_size(MPI_COMM_WORLD, &npes);
    if (e != MPI_SUCCESS) {
        ARMCI_Error("Cannot obtain number of PEs", e);
    }
    else if (npes != 2) {
        ARMCI_Error("This program must be run on 2 PEs", -1);
    }

    e = MPI_Comm_rank(MPI_COMM_WORLD, &mype);
    if (e != MPI_SUCCESS) {
        ARMCI_Error("Cannot obtain PE rank", e);
    }

    if (npes != 2) {
        ARMCI_Error("You must run on 2 nodes", -1);
        /* ARMCI_Error terminates everything */
    }

    p->prot.flag = armci_malloc(sizeof(int));
    pTime = armci_malloc(sizeof(double));
    pNrepeat = armci_malloc(sizeof(int));

    p->tr = p->rcv = 0;
    if ((p->prot.ipe = mype) == 0) {
        p->tr = 1;
        p->prot.nbor = 1;
        *p->prot.flag = 1;
    }
    else {
        p->rcv = 1;
        p->prot.nbor = 0;
        *p->prot.flag = 0;
    }
}


void Sync(ArgStruct *p) {
    MPI_Barrier(MPI_COMM_WORLD);
}


void PrepareToReceive(ArgStruct *p) {
}


void SendData(ArgStruct *p) {
    int p_bytes;
    void *remote_buff;
    int buf_offset=0;

    p_bytes = p->bufflen;

    buf_offset  = nbor_r_buff_offset;
    buf_offset += p->s_ptr - p->s_buff;
    remote_buff = remote_ptr(p->r_buff_orig) + buf_offset;

    ARMCI_Put(p->s_ptr, remote_buff, p_bytes, p->prot.nbor);
    ARMCI_AllFence();  /* may be necessary or not */
}


void RecvData(ArgStruct *p) {

    while (p->r_ptr[p->bufflen-1] != 'a' + (p->cache ? 1 - p->tr : 1)) 
    {
       /* BUSY WAIT */
    }

    p->r_ptr[p->bufflen-1] = 'a' + (p->cache ? p->tr : 0);
}


void SendTime(ArgStruct *p, double *t) {
    int p_bytes;
    void *remote_buff;

    *pTime = *t;
    
    p_bytes = sizeof(double);
    remote_buff = remote_ptr(pTime);
    ARMCI_Put(pTime, remote_buff, p_bytes, p->prot.nbor);

    p_bytes = sizeof(int);
    remote_buff = remote_ptr((void*)p->prot.flag);
    ARMCI_Put((void*)p->prot.flag, remote_buff, p_bytes, p->prot.nbor);
}


void RecvTime(ArgStruct *p, double *t) {

    while (*p->prot.flag != p->prot.ipe) 
    {
       /* BUSY WAIT */   
    }

    *t = *pTime; 
    *p->prot.flag = p->prot.nbor;
}


void SendRepeat(ArgStruct *p, int rpt) {
    void *remote_buff;
    int p_bytes;

    *pNrepeat = rpt;

    p_bytes = sizeof(int);
    remote_buff = remote_ptr(pNrepeat);
    ARMCI_Put(pNrepeat, remote_buff, p_bytes, p->prot.nbor);

    p_bytes = sizeof(int);
    remote_buff = remote_ptr((void*)p->prot.flag);
    ARMCI_Put((void*)p->prot.flag, remote_buff, p_bytes, p->prot.nbor);

}


void RecvRepeat(ArgStruct *p, int *rpt) {
    void *remote_buff;

    while (*p->prot.flag != p->prot.ipe)
    {
       /* BUSY WAIT */
    }
    
    *rpt = *pNrepeat;
    *p->prot.flag = p->prot.nbor;
}


void  CleanUp(ArgStruct *p) {
    ARMCI_Finalize();

}



void Reset(ArgStruct *p)
{

}

void AfterAlignmentInit(ArgStruct *p)
{
  MPI_Status s;

  /* Calculate difference between malloc'ed buffer and aligned buffer */

  int my_r_buff_offset = p->r_buff - p->r_buff_orig;

  /* Exchange offset data */

  MPI_Send(&my_r_buff_offset, 1, MPI_INT, p->prot.nbor, 0, MPI_COMM_WORLD);

  MPI_Recv(&nbor_r_buff_offset, 1, MPI_INT, p->prot.nbor,0,MPI_COMM_WORLD, &s);
  
}

void MyMalloc(ArgStruct *p, int bufflen, int soffset, int roffset)
{

/* the MAX() is easier than another if clause and the offsets should be
   small enough for this to never matter */

    p->r_buff = armci_malloc(bufflen+MAX(soffset,roffset));

    if(!p->cache)
      p->s_buff = armci_malloc(bufflen+soffset);

}
void FreeBuff(char *buff1, char* buff2)
{

  if(buff1 != NULL)
    armci_free(buff1);

  if(buff2 != NULL)
    armci_free(buff2);
}

