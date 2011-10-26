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
/*       ib.c              ---- Infiniband module for the Mellanox VAPI      */
/*****************************************************************************/

#define USE_VOLATILE_RPTR /* needed for polling on last byte of recv buffer */
#include    "netpipe.h"
#include    <stdio.h>
#include    <getopt.h>

/* Debugging output macro */

FILE* logfile;

#if 0
#define LOGPRINTF(_format, _aa...) fprintf(logfile, __FUNCTION__": " _format, ##_aa); fflush(logfile)
#else
#define LOGPRINTF(_format, _aa...)
#endif

/* Header files needed for Infiniband */

#include    "vapi.h"        /* Mellanox Verbs API */
#include    "evapi.h"       /* Mellanox Verbs API extension */
#include    "vapi_common.h" /* Mellanox VIP layer of HCA Verbs */

/* Global vars */

static VAPI_hca_hndl_t     hca_hndl=VAPI_INVAL_HNDL;
static VAPI_hca_port_t     hca_port;
static int                 port_num;
static IB_lid_t            lid;
static IB_lid_t            d_lid;
static VAPI_pd_hndl_t      pd_hndl=VAPI_INVAL_HNDL;
static VAPI_cqe_num_t      num_cqe;
static VAPI_cqe_num_t      act_num_cqe;
static VAPI_cq_hndl_t      s_cq_hndl=VAPI_INVAL_HNDL;
static VAPI_cq_hndl_t      r_cq_hndl=VAPI_INVAL_HNDL;
static EVAPI_compl_handler_hndl_t ceh_hndl=VAPI_INVAL_HNDL;
static VAPI_mrw_t          mr_in;
static VAPI_mrw_t          s_mr_out;
static VAPI_mrw_t          r_mr_out;
static VAPI_mr_hndl_t      s_mr_hndl=VAPI_INVAL_HNDL;
static VAPI_mr_hndl_t      r_mr_hndl=VAPI_INVAL_HNDL;
static VAPI_qp_init_attr_t qp_init_attr;
static VAPI_qp_prop_t      qp_prop;
static VAPI_qp_hndl_t      qp_hndl=VAPI_INVAL_HNDL;
static VAPI_qp_num_t       d_qp_num;
static VAPI_qp_attr_mask_t qp_attr_mask;
static VAPI_qp_attr_t      qp_attr;
static VAPI_qp_cap_t       qp_cap;
static VAPI_wc_desc_t      wc;
static int                 max_wq=50000;
static void*               remote_address;
static VAPI_rkey_t         remote_key;
static volatile int        receive_complete;

/* Local prototypes */

void event_handler(VAPI_hca_hndl_t, VAPI_cq_hndl_t, void*);

/* Function definitions */

void Init(ArgStruct *p, int* pargc, char*** pargv)
{
   /* Set defaults
    */
   p->prot.ib_mtu = MTU1024;             /* 1024 Byte MTU                    */
   p->prot.commtype = NP_COMM_SENDRECV;  /* Use Send/Receive communications  */
   p->prot.comptype = NP_COMP_LOCALPOLL; /* Use local polling for completion */
   p->tr = 0;                            /* I am not the transmitter         */
   p->rcv = 1;                           /* I am the receiver                */      
}

void Setup(ArgStruct *p)
{

 int one = 1;
 int sockfd;
 struct sockaddr_in *lsin1, *lsin2;      /* ptr to sockaddr_in in ArgStruct */
 char *host;
 struct hostent *addr;
 struct protoent *proto;
 int send_size, recv_size, sizeofint = sizeof(int);
 struct sigaction sigact1;
 char logfilename[80];

 /* Sanity check */
 if( p->prot.commtype == NP_COMM_RDMAWRITE && 
     p->prot.comptype != NP_COMP_LOCALPOLL ) {
   fprintf(stderr, "Error, RDMA Write may only be used with local polling.\n");
   fprintf(stderr, "Try using RDMA Write With Immediate Data with vapi polling\n");
   fprintf(stderr, "or event completion\n");
   exit(-1);
 }
 
 /* Open log file */
 sprintf(logfilename, ".iblog%d", 1 - p->tr);
 logfile = fopen(logfilename, "w");

 host = p->host;                           /* copy ptr to hostname */ 

 lsin1 = &(p->prot.sin1);
 lsin2 = &(p->prot.sin2);

 bzero((char *) lsin1, sizeof(*lsin1));
 bzero((char *) lsin2, sizeof(*lsin2));

 if ( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
   printf("NetPIPE: can't open stream socket! errno=%d\n", errno);
   exit(-4);
 }

 if(!(proto = getprotobyname("tcp"))){
   printf("NetPIPE: protocol 'tcp' unknown!\n");
   exit(555);
 }

 if (p->tr){                                  /* if client i.e., Sender */


   if (atoi(host) > 0) {                   /* Numerical IP address */
     lsin1->sin_family = AF_INET;
     lsin1->sin_addr.s_addr = inet_addr(host);

   } else {
      
     if ((addr = gethostbyname(host)) == NULL){
       printf("NetPIPE: invalid hostname '%s'\n", host);
       exit(-5);
     }

     lsin1->sin_family = addr->h_addrtype;
     bcopy(addr->h_addr, (char*) &(lsin1->sin_addr.s_addr), addr->h_length);
   }

   lsin1->sin_port = htons(p->port);

 } else {                                 /* we are the receiver (server) */
   
   bzero((char *) lsin1, sizeof(*lsin1));
   lsin1->sin_family      = AF_INET;
   lsin1->sin_addr.s_addr = htonl(INADDR_ANY);
   lsin1->sin_port        = htons(p->port);
   
   if (bind(sockfd, (struct sockaddr *) lsin1, sizeof(*lsin1)) < 0){
     printf("NetPIPE: server: bind on local address failed! errno=%d", errno);
     exit(-6);
   }

 }

 if(p->tr)
   p->commfd = sockfd;
 else
   p->servicefd = sockfd;

 

 /* Establish tcp connections */

 establish(p);

 /* Initialize Mellanox Infiniband */

 if(initIB(p) == -1) {
   CleanUp(p);
   exit(-1);
 }
}   

int initIB(ArgStruct *p)
{
  VAPI_ret_t          ret;

  /* Open HCA */

  /* open hca just in case it was not opened by system earlier */
  ret = VAPI_open_hca("InfiniHost0", &hca_hndl); 

  ret = EVAPI_get_hca_hndl("InfiniHost0", &hca_hndl);
  if(ret != VAPI_OK) {
    fprintf(stderr, "Error opening Infiniband HCA: %s\n", VAPI_strerror(ret));
    return -1;
  } else {
    LOGPRINTF("Opened Infiniband HCA\n");
  }

  /* Get HCA properties */

  port_num=1;
  ret = VAPI_query_hca_port_prop(hca_hndl, (IB_port_t)port_num, 
                                 (VAPI_hca_port_t *)&hca_port);
  if(ret != VAPI_OK) {
    fprintf(stderr, "Error querying Infiniband HCA: %s\n", VAPI_strerror(ret));
    return -1;
  } else {
    LOGPRINTF("Queried Infiniband HCA\n");
  }
  lid = hca_port.lid;
  LOGPRINTF("  lid = %d\n", lid);


  /* Allocate Protection Domain */

  ret = VAPI_alloc_pd(hca_hndl, &pd_hndl);
  if(ret != VAPI_OK) {
    fprintf(stderr, "Error allocating PD: %s\n", VAPI_strerror(ret));
    return -1;
  } else {
    LOGPRINTF("Allocated Protection Domain\n");
  }


  /* Create send completion queue */
  
  num_cqe = 30000; /* Requested number of completion q elements */
  ret = VAPI_create_cq(hca_hndl, num_cqe, &s_cq_hndl, &act_num_cqe);
  if(ret != VAPI_OK) {
    fprintf(stderr, "Error creating send CQ: %s\n", VAPI_strerror(ret));
    return -1;
  } else {
    LOGPRINTF("Created Send Completion Queue with %d elements\n", act_num_cqe);
  }


  /* Create recv completion queue */
  
  num_cqe = 20000; /* Requested number of completion q elements */
  ret = VAPI_create_cq(hca_hndl, num_cqe, &r_cq_hndl, &act_num_cqe);
  if(ret != VAPI_OK) {
    fprintf(stderr, "Error creating recv CQ: %s\n", VAPI_strerror(ret));
    return -1;
  } else {
    LOGPRINTF("Created Recv Completion Queue with %d elements\n", act_num_cqe);
  }


  /* Placeholder for MR */


  /* Create Queue Pair */

  qp_init_attr.cap.max_oust_wr_rq = max_wq; /* Max outstanding WR on RQ      */
  qp_init_attr.cap.max_oust_wr_sq = max_wq; /* Max outstanding WR on SQ      */
  qp_init_attr.cap.max_sg_size_rq = 1; /* Max scatter/gather entries on RQ */
  qp_init_attr.cap.max_sg_size_sq = 1; /* Max scatter/gather entries on SQ */
  qp_init_attr.pd_hndl            = pd_hndl; /* Protection domain handle   */
  qp_init_attr.rdd_hndl           = 0; /* Reliable datagram domain handle  */
  qp_init_attr.rq_cq_hndl         = r_cq_hndl; /* CQ handle for RQ         */
  qp_init_attr.rq_sig_type        = VAPI_SIGNAL_REQ_WR; /* Signalling type */
  qp_init_attr.sq_cq_hndl         = s_cq_hndl; /* CQ handle for RQ         */
  qp_init_attr.sq_sig_type        = VAPI_SIGNAL_REQ_WR; /* Signalling type */
  qp_init_attr.ts_type            = IB_TS_RC; /* Transmission type         */
  
  ret = VAPI_create_qp(hca_hndl, &qp_init_attr, &qp_hndl, &qp_prop);
  if(ret != VAPI_OK) {
    fprintf(stderr, "Error creating Queue Pair: %s\n", VAPI_strerror(ret));
    return -1;
  } else {
    LOGPRINTF("Created Queue Pair, max outstanding WR on RQ: %d, on SQ: %d\n",
              qp_prop.cap.max_oust_wr_rq, qp_prop.cap.max_oust_wr_sq);
  }


  /* Exchange lid and qp_num with other node */
  
  if( write(p->commfd, &lid, sizeof(lid) ) != sizeof(lid) ) {
    fprintf(stderr, "Failed to send lid over socket\n");
    return -1;
  }
  if( write(p->commfd, &qp_prop.qp_num, sizeof(qp_prop.qp_num) ) != sizeof(qp_prop.qp_num) ) {
    fprintf(stderr, "Failed to send qpnum over socket\n");
    return -1;
  }
  if( read(p->commfd, &d_lid, sizeof(d_lid) ) != sizeof(d_lid) ) {
    fprintf(stderr, "Failed to read lid from socket\n");
    return -1;
  }
  if( read(p->commfd, &d_qp_num, sizeof(d_qp_num) ) != sizeof(d_qp_num) ) {
    fprintf(stderr, "Failed to read qpnum from socket\n");
    return -1;
  }
  
  LOGPRINTF("Local: lid=%d qp_num=%d Remote: lid=%d qp_num=%d\n",
         lid, qp_prop.qp_num, d_lid, d_qp_num);


  /* Bring up Queue Pair */
  
  /******* INIT state ******/

  QP_ATTR_MASK_CLR_ALL(qp_attr_mask);

  qp_attr.qp_state = VAPI_INIT;
  QP_ATTR_MASK_SET(qp_attr_mask, QP_ATTR_QP_STATE);

  qp_attr.pkey_ix = 0;
  QP_ATTR_MASK_SET(qp_attr_mask, QP_ATTR_PKEY_IX);

  qp_attr.port = port_num;
  QP_ATTR_MASK_SET(qp_attr_mask, QP_ATTR_PORT);

  qp_attr.remote_atomic_flags = VAPI_EN_REM_WRITE | VAPI_EN_REM_READ;
  QP_ATTR_MASK_SET(qp_attr_mask, QP_ATTR_REMOTE_ATOMIC_FLAGS);

  ret = VAPI_modify_qp(hca_hndl, qp_hndl, &qp_attr, &qp_attr_mask, &qp_cap);
  if(ret != VAPI_OK) {
    fprintf(stderr, "Error modifying QP to INIT: %s\n", VAPI_strerror(ret));
    return -1;
  }

  LOGPRINTF("Modified QP to INIT\n");

  /******* RTR (Ready-To-Receive) state *******/

  QP_ATTR_MASK_CLR_ALL(qp_attr_mask);

  qp_attr.qp_state = VAPI_RTR;
  QP_ATTR_MASK_SET(qp_attr_mask, QP_ATTR_QP_STATE);

  qp_attr.qp_ous_rd_atom = 1;
  QP_ATTR_MASK_SET(qp_attr_mask, QP_ATTR_QP_OUS_RD_ATOM);

  qp_attr.dest_qp_num = d_qp_num;
  QP_ATTR_MASK_SET(qp_attr_mask, QP_ATTR_DEST_QP_NUM);

  qp_attr.av.sl = 0;
  qp_attr.av.grh_flag = FALSE;
  qp_attr.av.dlid = d_lid;
  qp_attr.av.static_rate = 0;
  qp_attr.av.src_path_bits = 0;
  QP_ATTR_MASK_SET(qp_attr_mask, QP_ATTR_AV);

  qp_attr.path_mtu = p->prot.ib_mtu;
  QP_ATTR_MASK_SET(qp_attr_mask, QP_ATTR_PATH_MTU);

  qp_attr.rq_psn = 0;
  QP_ATTR_MASK_SET(qp_attr_mask, QP_ATTR_RQ_PSN);

  qp_attr.pkey_ix = 0;
  QP_ATTR_MASK_SET(qp_attr_mask, QP_ATTR_PKEY_IX);

  qp_attr.min_rnr_timer = 5;
  QP_ATTR_MASK_SET(qp_attr_mask, QP_ATTR_MIN_RNR_TIMER);
  
  ret = VAPI_modify_qp(hca_hndl, qp_hndl, &qp_attr, &qp_attr_mask, &qp_cap);
  if(ret != VAPI_OK) {
    fprintf(stderr, "Error modifying QP to RTR: %s\n", VAPI_strerror(ret));
    return -1;
  }

  LOGPRINTF("Modified QP to RTR\n");

  /* Sync before going to RTS state */
  Sync(p);

  /******* RTS (Ready-to-Send) state *******/

  QP_ATTR_MASK_CLR_ALL(qp_attr_mask);

  qp_attr.qp_state = VAPI_RTS;
  QP_ATTR_MASK_SET(qp_attr_mask, QP_ATTR_QP_STATE);

  qp_attr.sq_psn = 0;
  QP_ATTR_MASK_SET(qp_attr_mask, QP_ATTR_SQ_PSN);

  qp_attr.timeout = 31;
  QP_ATTR_MASK_SET(qp_attr_mask, QP_ATTR_TIMEOUT);

  qp_attr.retry_count = 1;
  QP_ATTR_MASK_SET(qp_attr_mask, QP_ATTR_RETRY_COUNT);

  qp_attr.rnr_retry = 1;
  QP_ATTR_MASK_SET(qp_attr_mask, QP_ATTR_RNR_RETRY);

  qp_attr.ous_dst_rd_atom = 1;
  QP_ATTR_MASK_SET(qp_attr_mask, QP_ATTR_OUS_DST_RD_ATOM);

  ret = VAPI_modify_qp(hca_hndl, qp_hndl, &qp_attr, &qp_attr_mask, &qp_cap);
  if(ret != VAPI_OK) {
    fprintf(stderr, "Error modifying QP to RTS: %s\n", VAPI_strerror(ret));
    return -1;
  }
  
  LOGPRINTF("Modified QP to RTS\n");

  /* If using event completion, register event completion handler and request
   * the initial notification
   */
  if( p->prot.comptype == NP_COMP_EVENT ) {

    EVAPI_set_comp_eventh(hca_hndl, r_cq_hndl, event_handler, p, &ceh_hndl);
    VAPI_req_comp_notif(hca_hndl, r_cq_hndl, VAPI_NEXT_COMP);

  }
 
  return 0;
}

int finalizeIB(ArgStruct *p)
{
  VAPI_ret_t ret;

  LOGPRINTF("Finalizing IB stuff\n");

  /* Clear completion event handler */

  if(p->prot.comptype == NP_COMP_EVENT ) {
     LOGPRINTF("Clearing comp handler\n");
     ret = EVAPI_clear_comp_eventh(hca_hndl, ceh_hndl);
     if(ret != VAPI_OK) {
        fprintf(stderr, "Error clearing event handler: %s\n",
                VAPI_strerror(ret));
     }
  }

  if(qp_hndl != VAPI_INVAL_HNDL) {
    LOGPRINTF("Destroying QP\n");
    ret = VAPI_destroy_qp(hca_hndl, qp_hndl);
    if(ret != VAPI_OK) {
      fprintf(stderr, "Error destroying Queue Pair: %s\n", VAPI_strerror(ret));
    }
  }

  if(r_cq_hndl != VAPI_INVAL_HNDL) {
    LOGPRINTF("Destroying Recv CQ\n");
    ret = VAPI_destroy_cq(hca_hndl, r_cq_hndl);
    if(ret != VAPI_OK) {
      fprintf(stderr, "Error destroying recv CQ: %s\n", VAPI_strerror(ret));
    }
  }

  if(s_cq_hndl != VAPI_INVAL_HNDL) {
    LOGPRINTF("Destroying Send CQ\n");
    ret = VAPI_destroy_cq(hca_hndl, s_cq_hndl);
    if(ret != VAPI_OK) {
      fprintf(stderr, "Error destroying send CQ: %s\n", VAPI_strerror(ret));
    }
  }

  /* Check memory registrations just in case user bailed out */
  if(s_mr_hndl != VAPI_INVAL_HNDL) {
    LOGPRINTF("Deregistering send buffer\n");
    ret = VAPI_deregister_mr(hca_hndl, s_mr_hndl);
    if(ret != VAPI_OK) {
      fprintf(stderr, "Error deregistering send mr: %s\n", VAPI_strerror(ret));
    }
  }

  if(r_mr_hndl != VAPI_INVAL_HNDL) {
    LOGPRINTF("Deregistering recv buffer\n");
    ret = VAPI_deregister_mr(hca_hndl, r_mr_hndl);
    if(ret != VAPI_OK) {
      fprintf(stderr, "Error deregistering recv mr: %s\n", VAPI_strerror(ret));
    }
  }

  if(pd_hndl != VAPI_INVAL_HNDL) {
    LOGPRINTF("Deallocating PD\n");
    ret = VAPI_dealloc_pd(hca_hndl, pd_hndl);
    if(ret != VAPI_OK) {
      fprintf(stderr, "Error deallocating PD: %s\n", VAPI_strerror(ret));
    }
  }

  /* Application code should not close HCA, just release handle */

  if(hca_hndl != VAPI_INVAL_HNDL) {
    LOGPRINTF("Releasing HCA\n");
    ret = EVAPI_release_hca_hndl(hca_hndl);
    if(ret != VAPI_OK) {
      fprintf(stderr, "Error releasing HCA: %s\n", VAPI_strerror(ret));
    }
  }

  return 0;
}

void event_handler(VAPI_hca_hndl_t hca, VAPI_cq_hndl_t cq, void* data)
{
  VAPI_ret_t    ret;
 
  while(1) {
     
     ret = VAPI_poll_cq(hca, cq, &wc);

     if(ret == VAPI_CQ_EMPTY) {
        LOGPRINTF("Empty completion queue, requesting next notification\n");
        VAPI_req_comp_notif(hca_hndl, r_cq_hndl, VAPI_NEXT_COMP);
        return;
     } else if(ret != VAPI_OK) {
        fprintf(stderr, "Error in event_handler, polling cq: %s\n",
                VAPI_strerror(ret));
        exit(-1);
     } else if(wc.status != VAPI_SUCCESS) {
        fprintf(stderr, "Error in event_handler, on returned work completion "
                        "status: %s\n", VAPI_wc_status_sym(wc.status));
        exit(-1);
     }
     
     LOGPRINTF("Retrieved work completion\n");

     /* For ping-pong mode at least, this check shouldn't be needed for
      * normal operation, but it will help catch any bugs with multiple
      * sends coming through when we're only expecting one.
      */
     if(receive_complete == 1) {

        while(receive_complete != 0) sched_yield();

     }

     receive_complete = 1;

  }
  
}

static int
readFully(int fd, void *obuf, int len)
{
  int bytesLeft = len;
  char *buf = (char *) obuf;
  int bytesRead = 0;

  while (bytesLeft > 0 &&
        (bytesRead = read(fd, (void *) buf, bytesLeft)) > 0)
    {
      bytesLeft -= bytesRead;
      buf += bytesRead;
    }
  if (bytesRead <= 0)
    return bytesRead;
  return len;
}

void Sync(ArgStruct *p)
{
    char s[] = "SyncMe";
    char response[7];

    if (write(p->commfd, s, strlen(s)) < 0 ||
        readFully(p->commfd, response, strlen(s)) < 0)
      {
        perror("NetPIPE: error writing or reading synchronization string");
        exit(3);
      }
    if (strncmp(s, response, strlen(s)))
      {
        fprintf(stderr, "NetPIPE: Synchronization string incorrect!\n");
        exit(3);
      }
}

void PrepareToReceive(ArgStruct *p)
{
  VAPI_ret_t          ret;       /* Return code */
  VAPI_rr_desc_t      rr;        /* Receive request */
  VAPI_sg_lst_entry_t sg_entry;  /* Scatter/Gather list - holds buff addr */

  /* We don't need to post a receive if doing RDMA write with local polling */

  if( p->prot.commtype == NP_COMM_RDMAWRITE &&
      p->prot.comptype == NP_COMP_LOCALPOLL )
     return;
  
  rr.opcode = VAPI_RECEIVE;

  /* We only need signaled completions if using VAPI
   * completion methods.
   */
  if( p->prot.comptype == NP_COMP_LOCALPOLL )
     rr.comp_type = VAPI_UNSIGNALED;
  else
     rr.comp_type = VAPI_SIGNALED;

  rr.sg_lst_len = 1;
  rr.sg_lst_p = &sg_entry;

  sg_entry.lkey = r_mr_out.l_key;
  sg_entry.len = p->bufflen;
  sg_entry.addr = (VAPI_virt_addr_t)(MT_virt_addr_t)p->r_ptr;

  ret = VAPI_post_rr(hca_hndl, qp_hndl, &rr);
  if(ret != VAPI_OK) {
    fprintf(stderr, "Error posting recv request: %s\n", VAPI_strerror(ret));
    CleanUp(p);
    exit(-1);
  } else {
    LOGPRINTF("Posted recv request\n");
  }

  /* Set receive flag to zero and request event completion 
   * notification for this receive so the event handler will 
   * be triggered when the receive completes.
   */
  if( p->prot.comptype == NP_COMP_EVENT ) {
    receive_complete = 0;
  }
}

void SendData(ArgStruct *p)
{
  VAPI_ret_t          ret;       /* Return code */
  VAPI_sr_desc_t      sr;        /* Send request */
  VAPI_sg_lst_entry_t sg_entry;  /* Scatter/Gather list - holds buff addr */

  /* Fill in send request struct */

  if(p->prot.commtype == NP_COMM_SENDRECV) {
     sr.opcode = VAPI_SEND;
     LOGPRINTF("Doing regular send\n");
  } else if(p->prot.commtype == NP_COMM_SENDRECV_WITH_IMM) {
     sr.opcode = VAPI_SEND_WITH_IMM;
     LOGPRINTF("Doing regular send with imm\n");
  } else if(p->prot.commtype == NP_COMM_RDMAWRITE) {
     sr.opcode = VAPI_RDMA_WRITE;
     sr.remote_addr = (VAPI_virt_addr_t)(MT_virt_addr_t)(remote_address + (p->s_ptr - p->s_buff));
     sr.r_key = remote_key;
     LOGPRINTF("Doing RDMA write (raddr=%p)\n", sr.remote_addr);
  } else if(p->prot.commtype == NP_COMM_RDMAWRITE_WITH_IMM) {
     sr.opcode = VAPI_RDMA_WRITE_WITH_IMM;
     sr.remote_addr = (VAPI_virt_addr_t)(MT_virt_addr_t)(remote_address + (p->s_ptr - p->s_buff));
     sr.r_key = remote_key;
     LOGPRINTF("Doing RDMA write with imm (raddr=%p)\n", sr.remote_addr);
  } else {
     fprintf(stderr, "Error, invalid communication type in SendData\n");
     exit(-1);
  }
  
  sr.comp_type = VAPI_UNSIGNALED;
  sr.set_se = FALSE; /* This needed due to a bug in Mellanox HW rel a-0 */

  sr.sg_lst_len = 1;
  sr.sg_lst_p = &sg_entry;

  sg_entry.lkey = s_mr_out.l_key; /* Local memory region key */
  sg_entry.len = p->bufflen;
  sg_entry.addr = (VAPI_virt_addr_t)(MT_virt_addr_t)p->s_ptr;

  ret = VAPI_post_sr(hca_hndl, qp_hndl, &sr);
  if(ret != VAPI_OK) {
    fprintf(stderr, "Error posting send request: %s\n", VAPI_strerror(ret));
  } else {
    LOGPRINTF("Posted send request\n");
  }

}

void RecvData(ArgStruct *p)
{
  VAPI_ret_t ret;

  /* Busy wait for incoming data */

  LOGPRINTF("Receiving at buffer address %p\n", p->r_ptr);

  if( p->prot.comptype == NP_COMP_LOCALPOLL ) {
       
    /* Poll for receive completion locally on the receive data */

    LOGPRINTF("Waiting for last byte of data to arrive\n");
     
    while(p->r_ptr[p->bufflen-1] != 'a' + (p->cache ? 1 - p->tr : 1) ) 
    {
       /* BUSY WAIT -- this should be fine since we 
        * declared r_ptr with volatile qualifier */ 
    }

    /* Reset last byte */
    p->r_ptr[p->bufflen-1] = 'a' + (p->cache ? p->tr : 0);

    LOGPRINTF("Received all of data\n");

  } else if( p->prot.comptype == NP_COMP_VAPIPOLL ) {
     
     /* Poll for receive completion using VAPI poll function */

     LOGPRINTF("Polling completion queue for VAPI work completion\n");
     
     ret = VAPI_CQ_EMPTY;
     while(ret == VAPI_CQ_EMPTY)
        ret = VAPI_poll_cq(hca_hndl, r_cq_hndl, &wc);

     if(ret != VAPI_OK) {
        fprintf(stderr, "Error in RecvData, polling for completion: %s\n",
                VAPI_strerror(ret));
        exit(-1);
     }

     if(wc.status != VAPI_SUCCESS) {
        fprintf(stderr, "Error in status of returned completion: %s\n",
              VAPI_wc_status_sym(wc.status));
        exit(-1);
     }

     LOGPRINTF("Retrieved successful completion\n");
     
  } else if( p->prot.comptype == NP_COMP_EVENT ) {

     /* Instead of polling directly on data or VAPI completion queue,
      * let the VAPI event completion handler set a flag when the receive
      * completes, and poll on that instead. Could try using semaphore here
      * as well to eliminate busy polling
      */

     LOGPRINTF("Polling receive flag\n");
     
     while( receive_complete == 0 )
     {
        /* BUSY WAIT */
     }

     /* If in prepost-burst mode, we won't be calling PrepareToReceive
      * between ping-pongs, so we need to reset the receive_complete
      * flag here.
      */
     if( p->preburst ) receive_complete = 0;

     LOGPRINTF("Receive completed\n");
  }
}

/* Reset is used after a trial to empty the work request queues so we
   have enough room for the next trial to run */
void Reset(ArgStruct *p)
{

  VAPI_ret_t          ret;       /* Return code */
  VAPI_sr_desc_t      sr;        /* Send request */
  VAPI_rr_desc_t      rr;        /* Recv request */

  /* If comptype is event, then we'll use event handler to detect receive,
   * so initialize receive_complete flag
   */
  if(p->prot.comptype == NP_COMP_EVENT) receive_complete = 0;

  /* Prepost receive */
  rr.opcode = VAPI_RECEIVE;
  rr.comp_type = VAPI_SIGNALED;
  rr.sg_lst_len = 0;

  LOGPRINTF("Posting recv request in Reset\n");
  ret = VAPI_post_rr(hca_hndl, qp_hndl, &rr);
  if(ret != VAPI_OK) {
    fprintf(stderr, "  Error posting recv request: %s\n", VAPI_strerror(ret));
    CleanUp(p);
    exit(-1);
  }

  /* Make sure both nodes have preposted receives */
  Sync(p);

  /* Post Send */
  sr.opcode = VAPI_SEND;
  sr.comp_type = VAPI_SIGNALED;
  sr.set_se = FALSE; /* This needed due to a bug in Mellanox HW rel a-0 */
  sr.sg_lst_len = 0;

  LOGPRINTF("Posting send request \n");
  ret = VAPI_post_sr(hca_hndl, qp_hndl, &sr);
  if(ret != VAPI_OK) {
    fprintf(stderr, "  Error posting send request in Reset: %s\n", 
            VAPI_strerror(ret));
    exit(-1);
  }
  if(wc.status != VAPI_SUCCESS) {
     fprintf(stderr, "  Error in completion status: %s\n",
             VAPI_wc_status_sym(wc.status));
     exit(-1);
  }

  LOGPRINTF("Polling for completion of send request\n");
  ret = VAPI_CQ_EMPTY;
  while(ret == VAPI_CQ_EMPTY)
    ret = VAPI_poll_cq(hca_hndl, s_cq_hndl, &wc);

  if(ret != VAPI_OK) {
    fprintf(stderr, "Error polling CQ for send in Reset: %s\n", 
            VAPI_strerror(ret));
    exit(-1);
  }
  if(wc.status != VAPI_SUCCESS) {
     fprintf(stderr, "  Error in completion status: %s\n",
             VAPI_wc_status_sym(wc.status));
     exit(-1);
  }          
  
  LOGPRINTF("Status of send completion: %s\n", VAPI_wc_status_sym(wc.status));

  if(p->prot.comptype == NP_COMP_EVENT) { 
     /* If using event completion, the event handler will set receive_complete
      * when it gets the completion event.
      */
     LOGPRINTF("Waiting for receive_complete flag\n");
     while(receive_complete == 0) { /* BUSY WAIT */ }
  } else {
     LOGPRINTF("Polling for completion of recv request\n");
     ret = VAPI_CQ_EMPTY;
     while(ret == VAPI_CQ_EMPTY)
       ret = VAPI_poll_cq(hca_hndl, r_cq_hndl, &wc);
     
     if(ret != VAPI_OK) {
       fprintf(stderr, "Error polling CQ for recv in Reset: %s\n", 
               VAPI_strerror(ret));
       exit(-1);
     }
     if(wc.status != VAPI_SUCCESS) {
        fprintf(stderr, "  Error in completion status: %s\n",
                VAPI_wc_status_sym(wc.status));
        exit(-1);
     }

     LOGPRINTF("Status of recv completion: %s\n", VAPI_wc_status_sym(wc.status));
  }
  LOGPRINTF("Done with reset\n");
}

void SendTime(ArgStruct *p, double *t)
{
    uint32_t ltime, ntime;

    /*
      Multiply the number of seconds by 1e6 to get time in microseconds
      and convert value to an unsigned 32-bit integer.
      */
    ltime = (uint32_t)(*t * 1.e6);

    /* Send time in network order */
    ntime = htonl(ltime);
    if (write(p->commfd, (char *)&ntime, sizeof(uint32_t)) < 0)
      {
        printf("NetPIPE: write failed in SendTime: errno=%d\n", errno);
        exit(301);
      }
}

void RecvTime(ArgStruct *p, double *t)
{
    uint32_t ltime, ntime;
    int bytesRead;

    bytesRead = readFully(p->commfd, (void *)&ntime, sizeof(uint32_t));
    if (bytesRead < 0)
      {
        printf("NetPIPE: read failed in RecvTime: errno=%d\n", errno);
        exit(302);
      }
    else if (bytesRead != sizeof(uint32_t))
      {
        fprintf(stderr, "NetPIPE: partial read in RecvTime of %d bytes\n",
                bytesRead);
        exit(303);
      }
    ltime = ntohl(ntime);

    /* Result is ltime (in microseconds) divided by 1.0e6 to get seconds */
    *t = (double)ltime / 1.0e6;
}

void SendRepeat(ArgStruct *p, int rpt)
{
  uint32_t lrpt, nrpt;

  lrpt = rpt;
  /* Send repeat count as a long in network order */
  nrpt = htonl(lrpt);
  if (write(p->commfd, (void *) &nrpt, sizeof(uint32_t)) < 0)
    {
      printf("NetPIPE: write failed in SendRepeat: errno=%d\n", errno);
      exit(304);
    }
}

void RecvRepeat(ArgStruct *p, int *rpt)
{
  uint32_t lrpt, nrpt;
  int bytesRead;

  bytesRead = readFully(p->commfd, (void *)&nrpt, sizeof(uint32_t));
  if (bytesRead < 0)
    {
      printf("NetPIPE: read failed in RecvRepeat: errno=%d\n", errno);
      exit(305);
    }
  else if (bytesRead != sizeof(uint32_t))
    {
      fprintf(stderr, "NetPIPE: partial read in RecvRepeat of %d bytes\n",
              bytesRead);
      exit(306);
    }
  lrpt = ntohl(nrpt);

  *rpt = lrpt;
}

void establish(ArgStruct *p)
{
 int clen;
 int one = 1;
 struct protoent;

 clen = sizeof(p->prot.sin2);
 if(p->tr){
   if(connect(p->commfd, (struct sockaddr *) &(p->prot.sin1),
              sizeof(p->prot.sin1)) < 0){
     printf("Client: Cannot Connect! errno=%d\n",errno);
     exit(-10);
   }
  }
  else {
    /* SERVER */
    listen(p->servicefd, 5);
    p->commfd = accept(p->servicefd, (struct sockaddr *) &(p->prot.sin2),
                       &clen);

    if(p->commfd < 0){
      printf("Server: Accept Failed! errno=%d\n",errno);
      exit(-12);
    }
  }
}

void CleanUp(ArgStruct *p)
{
   char *quit="QUIT";
   if (p->tr)
   {
      write(p->commfd,quit, 5);
      read(p->commfd, quit, 5);
      close(p->commfd);
   }
   else
   {
      read(p->commfd,quit, 5);
      write(p->commfd,quit,5);
      close(p->commfd);
      close(p->servicefd);
   }

   finalizeIB(p);
}


void AfterAlignmentInit(ArgStruct *p)
{
  int bytesRead;

  /* Exchange buffer pointers and remote infiniband keys if doing rdma. Do
   * the exchange in this function because this will happen after any
   * memory alignment is done, which is important for getting the 
   * correct remote address.
  */
  if( p->prot.commtype == NP_COMM_RDMAWRITE || 
      p->prot.commtype == NP_COMM_RDMAWRITE_WITH_IMM ) {
     
     /* Send my receive buffer address
      */
     if(write(p->commfd, (void *)&p->r_buff, sizeof(void*)) < 0) {
        perror("NetPIPE: write of buffer address failed in AfterAlignmentInit");
        exit(-1);
     }
     
     LOGPRINTF("Sent buffer address: %p\n", p->r_buff);
     
     /* Send my remote key for accessing
      * my remote buffer via IB RDMA
      */
     if(write(p->commfd, (void *)&r_mr_out.r_key, sizeof(VAPI_rkey_t)) < 0) {
        perror("NetPIPE: write of remote key failed in AfterAlignmentInit");
        exit(-1);
     }
  
     LOGPRINTF("Sent remote key: %d\n", r_mr_out.r_key);
     
     /* Read the sent data
      */
     bytesRead = readFully(p->commfd, (void *)&remote_address, sizeof(void*));
     if (bytesRead < 0) {
        perror("NetPIPE: read of buffer address failed in AfterAlignmentInit");
        exit(-1);
     } else if (bytesRead != sizeof(void*)) {
        perror("NetPIPE: partial read of buffer address in AfterAlignmentInit");
        exit(-1);
     }
     
     LOGPRINTF("Received remote address from other node: %p\n", remote_address);
     
     bytesRead = readFully(p->commfd, (void *)&remote_key, sizeof(VAPI_rkey_t));
     if (bytesRead < 0) {
        perror("NetPIPE: read of remote key failed in AfterAlignmentInit");
        exit(-1);
     } else if (bytesRead != sizeof(VAPI_rkey_t)) {
        perror("NetPIPE: partial read of remote key in AfterAlignmentInit");
        exit(-1);
     }
     
     LOGPRINTF("Received remote key from other node: %d\n", remote_key);

  }
}


void MyMalloc(ArgStruct *p, int bufflen, int soffset, int roffset)
{
  VAPI_ret_t ret;

  /* Allocate buffers */

  p->r_buff = malloc(bufflen+MAX(soffset,roffset));
  if(p->r_buff == NULL) {
    fprintf(stderr, "Error malloc'ing buffer\n");
    exit(-1);
  }

  if(p->cache) {

    /* Infiniband spec says we can register same memory region
     * more than once, so just copy buffer address. We will register
     * the same buffer twice with Infiniband.
     */
    p->s_buff = p->r_buff;

  } else {

    p->s_buff = malloc(bufflen+soffset);
    if(p->s_buff == NULL) {
      fprintf(stderr, "Error malloc'ing buffer\n");
      exit(-1);
    }

  }

  /* Register buffers with Infiniband */

  mr_in.acl = VAPI_EN_LOCAL_WRITE | VAPI_EN_REMOTE_WRITE;
  mr_in.l_key = 0;
  mr_in.pd_hndl = pd_hndl;
  mr_in.r_key = 0;
  mr_in.size = bufflen+MAX(soffset,roffset);
  mr_in.start = (VAPI_virt_addr_t)(MT_virt_addr_t)p->r_buff;
  mr_in.type = VAPI_MR;

  ret = VAPI_register_mr(hca_hndl, &mr_in, &r_mr_hndl, &r_mr_out);
  if(ret != VAPI_OK)
        {
    fprintf(stderr, "Error registering recv buffer: %s\n", VAPI_strerror(ret));
    exit(-1);
        }
        else
        {
         LOGPRINTF("Registered Recv Buffer\n");
        }

  mr_in.acl = VAPI_EN_LOCAL_WRITE;
  mr_in.l_key = 0;
  mr_in.pd_hndl = pd_hndl;
  mr_in.r_key = 0;
  mr_in.size = bufflen+soffset;
  mr_in.start = (VAPI_virt_addr_t)(MT_virt_addr_t)p->s_buff;
  mr_in.type = VAPI_MR;

  ret = VAPI_register_mr(hca_hndl, &mr_in, &s_mr_hndl, &s_mr_out);
  if(ret != VAPI_OK) {
    fprintf(stderr, "Error registering send buffer: %s\n", VAPI_strerror(ret));
    exit(-1);
  } else {
    LOGPRINTF("Registered Send Buffer\n");
  }

}
void FreeBuff(char *buff1, char *buff2)
{
  VAPI_ret_t ret;

  if(s_mr_hndl != VAPI_INVAL_HNDL) {
    LOGPRINTF("Deregistering send buffer\n");
    ret = VAPI_deregister_mr(hca_hndl, s_mr_hndl);
    if(ret != VAPI_OK) {
      fprintf(stderr, "Error deregistering send mr: %s\n", VAPI_strerror(ret));
    } else {
      s_mr_hndl = VAPI_INVAL_HNDL;
    }
  }

  if(r_mr_hndl != VAPI_INVAL_HNDL) {
    LOGPRINTF("Deregistering recv buffer\n");
    ret = VAPI_deregister_mr(hca_hndl, r_mr_hndl);
    if(ret != VAPI_OK) {
      fprintf(stderr, "Error deregistering recv mr: %s\n", VAPI_strerror(ret));
    } else {
      r_mr_hndl = VAPI_INVAL_HNDL;
    }
  }

  if(buff1 != NULL)
    free(buff1);

  if(buff2 != NULL)
    free(buff2);
}

