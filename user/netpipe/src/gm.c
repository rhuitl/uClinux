#include "netpipe.h"

extern struct gm_port *gm_p;
extern unsigned long *ltime, *lrpt;
extern char *sync, *sync1;

void Init(ArgStruct *p, int* pargc, char*** pargv)
{
  p->tr = 0;
  p->rcv = 1;
}

void Setup(ArgStruct *p)
{
  if(gm_open(&gm_p,0,5,"port2",(enum gm_api_version) GM_API_VERSION) != GM_SUCCESS)
  {
    printf(" Couldn't open board 0 port 2\n");
    exit(-1);
  }
  else
    printf("Opened board 0 port2\n");
  
  if( p->tr )
    p->prot.host_id = gm_host_name_to_node_id(gm_p, p->host);

  gm_free_send_tokens(gm_p, GM_LOW_PRIORITY, gm_num_send_tokens(gm_p));
  ltime = gm_dma_malloc(gm_p, sizeof(unsigned long));
  lrpt  = gm_dma_malloc(gm_p, sizeof(unsigned long)); 
  sync  = gm_dma_malloc(gm_p, 64); 
  sync1 = gm_dma_malloc(gm_p, 64);
  sprintf(sync, "Syncme");   

  establish(p);

  p->prot.num_stokens = gm_num_send_tokens(gm_p);

}   

void my_send_callback (struct gm_port *port, void *context, gm_status_t status)
{

  if (status != GM_SUCCESS)
  {
    if (status != GM_SEND_DROPPED)
    {
      gm_perror ("send completed with error", status);
    }
  }
}

void establish(ArgStruct *p)
{
  gm_recv_event_t *e;
  int bytesRead, recv_sz;
  char temp[60];
  int todo = 1;

  if((p->r_buff = gm_dma_calloc(gm_p, 1, 64)) == 0) {
    printf("Couldn't allocate memory \n");
    exit(0);
  } 

  if((p->s_buff = gm_dma_calloc(gm_p, 1, 64)) == 0) {
    printf("Couldn't allocate memory \n"); 
    exit(0);
  }


  if(p->tr){
    sprintf(p->s_buff, "this is the sender!!");
    gm_send_to_peer_with_callback(gm_p, p->s_buff, 7,
            (unsigned long) strlen(p->s_buff), GM_LOW_PRIORITY, 
             p->prot.host_id, my_send_callback, NULL);
  } 
  else 
  {
    gm_provide_receive_buffer(gm_p, p->r_buff, 7, GM_LOW_PRIORITY); 
    while (todo) {
      e = gm_receive(gm_p);    
 
      switch(gm_ntoh_u8(e->recv.type))  {
        case GM_RECV_EVENT:
        case GM_PEER_RECV_EVENT:
        case GM_FAST_PEER_RECV_EVENT:
          /*
          printf("[recv] Received: \"%s\"\n",
                    (char *) gm_ntohp (e->recv.message));
          */
          recv_sz=(int) gm_ntoh_u32 (e->recv.length);
          p->prot.host_id= gm_ntoh_u16(e->recv.sender_node_id);
          todo--;
          break;
        case GM_NO_RECV_EVENT:
          break;
        default:
          gm_unknown(gm_p,e);
      }
    }  
  }
} 

int readFully(void *buff, int len) 
{
   int bytesRead,bytesLeft;
   gm_recv_event_t *e;

   bytesLeft=len; 
   bytesRead=0; 
   while (bytesLeft>0) {
     e = gm_receive(gm_p);

     switch(gm_ntoh_u8(e->recv.type))  {
       case GM_FAST_PEER_RECV_EVENT:
         bytesRead = (int) gm_ntoh_u32 (e->recv.length);
         bytesLeft -= bytesRead; 
        /* gm_memorize_message(buff, gm_ntohp (e->recv.message), gm_ntohl (e->recv.length)); */
         bcopy(gm_ntohp(e->recv.message), buff,bytesRead);                                          
        /* strncpy(buff, (char *) gm_ntohp (e->recv.message),bytesRead); */
         break; 
       case GM_RECV_EVENT:
       case GM_PEER_RECV_EVENT:
         bytesRead = (int) gm_ntoh_u32 (e->recv.length);
         bytesLeft -= bytesRead;
         break;
       case GM_NO_RECV_EVENT:
         break;

       default:
         gm_unknown(gm_p,e);
     }
   }
   return 1;
}   
    
void Sync(ArgStruct *p)
{
  int len; 
  len=strlen(sync);
  gm_send_to_peer_with_callback(gm_p, sync, gm_min_size_for_length(len), 
                                (unsigned long) (len+1), GM_LOW_PRIORITY, 
                                p->prot.host_id, my_send_callback, NULL); 

  gm_provide_receive_buffer(gm_p, sync1, gm_min_size_for_length(len), 
                            GM_LOW_PRIORITY); 

  readFully(sync1,len+1);
}

void PrepareToReceive(ArgStruct *p)
{
        /*
          The GM interface doesn't have a method to pre-post
          a buffer for reception of data.
        */
}

void SendData(ArgStruct *p)
{
    gm_send_to_peer_with_callback(gm_p, p->s_ptr, 
                                  gm_min_size_for_length(p->bufflen), 
                                  p->bufflen, GM_LOW_PRIORITY, 
                                  p->prot.host_id, my_send_callback, NULL);
}
 
void RecvData(ArgStruct *p)
{
   gm_provide_receive_buffer(gm_p, p->r_ptr, 
                             gm_min_size_for_length(p->bufflen), 
                             GM_LOW_PRIORITY);
 
   readFully(p->r_ptr, p->bufflen);
} 

void SendTime(ArgStruct *p, double *t)
{
    
    /*
      Multiply the number of seconds by 1e6 to get time in microseconds
      and convert value to an unsigned 32-bit integer.
      */
    *ltime = (unsigned long)(*t * 1.e6);
    gm_send_to_peer_with_callback(gm_p, ltime, gm_min_size_for_length(sizeof(unsigned long)), sizeof(unsigned long),
          GM_LOW_PRIORITY, p->prot.host_id, my_send_callback, NULL);
}

void RecvTime(ArgStruct *p, double *t)
{
    gm_provide_receive_buffer(gm_p, ltime, gm_min_size_for_length(sizeof(unsigned long)), GM_LOW_PRIORITY); 
    readFully(ltime, sizeof(unsigned long));
    /* ltime = ntohl(p->buff1); */

    /* Result is ltime (in microseconds) divided by 1.0e6 to get seconds */
    *t = (double)(*ltime) / 1.0e6;
}

void SendRepeat(ArgStruct *p, int rpt)
{

  *lrpt = (int)rpt;
  /* Send repeat count as a long in network order */
  gm_send_to_peer_with_callback(gm_p, lrpt, gm_min_size_for_length(sizeof(unsigned long)), sizeof(unsigned long),
          GM_LOW_PRIORITY, p->prot.host_id, my_send_callback, NULL);
}

void RecvRepeat(ArgStruct *p, int *rpt)
{
  gm_provide_receive_buffer(gm_p, lrpt, gm_min_size_for_length(sizeof(unsigned long)), GM_LOW_PRIORITY); 
  readFully(lrpt,sizeof(unsigned long));
  *rpt =(int)*lrpt;
}

void CleanUp(ArgStruct *p)
{
   sleep(2); 
   gm_close(gm_p);
   gm_exit(GM_SUCCESS);
   gm_finalize();
}


void Reset(ArgStruct *p)
{

}

void AfterAlignmentInit(ArgStruct *p)
{

}
void MyMalloc(ArgStruct *p, int bufflen, int soffset, int roffset)
{  
  if((p->r_buff = (char *)gm_dma_malloc(gm_p, bufflen+MAX(soffset,roffset)))==(char *)NULL)
  {
      fprintf(stderr,"couldn't allocate memory\n");
      exit(-1);
  } 

  if(!p->cache)
    if((p->s_buff = (char *)gm_dma_malloc(gm_p, bufflen+soffset))==(char *)NULL)
    {
        fprintf(stderr,"Couldn't allocate memory\n");
        exit(-1);
    } 
}

void FreeBuff(char *buff1, char *buff2)
{
  if(buff1 != NULL)
    gm_dma_free(gm_p, buff1);

  if(buff2 != NULL)
    gm_dma_free(gm_p, buff2);
}

