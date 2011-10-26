#include "netpipe.h"
#include <lapi.h>

lapi_handle_t  t_hndl;
lapi_cntr_t    l_cntr;
lapi_cntr_t    t_cntr;
lapi_cntr_t    c_cntr;
lapi_info_t    t_info;  /* LAPI info structure */
void           *global_addr[2];
void           *tgt_addr[2];
void           *rpt_addr[2];
void           *time_addr[2];
void           *offset_addr[2];
int            npRepeat;
int            nbor_r_buff_offset;

void Init(ArgStruct *p, int* pargc, char*** pargv)
{

}

void Setup(ArgStruct *p)
{
        int   one=1, loop, rc, val, cur_val;
        int   task_id;       /* My task id */
        int   num_tasks;     /* Number of tasks in my job */
        char* t_buf;         /* Buffer to manipulate */
        char  err_msg_buf[LAPI_MAX_ERR_STRING];

        bzero(&t_info, sizeof(lapi_info_t));

        t_info.err_hndlr = NULL;   /* Not registering error handler function */

        if ((rc = LAPI_Init(&t_hndl, &t_info)) != LAPI_SUCCESS) {
                LAPI_Msg_string(rc, err_msg_buf);
                printf("Error Message: %s, rc = %d\n", err_msg_buf, rc);
                exit (rc);
        }

        /* Get task number within job */

        rc = LAPI_Qenv(t_hndl, TASK_ID, &task_id);

        /* Get number of tasks in job */

        rc = LAPI_Qenv(t_hndl, NUM_TASKS, &num_tasks);

        if (num_tasks != 2) {
                printf("Error Message: Run with MP_PROCS set to 2\n");
                exit(1);
        }

        /* Turn off parameter checking - default is on */

        rc = LAPI_Senv(t_hndl, ERROR_CHK, 0);

        /* Initialize counters to be zero at the start */

        rc = LAPI_Setcntr(t_hndl, &l_cntr, 0);

        rc = LAPI_Setcntr(t_hndl, &t_cntr, 0);

        rc = LAPI_Setcntr(t_hndl, &c_cntr, 0);

        /* Exchange addresses for target counter, repeats, and rbuff offset */

        rc = LAPI_Address_init(t_hndl,&t_cntr,tgt_addr);

        rc = LAPI_Address_init(t_hndl,&npRepeat,rpt_addr); 

        rc = LAPI_Address_init(t_hndl,&nbor_r_buff_offset,offset_addr);

        p->tr = p->rcv = 0;
        if (task_id ==0)
        {
                p->tr = 1;
                p->prot.nbor=1;
        }
        else
        {
                p->rcv = 1;
                p->prot.nbor=0;
        }
}

void Sync(ArgStruct *p)
{
        LAPI_Gfence(t_hndl);
}

void PrepareToReceive(ArgStruct *p)
{
 /* Nothing to do */
}

void SendData(ArgStruct *p)
{
        int rc;
        int offset = p->s_ptr - p->s_buff;
        void* dest = global_addr[p->prot.nbor] + nbor_r_buff_offset + offset;

        /* We calculate the destination address because buffer alignment most
         * likely changed the start of the buffer from what malloc returned
         */
        rc = LAPI_Put(t_hndl, p->prot.nbor, p->bufflen*sizeof(char), dest,
                      (void *)p->s_ptr,tgt_addr[p->prot.nbor], 
                      &l_cntr,&c_cntr);

        /* Wait for local Put completion */

        rc = LAPI_Waitcntr(t_hndl, &l_cntr, 1, NULL); 

}

void RecvData(ArgStruct *p)
{
        int rc,val,cur_val;

        /* Poll for receive.  We have to use polling
         * as LAPI_Waitcntr does not guarantee making progress
         * on receives.
         */
        rc = LAPI_Getcntr(t_hndl, &t_cntr, &val);
        while (val < 1) {
            rc = LAPI_Probe(t_hndl); /* Poll the adapter once */
            rc = LAPI_Getcntr(t_hndl, &t_cntr, &val);
        }

        /* To clear the t_cntr value */
        rc = LAPI_Waitcntr(t_hndl, &t_cntr, 1, &cur_val); 

}

void SendTime(ArgStruct *p, double *t)
{
        int rc;
        rc = LAPI_Address_init(t_hndl,t,time_addr);
        rc = LAPI_Put(t_hndl,p->prot.nbor,sizeof(double),
               time_addr[p->prot.nbor],(void *)t,tgt_addr[p->prot.nbor],
               &l_cntr,&c_cntr);
        /* Wait for local Put completion */
        rc = LAPI_Waitcntr(t_hndl, &l_cntr, 1, NULL);

}

void RecvTime(ArgStruct *p, double *t)
{
        int rc, val, cur_val;
        rc = LAPI_Address_init(t_hndl,t,time_addr);
        rc = LAPI_Getcntr(t_hndl, &t_cntr, &val);
        while (val < 1) {
            rc = LAPI_Probe(t_hndl); /* Poll the adapter once */
            rc = LAPI_Getcntr(t_hndl, &t_cntr, &val);
        }
        /* To clear the t_cntr value */
        rc = LAPI_Waitcntr(t_hndl, &t_cntr, 1, &cur_val);
}

void SendRepeat(ArgStruct *p, int rpt)
{
        int rc;

        rc = LAPI_Put(t_hndl,p->prot.nbor,sizeof(int), rpt_addr[p->prot.nbor],
                        (void *)&rpt,tgt_addr[p->prot.nbor],&l_cntr,&c_cntr);

        /* Wait for local Put completion */
        rc = LAPI_Waitcntr(t_hndl, &l_cntr, 1, NULL);    
}

void RecvRepeat(ArgStruct *p, int *rpt) 
{
        int rc,val,cur_val;

        rc = LAPI_Getcntr(t_hndl, &t_cntr, &val);
        while (val < 1) {
            rc = LAPI_Probe(t_hndl); /* Poll the adapter once */
            rc = LAPI_Getcntr(t_hndl, &t_cntr, &val);
        }

        *rpt = npRepeat;

        /* To clear the t_cntr value */
        rc = LAPI_Waitcntr(t_hndl, &t_cntr, 1, &cur_val);  
}

void  CleanUp(ArgStruct *p)
{
	int rc;
	rc = LAPI_Gfence(t_hndl); /* Global fence to sync before terminating job */
	rc = LAPI_Term(t_hndl);   
}        


void Reset(ArgStruct *p)
{

}


void AfterAlignmentInit(ArgStruct* p)
{
    int rc, val, cur_val;
    int my_r_buff_offset = p->r_buff - p->r_buff_orig;

    /* Send my receive buffer offset to other guy */
    rc = LAPI_Put(t_hndl,p->prot.nbor,sizeof(int), offset_addr[p->prot.nbor],
                  (void *)&my_r_buff_offset,tgt_addr[p->prot.nbor],&l_cntr,&c_cntr);

    /* Wait for local Put completion */
    rc = LAPI_Waitcntr(t_hndl, &l_cntr, 1, NULL);

    /* Wait for incoming Put completion (We poll because receive progress not 
     * guaranteed in LAPI_Waitcntr() 
     */
    rc = LAPI_Getcntr(t_hndl, &t_cntr, &val);
    while (val < 1) {
      rc = LAPI_Probe(t_hndl); /* Poll the adapter once, make progress */
      rc = LAPI_Getcntr(t_hndl, &t_cntr, &val);
    }

    /* To clear the t_cntr value */
    rc = LAPI_Waitcntr(t_hndl, &t_cntr, 1, &cur_val);  
}

void MyMalloc(ArgStruct *p, int bufflen, int soffset, int roffset)
{
    int rc;

    if((p->r_buff=(char *)malloc(bufflen+MAX(soffset,roffset)))==(char *)NULL)
    {
        fprintf(stderr,"couldn't allocate memory for receive buffer\n");
        exit(-1);
    }
    rc = LAPI_Address_init(t_hndl,p->r_buff,global_addr);

    if(!p->cache)
      if((p->s_buff=(char *)malloc(bufflen+soffset))==(char *)NULL)
      {
          fprintf(stderr,"Couldn't allocate memory for send buffer\n");
          exit(-1);
      }

}

void FreeBuff(char *buff1, char *buff2)
{
    if(buff1 != NULL)
      free(buff1);

    if(buff2 != NULL)
      free(buff2);
}


