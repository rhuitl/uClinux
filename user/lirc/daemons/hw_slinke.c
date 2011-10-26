/*      $Id: hw_slinke.c,v 5.5 2001/02/18 16:44:54 columbus Exp $      */

/****************************************************************************
 ** hw_slinke.c ***********************************************************
 ****************************************************************************
 *
 * routines for Slinke receiver 
 * 
 * Copyright (C) 1999 Christoph Bartelmus <lirc@bartelmus.de>
 *  modified for logitech receiver by Isaac Lauer <inl101@alumni.psu.edu>
 *  modified for Slink-e receiver Max Spring <mspring@employees.org>
 *
 *  07/01/2000 0.0 Early first cut:
 *  - Slink-e must be configured for 19200,8N1.
 *  - Only receiving is implemented so far, no sending of IR codes.
 *  - Existing remote control definition files may not work with Slink-e.
 *
 *  07/02/2000 0.1 Made memory allocations safer; Freeing allocations.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include "hardware.h"
#include "serial.h"
#include "ir_remote.h"
#include "lircd.h"
#include "receive.h"
#include "hw_slinke.h"

void *slinke_malloc(size_t size){
    void *ptr = malloc(size);
    if (ptr == NULL){
        logprintf(LOG_ERR,"slinke_malloc: out of memory");
        return NULL;
    }else{
        memset(ptr,0,size);
        return ptr;
    } /* if */
} /* slinke_malloc */

void *slinke_realloc(void *optr, size_t size){
    void *nptr;
    nptr = realloc(optr,size);
    if (nptr == NULL){
        logprintf(LOG_ERR,"realloc: out of memory");
        return NULL;
    }else{
        return nptr;
    } /* if */
} /* slinke_realloc */

#define TIMEOUT 200000

#define MAX_PORT_COUNT 8
#define QUEUE_BUF_INIT_SIZE 32
#define QUEUE_BUF_MAX_SIZE 4096
struct port_queue_rec{
    unsigned char port_id,msg_id;
    int length,bufsize;
    unsigned char *buf;
};
struct port_queue_rec queue[MAX_PORT_COUNT];

/* values read from Slink-e*/

struct slinke_settings_rec{
   int  sample_period;   /* number of 1/5 microseconds */ 
   int  timeout_samples; /* number of sample periods */
   char *version;
};
struct slinke_settings_rec slinke_settings = {0,0,NULL};

extern struct ir_remote *repeat_remote,*last_remote;

struct timeval start,end,last;
lirc_t gap,signal_length;
ir_code pre,code;

struct hardware hw = {
    LIRC_DRIVER_DEVICE, /* default device */
    -1,                 /* fd */
    LIRC_CAN_REC_MODE2, /* features */
    0,                  /* send_mode */
    LIRC_MODE_MODE2,    /* rec_mode */
    0,                  /* code_length */
    slinke_init,        /* init_func */
    slinke_deinit,      /* deinit_func */
    NULL,               /* send_func */
    slinke_rec,         /* rec_func */
    slinke_decode       /* decode_func */
};

/*****************************************************************************/
/* Slink-e constants */

#define CMD_PORT_DONE           0x00
#define CMD_PORT_SM             0x1F
                                
#define CMD_DISABLE             0x02
#define CMD_ENABLE              0x03
#define CMD_SENDBITMODE         0x04
#define CMD_SETIRFS             0x04
#define CMD_GETIRFS             0x05
#define CMD_SETIRCFS            0x06
#define CMD_GETIRCFS            0x07
#define CMD_SETIRTIMEOUT        0x0C
#define CMD_GETIRTIMEOUT        0x0D
#define CMD_SETIRMINLEN         0x0E
#define CMD_GETIRMINLEN         0x0F
#define CMD_SETIRTXPORTS        0x08
#define CMD_GETIRTXPORTS        0x13
#define CMD_SETIRRXPORTEN       0x09
#define CMD_GETIRRXPORTEN       0x12
#define CMD_SETIRPORTECHO       0x0A
#define CMD_GETIRPORTECHO       0x10
#define CMD_SETIRRXPORTPOL      0x0B
#define CMD_GETIRRXPORTPOL      0x11
#define CMD_SETBAUD             0x08
#define CMD_GETBAUD             0x09
#define CMD_SETHSMODE           0x10
#define CMD_GETHSMODE           0x11
#define CMD_SETDIR              0x12
#define CMD_GETDIR              0x13
#define CMD_SAMPLE              0x14
#define CMD_GETVERSION          0x0B
#define CMD_GETSERIALNO         0x0C
#define CMD_SETSERIALNO         0x0D
#define CMD_SAVEDEFAULTS        0x0E
#define CMD_LOADDEFAULTS        0x0F
#define CMD_RESUME              0xAA
#define CMD_RESET               0xFF
                                
#define RSP_PORT_DONE           0x00
#define RSP_PORT_SM             0x1F
#define RSP_DISABLE             0x02
#define RSP_ENABLE              0x03
#define RSP_TX_TIMEOUT          0x81
#define RSP_CMD_ILLEGAL         0xFF
#define RSP_RX_ERROR            0x80
#define RSP_RX_BITMODE          0x04
#define RSP_EQRXPORT            0x01
#define RSP_EQIRFS              0x04
#define RSP_EQIRCFS             0x06
#define RSP_EQIRPORTECHO        0x0A
#define RSP_EQIRTIMEOUT         0x0C
#define RSP_EQIRMINLEN          0x0E
#define RSP_EQIRRXPORTEN        0x09
#define RSP_EQIRRXPORTPOL       0x0B
#define RSP_EQIRTXPORTS         0x08
#define RSP_IRFS_ILLEGAL        0x82
#define RSP_EQBAUD              0x08
#define RSP_SERIALIN_OVERFLOW   0x83
#define RSP_SERIALIN_OVERRUN    0x86
#define RSP_SERIALIN_FRAMEERROR 0x85
#define RSP_BAUD_ILLEGAL        0x84
#define RSP_EQHSMODE            0x10
#define RSP_EQDIR               0x12
#define RSP_EQVERSION           0x0B
#define RSP_EQSERIALNO          0x0C
#define RSP_DEFAULTSSAVED       0x0E
#define RSP_DEFAULTSLOADED      0x0F
#define RSP_SEEPROMWRERR        0x8F

#define TEST_SLINK              1
#define TEST_IR                 2
#define TEST_PAR                3
#define TEST_BAUD               4
#define TEST_IRMULTI            5

#define MAXDATABLOCK            30

#define RX_STATE_IDLE    0
#define RX_STATE_RECEIVE 1
#define RX_STATE_PSM     2
#define RX_STATE_PSM_PAR 3

#define	PORT_SL0                0
#define	PORT_SL1                1
#define	PORT_SL2                2
#define	PORT_SL3                3
#define	PORT_IR0                4
#define	PORT_PAR                5
#define	PORT_SER                6
#define	PORT_SYS                7

#define MSG_ID_UNKNOWN                             0
#define MSG_ID_PORT_RECEIVE                        1
#define MSG_ID_PORT_DISABLED                       2
#define MSG_ID_PORT_ENABLED                        3
#define MSG_ID_TRANSMISSION_TIMEOUT                4
#define MSG_ID_ILLEGAL_COMMAND                     5
#define MSG_ID_RECEIVE_ERROR                       6
#define MSG_ID_SAMPLING_PERIOD_EQUALS              7
#define MSG_ID_CARRIER_PERIOD_EQUALS               8
#define MSG_ID_TIMEOUT_PERIOD_EQUALS               9
#define MSG_ID_MINIMUM_MESSAGE_LENGTH_EQUALS       10
#define MSG_ID_TRANSMIT_PORTS_EQUAL                11
#define MSG_ID_RECEIVE_PORTS_EQUAL                 12
#define MSG_ID_LAST_RECEIVE_PORT_EQUALS            13
#define MSG_ID_RECEIVE_PORT_POLARITIES_EQUAL       14
#define MSG_ID_IR_ROUTING_TABLE_EQUALS             15
#define MSG_ID_INVALID_SAMPLE_PERIOD               16
#define MSG_ID_HANDSHAKING_MODE_EQUALS             17
#define MSG_ID_CONFIGURATION_DIRECTION_EQUALS      18
#define MSG_ID_BAUD_RATE_EQUALS                    19
#define MSG_ID_SERIAL_PORT_RECEIVE_BUFFER_OVERFLOW 20
#define MSG_ID_SERIAL_PORT_RECEIVE_BUFFER_OVERRUN  21
#define MSG_ID_SERIAL_PORT_RECEIVE_FRAMING_ERROR   22
#define MSG_ID_BAUD_RATE_ILLEGAL                   23
#define MSG_ID_VERSION_EQUALS                      24
#define MSG_ID_DEFAULTS_LOADED                     25
#define MSG_ID_DEFAULTS_SAVED                      26
#define MSG_ID_SERIAL_NUMBER_EQUALS                27
#define MSG_ID_SEEPROM_WRITE_ERROR                 28

#ifdef DEBUG
/*****************************************************************************/
char *to_byte_string(unsigned char *b, int n){
    static char *buf = NULL;
    static int buflen = 0;
    int i,reqlen = 3*n+1;
    char t[10];

    if (buf == NULL || reqlen > buflen){
        buflen = reqlen;
        buf = (char*)slinke_realloc(buf,buflen);
        if (buf == NULL) return "";
    } /* if */
    
    sprintf(buf,"%02x",b[0]); 
    for (i=1; i<n; i++){
        sprintf(t,":%02x",b[i]);
        strcat(buf,t); 
    } /* for */ 
    return buf;
} /* to_byte_string */

static int signal_to_int(lirc_t signal){
    return ((signal & PULSE_BIT) == 0)
         ?  (signal & PULSE_MASK)
         : -(signal & PULSE_MASK);
} /* signal_to_int */
#endif

/*****************************************************************************/
static void tx_bytes(unsigned char *b, int n){
    LOGPRINTF(3,"sending %s",to_byte_string(b,n));
    write(hw.fd,b,n); 
} /* tx_bytes */

static void enable_port(unsigned char port){
    unsigned char d[2];

    d[0] = ((port%7) << 5) + CMD_PORT_SM;
    d[1] = CMD_ENABLE;

    tx_bytes(d,sizeof(d));
} /* enable_port */

static void set_IR_receive_ports(unsigned char ports){
    unsigned char d[3];

    d[0] = (PORT_IR0 << 5) + CMD_PORT_SM;
    d[1] = CMD_SETIRRXPORTEN;
    d[2] = ports; 

    tx_bytes(d,sizeof(d));
} /* set_IR_receive_ports */

static void set_sample_period(unsigned period){
    unsigned char d[4];

    d[0] = (PORT_IR0 << 5) + CMD_PORT_SM;
    d[1] = CMD_SETIRFS;
    d[2] = (unsigned char)((period >> 8) & 0xff);
    d[3] = (unsigned char)( period       & 0xff);

    tx_bytes(d,sizeof(d));
} /* set_sample_period */

static void set_IR_timeout_period(unsigned samples){
    unsigned char d[4];

    d[0] = (PORT_IR0 << 5) + CMD_PORT_SM;
    d[1] = CMD_SETIRTIMEOUT;
    d[2] = (unsigned char)((samples >> 8) & 0xff);
    d[3] = (unsigned char)( samples       & 0xff);

    tx_bytes(d,sizeof(d));
} /* set_IR_timeout_period */

static void get_version(){
    unsigned char d[2];

    d[0] = (PORT_SYS << 5) + CMD_PORT_SM;
    d[1] = CMD_GETVERSION;

    tx_bytes(d,sizeof(d));
} /* get_version */

/*****************************************************************************/
int slinke_init(void){
    int i;
    
    logprintf(LOG_INFO,"slinke_init");
    signal_length=hw.code_length*1000000/1200;
    
    if(!tty_create_lock(hw.device)){
        logprintf(LOG_ERR,"could not create lock files");
        return(0);
    } /* if */

    if((hw.fd=open(hw.device,O_RDWR|O_NOCTTY))<0){
        logprintf(LOG_ERR,"could not open %s",hw.device);
        logperror(LOG_ERR,"slinke_init()");
        tty_delete_lock();
        return(0);
    } /* if */

    if(!tty_reset(hw.fd)){
        logprintf(LOG_ERR,"could not reset tty");
        slinke_deinit();
        return(0);
    } /* if */

    if(!tty_setbaud(hw.fd,19200)){
        logprintf(LOG_ERR,"could not set baud rate");
        slinke_deinit();
        return(0);
    } /* if */

    get_version(); 
    enable_port(PORT_IR0); 
    set_IR_receive_ports(0xff); 
    set_sample_period(250); 
    set_IR_timeout_period(1000); 
    
    for (i=0; i<MAX_PORT_COUNT; i++){
       queue[i].port_id = (unsigned char)i; 
       queue[i].length  = 0; 
       queue[i].bufsize = QUEUE_BUF_INIT_SIZE; 
       queue[i].buf     = (unsigned char*)slinke_malloc(QUEUE_BUF_INIT_SIZE);
       if (queue[i].buf == NULL){
           logprintf(LOG_ERR,"could not create port queue buffer");
           slinke_deinit();
           return(0);
       } /* if */
    } /* for */
    
    return(1);
} /* slinke_init */

/*****************************************************************************/
static int signal_queue_rd_idx,signal_queue_bufsize,signal_queue_length = 0;
static lirc_t *signal_queue_buf = NULL; 

/*****************************************************************************/
int slinke_deinit(void){
    int i;
    
    close(hw.fd);
    tty_delete_lock();
    
    if (signal_queue_buf != NULL)
    {
	free(signal_queue_buf);
	signal_queue_buf=NULL;
    }

    if (slinke_settings.version != NULL)
    {
        free(slinke_settings.version);
	slinke_settings.version=NULL;
    }
    
    for (i=0; i<MAX_PORT_COUNT ; i++){
       if(queue[i].buf!=NULL) free(queue[i].buf);
    } /* for */
    
    return(1);
} /* slinke_deinit */

/*****************************************************************************/
#ifdef DEBUG
char *msgIdReprs[] = {
    "unknown","port receive","port disabled","port enabled",
    "transmission timeout","illegal command","receive error",
    "sampling period equals","carrier period equals","timeout period equals",
    "minimum message length equals","transmit ports equal",
    "receive ports equal","last receive port equals",
    "receive port polarities equal","ir routing table equals",
    "invalid sample period","handshaking mode equals",
    "configuration direction equals","baud rate equals",
    "serial port receive buffer overflow","serial port receive buffer overrun",
    "serial port receive framing error","baud rate illegal","version equals",
    "defaults loaded","defaults saved","serial number equals",
    "seeprom write error",
};
char *slinkePorts[] = {"SL0","SL1","SL2","SL3","IR0","PAR","SER","SYS"};
#endif

/*****************************************************************************/
lirc_t readdata(void){
    lirc_t result;
    if (signal_queue_buf == NULL) return 0;
    if (signal_queue_rd_idx < signal_queue_length){
       result = signal_queue_buf[signal_queue_rd_idx++];
    }else{
       result = 0;
    } /* if */

    LOGPRINTF(3,"readdata: %d @ %d",
	      signal_to_int(result),signal_queue_rd_idx);
    return result;
} /* readdata */

static void reset_signal_queue(){
    if (signal_queue_buf == NULL){
        signal_queue_bufsize = 32; 
	signal_queue_buf = (lirc_t*)slinke_malloc(signal_queue_bufsize*
						  sizeof(lirc_t));
	if (signal_queue_buf == NULL){
            logprintf(LOG_ERR,"could not create signal queue buffer");
            return;
        } /* if */
    } /* if */
    signal_queue_buf[0] = PULSE_MASK; /* sync space */ 
    signal_queue_length = 1; 
    signal_queue_rd_idx = 0; 
} /* reset_signal_queue */

static void app_signal(int is_pulse, int period_len){
    lirc_t signal;
    
    if (signal_queue_buf == NULL) return;
    signal = (slinke_settings.sample_period > 0)
           ? (period_len * slinke_settings.sample_period) / 5
           : period_len;
    if (signal > PULSE_MASK) signal = PULSE_MASK; 
    if (is_pulse) signal |= PULSE_BIT;

    if (signal_queue_length >= signal_queue_bufsize){
        signal_queue_bufsize *= 2;
        signal_queue_buf = (lirc_t*)slinke_realloc
		(signal_queue_buf,signal_queue_bufsize*sizeof(lirc_t));
        if (signal_queue_buf == NULL){
            logprintf(LOG_ERR,"could not enlarge signal queue buffer");
            return;
        } /* if */
    } /* if */
    signal_queue_buf[signal_queue_length++] = signal; 
} /* app_signal */

static void end_of_signals(){
    if (signal_queue_buf == NULL) return;
    if (signal_queue_length > 0){
        int last_signal_idx = signal_queue_length-1; 
        if (is_space(signal_queue_buf[last_signal_idx])){
            signal_queue_buf[last_signal_idx] = PULSE_MASK; 
        }else{
            app_signal(/*is_pulse=*/0,PULSE_MASK); /* end sync space */
        } /* if */
    } /* if */
} /* end_of_signals */

#ifdef DEBUG
static char *signal_queue_to_string(){
    static char buf[10*QUEUE_BUF_MAX_SIZE];
    char s[30];
    int i;
    
    if (signal_queue_buf == NULL) return "";
    sprintf(buf,"{%d",signal_to_int(signal_queue_buf[0]));
    for (i=1; i<signal_queue_length; i++){
        sprintf(s,",%d",signal_to_int(signal_queue_buf[i]));
	if (strlen(buf)+strlen(s)+2 >= sizeof(buf)) break;
        strcat(buf,s); 
    } /* for */
    strcat(buf,"}"); 
    return buf;
} /* signal_queue_to_string */
#endif

/*****************************************************************************/
static char *process_rx_bytes(struct port_queue_rec *q, struct ir_remote *remotes){
    char *resp = NULL; 
    unsigned char *buf = q->buf; 
    int len = q->length;

    LOGPRINTF(2,"port #%d: %s",q->port_id,to_byte_string(buf,len));
    LOGPRINTF(2,"%s (0x%02x %s) len = %d",
	      slinkePorts[q->port_id],q->msg_id,msgIdReprs[q->msg_id],len);

    switch (q->msg_id){
    case MSG_ID_PORT_RECEIVE:{
         int i;
         int curr_period_len = 0; 
         int curr_period_is_pulse = 1; 
         reset_signal_queue(); 
         for (i=0; i<len; i++){
             int len = buf[i] & 0x7f; 
             int is_pulse = ((buf[i] & 0x80) != 0);
             if (is_pulse == curr_period_is_pulse){
                 curr_period_len += len;
             }else{
                 app_signal(curr_period_is_pulse,curr_period_len); 
                 curr_period_len = len; 
                 curr_period_is_pulse = is_pulse; 
             } /* if */
         } /* for */
         if (curr_period_len > 0) app_signal(curr_period_is_pulse,curr_period_len); 
         end_of_signals(); 

	 LOGPRINTF(2,"%d signals: %s",
		   signal_queue_length,signal_queue_to_string());

	     resp = decode_all(remotes);
         }break; 
    case MSG_ID_SAMPLING_PERIOD_EQUALS:{
         if (len == 2){
             slinke_settings.sample_period = (buf[0] << 8) | (buf[1]); 
             logprintf(LOG_INFO,"sample period %d * 1/5 usec",
		       slinke_settings.sample_period);
         } /* if */
         }break; 
    case MSG_ID_TIMEOUT_PERIOD_EQUALS:{
         if (len == 2){
             slinke_settings.timeout_samples = (buf[0] << 8) | (buf[1]); 
             logprintf(LOG_INFO,"timeout %d samples",
		       slinke_settings.timeout_samples);
         } /* if */
         }break; 
    case MSG_ID_VERSION_EQUALS:{
         if (len == 1){
             char s[10];
             sprintf(s,"%d.%d"
                    ,(unsigned)((buf[0] >> 4) & 0xf)
                    ,(unsigned)( buf[0]       & 0xf)); 
             if (slinke_settings.version != NULL)
	         free(slinke_settings.version);
             slinke_settings.version = strdup(s);
             if (slinke_settings.version == NULL){
                 logprintf(LOG_ERR,"could not allocate version string");
             }else{
                 logprintf(LOG_INFO,"Slink-e version %s",
			   slinke_settings.version);
             } /* if */
         } /* if */
         }break; 
    } /* switch */

    q->length = 0; 
    return resp;
} /* process_rx_bytes */

/*****************************************************************************/
static void enqueue_byte(struct port_queue_rec *q, unsigned char b){
    if (q->buf == NULL) return;
    if (q->length > q->bufsize){
       if (q->bufsize >= QUEUE_BUF_MAX_SIZE){
           if (q->bufsize == QUEUE_BUF_MAX_SIZE){
               LOGPRINTF(1,"maximum port queue buffer size reached");
           } /* if */
           return;
       } /* if */
       
       q->bufsize *= 2;
       q->buf = (unsigned char*)slinke_realloc(q->buf,q->bufsize);
       if (q->buf == NULL){
            logprintf(LOG_ERR,"could not enlarge port queue buffer");
            return;
       } /* if */
    } /* if */
    q->buf[q->length++] = b; 
} /* enqueue_byte */

/*****************************************************************************/
static char *accept_rx_byte(unsigned char rch, struct ir_remote *remotes){
    static int state = RX_STATE_IDLE; 
    static int msg_len;
    static unsigned char port_id = 0; 
    static struct port_queue_rec *curr_queue;
    char *resp = NULL; 

    LOGPRINTF(3,"accept_rx_byte %02x",rch);
    switch (state){

    case RX_STATE_IDLE: 
         port_id = (rch >> 5) & 7; 
         msg_len = rch & 0x1f; 
         curr_queue = &(queue[port_id]);
         switch (msg_len){
         case 0x00: /* PRE - port receive end */
              resp = process_rx_bytes(curr_queue,remotes);
              break; 
         case 0x1F: /* PSM - port special message */
              state = RX_STATE_PSM; 
              return NULL;
         default: 
              curr_queue->msg_id = MSG_ID_PORT_RECEIVE; 
              state = RX_STATE_RECEIVE; 
              return NULL;
         } /* switch */ 
         break;

    case RX_STATE_PSM:
         switch (rch){
         case 0x02: curr_queue->msg_id = MSG_ID_PORT_DISABLED;
                    break;
         case 0x03: curr_queue->msg_id = MSG_ID_PORT_ENABLED;
                    break; 
         case 0x81: curr_queue->msg_id = MSG_ID_TRANSMISSION_TIMEOUT;
                    break;
         case 0xff: curr_queue->msg_id = MSG_ID_ILLEGAL_COMMAND;
                    break;
         case 0x80: curr_queue->msg_id = MSG_ID_RECEIVE_ERROR;
                    break;
         case 0x82: curr_queue->msg_id = MSG_ID_INVALID_SAMPLE_PERIOD;
                    break;
         case 0x83: curr_queue->msg_id = MSG_ID_SERIAL_PORT_RECEIVE_BUFFER_OVERFLOW;
                    break;
         case 0x86: curr_queue->msg_id = MSG_ID_SERIAL_PORT_RECEIVE_BUFFER_OVERRUN;
                    break;
         case 0x85: curr_queue->msg_id = MSG_ID_SERIAL_PORT_RECEIVE_FRAMING_ERROR;
                    break;
         case 0x84: curr_queue->msg_id = MSG_ID_BAUD_RATE_ILLEGAL;
                    break;
         case 0x0f: curr_queue->msg_id = MSG_ID_DEFAULTS_LOADED;
                    break;
         case 0x0d: curr_queue->msg_id = MSG_ID_DEFAULTS_SAVED;
                    break;
         case 0x8f: curr_queue->msg_id = MSG_ID_SEEPROM_WRITE_ERROR;
                    break;
         default:
             state = RX_STATE_PSM_PAR;
             msg_len = 1;
             switch (rch){
             case 0x04: curr_queue->msg_id = MSG_ID_SAMPLING_PERIOD_EQUALS;
                        msg_len = 2;
                        break;
             case 0x06: curr_queue->msg_id = MSG_ID_CARRIER_PERIOD_EQUALS;
                        msg_len = 2;
                        break;
             case 0x0c: if (port_id == PORT_SYS){
                            curr_queue->msg_id = MSG_ID_SERIAL_NUMBER_EQUALS;
                            msg_len = 8;
                        }else{
                            curr_queue->msg_id = MSG_ID_TIMEOUT_PERIOD_EQUALS;
                            msg_len = 2;
                        } /* if */
                        break;
             case 0x0e: curr_queue->msg_id = MSG_ID_MINIMUM_MESSAGE_LENGTH_EQUALS;
                        break;
             case 0x08: if (port_id == PORT_IR0){
                            curr_queue->msg_id = MSG_ID_MINIMUM_MESSAGE_LENGTH_EQUALS;
                        }else{
                            curr_queue->msg_id = MSG_ID_BAUD_RATE_EQUALS;
                        } /* if */
                        break;
             case 0x01: curr_queue->msg_id = MSG_ID_LAST_RECEIVE_PORT_EQUALS;
                        break;
             case 0x0b: if (port_id == PORT_SYS){
                            curr_queue->msg_id = MSG_ID_VERSION_EQUALS;
                        }else{
                            curr_queue->msg_id = MSG_ID_RECEIVE_PORT_POLARITIES_EQUAL;
                        } /* if */
                        break;
             case 0x0a: curr_queue->msg_id = MSG_ID_IR_ROUTING_TABLE_EQUALS;
                        msg_len = 8;
                        break;
             case 0x10: curr_queue->msg_id = MSG_ID_HANDSHAKING_MODE_EQUALS;
                        break; 
             case 0x12: curr_queue->msg_id = MSG_ID_CONFIGURATION_DIRECTION_EQUALS;
                        break;
             } /* switch */
             return NULL;
         } /* switch */

         resp = process_rx_bytes(curr_queue,remotes);
         break; 
    
    case RX_STATE_PSM_PAR:
         enqueue_byte(curr_queue,rch); 
         if (--msg_len > 0) return NULL;
         resp = process_rx_bytes(curr_queue,remotes); 
         break;

    case RX_STATE_RECEIVE:
         enqueue_byte(curr_queue,rch); 
         if (--msg_len > 0) return NULL;
         break;

    default:
         return NULL;
    } /* switch */ 

    state = RX_STATE_IDLE; 
    return resp;
} /* accept_rx_byte */

/*****************************************************************************/
char *slinke_rec(struct ir_remote *remotes){
    char *resp = NULL; 
    int byteNo = 0; 
    unsigned char rch;

    do{
        if (!waitfordata(TIMEOUT)){
	    LOGPRINTF(0,"timeout reading byte %d",byteNo);
            return(NULL);
        } /* if */

        if (read(hw.fd,&rch,1) != 1){
	    LOGPRINTF(0,"reading of byte %d failed",byteNo);
            return(NULL);
        } /* if */
        byteNo++;

	LOGPRINTF(4,"byte %d: %02x",byteNo,rch);
    } while ((resp=accept_rx_byte(rch,remotes)) == NULL);
    gettimeofday(&end,NULL);
    last=end;

    return resp;
} /* slinke_rec */

/*****************************************************************************/
extern struct rbuf rec_buffer;

int slinke_decode(struct ir_remote *remote
                 ,ir_code          *prep
                 ,ir_code          *codep
                 ,ir_code          *postp
                 ,int              *repeat_flagp
                 ,lirc_t           *remaining_gapp){

    rewind_rec_buffer(); 
    rec_buffer.wptr = 0; 
    signal_queue_rd_idx = 0; 
	return receive_decode(remote
                         ,prep
                         ,codep
                         ,postp
                         ,repeat_flagp
                         ,remaining_gapp);
} /* slinke_decode */
