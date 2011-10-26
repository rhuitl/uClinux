/*      $Id: hw_default.c,v 5.19 2000/12/08 23:36:29 columbus Exp $      */

/****************************************************************************
 ** hw_default.c ************************************************************
 ****************************************************************************
 *
 * routines for hardware that supports ioctl() interface
 * 
 * Copyright (C) 1999 Christoph Bartelmus <lirc@bartelmus.de>
 *
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

/* disable daemonise if maintainer mode SIM_REC / SIM_SEND defined */
#if defined(SIM_REC) || defined (SIM_SEND)
# undef DAEMONIZE
#endif

#include "hardware.h"
#include "ir_remote.h"
#include "lircd.h"
#include "receive.h"
#include "transmit.h"
#include "hw_default.h"

extern struct ir_remote *repeat_remote;

unsigned long supported_send_modes[]=
{
	/* LIRC_CAN_SEND_STRING, I don't think there ever will be a driver 
	   that supports that */
	/* LIRC_CAN_SEND_LIRCCODE, */
        /* LIRC_CAN_SEND_CODE, */
	/* LIRC_CAN_SEND_MODE2, this one would be very easy */
	LIRC_CAN_SEND_PULSE,
	/* LIRC_CAN_SEND_RAW, */
	0
};
unsigned long supported_rec_modes[]=
{
	LIRC_CAN_REC_STRING,
	LIRC_CAN_REC_LIRCCODE,
        LIRC_CAN_REC_CODE,
	LIRC_CAN_REC_MODE2,
	/* LIRC_CAN_REC_PULSE, shouldn't be too hard */
	/* LIRC_CAN_REC_RAW, */
	0
};

struct hardware hw=
{
	LIRC_DRIVER_DEVICE, /* default device */
	-1,                 /* fd */
	0,                  /* features */
	0,                  /* send_mode */
	0,                  /* rec_mode */
	0,                  /* code_length */
	default_init,       /* init_func */
	default_deinit,     /* deinit_func */
	default_send,       /* send_func */
	default_rec,        /* rec_func */
	default_decode,     /* decode_func */
};

/*
  decoding stuff
*/

lirc_t readdata(void)
{
	lirc_t data;
	int ret;

#if defined(SIM_REC) && !defined(DAEMONIZE)
	while(1)
	{
		unsigned long scan;

		ret=fscanf(stdin,"space %ld\n",&scan);
		if(ret==1)
		{
			data=(lirc_t) scan;
			break;
		}
		ret=fscanf(stdin,"pulse %ld\n",&scan);
		if(ret==1)
		{
			data=(lirc_t) scan|PULSE_BIT;
			break;
		}
		ret=fscanf(stdin,"%*s\n");
		if(ret==EOF)
		{
			dosigterm(SIGTERM);
		}
	}
#else
	ret=read(hw.fd,&data,sizeof(data));
	if(ret!=sizeof(data))
	{
		LOGPRINTF(1,"error reading from lirc");
		LOGPERROR(1,NULL);
		dosigterm(SIGTERM);
	}
#endif
	return(data);
}

/*
  interface functions
*/

int default_init()
{
#if defined(SIM_SEND) && !defined(DAEMONIZE)
	hw.fd=STDOUT_FILENO;
	hw.features=LIRC_CAN_SEND_PULSE;
	hw.send_mode=LIRC_MODE_PULSE;
	hw.rec_mode=0;
#elif defined(SIM_REC) && !defined(DAEMONIZE)
	hw.fd=STDIN_FILENO;
	hw.features=LIRC_CAN_REC_MODE2;
	hw.send_mode=0;
	hw.rec_mode=LIRC_MODE_MODE2;
#else
	struct stat s;
	int i;
	
	/* FIXME: other modules might need this, too */
	init_rec_buffer();
	init_send_buffer();
	if((hw.fd=open(hw.device,O_RDWR))<0)
	{
		logprintf(LOG_ERR,"could not open %s",hw.device);
		logperror(LOG_ERR,"default_init()");
		return(0);
	}
	if(fstat(hw.fd,&s)==-1)
	{
		default_deinit();
		logprintf(LOG_ERR,"could not get file information");
		logperror(LOG_ERR,"default_init()");
		return(0);
	}
	if(S_ISFIFO(s.st_mode))
	{
		LOGPRINTF(1,"using defaults for the Irman");
		hw.features=LIRC_CAN_REC_MODE2;
		hw.rec_mode=LIRC_MODE_MODE2; /* this might change in future */
		return(1);
	}
	else if(!S_ISCHR(s.st_mode))
	{
		default_deinit();
		logprintf(LOG_ERR,"%s is not a character device!!!",
			  hw.device);
		logperror(LOG_ERR,"something went wrong during "
			  "installation");
		return(0);
	}
	else if(ioctl(hw.fd,LIRC_GET_FEATURES,&hw.features)==-1)
	{
		logprintf(LOG_ERR,"could not get hardware features");
		logprintf(LOG_ERR,"this device driver does not "
			  "support the new LIRC interface");
		logprintf(LOG_ERR,"make sure you use a current "
			  "version of the driver");
		default_deinit();
		return(0);
	}
#       ifdef DEBUG
	else
	{
		if(!(LIRC_CAN_SEND(hw.features) || 
		     LIRC_CAN_REC(hw.features)))
		{
			LOGPRINTF(1,"driver supports neither "
				  "sending nor receiving of IR signals");
		}
		if(LIRC_CAN_SEND(hw.features) && LIRC_CAN_REC(hw.features))
		{
			LOGPRINTF(1,"driver supports both sending and "
				  "receiving");
		}
		else if(LIRC_CAN_SEND(hw.features))
		{
			LOGPRINTF(1,"driver supports sending");
		}
		else if(LIRC_CAN_REC(hw.features))
		{
			LOGPRINTF(1,"driver supports receiving");
		}
	}
#       endif
	
	/* set send/receive method */
	hw.send_mode=0;
	if(LIRC_CAN_SEND(hw.features))
	{
		for(i=0;supported_send_modes[i]!=0;i++)
		{
			if(hw.features&supported_send_modes[i])
			{
				unsigned long mode;

				mode=LIRC_SEND2MODE(supported_send_modes[i]);
				if(ioctl(hw.fd,LIRC_SET_SEND_MODE,&mode)==-1)
				{
					logprintf(LOG_ERR,"could not set "
						  "send mode");
					logperror(LOG_ERR,"default_init()");
					default_deinit();
					return(0);
				}
				hw.send_mode=LIRC_SEND2MODE
				(supported_send_modes[i]);
				break;
			}
		}
		if(supported_send_modes[i]==0)
		{
			logprintf(LOG_NOTICE,"the send method of the "
				  "driver is not yet supported by lircd");
		}
	}
	hw.rec_mode=0;
	if(LIRC_CAN_REC(hw.features))
	{
		for(i=0;supported_rec_modes[i]!=0;i++)
		{
			if(hw.features&supported_rec_modes[i])
			{
				unsigned long mode;

				mode=LIRC_REC2MODE(supported_rec_modes[i]);
				if(ioctl(hw.fd,LIRC_SET_REC_MODE,&mode)==-1)
				{
					logprintf(LOG_ERR,"could not set "
						  "receive mode");
					logperror(LOG_ERR,"default_init()");
					return(0);
				}
				hw.rec_mode=LIRC_REC2MODE
				(supported_rec_modes[i]);
				break;
			}
		}
		if(supported_rec_modes[i]==0)
		{
			logprintf(LOG_NOTICE,"the receive method of the "
				  "driver is not yet supported by lircd");
		}
	}
	if(hw.rec_mode==LIRC_MODE_CODE)
	{
		hw.code_length=8;
	}
	else if(hw.rec_mode==LIRC_MODE_LIRCCODE)
	{
		if(ioctl(hw.fd,LIRC_GET_LENGTH,&hw.code_length)==-1)
		{
			logprintf(LOG_ERR,"could not get code length");
			logperror(LOG_ERR,"default_init()");
			default_deinit();
			return(0);
		}
		if(hw.code_length>sizeof(ir_code)*CHAR_BIT)
		{
			logprintf(LOG_ERR,"lircd can not handle %lu bit "
				  "codes",hw.code_length);
			default_deinit();
			return(0);
		}
	}
	if(!(hw.send_mode || hw.rec_mode))
	{
		default_deinit();
		return(0);
	}
#endif
	return(1);
}

int default_deinit(void)
{
#if (!defined(SIM_SEND) || !defined(SIM_SEND)) || defined(DAEMONIZE)
	close(hw.fd);
#endif
	return(1);
}

int write_send_buffer(int lirc,int length,lirc_t *signals)
{
#if defined(SIM_SEND) && !defined(DAEMONIZE)
	int i;

	if(send_buffer.wptr==0 && length>0 && signals!=NULL)
	{
		for(i=0;;)
		{
			printf("pulse %lu\n",(unsigned long) signals[i++]);
			if(i>=length) break;
			printf("space %lu\n",(unsigned long) signals[i++]);
		}
		return(length*sizeof(lirc_t));
	}
	
	if(send_buffer.wptr==0) 
	{
		LOGPRINTF(1,"nothing to send");
		return(0);
	}
	for(i=0;;)
	{
		printf("pulse %lu\n",(unsigned long) send_buffer.data[i++]);
		if(i>=send_buffer.wptr) break;
		printf("space %lu\n",(unsigned long) send_buffer.data[i++]);
	}
	return(send_buffer.wptr*sizeof(lirc_t));
#else
	if(send_buffer.wptr==0 && length>0 && signals!=NULL)
	{
		return(write(lirc,signals,length*sizeof(lirc_t)));
	}
	
	if(send_buffer.wptr==0) 
	{
		LOGPRINTF(1,"nothing to send");
		return(0);
	}
	return(write(lirc,send_buffer.data,
		     send_buffer.wptr*sizeof(lirc_t)));
#endif
}

int default_send(struct ir_remote *remote,struct ir_ncode *code)
{
	lirc_t remaining_gap;

	/* things are easy, because we only support one mode */
	if(hw.send_mode!=LIRC_MODE_PULSE)
		return(0);

#if !defined(SIM_SEND) || defined(DAEMONIZE)
	if(hw.features&LIRC_CAN_SET_SEND_CARRIER)
	{
		unsigned int freq;
		
		freq=remote->freq==0 ? 38000:remote->freq;
		if(ioctl(hw.fd,LIRC_SET_SEND_CARRIER,&freq)==-1)
		{
			logprintf(LOG_ERR,"could not set modulation "
				  "frequency");
			logperror(LOG_ERR,NULL);
			return(0);
		}
	}
	if(hw.features&LIRC_CAN_SET_SEND_DUTY_CYCLE)
	{
		unsigned int duty_cycle;
		
		duty_cycle=remote->duty_cycle==0 ? 50:remote->duty_cycle;
		if(ioctl(hw.fd,LIRC_SET_SEND_DUTY_CYCLE,&duty_cycle)==-1)
		{
			logprintf(LOG_ERR,"could not set duty cycle");
			logperror(LOG_ERR,NULL);
			return(0);
		}
	}
#endif
	remaining_gap=remote->remaining_gap;
	if(!init_send(remote,code)) return(0);
	
#if !defined(SIM_SEND) || defined(DAEMONIZE)
	if(remote->last_code!=NULL)
	{
		struct timeval current;
		unsigned long usecs;
		
		gettimeofday(&current,NULL);
		usecs=time_left(&current,&remote->last_send,remaining_gap*2);
		if(usecs>0) usleep(usecs);
	}
#endif

	if(write_send_buffer(hw.fd,code->length,code->signals)==-1)
	{
		logprintf(LOG_ERR,"write failed");
		logperror(LOG_ERR,NULL);
		return(0);
	}
	else
	{
		gettimeofday(&remote->last_send,NULL);
		remote->last_code=code;
#if defined(SIM_SEND) && !defined(DAEMONIZE)
		printf("space %lu\n",(unsigned long) remote->remaining_gap);
#endif
	}
	return(1);
}

char *default_rec(struct ir_remote *remotes)
{
	char c;
	int n;
	static char message[PACKET_SIZE+1];


	if(hw.rec_mode==LIRC_MODE_STRING)
	{
		int failed=0;

		/* inefficient but simple, fix this if you want */
		n=0;
		do
		{
			if(read(hw.fd,&c,1)!=1)
			{
				logprintf(LOG_ERR,"reading in mode "
					  "LIRC_MODE_STRING failed");
				return(NULL);
			}
			if(n>=PACKET_SIZE-1)
			{
				failed=1;
				n=0;
			}
			message[n++]=c;
		}
		while(c!='\n');
		message[n]=0;
		if(failed) return(NULL);
		return(message);
	}
	else
	{
		if(!clear_rec_buffer()) return(NULL);
		return(decode_all(remotes));
	}
}

int default_decode(struct ir_remote *remote,
		   ir_code *prep,ir_code *codep,ir_code *postp,
		   int *repeat_flagp,lirc_t *remaining_gapp)
{
	return(receive_decode(remote,prep,codep,postp,
			      repeat_flagp,remaining_gapp));
}
