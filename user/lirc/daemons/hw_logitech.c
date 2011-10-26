/*      $Id: hw_logitech.c,v 1.10 2001/02/18 16:44:54 columbus Exp $      */

/****************************************************************************
 ** hw_logitech.c ***********************************************************
 ****************************************************************************
 *
 * routines for Logitech receiver 
 * 
 * Copyright (C) 1999 Christoph Bartelmus <lirc@bartelmus.de>
 * 	modified for logitech receiver by Isaac Lauer <inl101@alumni.psu.edu>
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

#include "hardware.h"
#include "serial.h"
#include "ir_remote.h"
#include "lircd.h"
#include "hw_logitech.h"

#define NUMBYTES 16 
#define TIMEOUT 20000

extern struct ir_remote *repeat_remote,*last_remote;

unsigned char b[NUMBYTES];
struct timeval start,end,last;
lirc_t gap,signal_length;
ir_code pre,code;

struct hardware hw=
{
	LIRC_DRIVER_DEVICE,       /* default device */
	-1,                       /* fd */
	LIRC_CAN_REC_LIRCCODE,    /* features */
	0,                        /* send_mode */
	LIRC_MODE_LIRCCODE,       /* rec_mode */
	16,                       /* code_length */
	logitech_init,            /* init_func */
	logitech_deinit,          /* deinit_func */
	NULL,                     /* send_func */
	logitech_rec,             /* rec_func */
	logitech_decode           /* decode_func */
};

int logitech_decode(struct ir_remote *remote,
		  ir_code *prep,ir_code *codep,ir_code *postp,
		  int *repeat_flagp,lirc_t *remaining_gapp)
{
	if(!map_code(remote,prep,codep,postp,
		     8,pre,8,code,0,0))
	{
		return(0);
	}

	gap=0;
	if(start.tv_sec-last.tv_sec>=2) /* >1 sec */
	{
		*repeat_flagp=0;
	}
	else
	{
		gap=(start.tv_sec-last.tv_sec)*1000000+
		start.tv_usec-last.tv_usec;
		
		if(gap<remote->remaining_gap*(100+remote->eps)/100
		   || gap<=remote->remaining_gap+remote->aeps)
			*repeat_flagp=1;
		else
			*repeat_flagp=0;
	}
	
	*remaining_gapp=is_const(remote) ?
	(remote->gap>signal_length ? remote->gap-signal_length:0):
	remote->gap;

	LOGPRINTF(1,"pre: %llx",(unsigned long long) *prep);
	LOGPRINTF(1,"code: %llx",(unsigned long long) *codep);
	LOGPRINTF(1,"repeat_flag: %d",*repeat_flagp);
	LOGPRINTF(1,"gap: %lu",(unsigned long) gap);
	LOGPRINTF(1,"rem: %lu",(unsigned long) remote->remaining_gap);
	LOGPRINTF(1,"signal length: %lu",(unsigned long) signal_length);

	return(1);
}

int logitech_init(void)
{
	signal_length=hw.code_length*1000000/1200;
	
	if(!tty_create_lock(hw.device))
	{
		logprintf(LOG_ERR,"could not create lock files");
		return(0);
	}
	if((hw.fd=open(hw.device,O_RDWR|O_NONBLOCK|O_NOCTTY))<0)
	{
		logprintf(LOG_ERR,"could not open %s",hw.device);
		logperror(LOG_ERR,"logitech_init()");
		tty_delete_lock();
		return(0);
	}
	if(!tty_reset(hw.fd))
	{
		logprintf(LOG_ERR,"could not reset tty");
		logitech_deinit();
		return(0);
	}
	if(!tty_setbaud(hw.fd,1200))
	{
		logprintf(LOG_ERR,"could not set baud rate");
		logitech_deinit();
		return(0);
	}
	return(1);
}

int logitech_deinit(void)
{
	close(hw.fd);
	tty_delete_lock();
	return(1);
}

char *logitech_rec(struct ir_remote *remotes)
{
	char *m;
	int i=0;
	int repeat, mouse_event;
	b[i]=0x00;

	last=end;
	gettimeofday(&start,NULL);
	while(b[i] != 0xAA)
	{
		i++;
		if(i>=NUMBYTES)
		{
			LOGPRINTF(0,"buffer overflow",i);
			break;
		}
		if(i>0)
		{
			if(!waitfordata(TIMEOUT))
			{
				logprintf(LOG_ERR,"timeout reading byte %d",i);
				return(NULL);
			}
		}
		if(read(hw.fd,&b[i],1)!=1)
		{
			logprintf(LOG_ERR,"reading of byte %d failed",i);
			logperror(LOG_ERR,NULL);
			return(NULL);
		}
		LOGPRINTF(1,"byte %d: %02x",i,b[i]);
		if(b[i] >= 0x40 && b[i] <= 0x6F)
		{
			mouse_event=b[i];
			b[1]=0xA0;
			b[2]=mouse_event;
			LOGPRINTF(1,"mouse event: %02x",mouse_event);
			break;
		}
	}
	gettimeofday(&end,NULL);

	if(b[1] == 0xA0) repeat=0;
	else repeat=1;
	if(!repeat) pre=(ir_code) b[1];
	else pre=0xA0;
	code=(ir_code) b[2];
	
	m=decode_all(remotes);
	return(m);
}
