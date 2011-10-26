/*      $Id: hw_pixelview.c,v 5.12 2001/03/03 21:29:24 columbus Exp $      */

/****************************************************************************
 ** hw_pixelview.c **********************************************************
 ****************************************************************************
 *
 * routines for PixelView Play TV receiver
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

#include "hardware.h"
#include "serial.h"
#include "ir_remote.h"
#include "lircd.h"
#include "hw_pixelview.h"

extern struct ir_remote *repeat_remote,*last_remote;

unsigned char b[3];
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
	30,                       /* code_length */
	pixelview_init,           /* init_func */
	pixelview_deinit,         /* deinit_func */
	NULL,                     /* send_func */
	pixelview_rec,            /* rec_func */
	pixelview_decode          /* decode_func */
};

int pixelview_decode(struct ir_remote *remote,
		     ir_code *prep,ir_code *codep,ir_code *postp,
		     int *repeat_flagp,lirc_t *remaining_gapp)
{
#if 0
	if(remote->pone!=0  ||  remote->sone!=833) return(0);
	if(remote->pzero!=833 || remote->szero!=0) return(0);
#endif

	if(!map_code(remote,prep,codep,postp,
		     10,pre,20,code,0,0))
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

int pixelview_init(void)
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
		logperror(LOG_ERR,"pixelview_init()");
		tty_delete_lock();
		return(0);
	}
	if(!tty_reset(hw.fd))
	{
		logprintf(LOG_ERR,"could not reset tty");
		pixelview_deinit();
		return(0);
	}
	if(!tty_setbaud(hw.fd,1200))
	{
		logprintf(LOG_ERR,"could not set baud rate");
		pixelview_deinit();
		return(0);
	}
	return(1);
}

int pixelview_deinit(void)
{
	close(hw.fd);
	tty_delete_lock();
	return(1);
}

char *pixelview_rec(struct ir_remote *remotes)
{
	char *m;
	int i;
	
	last=end;
	gettimeofday(&start,NULL);
	for(i=0;i<3;i++)
	{
		if(i>0)
		{
			if(!waitfordata(50000))
			{
				logprintf(LOG_ERR,"timeout reading "
					  "byte %d",i);
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
	}
	gettimeofday(&end,NULL);
	
	pre=(reverse((ir_code) b[0],8)<<1)|1;
	code=(reverse((ir_code) b[1],8)<<1)|1;
	code=code<<10;
	code|=(reverse((ir_code) b[2],8)<<1)|1;
	
	m=decode_all(remotes);
	return(m);
}
