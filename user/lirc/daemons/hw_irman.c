/*      $Id: hw_irman.c,v 5.4 2001/01/21 12:54:42 columbus Exp $      */

/****************************************************************************
 ** hw_irman.c **********************************************************
 ****************************************************************************
 *
 * routines for Irman
 * 
 * Copyright (C) 1999 Christoph Bartelmus <lirc@bartelmus.de>
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <irman.h>

#include "hardware.h"
#include "serial.h"
#include "ir_remote.h"
#include "lircd.h"
#include "hw_irman.h"

extern struct ir_remote *repeat_remote,*last_remote;

unsigned char *codestring;
struct timeval start,end,last;
lirc_t gap;
ir_code code;

#define CODE_LENGTH 64

struct hardware hw=
{
	LIRC_DRIVER_DEVICE,       /* default device */
	-1,                       /* fd */
	LIRC_CAN_REC_LIRCCODE,    /* features */
	0,                        /* send_mode */
	LIRC_MODE_LIRCCODE,       /* rec_mode */
	CODE_LENGTH,              /* code_length */
	irman_init,               /* init_func */
	irman_deinit,             /* deinit_func */
	NULL,                     /* send_func */
	irman_rec,                /* rec_func */
	irman_decode              /* decode_func */
};

int irman_decode(struct ir_remote *remote,
		     ir_code *prep,ir_code *codep,ir_code *postp,
		     int *repeat_flagp,lirc_t *remaining_gapp)
{
	ir_code help,mask;
	int i;

	if(remote->pre_data_bits+
	   remote->bits+
	   remote->post_data_bits!=CODE_LENGTH ||
	   remote->flags&CONST_LENGTH) return(0);

	help=code;

	if(remote->post_data_bits>0)
	{
		mask=0;
		for(i=0;i<remote->post_data_bits;i++)
		{
			mask=mask<<1;
			mask=mask|1;
		}
		*postp=help&mask;
		help=help>>remote->post_data_bits;
	}
	if(remote->bits>0)
	{
		mask=0;
		for(i=0;i<remote->bits;i++)
		{
			mask=mask<<1;
			mask=mask|1;
		}
		*codep=help&mask;
		help=help>>remote->bits;
	}
	if(remote->pre_data_bits>0)
	{
		mask=0;
		for(i=0;i<remote->pre_data_bits;i++)
		{
			mask=mask<<1;
			mask=mask|1;
		}
		*prep=help&mask;
		help=help>>remote->pre_data_bits;
	}
	
	if(start.tv_sec-last.tv_sec>=2) /* >1 sec */
	{
		*repeat_flagp=0;
	}
	else
	{
		gap=time_elapsed(&last,&start);
		
		if(gap<=remote->remaining_gap*(100+remote->eps)/100
		   || gap<=remote->remaining_gap+remote->aeps)
			*repeat_flagp=1;
		else
			*repeat_flagp=0;
	}
	
	*remaining_gapp=remote->gap;

	LOGPRINTF(1,"pre: %llx",(unsigned long long) *prep);
	LOGPRINTF(1,"code: %llx",(unsigned long long) *codep);
	LOGPRINTF(1,"post: %llx",(unsigned long long) *postp);
	LOGPRINTF(1,"repeat_flag: %d",*repeat_flagp);
	LOGPRINTF(1,"gap: %lu",(unsigned long) gap);
	LOGPRINTF(1,"rem: %lu",(unsigned long) remote->remaining_gap);
	return(1);
}

int irman_init(void)
{
	if(!tty_create_lock(hw.device))
	{
		logprintf(LOG_ERR,"could not create lock files");
		return(0);
	}
	if((hw.fd=ir_init(hw.device))<0)
	{
		logprintf(LOG_ERR,"could not open %s",hw.device);
		logperror(LOG_ERR,"irman_init()");
		tty_delete_lock();
		return(0);
	}
	return(1);
}

int irman_deinit(void)
{
	ir_finish();
	sleep(1); /* give hardware enough time to reset */
	close(hw.fd);
	tty_delete_lock();
	return(1);
}

char *irman_rec(struct ir_remote *remotes)
{
	static char *text=NULL;
	char *m;
	int i;
	
	last=end;
	gettimeofday(&start,NULL);
	codestring=ir_get_code();
	gettimeofday(&end,NULL);
	if(codestring==NULL)
	{
#               ifdef DEBUG
		if(errno==IR_EDUPCODE)
		{
			LOGPRINTF(1,"received \"%s\" (dup - ignored)",
				  text ? text:"(null - bug)");
		}
		else if(errno==IR_EDISABLED)
		{
			LOGPRINTF(1,"irman not initialised (this is a bug)");
		}
		else
		{
			LOGPRINTF(1,"error reading code: \"%s\"",
				  ir_strerror(errno));
		}
#               endif
		return(NULL);
	}
	
	text=ir_code_to_text(codestring);
	LOGPRINTF(1,"received \"%s\"",text);

	/* this is only historical but it's necessary for
	   compatibility to older versionns and it's handy to
	   recognize Irman config files */
	code=0xffff;

	for(i=0;i<IR_CODE_LEN;i++)
	{
		code=code<<8;
		code=code|(ir_code) (unsigned char) codestring[i];
	}

	m=decode_all(remotes);
	return(m);
}
