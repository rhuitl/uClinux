
/****************************************************************************
 ** hw_pinsys.c *************************************************************
 ****************************************************************************
 *
 * adapted routines for Pinnacle Systems PCTV (pro) receiver
 * 
 * Original routines from hw_pixelview.c :
 * Copyright (C) 1999 Christoph Bartelmus <lirc@bartelmus.de>
 *
 * Adapted by Bart Alewijnse (scarfman@geocities.com)
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

#include "hw_pinsys.h"
#include <termios.h>

extern struct ir_remote *repeat_remote,*last_remote;

/* Technically, the code is three bytes long, however, only five bits
   in the last byte are needed to identify a button. If you don't
   define the following, the ir_cide code will only be the last
   byte. I don't know why I left it in.. well, who knows.

#define PINSYS_THREEBYTE

*/

#define REPEAT_FLAG 0x40

unsigned char b[3], t;
struct timeval start,end,last;
lirc_t gap,signal_length;
ir_code code;

struct hardware hw=
{
	LIRC_DRIVER_DEVICE,       /* default device */
	-1,                       /* fd */
	LIRC_CAN_REC_LIRCCODE,    /* features */
	0,                        /* send_mode */
	LIRC_MODE_LIRCCODE,       /* rec_mode */
	/* remember to change signal_length if you correct this one */
#ifdef PINSYS_THREEBYTE
	24,                       /* code_length */
#else
	8,                        /* code_length */
#endif
	pinsys_init,              /* init_func */
	pinsys_deinit,            /* deinit_func */
	NULL,                     /* send_func */
	pinsys_rec,               /* rec_func */
	pinsys_decode             /* decode_func */
};

/**** start of autodetect code ***************************/
int is_it_is_it_huh(int port)
{
	int j;
	
	tty_clear(port,1,0);
	
	ioctl(port,TIOCMGET, &j);
	if((j&TIOCM_CTS) || (j&TIOCM_DSR))
	{
		return 0;
	}
  
	tty_set(port,1,0);
	ioctl(port,TIOCMGET, &j);
	if((!(j&TIOCM_CTS)) || (j&TIOCM_DSR))
	{
		return 0;
	}
	return 1;
}

/* returns 0-3, the port, or -1 if it can't find the device */
int autodetect(void)
{
	int port,i;
	long backup;
	char device[20];

	/* hardcoded the device names.. it's easy enough to change
	   that, but it's unlikely to be on something else. */

	for(i=0;i<4;i++)
	{
		sprintf(device,"/dev/ttyS%d",i);
		
		if(!tty_create_lock(device))
		{
			continue;
		}
		port=open("/dev/ttyS0", O_RDONLY | O_NOCTTY);
		if(port < 0 )
		{
			logprintf(LOG_WARNING,"couldn't open %s",device);
			tty_delete_lock();
			continue;
		}
		else
		{
			ioctl(port,TIOCMGET, &backup);
			
			if(is_it_is_it_huh(port))
			{
				ioctl(port,TIOCMSET, &backup);
				close(port);
				tty_delete_lock();
				return i;
			}
			ioctl(port,TIOCMSET, &backup);
			close(port);
		}
		tty_delete_lock();
	}
	return -1;
}
/************** end of autodetect code *************/


int pinsys_decode(struct ir_remote *remote,
		  ir_code *prep,ir_code *codep,ir_code *postp,
		  int *repeat_flagp,lirc_t *remaining_gapp)
{
	if(!map_code(remote,prep,codep,postp,
		     0,0,8,code&(~REPEAT_FLAG),0,0))
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
		
		/* let's believe the remote */
		if(code&REPEAT_FLAG)
		{
			*repeat_flagp=1;
		}
	}
	
	*remaining_gapp=is_const(remote) ?
		(remote->gap>signal_length ? remote->gap-signal_length:0):
		remote->gap;
	
	LOGPRINTF(1,"code: %llx\n",(unsigned long long) *codep);
	LOGPRINTF(1,"repeat_flag: %d\n",*repeat_flagp);
	LOGPRINTF(1,"gap: %lu\n",(unsigned long) gap);
	LOGPRINTF(1,"rem: %lu\n",(unsigned long) remote->remaining_gap);
	LOGPRINTF(1,"signal length: %lu\n",(unsigned long) signal_length);
	
	return(1);
}

int pinsys_init(void)
{
	signal_length=(hw.code_length+(hw.code_length/8)*2)*1000000/1200;

	if(!tty_create_lock(hw.device))
	{
		logprintf(LOG_ERR,"could not create lock files");
		return(0);
	}
	if((hw.fd=open(hw.device,O_RDWR|O_NONBLOCK|O_NOCTTY))<0)
	{
		int detected;
		/* last character gets overwritten */
		char auto_lirc_device[]="/dev/ttyS_";
		
		tty_delete_lock();
		logprintf(LOG_WARNING,"could not open %s, "
			  "autodetecting on /dev/ttyS[0-3]",hw.device);
		logperror(LOG_WARNING,"pinsys_init()");
		/* it can also mean you compiled serial support as a
		   module and it isn't inserted, but that's unlikely
		   unless you're me. */
		
		detected=autodetect();
		
		if (detected==-1)
		{
			logprintf(LOG_ERR,"no device found on /dev/ttyS[0-3]");
			tty_delete_lock();
			return(0);
		}
		else /* detected */
		{
			auto_lirc_device[9]='0'+detected;
			hw.device=auto_lirc_device;
			if((hw.fd=open(hw.device,
				       O_RDWR|O_NONBLOCK|O_NOCTTY))<0)
			{
				/* unlikely, but hey. */
				logprintf(LOG_ERR,"couldn't open "
					  "autodetected device \"%s\"",
					  hw.device);
				logperror(LOG_ERR,"pinsys_init()");
				tty_delete_lock();
				return(0);
			}
		}
	}
	if(!tty_reset(hw.fd))
	{
		logprintf(LOG_ERR,"could not reset tty");
		pinsys_deinit();
		return(0);
	}
	if(!tty_setbaud(hw.fd,1200))
	{
		logprintf(LOG_ERR,"could not set baud rate");
		pinsys_deinit();
		return(0);
	}
	/* set RTS, clear DTR */
	if(!tty_set(hw.fd,1,0) || !tty_clear(hw.fd,0,1))
	{ 
		logprintf(LOG_ERR,"could not set modem lines (DTR/RTS)");
		pinsys_deinit();
		return(0);
	}

	/* I dunno, but when lircd starts may log `reading of byte 1
	   failed' I know that happened when testing, it's a zero
	   byte. Problem is, flushing doesn't fix it. It's not fatal,
	   it's an indication that it gets fixed.  still... */

	if (tcflush(hw.fd, TCIFLUSH)<0)
	{
		logprintf(LOG_ERR,"could not flush input buffer");
		pinsys_deinit();
		return(0);
	}
	return(1);
}

int pinsys_deinit(void)
{
	close(hw.fd);
	tty_delete_lock();
	return(1);
}

char *pinsys_rec(struct ir_remote *remotes)
{
	char *m;
	int i;
	
	last=end;
	gettimeofday(&start,NULL);
	
	for(i=0;i<3;i++)
	{
		if (i>0)
		{
			if(!waitfordata(10000))
			{
				logprintf(LOG_WARNING,
					  "timeout reading byte %d",i);
				/* likely to be !=3 bytes, so flush. */
				tcflush(hw.fd, TCIFLUSH);
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

#ifdef PINSYS_THREEBYTE
	code = (b[2]) | (b[1]<<8) | (b[0]<<16);
#else
	code = b[2];
#endif

	LOGPRINTF(1," -> %016lx",(unsigned long) code);
	m=decode_all(remotes);
	return(m);
}
