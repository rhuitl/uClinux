/*      $Id: lirc_parallel.c,v 5.11 2001/01/18 21:32:23 columbus Exp $      */

/****************************************************************************
 ** lirc_parallel.c *********************************************************
 ****************************************************************************
 * 
 * lirc_parallel - device driver for infra-red signal receiving and
 *                 transmitting unit built by the author
 * 
 * Copyright (C) 1998 Christoph Bartelmus <lirc@bartelmus.de>
 *
 */ 

/***********************************************************************
 *************************       Includes        ***********************
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <linux/version.h>
#if LINUX_VERSION_CODE >= 0x020100 && LINUX_VERSION_CODE < 0x020200
#error "--- Sorry, 2.1.x kernels are not supported. ---"
#elif LINUX_VERSION_CODE >= 0x020200
#define KERNEL_2_2
#include <linux/config.h>
#ifdef CONFIG_SMP
#error "--- Sorry, this driver is not SMP safe. ---"
#endif
#endif

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/config.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/ioport.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/delay.h>

#include <asm/io.h>
#include <asm/signal.h>
#include <asm/irq.h>

#ifdef KERNEL_2_2
#include <asm/uaccess.h>
#include <linux/poll.h>
#include <linux/parport.h>
#endif

#include "drivers/lirc.h"

#include "lirc_parallel.h"

#define LIRC_DRIVER_NAME "lirc_parallel"

/***********************************************************************
 *************************   Globale Variablen   ***********************
 ***********************************************************************/

unsigned int irq = LIRC_IRQ;
unsigned int port = LIRC_PORT;
#ifdef LIRC_TIMER
unsigned int timer = 0;
unsigned int default_timer = LIRC_TIMER;
#endif

#define WBUF_SIZE (256)
#define RBUF_SIZE (256) /* this must be a power of 2 larger than 1 */

static lirc_t wbuf[WBUF_SIZE];
static lirc_t rbuf[RBUF_SIZE];

static struct wait_queue *lirc_wait=NULL;

unsigned int rptr=0,wptr=0;
unsigned int lost_irqs=0;
int is_open=0;

#ifdef KERNEL_2_2
struct parport *pport;
struct pardevice *ppdevice;
int is_claimed=0;
#endif

/***********************************************************************
 *************************   Interne Funktionen  ***********************
 ***********************************************************************/

unsigned int __inline__ in(int offset)
{
#ifdef KERNEL_2_2
	switch(offset)
	{
	case LIRC_LP_BASE:
		return(parport_read_data(pport));
	case LIRC_LP_STATUS:
		return(parport_read_status(pport));
	case LIRC_LP_CONTROL:
		return(parport_read_control(pport));
	}
	return(0); /* make compiler happy */
#else
	return(inb(port+offset));
#endif
}

void __inline__ out(int offset, int value)
{
#ifdef KERNEL_2_2
	switch(offset)
	{
	case LIRC_LP_BASE:
		parport_write_data(pport,value);
		break;
	case LIRC_LP_STATUS:
		parport_write_status(pport,value);
		break;
	case LIRC_LP_CONTROL:
		parport_write_control(pport,value);
		break;
	}
#else
	outb(value,port+offset);
#endif
}

unsigned int __inline__ lirc_get_timer(void)
{
	return(in(LIRC_PORT_TIMER)&LIRC_PORT_TIMER_BIT);
}

unsigned int __inline__  lirc_get_signal(void)
{
	return(in(LIRC_PORT_SIGNAL)&LIRC_PORT_SIGNAL_BIT);
}

void __inline__ lirc_on(void)
{
	out(LIRC_PORT_DATA,LIRC_PORT_DATA_BIT);
}

void __inline__ lirc_off(void)
{
	out(LIRC_PORT_DATA,0);
}

unsigned int init_lirc_timer(void)
{
	struct timeval tv,now;
	unsigned int level,newlevel,timeelapsed,newtimer;
	int count=0;
	
	do_gettimeofday(&tv);
	tv.tv_sec++;                     /* wait max. 1 sec. */
	level=lirc_get_timer();
	do
	{
		newlevel=lirc_get_timer();
		if(level==0 && newlevel!=0) count++;
		level=newlevel;
		do_gettimeofday(&now);
	}
	while(count<1000 && (now.tv_sec<tv.tv_sec 
			     || (now.tv_sec==tv.tv_sec 
				 && now.tv_usec<tv.tv_sec)));

	timeelapsed=((now.tv_sec+1-tv.tv_sec)*1000000
		     +(now.tv_usec-tv.tv_usec));
	if(count>=1000 && timeelapsed>0)
	{
		if(default_timer==0)                    /* autodetect timer */
		{
			newtimer=(1000000*count)/timeelapsed;
			printk(KERN_INFO "%s: %u Hz timer detected\n",
			       LIRC_DRIVER_NAME,newtimer);
			return(newtimer);
		}
		else
		{
			newtimer=(1000000*count)/timeelapsed;
			if(abs(newtimer-default_timer)>
			   default_timer/10) /* bad timer */
			{
				printk(KERN_NOTICE "%s: bad timer: %u Hz\n",
				       LIRC_DRIVER_NAME,newtimer);
				printk(KERN_NOTICE "%s: using default timer: "
				       "%u Hz\n",
				       LIRC_DRIVER_NAME,default_timer);
				return(default_timer);
			}
			else
			{
				printk(KERN_INFO "%s: %u Hz timer detected\n",
				       LIRC_DRIVER_NAME,newtimer);
				return(newtimer); /* use detected value */
			}
		}
	}
	else
	{
		printk(KERN_NOTICE "%s: no timer detected\n",LIRC_DRIVER_NAME);
		return(0);
	}
}

#ifdef KERNEL_2_2
int lirc_claim(void)
{
	if(parport_claim(ppdevice)!=0)
	{
		printk(KERN_WARNING "%s: could not claim port\n",
		       LIRC_DRIVER_NAME);
		printk(KERN_WARNING "%s: waiting for port becoming available"
		       "\n",LIRC_DRIVER_NAME);
		if(parport_claim_or_block(ppdevice)<0)
		{
			printk(KERN_NOTICE "%s: could not claim port, giving"
			       " up\n",LIRC_DRIVER_NAME);
			return(0);
		}
	}
	out(LIRC_LP_CONTROL,LP_PSELECP|LP_PINITP);
	is_claimed=1;
	return(1);
}
#endif

/***********************************************************************
 *************************   interrupt handler  ************************
 ***********************************************************************/

static inline void rbuf_write(lirc_t signal)
{
	unsigned int nwptr;

	nwptr=(wptr+1) & (RBUF_SIZE-1);
	if(nwptr==rptr) /* no new signals will be accepted */
	{
		lost_irqs++;
		printk(KERN_NOTICE "%s: buffer overrun\n",LIRC_DRIVER_NAME);
		return;
	}	
	rbuf[wptr]=signal;
	wptr=nwptr;
}

void irq_handler(int i,void *blah,struct pt_regs * regs)
{
	struct timeval tv;
	static struct timeval lasttv;
	static int init=0;
	long signal;
	lirc_t data;
	unsigned int level,newlevel;
	unsigned int timeout;

	if(!MOD_IN_USE)
		return;

#ifdef KERNEL_2_2
	if(!is_claimed)
	{
		return;
	}
#endif

	/* disable interrupt */
	/*
	  disable_irq(irq);
	  out(LIRC_PORT_IRQ,in(LIRC_PORT_IRQ)&(~LP_PINTEN));
	*/
	if(in(1)&LP_PSELECD)
	{
		return;
	}

#ifdef LIRC_TIMER
	if(init)
	{
		do_gettimeofday(&tv);
		
	        signal=tv.tv_sec-lasttv.tv_sec;
		if(signal>15)
		{
			data=PULSE_MASK;  /* really long time */
		}
		else
		{
			data=(lirc_t) (signal*1000000+
				       tv.tv_usec-lasttv.tv_usec+
				       LIRC_SFH506_DELAY);
		};

		rbuf_write(data); /* space */
	}
	else
	{
		if(timer==0) /* wake up; we'll lose this signal 
				but it will be garbage if the device 
				is turned on anyway
			      */
		{
			timer=init_lirc_timer();
			/* enable_irq(irq); */
			return;
		}
		init=1;
	}

	timeout=timer/10;           /* timeout after 1/10 sec. */
	signal=1;
	level=lirc_get_timer();
	do{
		newlevel=lirc_get_timer();
		if(level==0 && newlevel!=0) signal++;
		level=newlevel;

		/* giving up */
		if(signal>timeout || (in(1)&LP_PSELECD))
		{
			signal=0;
			printk(KERN_NOTICE "%s: timeout\n",LIRC_DRIVER_NAME);
			break;
		}
	}
	while(lirc_get_signal());
	if(signal!=0)
	{
		/* ajust value to usecs */
		signal=(long) (((unsigned long long) signal)*1000000)/timer;

		if(signal>LIRC_SFH506_DELAY)
		{
			data=signal-LIRC_SFH506_DELAY;
		}
		else
		{
			data=1;
		}
		rbuf_write(PULSE_BIT|data); /* pulse */
	}
	do_gettimeofday(&lasttv);
#else
	/* add your code here */
#endif
	
	wake_up_interruptible(&lirc_wait);

	/* enable interrupt */
	/*
	  enable_irq(irq);
	  out(LIRC_PORT_IRQ,in(LIRC_PORT_IRQ)|LP_PINTEN);
	*/
}

/***********************************************************************
 **************************   file_operations   ************************
 ***********************************************************************/

#ifdef KERNEL_2_2
static loff_t lirc_lseek(struct file *filep,loff_t offset,int orig)
{
	return(-ESPIPE);
}
#else
static int lirc_lseek(struct inode *inode,struct file *filep,off_t offset,int orig)
{
	return(-ESPIPE);
}
#endif

#ifdef KERNEL_2_2
static ssize_t lirc_read(struct file *filep,char *buf,size_t n,loff_t *ppos)
{
#else
static int lirc_read(struct inode *node,struct file *filep,char *buf,int n)
{
#endif
	int result;
	int count=0;
	struct wait_queue wait={current,NULL};
	
	if(n%sizeof(lirc_t)) return(-EINVAL);
	
	result=verify_area(VERIFY_WRITE,buf,n);
	if(result) return(result);
	
	add_wait_queue(&lirc_wait,&wait);
	current->state=TASK_INTERRUPTIBLE;
	while(count<n)
	{
		if(rptr!=wptr)
		{
#ifdef KERNEL_2_2
			copy_to_user(buf+count,(char *) &rbuf[rptr],
				     sizeof(lirc_t));
#else
			memcpy_tofs(buf+count,(char *) &rbuf[rptr],
				    sizeof(lirc_t));
#endif
			rptr=(rptr+1)&(RBUF_SIZE-1);
			count+=sizeof(lirc_t);
		}
		else
		{
			if(filep->f_flags & O_NONBLOCK)
			{
				result=-EAGAIN;
				break;
			}
#ifdef KERNEL_2_2
			if (signal_pending(current))
			{
				result=-ERESTARTSYS;
				break;
			}
#else
			if(current->signal & ~current->blocked)
			{
				result=-EINTR;
				break;
			}
#endif
			schedule();
			current->state=TASK_INTERRUPTIBLE;
		}
	}
	remove_wait_queue(&lirc_wait,&wait);
	current->state=TASK_RUNNING;
	return(count ? count:result);
}

#ifdef KERNEL_2_2
static ssize_t lirc_write(struct file *filep,const char *buf,size_t n,
			  loff_t *ppos)
#else
static int lirc_write(struct inode *node,struct file *filep,const char *buf,
		      int n)
#endif
{
	int result,count;
	unsigned int i;
	unsigned int level,newlevel;
	unsigned long flags;
	lirc_t counttimer;
	
#ifdef KERNEL_2_2
	if(!is_claimed)
	{
		return(-EBUSY);
	}
#endif
	if(n%sizeof(lirc_t)) return(-EINVAL);
	result=verify_area(VERIFY_READ,buf,n);
	if(result) return(result);
	
	count=n/sizeof(lirc_t);
	
	if(count>WBUF_SIZE || count%2==0) return(-EINVAL);
	
#ifdef KERNEL_2_2
	copy_from_user(wbuf,buf,n);
#else
	memcpy_fromfs(wbuf,buf,n);

	/*
	  if(check_region(port,LIRC_PORT_LEN)!=0) return(-EBUSY);
	*/
#endif
	
#ifdef LIRC_TIMER
	if(timer==0) /* try again if device is ready */
	{
		timer=init_lirc_timer();
		if(timer==0) return(-EIO);
	}

	/* ajust values from usecs */
	for(i=0;i<count;i++)
	{
		wbuf[i]=(lirc_t) (((double) wbuf[i])*timer/1000000);
	}
	
	save_flags(flags);cli();
	i=0;
	while(i<count)
	{
		level=lirc_get_timer();
		counttimer=0;
		lirc_on();
		do
		{
			newlevel=lirc_get_timer();
			if(level==0 && newlevel!=0) counttimer++;
			level=newlevel;
			if(in(1)&LP_PSELECD)
			{
				lirc_off();
				restore_flags(flags); /* sti(); */
				return(-EIO);
			}
		}
		while(counttimer<wbuf[i]);i++;
		
		lirc_off();
		if(i==count) break;
		counttimer=0;
		do
		{
			newlevel=lirc_get_timer();
			if(level==0 && newlevel!=0) counttimer++;
			level=newlevel;
			if(in(1)&LP_PSELECD)
			{
				restore_flags(flags); /* sti(); */
				return(-EIO);
			}
		}
		while(counttimer<wbuf[i]);i++;
	}
	restore_flags(flags); /* sti(); */
#else
	/* 
	   place code that handles write
	   without extarnal timer here
	*/
#endif
	return(n);
}

#ifdef KERNEL_2_2
static unsigned int lirc_poll(struct file *file, poll_table * wait)
{
	poll_wait(file, &lirc_wait,wait);
	if (rptr!=wptr)
		return(POLLIN|POLLRDNORM);
	return(0);
}
#else
static int lirc_select(struct inode *node,struct file *file,int sel_type,
		       select_table *wait)
{
	if(sel_type!=SEL_IN)
		return 0;
	if(rptr!=wptr)
		return(1);
	select_wait(&lirc_wait,wait);
	return(0);
}
#endif

static int lirc_ioctl(struct inode *node,struct file *filep,unsigned int cmd,
		      unsigned long arg)
{
        int result;
	unsigned long features=LIRC_CAN_SEND_PULSE|LIRC_CAN_REC_MODE2,mode;
	
	switch(cmd)
	{
	case LIRC_GET_FEATURES:
#               ifdef KERNEL_2_2
		result=put_user(features,(unsigned long *) arg);
		if(result) return(result); 
#               else
		result=verify_area(VERIFY_WRITE,(unsigned long*) arg,
				   sizeof(unsigned long));
		if(result) return(result);
		put_user(features,(unsigned long *) arg);
#               endif
		break;
	case LIRC_GET_SEND_MODE:
#               ifdef KERNEL_2_2
		result=put_user(LIRC_MODE_PULSE,(unsigned long *) arg);
		if(result) return(result); 
#               else
		result=verify_area(VERIFY_WRITE,(unsigned long *) arg,
				   sizeof(unsigned long));
		if(result) return(result);
		put_user(LIRC_MODE_PULSE,(unsigned long *) arg);
#               endif
		break;
	case LIRC_GET_REC_MODE:
#               ifdef KERNEL_2_2
		result=put_user(LIRC_MODE_MODE2,(unsigned long *) arg);
		if(result) return(result); 
#               else
		result=verify_area(VERIFY_WRITE,(unsigned long *) arg,
				   sizeof(unsigned long));
		if(result) return(result);
		put_user(LIRC_MODE_MODE2,(unsigned long *) arg);
#               endif
		break;
	case LIRC_SET_SEND_MODE:
#               ifdef KERNEL_2_2
		result=get_user(mode,(unsigned long *) arg);
		if(result) return(result);
#               else
		result=verify_area(VERIFY_READ,(unsigned long *) arg,
				   sizeof(unsigned long));
		if(result) return(result);
		mode=get_user((unsigned long *) arg);
#               endif
		if(mode!=LIRC_MODE_PULSE) return(-EINVAL);
		break;
	case LIRC_SET_REC_MODE:
#               ifdef KERNEL_2_2
		result=get_user(mode,(unsigned long *) arg);
		if(result) return(result);
#               else
		result=verify_area(VERIFY_READ,(unsigned long *) arg,
				   sizeof(unsigned long));
		if(result) return(result);
		mode=get_user((unsigned long *) arg);
#               endif
		if(mode!=LIRC_MODE_MODE2) return(-ENOSYS);
		break;
	default:
		return(-ENOIOCTLCMD);
	}
	return(0);
}

static int lirc_open(struct inode* node,struct file* filep)
{
#ifndef KERNEL_2_2
	int result;
#endif
	
	if(MOD_IN_USE)
	{
		return(-EBUSY);
	}
#ifdef KERNEL_2_2
	if(!lirc_claim())
	{
		return(-EBUSY);
	}
	pport->ops->enable_irq(pport);
#else
	result=request_irq(irq,irq_handler,SA_INTERRUPT,
			   LIRC_DRIVER_NAME,NULL);
	switch(result)
	{
	case -EBUSY:
		printk(KERN_NOTICE "%s: IRQ %u busy\n",LIRC_DRIVER_NAME,irq);
		return(-EBUSY);
	case -EINVAL:
		printk(KERN_NOTICE "%s: bad irq number or handler\n",
		       LIRC_DRIVER_NAME);
		return(-EINVAL);
	}
	/* enable interrupt */
	out(LIRC_PORT_IRQ,LP_PINITP|LP_PSELECP|LP_PINTEN);
#endif

	/* init read ptr */
	rptr=wptr=0;
	lost_irqs=0;

	MOD_INC_USE_COUNT;
	is_open=1;
	return(0);
}

#ifdef KERNEL_2_2
static int lirc_close(struct inode* node,struct file* filep)
#else
static void lirc_close(struct inode* node,struct file* filep)
#endif
{
#ifdef KERNEL_2_2
	if(is_claimed)
	{
		is_claimed=0;
		parport_release(ppdevice);
	}
#else
	free_irq(irq,NULL);
	
	/* disable interrupt */
	/*
	  FIXME
	  out(LIRC_PORT_IRQ,LP_PINITP|LP_PSELECP);
	*/
#endif
	is_open=0;
	MOD_DEC_USE_COUNT;
#ifdef KERNEL_2_2
	return(0);
#endif
}

static struct file_operations lirc_fops = 
{
#ifdef KERNEL_2_2
	llseek:  lirc_lseek,
#else
	lseek:   lirc_lseek,
#endif
	read:    lirc_read,
	write:   lirc_write,
#ifdef KERNEL_2_2
	poll:    lirc_poll,
#else
	select:  lirc_select,
#endif
	ioctl:   lirc_ioctl,
	open:    lirc_open,
	release: lirc_close
};

#ifdef MODULE

#if LINUX_VERSION_CODE >= 0x020200
MODULE_AUTHOR("Christoph Bartelmus");
MODULE_DESCRIPTION("Infrared receiver driver for parallel ports.");

MODULE_PARM(port, "i");
MODULE_PARM_DESC(port, "I/O address (0x3bc, 0x378 or 0x278)");

MODULE_PARM(irq, "i");
MODULE_PARM_DESC(irq, "Interrupt (7 or 5)");

EXPORT_NO_SYMBOLS;
#endif

#ifdef KERNEL_2_2
int pf(void *handle);
void kf(void *handle);

static struct timer_list poll_timer;
static void poll_state(unsigned long ignored);

static void poll_state(unsigned long ignored)
{
	printk(KERN_NOTICE "%s: time\n",
	       LIRC_DRIVER_NAME);
	del_timer(&poll_timer);
	if(is_claimed)
		return;
	kf(NULL);
	if(!is_claimed)
	{
		printk(KERN_NOTICE "%s: could not claim port, giving up\n",
		       LIRC_DRIVER_NAME);
		init_timer(&poll_timer);
		poll_timer.expires=jiffies+HZ;
		poll_timer.data=(unsigned long) current;
		poll_timer.function=poll_state;
		add_timer(&poll_timer);
	}
}

int pf(void *handle)
{
	pport->ops->disable_irq(pport);
	is_claimed=0;
	return(0);
}


void kf(void *handle)
{
	if(!is_open)
		return;
	if(!lirc_claim())
		return;
	pport->ops->enable_irq(pport);
	/* this is a bit annoying when you actually print...*/
	/*
	printk(KERN_INFO "%s: reclaimed port\n",LIRC_DRIVER_NAME);
	*/
}
#endif

/***********************************************************************
 ******************   init_module()/cleanup_module()  ******************
 ***********************************************************************/

int init_module(void)
{
#ifdef KERNEL_2_2
	pport=parport_enumerate();
	while(pport!=NULL)
	{
		if(pport->base==port)
		{
			break;
		}
		pport=pport->next;
	}
	if(pport==NULL)
	{
		printk(KERN_NOTICE "%s: no port at %x found\n",
		       LIRC_DRIVER_NAME,port);
		return(-ENXIO);
	}
	ppdevice=parport_register_device(pport,LIRC_DRIVER_NAME,
					 pf,kf,irq_handler,0,NULL);
	if(ppdevice==NULL)
	{
		printk(KERN_NOTICE "%s: parport_register_device() failed\n",
		       LIRC_DRIVER_NAME);
		return(-ENXIO);
	}
	if(parport_claim(ppdevice)!=0)
		goto skip_init;
	is_claimed=1;
	out(LIRC_LP_CONTROL,LP_PSELECP|LP_PINITP);
#else
	if(check_region(port,LIRC_PORT_LEN)!=0)
	{
		printk(KERN_NOTICE "%s: port already in use\n",LIRC_DRIVER_NAME);
		return(-EBUSY);
	}
	request_region(port,LIRC_PORT_LEN,LIRC_DRIVER_NAME);
#endif

#ifdef LIRC_TIMER
#       ifdef DEBUG
	out(LIRC_PORT_DATA,LIRC_PORT_DATA_BIT);
#       endif
	
	timer=init_lirc_timer();

#       if 0 	/* continue even if device is offline */
	if(timer==0) 
	{
#       ifdef KERNEL_2_2
		is_claimed=0;
		parport_release(pport);
		parport_unregister_device(ppdevice);
#       else
		release_region(port,LIRC_PORT_LEN);
#       endif
		return(-EIO);
	}
	
#       endif
#       ifdef DEBUG
	out(LIRC_PORT_DATA,0);
#       endif
#endif 

#ifdef KERNEL_2_2
	is_claimed=0;
	parport_release(ppdevice);
 skip_init:
#endif
	if(register_chrdev(LIRC_MAJOR, LIRC_DRIVER_NAME, &lirc_fops)<0)
	{
		printk(KERN_NOTICE "%s: register_chrdev() failed\n",LIRC_DRIVER_NAME);
#ifdef KERNEL_2_2
		parport_unregister_device(ppdevice);
#else
		release_region(port,LIRC_PORT_LEN);
#endif
		return(-EIO);
	}
	printk(KERN_INFO "%s: installed using port 0x%04x irq %d\n",LIRC_DRIVER_NAME,port,irq);
	return(0);
}
  
void cleanup_module(void)
{
	if(MOD_IN_USE) return;
#ifdef KERNEL_2_2
	parport_unregister_device(ppdevice);
#else
	release_region(port,LIRC_PORT_LEN);
#endif
	unregister_chrdev(LIRC_MAJOR,LIRC_DRIVER_NAME);
}
#endif
