/*      $Id: lirc_serial.c,v 5.25 2001/03/08 08:58:10 columbus Exp $      */

/****************************************************************************
 ** lirc_serial.c ***********************************************************
 ****************************************************************************
 *
 * lirc_serial - Device driver that records pulse- and pause-lengths
 *               (space-lengths) between DDCD event on a serial port.
 *
 * Copyright (C) 1996,97 Ralph Metzler <rjkm@thp.uni-koeln.de>
 * Copyright (C) 1998 Trent Piepho <xyzzy@u.washington.edu>
 * Copyright (C) 1998 Ben Pfaff <blp@gnu.org>
 * Copyright (C) 1999 Christoph Bartelmus <lirc@bartelmus.de>
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
 
#include <linux/version.h>
#if LINUX_VERSION_CODE >= 0x020100
#define KERNEL_2_1
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
#define KERNEL_2_3
#endif
#endif

#include <linux/config.h>

#ifndef CONFIG_SERIAL_MODULE
#warning "******************************************"
#warning " Your serial port driver is compiled into "
#warning " the kernel. You will have to release the "
#warning " port you want to use for LIRC with:      "
#warning "    setserial /dev/ttySx uart none        "
#warning "******************************************"
#if 0
#error "--- Please compile your Linux kernel serial port    ---"
#error "--- driver as a module. Read the LIRC documentation ---"
#error "--- for further details.                            ---"
#endif
#endif

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/serial_reg.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/delay.h>
#ifdef KERNEL_2_1
#include <linux/poll.h>
#endif

#include <asm/system.h>
#include <asm/segment.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/fcntl.h>

#include "drivers/lirc.h"

#ifdef LIRC_SERIAL_IRDEO

#define LIRC_SIGNAL_PIN UART_MSR_DSR
#define LIRC_SIGNAL_PIN_CHANGE UART_MSR_DDSR
#ifndef LIRC_SERIAL_TRANSMITTER
#define LIRC_SERIAL_TRANSMITTER
#endif
#ifndef LIRC_SERIAL_SOFTCARRIER
#define LIRC_SERIAL_SOFTCARRIER
#endif

#else

#define LIRC_SIGNAL_PIN UART_MSR_DCD
#define LIRC_SIGNAL_PIN_CHANGE UART_MSR_DDCD
#endif

#define LIRC_DRIVER_NAME "lirc_serial"

#define RS_ISR_PASS_LIMIT 256

/* A long pulse code from a remote might take upto 300 bytes.  The
   daemon should read the bytes as soon as they are generated, so take
   the number of keys you think you can push before the daemon runs
   and multiply by 300.  The driver will warn you if you overrun this
   buffer.  If you have a slow computer or non-busmastering IDE disks,
   maybe you will need to increase this.  */

/* This MUST be a power of two!  It has to be larger than 1 as well. */

#define RBUF_LEN 256
#define WBUF_LEN 256

static int major = LIRC_MAJOR;
static int sense = -1;   /* -1 = auto, 0 = active high, 1 = active low */

#ifdef KERNEL_2_3
static DECLARE_WAIT_QUEUE_HEAD(lirc_wait_in);
#else
static struct wait_queue *lirc_wait_in = NULL;
#endif

#ifdef KERNEL_2_1
static spinlock_t lirc_lock = SPIN_LOCK_UNLOCKED;
#endif

static int port = LIRC_PORT;
static int irq = LIRC_IRQ;

static struct timeval lasttv = {0, 0};

static lirc_t rbuf[RBUF_LEN];
static int rbh, rbt;
#ifdef LIRC_SERIAL_TRANSMITTER
static lirc_t wbuf[WBUF_LEN];

#if defined(__i386__)
/*
  From:
  Linux I/O port programming mini-HOWTO
  Author: Riku Saikkonen <Riku.Saikkonen@hut.fi>
  v, 28 December 1997
  
  [...]
  Actually, a port I/O instruction on most ports in the 0-0x3ff range
  takes almost exactly 1 microsecond, so if you're, for example, using
  the parallel port directly, just do additional inb()s from that port
  to delay.
  [...]
*/

/* 2 is subtracted from the actual value to compensate the port
   access latency, 2 instead of 1 because that generated better
   results according to my oscilloscope */
  
#define LIRC_SERIAL_TRANSMITTER_LATENCY 2
#else
/* does anybody have information on other platforms ? */
#define LIRC_SERIAL_TRANSMITTER_LATENCY 1
#endif

/* pulse/space ratio of 50/50 */
unsigned long pulse_width = (13-LIRC_SERIAL_TRANSMITTER_LATENCY);
/* 1000000/freq-pulse_width */
unsigned long space_width = (13-LIRC_SERIAL_TRANSMITTER_LATENCY);
unsigned int freq = 38000;      /* modulation frequency */
unsigned int duty_cycle = 50;   /* duty cycle of 50% */
#endif

#ifdef LIRC_SERIAL_ANIMAX
#define LIRC_OFF (UART_MCR_RTS|UART_MCR_DTR|UART_MCR_OUT2)

#elif defined(LIRC_SERIAL_IRDEO)
#define LIRC_OFF (UART_MCR_RTS|UART_MCR_DTR|UART_MCR_OUT2)
#define LIRC_ON  UART_MCR_OUT2

#else
#define LIRC_OFF (UART_MCR_RTS|UART_MCR_OUT2)
#define LIRC_ON  (LIRC_OFF|UART_MCR_DTR)
#endif

static inline unsigned int sinp(int offset)
{
	return inb(port + offset);
}

static inline void soutp(int offset, int value)
{
	outb(value, port + offset);
}

#ifdef LIRC_SERIAL_TRANSMITTER
void on(void)
{
	soutp(UART_MCR,LIRC_ON);
}
  
void off(void)
{
	soutp(UART_MCR,LIRC_OFF);
}

void send_pulse(unsigned long length)
{
#ifdef LIRC_SERIAL_IRDEO
	long rawbits;
	int i;
	unsigned char output;
	unsigned char chunk,shifted;
	
	/* how many bits have to be sent ? */
	rawbits=length*1152/10000;
	if(duty_cycle>50) chunk=3;
	else chunk=1;
	for(i=0,output=0x7f;rawbits>0;rawbits-=3)
	{
		shifted=chunk<<(i*3);
		shifted>>=1;
		output&=(~shifted);
		i++;
		if(i==3)
		{
			soutp(UART_TX,output);
			while(!(sinp(UART_LSR) & UART_LSR_TEMT));
			output=0x7f;
			i=0;
		}
	}
	if(i!=2)
	{
		soutp(UART_TX,output);
		while(!(sinp(UART_LSR) & UART_LSR_TEMT));
	}
#else
#ifdef LIRC_SERIAL_SOFTCARRIER
	unsigned long k,delay;
	int flag;
#endif

	if(length==0) return;
#ifdef LIRC_SERIAL_SOFTCARRIER
	/* this won't give us the carrier frequency we really want
	   due to integer arithmetic, but we can accept this inaccuracy */

	for(k=flag=0;k<length;k+=delay,flag=!flag)
	{
		if(flag)
		{
			off();
			delay=space_width;
		}
		else
		{
			on();
			delay=pulse_width;
		}
		udelay(delay);
	}
#else
	on();
	udelay(length);
#endif
#endif
}

void send_space(unsigned long length)
{
	if(length==0) return;
#       ifndef LIRC_SERIAL_IRDEO
	off();
#       endif
	udelay(length);
}
#endif

static void inline rbwrite(lirc_t l)
{
	unsigned int nrbt;

	nrbt=(rbt+1) & (RBUF_LEN-1);
	if(nrbt==rbh)      /* no new signals will be accepted */
	{
#               ifdef DEBUG
		printk(KERN_WARNING  LIRC_DRIVER_NAME  ": Buffer overrun\n");
#               endif
		return;
	}
	rbuf[rbt]=l;
	rbt=nrbt;
}

static void inline frbwrite(lirc_t l)
{
	/* simple noise filter */
	static lirc_t pulse=0L,space=0L;
	static unsigned int ptr=0;
	
	if(ptr>0 && (l&PULSE_BIT))
	{
		pulse+=l&PULSE_MASK;
		if(pulse>250)
		{
			rbwrite(space);
			rbwrite(pulse|PULSE_BIT);
			ptr=0;
			pulse=0;
		}
		return;
	}
	if(!(l&PULSE_BIT))
	{
		if(ptr==0)
		{
			if(l>20000)
			{
				space=l;
				ptr++;
				return;
			}
		}
		else
		{
			if(l>20000)
			{
				space+=pulse;
				if(space>PULSE_MASK) space=PULSE_MASK;
				space+=l;
				if(space>PULSE_MASK) space=PULSE_MASK;
				pulse=0;
				return;
			}
			rbwrite(space);
			rbwrite(pulse|PULSE_BIT);
			ptr=0;
			pulse=0;
		}
	}
	rbwrite(l);
}

void irq_handler(int i, void *blah, struct pt_regs *regs)
{
	struct timeval tv;
	int status,counter,dcd;
	long deltv;
	lirc_t data;
	
	counter=0;
	do{
		counter++;
		status=sinp(UART_MSR);
		if(counter>RS_ISR_PASS_LIMIT)
		{
			printk(KERN_WARNING LIRC_DRIVER_NAME ": AIEEEE: "
			       "We're caught!\n");
			break;
		}
		if((status&LIRC_SIGNAL_PIN_CHANGE) && sense!=-1)
		{
			/* get current time */
			do_gettimeofday(&tv);
			
			/* New mode, written by Trent Piepho 
			   <xyzzy@u.washington.edu>. */
			
			/* The old format was not very portable.
			   We now use the type lirc_t to pass pulses
			   and spaces to user space.
			   
			   If PULSE_BIT is set a pulse has been
			   received, otherwise a space has been
			   received.  The driver needs to know if your
			   receiver is active high or active low, or
			   the space/pulse sense could be
			   inverted. The bits denoted by PULSE_MASK are
			   the length in microseconds. Lengths greater
			   than or equal to 16 seconds are clamped to
			   PULSE_MASK.  All other bits are unused.
			   This is a much simpler interface for user
			   programs, as well as eliminating "out of
			   phase" errors with space/pulse
			   autodetection. */

			/* calculate time since last interrupt in
			   microseconds */
			dcd=(status & LIRC_SIGNAL_PIN) ? 1:0;
			
			deltv=tv.tv_sec-lasttv.tv_sec;
			if(deltv>15) 
			{
#ifdef DEBUG
				printk(KERN_WARNING LIRC_DRIVER_NAME
				       ": AIEEEE: %d %d %lx %lx %lx %lx\n",
				       dcd,sense,
				       tv.tv_sec,lasttv.tv_sec,
				       tv.tv_usec,lasttv.tv_usec);
#endif
				data=PULSE_MASK; /* really long time */
				if(!(dcd^sense)) /* sanity check */
				{
				        /* detecting pulse while this
					   MUST be a space! */
				        sense=sense ? 0:1;
				}
			}
			else
			{
				data=(lirc_t) (deltv*1000000+
					       tv.tv_usec-
					       lasttv.tv_usec);
			};
			if(tv.tv_sec<lasttv.tv_sec ||
			   (tv.tv_sec==lasttv.tv_sec &&
			    tv.tv_usec<lasttv.tv_usec))
			{
				printk(KERN_WARNING LIRC_DRIVER_NAME
				       ": AIEEEE: your clock just jumped "
				       "backwards\n");
				printk(KERN_WARNING LIRC_DRIVER_NAME
				       "%d %d %lx %lx %lx %lx\n",
				       dcd,sense,
				       tv.tv_sec,lasttv.tv_sec,
				       tv.tv_usec,lasttv.tv_usec);
				data=PULSE_MASK;
			}
			frbwrite(dcd^sense ? data : (data|PULSE_BIT));
			lasttv=tv;
			wake_up_interruptible(&lirc_wait_in);
		}
	} while(!(sinp(UART_IIR) & UART_IIR_NO_INT)); /* still pending ? */
}

#ifdef KERNEL_2_3
static DECLARE_WAIT_QUEUE_HEAD(power_supply_queue);
#else
static struct wait_queue *power_supply_queue = NULL;
#endif
#ifndef KERNEL_2_1
static struct timer_list power_supply_timer;

static void power_supply_up(unsigned long ignored)
{
        wake_up(&power_supply_queue);
}
#endif

static int init_port(void)
{
	unsigned long flags;

        /* Check io region*/
	
        if((check_region(port,8))==-EBUSY)
	{
#if 0
		/* this is the correct behaviour but many people have
                   the serial driver compiled into the kernel... */
		printk(KERN_ERR  LIRC_DRIVER_NAME  
		       ": port %04x already in use\n", port);
		return(-EBUSY);
#else
		printk(KERN_ERR LIRC_DRIVER_NAME  
		       ": port %04x already in use, proceding anyway\n", port);
		printk(KERN_WARNING LIRC_DRIVER_NAME  
		       ": compile the serial port driver as module and\n");
		printk(KERN_WARNING LIRC_DRIVER_NAME  
		       ": make sure this module is loaded first\n");
		release_region(port,8);
#endif
	}
	
	/* Reserve io region. */
	request_region(port, 8, LIRC_DRIVER_NAME);
	
	save_flags(flags);cli();
	
	/* Set DLAB 0. */
	soutp(UART_LCR, sinp(UART_LCR) & (~UART_LCR_DLAB));
	
	/* First of all, disable all interrupts */
	soutp(UART_IER, sinp(UART_IER)&
	      (~(UART_IER_MSI|UART_IER_RLSI|UART_IER_THRI|UART_IER_RDI)));
	
	/* Clear registers. */
	sinp(UART_LSR);
	sinp(UART_RX);
	sinp(UART_IIR);
	sinp(UART_MSR);
	
	/* Set line for power source */
	soutp(UART_MCR, LIRC_OFF);
	
	/* Clear registers again to be sure. */
	sinp(UART_LSR);
	sinp(UART_RX);
	sinp(UART_IIR);
	sinp(UART_MSR);

#ifdef LIRC_SERIAL_IRDEO
	/* setup port to 7N1 @ 115200 Baud */
	/* 7N1+start = 9 bits at 115200 ~ 3 bits at 38kHz */

	/* Set DLAB 1. */
	soutp(UART_LCR, sinp(UART_LCR) | UART_LCR_DLAB);
	/* Set divisor to 1 => 115200 Baud */
	soutp(UART_DLM,0);
	soutp(UART_DLL,1);
	/* Set DLAB 0 +  7N1 */
	soutp(UART_LCR,UART_LCR_WLEN7);
	/* THR interrupt already disabled at this point */
#endif
	
	restore_flags(flags);
	
	/* If pin is high, then this must be an active low receiver. */
	if(sense==-1)
	{
		/* wait 1 sec for the power supply */
		
#               ifdef KERNEL_2_1
		sleep_on_timeout(&power_supply_queue,HZ);
#               else
		init_timer(&power_supply_timer);
		power_supply_timer.expires=jiffies+HZ;
		power_supply_timer.data=(unsigned long) current;
		power_supply_timer.function=power_supply_up;
		add_timer(&power_supply_timer);
		sleep_on(&power_supply_queue);
		del_timer(&power_supply_timer);
#               endif
		
		sense=(sinp(UART_MSR) & LIRC_SIGNAL_PIN) ? 1:0;
		printk(KERN_INFO  LIRC_DRIVER_NAME  ": auto-detected active "
		       "%s receiver\n",sense ? "low":"high");
	}
	else
	{
		printk(KERN_INFO  LIRC_DRIVER_NAME  ": Manually using active "
		       "%s receiver\n",sense ? "low":"high");
	};
	
	return 0;
}

static int lirc_open(struct inode *ino, struct file *filep)
{
	int result;
	unsigned long flags;
	
#       ifdef KERNEL_2_1
	spin_lock(&lirc_lock);
#       endif
	if(MOD_IN_USE)
	{
#               ifdef KERNEL_2_1
		spin_unlock(&lirc_lock);
#               endif
		return -EBUSY;
	}
	
	/* initialize timestamp */
	do_gettimeofday(&lasttv);
	
	result=request_irq(irq,irq_handler,SA_INTERRUPT,LIRC_DRIVER_NAME,NULL);
	switch(result)
	{
	case -EBUSY:
		printk(KERN_ERR LIRC_DRIVER_NAME ": IRQ %d busy\n", irq);
#               ifdef KERNEL_2_1
		spin_unlock(&lirc_lock);
#               endif
		return -EBUSY;
	case -EINVAL:
		printk(KERN_ERR LIRC_DRIVER_NAME
		       ": Bad irq number or handler\n");
#               ifdef KERNEL_2_1
		spin_unlock(&lirc_lock);
#               endif
		return -EINVAL;
	default:
#               ifdef DEBUG
		printk(KERN_INFO LIRC_DRIVER_NAME
		       ": Interrupt %d, port %04x obtained\n", irq, port);
#               endif
		break;
	};

	/* finally enable interrupts. */
	save_flags(flags);cli();
	
	/* Set DLAB 0. */
	soutp(UART_LCR, sinp(UART_LCR) & (~UART_LCR_DLAB));
	
	soutp(UART_IER, sinp(UART_IER)|UART_IER_MSI);
	
	restore_flags(flags);
	
	/* Init read buffer pointers. */
	rbh = rbt = 0;
	
	MOD_INC_USE_COUNT;
#       ifdef KERNEL_2_1
	spin_unlock(&lirc_lock);
#       endif
	return 0;
}

#ifdef KERNEL_2_1
static int lirc_close(struct inode *node, struct file *file)
#else
static void lirc_close(struct inode *node, struct file *file)
#endif
{	unsigned long flags;
	
	save_flags(flags);cli();
	
	/* Set DLAB 0. */
	soutp(UART_LCR, sinp(UART_LCR) & (~UART_LCR_DLAB));
	
	/* First of all, disable all interrupts */
	soutp(UART_IER, sinp(UART_IER)&
	      (~(UART_IER_MSI|UART_IER_RLSI|UART_IER_THRI|UART_IER_RDI)));
	restore_flags(flags);
	
	free_irq(irq, NULL);
#       ifdef DEBUG
	printk(KERN_INFO  LIRC_DRIVER_NAME  ": freed IRQ %d\n", irq);
#       endif
	MOD_DEC_USE_COUNT;
#ifdef KERNEL_2_1
	return 0;
#endif
}

#ifdef KERNEL_2_1
static unsigned int lirc_poll(struct file *file, poll_table * wait)
{
	poll_wait(file, &lirc_wait_in, wait);
	if (rbh != rbt)
		return POLLIN | POLLRDNORM;
	return 0;
}
#else
static int lirc_select(struct inode *node, struct file *file,
		       int sel_type, select_table * wait)
{
	if (sel_type != SEL_IN)
		return 0;
	if (rbh != rbt)
		return 1;
	select_wait(&lirc_wait_in, wait);
	return 0;
}
#endif

#ifdef KERNEL_2_1
static ssize_t lirc_read(struct file *file, char *buf,
			 size_t count, loff_t * ppos)
#else
static int lirc_read(struct inode *node, struct file *file, char *buf,
		     int count)
#endif
{
	int n=0,retval=0;
#ifdef KERNEL_2_3
	DECLARE_WAITQUEUE(wait,current);
#else
	struct wait_queue wait={current,NULL};
#endif
	
	if(n%sizeof(lirc_t)) return(-EINVAL);
	
	add_wait_queue(&lirc_wait_in,&wait);
	current->state=TASK_INTERRUPTIBLE;
	while (n < count)
	{
		if (rbt != rbh) {
#                       ifdef KERNEL_2_1
			copy_to_user((void *) buf+n,
				     (void *) &rbuf[rbh],sizeof(lirc_t));
#                       else
			memcpy_tofs((void *) buf+n,
				    (void *) &rbuf[rbh],sizeof(lirc_t));
#                       endif
			rbh = (rbh + 1) & (RBUF_LEN - 1);
			n+=sizeof(lirc_t);
		} else {
			if (file->f_flags & O_NONBLOCK) {
				retval = -EAGAIN;
				break;
			}
#                       ifdef KERNEL_2_1
			if (signal_pending(current)) {
				retval = -ERESTARTSYS;
				break;
			}
#                       else
			if (current->signal & ~current->blocked) {
				retval = -EINTR;
				break;
			}
#                       endif
			schedule();
			current->state=TASK_INTERRUPTIBLE;
		}
	}
	remove_wait_queue(&lirc_wait_in,&wait);
	current->state=TASK_RUNNING;
	return (n ? n : retval);
}

#ifdef KERNEL_2_1
static ssize_t lirc_write(struct file *file, const char *buf,
			 size_t n, loff_t * ppos)
#else
static int lirc_write(struct inode *node, struct file *file, const char *buf,
                     int n)
#endif
{
#ifdef LIRC_SERIAL_TRANSMITTER
	int retval,i,count;
	unsigned long flags;
	
	if(n%sizeof(lirc_t)) return(-EINVAL);
	retval=verify_area(VERIFY_READ,buf,n);
	if(retval) return(retval);
	count=n/sizeof(lirc_t);
	if(count>WBUF_LEN || count%2==0) return(-EINVAL);
#       ifdef KERNEL_2_1
	copy_from_user(wbuf,buf,n);
#       else
	memcpy_fromfs(wbuf,buf,n);
#       endif
	save_flags(flags);cli();
#       ifdef LIRC_SERIAL_IRDEO
	/* DTR, RTS down */
	on();
#       endif
	for(i=0;i<count;i++)
	{
		if(i%2) send_space(wbuf[i]);
		else send_pulse(wbuf[i]);
	}
	off();
	restore_flags(flags);
	return(n);
#else
	return(-EBADF);
#endif
}

static int lirc_ioctl(struct inode *node,struct file *filep,unsigned int cmd,
		      unsigned long arg)
{
        int result;
	unsigned long value;
	unsigned int ivalue;
	unsigned long features=
#       ifdef LIRC_SERIAL_TRANSMITTER
#       ifdef LIRC_SERIAL_SOFTCARRIER
	LIRC_CAN_SET_SEND_DUTY_CYCLE|
#       ifndef LIRC_SERIAL_IRDEO
	LIRC_CAN_SET_SEND_CARRIER|
#       endif
#       endif
	LIRC_CAN_SEND_PULSE|
#       endif
	LIRC_CAN_REC_MODE2;
	
	switch(cmd)
	{
	case LIRC_GET_FEATURES:
#               ifdef KERNEL_2_1
		result=put_user(features,(unsigned long *) arg);
		if(result) return(result); 
#               else
		result=verify_area(VERIFY_WRITE,(unsigned long*) arg,
				   sizeof(unsigned long));
		if(result) return(result);
		put_user(features,(unsigned long *) arg);
#               endif
		break;
#       ifdef LIRC_SERIAL_TRANSMITTER
	case LIRC_GET_SEND_MODE:
#               ifdef KERNEL_2_1
		result=put_user(LIRC_MODE_PULSE,(unsigned long *) arg);
		if(result) return(result); 
#               else
		result=verify_area(VERIFY_WRITE,(unsigned long *) arg,
				   sizeof(unsigned long));
		if(result) return(result);
		put_user(LIRC_MODE_PULSE,(unsigned long *) arg);
#               endif
		break;
#       endif
	case LIRC_GET_REC_MODE:
#               ifdef KERNEL_2_1
		result=put_user(LIRC_MODE_MODE2,(unsigned long *) arg);
		if(result) return(result); 
#               else
		result=verify_area(VERIFY_WRITE,(unsigned long *) arg,
				   sizeof(unsigned long));
		if(result) return(result);
		put_user(LIRC_MODE_MODE2,(unsigned long *) arg);
#               endif
		break;
#       ifdef LIRC_SERIAL_TRANSMITTER
	case LIRC_SET_SEND_MODE:
#               ifdef KERNEL_2_1
		result=get_user(value,(unsigned long *) arg);
		if(result) return(result);
#               else
		result=verify_area(VERIFY_READ,(unsigned long *) arg,
				   sizeof(unsigned long));
		if(result) return(result);
		value=get_user((unsigned long *) arg);
#               endif
		if(value!=LIRC_MODE_PULSE) return(-ENOSYS);
		break;
#       endif
	case LIRC_SET_REC_MODE:
#               ifdef KERNEL_2_1
		result=get_user(value,(unsigned long *) arg);
		if(result) return(result);
#               else
		result=verify_area(VERIFY_READ,(unsigned long *) arg,
				   sizeof(unsigned long));
		if(result) return(result);
		value=get_user((unsigned long *) arg);
#               endif
		if(value!=LIRC_MODE_MODE2) return(-ENOSYS);
		break;
#       ifdef LIRC_SERIAL_TRANSMITTER
#       ifdef LIRC_SERIAL_SOFTCARRIER
	case LIRC_SET_SEND_DUTY_CYCLE:
#               ifdef KERNEL_2_1
		result=get_user(ivalue,(unsigned int *) arg);
		if(result) return(result);
#               else
		result=verify_area(VERIFY_READ,(unsigned int *) arg,
				   sizeof(unsigned int));
		if(result) return(result);
		ivalue=get_user((unsigned int *) arg);
#               endif
		if(ivalue<=0 || ivalue>100) return(-EINVAL);
		/* (ivalue/100)*(1000000/freq) */
		duty_cycle=ivalue;
		pulse_width=(unsigned long) duty_cycle*10000/freq;
		space_width=(unsigned long) 1000000L/freq-pulse_width;
		if(pulse_width>=LIRC_SERIAL_TRANSMITTER_LATENCY)
			pulse_width-=LIRC_SERIAL_TRANSMITTER_LATENCY;
		if(space_width>=LIRC_SERIAL_TRANSMITTER_LATENCY)
			space_width-=LIRC_SERIAL_TRANSMITTER_LATENCY;
		break;
	case LIRC_SET_SEND_CARRIER:
#               ifdef KERNEL_2_1
		result=get_user(ivalue,(unsigned int *) arg);
		if(result) return(result);
#               else
		result=verify_area(VERIFY_READ,(unsigned int *) arg,
				   sizeof(unsigned int));
		if(result) return(result);
		ivalue=get_user((unsigned int *) arg);
#               endif
		if(ivalue>500000 || ivalue<20000) return(-EINVAL);
		freq=ivalue;
		pulse_width=(unsigned long) duty_cycle*10000/freq;
		space_width=(unsigned long) 1000000L/freq-pulse_width;
		if(pulse_width>=LIRC_SERIAL_TRANSMITTER_LATENCY)
			pulse_width-=LIRC_SERIAL_TRANSMITTER_LATENCY;
		if(space_width>=LIRC_SERIAL_TRANSMITTER_LATENCY)
			space_width-=LIRC_SERIAL_TRANSMITTER_LATENCY;
		break;
#       endif
#       endif
	default:
		return(-ENOIOCTLCMD);
	}
	return(0);
}

static struct file_operations lirc_fops =
{
	read:    lirc_read,
	write:   lirc_write,
#       ifdef KERNEL_2_1
	poll:    lirc_poll,
#       else
	select:  lirc_select,
#       endif
	ioctl:   lirc_ioctl,
	open:    lirc_open,
	release: lirc_close
};

#ifdef MODULE

#if LINUX_VERSION_CODE >= 0x020100
MODULE_AUTHOR("Ralph Metzler, Trent Piepho, Ben Pfaff, Christoph Bartelmus");
MODULE_DESCRIPTION("Infrared receiver driver for serial ports.");

MODULE_PARM(port, "i");
MODULE_PARM_DESC(port, "I/O address (0x3f8 or 0x2f8)");

MODULE_PARM(irq, "i");
MODULE_PARM_DESC(irq, "Interrupt (4 or 3)");

MODULE_PARM(sense, "i");
MODULE_PARM_DESC(sense, "Override autodetection of IR receiver circuit"
		 " (0 = active high, 1 = active low )");

EXPORT_NO_SYMBOLS;
#endif

int init_module(void)
{
	int result;

	if ((result = init_port()) < 0)
		return result;
	if (register_chrdev(major, LIRC_DRIVER_NAME, &lirc_fops) < 0) {
		printk(KERN_ERR  LIRC_DRIVER_NAME  
		       ": register_chrdev failed!\n");
		release_region(port, 8);
		return -EIO;
	}
	return 0;
}

void cleanup_module(void)
{
	release_region(port, 8);
	unregister_chrdev(major, LIRC_DRIVER_NAME);
#       ifdef DEBUG
	printk(KERN_INFO  LIRC_DRIVER_NAME  ": cleaned up module\n");
#       endif
}

#endif
