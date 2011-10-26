/*
 * LIRC SIR driver, (C) 2000 Milan Pikula <www@fornax.sk>
 *
 * lirc_sir - Device driver for use with SIR (serial infra red)
 * mode of IrDA on many notebooks.
 *
 * 2000/09/16 Frank Przybylski <mail@frankprzybylski.de> :
 *  added timeout and relaxed pulse detection, removed gap bug
 *
 * 2000/12/15 Christoph Bartelmus <lirc@bartelmus.de> : 
 *   added support for Tekram Irmate 210 (sending does not work yet,
 *   kind of disappointing that nobody was able to implement that
 *   before),
 *   major clean-up
 */


#include <linux/version.h>
#if LINUX_VERSION_CODE >= 0x020100
#define KERNEL_2_1
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
#define KERNEL_2_3
#endif
#else
#define KERNEL_2_0
#endif

#include <linux/module.h>

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
 
#include <linux/config.h>

#ifndef CONFIG_SERIAL_MODULE
#warning "******************************************"
#warning " Your serial port driver is compiled into "
#warning " the kernel. You will have to release the "
#warning " port you want to use for LIRC with:      "
#warning "    setserial /dev/ttySx uart none        "
#warning "******************************************"
#endif

#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/signal.h>
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

#include <linux/timer.h>

#include "drivers/lirc.h"

/* SECTION: Definitions */

#ifdef LIRC_SIR_TEKRAM
/* stolen from kernel source */
/* definitions for Tekram dongle */
#define TEKRAM_115200 0x00
#define TEKRAM_57600  0x01
#define TEKRAM_38400  0x02
#define TEKRAM_19200  0x03
#define TEKRAM_9600   0x04
#define TEKRAM_2400   0x08

#define TEKRAM_PW 0x10 /* Pulse select bit */
#endif

#define RBUF_LEN 1024
#define WBUF_LEN 1024

#define LIRC_DRIVER_NAME "lirc_sir"
#ifdef LIRC_SIR_TEKRAM
/* 10bit * 1s/115200bit in milli seconds = 87ms*/
#define TIME_CONST (10000000ul/115200ul)
#else
#define PULSE '['
/* 9bit * 1s/115200bit in milli seconds = 78.125ms*/
#define TIME_CONST (9000000ul/115200ul)
#endif
/* timeout for sequences in jiffies (=5/100s) */
/* must be longer than TIME_CONST */
#define SIR_TIMEOUT	(HZ*5/100)

static int major = LIRC_MAJOR;
static int iobase = LIRC_PORT;
static int irq = LIRC_IRQ;

static spinlock_t timer_lock = SPIN_LOCK_UNLOCKED;
static struct timer_list timerlist;
/* time of last signal change detected */
static struct timeval last_tv = {0, 0};
/* time of last UART data ready interrupt */
static struct timeval last_intr_tv = {0, 0};
static int last_value = 0;

#ifdef KERNEL_2_3
static DECLARE_WAIT_QUEUE_HEAD(lirc_read_queue);
#else
static struct wait_queue * lirc_read_queue = NULL;
#endif

static spinlock_t hardware_lock = SPIN_LOCK_UNLOCKED;
static spinlock_t dev_lock = SPIN_LOCK_UNLOCKED;

static lirc_t rx_buf[RBUF_LEN]; unsigned int rx_tail = 0, rx_head = 0;
#ifndef LIRC_SIR_TEKRAM
static lirc_t tx_buf[WBUF_LEN];
#endif

/* SECTION: Prototypes */

/* Communication with user-space */
static int lirc_open(struct inode * inode, struct file * file);
#ifdef KERNEL_2_1
static int lirc_close(struct inode * inode, struct file *file);
static unsigned int lirc_poll(struct file * file, poll_table * wait);
#else
static void lirc_close(struct inode * inode, struct file *file);
static int lirc_select(struct inode * inode, struct file * file,
		int type, select_table * wait);
#endif
static ssize_t lirc_read(struct file * file, char * buf, size_t count,
		loff_t * ppos);
static ssize_t lirc_write(struct file * file, const char * buf, size_t n, loff_t * pos);
static int lirc_ioctl(struct inode *node,struct file *filep,unsigned int cmd,
		unsigned long arg);
static void add_read_queue(int flag, unsigned long val);
#ifdef MODULE
static int init_chrdev(void);
static void drop_chrdev(void);
#endif
	/* Hardware */
static void sir_interrupt(int irq, void * dev_id, struct pt_regs * regs);
#ifndef LIRC_SIR_TEKRAM
static void send_space(unsigned long len);
static void send_pulse(unsigned long len);
#endif
static int init_hardware(void);
static void drop_hardware(void);
	/* Initialisation */
static int init_port(void);
static void drop_port(void);
int init_module(void);
void cleanup_module(void);


static inline unsigned int sinp(int offset)
{
	return inb(iobase + offset);
}

static inline void soutp(int offset, int value)
{
	outb(value, iobase + offset);
}

/* SECTION: Communication with user-space */

static int lirc_open(struct inode * inode, struct file * file)
{
	spin_lock(&dev_lock);
	if (MOD_IN_USE) {
		spin_unlock(&dev_lock);
		return -EBUSY;
	}
	MOD_INC_USE_COUNT;
	spin_unlock(&dev_lock);
	return 0;
}

#ifdef KERNEL_2_1
static int lirc_close(struct inode * inode, struct file *file)
#else
static void lirc_close(struct inode * inode, struct file *file)
#endif
{
	MOD_DEC_USE_COUNT;
#ifdef KERNEL_2_1
	return 0;
#endif
}

#ifdef KERNEL_2_1
static unsigned int lirc_poll(struct file * file, poll_table * wait)
{
	poll_wait(file, &lirc_read_queue, wait);
	if (rx_head != rx_tail)
		return POLLIN | POLLRDNORM;
	return 0;
}
#else
static int lirc_select(struct inode * inode, struct file * file,
		int type, select_table * wait)
{
	if (type != SEL_IN)
		return 0;
	if (rx_head != rx_tail)
		return 1;
	select_wait(&lirc_read_queue, wait);
	return 0;
}
#endif

static ssize_t lirc_read(struct file * file, char * buf, size_t count,
		loff_t * ppos)
{
	int i = 0;
	int retval = 0;
	unsigned long flags;
	
	while (i < count) {
		save_flags(flags); cli();
		if (rx_head != rx_tail) {
			retval = verify_area(VERIFY_WRITE,
					(void *)buf + i,
					sizeof(lirc_t));
			if (retval) {
				restore_flags(flags);
				return retval;
			}
#ifdef KERNEL_2_1
			copy_to_user((void *)buf + i,
					(void *)(rx_buf + rx_head),
					sizeof(lirc_t));
#else
			memcpy_tofs((void *)buf + i,
					(void *)(rx_buf + rx_head),
					sizeof(lirc_t));
#endif
			rx_head = (rx_head + 1) & (RBUF_LEN - 1);
			i+=sizeof(lirc_t);
			restore_flags(flags);
		} else {
			restore_flags(flags);
			if (file->f_flags & O_NONBLOCK) {
				retval = -EAGAIN;
				break;
			}
			interruptible_sleep_on(&lirc_read_queue);
			if (signal_pending(current)) {
				retval = -ERESTARTSYS;
				break;
			}
		}
	}
	if (i)
		return i;
	return retval;
}
static ssize_t lirc_write(struct file * file, const char * buf, size_t n, loff_t * pos)
{
#ifdef LIRC_SIR_TEKRAM
	return(-EBADF);
#else
	int i;
	int retval;

        if(n%sizeof(lirc_t) || (n/sizeof(lirc_t)) > WBUF_LEN)
		return(-EINVAL);
	retval = verify_area(VERIFY_READ, buf, n);
	if (retval)
		return retval;
	copy_from_user(tx_buf, buf, n);
	i = 0;
	n/=sizeof(lirc_t);
	while (1) {
		if (i >= n)
			break;
		if (tx_buf[i])
			send_pulse(tx_buf[i]);
		i++;
		if (i >= n)
			break;
		if (tx_buf[i])
			send_space(tx_buf[i]);
		i++;
	}
	return n;
#endif
}

static int lirc_ioctl(struct inode *node,struct file *filep,unsigned int cmd,
		unsigned long arg)
{
	int retval = 0;
	unsigned long value = 0;

#ifdef LIRC_SIR_TEKRAM
	if (cmd == LIRC_GET_FEATURES)
		value = LIRC_CAN_REC_MODE2;
	else if (cmd == LIRC_GET_SEND_MODE)
		value = 0;
	else if (cmd == LIRC_GET_REC_MODE)
		value = LIRC_MODE_MODE2;
#else
	if (cmd == LIRC_GET_FEATURES)
		value = LIRC_CAN_SEND_PULSE | LIRC_CAN_REC_MODE2;
	else if (cmd == LIRC_GET_SEND_MODE)
		value = LIRC_MODE_PULSE;
	else if (cmd == LIRC_GET_REC_MODE)
		value = LIRC_MODE_MODE2;
#endif

	switch (cmd) {
	case LIRC_GET_FEATURES:
	case LIRC_GET_SEND_MODE:
	case LIRC_GET_REC_MODE:
#ifdef KERNEL_2_0
		retval = verify_area(VERIFY_WRITE, (unsigned long *) arg,
			sizeof(unsigned long));
		if (retval)
			break;
#else
		retval =
#endif
		put_user(value, (unsigned long *) arg);
		break;

	case LIRC_SET_SEND_MODE:
	case LIRC_SET_REC_MODE:
#ifdef KERNEL_2_0
		retval = verify_area(VERIFY_READ, (unsigned long *) arg,
			sizeof(unsigned long));
		if (retval)
			break;
		value = get_user((unsigned long *) arg);
#else
		retval = get_user(value, (unsigned long *) arg);
#endif
		break;
	default:
		retval = -ENOIOCTLCMD;

	}
	
	if (retval)
		return retval;
	
#ifdef LIRC_SIR_TEKRAM
	if (cmd == LIRC_SET_REC_MODE) {
		if (value != LIRC_MODE_MODE2)
			retval = -ENOSYS;
	} else if (cmd == LIRC_SET_SEND_MODE) {
		retval = -ENOSYS;
	}
#else
	if (cmd == LIRC_SET_REC_MODE) {
		if (value != LIRC_MODE_MODE2)
			retval = -ENOSYS;
	} else if (cmd == LIRC_SET_SEND_MODE) {
		if (value != LIRC_MODE_PULSE)
			retval = -ENOSYS;
	}
#endif
	return retval;
}

static void add_read_queue(int flag, unsigned long val)
{
	unsigned int new_rx_tail;
	lirc_t newval;

#ifdef DEBUG_SIGNAL
	printk(KERN_DEBUG LIRC_DRIVER_NAME
		": add flag %d with val %lu\n",
		flag,val);
#endif

	newval = val & PULSE_MASK;

	/* statistically pulses are ~TIME_CONST/2 too long: we could
	   maybe make this more exactly but this is good enough */
	if(flag) /* pulse */
	{
		if(newval>TIME_CONST/2)
		{
			newval-=TIME_CONST/2;
		}
		else /* should not ever happen */
		{
			newval=1;
		}
		newval|=PULSE_BIT;
	}
	else
	{
		newval+=TIME_CONST/2;
	}
	new_rx_tail = (rx_tail + 1) & (RBUF_LEN - 1);
	if (new_rx_tail == rx_head) {
#               ifdef DEBUG
		printk(KERN_WARNING LIRC_DRIVER_NAME ": Buffer overrun.\n");
#               endif
		return;
	}
	rx_buf[rx_tail] = newval;
	rx_tail = new_rx_tail;
	wake_up_interruptible(&lirc_read_queue);
}

static struct file_operations lirc_fops =
{
	read:    lirc_read,
	write:   lirc_write,
#ifdef KERNEL_2_1
	poll:    lirc_poll,
#else
	select:  lirc_select,
#endif
	ioctl:   lirc_ioctl,
	open:    lirc_open,
	release: lirc_close,
};

#ifdef MODULE
static int init_chrdev(void)
{
	int retval;

	retval = register_chrdev(major, LIRC_DRIVER_NAME, &lirc_fops);
	if (retval < 0) {
		printk(KERN_ERR LIRC_DRIVER_NAME ": init_chrdev() failed.\n");
		return retval;
	}
	return 0;
}

static void drop_chrdev(void)
{
	unregister_chrdev(major, LIRC_DRIVER_NAME);
}
#endif

/* SECTION: Hardware */
static long delta(struct timeval * tv1, struct timeval * tv2)
{
	unsigned long deltv;
	
	deltv = tv2->tv_sec - tv1->tv_sec;
	if (deltv > 15)
		deltv = 0xFFFFFF;
	else
		deltv = deltv*1000000 +
			tv2->tv_usec -
			tv1->tv_usec;
	return deltv;
}

static void sir_timeout(unsigned long data) 
{
	/* if last received signal was a pulse, but receiving stopped
	   within the 9 bit frame, we need to finish this pulse and
	   simulate a signal change to from pulse to space. Otherwise
	   upper layers will receive two sequences next time. */
	
	unsigned long flags;
	unsigned long pulse_end;
	
	/* avoid interference with interrupt */
 	spin_lock_irqsave(&timer_lock, flags);
	if (last_value)
	{
		/* clear unread bits in UART and restart */
		outb(UART_FCR_CLEAR_RCVR, iobase + UART_FCR);
		/* determine 'virtual' pulse end: */
	 	pulse_end = delta(&last_tv, &last_intr_tv);
#ifdef DEBUG_SIGNAL
		printk(KERN_DEBUG LIRC_DRIVER_NAME
			": timeout add %d for %lu usec\n",last_value,pulse_end);
#endif
		add_read_queue(last_value,pulse_end);
		last_value = 0;
		last_tv=last_intr_tv;
	}
	spin_unlock_irqrestore(&timer_lock, flags);		
}

static void sir_interrupt(int irq, void * dev_id, struct pt_regs * regs)
{
	int iir, lsr;
	unsigned char data;
	struct timeval curr_tv;
	static unsigned long deltv;
	unsigned long deltintrtv;
	unsigned long flags;

	while ((iir = inb(iobase + UART_IIR) & UART_IIR_ID)) {
		switch (iir) { /* FIXME toto treba preriedit */
		case UART_IIR_RLSI:
			break;
		case UART_IIR_RDI:
			/* avoid interference with timer */
		 	spin_lock_irqsave(&timer_lock, flags);
			while ((lsr = inb(iobase + UART_LSR))
				& UART_LSR_DR) { /* data ready */
				del_timer(&timerlist);
				data = inb(iobase + UART_RX);
				do_gettimeofday(&curr_tv);
				deltv = delta(&last_tv, &curr_tv);
				deltintrtv = delta(&last_intr_tv, &curr_tv);
#ifdef DEBUG_SIGNAL
				printk(KERN_DEBUG LIRC_DRIVER_NAME": t %lu , d %d\n",deltintrtv,(int)data);
#endif
				/* if nothing came in last 2 cycles,
				   it was gap */
				if (deltintrtv > TIME_CONST * 2) {
					if (last_value) {
#ifdef DEBUG_SIGNAL
						printk(KERN_DEBUG LIRC_DRIVER_NAME ": GAP\n");
#endif
						/* simulate signal change */
						add_read_queue(last_value,
							       deltv-
							       deltintrtv);
						last_value = 0;
						last_tv.tv_sec = last_intr_tv.tv_sec;
						last_tv.tv_usec = last_intr_tv.tv_usec;
						deltv = deltintrtv;
					}
				}
				data = 1;
				if (data ^ last_value) {
					/* deltintrtv > 2*TIME_CONST,
                                           remember ? */
					/* the other case is timeout */
					add_read_queue(last_value,
						       deltv-TIME_CONST);
					last_value = data;
					last_tv = curr_tv;
					if(last_tv.tv_usec>=TIME_CONST)
					{
						last_tv.tv_usec-=TIME_CONST;
					}
					else
					{
						last_tv.tv_sec--;
						last_tv.tv_usec+=1000000-
							TIME_CONST;
					}
				}
				last_intr_tv = curr_tv;
				if (data)
				{
					/* start timer for end of sequence detection */
					timerlist.expires = jiffies + SIR_TIMEOUT;
					add_timer(&timerlist);
				}
			}
			spin_unlock_irqrestore(&timer_lock, flags);
			break;
		case UART_IIR_THRI:
#if 0
			if (lsr & UART_LSR_THRE) /* FIFO is empty */
				outb(data, iobase + UART_TX)
#endif
			break;
		default:
			break;
		}
	}
}

#ifndef LIRC_SIR_TEKRAM
static void send_space(unsigned long len)
{
	udelay(len);
}

static void send_pulse(unsigned long len)
{
	long bytes_out = len / TIME_CONST;
	long time_left;

	if (!bytes_out)
		bytes_out++;
	time_left = (long)len - (long)bytes_out * (long)TIME_CONST;
	while (--bytes_out) {
		outb(PULSE, iobase + UART_TX);
		/* FIXME treba seriozne cakanie z drivers/char/serial.c */
		while (!(inb(iobase + UART_LSR) & UART_LSR_TEMT));
	}
#if 0
	if (time_left > 0)
		udelay(time_left);
#endif
}
#endif

static int init_hardware(void)
{
	int flags;

	spin_lock_irqsave(&hardware_lock, flags);
	/* reset UART */
#ifdef LIRC_SIR_TEKRAM
	/* disable FIFO */ 
	soutp(UART_FCR,
	      UART_FCR_CLEAR_RCVR|
	      UART_FCR_CLEAR_XMIT|
	      UART_FCR_TRIGGER_1);
	
	/* Set DLAB 0. */
	soutp(UART_LCR, sinp(UART_LCR) & (~UART_LCR_DLAB));
	
	/* First of all, disable all interrupts */
	soutp(UART_IER, sinp(UART_IER)&
	      (~(UART_IER_MSI|UART_IER_RLSI|UART_IER_THRI|UART_IER_RDI)));
	
	/* Set DLAB 1. */
	soutp(UART_LCR, sinp(UART_LCR) | UART_LCR_DLAB);
	
	/* Set divisor to 12 => 9600 Baud */
	soutp(UART_DLM,0);
	soutp(UART_DLL,12);
	
	/* Set DLAB 0. */
	soutp(UART_LCR, sinp(UART_LCR) & (~UART_LCR_DLAB));
	
	/* power supply */
	soutp(UART_MCR, UART_MCR_RTS|UART_MCR_DTR|UART_MCR_OUT2);
	udelay(50*1000);
	
	/* -DTR low -> reset PIC */
	soutp(UART_MCR, UART_MCR_RTS|UART_MCR_OUT2);
	udelay(1*1000);
	
	soutp(UART_MCR, UART_MCR_RTS|UART_MCR_DTR|UART_MCR_OUT2);
	udelay(100);


        /* -RTS low -> send control byte */
	soutp(UART_MCR, UART_MCR_DTR|UART_MCR_OUT2);
	udelay(7);
	soutp(UART_TX, TEKRAM_115200|TEKRAM_PW);
	
	/* one byte takes ~1042 usec to transmit at 9600,8N1 */
	udelay(1500);
	
	/* back to normal operation */
	soutp(UART_MCR, UART_MCR_RTS|UART_MCR_DTR|UART_MCR_OUT2);
	udelay(50);

	udelay(1500);
	
	/* read previous control byte */
	printk(KERN_INFO LIRC_DRIVER_NAME
	       ": 0x%02x\n",sinp(UART_RX));
	
	/* Set DLAB 1. */
	soutp(UART_LCR, sinp(UART_LCR) | UART_LCR_DLAB);
	
	/* Set divisor to 1 => 115200 Baud */
	soutp(UART_DLM,0);
	soutp(UART_DLL,1);

	/* Set DLAB 0, 8 Bit */
	soutp(UART_LCR, UART_LCR_WLEN8);
	/* enable interrupts */
	soutp(UART_IER, sinp(UART_IER)|UART_IER_RDI);
#else
	outb(0, iobase + UART_MCR);
	outb(0, iobase + UART_IER);
	/* init UART */
		/* set DLAB, speed = 115200 */
	outb(UART_LCR_DLAB | UART_LCR_WLEN7, iobase + UART_LCR);
	outb(1, iobase + UART_DLL); outb(0, iobase + UART_DLM);
		/* 7N1+start = 9 bits at 115200 ~ 3 bits at 44000 */
	outb(UART_LCR_WLEN7, iobase + UART_LCR);
		/* FIFO operation */
	outb(UART_FCR_ENABLE_FIFO, iobase + UART_FCR);
		/* interrupts */
	// outb(UART_IER_RLSI|UART_IER_RDI|UART_IER_THRI, iobase + UART_IER);	
	outb(UART_IER_RDI, iobase + UART_IER);	
	/* turn on UART */
	outb(UART_MCR_DTR|UART_MCR_RTS|UART_MCR_OUT2, iobase + UART_MCR);
#endif
	spin_unlock_irqrestore(&hardware_lock, flags);
	return 0;
}

static void drop_hardware(void)
{
	int flags;

	spin_lock_irqsave(&hardware_lock, flags);
	/* turn off interrupts */
	outb(0, iobase + UART_IER);	
	spin_unlock_irqrestore(&hardware_lock, flags);
}

/* SECTION: Initialisation */

static int init_port(void)
{
	int retval;

	/* get I/O port access and IRQ line */
	retval = check_region(iobase, 8);
	if (retval < 0) {
		printk(KERN_ERR LIRC_DRIVER_NAME
			": i/o port 0x%.4x already in use.\n",
			iobase);
		return retval;
	}
	retval = request_irq(irq, sir_interrupt, SA_INTERRUPT,
			LIRC_DRIVER_NAME, NULL);
	if (retval < 0) {
		printk(KERN_ERR LIRC_DRIVER_NAME
			": IRQ %d already in use.\n",
			irq);
		return retval;
	}
	request_region(iobase, 8, LIRC_DRIVER_NAME);
	printk(KERN_INFO LIRC_DRIVER_NAME
		": I/O port 0x%.4x, IRQ %d.\n",
		iobase, irq);

	init_timer(&timerlist);
	timerlist.function = sir_timeout;
	timerlist.data = 0xabadcafe;

	return 0;
}

static void drop_port(void)
{
	free_irq(irq, NULL);
	release_region(iobase, 8);
}

int init_lirc_sir(void)
{
	int retval;

#ifdef KERNEL_2_3
	init_waitqueue_head(&lirc_read_queue);
#endif
	retval = init_port();
	if (retval < 0)
		return retval;
	init_hardware();
	printk(KERN_INFO LIRC_DRIVER_NAME
		": Installed.\n");
	return 0;
}

#ifdef MODULE

#ifdef KERNEL_2_1
#ifdef LIRC_SIR_TEKRAM
MODULE_AUTHOR("Christoph Bartelmus");
MODULE_DESCRIPTION("Infrared receiver driver for Tekram Irmate 210");
#else
MODULE_AUTHOR("Milan Pikula");
MODULE_DESCRIPTION("Infrared receiver driver for SIR type serial ports");
#endif
MODULE_PARM(iobase, "i");
MODULE_PARM_DESC(iobase, "I/O address base (0x3f8 or 0x2f8)");
MODULE_PARM(irq, "i");
MODULE_PARM_DESC(irq, "Interrupt (4 or 3)");

EXPORT_NO_SYMBOLS;
#endif

int init_module(void)
{
	int retval;

	retval = init_chrdev();
	if (retval < 0)
		return retval;
	retval = init_lirc_sir();
	if (retval) {
		drop_chrdev();
		return retval;
	}
	return 0;
}

void cleanup_module(void)
{
	drop_hardware();
	drop_chrdev();
	drop_port();
	printk(KERN_INFO LIRC_DRIVER_NAME ": Uninstalled.\n");
}
#endif


