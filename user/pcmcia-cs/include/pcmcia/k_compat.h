/*
 * k_compat.h 1.133 2000/11/27 05:39:45
 *
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.1 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License
 * at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and
 * limitations under the License. 
 *
 * The initial developer of the original code is David A. Hinds
 * <dahinds@users.sourceforge.net>.  Portions created by David A. Hinds
 * are Copyright (C) 1999 David A. Hinds.  All Rights Reserved.
 *
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU Public License version 2 (the "GPL"), in which
 * case the provisions of the GPL are applicable instead of the
 * above.  If you wish to allow the use of your version of this file
 * only under the terms of the GPL and not to allow others to use
 * your version of this file under the MPL, indicate your decision by
 * deleting the provisions above and replace them with the notice and
 * other provisions required by the GPL.  If you do not delete the
 * provisions above, a recipient may use your version of this file
 * under either the MPL or the GPL.
 */

#ifndef _LINUX_K_COMPAT_H
#define _LINUX_K_COMPAT_H

#define __LINUX__
#define VERSION(v,p,s)		(((v)<<16)+(p<<8)+s)

/* These are deprecated: should not use any more */
#define RUN_AT(x)		(jiffies+(x))
#define CONST			const
#define ALLOC_SKB(len)		dev_alloc_skb(len+2)
#define DEVICE(req)		((req)->rq_dev)
#define GET_PACKET(dev, skb, count)\
		skb_reserve((skb), 2); \
		BLOCK_INPUT(skb_put((skb), (count)), (count)); \
		(skb)->protocol = eth_type_trans((skb), (dev))

#define BLK_DEV_HDR		"linux/blk.h"
#define NEW_MULTICAST
#ifdef CONFIG_NET_PCMCIA_RADIO
#define HAS_WIRELESS_EXTENSIONS
#endif

#define FREE_IRQ(i,d)		free_irq(i, d)
#define REQUEST_IRQ(i,h,f,n,d)	request_irq(i,h,f,n,d)
#define IRQ(a,b,c)		(a,b,c)
#define DEV_ID			dev_id
#define IRQ_MAP(irq, dev)	do { } while (0)

#if (LINUX_VERSION_CODE < VERSION(2,2,18))
#include <linux/wait.h>
#ifndef init_waitqueue_head
#if (LINUX_VERSION_CODE < VERSION(2,0,16))
#define init_waitqueue_head(p)	(*(p) = NULL)
#else
#define init_waitqueue_head(p)	init_waitqueue(p)
#endif
typedef struct wait_queue *wait_queue_head_t;
#endif
#endif

#define FS_SIZE_T		ssize_t
#define U_FS_SIZE_T		size_t

#if (LINUX_VERSION_CODE < VERSION(2,1,31))
#define FS_RELEASE_T		void
#else
#define FS_RELEASE_T		int
#endif

#if (LINUX_VERSION_CODE < VERSION(2,1,38))
#define test_and_set_bit	set_bit
#endif

#if (LINUX_VERSION_CODE > VERSION(2,1,16))
#define AUTOCONF_INCLUDED
#define EXPORT_SYMTAB
#define register_symtab(x)
#endif
#ifdef CONFIG_MODVERSIONS
#define MODVERSIONS		1
#include <linux/modversions.h>
#endif
#include <linux/module.h>

#if (LINUX_VERSION_CODE < VERSION(2,1,45))
#define F_INODE(file)		((file)->f_inode)
#else
#define F_INODE(file)		((file)->f_dentry->d_inode)
#endif

#if (LINUX_VERSION_CODE < VERSION(2,1,51))
#define INVALIDATE_INODES(r)	invalidate_inodes(r)
#else
#define INVALIDATE_INODES(r) \
	do { struct super_block *sb = get_super(r); \
	if (sb) invalidate_inodes(sb); } while (0)
#endif

#if (LINUX_VERSION_CODE < VERSION(2,1,60))
#define FOPS(i,f,b,c,p)		(i,f,b,c)
#define FPOS			(file->f_pos)
#else
#define FOPS(i,f,b,c,p)		(f,b,c,p)
#define FPOS			(*ppos)
#endif

#if (LINUX_VERSION_CODE < VERSION(2,1,68))
#define signal_pending(cur)	((cur)->signal & ~(cur)->blocked)
#endif

#if (LINUX_VERSION_CODE < VERSION(2,1,89))
#define POLL_WAIT(f, q, w)	poll_wait(q, w)
#else
#define POLL_WAIT(f, q, w)	poll_wait(f, q, w)
#endif

#if (LINUX_VERSION_CODE < VERSION(2,1,90))
#define spin_lock(l)		do { } while (0)
#define spin_unlock(l)		do { } while (0)
#define spin_lock_irqsave(l,f)	do { save_flags(f); cli(); } while (0)
#define spin_unlock_irqrestore(l,f) do { restore_flags(f); } while (0)
#define spin_lock_init(s)	do { } while (0)
#define spin_trylock(l)		(1)
typedef int spinlock_t;
#else
#if (LINUX_VERSION_CODE < VERSION(2,3,17))
#include <asm/spinlock.h>
#else
#include <linux/spinlock.h>
#endif
#if defined(CONFIG_SMP) || (LINUX_VERSION_CODE > VERSION(2,3,6)) || \
    (defined(__powerpc__) && (LINUX_VERSION_CODE > VERSION(2,2,11)))
#define USE_SPIN_LOCKS
#endif
#endif

#if (LINUX_VERSION_CODE < VERSION(2,2,12)) && \
    !defined(CONFIG_SMP) && defined(__alpha__)
#undef spin_trylock
#define spin_trylock(l)		(1)
#endif

#ifndef spin_is_locked
#define spin_is_locked(l)	(0)
#endif

#if (LINUX_VERSION_CODE < VERSION(2,1,104))
#define mdelay(x) { int i; for (i=0;i<x;i++) udelay(1000); }
#endif

#if (LINUX_VERSION_CODE < VERSION(2,1,0))
#define __set_current_state(n) \
    do { current->state = TASK_INTERRUPTIBLE; } while (0)
#elif (LINUX_VERSION_CODE < VERSION(2,2,18))
#include <linux/sched.h>
#ifndef __set_current_state
#define __set_current_state(n)	do { current->state = (n); } while (0)
#endif
#endif

#define wacquire(w)		do { } while (0)
#define wrelease(w)		do { } while (0)
#define wsleep(w)		interruptible_sleep_on(w)
#define wakeup(w)		wake_up_interruptible(w)
#define wsleeptimeout(w,t)	interruptible_sleep_on_timeout(w,t)
#if (LINUX_VERSION_CODE < VERSION(2,1,127))
#define interruptible_sleep_on_timeout(w,t) \
    ({(current->timeout=jiffies+(t));wsleep(w);current->timeout;})
#define schedule_timeout(t) \
    do { current->timeout = jiffies+(t); schedule(); } while (0)
#endif

#if (LINUX_VERSION_CODE < VERSION(2,1,126))
#define SCSI_DISK0_MAJOR	SCSI_DISK_MAJOR
#endif

typedef unsigned long k_time_t;
#define ACQUIRE_RESOURCE_LOCK	do {} while (0)
#define RELEASE_RESOURCE_LOCK	do {} while (0)

/* Only for backwards compatibility */
#include <asm/uaccess.h>

#include <linux/ioport.h>
#if defined(check_mem_region) && !defined(HAVE_MEMRESERVE)
#define HAVE_MEMRESERVE
#endif
#ifndef HAVE_MEMRESERVE
#define vacate_region		release_region
#define vacate_mem_region	release_mem_region
extern int check_mem_region(unsigned long base, unsigned long num);
extern void request_mem_region(unsigned long base, unsigned long num,
			       char *name);
extern void release_mem_region(unsigned long base, unsigned long num);
#endif

#if (LINUX_VERSION_CODE < VERSION(2,2,0))
#define in_interrupt()		(intr_count)
#endif

#if (LINUX_VERSION_CODE < VERSION(2,3,32))
#define BLK_DEFAULT_QUEUE(n)	blk_dev[n].request_fn
#define blk_init_queue(q, req)	q = (req)
#define blk_cleanup_queue(q)	q = NULL
#define request_arg_t		void
#else
#define request_arg_t		request_queue_t *q
#endif

#include <linux/sched.h>
#ifndef CAP_SYS_ADMIN
#define capable(x)		(suser())
#endif

#if (LINUX_VERSION_CODE < VERSION(2,3,38))
#define block_device_operations file_operations
#endif

#if (LINUX_VERSION_CODE < VERSION(2,3,40))
#define register_disk(dev, drive, minors, ops, size) \
    do { (dev)->part[(drive)*(minors)].nr_sects = size; \
	if (size == 0) (dev)->part[(drive)*(minors)].start_sect = -1; \
	resetup_one_dev(dev, drive); } while (0);
#endif

#if (LINUX_VERSION_CODE < VERSION(2,2,0))
#define timer_pending(a)	(((a)->prev) != NULL)
#define mod_timer(a, b)	\
    do { del_timer(a); (a)->expires = (b); add_timer(a); } while (0)
#endif

#endif /* _LINUX_K_COMPAT_H */
