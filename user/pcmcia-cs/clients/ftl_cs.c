/*======================================================================

    A Flash Translation Layer memory card driver

    This driver implements a disk-like block device driver with an
    apparent block size of 512 bytes for flash memory cards.

    ftl_cs.c 1.66 2000/06/12 21:27:25

    The contents of this file are subject to the Mozilla Public
    License Version 1.1 (the "License"); you may not use this file
    except in compliance with the License. You may obtain a copy of
    the License at http://www.mozilla.org/MPL/

    Software distributed under the License is distributed on an "AS
    IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
    implied. See the License for the specific language governing
    rights and limitations under the License.

    The initial developer of the original code is David A. Hinds
    <dahinds@users.sourceforge.net>.  Portions created by David A. Hinds
    are Copyright (C) 1999 David A. Hinds.  All Rights Reserved.

    Alternatively, the contents of this file may be used under the
    terms of the GNU Public License version 2 (the "GPL"), in which
    case the provisions of the GPL are applicable instead of the
    above.  If you wish to allow the use of your version of this file
    only under the terms of the GPL and not to allow others to use
    your version of this file under the MPL, indicate your decision
    by deleting the provisions above and replace them with the notice
    and other provisions required by the GPL.  If you do not delete
    the provisions above, a recipient may use your version of this
    file under either the MPL or the GPL.

    LEGAL NOTE: The FTL format is patented by M-Systems.  They have
    granted a license for its use with PCMCIA devices:

     "M-Systems grants a royalty-free, non-exclusive license under
      any presently existing M-Systems intellectual property rights
      necessary for the design and development of FTL-compatible
      drivers, file systems and utilities using the data formats with
      PCMCIA PC Cards as described in the PCMCIA Flash Translation
      Layer (FTL) Specification."

    Use of the FTL format for non-PCMCIA applications may be an
    infringement of these patents.  For additional information,
    contact M-Systems (http://www.m-sys.com) directly.
      
======================================================================*/

#include <pcmcia/config.h>
#include <pcmcia/k_compat.h>

/* #define PSYCHO_DEBUG */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/malloc.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/major.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/hdreg.h>
#include <asm/io.h>
#include <asm/system.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <stdarg.h>

#if (LINUX_VERSION_CODE >= VERSION(2,1,0))
#include <linux/vmalloc.h>
#endif
#if (LINUX_VERSION_CODE >= VERSION(2,3,3))
#include <linux/blkpg.h>
#endif

#include <pcmcia/version.h>
#include <pcmcia/cs_types.h>
#include <pcmcia/cs.h>
#include <pcmcia/bulkmem.h>
#include <pcmcia/cistpl.h>
#include <pcmcia/ds.h>
#include <pcmcia/ftl.h>

/*====================================================================*/

/* Parameters that can be set with 'insmod' */

/* Major device # for FTL device */
static int major_dev = 0;

static int shuffle_freq = 50;

MODULE_PARM(major_dev, "i");
MODULE_PARM(shuffle_freq, "i");

/*====================================================================*/

/* Funky stuff for setting up a block device */
#define MAJOR_NR		major_dev
#define DEVICE_NAME		"ftl"
#define DEVICE_REQUEST		do_ftl_request
#define DEVICE_ON(device)
#define DEVICE_OFF(device)

#define DEVICE_NR(minor)	((minor)>>5)
#define REGION_NR(minor)	(((minor)>>3)&3)
#define PART_NR(minor)		((minor)&7)
#define MINOR_NR(dev,reg,part)	(((dev)<<5)+((reg)<<3)+(part))

#include <linux/blk.h>

#ifdef PCMCIA_DEBUG
static int pc_debug = PCMCIA_DEBUG;
MODULE_PARM(pc_debug, "i");
#define DEBUG(n, args...) if (pc_debug>(n)) printk(KERN_DEBUG args)
static char *version =
"ftl_cs.c 1.66 2000/06/12 21:27:25 (David Hinds)";
#else
#define DEBUG(n, args...)
#endif

/*====================================================================*/

/* Maximum number of separate memory devices we'll allow */
#define MAX_DEV		4

/* Maximum number of regions per device */
#define MAX_REGION	4

/* Maximum number of partitions in an FTL region */
#define PART_BITS	3
#define MAX_PART	8

/* Maximum number of outstanding erase requests per socket */
#define MAX_ERASE	8

/* Sector size -- shouldn't need to change */
#define SECTOR_SIZE	512

static void ftl_config(dev_link_t *link);
static void ftl_release(u_long arg);
static int ftl_event(event_t event, int priority,
		     event_callback_args_t *args);

static dev_link_t *ftl_attach(void);
static void ftl_detach(dev_link_t *);

/* Each memory region corresponds to a minor device */
typedef struct partition_t {
    dev_node_t		dev;
    u_int		state;
    u_int		*VirtualBlockMap;
    u_int		*VirtualPageMap;
    u_int		FreeTotal;
    struct eun_info_t {
	u_int			Offset;
	u_int			EraseCount;
	u_int			Free;
	u_int			Deleted;
    } *EUNInfo;
    struct xfer_info_t {
	u_int			Offset;
	u_int			EraseCount;
	u_short			state;
    } *XferInfo;
    u_short		bam_index;
    u_int		*bam_cache;
    u_short		DataUnits;
    u_int		BlocksPerUnit;
    erase_unit_header_t	header;
    region_info_t	region;
    memory_handle_t	handle;
    int			open;
    int			locked;
} partition_t;

/* Partition state flags */
#define FTL_FORMATTED	0x01

/* Transfer unit states */
#define XFER_UNKNOWN	0x00
#define XFER_ERASING	0x01
#define XFER_ERASED	0x02
#define XFER_PREPARED	0x03
#define XFER_FAILED	0x04

typedef struct ftl_dev_t {
    dev_link_t		link;
    eraseq_handle_t	eraseq_handle;
    eraseq_entry_t	eraseq[MAX_ERASE];
    wait_queue_head_t	erase_pending;
    partition_t		minor[CISTPL_MAX_DEVICES];
} ftl_dev_t;

static dev_info_t dev_info = "ftl_cs";
static dev_link_t *dev_table[MAX_DEV] = { NULL, /* ... */ };

static struct hd_struct ftl_hd[MINOR_NR(MAX_DEV, 0, 0)];
static int ftl_sizes[MINOR_NR(MAX_DEV, 0, 0)];
static int ftl_blocksizes[MINOR_NR(MAX_DEV, 0, 0)];

static wait_queue_head_t ftl_wait_open;

static struct gendisk ftl_gendisk = {
    major:		0,
    major_name:		"ftl",
    minor_shift:	PART_BITS,
    max_p:		MAX_PART,
#if (LINUX_VERSION_CODE < VERSION(2,3,40))
    max_nr:		MAX_DEV*MAX_PART,
#endif
    part:		ftl_hd,
    sizes:		ftl_sizes,
    nr_real:		MAX_DEV*MAX_PART
};

/*====================================================================*/

static int ftl_ioctl(struct inode *inode, struct file *file,
		     u_int cmd, u_long arg);
static int ftl_open(struct inode *inode, struct file *file);
static FS_RELEASE_T ftl_close(struct inode *inode, struct file *file);
static int ftl_reread_partitions(int minor);

static struct block_device_operations ftl_blk_fops = {
    open:	ftl_open,
    release:	ftl_close,
    ioctl:	ftl_ioctl,
#ifdef block_device_operations
    read:	block_read,
    write:	block_write,
    fsync:	block_fsync
#endif
};

/*====================================================================*/

static void cs_error(int func, int ret)
{
    int i;
    error_info_t err = { func, ret };
    
    for (i = 0; i < MAX_DEV; i++)
	if (dev_table[i] != NULL) break;
    CardServices(ReportError, dev_table[i]->handle, &err);
}

/*======================================================================

    ftl_attach() creates an "instance" of the driver, allocating
    local data structures for one device.  The device is registered
    with Card Services.

======================================================================*/

static dev_link_t *ftl_attach(void)
{
    client_reg_t client_reg;
    dev_link_t *link;
    ftl_dev_t *dev;
    eraseq_hdr_t eraseq_hdr;
    int i, ret;
    
    DEBUG(0, "ftl_cs: ftl_attach()\n");

    for (i = 0; i < MAX_DEV; i++)
	if (dev_table[i] == NULL) break;
    if (i == MAX_DEV) {
	printk(KERN_NOTICE "ftl_cs: no devices available\n");
	return NULL;
    }
    
    /* Create new memory card device */
    dev = kmalloc(sizeof(*dev), GFP_KERNEL);
    if (!dev) return NULL;
    memset(dev, 0, sizeof(*dev));
    link = &dev->link; link->priv = dev;

    link->release.function = &ftl_release;
    link->release.data = (u_long)link;
    dev_table[i] = link;
    init_waitqueue_head(&dev->erase_pending);

    /* Register with Card Services */
    client_reg.dev_info = &dev_info;
    client_reg.Attributes = INFO_IO_CLIENT | INFO_CARD_SHARE;
    client_reg.EventMask =
	CS_EVENT_RESET_PHYSICAL | CS_EVENT_CARD_RESET |
	CS_EVENT_CARD_INSERTION | CS_EVENT_CARD_REMOVAL |
	CS_EVENT_PM_SUSPEND | CS_EVENT_PM_RESUME;
    client_reg.event_handler = &ftl_event;
    client_reg.Version = 0x0210;
    client_reg.event_callback_args.client_data = link;
    ret = CardServices(RegisterClient, &link->handle, &client_reg);
    if (ret != CS_SUCCESS) {
	cs_error(RegisterClient, ret);
	ftl_detach(link);
	return NULL;
    }

    for (i = 0; i < MAX_ERASE; i++)
	dev->eraseq[i].State = ERASE_IDLE;
    eraseq_hdr.QueueEntryCnt = MAX_ERASE;
    eraseq_hdr.QueueEntryArray = dev->eraseq;
    dev->eraseq_handle = (void *)link->handle;
    ret = CardServices(RegisterEraseQueue, &dev->eraseq_handle, &eraseq_hdr);
    if (ret != CS_SUCCESS) {
	cs_error(RegisterEraseQueue, ret);
	dev->eraseq_handle = NULL;
	ftl_detach(link);
	return NULL;
    }
    
    return link;
} /* ftl_attach */

/*======================================================================

    This deletes a driver "instance".  The device is de-registered
    with Card Services.  If it has been released, all local data
    structures are freed.  Otherwise, the structures will be freed
    when the device is released.

======================================================================*/

static void ftl_detach(dev_link_t *link)
{
    ftl_dev_t *dev = link->priv;
    int i;

    DEBUG(0, "ftl_cs: ftl_detach(0x%p)\n", link);
    
    /* Locate device structure */
    for (i = 0; i < MAX_DEV; i++)
	if (dev_table[i] == link) break;
    if (i == MAX_DEV)
	return;

    del_timer(&link->release);
    if (link->state & DEV_CONFIG) {
	ftl_release((u_long)link);
	if (link->state & DEV_STALE_CONFIG) {
	    link->state |= DEV_STALE_LINK;
	    return;
	}
    }

    if (dev->eraseq_handle)
	CardServices(DeregisterEraseQueue, dev->eraseq_handle);
    if (link->handle)
	CardServices(DeregisterClient, link->handle);
    
    /* Unlink device structure, free bits */
    dev_table[i] = NULL;
    kfree(dev);
    
} /* ftl_detach */

/*======================================================================

    ftl_config() is scheduled to run after a CARD_INSERTION event
    is received, to configure the PCMCIA socket, and to make the
    ethernet device available to the system.
    
======================================================================*/

static void ftl_config(dev_link_t *link)
{
    ftl_dev_t *dev = link->priv;
    partition_t *minor;
    region_info_t region;
    dev_node_t **tail;
    int i, ret, nr;

    DEBUG(0, "ftl_cs: ftl_config(0x%p)\n", link);

    /* Configure card */
    link->state |= DEV_CONFIG;

    for (i = 0; i < MAX_DEV; i++)
	if (dev_table[i] == link) break;
    tail = &link->dev;
    minor = dev->minor;
    nr = 0;
    region.Attributes = REGION_TYPE_CM;
    ret = CardServices(GetFirstRegion, link->handle, &region);
    while (ret == CS_SUCCESS) {
	minor->region = region;
	sprintf(minor->dev.dev_name, "ftl%dc%d", i, nr);
	minor->dev.major = major_dev;
	minor->dev.minor = MINOR_NR(i, nr, 0);
	*tail = &minor->dev; tail = &minor->dev.next;
	minor++; nr++;
	ret = CardServices(GetNextRegion, link->handle, &region);
    }
    *tail = NULL;
    
    link->state &= ~DEV_CONFIG_PENDING;
    
    if (nr == 0)
	printk(KERN_NOTICE "ftl_cs: no regions found!\n");
    else {
	printk(KERN_INFO "ftl_cs: ftl%d:", i);
	minor = dev->minor;
	for (i = 0; i < nr; i++) {
	    if (minor[i].region.RegionSize & 0xfffff)
		printk(" %u kb", minor[i].region.RegionSize >> 10);
	    else
		printk(" %u mb", minor[i].region.RegionSize >> 20);
	}
	printk("\n");
    }
    
} /* ftl_config */

/*======================================================================

    After a card is removed, ftl_release() will unregister the 
    device, and release the PCMCIA configuration.  If the device is
    still open, this will be postponed until it is closed.
    
======================================================================*/

static void ftl_release(u_long arg)
{
    dev_link_t *link = (dev_link_t *)arg;
    int i;
    
    DEBUG(0, "ftl_cs: ftl_release(0x%p)\n", link);

    for (i = 0; i < MAX_DEV; i++)
	if (dev_table[i] == link) break;
    if (link->open) {
	DEBUG(1, "ftl_cs: release postponed, ftl%d still open\n", i);
	link->state |= DEV_STALE_CONFIG;
	return;
    }

    link->dev = NULL;
    if (link->win)
	CardServices(ReleaseWindow, link->win);
    link->state &= ~DEV_CONFIG;
    
    if (link->state & DEV_STALE_LINK)
	ftl_detach(link);
    
} /* ftl_release */

/*======================================================================

    The card status event handler.  Mostly, this schedules other
    stuff to run after an event is received.
    
======================================================================*/

static void save_status(eraseq_entry_t *erase);

static int ftl_event(event_t event, int priority,
		     event_callback_args_t *args)
{
    dev_link_t *link = args->client_data;
    ftl_dev_t *dev = link->priv;

    DEBUG(1, "ftl_cs: ftl_event()\n");
    
    switch (event) {
    case CS_EVENT_CARD_REMOVAL:
	link->state &= ~DEV_PRESENT;
	if (link->state & DEV_CONFIG)
	    mod_timer(&link->release, jiffies + HZ/20);
	break;
    case CS_EVENT_CARD_INSERTION:
	link->state |= DEV_PRESENT | DEV_CONFIG_PENDING;
	ftl_config(link);
	break;
    case CS_EVENT_ERASE_COMPLETE:
	save_status((eraseq_entry_t *)(args->info));
	wake_up(&dev->erase_pending);
	break;
    case CS_EVENT_PM_SUSPEND:
	link->state |= DEV_SUSPEND;
	/* Fall through... */
    case CS_EVENT_RESET_PHYSICAL:
	/* get_lock(link); */
	break;
    case CS_EVENT_PM_RESUME:
	link->state &= ~DEV_SUSPEND;
	/* Fall through... */
    case CS_EVENT_CARD_RESET:
	/* free_lock(link); */
	break;
    }
    return 0;
} /* ftl_event */

/*======================================================================

    Scan_header() checks to see if a memory region contains an FTL
    partition.  build_maps() reads all the erase unit headers, builds
    the erase unit map, and then builds the virtual page map.
    
======================================================================*/

static int scan_header(partition_t *part)
{
    erase_unit_header_t header;
    mem_op_t req;
    int ret;

    part->header.FormattedSize = 0;
    /* Search first megabyte for a valid FTL header */
    req.Attributes = MEM_OP_BUFFER_KERNEL;
    req.Count = sizeof(header);
    for (req.Offset = 0;
	 req.Offset < 0x100000;
	 req.Offset += part->region.BlockSize) {
	ret = CardServices(ReadMemory, part->handle, &req, &header);
	if (ret != CS_SUCCESS) {
	    cs_error(ReadMemory, ret);
	    return -1;
	}
	if (strcmp(header.DataOrgTuple+3, "FTL100") == 0) break;
    }
    if (req.Offset == 0x100000) {
	printk(KERN_NOTICE "ftl_cs: FTL header not found.\n");
	return -1;
    }
    if ((header.NumEraseUnits > 65536) || (header.BlockSize != 9) ||
	(header.EraseUnitSize < 10) || (header.EraseUnitSize > 31) ||
	(header.NumTransferUnits >= header.NumEraseUnits)) {
	printk(KERN_NOTICE "ftl_cs: FTL header corrupt!\n");
	return -1;
    }
    part->header = header;
    return 0;
}

static int build_maps(partition_t *part)
{
    erase_unit_header_t header;
    mem_op_t req;
    u_short xvalid, xtrans, i;
    u_int blocks, j;
    int hdr_ok, ret;

    /* Set up erase unit maps */
    part->DataUnits = part->header.NumEraseUnits -
	part->header.NumTransferUnits;
    part->EUNInfo = kmalloc(part->DataUnits * sizeof(struct eun_info_t),
			    GFP_KERNEL);
    if (!part->EUNInfo) return -1;
    for (i = 0; i < part->DataUnits; i++)
	part->EUNInfo[i].Offset = 0xffffffff;
    part->XferInfo =
	kmalloc(part->header.NumTransferUnits * sizeof(struct xfer_info_t),
		GFP_KERNEL);
    if (!part->XferInfo) return -1;

    req.Attributes = MEM_OP_BUFFER_KERNEL;
    req.Count = sizeof(header);
    xvalid = xtrans = 0;
    for (i = 0; i < part->header.NumEraseUnits; i++) {
	req.Offset = ((i + part->header.FirstPhysicalEUN)
		      << part->header.EraseUnitSize);
	ret = CardServices(ReadMemory, part->handle, &req, &header);
	if (ret != CS_SUCCESS) {
	    cs_error(ReadMemory, ret);
	    return -1;
	}
	/* Is this a transfer partition? */
	hdr_ok = (strcmp(header.DataOrgTuple+3, "FTL100") == 0);
	if (hdr_ok && (header.LogicalEUN < part->DataUnits) &&
	    (part->EUNInfo[header.LogicalEUN].Offset == 0xffffffff)) {
	    part->EUNInfo[header.LogicalEUN].Offset = req.Offset;
	    part->EUNInfo[header.LogicalEUN].EraseCount =
		header.EraseCount;
	    xvalid++;
	} else {
	    if (xtrans == part->header.NumTransferUnits) {
		printk(KERN_NOTICE "ftl_cs: format error: too many "
		       "transfer units!\n");
		return -1;
	    }
	    if (hdr_ok && (header.LogicalEUN == 0xffff)) {
		part->XferInfo[xtrans].state = XFER_PREPARED;
		part->XferInfo[xtrans].EraseCount = header.EraseCount;
	    } else {
		part->XferInfo[xtrans].state = XFER_UNKNOWN;
		/* Pick anything reasonable for the erase count */
		part->XferInfo[xtrans].EraseCount =
		    part->header.EraseCount;
	    }
	    part->XferInfo[xtrans].Offset = req.Offset;
	    xtrans++;
	}
    }
    /* Check for format trouble */
    header = part->header;
    if ((xtrans != header.NumTransferUnits) ||
	(xvalid+xtrans != header.NumEraseUnits)) {
	printk(KERN_NOTICE "ftl_cs: format error: erase units "
	       "don't add up!\n");
	return -1;
    }
    
    /* Set up virtual page map */
    blocks = header.FormattedSize >> header.BlockSize;
    part->VirtualBlockMap = vmalloc(blocks * sizeof(u_int));
    memset(part->VirtualBlockMap, 0xff, blocks * sizeof(u_int));
    part->BlocksPerUnit = (1 << header.EraseUnitSize) >> header.BlockSize;
    req.Count = part->BlocksPerUnit * sizeof(u_int);

    part->bam_cache = kmalloc(part->BlocksPerUnit * sizeof(u_int),
			      GFP_KERNEL);
    if (!part->bam_cache) return -1;
    part->bam_index = 0xffff;
    part->FreeTotal = 0;
    for (i = 0; i < part->DataUnits; i++) {
	part->EUNInfo[i].Free = 0;
	part->EUNInfo[i].Deleted = 0;
	req.Offset = part->EUNInfo[i].Offset + header.BAMOffset;
	ret = CardServices(ReadMemory, part->handle, &req,
			   part->bam_cache);
	if (ret != CS_SUCCESS) {
	    cs_error(ReadMemory, ret);
	    return -1;
	}
	for (j = 0; j < part->BlocksPerUnit; j++) {
	    if (BLOCK_FREE(part->bam_cache[j])) {
		part->EUNInfo[i].Free++;
		part->FreeTotal++;
	    } else if ((BLOCK_TYPE(part->bam_cache[j]) == BLOCK_DATA) &&
		     (BLOCK_NUMBER(part->bam_cache[j]) < blocks))
		part->VirtualBlockMap[BLOCK_NUMBER(part->bam_cache[j])] =
		    (i << header.EraseUnitSize) + (j << header.BlockSize);
	    else if (BLOCK_DELETED(part->bam_cache[j]))
		part->EUNInfo[i].Deleted++;
	}
    }
    
    return 0;
    
} /* build_maps */

/*======================================================================

    Erase_xfer() schedules an asynchronous erase operation for a
    transfer unit.
    
======================================================================*/

static int erase_xfer(ftl_dev_t *dev, partition_t *part,
		      u_short xfernum)
{
    int i, ret;
    struct xfer_info_t *xfer;

    xfer = &part->XferInfo[xfernum];
    DEBUG(1, "ftl_cs: erasing xfer unit at 0x%x\n", xfer->Offset);
    xfer->state = XFER_ERASING;
    /* Is there a free erase slot? */
    for (;;) {
	for (i = 0; i < MAX_ERASE; i++)
	    if (!ERASE_IN_PROGRESS(dev->eraseq[i].State)) break;
	if (i < MAX_ERASE) break;
	DEBUG(0, "ftl_cs: erase queue is full\n");
	sleep_on(&dev->erase_pending);
    }

    /* Queue the request */
    dev->eraseq[i].State = ERASE_QUEUED;
    dev->eraseq[i].Handle = part->handle;
    dev->eraseq[i].Offset = xfer->Offset;
    dev->eraseq[i].Size = part->region.BlockSize;
    dev->eraseq[i].Optional = part;
    ret = CardServices(CheckEraseQueue, dev->eraseq_handle);
    if (ret != CS_SUCCESS) {
	cs_error(CheckEraseQueue, ret);
	return -EIO;
    }
    xfer->EraseCount++;
    return ret;
} /* erase_xfer */

/*======================================================================

    Prepare_xfer() takes a freshly erased transfer unit and gives
    it an appropriate header.
    
======================================================================*/

static void save_status(eraseq_entry_t *erase)
{
    partition_t *part;
    struct xfer_info_t *xfer;
    int i;
    
    /* Look up the transfer unit */
    part = (partition_t *)(erase->Optional);
    for (i = 0; i < part->header.NumTransferUnits; i++)
	if (part->XferInfo[i].Offset == erase->Offset) break;
    if (i == part->header.NumTransferUnits) {
	printk(KERN_NOTICE "ftl_cs: internal error: "
	       "erase lookup failed!\n");
	return;
    }
    xfer = &part->XferInfo[i];
    if (erase->State == ERASE_PASSED)
	xfer->state = XFER_ERASED;
    else {
	xfer->state = XFER_FAILED;
	printk(KERN_NOTICE "ftl_cs: erase failed: state = %d\n",
	       erase->State);
    }
}

static void prepare_xfer(partition_t *part, int i)
{
    erase_unit_header_t header;
    mem_op_t req;
    struct xfer_info_t *xfer;
    int nbam, ret;
    u_int ctl;

    xfer = &part->XferInfo[i];
    xfer->state = XFER_FAILED;
    
    DEBUG(1, "ftl_cs: preparing xfer unit at 0x%x\n", xfer->Offset);

    /* Write the transfer unit header */
    header = part->header;
    header.LogicalEUN = 0xffff;
    header.EraseCount = xfer->EraseCount;
    req.Attributes = MEM_OP_BUFFER_KERNEL;
    req.Count = sizeof(header);
    req.Offset = xfer->Offset;
    ret = CardServices(WriteMemory, part->handle, &req, &header);
    if (ret != CS_SUCCESS) {
	cs_error(WriteMemory, ret);
	return;
    }

    /* Write the BAM stub */
    nbam = (part->BlocksPerUnit * sizeof(u_int) +
	    part->header.BAMOffset + SECTOR_SIZE - 1) / SECTOR_SIZE;
    req.Offset = xfer->Offset + part->header.BAMOffset;
    req.Count = sizeof(u_int);
    ctl = BLOCK_CONTROL;
    for (i = 0; i < nbam; i++, req.Offset += sizeof(u_int)) {
	ret = CardServices(WriteMemory, part->handle, &req, &ctl);
	if (ret != CS_SUCCESS) {
	    cs_error(WriteMemory, ret);
	    return;
	}
    }
    xfer->state = XFER_PREPARED;
    
} /* prepare_xfer */

/*======================================================================

    Copy_erase_unit() takes a full erase block and a transfer unit,
    copies everything to the transfer unit, then swaps the block
    pointers.

    All data blocks are copied to the corresponding blocks in the
    target unit, so the virtual block map does not need to be
    updated.
    
======================================================================*/

static int copy_erase_unit(partition_t *part, u_short srcunit,
			   u_short xferunit)
{
    u_char buf[SECTOR_SIZE];
    struct eun_info_t *eun;
    struct xfer_info_t *xfer;
    mem_op_t req;
    u_int src, dest, free, i;
    u_short unit;
    int ret;

    eun = &part->EUNInfo[srcunit];
    xfer = &part->XferInfo[xferunit];
    DEBUG(2, "ftl_cs: copying block 0x%x to 0x%x\n",
	  eun->Offset, xfer->Offset);
	
    req.Attributes = MEM_OP_BUFFER_KERNEL;
    
    /* Read current BAM */
    if (part->bam_index != srcunit) {
	req.Offset = eun->Offset + part->header.BAMOffset;
	req.Count = part->BlocksPerUnit * sizeof(u_int);
	ret = CardServices(ReadMemory, part->handle, &req, part->bam_cache);
	/* mark the cache bad, in case we get an error later */
	part->bam_index = 0xffff;
	if (ret != CS_SUCCESS) goto read_error;
    }
    
    /* Write the LogicalEUN for the transfer unit */
    xfer->state = XFER_UNKNOWN;
    req.Count = sizeof(u_short);
    req.Offset = xfer->Offset + 20; /* Bad! */
    unit = 0x7fff;
    ret = CardServices(WriteMemory, part->handle, &req, &unit);
    if (ret != CS_SUCCESS) goto write_error;
    
    /* Copy all data blocks from source unit to transfer unit */
    src = eun->Offset; dest = xfer->Offset;
    req.Count = SECTOR_SIZE;
    free = 0;
    ret = 0;
    for (i = 0; i < part->BlocksPerUnit; i++) {
	switch (BLOCK_TYPE(part->bam_cache[i])) {
	case BLOCK_CONTROL:
	    /* This gets updated later */
	    break;
	case BLOCK_DATA:
	case BLOCK_REPLACEMENT:
	    req.Offset = src;
	    ret = CardServices(ReadMemory, part->handle, &req, buf);
	    if (ret != CS_SUCCESS) goto read_error;
	    req.Offset = dest;
	    ret = CardServices(WriteMemory, part->handle, &req, buf);
	    if (ret != CS_SUCCESS) goto write_error;
	    break;
	default:
	    /* All other blocks must be free */
	    part->bam_cache[i] = 0xffffffff;
	    free++;
	    break;
	}
	src += SECTOR_SIZE;
	dest += SECTOR_SIZE;
    }

    /* Write the BAM to the transfer unit */
    req.Offset = xfer->Offset + part->header.BAMOffset;
    req.Count = part->BlocksPerUnit * sizeof(int);
    ret = CardServices(WriteMemory, part->handle, &req, part->bam_cache);
    if (ret != CS_SUCCESS) goto write_error;
    
    /* All clear? Then update the LogicalEUN again */
    req.Offset = xfer->Offset + 20; /* Bad! */
    req.Count = sizeof(u_short);
    ret = CardServices(WriteMemory, part->handle, &req, &srcunit);
    if (ret != CS_SUCCESS) goto write_error;

    /* Update the maps and usage stats*/
    i = xfer->EraseCount;
    xfer->EraseCount = eun->EraseCount;
    eun->EraseCount = i;
    i = xfer->Offset;
    xfer->Offset = eun->Offset;
    eun->Offset = i;
    part->FreeTotal -= eun->Free;
    part->FreeTotal += free;
    eun->Free = free;
    eun->Deleted = 0;
    
    /* Now, the cache should be valid for the new block */
    part->bam_index = srcunit;

    return CS_SUCCESS;
    
read_error:
    cs_error(ReadMemory, ret);
    return ret;
    
write_error:
    cs_error(WriteMemory, ret);
    return ret;
} /* copy_erase_unit */

/*======================================================================

    reclaim_block() picks a full erase unit and a transfer unit and
    then calls copy_erase_unit() to copy one to the other.  Then, it
    schedules an erase on the expired block.

    What's a good way to decide which transfer unit and which erase
    unit to use?  Beats me.  My way is to always pick the transfer
    unit with the fewest erases, and usually pick the data unit with
    the most deleted blocks.  But with a small probability, pick the
    oldest data unit instead.  This means that we generally postpone
    the next reclaimation as long as possible, but shuffle static
    stuff around a bit for wear leveling.
    
======================================================================*/

static int reclaim_block(ftl_dev_t *dev, partition_t *part)
{
    u_short i, eun, xfer;
    u_int best;
    int queued, ret;

    DEBUG(0, "ftl_cs: reclaiming space...\n");
	
    /* Pick the least erased transfer unit */
    best = 0xffffffff; xfer = 0xffff;
    do {
	queued = 0;
	for (i = 0; i < part->header.NumTransferUnits; i++) {
	    if (part->XferInfo[i].state == XFER_UNKNOWN)
		erase_xfer(dev, part, i);
	    if (part->XferInfo[i].state == XFER_ERASING)
		queued = 1;
	    else if (part->XferInfo[i].state == XFER_ERASED)
		prepare_xfer(part, i);
	    if ((part->XferInfo[i].state == XFER_PREPARED) &&
		(part->XferInfo[i].EraseCount <= best)) {
		    best = part->XferInfo[i].EraseCount;
		    xfer = i;
		}
	}
	if (xfer == 0xffff) {
	    if (queued) {
		DEBUG(1, "ftl_cs: waiting for transfer "
		      "unit to be prepared...\n");
		sleep_on(&dev->erase_pending);
	    } else {
		static int ne = 0;
		if (++ne < 5)
		    printk(KERN_NOTICE "ftl_cs: reclaim failed: no "
			   "suitable transfer units!\n");
		return CS_GENERAL_FAILURE;
	    }
	}
    } while (xfer == 0xffff);

    eun = 0;
    if ((jiffies % shuffle_freq) == 0) {
	DEBUG(1, "ftl_cs: recycling freshest block...\n");
	best = 0xffffffff;
	for (i = 0; i < part->DataUnits; i++)
	    if (part->EUNInfo[i].EraseCount <= best) {
		best = part->EUNInfo[i].EraseCount;
		eun = i;
	    }
    } else {
	best = 0;
	for (i = 0; i < part->DataUnits; i++)
	    if (part->EUNInfo[i].Deleted >= best) {
		best = part->EUNInfo[i].Deleted;
		eun = i;
	    }
	if (best == 0) {
	    static int ne = 0;
	    if (++ne < 5)
		printk(KERN_NOTICE "ftl_cs: reclaim failed: "
		       "no free blocks!\n");
	    return CS_GENERAL_FAILURE;
	}
    }
    ret = copy_erase_unit(part, eun, xfer);
    if (ret == CS_SUCCESS)
	erase_xfer(dev, part, xfer);
    else
	printk(KERN_NOTICE "ftl_cs: copy_erase_unit failed!\n");
    return ret;
} /* reclaim_block */

/*======================================================================

    Find_free() searches for a free block.  If necessary, it updates
    the BAM cache for the erase unit containing the free block.  It
    returns the block index -- the erase unit is just the currently
    cached unit.  If there are no free blocks, it returns 0 -- this
    is never a valid data block because it contains the header.
    
======================================================================*/

#ifdef PSYCHO_DEBUG
static void dump_lists(partition_t *part)
{
    int i;
    printk(KERN_DEBUG "ftl_cs: Free total = %d\n", part->FreeTotal);
    for (i = 0; i < part->DataUnits; i++)
	printk(KERN_DEBUG "ftl_cs:   unit %d: %d phys, %d free, "
	       "%d deleted\n", i,
	       part->EUNInfo[i].Offset >> part->header.EraseUnitSize,
	       part->EUNInfo[i].Free, part->EUNInfo[i].Deleted);
}
#endif

static u_int find_free(partition_t *part)
{
    u_short stop, eun;
    u_int blk;
    mem_op_t req;
    int ret;
    
    /* Find an erase unit with some free space */
    stop = (part->bam_index == 0xffff) ? 0 : part->bam_index;
    eun = stop;
    do {
	if (part->EUNInfo[eun].Free != 0) break;
	/* Wrap around at end of table */
	if (++eun == part->DataUnits) eun = 0;
    } while (eun != stop);

    if (part->EUNInfo[eun].Free == 0)
	return 0;
    
    /* Is this unit's BAM cached? */
    if (eun != part->bam_index) {
	/* Invalidate cache */
	part->bam_index = 0xffff;
	req.Attributes = MEM_OP_BUFFER_KERNEL;
	req.Count = part->BlocksPerUnit * sizeof(u_int);
	req.Offset = part->EUNInfo[eun].Offset + part->header.BAMOffset;
	ret = CardServices(ReadMemory, part->handle, &req,
			   part->bam_cache);
	if (ret != CS_SUCCESS) {
	    cs_error(ReadMemory, ret);
	    return 0;
	}
	part->bam_index = eun;
    }

    /* Find a free block */
    for (blk = 0; blk < part->BlocksPerUnit; blk++)
	if (BLOCK_FREE(part->bam_cache[blk])) break;
    if (blk == part->BlocksPerUnit) {
#ifdef PSYCHO_DEBUG
	static int ne = 0;
	if (++ne == 1)
	    dump_lists(part);
#endif
	printk(KERN_NOTICE "ftl_cs: bad free list!\n");
	return 0;
    }
    DEBUG(2, "ftl_cs: found free block at %d in %d\n", blk, eun);
    return blk;
    
} /* find_free */

/*======================================================================

    This gets a memory handle for the region corresponding to the
    minor device number.
    
======================================================================*/

static int ftl_open(struct inode *inode, struct file *file)
{
    int minor = MINOR(inode->i_rdev);
    dev_link_t *link;
    ftl_dev_t *dev;
    partition_t *partition;
    open_mem_t open;
    int ret;

    MOD_INC_USE_COUNT;
    DEBUG(0, "ftl_cs: ftl_open(%d)\n", minor);

    link = dev_table[DEVICE_NR(minor)];
    if (!DEV_OK(link))
	goto failed;

    dev = (ftl_dev_t *)link->priv;
    partition = &dev->minor[REGION_NR(minor)];
    if (partition->region.RegionSize == 0)
	goto failed;
    while (partition->locked)
	sleep_on(&ftl_wait_open);

    if (partition->handle == NULL) {
	partition->handle = (memory_handle_t)link->handle;
	open.Attributes = partition->region.Attributes;
	open.Offset = partition->region.CardOffset;
	ret = CardServices(OpenMemory, &partition->handle, &open);
	if (ret != CS_SUCCESS) {
	    cs_error(OpenMemory, ret);
	    goto failed;
	}
	if ((scan_header(partition) == 0) &&
	    (build_maps(partition) == 0)) {
	    partition->state = FTL_FORMATTED;
	    ftl_reread_partitions(minor);
#ifdef PCMCIA_DEBUG
	    printk(KERN_INFO "ftl_cs: opening %d kb FTL partition\n",
		   partition->header.FormattedSize >> 10);
#endif
	} else {
	    CardServices(CloseMemory, partition->handle);
	    partition->handle = NULL;
	    printk(KERN_NOTICE "ftl_cs: FTL partition is invalid.\n");
	    goto failed;
	}
    }

    partition->open++;
    link->open++;
    return 0;
failed:
    MOD_DEC_USE_COUNT;
    return -ENODEV;
} /* ftl_open */

/*====================================================================*/

static FS_RELEASE_T ftl_close(struct inode *inode, struct file *file)
{
    dev_link_t *link;
    int minor = MINOR(inode->i_rdev);
    ftl_dev_t *dev;
    partition_t *part;
    int i;
    
    DEBUG(0, "ftl_cs: ftl_close(%d)\n", minor);

    /* Flush all writes */
    fsync_dev(inode->i_rdev);
    INVALIDATE_INODES(inode->i_rdev);
    invalidate_buffers(inode->i_rdev);
    
    link = dev_table[DEVICE_NR(minor)];
    dev = (ftl_dev_t *)link->priv;
    part = &dev->minor[REGION_NR(minor)];
    
    /* Wait for any pending erase operations to complete */
    for (i = 0; i < part->header.NumTransferUnits; i++) {
	if (part->XferInfo[i].state == XFER_ERASING)
	    sleep_on(&dev->erase_pending);
	if (part->XferInfo[i].state == XFER_ERASED)
	    prepare_xfer(part, i);
    }
    
    link->open--;
    part->open--;
    if (part->open == 0) {
	CardServices(CloseMemory, part->handle);
	part->handle = NULL;
	if (part->VirtualBlockMap) {
	    vfree(part->VirtualBlockMap);
	    part->VirtualBlockMap = NULL;
	}
	if (part->VirtualPageMap) {
	    kfree(part->VirtualPageMap);
	    part->VirtualPageMap = NULL;
	}
	if (part->EUNInfo) {
	    kfree(part->EUNInfo);
	    part->EUNInfo = NULL;
	}
	if (part->XferInfo) {
	    kfree(part->XferInfo);
	    part->XferInfo = NULL;
	}
	if (part->bam_cache) {
	    kfree(part->bam_cache);
	    part->bam_cache = NULL;
	}
    }
    
    MOD_DEC_USE_COUNT;
    return (FS_RELEASE_T)0;
} /* ftl_close */

/*======================================================================

    Read a series of sectors from an FTL partition.
    
======================================================================*/

static int ftl_read(partition_t *part, caddr_t buffer,
		    u_long sector, u_long nblocks)
{
    mem_op_t req;
    u_int log_addr, bsize;
    u_long i;
    int ret;
    
    DEBUG(2, "ftl_cs: ftl_read(0x%p, 0x%lx, %ld)\n",
	  part->handle, sector, nblocks);
    if (!(part->state & FTL_FORMATTED)) {
	printk(KERN_NOTICE "ftl_cs: bad partition\n");
	return -EIO;
    }
    bsize = part->region.BlockSize;
    req.Attributes = MEM_OP_BUFFER_KERNEL;
    req.Count = SECTOR_SIZE;
    for (i = 0; i < nblocks; i++) {
	if (((sector+i) * SECTOR_SIZE) >= part->header.FormattedSize) {
	    printk(KERN_NOTICE "ftl_cs: bad read offset\n");
	    return -EIO;
	}
	log_addr = part->VirtualBlockMap[sector+i];
	if (log_addr == 0xffffffff)
	    memset(buffer, 0, SECTOR_SIZE);
	else {
	    req.Offset = (part->EUNInfo[log_addr / bsize].Offset
			  + (log_addr % bsize));
	    ret = CardServices(ReadMemory, part->handle, &req, buffer);
	    if (ret != CS_SUCCESS) {
		cs_error(ReadMemory, ret);
		return -EIO;
	    }
	}
	buffer += SECTOR_SIZE;
    }
    return 0;
} /* ftl_read */

/*======================================================================

    Write a series of sectors to an FTL partition
    
======================================================================*/

static int set_bam_entry(partition_t *part, u_int log_addr,
			 u_int virt_addr)
{
    mem_op_t req;
    u_int bsize, blk;
#ifdef PSYCHO_DEBUG
    u_int old_addr;
#endif
    u_short eun;
    int ret;
    
    DEBUG(2, "ftl_cs: set_bam_entry(0x%p, 0x%x, 0x%x)\n",
	  part->handle, log_addr, virt_addr);
    bsize = part->region.BlockSize;
    eun = log_addr / bsize;
    blk = (log_addr % bsize) / SECTOR_SIZE;
    req.Attributes = MEM_OP_BUFFER_KERNEL;
    req.Count = sizeof(u_int);
    req.Offset = (part->EUNInfo[eun].Offset + blk * sizeof(u_int) +
		  part->header.BAMOffset);
    
#ifdef PSYCHO_DEBUG
    CardServices(ReadMemory, part->handle, &req, &old_addr);
    if (((virt_addr == 0xfffffffe) && !BLOCK_FREE(old_addr)) ||
	((virt_addr == 0) && (BLOCK_TYPE(old_addr) != BLOCK_DATA)) ||
	(!BLOCK_DELETED(virt_addr) && (old_addr != 0xfffffffe))) {
	static int ne = 0;
	if (++ne < 5) {
	    printk(KERN_NOTICE "ftl_cs: set_bam_entry() inconsistency!\n");
	    printk(KERN_NOTICE "ftl_cs:   log_addr = 0x%x, old = 0x%x"
		   ", new = 0x%x\n", log_addr, old_addr, virt_addr);
	}
	return CS_GENERAL_FAILURE;
    }
#endif
    if (part->bam_index == eun) {
#ifdef PSYCHO_DEBUG
	if (part->bam_cache[blk] != old_addr) {
	    static int ne = 0;
	    if (++ne < 5) {
		printk(KERN_NOTICE "ftl_cs: set_bam_entry() "
		       "inconsistency!\n");
		printk(KERN_NOTICE "ftl_cs:   log_addr = 0x%x, cache"
		       " = 0x%x, card = 0x%x\n",
		       part->bam_cache[blk], old_addr);
	    }
	    return CS_GENERAL_FAILURE;
	}
#endif
	part->bam_cache[blk] = virt_addr;
    }

    ret = CardServices(WriteMemory, part->handle, &req, &virt_addr);
    if (ret != CS_SUCCESS) {
	printk(KERN_NOTICE "ftl_cs: set_bam_entry() failed!\n");
	printk(KERN_NOTICE "ftl_cs:   log_addr = 0x%x, new = 0x%x\n",
	       log_addr, virt_addr);
	cs_error(WriteMemory, ret);
    }
    return ret;
} /* set_bam_entry */

static int ftl_write(ftl_dev_t *dev, partition_t *part, caddr_t buffer,
		     u_long sector, u_long nblocks)
{
    mem_op_t req;
    u_int bsize, log_addr, virt_addr, old_addr, blk;
    u_long i;
    int ret;

    DEBUG(2, "ftl_cs: ftl_write(0x%p, %ld, %ld)\n",
	  part->handle, sector, nblocks);
    if (!(part->state & FTL_FORMATTED)) {
	printk(KERN_NOTICE "ftl_cs: bad partition\n");
	return -EIO;
    }
    /* See if we need to reclaim space, before we start */
    while (part->FreeTotal < nblocks) {
	ret = reclaim_block(dev, part);
	if (ret != CS_SUCCESS)
	    return ret;
    }
    
    bsize = part->region.BlockSize;
    req.Attributes = MEM_OP_BUFFER_KERNEL;
    req.Count = SECTOR_SIZE;
    virt_addr = sector * SECTOR_SIZE | BLOCK_DATA;
    for (i = 0; i < nblocks; i++) {
	if (virt_addr >= part->header.FormattedSize) {
	    printk(KERN_NOTICE "ftl_cs: bad write offset\n");
	    return -EIO;
	}

	/* Grab a free block */
	blk = find_free(part);
	if (blk == 0) {
	    static int ne = 0;
	    if (++ne < 5)
		printk(KERN_NOTICE "ftl_cs: internal error: "
		       "no free blocks!\n");
	    return -ENOSPC;
	}

	/* Tag the BAM entry, and write the new block */
	log_addr = part->bam_index * bsize + blk * SECTOR_SIZE;
	part->EUNInfo[part->bam_index].Free--;
	part->FreeTotal--;
	if (set_bam_entry(part, log_addr, 0xfffffffe))
	    return -EIO;
	part->EUNInfo[part->bam_index].Deleted++;
	req.Offset = (part->EUNInfo[part->bam_index].Offset +
		      blk * SECTOR_SIZE);
	ret = CardServices(WriteMemory, part->handle, &req, buffer);
	if (ret != CS_SUCCESS) {
	    printk(KERN_NOTICE "ftl_cs: block write failed!\n");
	    printk(KERN_NOTICE "ftl_cs:   log_addr = 0x%x, virt_addr"
		   " = 0x%x, Offset = 0x%x\n", log_addr, virt_addr,
		   req.Offset);
	    cs_error(WriteMemory, ret);
	    return -EIO;
	}
	
	/* Only delete the old entry when the new entry is ready */
	old_addr = part->VirtualBlockMap[sector+i];
	if (old_addr != 0xffffffff) {
	    part->VirtualBlockMap[sector+i] = 0xffffffff;
	    part->EUNInfo[old_addr/bsize].Deleted++;
	    if (set_bam_entry(part, old_addr, 0) != CS_SUCCESS)
		return -EIO;
	}

	/* Finally, set up the new pointers */
	if (set_bam_entry(part, log_addr, virt_addr))
	    return -EIO;
	part->VirtualBlockMap[sector+i] = log_addr;
	part->EUNInfo[part->bam_index].Deleted--;
	
	buffer += SECTOR_SIZE;
	virt_addr += SECTOR_SIZE;
    }
    return 0;
} /* ftl_write */

/*======================================================================

    IOCTL calls for getting device parameters.

======================================================================*/

static int ftl_ioctl(struct inode *inode, struct file *file,
		     u_int cmd, u_long arg)
{
    struct hd_geometry *geo = (struct hd_geometry *)arg;
    int ret = 0, minor = MINOR(inode->i_rdev);
    dev_link_t *link;
    ftl_dev_t *dev;
    partition_t *part;
    u_long sect;

    link = dev_table[DEVICE_NR(minor)];
    if (!DEV_OK(link)) return -ENODEV;
    dev = (ftl_dev_t *)link->priv;
    part = &dev->minor[REGION_NR(minor)];

    switch (cmd) {
    case HDIO_GETGEO:
	ret = verify_area(VERIFY_WRITE, (long *)arg, sizeof(*geo));
	if (ret) return ret;
	/* Sort of arbitrary: round size down to 4K boundary */
	sect = part->header.FormattedSize/SECTOR_SIZE;
	put_user(1, (char *)&geo->heads);
	put_user(8, (char *)&geo->sectors);
	put_user((sect>>3), (short *)&geo->cylinders);
	put_user(ftl_hd[minor].start_sect, (u_long *)&geo->start);
	break;
    case BLKGETSIZE:
	ret = verify_area(VERIFY_WRITE, (long *)arg, sizeof(long));
	if (ret) return ret;
	put_user(ftl_hd[minor].nr_sects, (long *)arg);
	break;
    case BLKRRPART:
	ret = ftl_reread_partitions(minor);
	break;
#if (LINUX_VERSION_CODE < VERSION(2,3,3))
    case BLKFLSBUF:
	if (!capable(CAP_SYS_ADMIN)) return -EACCES;
	fsync_dev(inode->i_rdev);
	invalidate_buffers(inode->i_rdev);
	break;
    RO_IOCTLS(inode->i_rdev, arg);
#else
    case BLKROSET:
    case BLKROGET:
    case BLKFLSBUF:
	ret = blk_ioctl(inode->i_rdev, cmd, arg);
	break;
#endif
    default:
	ret = -EINVAL;
    }

    return ret;
} /* ftl_ioctl */

/*======================================================================

    Handler for block device requests

======================================================================*/

static int ftl_reread_partitions(int minor)
{
    int d = DEVICE_NR(minor), r = REGION_NR(minor);
    ftl_dev_t *dev = dev_table[d]->priv;
    partition_t *part = &(dev->minor[r]);
    int i, whole;

    DEBUG(0, "ftl_cs: ftl_reread_partition(%d)\n", minor);
    if (part->locked || (part->open > 1))
	return -EBUSY;
    part->locked = 1;
    
    whole = minor & ~(MAX_PART-1);
    for (i = 0; i < MAX_PART; i++) {
	if (ftl_hd[whole+i].nr_sects > 0) {
	    kdev_t rdev = MKDEV(major_dev, whole+i);
	    sync_dev(rdev);
	    INVALIDATE_INODES(rdev);
	    invalidate_buffers(rdev);
	}
	ftl_hd[whole+i].start_sect = 0;
	ftl_hd[whole+i].nr_sects = 0;
    }

    scan_header(part);
    register_disk(&ftl_gendisk, whole >> PART_BITS, MAX_PART,
		  &ftl_blk_fops, part->header.FormattedSize/SECTOR_SIZE);

#ifdef PCMCIA_DEBUG
    for (i = 0; i < MAX_PART; i++) {
	if (ftl_hd[whole+i].nr_sects > 0)
	    printk(KERN_INFO "  %d: start %ld size %ld\n", i,
		   ftl_hd[whole+i].start_sect,
		   ftl_hd[whole+i].nr_sects);
    }
#endif
    
    part->locked = 0;
    wake_up(&ftl_wait_open);
    return 0;
}

/*======================================================================

    Handler for block device requests

======================================================================*/

static void do_ftl_request(request_arg_t)
{
    int ret, minor;
    dev_link_t *link;
    ftl_dev_t *dev;
    partition_t *part;

    DEBUG(2, "ftl_cs: starting do_ftl_request()\n");
    
    do {
	sti();
	INIT_REQUEST;

	minor = MINOR(CURRENT->rq_dev);
	
	link = dev_table[DEVICE_NR(minor)];
	dev = (ftl_dev_t *)link->priv;
	part = &dev->minor[REGION_NR(minor)];
	ret = 0;
	
	switch (CURRENT->cmd) {
	    
	case READ:
	    ret = ftl_read(part, CURRENT->buffer,
			   CURRENT->sector+ftl_hd[minor].start_sect,
			   CURRENT->current_nr_sectors);
	    break;
	    
	case WRITE:
	    ret = ftl_write(dev, part, CURRENT->buffer,
			    CURRENT->sector+ftl_hd[minor].start_sect,
			    CURRENT->current_nr_sectors);
	    break;
	    
	default:
	    panic("ftl_cs: unknown block command!\n");
	    
	}
	end_request((ret == 0) ? 1 : 0);
    } while (1);
} /* do_ftl_request */

/*====================================================================*/

static int __init init_ftl_cs(void)
{
    servinfo_t serv;
    int i;
    
    DEBUG(0, "%s\n", version);
    
    CardServices(GetCardServicesInfo, &serv);
    if (serv.Revision != CS_RELEASE_CODE) {
	printk(KERN_NOTICE "ftl_cs: Card Services release "
	       "does not match!\n");
	return -1;
    }
    
    register_pccard_driver(&dev_info, &ftl_attach, &ftl_detach);

    major_dev = register_blkdev(major_dev, "ftl", &ftl_blk_fops);
    if (major_dev == 0) {
	printk(KERN_NOTICE "ftl_cs: unable to grab major "
	       "device number!\n");
	return -ENODEV;
    }

    for (i = 0; i < MINOR_NR(MAX_DEV, 0, 0); i++)
	ftl_blocksizes[i] = 1024;
    for (i = 0; i < MAX_DEV*MAX_PART; i++) {
	ftl_hd[i].nr_sects = 0;
	ftl_hd[i].start_sect = 0;
    }
    blksize_size[major_dev] = ftl_blocksizes;
    ftl_gendisk.major = major_dev;
    blk_init_queue(BLK_DEFAULT_QUEUE(major_dev), &do_ftl_request);
    ftl_gendisk.next = gendisk_head;
    gendisk_head = &ftl_gendisk;
    init_waitqueue_head(&ftl_wait_open);
    
    return 0;
}

static void __exit exit_ftl_cs(void)
{
    int i;
    dev_link_t *link;
    struct gendisk *gd, **gdp;

    DEBUG(0, "ftl_cs: unloading\n");
    unregister_pccard_driver(&dev_info);
    if (major_dev != 0) {
	unregister_blkdev(major_dev, "ftl");
	blk_cleanup_queue(BLK_DEFAULT_QUEUE(major_dev));
	blksize_size[major_dev] = NULL;
    }
    for (i = 0; i < MAX_DEV; i++) {
	link = dev_table[i];
	if (link) {
	    if (link->state & DEV_CONFIG)
		ftl_release((u_long)link);
	    ftl_detach(link);
	}
    }
    for (gdp = &gendisk_head; *gdp; gdp = &((*gdp)->next))
	if (*gdp == &ftl_gendisk) {
	    gd = *gdp; *gdp = gd->next;
	    break;
	}
}

module_init(init_ftl_cs);
module_exit(exit_ftl_cs);
