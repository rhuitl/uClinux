/*======================================================================

    A simple MTD for accessing static RAM

    sram_mtd.c 1.49 2000/06/12 21:27:27

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
    
======================================================================*/

#include <pcmcia/config.h>
#include <pcmcia/k_compat.h>

#ifdef __LINUX__
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
#include <asm/io.h>
#include <asm/system.h>
#include <asm/segment.h>
#endif

#include <stdarg.h>

#include <pcmcia/version.h>
#include <pcmcia/cs_types.h>
#include <pcmcia/cs.h>
#include <pcmcia/bulkmem.h>
#include <pcmcia/cistpl.h>
#include <pcmcia/ds.h>
#include <pcmcia/mem_op.h>

#ifdef PCMCIA_DEBUG
static int pc_debug = PCMCIA_DEBUG;
MODULE_PARM(pc_debug, "i");
#define DEBUG(n, args...) do { if (pc_debug>(n)) printk(KERN_INFO args); } while (0)
static char *version =
"sram_mtd.c 1.49 2000/06/12 21:27:27 (David Hinds)";
#else
#define DEBUG(n, args...) do { } while (0)
#endif

/*====================================================================*/

/* Parameters that can be set with 'insmod' */

static int word_width = 1;			/* 1 = 16-bit */
static int mem_speed = 0;			/* in ns */

MODULE_PARM(word_width, "i");
MODULE_PARM(mem_speed, "i");

/*====================================================================*/

static void sram_config(dev_link_t *link);
static void sram_release(u_long arg);
static int sram_event(event_t event, int priority,
		       event_callback_args_t *args);

static dev_link_t *sram_attach(void);
static void sram_detach(dev_link_t *);

typedef struct sram_dev_t {
    dev_link_t		link;
    caddr_t		Base;
    u_int		Size;
    int			nregion;
    region_info_t	region[2*CISTPL_MAX_DEVICES];
} sram_dev_t;

static dev_info_t dev_info = "sram_mtd";

static dev_link_t *dev_list = NULL;

#ifdef __BEOS__
static cs_client_module_info *cs;
static ds_module_info *ds;
static isa_module_info *isa;
#define CardServices		cs->_CardServices
#define MTDHelperEntry		cs->_MTDHelperEntry
#define add_timer		cs->_add_timer
#define del_timer		cs->_del_timer
#define register_pccard
#define unregister_pccard_driver ds->_unregister_pccard_driver
#endif

/*====================================================================*/

static void cs_error(client_handle_t handle, int func, int ret)
{
    error_info_t err = { func, ret };
    CardServices(ReportError, handle, &err);
}

/*======================================================================

    sram_attach() creates an "instance" of the driver, allocating
    local data structures for one device.  The device is registered
    with Card Services.

======================================================================*/

static dev_link_t *sram_attach(void)
{
    client_reg_t client_reg;
    dev_link_t *link;
    sram_dev_t *dev;
    int ret;
    
    DEBUG(0, "sram_attach()\n");

    /* Create new memory card device */
    dev = kmalloc(sizeof(*dev), GFP_KERNEL);
    if (!dev) return NULL;
    memset(dev, 0, sizeof(*dev));
    link = &dev->link; link->priv = dev;
    
    link->release.function = &sram_release;
    link->release.data = (u_long)link;

    /* Register with Card Services */
    link->next = dev_list;
    dev_list = link;
    client_reg.dev_info = &dev_info;
    client_reg.Attributes = INFO_MTD_CLIENT | INFO_CARD_SHARE;
    client_reg.EventMask =
	CS_EVENT_RESET_PHYSICAL | CS_EVENT_CARD_RESET |
	CS_EVENT_CARD_INSERTION | CS_EVENT_CARD_REMOVAL |
	CS_EVENT_PM_SUSPEND | CS_EVENT_PM_RESUME;
    client_reg.event_handler = &sram_event;
    client_reg.Version = 0x0210;
    client_reg.event_callback_args.client_data = link;
    ret = CardServices(RegisterClient, &link->handle, &client_reg);
    if (ret != 0) {
	cs_error(link->handle, RegisterClient, ret);
	sram_detach(link);
	return NULL;
    }

    return link;
} /* sram_attach */

/*======================================================================

    This deletes a driver "instance".  The device is de-registered
    with Card Services.  If it has been released, all local data
    structures are freed.  Otherwise, the structures will be freed
    when the device is released.

======================================================================*/

static void sram_detach(dev_link_t *link)
{
    dev_link_t **linkp;
    int ret;

    DEBUG(0, "sram_detach(0x%p)\n", link);
    
    /* Locate device structure */
    for (linkp = &dev_list; *linkp; linkp = &(*linkp)->next)
	if (*linkp == link) break;
    if (*linkp == NULL)
	return;

    del_timer(&link->release);
    if (link->state & DEV_CONFIG)
	sram_release((u_long)link);

    if (link->handle) {
	ret = CardServices(DeregisterClient, link->handle);
	if (ret != CS_SUCCESS)
	    cs_error(link->handle, DeregisterClient, ret);
    }
    
    /* Unlink device structure, free bits */
    *linkp = link->next;
    kfree(link->priv);
    
} /* sram_detach */

/*======================================================================

    sram_config() is scheduled to run after a CARD_INSERTION event
    is received, to bind the MTD to appropriate memory regions.
    
======================================================================*/

static void printk_size(u_int sz)
{
    if (sz & 0x3ff)
	printk("%u bytes", sz);
    else if (sz & 0xfffff)
	printk("%u kb", sz >> 10);
    else
	printk("%u mb", sz >> 20);
}

static void sram_config(dev_link_t *link)
{
    client_handle_t handle = link->handle;
    sram_dev_t *dev = link->priv;
    win_req_t req;
    mtd_reg_t reg;
    region_info_t region;
    int i, attr, ret;

    DEBUG(0, "sram_config(0x%p)\n", link);

    /* Allocate a small memory window */
    if (word_width)
	req.Attributes = WIN_DATA_WIDTH_16;
    else
	req.Attributes = WIN_DATA_WIDTH_8;
    req.Base = req.Size = 0;
    req.AccessSpeed = mem_speed;
    link->win = (window_handle_t)handle;
    ret = MTDHelperEntry(MTDRequestWindow, &link->win, &req);
    if (ret != 0) {
	cs_error(handle, RequestWindow, ret);
	link->state &= ~DEV_CONFIG_PENDING;
	sram_release((u_long)link);
	return;
    }

    link->state |= DEV_CONFIG;

    /* Grab info for all the memory regions we can access */
    dev->Base = ioremap(req.Base, req.Size);
    dev->Size = req.Size;
    i = 0;
    for (attr = 0; attr < 2; attr++) {
	region.Attributes = attr ? REGION_TYPE_AM : REGION_TYPE_CM;
	ret = CardServices(GetFirstRegion, handle, &region);
	while (ret == CS_SUCCESS) {
	    reg.Attributes = region.Attributes;
	    reg.Offset = region.CardOffset;
	    reg.MediaID = (u_long)&dev->region[i];
	    ret = CardServices(RegisterMTD, handle, &reg);
	    if (ret != 0) break;		
	    printk(KERN_INFO "sram_mtd: %s at 0x%x, ",
		   attr ? "attr" : "common", region.CardOffset);
	    printk_size(region.RegionSize);
	    printk(", %d ns\n", region.AccessSpeed);
	    dev->region[i] = region; i++;
	    ret = CardServices(GetNextRegion, &region);
	}
    }
    dev->nregion = i;
    
} /* sram_config */

/*======================================================================

    After a card is removed, sram_release() will release the memory
    window allocated for this socket.
    
======================================================================*/

static void sram_release(u_long arg)
{
    dev_link_t *link = (dev_link_t *)arg;
    sram_dev_t *dev = link->priv;
    int ret;
    
    DEBUG(0, "sram_release(0x%p)\n", link);

    if (link->win) {
	iounmap(dev->Base);
	ret = MTDHelperEntry(MTDReleaseWindow, link->win);
	if (ret != CS_SUCCESS)
	    cs_error(link->handle, ReleaseWindow, ret);
    }
    link->state &= ~DEV_CONFIG;
    
    if (link->state & DEV_STALE_LINK)
	sram_detach(link);
    
} /* sram_release */

/*====================================================================*/

static int sram_read(dev_link_t *link, char *buf, mtd_request_t *req)
{
    sram_dev_t *dev = (sram_dev_t *)link->priv;
    region_info_t *region;
    mtd_mod_win_t mod;
    u_int from, length, nb;
    int ret;
    
    DEBUG(1, "sram_read(0x%p, 0x%lx, 0x%p, 0x%x, 0x%x)\n", link,
	  req->MediaID, buf, req->SrcCardOffset, req->TransferLength);

    region = (region_info_t *)(req->MediaID);
    if (region->Attributes & REGION_TYPE_AM)
	mod.Attributes = WIN_MEMORY_TYPE_AM;
    else
	mod.Attributes = WIN_MEMORY_TYPE_CM;
    mod.AccessSpeed = region->AccessSpeed;

    mod.CardOffset = req->SrcCardOffset & ~(dev->Size-1);
    from = req->SrcCardOffset & (dev->Size-1);
    for (length = req->TransferLength; length > 0; length -= nb) {
	ret = MTDHelperEntry(MTDModifyWindow, link->win, &mod);
	if (ret != CS_SUCCESS) {
	    cs_error(link->handle, MapMemPage, ret);
	    return ret;
	}
	nb = (from+length > dev->Size) ? dev->Size-from : length;
	
	if (req->Function & MTD_REQ_KERNEL)
	    copy_from_pc(buf, &dev->Base[from], nb);
	else
	    copy_pc_to_user(buf, dev->Base+from, nb);
	buf += nb;
	
	from = 0;
	mod.CardOffset += dev->Size;
    }
    return CS_SUCCESS;
} /* sram_read */

/*====================================================================*/

static int sram_write(dev_link_t *link, char *buf, mtd_request_t *req)
{
    sram_dev_t *dev = (sram_dev_t *)link->priv;
    mtd_mod_win_t mod;
    region_info_t *region;
    u_int from, length, nb;
    cs_status_t status;
    int ret;

    DEBUG(1, "sram_write(0x%p, 0x%lx, 0x%p, 0x%x, 0x%x)\n", link,
	  req->MediaID, buf, req->DestCardOffset, req->TransferLength);

    /* Check card write protect status */
    ret = CardServices(GetStatus, link->handle, &status);
    if (ret != 0) {
	cs_error(link->handle, GetStatus, ret);
	return CS_GENERAL_FAILURE;
    }
    if (status.CardState & CS_EVENT_WRITE_PROTECT)
	return CS_WRITE_PROTECTED;
    
    region = (region_info_t *)(req->MediaID);
    if (region->Attributes & REGION_TYPE_AM)
	mod.Attributes = WIN_MEMORY_TYPE_AM;
    else
	mod.Attributes = WIN_MEMORY_TYPE_CM;
    mod.AccessSpeed = region->AccessSpeed;
    
    mod.CardOffset = req->DestCardOffset & ~(dev->Size-1);
    from = req->DestCardOffset & (dev->Size-1);
    for (length = req->TransferLength ; length > 0; length -= nb) {
	ret = MTDHelperEntry(MTDModifyWindow, link->win, &mod);
	if (ret != CS_SUCCESS) {
	    cs_error(link->handle, MapMemPage, ret);
	    return ret;
	}
	nb = (from+length > dev->Size) ? dev->Size-from : length;

	if (req->Function & MTD_REQ_KERNEL)
	    copy_to_pc(dev->Base+from, buf, nb);
	else
	    copy_user_to_pc(dev->Base+from, buf, nb);
	buf += nb;
	
	from = 0;
	mod.CardOffset += dev->Size;
    }
    return CS_SUCCESS;
} /* sram_write */

/*====================================================================*/

#if 0
static int sram_erase(dev_link_t *link, char *buf, mtd_request_t *req)
{
    DEBUG(1, "sram_erase(0x%p, 0x%lx, 0x%p, 0x%x, 0x%x)\n", link,
	  req->MediaID, buf, req->DestCardOffset, req->TransferLength);

    if (req->Function & MTD_REQ_TIMEOUT) {
	DEBUG(2, "sram_erase: complete\n");
	return CS_SUCCESS;
    } else {
	DEBUG(2, "sram_erase: starting\n");
	req->Status = MTD_WAITTIMER;
	req->Timeout = 10;
	return CS_BUSY;
    }
    
} /* sram_erase */
#endif

/*====================================================================*/

static int sram_request(dev_link_t *link, void *buf, mtd_request_t *req)
{
    int ret = 0;
    if (!(link->state & DEV_PRESENT))
	return CS_NO_CARD;
    switch (req->Function & MTD_REQ_ACTION) {
    case MTD_REQ_READ:
	ret = sram_read(link, buf, req);
	break;
    case MTD_REQ_WRITE:
	ret = sram_write(link, buf, req);
	break;
    case MTD_REQ_ERASE:
#if 0
	ret = sram_erase(link, buf, req);
#endif
	ret = CS_UNSUPPORTED_FUNCTION;
	break;
    case MTD_REQ_COPY:
	ret = CS_UNSUPPORTED_FUNCTION;
	break;
    }
    if (!(link->state & DEV_PRESENT))
	return CS_GENERAL_FAILURE;
    return ret;
} /* sram_request */

/*======================================================================

    The card status event handler.  Mostly, this schedules other
    stuff to run after an event is received.  A CARD_REMOVAL event
    also sets some flags to discourage the driver from trying to
    talk to the card any more.
    
======================================================================*/

static int sram_event(event_t event, int priority,
		      event_callback_args_t *args)
{
    dev_link_t *link = args->client_data;

    DEBUG(1, "sram_event(0x%06x)\n", event);
    
    switch (event) {
	
    case CS_EVENT_CARD_REMOVAL:
	link->state &= ~DEV_PRESENT;
	if (link->state & DEV_CONFIG)
	    mod_timer(&link->release, jiffies + HZ/20);
	break;
	
    case CS_EVENT_CARD_INSERTION:
	link->state |= DEV_PRESENT | DEV_CONFIG_PENDING;
	sram_config(link);
	break;
	
    case CS_EVENT_PM_SUSPEND:
	link->state |= DEV_SUSPEND;
	/* Fall through... */
    case CS_EVENT_RESET_PHYSICAL:
	break;
	
    case CS_EVENT_PM_RESUME:
	link->state &= ~DEV_SUSPEND;
	/* Fall through... */
    case CS_EVENT_CARD_RESET:
	break;
	
    case CS_EVENT_MTD_REQUEST:
	return sram_request(link, args->buffer, args->mtdrequest);
	break;
	
    }
    return CS_SUCCESS;
} /* sram_event */

/*====================================================================*/

#ifdef __LINUX__

static int __init init_sram_mtd(void)
{
    servinfo_t serv;
    DEBUG(0, "%s\n", version);
    CardServices(GetCardServicesInfo, &serv);
    if (serv.Revision != CS_RELEASE_CODE) {
	printk(KERN_NOTICE "sram_mtd: Card Services release "
	       "does not match!\n");
	return -1;
    }
    register_pccard_driver(&dev_info, &sram_attach, &sram_detach);
    return 0;
}

static void __exit exit_sram_mtd(void)
{
    DEBUG(0, "sram_mtd: unloading\n");
    unregister_pccard_driver(&dev_info);
    while (dev_list != NULL)
	sram_detach(dev_list);
}

module_init(init_sram_mtd);
module_exit(exit_sram_mtd);

#endif /* __LINUX__ */

/*====================================================================*/

#ifdef __BEOS__

static status_t std_ops(int32 op)
{
    int ret;
    DEBUG(0, "sram_mtd: std_ops(%d)\n", op);
    switch (op) {
    case B_MODULE_INIT:
	ret = get_module(CS_CLIENT_MODULE_NAME, (struct module_info **)&cs);
	if (ret != B_OK) return ret;
	ret = get_module(DS_MODULE_NAME, (struct module_info **)&ds);
	if (ret != B_OK) return ret;
	ret = get_module(B_ISA_MODULE_NAME, (struct module_info **)&isa);
	if (ret != B_OK) return ret;
	register_pccard_driver(&dev_info, &sram_attach, &sram_detach);
	break;
    case B_MODULE_UNINIT:
	unregister_pccard_driver(&dev_info);
	while (dev_list != NULL)
	    sram_detach(dev_list);
	if (isa) put_module(B_ISA_MODULE_NAME);
	if (ds) put_module(DS_MODULE_NAME);
	if (cs) put_module(CS_CLIENT_MODULE_NAME);
	break;
    }
    return B_OK;
}

static module_info sram_mtd_mod_info = {
    MTD_MODULE_NAME("sram_mtd"), 0, &std_ops
};

_EXPORT module_info *modules[] = {
    &sram_mtd_mod_info,
    NULL
};

#endif /* __BEOS__ */
