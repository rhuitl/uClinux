/*======================================================================

    A driver for the Adaptec APA1480 CardBus SCSI Host Adapter

    apa1480_cb.c 1.25 2001/02/16 03:19:16

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

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/malloc.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/ioport.h>
#include <scsi/scsi.h>
#include <linux/major.h>
#include <linux/blk.h>
#include <linux/pci.h>

#include <../drivers/scsi/scsi.h>
#include <../drivers/scsi/hosts.h>
#include <scsi/scsi_ioctl.h>

/* the Configure script figures out where to find this */
#include AIC7XXX_H

#include <pcmcia/driver_ops.h>

#ifdef PCMCIA_DEBUG
static int pc_debug = PCMCIA_DEBUG;
MODULE_PARM(pc_debug, "i");
#define DEBUG(n, args...) if (pc_debug>(n)) printk(KERN_DEBUG args)
static char *version =
"apa1480_cb.c 1.25 2001/02/16 03:19:16 (David Hinds)";
#else
#define DEBUG(n, args...)
#endif

/*====================================================================*/

/* Parameters that can be set with 'insmod' */

static char *aic7xxx = NULL;	/* see kernel's README.aic7xxx */
MODULE_PARM(aic7xxx, "s");

/*====================================================================*/

static Scsi_Host_Template driver_template = AIC7XXX;

extern void aic7xxx_setup(char *, int *);

static dev_node_t *apa1480_attach(dev_locator_t *loc);
static void apa1480_detach(dev_node_t *node);

struct driver_operations apa1480_ops = {
    "apa1480_cb", apa1480_attach, NULL, NULL, apa1480_detach
};

/*====================================================================*/

static dev_node_t *apa1480_attach(dev_locator_t *loc)
{
    u_char bus, devfn;
    Scsi_Device *dev;
    dev_node_t *node;
    u_int io;
    int n = 0;
#if (LINUX_VERSION_CODE >= VERSION(2,1,75))
    struct Scsi_Host *host;
#endif
    
    if (loc->bus != LOC_PCI) return NULL;
    bus = loc->b.pci.bus; devfn = loc->b.pci.devfn;
    printk(KERN_INFO "apa1480_attach(device %02x:%02x.%d)\n",
	   bus, PCI_SLOT(devfn), PCI_FUNC(devfn));

#if (LINUX_VERSION_CODE >= VERSION(2,1,23))
    driver_template.module = &__this_module;
#else
    driver_template.usage_count = &GET_USE_COUNT(__this_module);
#endif

    /* A hack to work around resource allocation confusion */
    pcibios_read_config_dword(bus, devfn, PCI_BASE_ADDRESS_0, &io);
    release_region(io & PCI_BASE_ADDRESS_IO_MASK, 0x100);

    if (aic7xxx) {
	char *s = kmalloc(strlen(aic7xxx)+12, GFP_KERNEL);
	sprintf(s, "%s,no_probe:1", aic7xxx);
	printk(KERN_INFO "opts: %s\n", s);
	aic7xxx_setup(s, NULL);
	kfree(s);
    } else {
	aic7xxx_setup("no_probe:1", NULL);
    }
    scsi_register_module(MODULE_SCSI_HA, &driver_template);

    node = kmalloc(7 * sizeof(dev_node_t), GFP_KERNEL);
#if (LINUX_VERSION_CODE < VERSION(2,1,75))
    for (dev = scsi_devices; dev; dev = dev->next)
	if (dev->host->hostt == &driver_template) {
#else
    for (host = scsi_hostlist; host; host = host->next)
	if (host->hostt == &driver_template)
	    for (dev = host->host_queue; dev; dev = dev->next) {
#endif
	    u_long arg[2], id;
	    kernel_scsi_ioctl(dev, SCSI_IOCTL_GET_IDLUN, arg);
	    id = (arg[0]&0x0f) + ((arg[0]>>4)&0xf0) +
		((arg[0]>>8)&0xf00) + ((arg[0]>>12)&0xf000);
	    node[n].minor = 0;
	    switch (dev->type) {
	    case TYPE_TAPE:
		node[n].major = SCSI_TAPE_MAJOR;
		sprintf(node[n].dev_name, "st#%04lx", id);
		break;
	    case TYPE_DISK:
	    case TYPE_MOD:
		node[n].major = SCSI_DISK0_MAJOR;
		sprintf(node[n].dev_name, "sd#%04lx", id);
		break;
	    case TYPE_ROM:
	    case TYPE_WORM:
		node[n].major = SCSI_CDROM_MAJOR;
		sprintf(node[n].dev_name, "sr#%04lx", id);
		break;
	    default:
		node[n].major = SCSI_GENERIC_MAJOR;
		sprintf(node[n].dev_name, "sg#%04lx", id);
		break;
	    }
	    if (n) node[n-1].next = &node[n];
	    n++;
	}
    if (n == 0) {
	printk(KERN_INFO "apa1480_cs: no SCSI devices found\n");
	scsi_unregister_module(MODULE_SCSI_HA, &driver_template);
	kfree(node);
	return NULL;
    } else
	node[n-1].next = NULL;
    
    MOD_INC_USE_COUNT;
    return node;
}

static void apa1480_detach(dev_node_t *node)
{
    MOD_DEC_USE_COUNT;
    scsi_unregister_module(MODULE_SCSI_HA, &driver_template);
    kfree(node);
}

/*====================================================================*/

static int __init init_apa1480_cb(void) {
    DEBUG(0, "%s\n", version);
    register_driver(&apa1480_ops);
    return 0;
}

static void __exit exit_apa1480_cb(void) {
    DEBUG(0, "apa1480_cs: unloading\n");
    unregister_driver(&apa1480_ops);
}

module_init(init_apa1480_cb);
module_exit(exit_apa1480_cb);
