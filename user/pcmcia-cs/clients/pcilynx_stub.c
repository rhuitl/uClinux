/*======================================================================

    A driver for the Newer Technology FireWire 2 Go CardBus IEEE1934/
    FireWire Host Adapter

    pcilynx_stub.c 1.00 2000/09/07 15:46:42

    The contents of this file are subject to the Mozilla Public
    License Version 1.1 (the "License"); you may not use this file
    except in compliance with the License. You may obtain a copy of
    the License at http://www.mozilla.org/MPL/

    Software distributed under the License is distributed on an "AS
    IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
    implied. See the License for the specific language governing
    rights and limitations under the License.

    The initial developer of the original code is Albrecht Dreﬂ
    <ad@mpifr-bonn.mpg.de>.  However, most parts were actually copied
    from the file apa1480_stub.c, developed by David A. Hinds
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
#include <linux/major.h>
#include <linux/blk.h>
#include <linux/pci.h>
#include <asm/io.h>

#include <../drivers/ieee1394/ieee1394.h>
#include <../drivers/ieee1394/ieee1394_types.h>
#include <../drivers/ieee1394/hosts.h>
#include <../drivers/ieee1394/ieee1394_core.h>
#define lynx_csr_rom bogus_stuff
#include <../drivers/ieee1394/pcilynx.h>

#include <pcmcia/driver_ops.h>

#ifdef PCMCIA_DEBUG
static int pc_debug = PCMCIA_DEBUG;
MODULE_PARM(pc_debug, "i");
#define DEBUG(n, args...) if (pc_debug>(n)) printk(KERN_DEBUG args)
static char *version =
"pcilynx_cb.c 1.00 2000/09/07 15:46:42 (Albrecht Dreﬂ)";
#else
#define DEBUG(n, args...)
#endif

/*====================================================================*/

extern struct hpsb_host_template *get_lynx_template(void);

static dev_node_t *pcilynx_attach(dev_locator_t *loc);
static void pcilynx_detach(dev_node_t *node);

struct driver_operations pcilynx_ops = {
    "pcilynx_cb", pcilynx_attach, NULL, NULL, pcilynx_detach
};

/*====================================================================*/

static dev_node_t *pcilynx_attach(dev_locator_t *loc)
{
    u_char bus, devfn;
    dev_node_t *node;
    u_int io;
    
    if (loc->bus != LOC_PCI) 
      return NULL;
    bus = loc->b.pci.bus; 
    devfn = loc->b.pci.devfn;
    printk(KERN_INFO "pcilynx_attach(device %02x:%02x.%d)\n",
	   bus, PCI_SLOT(devfn), PCI_FUNC(devfn));

    /* A hack to work around resource allocation confusion */
    pcibios_read_config_dword(bus, devfn, PCI_BASE_ADDRESS_0, &io);
    release_region(io & PCI_BASE_ADDRESS_IO_MASK, 0x100);

    if (hpsb_register_lowlevel(get_lynx_template())) 
      {
	printk(KERN_ERR "registering failed");
	return NULL;
      } 
    else 
      {
	node = kmalloc(sizeof(dev_node_t), GFP_KERNEL);
	strcpy (node->dev_name, "pcilynx");
	node->major = PCILYNX_MAJOR;
	node->minor = 0;
	node->next = NULL;
	MOD_INC_USE_COUNT;
	return node;
      }
}

static void pcilynx_detach(dev_node_t *node)
{
    hpsb_unregister_lowlevel(get_lynx_template());
    printk(KERN_INFO "removed pcilynx_cb module\n");
    kfree(node);
    MOD_DEC_USE_COUNT;
}

/*====================================================================*/

static int __init init_pcilynx_cb(void) {
    DEBUG(0, "%s: loading\n", version);
    register_driver(&pcilynx_ops);
    return 0;
}

static void __exit exit_pcilynx_cb(void) {
    DEBUG(0, "%s: unloading\n", version);
    unregister_driver(&pcilynx_ops);
}

module_init(init_pcilynx_cb);
module_exit(exit_pcilynx_cb);
