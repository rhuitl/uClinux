/*======================================================================

    A direct memory interface driver for CardBus cards

    memory_cb.c 1.16 2000/06/12 21:27:26

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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/malloc.h>
#include <linux/string.h>
#include <linux/ioport.h>
#include <linux/major.h>
#include <linux/pci.h>
#include <asm/io.h>

#include <pcmcia/driver_ops.h>
#include <pcmcia/mem_op.h>

#ifdef PCMCIA_DEBUG
static int pc_debug = PCMCIA_DEBUG;
MODULE_PARM(pc_debug, "i");
#define DEBUG(n, args...) if (pc_debug>(n)) printk(KERN_DEBUG args)
static char *version =
"memory_cb.c 1.16 2000/06/12 21:27:26 (David Hinds)";
#else
#define DEBUG(n, args...)
#endif

/*====================================================================*/

/* Parameters that can be set with 'insmod' */

/*====================================================================*/

typedef struct memory_dev_t {
    dev_node_t		node;
    struct pci_dev	*pdev;
    u_int		open, stopped;
    u_int		base[8];
    u_int		size[8];
    u_char		*virt[8];
} memory_dev_t;

#define MAX_DEV 8
static memory_dev_t *dev_table[MAX_DEV] = { 0 };

static int major_dev = 0;

/*====================================================================*/

#define FIND_FIRST_BIT(n)	((n) - ((n) & ((n)-1)))
#define CB_BAR(n)		(PCI_BASE_ADDRESS_0+(4*(n)))
#define CB_ROM_BASE		0x0030

static dev_node_t *memory_attach(dev_locator_t *loc)
{
    u_char bus, devfn, cmd;
    memory_dev_t *dev;
    int i, br;
    
    if (loc->bus != LOC_PCI) return NULL;
    bus = loc->b.pci.bus; devfn = loc->b.pci.devfn;
    printk(KERN_INFO "memory_attach(device %02x:%02x.%d)\n",
	   bus, PCI_SLOT(devfn), PCI_FUNC(devfn));

    for (i = 0; i < MAX_DEV; i++)
	if (dev_table[i] == NULL) break;
    if (i == MAX_DEV) return NULL;
    dev_table[i] = dev = kmalloc(sizeof(memory_dev_t), GFP_KERNEL);
    memset(dev, 0, sizeof(memory_dev_t));
    dev->pdev = pci_find_slot(bus, devfn);
    sprintf(dev->node.dev_name, "cbmem%d", i);
    dev->node.major = major_dev;
    dev->node.minor = i<<3;
    
    dev->size[0] = 0x100;
    printk(KERN_INFO "memory_cb: cbmem%d: 0 [256 b]", i);
    pci_read_config_byte(dev->pdev, PCI_COMMAND, &cmd);
    pci_write_config_byte(dev->pdev, PCI_COMMAND, 0);
    for (i = 1; i < 8; i++) {
	br = (i == 7) ? CB_ROM_BASE : CB_BAR(i-1);
	pci_read_config_dword(dev->pdev, br, &dev->base[i]);
	pci_write_config_dword(dev->pdev, br, 0xffffffff);
	pci_read_config_dword(dev->pdev, br, &dev->size[i]);
	pci_write_config_dword(dev->pdev, br, dev->base[i]);
	dev->size[i] &= PCI_BASE_ADDRESS_MEM_MASK;
	dev->size[i] = FIND_FIRST_BIT(dev->size[i]);
	if (dev->size[i] == 0) continue;
	if ((i == 7) || ((dev->base[i] & PCI_BASE_ADDRESS_SPACE) == 0)) {
	    dev->base[i] &= PCI_BASE_ADDRESS_MEM_MASK;
	    dev->virt[i] = ioremap(dev->base[i], dev->size[i]);
	} else {
	    dev->base[i] &= PCI_BASE_ADDRESS_IO_MASK;
	}
	if (dev->size[i] & 0x3ff)
	    printk(", %d [%d b]", i, dev->size[i]);
	else
	    printk(", %d [%d kb]", i, dev->size[i]>>10);
    }
    printk("\n");
    pci_write_config_byte(dev->pdev, PCI_COMMAND, cmd);
    MOD_INC_USE_COUNT;
    return &dev->node;
}

static void memory_detach(dev_node_t *node)
{
    memory_dev_t *dev = (memory_dev_t *)node;
    int i;

    dev->stopped = 1;
    if (dev->open) return;
    dev_table[node->minor >> 3] = NULL;
    for (i = 0; i < 8; i++)
	if (dev->virt[i] != NULL) iounmap(dev->virt[i]);
    kfree(dev);
    MOD_DEC_USE_COUNT;
}

/*====================================================================*/

static int memory_open(struct inode *inode, struct file *file)
{
    int minor = MINOR(F_INODE(file)->i_rdev);
    memory_dev_t *dev = dev_table[minor>>3];

    DEBUG(0, "memory_open(%d)\n", minor);
    if ((dev == NULL) || (dev->stopped) || (dev->size[minor&7] == 0))
	return -ENODEV;
    dev->open++;
    MOD_INC_USE_COUNT;
    return 0;
}

static FS_RELEASE_T memory_close(struct inode *inode, struct file *file)
{
    int minor = MINOR(F_INODE(file)->i_rdev);
    memory_dev_t *dev = dev_table[minor>>3];
    
    DEBUG(0, "memory_close(%d)\n", minor);
    dev->open--;
    MOD_DEC_USE_COUNT;
    if (dev->stopped && (dev->open == 0))
	memory_detach((dev_node_t *)dev);
    return (FS_RELEASE_T)0;
}

static ssize_t memory_read FOPS(struct inode *inode,
				struct file *file, char *buf,
				size_t count, loff_t *ppos)
{
    int minor = MINOR(F_INODE(file)->i_rdev);
    memory_dev_t *dev = dev_table[minor>>3];
    int space = minor & 7;
    size_t i, odd, pos = FPOS;
    
    DEBUG(2, "memory_read(%d, 0x%lx, 0x%lx)\n", minor,
	  (u_long)pos, (u_long)count);

    if (dev->stopped)
	return -ENODEV;
    if (pos >= dev->size[space])
	return 0;
    if (count > dev->size[space] - pos)
	count = dev->size[space] - pos;

    odd = count & 3; count &= ~3;

    if (space == 0) {

	for (i = 0; i < count; i += 4, pos += 4, buf += 4)
	    pci_read_config_dword(dev->pdev, pos, (u32 *)buf);
	if (odd & 2) {
	    pci_read_config_word(dev->pdev, pos, (u16 *)buf);
	    pos += 2; buf += 2;
	}
	if (odd & 1) {
	    pci_read_config_byte(dev->pdev, pos, buf);
	}

    } else if (dev->virt[space] != NULL) {

	for (i = 0; i < count; i += 4, pos += 4, buf += 4)
	    *(u32 *)buf = readl_ns(dev->virt[space]+pos);
	if (odd & 2) {
	    *(u16 *)buf = readw_ns(dev->virt[space]+pos);
	    pos += 2; buf += 2;
	}
	if (odd & 1) {
	    *buf = readb(dev->virt[space]+pos);
	}

    } else {

	for (i = 0; i < count; i += 4, pos += 4, buf += 4)
	    *(u32 *)buf = inl(dev->base[space]+pos);
	if (odd & 2) {
	    *(u16 *)buf = inw(dev->base[space]+pos);
	    pos += 2; buf += 2;
	}
	if (odd & 1) {
	    *buf = inb(dev->base[space]+pos);
	}

    }

    FPOS += count+odd;
    return count+odd;
}

static ssize_t memory_write FOPS(struct inode *inode,
				 struct file *file, const char *buf,
				 size_t count, loff_t *ppos)
{
    int minor = MINOR(F_INODE(file)->i_rdev);
    memory_dev_t *dev = dev_table[minor>>3];
    int space = minor & 7;
    size_t i, odd, pos = FPOS;
    
    DEBUG(2, "memory_read(%d, 0x%lx, 0x%lx)\n", minor,
	  (u_long)pos, (u_long)count);
    
    if (dev->stopped)
	return -ENODEV;
    if (pos >= dev->size[space])
	return 0;
    if (count > dev->size[space] - pos)
	count = dev->size[space] - pos;

    odd = count & 3; count &= ~3;

    if (space == 0) {

	for (i = 0; i < count; i += 4, pos += 4, buf += 4)
	    pci_write_config_dword(dev->pdev, pos, *(u32 *)buf);
	if (odd & 2) {
	    pci_write_config_word(dev->pdev, pos, *(u16 *)buf);
	    pos += 2; buf += 2;
	}
	if (odd & 1) {
	    pci_write_config_byte(dev->pdev, pos, *buf);
	}

    } else if (dev->virt[space] != NULL) {

	for (i = 0; i < count; i += 4, pos += 4, buf += 4)
	    writel_ns(*(u32 *)buf, dev->virt[space]+pos);
	if (odd & 2) {
	    writew_ns(*(u16 *)buf, dev->virt[space]+pos);
	    pos += 2; buf += 2;
	}
	if (odd & 1) {
	    writeb(*buf, dev->virt[space]+pos);
	}

    } else {

	for (i = 0; i < count; i += 4, pos += 4, buf += 4)
	    outl(*(u32 *)buf, dev->base[space]+pos);
	if (odd & 2) {
	    outw(*(u16 *)buf, dev->base[space]+pos);
	    pos += 2; buf += 2;
	}
	if (odd & 1) {
	    outb(*buf, dev->base[space]+pos);
	}

    }

    FPOS += count+odd;
    return count+odd;
}

/*====================================================================*/

static struct file_operations memory_fops = {
    open:	memory_open,
    release:	memory_close,
    read:	memory_read,
    write:	memory_write,
};

struct driver_operations memory_ops = {
    "memory_cb", memory_attach, NULL, NULL, memory_detach
};

static int __init init_memory_cb(void)
{
    DEBUG(0, "%s\n", version);
    major_dev = register_chrdev(major_dev, "memory_cb", &memory_fops);
    if (major_dev == 0) {
	printk(KERN_NOTICE "memory_cb: unable to grab major "
	       "device number!\n");
	return -1;
    }
    register_driver(&memory_ops);
    return 0;
}

static void exit_memory_cb(void)
{
    DEBUG(0, "memory_cb: unloading\n");
    unregister_driver(&memory_ops);
    if (major_dev != 0)
	unregister_chrdev(major_dev, "memory_cb");
}

module_init(init_memory_cb);
module_exit(exit_memory_cb);
