#include <pcmcia/config.h>
#define __NO_VERSION__
#include <pcmcia/k_compat.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/malloc.h>
#include <linux/ioport.h>
#include <linux/pci.h>
#include <linux/pnp_bios.h>
#include <linux/pnp_resource.h>
#include <asm/irq.h>

/* From rsrc_mgr.c */
void request_io_region(u_long base, u_long num, char *name);

/*======================================================================

    PnP interrupt table manager

======================================================================*/

struct irq_entry {
    char *name;
    struct irq_entry *next;
};

static struct irq_entry *irq[NR_IRQS];

int proc_read_irq(char *buf, char **start, off_t pos,
		  int count, int *eof, void *data)
{
    int i;
    struct irq_entry *e;
    char *p = buf;
    for (i = 0; i < NR_IRQS; i++) {
	if (!irq[i]) continue;
	p += sprintf(p, "%3d:  ", i);
	for (e = irq[i]; e; e = e->next) {
	    strcpy(p, e->name);
	    if (e->next)
		strcat(p, ", ");
	    p += strlen(p);
	}
	strcat(p, "\n");
	p++;
    }
    return (p - buf);
}

void alloc_pnp_irq(int n, char *name)
{
    struct irq_entry **e = &irq[n];
    while (*e != NULL)
	e = &((*e)->next);
    *e = kmalloc(sizeof(*e), GFP_KERNEL);
    if (*e) {
	(*e)->name = name;
	(*e)->next = NULL;
    }
}

int check_pnp_irq(int n)
{
    return (irq[n] ? -EBUSY : 0);
}

void free_pnp_irqs(void)
{
    int n;
    struct irq_entry *e, *f;
    for (n = 0; n < NR_IRQS; n++)
	for (e = irq[n]; e; e = f) {
	    f = e->next;
	    kfree(e);
	}
}

/*======================================================================

    PCI device resource enumeration

======================================================================*/

#ifdef CONFIG_PCI

static char *pci_names = NULL;

static int pci_claim_resources(void)
{
    struct pci_dev *dev;
    int r;
    unsigned long flags;
#if (LINUX_VERSION_CODE < VERSION(2,3,13))
    unsigned long a;
    u32 b, sz, idx;
    u16 cmd, tmp;
#endif
    char *name;

    r = 0; pci_for_each_dev(dev) r++;
    name = pci_names = kmalloc(r*12, GFP_KERNEL);
    if (!name) return -ENOMEM;
    
    save_flags(flags);
    cli();
    pci_for_each_dev(dev) {
	if (dev->hdr_type != PCI_HEADER_TYPE_NORMAL)
	    continue;
	sprintf(name, "pci %02x:%02x.%1x", dev->bus->number,
		PCI_SLOT(dev->devfn), PCI_FUNC(dev->devfn));
	if (dev->irq)
	    alloc_pnp_irq(dev->irq, name);
#if (LINUX_VERSION_CODE < VERSION(2,3,13))
	/* Disable IO and memory while we fiddle */
	pci_read_config_word(dev, PCI_COMMAND, &cmd);
	tmp = cmd & ~(PCI_COMMAND_IO | PCI_COMMAND_MEMORY);
	pci_write_config_word(dev, PCI_COMMAND, tmp);
	for (idx = 0; idx < 6; idx++) {
	    a = dev->base_address[idx];
	    r = PCI_BASE_ADDRESS_0 + 4*idx;
	    if (((a & PCI_BASE_ADDRESS_SPACE_IO) &&
		 !(a & PCI_BASE_ADDRESS_IO_MASK)) ||
		!(a & PCI_BASE_ADDRESS_MEM_MASK))
		continue;
	    pci_read_config_dword(dev, r, &b);
	    pci_write_config_dword(dev, r, ~0);
	    pci_read_config_dword(dev, r, &sz);
	    pci_write_config_dword(dev, r, b);
	    if (a & PCI_BASE_ADDRESS_SPACE_IO) {
		a &= PCI_BASE_ADDRESS_IO_MASK;
		sz = (~(sz & PCI_BASE_ADDRESS_IO_MASK))+1;
		sz &= 0xffff;
		if (sz <= 0x100)
		    request_io_region(a, sz, name);
	    } else {
		a &= PCI_BASE_ADDRESS_MEM_MASK;
		sz = (~(sz & PCI_BASE_ADDRESS_MEM_MASK))+1;
		request_mem_region(a, sz, name);
	    }
	}
	if (dev->rom_address & ~1) {
	    r = PCI_ROM_ADDRESS;
	    pci_read_config_dword(dev, r, &b);
	    pci_write_config_dword(dev, r, ~0);
	    pci_read_config_dword(dev, r, &sz);
	    pci_write_config_dword(dev, r, b);
	    sz = (~(sz & ~1))+1;
	    request_mem_region(dev->rom_address & ~1, sz, name);
	}
	pci_write_config_word(dev, PCI_COMMAND, cmd);
#endif
	name += 12;
    }
    restore_flags(flags);
    return 0;
}

#endif /* CONFIG_PCI */

/*======================================================================

    PnP device resource enumeration
    
======================================================================*/

#define flip16(n)	le16_to_cpu(n)
#define flip32(n)	le32_to_cpu(n)

static struct pnp_dev_node_info node_info;

static void pnp_scan_node(char *name, u8 *buf, int len)
{
    union pnp_resource *p = (union pnp_resource *)buf;
    int tag = 0, sz;
    
    while (((u8 *)p < buf+len) && (tag != PNP_RES_SMTAG_END)) {
	if (p->lg.tag & PNP_RES_LARGE_ITEM) {
	    
	    union pnp_large_resource *r = &p->lg.d;
	    tag = p->lg.tag & ~PNP_RES_LARGE_ITEM;
	    sz = flip16(p->lg.sz) + 3;
	    switch (tag) {
	    case PNP_RES_LGTAG_MEM:
		if (r->mem.len && (r->mem.min == r->mem.max))
		    request_mem_region(flip16(r->mem.min)<<8,
				       flip16(r->mem.len), name);
		break;
	    case PNP_RES_LGTAG_MEM32:
		if (r->mem32.len && (r->mem32.min == r->mem32.max))
		    request_mem_region(flip32(r->mem32.min),
				       flip32(r->mem32.len), name);
		break;
	    case PNP_RES_LGTAG_MEM32_FIXED:
		if (r->mem32_fixed.len)
		    request_mem_region(flip32(r->mem32_fixed.base),
				       flip32(r->mem32_fixed.len), name);
		break;
	    }
	    
	} else {
	    
	    union pnp_small_resource *r = &p->sm.d;
	    tag = (p->sm.tag >> 3); sz = (p->sm.tag & 7) + 1;
	    switch (tag) {
	    case PNP_RES_SMTAG_IRQ:
		if (r->irq.mask && !(r->irq.mask & (r->irq.mask-1)))
		    alloc_pnp_irq(ffs(flip16(r->irq.mask))-1, name);
		break;
	    case PNP_RES_SMTAG_IO:
		if (r->io.len && (r->io.min == r->io.max))
		    request_io_region(flip16(r->io.min),
				      r->io.len, name);
		break;
	    case PNP_RES_SMTAG_IO_FIXED:
		if (r->io_fixed.len)
		    request_io_region(flip16(r->io_fixed.base),
				      r->io_fixed.len, name);
		break;
	    }
	    
	}
	(u8 *)p += sz;
    }
}

static char *pnp_names = NULL;

static int pnp_claim_resources(void)
{
    struct pnp_bios_node *node;
    char *name;
    u8 num;
    
    node = kmalloc(node_info.max_node_size, GFP_KERNEL);
    if (!node) return -ENOMEM;
    pnp_names = kmalloc(node_info.no_nodes*7, GFP_KERNEL);
    if (!pnp_names) {
	kfree(node);
	return -ENOMEM;
    }
    for (name = pnp_names, num = 0; num != 0xff; name += 7) {
	pnp_bios_get_dev_node(&num, 0, node);
	sprintf(name, "pnp %02x", node->handle);
	pnp_scan_node(name, node->data, node->size - sizeof(*node));
    }
    kfree(node);
    return 0;
}

/*====================================================================*/

void pnp_rsrc_init(void)
{
#ifdef CONFIG_PCI
    if (pcibios_present())
	pci_claim_resources();
#endif
    if (pnp_bios_present()) {
	if ((pnp_bios_dev_node_info(&node_info) == 0) &&
	    (node_info.no_nodes > 0))
	    pnp_claim_resources();
    }
}

void pnp_rsrc_done(void)
{
    if (pnp_names)
	kfree(pnp_names);
    free_pnp_irqs();
#ifdef CONFIG_PCI
    if (pci_names)
	kfree(pci_names);
#endif
}
