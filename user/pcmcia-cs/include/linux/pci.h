#ifndef _COMPAT_PCI_H
#define _COMPAT_PCI_H

#include_next <linux/pci.h>
#include <linux/version.h>

#ifndef PCI_FUNC
#define PCI_FUNC(devfn)		((devfn)&7)
#define PCI_SLOT(devfn)		((devfn)>>3)
#define PCI_DEVFN(dev,fn)	(((dev)<<3)|((fn)&7))
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,1,0))
extern struct pci_dev *pci_devices;
extern struct pci_bus pci_root;
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,1,93))

#include <linux/bios32.h>
#include <linux/types.h>

extern struct pci_dev *pci_find_slot(u_int bus, u_int devfn);
extern struct pci_dev *pci_find_class(u_int class, struct pci_dev *from);

#define pci_fn(x, sz, t) \
    static inline int pci_##x##_config_##sz(struct pci_dev *d, u8 w, t v) \
    { return pcibios_##x##_config_##sz(d->bus->number, d->devfn, w, v); }
pci_fn(read, byte, u8 *)
pci_fn(read, word, u16 *)
pci_fn(read, dword, u32 *)
pci_fn(write, byte, u8)
pci_fn(write, word, u16)
pci_fn(write, dword, u32)

#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,3,24))
extern int pci_enable_device(struct pci_dev *dev);
extern int pci_set_power_state(struct pci_dev *dev, int state);
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,3,40))
#define pci_for_each_dev(p) for (p = pci_devices; p; p = p->next)
#endif

extern u32 pci_irq_mask;

#endif /* _COMPAT_PCI_H */
