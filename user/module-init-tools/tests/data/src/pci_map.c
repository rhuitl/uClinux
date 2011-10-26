/* Simple file with a PCI map in it. */
#define __stringify_1(x)	#x
#define __stringify(x)		__stringify_1(x)

#define MODULE_GENERIC_TABLE(gtype,name)			\
static const unsigned long __module_##gtype##_size		\
  __attribute__ ((unused)) = sizeof(struct gtype##_id);		\
static const struct gtype##_id * __module_##gtype##_table	\
  __attribute__ ((unused)) = name;				\
extern const struct gtype##_id __mod_##gtype##_table		\
  __attribute__ ((unused, alias(__stringify(name))))

#define MODULE_DEVICE_TABLE(type,name)		\
  MODULE_GENERIC_TABLE(type##_device,name)

#define PCI_ANY_ID (~0)

struct pci_device_id {
	unsigned int vendor, device;		/* Vendor and device ID or PCI_ANY_ID */
	unsigned int subvendor, subdevice;	/* Subsystem ID's or PCI_ANY_ID */
	unsigned int class, class_mask;		/* (class,subclass,prog-if) triplet */
	unsigned long driver_data;		/* Data private to the driver */
};

static struct pci_device_id pci_ids[] = {
	{ 1, 2, 3, 4, 5, 6, 0xdeadbeef },
	{ 11, 12, 13, 14, 15, 16, 0xdeadbee5 },
	{0,}	/* 0 terminated list. */
};
MODULE_DEVICE_TABLE(pci, pci_ids);
