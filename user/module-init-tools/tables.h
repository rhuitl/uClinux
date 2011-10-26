#ifndef MODINITTOOLS_TABLES_H
#define MODINITTOOLS_TABLES_H
#include <stddef.h>

/* Taken from the 2.5.49 kernel, with the kernel specific fields removed */
struct pci_device_id {
	unsigned int vendor, device;		/* Vendor and device ID or PCI_ANY_ID */
	unsigned int subvendor, subdevice;	/* Subsystem ID's or PCI_ANY_ID */
	unsigned int class, class_mask;		/* (class,subclass,prog-if) triplet */
};
#define PCI_DEVICE_SIZE32 (6 * 4 + 4)
#define PCI_DEVICE_SIZE64 (6 * 4 + 8)

struct usb_device_id {
	/* which fields to match against? */
	unsigned short	match_flags;

	/* Used for product specific matches; range is inclusive */
	unsigned short	idVendor;
	unsigned short	idProduct;
	unsigned short	bcdDevice_lo;
	unsigned short	bcdDevice_hi;

	/* Used for device class matches */
	unsigned char	bDeviceClass;
	unsigned char	bDeviceSubClass;
	unsigned char	bDeviceProtocol;

	/* Used for interface class matches */
	unsigned char	bInterfaceClass;
	unsigned char	bInterfaceSubClass;
	unsigned char	bInterfaceProtocol;

};
#define USB_DEVICE_SIZE32 (5 * 2 + 6 * 1 + 4)
#define USB_DEVICE_SIZE64 (5 * 2 + 6 * 1 + 8)

struct ieee1394_device_id {
	unsigned int match_flags;
	unsigned int vendor_id;
	unsigned int model_id;
	unsigned int specifier_id;
	unsigned int version;
};
#define IEEE1394_DEVICE_SIZE32 (5 * 4 + 4)
#define IEEE1394_DEVICE_SIZE64 (5 * 4 + 4 /*padding*/ + 8)

struct ccw_device_id {
	unsigned short match_flags;	/* which fields to match against */

	unsigned short cu_type;		/* control unit type     */
	unsigned short dev_type;	/* device type           */
	unsigned char  cu_model;	/* control unit model    */
	unsigned char  dev_model;	/* device model          */
};
#define CCW_DEVICE_SIZE32 (3 * 2 + 2 * 1 + 4)
#define CCW_DEVICE_SIZE64 (3 * 2 + 2 * 1 + 8)

struct pnp_device_id {
	char id[8];
};
#define PNP_DEVICE_SIZE32 (8 + 4)
#define PNP_DEVICE_SIZE64 (8 + 8)

struct pnp_card_devid
{
	char devid[8][8];
};
struct pnp_card_device_id_32 {
	char id[8];
	char driver_data[4];
	char devid[8][8];
};
struct pnp_card_device_id_64 {
	char id[8];
	char driver_data[8];
	char devid[8][8];
};
#define PNP_CARD_DEVICE_SIZE32 (sizeof(struct pnp_card_device_id_32))
#define PNP_CARD_DEVICE_SIZE64 (sizeof(struct pnp_card_device_id_64))
#define PNP_CARD_DEVICE_OFFSET32 (offsetof(struct pnp_card_device_id_32, devid))
#define PNP_CARD_DEVICE_OFFSET64 (offsetof(struct pnp_card_device_id_64, devid))
struct input_device_id_old_64 {
	unsigned long long match_flags;
	unsigned short bustype;
	unsigned short vendor;
	unsigned short product;
	unsigned short version;
	unsigned long long evbit[1];
	unsigned long long keybit[8]; /* 512 bits */
	unsigned long long relbit[1];
	unsigned long long absbit[1]; /* 64 bits */
	unsigned long long mscbit[1];
	unsigned long long ledbit[1];
	unsigned long long sndbit[1];
	unsigned long long ffbit[2]; /* 128 bits */
	unsigned long long driver_info;
};

struct input_device_id_old_32 {
	unsigned int match_flags;
	unsigned short bustype;
	unsigned short vendor;
	unsigned short product;
	unsigned short version;
	unsigned int evbit[1];
	unsigned int keybit[16]; /* 512 bits */
	unsigned int relbit[1];
	unsigned int absbit[2]; /* 64 bits */
	unsigned int mscbit[1];
	unsigned int ledbit[1];
	unsigned int sndbit[1];
	unsigned int ffbit[4]; /* 128 bits */
	unsigned int driver_info;
};

/* Whee... structure changed in 2.6.14 and broke module-init-tools. */
struct input_device_id_64 {
	unsigned long long match_flags;
	unsigned short bustype;
	unsigned short vendor;
	unsigned short product;
	unsigned short version;
	unsigned long long evbit[1];
	unsigned long long keybit[8]; /* 512 bits */
	unsigned long long relbit[1];
	unsigned long long absbit[1]; /* 64 bits */
	unsigned long long mscbit[1];
	unsigned long long ledbit[1];
	unsigned long long sndbit[1];
	unsigned long long ffbit[2]; /* 128 bits */
	unsigned long long swbit[1];
	unsigned long long driver_info;
};

struct input_device_id_32 {
	unsigned int match_flags;
	unsigned short bustype;
	unsigned short vendor;
	unsigned short product;
	unsigned short version;
	unsigned int evbit[1];
	unsigned int keybit[16]; /* 512 bits */
	unsigned int relbit[1];
	unsigned int absbit[2]; /* 64 bits */
	unsigned int mscbit[1];
	unsigned int ledbit[1];
	unsigned int sndbit[1];
	unsigned int ffbit[4]; /* 128 bits */
	unsigned int swbit[1];
	unsigned int driver_info;
};

/* These are the old sizes. */
#define INPUT_DEVICE_SIZE32 (4 + 4 * 2 + 4 + 16 * 4 + 4 + 2 * 4 + 4 + 4 + 4 + 4 * 4 + 4)
#define INPUT_DEVICE_SIZE64 (8 + 4 * 2 + 8 + 8 * 8 + 8 + 8 + 8 + 8 + 8 + 2 * 8 + 8)

struct serio_device_id {
	unsigned char type;
	unsigned char extra;
	unsigned char id;
	unsigned char proto;
};
#define SERIO_DEVICE_SIZE32 (4 * 1)
#define SERIO_DEVICE_SIZE64 (4 * 1 + 4)

struct of_device_id {
	char name[32];
	char type[32];
	char compatible[128];
};

#define OF_DEVICE_SIZE32 (32 * 2 + 128 + 4)
#define OF_DEVICE_SIZE64 (32 * 2 + 128 + 8)

/* Functions provided by tables.c */
struct module;
void output_usb_table(struct module *modules, FILE *out);
void output_ieee1394_table(struct module *modules, FILE *out);
void output_pci_table(struct module *modules, FILE *out);
void output_ccw_table(struct module *modules, FILE *out);
void output_isapnp_table(struct module *modules, FILE *out);
void output_input_table(struct module *modules, FILE *out);
void output_serio_table(struct module *modules, FILE *out);
void output_of_table(struct module *modules, FILE *out);

#endif /* MODINITTOOLS_TABLES_H */
