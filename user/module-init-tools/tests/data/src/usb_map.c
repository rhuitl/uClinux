/* Simple file with a USB map in it. */
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

#define USB_DEVICE(vend,prod) \
	.match_flags = USB_DEVICE_ID_MATCH_DEVICE, .idVendor = (vend), .idProduct = (prod)

struct usb_device_id {
	/* which fields to match against? */
	unsigned short		match_flags;

	/* Used for product specific matches; range is inclusive */
	unsigned short		idVendor;
	unsigned short		idProduct;
	unsigned short		bcdDevice_lo;
	unsigned short		bcdDevice_hi;

	/* Used for device class matches */
	unsigned char		bDeviceClass;
	unsigned char		bDeviceSubClass;
	unsigned char		bDeviceProtocol;

	/* Used for interface class matches */
	unsigned char		bInterfaceClass;
	unsigned char		bInterfaceSubClass;
	unsigned char		bInterfaceProtocol;

	/* not matched against */
	unsigned long	driver_info;
};

struct usb_device_id usb_ids[] = {
	{  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	   0xdeadbeef },
	{  11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
	   0xdeadbee5 },
	{ }
};

MODULE_DEVICE_TABLE(usb, usb_ids);
