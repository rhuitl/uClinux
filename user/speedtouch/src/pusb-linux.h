#include <stdint.h>		/* uint*_t */

#define __u8 uint8_t
#define __u16 uint16_t
#define __u32 uint32_t

/* from <linux/usb.h> */

/*
 * USB directions
 */
#define USB_DIR_OUT			0		/* to device */
#define USB_DIR_IN			0x80		/* to host */



/* from <linux/usbdevice_fs.h> */

/* usbdevfs ioctl codes */

struct usbdevfs_ctrltransfer {
	__u8 requesttype;
	__u8 request;
	__u16 value;
	__u16 index;
	__u16 length;
	__u32 timeout;  /* in milliseconds */
	void *data;
};

struct usbdevfs_bulktransfer {
	unsigned int ep;
	unsigned int len;
	unsigned int timeout; /* in milliseconds */
	void *data;
};

struct usbdevfs_setinterface {
	unsigned int interface;
	unsigned int altsetting;
};

struct usbdevfs_disconnectsignal {
	unsigned int signr;
	void *context;
};

#define USBDEVFS_URB_DISABLE_SPD           1
#define USBDEVFS_URB_ISO_ASAP              2
#define USBDEVFS_URB_QUEUE_BULK            0x10

#define USBDEVFS_URB_TYPE_ISO		   0
#define USBDEVFS_URB_TYPE_INTERRUPT	   1
#define USBDEVFS_URB_TYPE_CONTROL	   2
#define USBDEVFS_URB_TYPE_BULK		   3

struct usbdevfs_iso_packet_desc {
	unsigned int length;
	unsigned int actual_length;
	unsigned int status;
};

struct usbdevfs_urb {
	unsigned char type;
	unsigned char endpoint;
	int status;
	unsigned int flags;
	void *buffer;
	int buffer_length;
	int actual_length;
	int start_frame;
	int number_of_packets;
	int error_count;
	unsigned int signr;  /* signal to be sent on error, -1 if none should be sent */
	void *usercontext;
	struct usbdevfs_iso_packet_desc iso_frame_desc[0];
};

/* ioctls for talking to drivers in the usbcore module: */
struct usbdevfs_ioctl {
	int	ifno;		/* interface 0..N ; negative numbers reserved */
	int	ioctl_code;	/* MUST encode size + direction of data so the
				 * macros in <asm/ioctl.h> give correct values */
	void	*data;		/* param buffer (in, or out) */
};

#define USBDEVFS_CONTROL           _IOWR('U', 0, struct usbdevfs_ctrltransfer)
#define USBDEVFS_BULK              _IOWR('U', 2, struct usbdevfs_bulktransfer)
#define USBDEVFS_RESETEP           _IOR('U', 3, unsigned int)
#define USBDEVFS_SETINTERFACE      _IOR('U', 4, struct usbdevfs_setinterface)
#define USBDEVFS_SETCONFIGURATION  _IOR('U', 5, unsigned int)
#define USBDEVFS_GETDRIVER         _IOW('U', 8, struct usbdevfs_getdriver)
#define USBDEVFS_SUBMITURB         _IOR('U', 10, struct usbdevfs_urb)
#define USBDEVFS_DISCARDURB        _IO('U', 11)
#define USBDEVFS_REAPURB           _IOW('U', 12, void *)
#define USBDEVFS_REAPURBNDELAY     _IOW('U', 13, void *)
#define USBDEVFS_DISCSIGNAL        _IOR('U', 14, struct usbdevfs_disconnectsignal)
#define USBDEVFS_CLAIMINTERFACE    _IOR('U', 15, unsigned int)
#define USBDEVFS_RELEASEINTERFACE  _IOR('U', 16, unsigned int)
#define USBDEVFS_CONNECTINFO       _IOW('U', 17, struct usbdevfs_connectinfo)
#define USBDEVFS_IOCTL             _IOWR('U', 18, struct usbdevfs_ioctl)
#define USBDEVFS_HUB_PORTINFO      _IOR('U', 19, struct usbdevfs_hub_portinfo)
#define USBDEVFS_RESET             _IO('U', 20)
#define USBDEVFS_CLEAR_HALT        _IOR('U', 21, unsigned int)

#undef __u8
#undef __u16
#undef __u32

