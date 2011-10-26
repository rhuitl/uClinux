/*
*  ALCATEL SpeedTouch USB : Simple portable USB interface - *BSD implementation
*  Copyright (C) 2001 Benoit PAPILLAULT
*  
*  This program is free software; you can redistribute it and/or
*  modify it under the terms of the GNU General Public License
*  as published by the Free Software Foundation; either version 2
*  of the License, or (at your option) any later version.
*  
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*  
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*
*  Author   : Richard Tobin
*  Creation : May 2001
*
* $Id: pusb-bsd.c,v 1.18 2004/03/03 22:11:01 edgomez Exp $
*/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>		/* for strerror */
#include <dev/usb/usb.h>
#include <sys/ioctl.h>
#include <sys/param.h>

#include "pusb.h"

/* sufficient for most purposes I think... */
#define MAX_CONTROLLERS 10

/******************************************************************************
* Patch USB structures for the change in early 2002 
******************************************************************************/
#if (defined (__FreeBSD__) && ((__FreeBSD_version > 500000 && __FreeBSD_version < 500031) || (__FreeBSD_version < 450001))) || (defined (__NetBSD__) && __NetBSD_Version__ < 105280000) || (defined (__OpenBSD__) && OpenBSD < 200211)

/* struct usb_ctl_request */
#define ucr_actlen  actlen
#define ucr_flags   flags
#define ucr_data    data
#define ucr_request request
#define ucr_addr    addr

/* struct usb_alt_interface */
#define uai_alt_no          alt_no
#define uai_interface_index interface_index

/* struct usb_device_info */
#define udi_productNo productNo
#define udi_product   product
#define udi_vendorNo  vendorNo
#define udi_vendor    vendor
#define udi_devnames  devnames
#define udi_addr      addr
#endif

/******************************************************************************
*	Structures
******************************************************************************/

struct pusb_device_t {
    char *prefix;
    int fd;
    int timeout;
};

struct pusb_endpoint_t {
	int fd;
	int timeout_read;
	int timeout_write;
};

/*****************************************************************************
*	Local Prototypes
*****************************************************************************/

static pusb_device_t make_device(int fd, const char *prefix);
static pusb_endpoint_t make_endpoint(int fd);
int pusb_get_interface(pusb_device_t dev, int interface);
int pusb_get_configuration(pusb_device_t dev);

/*****************************************************************************
*	Library functions
*****************************************************************************/

static pusb_device_t make_device(int fd, const char *prefix)
{
	pusb_device_t dev;

	if(!(dev = malloc(sizeof(*dev))))
		return 0;

	dev->fd = fd;
	dev->timeout = -1;
	if(!(dev->prefix = strdup(prefix)))
	{
		free(dev);
		return 0;
	}

	return dev;
}

static pusb_endpoint_t make_endpoint(int fd)
{
	pusb_endpoint_t ep;

	if(!(ep = malloc(sizeof(*ep))))
	return 0;

	ep->fd = fd;
	ep->timeout_write = -1;
	ep->timeout_read = -1;

	return ep;
}

pusb_device_t pusb_search_open(int vendorID, int productID)
{
	int controller, device;
	int cfd, dfd;
	char buf[20], prefix[20];

	for(controller = 0; controller < MAX_CONTROLLERS; controller++)
	{
		sprintf(buf, "/dev/usb%d", controller);
		cfd = open(buf, O_RDONLY);
		if(cfd < 0)
		{
			if(errno != ENXIO && errno != ENOENT)
			fprintf(stderr, "pusb_search_open: can't open %s: %s\n",
			buf, strerror(errno));
			continue;
		}
		
		for(device = 1; device < USB_MAX_DEVICES; device++)
		{
			struct usb_device_info di;
			
			di.udi_addr = device;
			if(ioctl(cfd, USB_DEVICEINFO, &di) < 0)
				continue;
			
#ifdef debug
			{
				int j;
				fprintf(stderr, "something on controller %d device %d\n",
						  controller, device);
				fprintf(stderr, "vendor %s product %s\n", di.udi_vendor, di.udi_product);
				for(j=0; j<4; j++)
					fprintf(stderr, "name %s\n", di.devnames[j]);
			}
#endif

			if(di.udi_vendorNo == vendorID && di.udi_productNo == productID)
			{ if(strncmp(di.udi_devnames[0], "ugen", 4) != 0)
				{
		    /* Has a real driver, don't mess with it */
					continue;
				}
				sprintf(prefix, "/dev/%s", di.udi_devnames[0]);

#if defined(__FreeBSD__)
				sprintf(buf, "%s", prefix);
#else		
				sprintf(buf, "%s.00", prefix);
#endif
				dfd =  open(buf, O_RDWR);
				
				if(dfd < 0)
				{
					fprintf(stderr,
						"pusb_search_open: couldn't open device %s: %s\n",
						buf, strerror(errno));
					close(cfd);
					return 0;
				}
				else
				{
					close(cfd);
					return make_device(dfd, prefix);
				}
			}
		}
	}

#ifdef debug
	fprintf(stderr, "didn't find device\n");
#endif
	
	close(cfd);
	return 0;
}

pusb_device_t pusb_open(const char *path)
{
	int dfd;
	char buf[20], prefix[20];
	
	sprintf(prefix, "%s", path);
#if defined(__FreeBSD__)
	sprintf(buf, "%s", prefix);
#else		
	sprintf(buf, "%s.00", prefix);
#endif
	dfd =  open(buf, O_RDWR);
	
	if(dfd < 0)
	{
		fprintf(stderr,
				"pusb_search_open: couldn't open device %s: %s\n",
			    buf, strerror(errno));
		return 0;
	}
	else
		return make_device(dfd, prefix);
}

int pusb_close(pusb_device_t dev)
{
	int ret;
	
	ret = close(dev->fd);
	free(dev->prefix);
	free(dev);
	
	return ret;
}

/*
* Function     : pusb_get_revision
* Return value : device descriptor revision, -1 on error
* Description  : open device and read revision number
*/
int pusb_get_revision(pusb_device_t dev)
{
        usb_device_descriptor_t desc;

	if (ioctl(dev->fd, USB_GET_DEVICE_DESC, &desc) < 0)
		return -1;

        return UGETW(desc.bcdDevice);
}

int pusb_control_msg(pusb_device_t dev,
		int request_type, int request,
		int value, int index, 
		unsigned char *buf, int size, int timeout)
{
	struct usb_ctl_request req;
	
	req.ucr_request.bmRequestType = request_type;
	req.ucr_request.bRequest = request;
	USETW(req.ucr_request.wValue, value);
	USETW(req.ucr_request.wIndex, index);
	USETW(req.ucr_request.wLength, size);
	
	req.ucr_data = buf;
	req.ucr_flags = USBD_SHORT_XFER_OK;
	
	/* !!! If your kernel is built with DIAGNOSTIC (which it is by
	 * !!! default under some versions of NetBSD) this ioctl will fail.
	 */
/*	
	if(timeout != dev->timeout)
	{
		if(ioctl(dev->fd, USB_SET_TIMEOUT, &timeout) < 0)
		{
#if defined(__NetBSD__) || defined(__OpenBSD__)
#else
			return -1;
#endif
		}
		dev->timeout = timeout;
	}
	*/
	
	if(ioctl(dev->fd, USB_DO_REQUEST, &req) < 0)
		return -1;
	else
		return req.ucr_actlen;
}

int pusb_set_configuration(pusb_device_t dev, int config)
{
	return ioctl(dev->fd, USB_SET_CONFIG, &config);
}

int pusb_get_configuration(pusb_device_t dev)
{
	int config;
	if(ioctl(dev->fd, USB_GET_CONFIG, &config) < 0)
		return -1;
	return config;
}

int pusb_set_interface(pusb_device_t dev, int interface, int alternate)
{
	struct usb_alt_interface intf;
	int config;
	
	intf.uai_interface_index = interface;
	intf.uai_alt_no = alternate;
	
	if(ioctl(dev->fd, USB_SET_ALTINTERFACE, &intf) < 0)
	{
		perror("USB_SET_ALTINTERFACE");
		return -1;
	}
	
	/* BUG: at least in FreeBSD 4.3, USB_SET_ALTINTERFACE does not
	 * make the necessary devices for the interface.  So we call
	 * USB_SET_CONFIG to ensure they are created.  But this will
	 * fail if any endpoints (other than the control) are open.
	 * Of course, the devices might already exist, so failure
	 * to set the configuration does not mean it will not work.
	 */
	
	config = pusb_get_configuration(dev);
	if(config < 0 || pusb_set_configuration(dev, config) < 0)
	{
		fprintf(stderr, "warning: pusb_set_interface may have failed\n");
	}
	return 0;
}

int pusb_get_interface(pusb_device_t dev, int interface)
{
	struct usb_alt_interface intf;
	
	intf.uai_interface_index = interface;
	
	if(ioctl(dev->fd, USB_GET_ALTINTERFACE, &intf) < 0)
		return -1;
	return intf.uai_alt_no;
}

pusb_endpoint_t pusb_endpoint_open(pusb_device_t dev, int epnum, int flags)
{
	int one = 1;
	char buf[20];
	int fd;

#if defined(__FreeBSD__)
	sprintf(buf, "%s.%d", dev->prefix, epnum & 0x0f);
#else
	sprintf(buf, "%s.%02d", dev->prefix, epnum & 0x0f);
#endif
	fd = open(buf, flags, 0);
	if(fd < 0)
	{
		fprintf(stderr,
				"pusb_endpoint_open: couldn't open endpoint %s: %s\n",
				buf, strerror(errno));
		return 0;
	}
	
	if(ioctl(fd, USB_SET_SHORT_XFER, &one) < 0)
		return 0;
	
	return make_endpoint(fd);
}

int pusb_endpoint_read(pusb_endpoint_t ep, 
		unsigned char *buf, int size, int timeout)
{
	int ret;
	
	if(timeout != ep->timeout_read)
	{
		if(ioctl(ep->fd, USB_SET_TIMEOUT, &timeout) < 0)
			return -1;
		ep->timeout_read = timeout;
	}
	
	ret = read(ep->fd, buf, size);
#ifdef debug
	fprintf(stderr, "pusb_endpoint_read: read returned %d\n", ret);
#endif
	
	return ret;
}

int pusb_endpoint_write(pusb_endpoint_t ep, 
		const unsigned char *buf, int size, int timeout)
{
	int sent = 0;
	int ret;
	/*
	 * Timeout can't be set on writing endpoint.
	 * ugen.c define it by default to USBD_NO_TIMEOUT
 
	if(timeout != ep->timeout_write)
	{
		if(ioctl(ep->fd, USB_SET_TIMEOUT, &timeout) < 0)
			return -1;
		ep->timeout_write = timeout;
	}

	 */ 
	
	do {
		ret = write(ep->fd, buf+sent, size-sent);
		if(ret < 0)
			return sent > 0 ? sent : -1;
		sent += ret;
	} while(ret > 0 && sent < size);
	
	return sent;
}

int pusb_endpoint_close(pusb_endpoint_t ep)
{
	int ret;
	
	ret = close(ep->fd);
	free(ep);
	
	return ret;
}

/* Function not existing in this USB stack */
int pusb_claim_interface(pusb_device_t dev,int interface)
{
	return 0;
}

/* Function not existing in this USB stack */
int pusb_release_interface(pusb_device_t dev,int interface)
{
	return 0;
}

/* Function not existing in this USB stack */
int pusb_ioctl (pusb_device_t dev,int interface,int code,void *data)
{
	return -ENOTTY;
}
