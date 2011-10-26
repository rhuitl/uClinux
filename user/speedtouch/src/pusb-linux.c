/*
*  ALCATEL SpeedTouch USB : Portable USB user library -- Linux implementation
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
*  Author   : Benoit PAPILLAULT <benoit.papillault@free.fr>
*  Creation : 29/05/2001
*
*  $Id: pusb-linux.c,v 1.12 2004/02/15 21:25:07 edgomez Exp $
*/

#ifndef _PUSB_LINUX_C_
#define _PUSB_LINUX_C_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include "pusb-linux.h"
#include "pusb.h"

/* Some kernel types must be faked if undefined */
#if !defined(__u8)
#define __u8 uint8_t
#endif
#if !defined(__u16)
#define __u16 uint16_t
#endif
#if !defined(__u32)
#define __u32 uint32_t
#endif

/******************************************************************************
*	Structures
******************************************************************************/

struct pusb_device_t
{
	int fd;
};

struct pusb_endpoint_t
{
	int fd;
	int ep;
};

static const char usb_path[] = "/proc/bus/usb";

/* Device descriptor */
struct usb_device_descriptor {
	__u8  bLength;
	__u8  bDescriptorType;
	__u16 bcdUSB;
	__u8  bDeviceClass;
	__u8  bDeviceSubClass;
	__u8  bDeviceProtocol;
	__u8  bMaxPacketSize0;
	__u16 idVendor;
	__u16 idProduct;
	__u16 bcdDevice;
	__u8  iManufacturer;
	__u8  iProduct;
	__u8  iSerialNumber;
	__u8  bNumConfigurations;
} __attribute__ ((packed));

/*****************************************************************************
*	Local Prototypes
*****************************************************************************/

static int test_file(const char *path, int vendorID, int productID);
static int usbfs_search(const char *path, int vendorID, int productID);
static pusb_device_t make_device(int fd);

/*****************************************************************************
*       Global Data
*****************************************************************************/

/* Holds the page size on current host
 * This variable is initialized each time make_device() is called, so we are
 * sure it is initialized before it's used */
static long pagesize = -1;

/*****************************************************************************
*	Library functions
*****************************************************************************/



/*
* Function     : pusb_search_open
* Return value : NULL on error, a valid pusb_device_t on success
* Description  : 
*/
pusb_device_t pusb_search_open(int vendorID, int productID)
{
	int fd;

	if ((fd = usbfs_search("/proc/bus/usb",vendorID,productID)) < 0)
		return(NULL);

	return(make_device(fd));

}

/*
* Function     : pusb_open
* Return value : NULL on error, a valid pusb_device_t on success
* Description  : Opens the USB device pointed by path
*/
pusb_device_t pusb_open(const char *path)
{
	int fd; 

	if ((fd = open(path, O_RDWR)) < 0)
		return(NULL);

	return(make_device(fd));

}

/*
* Function     : pusb_close
* Return value : 0 on success, -1 on error (errno is set)
* Description  : Closes the USB dev
*/
int pusb_close(pusb_device_t dev)
{

	int ret;

	ret = close(dev->fd);
	free(dev);

	return(ret);

}

/*
* Function     : pusb_get_revision
* Return value : device descriptor revision, -1 on error
* Description  : open device and read revision number
*/
int pusb_get_revision(pusb_device_t dev)
{
	struct usb_device_descriptor desc;

	if(lseek(dev->fd, 0, SEEK_SET) != 0) {
		return(-1);
	}	
	if(read(dev->fd, &desc, sizeof(desc)) == sizeof(desc))  {
		if(desc.bLength == sizeof(desc)) {
			return desc.bcdDevice;
		}
	}
	return(-1);
}

/*
* Function     : pusb_control_msg
* Return value : ioctl returned value (see linux usb docs)
* Description  : sends a control msg urb to the device
*/
int pusb_control_msg(	pusb_device_t dev,
			int request_type,
			int request,
			int value,
			int index, 
			unsigned char *buf,
			int size,
			int timeout)
{

	int ret;
	struct usbdevfs_ctrltransfer ctrl;

	ctrl.requesttype = request_type;
	ctrl.request     = request;
	ctrl.value       = value;
	ctrl.index       = index;
	ctrl.length      = size;
	ctrl.timeout     = timeout;
	ctrl.data        = buf;

	ret = ioctl(dev->fd,USBDEVFS_CONTROL,&ctrl);

	return(ret);

}

/*
* Function     : pusb_set_configuration
* Return value : ioctl returned value (see linux-usb docs)
* Description  : cf function name
*/
int pusb_set_configuration(pusb_device_t dev, int config)
{

	int ret;

	ret = ioctl(dev->fd,USBDEVFS_SETCONFIGURATION,&config);

	return(ret);

}

/*
* Function     : pusb_set_interface
* Return value : ioctl returned value (see linux-usb docs)
* Description  : see function name
*/
int pusb_set_interface(pusb_device_t dev, int interface, int alternate)
{

	struct usbdevfs_setinterface setintf;
	int ret;

	setintf.interface = interface;
	setintf.altsetting = alternate;

	ret = ioctl(dev->fd,USBDEVFS_SETINTERFACE,&setintf);

	return(ret);

}

/*
* Function     : pusb_endpoint_open
* Return value : NULL on error, a valid ep on success
* Description  : see function name
*/
pusb_endpoint_t pusb_endpoint_open(pusb_device_t dev, int epnum, int flags)
{

	pusb_endpoint_t ep;

	if ((ep = (pusb_endpoint_t) malloc(sizeof(*ep))) == NULL)
		return(NULL);

	ep->fd = dev->fd;
	ep->ep = epnum & 0xf;

	return(ep);

}

/*
* Function     : pusb_endpoint_rw_no_timeout
* Return value : ioctl returned value
* Description  : Writes or Read from an usb end point (without timeout value)
*/
int pusb_endpoint_rw_no_timeout(int fd,
				int ep,
				const unsigned char *buf,
				int size)
{

	struct usbdevfs_urb urb, * purb;
	int ret;

	memset(&urb,0,sizeof(urb));

	urb.type          = USBDEVFS_URB_TYPE_BULK;
	urb.endpoint      = ep;
	urb.flags         = 0;
	urb.buffer        = (unsigned char*)buf;
	urb.buffer_length = size;
	urb.signr         = 0;

	do {
		ret = ioctl(fd,USBDEVFS_SUBMITURB,&urb);
	} while(ret < 0 && errno == EINTR);

	if (ret < 0)
		return(ret);

	do {
		ret = ioctl(fd,USBDEVFS_REAPURB,&purb);
	} while(ret < 0 && errno == EINTR);

	if(ret < 0)
		return(ret);

/*
	if(purb != &urb)
		fprintf(stderr, "purb=%p, &urb=%p\n",purb,&urb);

	if(purb->buffer != buf)
		fprintf(stderr, "purb->buffer=%p, buf=%p\n",purb->buffer,buf);
*/

	return (purb->status < 0) ? purb->status : purb->actual_length;

}

/*
* Function     : pusb_endpoint_rw
* Return value : ioctl returned value
* Description  : Writes or Read from an usb end point (with timeout value)
*/
int pusb_endpoint_rw(
			int fd,
			int ep,
			const unsigned char * buf,
			int size,
			int timeout)
{

	struct usbdevfs_bulktransfer bulk;
	int ret, received = 0;

	do {

		bulk.ep      = ep;
		bulk.len     = (size > pagesize)? pagesize: size;
		bulk.timeout = timeout;
		bulk.data    = (unsigned char*)buf;

		do {
			ret = ioctl(fd,USBDEVFS_BULK,&bulk);
		} while (ret < 0 && errno == EINTR);

		if (ret < 0)
			return(ret);
		
		buf      += ret;
		size     -= ret;
		received += ret;

	} while(ret==bulk.len && size>0);
	
	return(received);
}

/*
* Function     : pusb_endpoint_write
* Return value : same as pusb_endpoint_rw
* Description  : wrapper to the pusb_endpoint_rw
*/
int pusb_endpoint_write(pusb_endpoint_t ep, 
			const unsigned char *buf,
			int size,
			int timeout)
{

	if(timeout == 0)
		return pusb_endpoint_rw_no_timeout(ep->fd,ep->ep|USB_DIR_OUT,buf,size);

	return(pusb_endpoint_rw(ep->fd,ep->ep|USB_DIR_OUT,buf,size,timeout));

}

/*
* Function     : pusb_endpoint_read
* Return value : same as pusb_endpoint_rw
* Description  : wrapper to the pusb_endpoint_rw
*/
int pusb_endpoint_read(	pusb_endpoint_t ep, 
			unsigned char *buf,
			int size,
			int timeout)
{

	if(timeout == 0)
		return(pusb_endpoint_rw_no_timeout(ep->fd,ep->ep|USB_DIR_IN,buf,size));

	return(pusb_endpoint_rw(ep->fd,ep->ep|USB_DIR_IN,buf,size,timeout));

}

/*
* Function     : pusb_endpoint_close
* Return value : 0
* Description  : Close the end pont given in parameter
*/
int pusb_endpoint_close(pusb_endpoint_t ep)
{
	/* nothing to do on the struct content */
	free(ep);

	return(0);

}

/*
* Function     : pusb_claim_interface
* Return value : ioctl returned value
* Description  : Claims an interface for use
*/
int pusb_claim_interface(pusb_device_t dev, int interface)
{

	return(ioctl(dev->fd, USBDEVFS_CLAIMINTERFACE,&interface));

}

/*
* Function     : pusb_release_interface
* Return value : ioctl returned value
* Description  : Release the usb interface
*/
int pusb_release_interface(pusb_device_t dev, int interface)
{

	return(ioctl(dev->fd,USBDEVFS_RELEASEINTERFACE,&interface));

}
 
int pusb_ioctl (pusb_device_t dev,int interface,int code,void *data)
{
	struct usbdevfs_ioctl ctrl;

	ctrl.ifno = interface;
	ctrl.ioctl_code = code;
	ctrl.data = data;

	return(ioctl(dev->fd,USBDEVFS_IOCTL,&ctrl));
}

/*****************************************************************************
*	Local functions
*****************************************************************************/

/*
* Function     : test_file
* Return value : -1 on error, a valid filedescriptor on success
* Description  : Try to open the file and get USB device information,
*                if it's ok, check if it matches vendorID & productID
*/
static int test_file(const char *path, int vendorID, int productID)
{

	int fd;
	struct usb_device_descriptor desc;
	
	if((fd = open(path, O_RDWR)) == -1) {
		perror(path);
		return(-1);
	}
  
	if(read(fd,&desc,sizeof(desc)) == sizeof(desc))  {

		/*
		* Great, we read something
		* check, it match the correct structure
		*/
		if(desc.bLength == sizeof(desc)) {

			/*	  
			  fprintf(stderr, "=== %s ===\n",path);
			  fprintf(stderr, "  bLength         = %u\n",desc.bLength);
			  fprintf(stderr, "  bDescriptorType = %u\n",desc.bDescriptorType);
			  fprintf(stderr, "  bcdUSB          = %04x\n",desc.bcdUSB);
			  fprintf(stderr, "  idVendor        = %04x\n",desc.idVendor);
			  fprintf(stderr, "  idProduct       = %04x\n",desc.idProduct);
			  fprintf(stderr, "  bcdDevice       = %04x\n",desc.bcdDevice);
			*/
			if(	vendorID == desc.idVendor &&
				productID == desc.idProduct)
				return(fd);
		}

	}
	
	close(fd);

	return(-1);

}

/*
* Function     : usbfs_search
* Return value : -1 on error, a valid filedescriptor on success
* Description  : Search for a vendorID, productID.
*/
static int usbfs_search(const char *path, int vendorID, int productID)
{

	int result = -1;
	
	DIR * dir;
	struct dirent * dirp;
	
	if((dir = opendir(path)) == NULL) {
		perror(path);
		return(-1);
	}
	
	while((dirp=readdir(dir)) != NULL) {

		struct stat statbuf;
		char file[PATH_MAX+1];
		
		if (strlen(dirp->d_name) != 3)
			continue;

		if (!isdigit(dirp->d_name[0]) ||
		    !isdigit(dirp->d_name[1]) ||
		    !isdigit(dirp->d_name[2]))
			continue;

		sprintf(file,"%s/%s",path,dirp->d_name);
		
		if (stat(file,&statbuf) != 0) {
			perror(file);
			continue;
		}
		
		if (S_ISDIR(statbuf.st_mode)) {

			if((result = usbfs_search(file,vendorID,productID)) < 0)
				continue;
			else
				break;
		}
		
		if (S_ISREG(statbuf.st_mode)) {

			if ((result=test_file(file,vendorID,productID)) < 0)
				continue;
			else
				break;
		}

	}
	
	closedir(dir);

	return(result);

}

/*
* Function     : make_device
* Return value : NULL on error, a valid pusb_device_t
* Description  : Allocates a pusb_device_t data structure
*/
static pusb_device_t make_device(int fd)
{

	pusb_device_t dev;

	if((dev = malloc(sizeof(*dev))) == NULL) {
		close (fd);
		return(NULL);
	}
	
	dev->fd = fd;

	/* A bit hacky, but find the page size here so the lib knows about it,
	 * before writing operations are performed */
	pagesize = sysconf(_SC_PAGESIZE);

	return(dev);

}

#endif /* _PUSB_LINUX_C_ */
