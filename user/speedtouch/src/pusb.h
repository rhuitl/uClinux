/*
*  ALCATEL SpeedTouch USB : Portable USB user library
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
* $Id: pusb.h,v 1.5 2004/02/15 21:25:07 edgomez Exp $
*/

#ifndef PUSB_H
#define PUSB_H

/* Simple portable USB interface */

typedef struct pusb_device_t *pusb_device_t;
typedef struct pusb_endpoint_t *pusb_endpoint_t;

pusb_device_t pusb_search_open(int vendorID, int productID);
pusb_device_t pusb_open(const char *path);
int pusb_close(pusb_device_t dev);

int pusb_get_revision(pusb_device_t dev);
int pusb_control_msg(pusb_device_t dev,
		     int request_type, int request,
		     int value, int index, 
		     unsigned char *buf, int size, int timeout);
int pusb_set_configuration(pusb_device_t dev, int config);
int pusb_set_interface(pusb_device_t dev, int interface, int alternate);

int pusb_claim_interface(pusb_device_t dev,int interface);
int pusb_release_interface(pusb_device_t dev,int interface);

int pusb_ioctl (pusb_device_t dev,int interface,int code,void *data);

pusb_endpoint_t pusb_endpoint_open(pusb_device_t dev, int epnum, int flags);
int pusb_endpoint_read(pusb_endpoint_t ep, 
		       unsigned char *buf, int size, int timeout);
int pusb_endpoint_write(pusb_endpoint_t ep, 
			const unsigned char *buf, int size, int timeout);
int pusb_endpoint_close(pusb_endpoint_t ep);

#endif
