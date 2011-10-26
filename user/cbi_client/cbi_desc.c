/*********************************************************************
 *
 * Copyright:
 *	MOTOROLA, INC. All Rights Reserved.  
 *  You are hereby granted a copyright license to use, modify, and
 *  distribute the SOFTWARE so long as this entire notice is
 *  retained without alteration in any modified and/or redistributed
 *  versions, and that such modified versions are clearly identified
 *  as such. No licenses are granted by implication, estoppel or
 *  otherwise under any patents or trademarks of Motorola, Inc. This 
 *  software is provided on an "AS IS" basis and without warranty.
 *
 *  To the maximum extent permitted by applicable law, MOTOROLA 
 *  DISCLAIMS ALL WARRANTIES WHETHER EXPRESS OR IMPLIED, INCLUDING 
 *  IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR
 *  PURPOSE AND ANY WARRANTY AGAINST INFRINGEMENT WITH REGARD TO THE 
 *  SOFTWARE (INCLUDING ANY MODIFIED VERSIONS THEREOF) AND ANY 
 *  ACCOMPANYING WRITTEN MATERIALS.
 * 
 *  To the maximum extent permitted by applicable law, IN NO EVENT
 *  SHALL MOTOROLA BE LIABLE FOR ANY DAMAGES WHATSOEVER (INCLUDING 
 *  WITHOUT LIMITATION, DAMAGES FOR LOSS OF BUSINESS PROFITS, BUSINESS 
 *  INTERRUPTION, LOSS OF BUSINESS INFORMATION, OR OTHER PECUNIARY
 *  LOSS) ARISING OF THE USE OR INABILITY TO USE THE SOFTWARE.   
 * 
 *  Motorola assumes no responsibility for the maintenance and support
 *  of this software
 ********************************************************************/

/*
 * File:	cbi_desc.c
 * Purpose:	Descriptors for CBI
 */

#include "descriptors.h"
#include "cbi.h"

/********************************************************************/

/* Structure for CBI Interface Type */
typedef struct {
	USB_DEVICE_DESC device_desc;
	USB_CONFIG_DESC config_desc;
	USB_INTERFACE_DESC interface_desc;
	USB_ENDPOINT_DESC bulk_in_desc;
	USB_ENDPOINT_DESC bulk_out_desc;
	USB_ENDPOINT_DESC interrupt_desc;
} DESCRIPTOR_STRUCT;

/* String descriptors */
USB_STRING_DESC string_desc = { 
        {6, STRING, 0x09, 0x04, 0x07, 0x04},
        {18, STRING, 'M',0,'o',0,'t',0,'o',0,'r',0,'o',0,'l',0,'a',0},
        {54, STRING, 'M',0,'C',0,'F',0,'5',0,'2',0,'7',0,'2',0,' ',0,'C',0,'o',0,'l',0,'d',0,'F',0,'i',0,'r',0,'e',0,' ',0,'P',0,'r',0,'o',0,'c',0,'e',0,'s',0,'s',0,'o',0,'r',0},
        {26, STRING, 'S',0,'e',0,'l',0,'f',0,'-',0,'p',0,'o',0,'w',0,'e',0,'r',0,'e',0,'d',0},
        {78, STRING, 'C',0,'o',0,'n',0,'t',0,'r',0,'o',0,'l',0,'/',0,'B',0,'u',0,'l',0,'k',0,'/',0,'I',0,'n',0,'t',0,'e',0,'r',0,'r',0,'u',0,'p',0,'t',0,' ',0,'(',0,'C',0,'B',0,'I',0,')',0,' ',0,'T',0,'r',0,'a',0,'n',0,'s',0,'p',0,'o',0,'r',0,'t',0},
        {18, STRING, 'M',0,'o',0,'t',0,'o',0,'r',0,'o',0,'l',0,'a',0},
        {54, STRING, 'M',0,'C',0,'F',0,'5',0,'2',0,'7',0,'2',0,' ',0,'C',0,'o',0,'l',0,'d',0,'F',0,'i',0,'r',0,'e',0,' ',0,'P',0,'r',0,'o',0,'c',0,'e',0,'s',0,'s',0,'o',0,'r',0},
        {26, STRING, 'S',0,'e',0,'l',0,'f',0,'-',0,'p',0,'o',0,'w',0,'e',0,'r',0,'e',0,'d',0},
        {78, STRING, 'C',0,'o',0,'n',0,'t',0,'r',0,'o',0,'l',0,'/',0,'B',0,'u',0,'l',0,'k',0,'/',0,'I',0,'n',0,'t',0,'e',0,'r',0,'r',0,'u',0,'p',0,'t',0,' ',0,'(',0,'C',0,'B',0,'I',0,')',0,' ',0,'T',0,'r',0,'a',0,'n',0,'s',0,'p',0,'o',0,'r',0,'t',0},
};

/********************************************************************/

/* Initialize the CBI descriptors */
DESCRIPTOR_STRUCT Descriptors =
{
	/* Device Descriptor */
	{
	/* bLength */			sizeof(USB_DEVICE_DESC),
	/* bDescriptorType */		DEVICE,
	/* bcdUSBL */			0x10,
	/* bcdUSBH */			0x01,		/* USB 1.10 */
	/* bDeviceClass */		0,
	/* bDeviceSubClass */		0,
	/* bDeviceProtocol */		0,
	/* bMaxPacketSize0 */		8,
	/* idVendorL */			0xCD,
	/* idVendorH */			0xAB,		/* arbitrary */
	/* idProductL */		0x35,
	/* idProductH */		0x12,		/* arbitrary */
	/* bcdDeviceL */		0,
	/* bcdDeviceH */		1,		/* arbitrary */
	/* iManufacturern */		1,
	/* iProduct */			2,
	/* iSerialNumber */		0,
	/* bNumConfigurations */	1,
	},

	/* Configuration Descriptor */
	{
	/* bLength */			sizeof(USB_CONFIG_DESC),
	/* bDescriptorType */		CONFIGURATION,
	/* wTotalLengthL */		(sizeof(DESCRIPTOR_STRUCT) - sizeof(USB_DEVICE_DESC)) & 0x00FF,
	/* wTotalLengthH */		(sizeof(DESCRIPTOR_STRUCT) - sizeof(USB_DEVICE_DESC)) >> 8,
	/* bNumInterfaces */		1,
	/* bConfigurationValue */	1,	/* This is configuration #1 */
	/* iConfiguration */		3,
	/* bmAttributes */		SELF_POWERED, 
	/* maxPower */			0,
	},

	/* Interface Descriptor */
	{
	/* bLength */			sizeof(USB_INTERFACE_DESC),
	/* bDescriptorType */		INTERFACE,
	/* bInterfaceNumber */		0,		/* This is interface #0 */
	/* bAlternateSetting */		0,
	/* bNumEndpoints */		3,
	/* bInterfaceClass */		MASS_STORAGE_INTERFACE,
	/* bInterfaceSubClass */	VENDOR_SPECIFIC,
	/* bInterfaceProtocol */	CBI_TRANSFER_PROTOCOL,
	/* iInterface */		4,
	},

	
	/* Endpoint BULK_IN Descriptor */
	{
	/* bLength */			sizeof(USB_ENDPOINT_DESC),
	/* bDescriptorType */		ENDPOINT,
	/* bEndpointAddress */		(1 | IN),	/* This is endpoint #1 */
	/* bmAttributes */		BULK,
	/* wMaxPacketSizeL */		0x40,		/* 64 */
	/* wMaxPacketSizeH */		0x00,
	/* bInterval */			0,	
	},

	/* Endpoint BULK_OUT Descriptor */
	{
	/* bLength */			sizeof(USB_ENDPOINT_DESC),
	/* bDescriptorType */		ENDPOINT,
	/* bEndpointAddress */		(2 | OUT),	/* This is endpoint #2 */
	/* bmAttributes */		BULK,
	/* wMaxPacketSizeL */		0x40,		/*64 */
	/* wMaxPacketSizeH */		0x00,
	/* bInterval */			0,
	},

	/* Endpoint Interrupt Descriptor */
	{
	/* bLength */			sizeof(USB_ENDPOINT_DESC),
	/* bDescriptorType */		ENDPOINT,
	/* bEndpointAddress */		(3 | IN),	/* This is endpoint #3 */
	/* bmAttributes */		INTERRUPT,
	/* wMaxPacketSizeL */		0x02,
	/* wMaxPacketSizeH */		0x00,
	/* bInterval */			1,		/* 10 ms */
	}
};

/********************************************************************/
unsigned short int
usb_get_desc_size(void)
{
	return (sizeof(DESCRIPTOR_STRUCT));
}
