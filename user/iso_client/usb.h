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
 * File:		usb.h
 * Purpose:		USB Header File
. Defines the interface of driver.
 *			
 */

#ifndef USB_H
#define USB_H

/***********************************************************************/
#ifndef _CPU_MCF5272_H
typedef unsigned char		uint8;  /*  8 bits */
typedef unsigned short int	uint16; /* 16 bits */
typedef unsigned long int	uint32; /* 32 bits */
#endif

#ifdef	FALSE
#undef	FALSE
#endif
#define FALSE	(0)

#ifdef	TRUE
#undef	TRUE
#endif
#define	TRUE	(1)

#ifdef	NULL
#undef	NULL
#endif
#define NULL	(0)

/***********************************************************************/
/* The major device number. We can't rely on dynamic
 * registration, because we need to know major number. */
#define MAJOR_NUM 127

/* We use MAJOR_NUM as magic number */
/* Initialize USB driver */
#define USB_INIT _IOW(MAJOR_NUM, 0, char *)

/* Get last command */
#define USB_GET_COMMAND _IOR(MAJOR_NUM, 1, char *)

/* Check if endpoint is busy */
#define USB_EP_BUSY _IO(MAJOR_NUM, 2)

/* Wait while endpoint is busy */
#define USB_EP_WAIT _IOW(MAJOR_NUM, 3, uint32)

/* Get current configuration number */
#define USB_GET_CURRENT_CONFIG _IOR(MAJOR_NUM, 4, uint32)

/* Accept command (send CMD_OVER to Host) */
#define USB_COMMAND_ACCEPTED _IO(MAJOR_NUM, 5)

/* Set NOT_SUPPORTED_COMMAND status (send CMD_OVER
and CMD_ERROR to Host) */
#define USB_NOT_SUPPORTED_COMMAND _IO(MAJOR_NUM, 6)

/* Set sendZLP flag to TRUE */
#define USB_SET_SEND_ZLP _IO(MAJOR_NUM, 7)

/* Set start frame number for ISO transfer */
#define USB_SET_START_FRAME _IOW(MAJOR_NUM, 8, uint32)

/* Set final frame number for ISO transfer */
#define USB_SET_FINAL_FRAME _IOW(MAJOR_NUM, 9, uint32)

/* Get current frame number */
#define USB_GET_FRAME_NUMBER _IO(MAJOR_NUM, 10)

/* STALL given endpoint */
#define USB_EP_STALL _IO(MAJOR_NUM, 12)
/********************************************************************/

/* The names of the device files */
#define USB_EP0_FILE_NAME "/dev/usb0"
#define USB_EP1_FILE_NAME "/dev/usb1"
#define USB_EP2_FILE_NAME "/dev/usb2"
#define USB_EP3_FILE_NAME "/dev/usb3"
#define USB_EP4_FILE_NAME "/dev/usb4"
#define USB_EP5_FILE_NAME "/dev/usb5"
#define USB_EP6_FILE_NAME "/dev/usb6"
#define USB_EP7_FILE_NAME "/dev/usb7"

/* The name of the device */
#define DEVICE_NAME "usb"

/* Total number of EPs in this USB core */
#define NUM_ENDPOINTS		8

/* Definitions for Device Config Change events */
#define USB_NO_NEW_COMMAND	0
#define USB_CONFIGURATION_CHG	1
#define USB_INTERFACE_CHG	2
#define USB_ADDRESS_CHG		4
#define USB_DEVICE_RESET	8
#define USB_NEW_COMMAND		16

/* Definitions for Bus State Change events */
#define SUSPEND             	1 
#define RESUME              	2
#define ENABLE_WAKEUP      	4
#define RESET               	8

/* Definition for Device states */
#define USB_CONFIGURED          0
#define USB_NOT_CONFIGURED      2

#define USB_EP_IS_FREE		0
#define USB_EP_IS_BUSY		1

/* Status definitions. These constants driver uses to report status, raised during a transfer,
    to client application */
#define SUCCESS			0
#define MALLOC_ERROR		2
#define NOT_SUPPORTED_COMMAND	4

/********************************************************************/
/* Structure contains current configuration and alt setting number */
typedef struct {
	uint32 cur_config_num;
	uint32 altsetting;
} CONFIG_STATUS;

/* Structure for Request */
typedef struct {
	uint8 bmRequestType;
	uint8 bRequest;
	uint16 wValue;
	uint16 wIndex;
	uint16 wLength;
} REQUEST;

/* Structure for Command */
typedef struct COMMAND_QUEUE_ITEM{
	uint8 * cbuffer;							/* Pointer to command buffer */
 	REQUEST request;			/* Request from Host*/
	struct COMMAND_QUEUE_ITEM * NextC;	/* Pointer to the next comand in the Queue */
} QUEUE_ITEM;

/* Structure for Command Buffer for Client*/
typedef struct {
	uint8 * cbuffer;							/* Pointer to command buffer */
 	REQUEST request;			/* Request from Host*/
} DEVICE_COMMAND;

/********************************************************************/
typedef struct{
        uint8 * pDescriptor;
        uint32 DescSize;
        uint8 * pStrDescriptor;
} DESC_INFO;

/********************************************************************/

#endif /* USB_H */
