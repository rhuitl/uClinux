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
 * File:		cbi.h
 * Purpose:		USB Class Control Bulk Interrupt definitions
 */

#ifndef CBI_H
#define CBI_H

#include "usb.h"

/***********************************************************************/

/* Length of Command Buffer */
#define COMMAND_BUFFER_LENGTH		262

#define FILE_NAME_LENGTH		256

/* Command set of usb audio demonstration program */
#define USB_AUDIO_START			0x20
#define USB_AUDIO_STOP			0x21
#define USB_AUDIO_SET_VOLUME		0x22

#define START_TEST_OUT_TRANSFER		0x01
#define START_TEST_IN_TRANSFER		0x02
#define START_TEST_INOUT_TRANSFER	0x03

/* USB CBI Class Endpoint numbers */
#define CONTROL_IN			0x00
#define CONTROL_OUT			0x00
#define BULK_IN				0x01
#define BULK_OUT			0x02
#define INTERRUPT			0x03

/* Interface Classes */
#define MASS_STORAGE_INTERFACE		0x08

/* CBI Interface Subclasses */
#define NO_SUBCLASS			0x00
#define VENDOR_SPECIFIC			0xFF

/* CBI Interface Protocol Codes */
#define NONE				0x00
#define CBI_TRANSFER_PROTOCOL		0x00

/* String descriptors definitions */
#define NUM_STRING_DESC			4
#define NUM_LANGUAGES			2
typedef STR_DESC USB_STRING_DESC [NUM_STRING_DESC * NUM_LANGUAGES + 1];

/********************************************************************/

#endif /* CBI_H */
