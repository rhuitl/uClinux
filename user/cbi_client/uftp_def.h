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
 * File:		uftp_def.h
 * Purpose:	USB File transfer definitions
 */

#ifndef UFTP_DEF_H
#define UFTP_DEF_H

/********************************************************************/
/* UFTP command set  */
#define UFTP_READ				0x01
#define UFTP_WRITE				0x02
#define UFTP_GET_FILE_INFO			0x03
#define UFTP_GET_DIR				0x04
# define UFTP_SET_TRANSFER_LENGTH		0x05
#define UFTP_DELETE				0x06

/* UFTP status codes */
#define UFTP_SUCCESS				0x0000
#define UFTP_FILE_DOES_NOT_EXIST		0x0011
#define UFTP_MEMORY_ALLOCATION_FAIL		0x0021
#define UFTP_NO_POSITION_FOR_NEW_FILE		0x0031
#define UFTP_NOT_ENOUGH_SPACE_FOR_FILE		0x0041

#endif /* UFTP_DEF_H
 */
