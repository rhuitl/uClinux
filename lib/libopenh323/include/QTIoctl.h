/*
	QTIoctl.h

	Copyright (c) 1996-1999, Quicknet Technologies, Inc.
	All Rights Reserved.

	DeviceIoControl codes for Internet PhoneJACK, LineJACK, etc. drivers.

	-----------------------------------------------------------------

	$Header: /cvsroot/openh323/openh323/include/QTIoctl.h,v 1.5 2001/09/20 23:58:40 robertj Exp $
*/

#ifndef _QTIOCTL_H_
#define _QTIOCTL_H_

//
// The following #defines come from <winioctl.h>.
//

//
//- Beginning of included from <winioctl.h> section ------------------------------
//
// Macro definition for defining IOCTL and FSCTL function control codes.  Note
// that function codes 0-2047 are reserved for Microsoft Corporation, and
// 2048-4095 are reserved for customers.
//
#undef CTL_CODE
#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DWORD)(DeviceType) << 16) | ((DWORD)(Access) << 14) | ((DWORD)(Function) << 2) | (DWORD)(Method) \
)

//
// Define the method codes for how buffers are passed for I/O and FS controls
//

#define METHOD_BUFFERED                 0
#define METHOD_IN_DIRECT                1
#define METHOD_OUT_DIRECT               2
#define METHOD_NEITHER                  3

//
// Define the access check value for any access
//
//
// The FILE_READ_ACCESS and FILE_WRITE_ACCESS constants are also defined in
// ntioapi.h as FILE_READ_DATA and FILE_WRITE_DATA. The values for these
// constants *MUST* always be in sync.
//


#define FILE_ANY_ACCESS                 0
#define FILE_READ_ACCESS          ( 0x0001 )    // file & pipe
#define FILE_WRITE_ACCESS         ( 0x0002 )    // file & pipe

//
//- End of included from <winioctl.h> section ------------------------------
//

#define FILE_READ_WRITE_ACCESS (FILE_WRITE_ACCESS|FILE_READ_ACCESS)
#define ARG_DWORD	0x400
#define ARG_VOID	0

#define MASK_DWORD		( ARG_DWORD << 2 )
#define MASK_VOID		( ARG_VOID << 2 )
#define MASK_WRITE		( FILE_WRITE_ACCESS << 14 )
#define MASK_READ		( FILE_READ_ACCESS << 14 )
#define MASK_READ_WRITE	( FILE_READ_WRITE_ACCESS << 14 )

#define IoctlTransferType( Code )	(Code & 3)
#define IoctlDeviceType( Code )		((Code >> 16) & 0xffff)
#define IoctlRequiredAccess( Code )	((Code & 0xc000)>>14)
#define IoctlControlCode( Code )	((Code >> 2) & 0x03ff)
#define IoctlFunctionCode( Code )	((Code >> 2) & 0x0bff)
#define IoctlIsVoidArg( Code )		((Code & MASK_DWORD) == MASK_VOID)
#define IoctlIsRead( Code )			((Code & MASK_READ) == MASK_READ)
#define IoctlIsWrite( Code )		((Code & MASK_WRITE) == MASK_WRITE)
#define IoctlIsReadWrite( Code )	((Code & MASK_READ_WRITE) == MASK_READ_WRITE)
#define IoctlHasArgument( Code )	((Code & (MASK_WRITE|MASK_DWORD))== (MASK_WRITE|MASK_DWORD))
#define IoctlHasBuffer( Code )		((Code & MASK_READ_WRITE) != 0)

#ifndef LPVOID
#ifndef FAR
#define FAR
#endif
    typedef void FAR * LPVOID;
#endif

#ifndef DEVNODE
#define DEVNODE DWORD
#endif

/////////////////////////////////////////////////////////////////////////////////////////////////////////
// Win32 device operations

#define FILE_DEVICE_DEVICE 0x8009
#define DEVICE_CODE( fn, Access, ArgSize ) CTL_CODE( FILE_DEVICE_DEVICE, (0x800 + ArgSize + fn ), METHOD_BUFFERED, Access )

// Function codes
#define IOCTL_Device_Open DEVICE_CODE( 0, FILE_WRITE_ACCESS, ARG_DWORD) // (ARG_DWORD dwSerialNo)
#define IOCTL_Device_Close DEVICE_CODE( 1, FILE_WRITE_ACCESS, ARG_VOID) // (void)
#define IOCTL_Device_Read DEVICE_CODE( 2, FILE_WRITE_ACCESS, ARG_VOID) // (void)
#define IOCTL_Device_Write DEVICE_CODE( 3, FILE_WRITE_ACCESS, ARG_VOID) // (void)
#define IOCTL_Device_CancelIO DEVICE_CODE( 6, FILE_WRITE_ACCESS, ARG_VOID) // (void)
#define IOCTL_Device_GetSerialNumber DEVICE_CODE( 7, FILE_READ_ACCESS, ARG_VOID) // void
#define IOCTL_Device_GetG729Enable DEVICE_CODE( 8, FILE_READ_ACCESS, ARG_VOID) // void
#define IOCTL_Device_SetG729Enable DEVICE_CODE( 9, FILE_WRITE_ACCESS, ARG_DWORD) // (void)

//==========================================================================
//==========================================================================
//
//	IOCTL and function codes for Quicknet's Internet PhoneJACK and
//	Internet LineJACK cards.
//
//==========================================================================
//--------------------------------------------------------------------------
//	Codec support
//--------------------------------------------------------------------------
//
#define FILE_DEVICE_CODEC		0x8002

#define CODEC_IOCTL_CODE( fn, Access, ArgSize ) CTL_CODE( FILE_DEVICE_CODEC, (0x800 + ArgSize + fn ), METHOD_BUFFERED, Access )

#define IOCTL_Codec_SetSetRate		CODEC_IOCTL_CODE( 0, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wSetRate)
#define IOCTL_Codec_GetSetRate		CODEC_IOCTL_CODE( 1, FILE_READ_ACCESS, ARG_VOID)		// (void)
#define IOCTL_Codec_SetINPUT_CODEC	CODEC_IOCTL_CODE( 2, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wData)
#define IOCTL_Codec_GetINPUT_CODEC	CODEC_IOCTL_CODE( 3, FILE_READ_ACCESS, ARG_VOID)		// (void)
#define IOCTL_Codec_SetOUTPUT_CODEC	CODEC_IOCTL_CODE( 4, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wData)
#define IOCTL_Codec_GetOUTPUT_CODEC	CODEC_IOCTL_CODE( 5, FILE_READ_ACCESS, ARG_VOID)		// (void)
#define IOCTL_Codec_SetLong			CODEC_IOCTL_CODE( 6, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wData)
#define IOCTL_Codec_GetLong			CODEC_IOCTL_CODE( 7, FILE_READ_ACCESS, ARG_VOID)		// (void)
#define IOCTL_Codec_SetMaster		CODEC_IOCTL_CODE( 8, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wData)
#define IOCTL_Codec_GetMaster		CODEC_IOCTL_CODE( 9, FILE_READ_ACCESS, ARG_VOID)		// (void)
#define IOCTL_Codec_SetLaw			CODEC_IOCTL_CODE( 10, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wData)
#define IOCTL_Codec_GetLaw			CODEC_IOCTL_CODE( 11, FILE_READ_ACCESS, ARG_VOID)		// (void)
#define IOCTL_Codec_SetWidth		CODEC_IOCTL_CODE( 12, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wData)
#define IOCTL_Codec_GetWidth		CODEC_IOCTL_CODE( 13, FILE_READ_ACCESS, ARG_VOID)		// (void)
#define IOCTL_Codec_SetCO_RATE		CODEC_IOCTL_CODE( 14, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wData)
#define IOCTL_Codec_GetCO_RATE		CODEC_IOCTL_CODE( 15, FILE_READ_ACCESS, ARG_VOID)		// (void)
#define IOCTL_Codec_SetFSYNC_RATE	CODEC_IOCTL_CODE( 16, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wData)
#define IOCTL_Codec_GetFSYNC_RATE	CODEC_IOCTL_CODE( 17, FILE_READ_ACCESS, ARG_VOID)		// (void)
#define IOCTL_Codec_SetWIDE			CODEC_IOCTL_CODE( 18, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wData)
#define IOCTL_Codec_GetWIDE			CODEC_IOCTL_CODE( 19, FILE_READ_ACCESS, ARG_VOID)		// (void)
#define IOCTL_Codec_Loopback		CODEC_IOCTL_CODE( 20, FILE_READ_ACCESS, ARG_VOID)		// (void)
#define IOCTL_Codec_SetKHz			CODEC_IOCTL_CODE( 23, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wData)
#define IOCTL_Codec_GetKHz			CODEC_IOCTL_CODE( 24, FILE_READ_ACCESS, ARG_VOID)		// (void)
#define IOCTL_Codec_SetLegacyKHz	CODEC_IOCTL_CODE( 25, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wData)
#define IOCTL_Codec_GetLegacyKHz	CODEC_IOCTL_CODE( 26, FILE_READ_ACCESS, ARG_VOID)		// (void)
#define IOCTL_Codec_SetChannels		CODEC_IOCTL_CODE( 27, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wData)
#define IOCTL_Codec_GetChannels		CODEC_IOCTL_CODE( 28, FILE_READ_ACCESS, ARG_VOID)		// (void)

#define fnCodec_SetSetRate			IOCTL_Codec_SetSetRate 
#define fnCodec_GetSetRate			IOCTL_Codec_GetSetRate 
#define fnCodec_SetINPUT_CODEC		IOCTL_Codec_SetINPUT_CODEC 
#define fnCodec_GetINPUT_CODEC		IOCTL_Codec_GetINPUT_CODEC 
#define fnCodec_SetOUTPUT_CODEC		IOCTL_Codec_SetOUTPUT_CODEC 
#define fnCodec_GetOUTPUT_CODEC		IOCTL_Codec_GetOUTPUT_CODEC 
#define fnCodec_SetLong				IOCTL_Codec_SetLong 
#define fnCodec_GetLong				IOCTL_Codec_GetLong 
#define fnCodec_SetMaster			IOCTL_Codec_SetMaster 
#define fnCodec_GetMaster			IOCTL_Codec_GetMaster 
#define fnCodec_SetLaw				IOCTL_Codec_SetLaw 
#define fnCodec_GetLaw				IOCTL_Codec_GetLaw 
#define fnCodec_SetWidth			IOCTL_Codec_SetWidth 
#define fnCodec_GetWidth			IOCTL_Codec_GetWidth 
#define fnCodec_SetCO_RATE			IOCTL_Codec_SetCO_RATE 
#define fnCodec_GetCO_RATE			IOCTL_Codec_GetCO_RATE 
#define fnCodec_SetFSYNC_RATE		IOCTL_Codec_SetFSYNC_RATE 
#define fnCodec_GetFSYNC_RATE		IOCTL_Codec_GetFSYNC_RATE 
#define fnCodec_SetWIDE				IOCTL_Codec_SetWIDE 
#define fnCodec_GetWIDE				IOCTL_Codec_GetWIDE 
#define fnCodec_Loopback			IOCTL_Codec_Loopback 
#define fnCodec_SetKHz				IOCTL_Codec_SetKHz 
#define fnCodec_GetKHz				IOCTL_Codec_GetKHz 
#define fnCodec_SetLegacyKHz		IOCTL_Codec_SetLegacyKHz	
#define fnCodec_GetLegacyKHz		IOCTL_Codec_GetLegacyKHz	
#define fnCodec_SetChannels			IOCTL_Codec_SetChannels 
#define fnCodec_GetChannels			IOCTL_Codec_GetChannels 

//==========================================================================
//--------------------------------------------------------------------------
//	Compression/Decompression support
//--------------------------------------------------------------------------
//
#define FILE_DEVICE_COMPRESS 0x8008

#define COMPRESS_IOCTL_CODE( fn, Access, ArgSize ) CTL_CODE( FILE_DEVICE_COMPRESS, (0x800 + ArgSize + fn ), METHOD_BUFFERED, Access )

#define IOCTL_Compress_Start		COMPRESS_IOCTL_CODE( 0, FILE_WRITE_ACCESS, ARG_VOID) // (void)
#define IOCTL_Compress_Continue		COMPRESS_IOCTL_CODE( 1, FILE_WRITE_ACCESS, ARG_VOID) // (void)
#define IOCTL_Compress_Stop			COMPRESS_IOCTL_CODE( 2, FILE_WRITE_ACCESS, ARG_VOID) // (void)
#define IOCTL_Compress_SetRate		COMPRESS_IOCTL_CODE( 3, FILE_WRITE_ACCESS, ARG_DWORD) // (WORD wNew)
#define IOCTL_Compress_GetRate		COMPRESS_IOCTL_CODE( 4, FILE_READ_ACCESS, ARG_VOID) // (void)
#define IOCTL_Compress_SetTFRMode	COMPRESS_IOCTL_CODE( 5, FILE_WRITE_ACCESS, ARG_DWORD) // (WORD wNew)
#define IOCTL_Compress_GetTFRMode	COMPRESS_IOCTL_CODE( 6, FILE_READ_ACCESS, ARG_VOID) // (void)
#define IOCTL_Decompress_Start		COMPRESS_IOCTL_CODE( 7, FILE_WRITE_ACCESS, ARG_VOID) // (void)
#define IOCTL_Decompress_Continue	COMPRESS_IOCTL_CODE( 8, FILE_WRITE_ACCESS, ARG_VOID) // (void)
#define IOCTL_Decompress_Stop		COMPRESS_IOCTL_CODE( 9, FILE_WRITE_ACCESS, ARG_VOID) // (void)
#define IOCTL_Decompress_SetRate	COMPRESS_IOCTL_CODE( 10, FILE_WRITE_ACCESS, ARG_VOID) // (ARG_DWORD wNew)
#define IOCTL_Decompress_GetRate	COMPRESS_IOCTL_CODE( 11, FILE_READ_ACCESS, ARG_VOID) // (void)
#define IOCTL_Decompress_SetTFRMode	COMPRESS_IOCTL_CODE( 12, FILE_WRITE_ACCESS, ARG_VOID) // (ARG_DWORD wNew)
#define IOCTL_Decompress_GetTFRMode	COMPRESS_IOCTL_CODE( 13, FILE_READ_ACCESS, ARG_VOID) // (void)

#define fnCompress_Start			IOCTL_Compress_Start 
#define fnCompress_Continue			IOCTL_Compress_Continue 
#define fnCompress_Stop				IOCTL_Compress_Stop 
#define fnCompress_SetRate			IOCTL_Compress_SetRate 
#define fnCompress_GetRate			IOCTL_Compress_GetRate 
#define fnCompress_SetTFRMode		IOCTL_Compress_SetTFRMode 
#define fnCompress_GetTFRMode		IOCTL_Compress_GetTFRMode 
#define fnDecompress_Start			IOCTL_Decompress_Start 
#define fnDecompress_Continue		IOCTL_Decompress_Continue 
#define fnDecompress_Stop			IOCTL_Decompress_Stop 
#define fnDecompress_SetRate		IOCTL_Decompress_SetRate 
#define fnDecompress_GetRate		IOCTL_Decompress_GetRate 
#define fnDecompress_SetTFRMode		IOCTL_Decompress_SetTFRMode 
#define fnDecompress_GetTFRMode		IOCTL_Decompress_GetTFRMode 

//==========================================================================
//--------------------------------------------------------------------------
//	Device support
//--------------------------------------------------------------------------
//
#define FILE_DEVICE_DEVCTRL 0x8007

#define DEVCTRL_IOCTL_CODE( fn, Access, ArgSize ) CTL_CODE( FILE_DEVICE_DEVCTRL, (0x800 + ArgSize + fn ), METHOD_BUFFERED, Access )

#define IOCTL_DevCtrl_CheckROM				DEVCTRL_IOCTL_CODE( 0, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_TestSRAM				DEVCTRL_IOCTL_CODE( 1, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_SRAM8Bit				DEVCTRL_IOCTL_CODE( 2, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_SRAM16Bit				DEVCTRL_IOCTL_CODE( 3, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_GetIdCode				DEVCTRL_IOCTL_CODE( 4, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_GetVersionCode		DEVCTRL_IOCTL_CODE( 5, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_TestCountMode			DEVCTRL_IOCTL_CODE( 6, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_TestDigitalMilliwatt	DEVCTRL_IOCTL_CODE( 7, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_TestLoopback			DEVCTRL_IOCTL_CODE( 8, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_TestExit				DEVCTRL_IOCTL_CODE( 9, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_Slowdown				DEVCTRL_IOCTL_CODE( 10, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD)
#define IOCTL_DevCtrl_GPIODirection			DEVCTRL_IOCTL_CODE( 11, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD)
#define IOCTL_DevCtrl_GPIOWrite				DEVCTRL_IOCTL_CODE( 12, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD)
#define IOCTL_DevCtrl_GPIORead				DEVCTRL_IOCTL_CODE( 13, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_EnableFR				DEVCTRL_IOCTL_CODE( 14, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_DisableFR				DEVCTRL_IOCTL_CODE( 15, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_ClearFR				DEVCTRL_IOCTL_CODE( 16, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_ReadFR				DEVCTRL_IOCTL_CODE( 17, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_SetAnalogSource		DEVCTRL_IOCTL_CODE( 18, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD)
#define IOCTL_DevCtrl_GetAnalogSource		DEVCTRL_IOCTL_CODE( 19, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_SetSLICState			DEVCTRL_IOCTL_CODE( 20, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD)
#define IOCTL_DevCtrl_GetSLICState			DEVCTRL_IOCTL_CODE( 21, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_ReadHookState			DEVCTRL_IOCTL_CODE( 22, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_GetOnHook				DEVCTRL_IOCTL_CODE( 23, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_SetRingPattern		DEVCTRL_IOCTL_CODE( 24, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD)
#define IOCTL_DevCtrl_SetLineJackMode		DEVCTRL_IOCTL_CODE( 25, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD)
#define IOCTL_DevCtrl_GetLineJackMode		DEVCTRL_IOCTL_CODE( 26, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_LineSetOnHook			DEVCTRL_IOCTL_CODE( 27, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD)
#define IOCTL_DevCtrl_LineGetRinging		DEVCTRL_IOCTL_CODE( 28, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_SetPotsToSlic			DEVCTRL_IOCTL_CODE( 29, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD)
#define IOCTL_DevCtrl_GetPotsToSlic			DEVCTRL_IOCTL_CODE( 30, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_GetLineOnHook			DEVCTRL_IOCTL_CODE( 31, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_GetLineCallerOnHook	DEVCTRL_IOCTL_CODE( 32, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_GetLinePhoneOnHook	DEVCTRL_IOCTL_CODE( 33, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_SetSpeaker			DEVCTRL_IOCTL_CODE( 34, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD)
#define IOCTL_DevCtrl_GetLineTestResult		DEVCTRL_IOCTL_CODE( 35, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_LineTest				DEVCTRL_IOCTL_CODE( 36, FILE_READ_WRITE_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_Wink					DEVCTRL_IOCTL_CODE( 37, FILE_READ_WRITE_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_Flash					DEVCTRL_IOCTL_CODE( 38, FILE_READ_WRITE_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_LineGetCallerID		DEVCTRL_IOCTL_CODE( 39, FILE_READ_ACCESS, ARG_VOID)	// char* returned in input buffer
#define IOCTL_DevCtrl_GetAttachedDevices	DEVCTRL_IOCTL_CODE( 40, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_GetFlashState			DEVCTRL_IOCTL_CODE( 41, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_GetCoefficientGroup	DEVCTRL_IOCTL_CODE( 42, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_DevCtrl_SetCoefficientGroup	DEVCTRL_IOCTL_CODE( 43, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (DWORD)
#define IOCTL_DevCtrl_GetPhoneType			DEVCTRL_IOCTL_CODE( 44, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (DWORD)
#define IOCTL_DevCtrl_SetPhoneType			DEVCTRL_IOCTL_CODE( 45, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (DWORD)
#define IOCTL_DevCtrl_SetRingCadence		DEVCTRL_IOCTL_CODE( 46, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (DWORD)
#define IOCTL_DevCtrl_SetWinkGenTime		DEVCTRL_IOCTL_CODE( 47, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (DWORD)
#define IOCTL_DevCtrl_GetWinkGenTime		DEVCTRL_IOCTL_CODE( 48, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (DWORD)
#define IOCTL_DevCtrl_SetFlashDetTime		DEVCTRL_IOCTL_CODE( 49, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (DWORD)
#define IOCTL_DevCtrl_GetFlashDetTime		DEVCTRL_IOCTL_CODE( 50, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (DWORD)
#define IOCTL_DevCtrl_SetLineFlashGenTime	DEVCTRL_IOCTL_CODE( 51, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (DWORD)
#define IOCTL_DevCtrl_GetLineFlashGenTime	DEVCTRL_IOCTL_CODE( 52, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (DWORD)
#define IOCTL_DevCtrl_SetLineWinkDetTime	DEVCTRL_IOCTL_CODE( 53, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (DWORD)
#define IOCTL_DevCtrl_GetLineWinkDetTime	DEVCTRL_IOCTL_CODE( 54, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (DWORD)
#define IOCTL_DevCtrl_SetAutoPhoneHookSwitch	DEVCTRL_IOCTL_CODE( 55, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (DWORD)
#define IOCTL_DevCtrl_GetAutoPhoneHookSwitch	DEVCTRL_IOCTL_CODE( 56, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (DWORD)
#define IOCTL_DevCtrl_SetLEDState			DEVCTRL_IOCTL_CODE( 57, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (DWORD)
#define IOCTL_DevCtrl_GetLEDState			DEVCTRL_IOCTL_CODE( 58, FILE_READ_WRITE_ACCESS, ARG_VOID)	// (void)

#define fnDevCtrl_CheckROM				IOCTL_DevCtrl_CheckROM 
#define fnDevCtrl_TestSRAM				IOCTL_DevCtrl_TestSRAM 
#define fnDevCtrl_SRAM8Bit				IOCTL_DevCtrl_SRAM8Bit 
#define fnDevCtrl_SRAM16Bit				IOCTL_DevCtrl_SRAM16Bit 
#define fnDevCtrl_GetIdCode				IOCTL_DevCtrl_GetIdCode 
#define fnDevCtrl_GetVersionCode		IOCTL_DevCtrl_GetVersionCode 
#define fnDevCtrl_TestCountMode			IOCTL_DevCtrl_TestCountMode 
#define fnDevCtrl_TestDigitalMilliwatt	IOCTL_DevCtrl_TestDigitalMilliwatt 
#define fnDevCtrl_TestLoopback			IOCTL_DevCtrl_TestLoopback 
#define fnDevCtrl_TestExit				IOCTL_DevCtrl_TestExit 
#define fnDevCtrl_Slowdown				IOCTL_DevCtrl_Slowdown 
#define fnDevCtrl_GPIODirection			IOCTL_DevCtrl_GPIODirection 
#define fnDevCtrl_GPIOWrite				IOCTL_DevCtrl_GPIOWrite 
#define fnDevCtrl_GPIORead				IOCTL_DevCtrl_GPIORead 
#define fnDevCtrl_EnableFR				IOCTL_DevCtrl_EnableFR 
#define fnDevCtrl_DisableFR				IOCTL_DevCtrl_DisableFR 
#define fnDevCtrl_ClearFR				IOCTL_DevCtrl_ClearFR 
#define fnDevCtrl_ReadFR				IOCTL_DevCtrl_ReadFR 
#define fnDevCtrl_SetAnalogSource		IOCTL_DevCtrl_SetAnalogSource 
#define fnDevCtrl_GetAnalogSource		IOCTL_DevCtrl_GetAnalogSource 
#define fnDevCtrl_SetSLICState			IOCTL_DevCtrl_SetSLICState 
#define fnDevCtrl_GetSLICState			IOCTL_DevCtrl_GetSLICState 
#define fnDevCtrl_ReadHookState			IOCTL_DevCtrl_ReadHookState 
#define fnDevCtrl_GetOnHook				IOCTL_DevCtrl_GetOnHook 
#define fnDevCtrl_SetRingPattern		IOCTL_DevCtrl_SetRingPattern 
#define fnDevCtrl_SetLineJackMode		IOCTL_DevCtrl_SetLineJackMode 
#define fnDevCtrl_GetLineJackMode		IOCTL_DevCtrl_GetLineJackMode 
#define fnDevCtrl_LineSetOnHook			IOCTL_DevCtrl_LineSetOnHook 
#define fnDevCtrl_LineGetRinging		IOCTL_DevCtrl_LineGetRinging 
#define fnDevCtrl_SetPotsToSlic			IOCTL_DevCtrl_SetPotsToSlic
#define fnDevCtrl_GetPotsToSlic			IOCTL_DevCtrl_GetPotsToSlic
#define fnDevCtrl_GetLineOnHook			IOCTL_DevCtrl_GetLineOnHook
#define fnDevCtrl_GetLineCallerOnHook	IOCTL_DevCtrl_GetLineCallerOnHook
#define fnDevCtrl_GetLinePhoneOnHook	IOCTL_DevCtrl_GetLinePhoneOnHook
#define fnDevCtrl_SetSpeaker			IOCTL_DevCtrl_SetSpeaker
#define fnDevCtrl_GetLineTestResult		IOCTL_DevCtrl_GetLineTestResult
#define fnDevCtrl_LineTest				IOCTL_DevCtrl_LineTest
#define fnDevCtrl_Wink					IOCTL_DevCtrl_Wink
#define	fnDevCtrl_Flash					IOCTL_DevCtrl_Flash
#define	fnDevCtrl_LineGetCallerID		IOCTL_DevCtrl_LineGetCallerID
#define	fnDevCtrl_GetAttachedDevices	IOCTL_DevCtrl_GetAttachedDevices
#define	fnDevCtrl_GetFlashState			IOCTL_DevCtrl_GetFlashState
#define	fnDevCtrl_GetCoefficientGroup	IOCTL_DevCtrl_GetCoefficientGroup
#define	fnDevCtrl_SetCoefficientGroup	IOCTL_DevCtrl_SetCoefficientGroup
#define	fnDevCtrl_GetPhoneType			IOCTL_DevCtrl_GetPhoneType
#define	fnDevCtrl_SetPhoneType			IOCTL_DevCtrl_SetPhoneType
#define	fnDevCtrl_SetRingCadence		IOCTL_DevCtrl_SetRingCadence
#define	fnDevCtrl_SetWinkGenTime		IOCTL_DevCtrl_SetWinkGenTime
#define	fnDevCtrl_GetWinkGenTime		IOCTL_DevCtrl_GetWinkGenTime
#define	fnDevCtrl_SetFlashDetTime		IOCTL_DevCtrl_SetFlashDetTime
#define	fnDevCtrl_GetFlashDetTime		IOCTL_DevCtrl_GetFlashDetTime
#define	fnDevCtrl_SetLineFlashGenTime	IOCTL_DevCtrl_SetLineFlashGenTime
#define	fnDevCtrl_GetLineFlashGenTime	IOCTL_DevCtrl_GetLineFlashGenTime
#define	fnDevCtrl_SetLineWinkDetTime	IOCTL_DevCtrl_SetLineWinkDetTime
#define	fnDevCtrl_GetLineWinkDetTime	IOCTL_DevCtrl_GetLineWinkDetTime
#define	fnDevCtrl_SetAutoPhoneHookSwitch	IOCTL_DevCtrl_SetAutoPhoneHookSwitch
#define	fnDevCtrl_GetAutoPhoneHookSwitch	IOCTL_DevCtrl_GetAutoPhoneHookSwitch
#define	fnDevCtrl_SetLEDState			IOCTL_DevCtrl_SetLEDState
#define	fnDevCtrl_GetLEDState			IOCTL_DevCtrl_GetLEDState

//==========================================================================
//--------------------------------------------------------------------------
//	Filter support
//--------------------------------------------------------------------------
//
#define FILE_DEVICE_FILTER 0x8006

#define FILTER_IOCTL_CODE( fn, Access, ArgSize ) CTL_CODE( FILE_DEVICE_FILTER, (0x800 + ArgSize + fn ), METHOD_BUFFERED, Access )

#define IOCTL_Filter_SetFilterModeSync	FILTER_IOCTL_CODE( 0, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wNew)
#define IOCTL_Filter_SetFilterModeAsync	FILTER_IOCTL_CODE( 1, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wNew)
#define IOCTL_Filter_GetFilterMode		FILTER_IOCTL_CODE( 2, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Filter_EnableDTMFDetect	FILTER_IOCTL_CODE( 3, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Filter_DisableDTMFDetect	FILTER_IOCTL_CODE( 4, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Filter_IsDTMFValid		FILTER_IOCTL_CODE( 5, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Filter_GetDTMFDigit		FILTER_IOCTL_CODE( 6, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Filter_GetFrameCount		FILTER_IOCTL_CODE( 7, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Filter_IsCPFValid			FILTER_IOCTL_CODE( 8, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Filter_SetFilterPrescaler	FILTER_IOCTL_CODE( 9, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wScale )
#define IOCTL_Filter_GetFilterPrescaler	FILTER_IOCTL_CODE( 10, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Filter_LineMonitor		FILTER_IOCTL_CODE( 11, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Filter_ProgramFilter		FILTER_IOCTL_CODE( 12, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Filter_EnableFilter		FILTER_IOCTL_CODE( 13, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Filter_DisableFilter		FILTER_IOCTL_CODE( 14, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Filter_DetectToneCadence	FILTER_IOCTL_CODE( 15, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Filter_StopDetectToneCadence	FILTER_IOCTL_CODE( 16, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Filter_IsToneCadenceValid	FILTER_IOCTL_CODE( 17, FILE_READ_ACCESS, ARG_VOID)	// (void)

#define fnFilter_SetFilterModeSync		IOCTL_Filter_SetFilterModeSync
#define fnFilter_SetFilterModeAsync		IOCTL_Filter_SetFilterModeAsync
#define fnFilter_GetFilterMode			IOCTL_Filter_GetFilterMode
#define fnFilter_EnableDTMFDetect		IOCTL_Filter_EnableDTMFDetect
#define fnFilter_DisableDTMFDetect		IOCTL_Filter_DisableDTMFDetect
#define fnFilter_IsDTMFValid			IOCTL_Filter_IsDTMFValid
#define fnFilter_GetDTMFDigit			IOCTL_Filter_GetDTMFDigit
#define fnFilter_GetFrameCount			IOCTL_Filter_GetFrameCount
#define fnFilter_IsCPFValid				IOCTL_Filter_IsCPFValid
#define fnFilter_SetFilterPrescaler		IOCTL_Filter_SetFilterPrescaler
#define fnFilter_GetFilterPrescaler		IOCTL_Filter_GetFilterPrescaler
#define fnFilter_LineMonitor			IOCTL_Filter_LineMonitor
#define fnFilter_ProgramFilter			IOCTL_Filter_ProgramFilter
#define fnFilter_EnableFilter			IOCTL_Filter_EnableFilter
#define fnFilter_DisableFilter			IOCTL_Filter_DisableFilter
#define fnFilter_DetectToneCadence		IOCTL_Filter_DetectToneCadence
#define fnFilter_StopDetectToneCadence	IOCTL_Filter_StopDetectToneCadence
#define fnFilter_IsToneCadenceValid		IOCTL_Filter_IsToneCadenceValid

//==========================================================================
//--------------------------------------------------------------------------
//	Idle support
//--------------------------------------------------------------------------
//
#define FILE_DEVICE_IDLE	0x8000

#define IDLE_IOCTL_CODE( fn, Access, ArgSize ) CTL_CODE( FILE_DEVICE_IDLE, (0x800 + ArgSize + fn ), METHOD_BUFFERED, Access )

#define IOCTL_Idle_Idle				IDLE_IOCTL_CODE( 0, FILE_READ_ACCESS, ARG_VOID)			// (void)
#define IOCTL_Idle_SetMasterGain	IDLE_IOCTL_CODE( 1, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wNew)
#define IOCTL_Idle_GetMasterGain	IDLE_IOCTL_CODE( 2, FILE_READ_ACCESS, ARG_VOID)			// (void)
#define IOCTL_Idle_SetSyncToneMode	IDLE_IOCTL_CODE( 3, FILE_READ_ACCESS, ARG_VOID)			// (void)
#define IOCTL_Idle_SetAsyncToneMode	IDLE_IOCTL_CODE( 4, FILE_READ_ACCESS, ARG_VOID)			// (void)
#define IOCTL_Idle_SetToneIndex		IDLE_IOCTL_CODE( 5, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wNew)
#define IOCTL_Idle_GetToneIndex		IDLE_IOCTL_CODE( 6, FILE_READ_ACCESS, ARG_VOID)			// (void)
#define IOCTL_Idle_GetToneMode		IDLE_IOCTL_CODE( 7, FILE_READ_ACCESS, ARG_VOID)			// (void)
#define IOCTL_Idle_SetToneOnPeriod	IDLE_IOCTL_CODE( 8, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wNew)
#define IOCTL_Idle_GetToneOnPeriod	IDLE_IOCTL_CODE( 9, FILE_READ_ACCESS, ARG_VOID)			// (void)
#define IOCTL_Idle_SetToneOffPeriod	IDLE_IOCTL_CODE( 10, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wNew)
#define IOCTL_Idle_GetToneOffPeriod	IDLE_IOCTL_CODE( 11, FILE_READ_ACCESS, ARG_VOID)		// (void)
#define IOCTL_Idle_GetToneState		IDLE_IOCTL_CODE( 12, FILE_READ_ACCESS, ARG_VOID)		// (void)
#define IOCTL_Idle_GenerateTone		IDLE_IOCTL_CODE( 13, FILE_READ_ACCESS, ARG_VOID)		// (void)
#define IOCTL_Idle_NewToneInit		IDLE_IOCTL_CODE( 14, FILE_READ_ACCESS, ARG_VOID)		// (IDLE_NEW_TONE*)
#define IOCTL_Idle_PlayTone			IDLE_IOCTL_CODE( 15, FILE_READ_ACCESS, ARG_DWORD)		// (IDLE_TONE*)
#define IOCTL_Idle_StopTone			IDLE_IOCTL_CODE( 16, FILE_READ_ACCESS, ARG_VOID)		// (void)

#define fnIdle_Idle					IOCTL_Idle_Idle
#define fnIdle_SetMasterGain		IOCTL_Idle_SetMasterGain
#define fnIdle_GetMasterGain		IOCTL_Idle_GetMasterGain
#define fnIdle_SetSyncToneMode		IOCTL_Idle_SetSyncToneMode
#define fnIdle_SetAsyncToneMode		IOCTL_Idle_SetAsyncToneMode
#define fnIdle_SetToneIndex			IOCTL_Idle_SetToneIndex
#define fnIdle_GetToneIndex			IOCTL_Idle_GetToneIndex
#define fnIdle_GetToneMode			IOCTL_Idle_GetToneMode
#define fnIdle_SetToneOnPeriod		IOCTL_Idle_SetToneOnPeriod
#define fnIdle_GetToneOnPeriod		IOCTL_Idle_GetToneOnPeriod
#define fnIdle_SetToneOffPeriod		IOCTL_Idle_SetToneOffPeriod
#define fnIdle_GetToneOffPeriod		IOCTL_Idle_GetToneOffPeriod
#define fnIdle_GetToneState			IOCTL_Idle_GetToneState
#define fnIdle_GenerateTone			IOCTL_Idle_GenerateTone
#define fnIdle_NewToneInit			IOCTL_Idle_NewToneInit
#define fnIdle_PlayTone				IOCTL_Idle_PlayTone
#define fnIdle_StopTone				IOCTL_Idle_StopTone

//==========================================================================
//--------------------------------------------------------------------------
//	Mixer support
//--------------------------------------------------------------------------
//
#define FILE_DEVICE_MIXER 0x800A

#define MIXER_IOCTL_CODE( fn, Access, ArgSize ) CTL_CODE( FILE_DEVICE_MIXER, (0x800 + ArgSize + fn ), METHOD_BUFFERED, Access )

#define IOCTL_Mixer_SetPlaybackLineControls		MIXER_IOCTL_CODE( 0, FILE_READ_WRITE_ACCESS, ARG_VOID)	// MIXER_LINE* pMixerLine 
#define IOCTL_Mixer_GetPlaybackLineControls		MIXER_IOCTL_CODE( 1, FILE_READ_ACCESS, ARG_VOID)		// MIXER_LINE* pMixerLine
#define IOCTL_Mixer_SetRecordLineControls		MIXER_IOCTL_CODE( 2, FILE_READ_WRITE_ACCESS, ARG_VOID)	// MIXER_LINE* pMixerLine
#define IOCTL_Mixer_GetRecordLineControls		MIXER_IOCTL_CODE( 3, FILE_READ_ACCESS, ARG_VOID)		// MIXER_LINE* pMixerLine
#define IOCTL_Mixer_SetOutputMixer				MIXER_IOCTL_CODE( 4, FILE_READ_WRITE_ACCESS, ARG_VOID)	// MIXER_LINE* pMixerLine
#define IOCTL_Mixer_GetOutputMixer				MIXER_IOCTL_CODE( 5, FILE_READ_ACCESS, ARG_VOID)		// MIXER_LINE* pMixerLine
#define IOCTL_Mixer_SetInputMixer				MIXER_IOCTL_CODE( 6, FILE_READ_WRITE_ACCESS, ARG_VOID)	// MIXER_LINE* pMixerLine
#define IOCTL_Mixer_GetInputMixer				MIXER_IOCTL_CODE( 7, FILE_READ_ACCESS, ARG_VOID)		// MIXER_LINE* pMixerLine
#define IOCTL_Mixer_SetMasterRecordGain			MIXER_IOCTL_CODE( 8, FILE_READ_WRITE_ACCESS, ARG_DWORD)		// LONG lGain in 1/10 dB
#define IOCTL_Mixer_SetMasterPlaybackGain		MIXER_IOCTL_CODE( 9, FILE_READ_WRITE_ACCESS, ARG_DWORD)		// LONG lGain in 1/10 dB
#define IOCTL_Mixer_SetPSTNRecordGain			MIXER_IOCTL_CODE( 10, FILE_READ_WRITE_ACCESS, ARG_DWORD)		// LONG lGain in 1/10 dB
#define IOCTL_Mixer_SetPSTNPlaybackGain			MIXER_IOCTL_CODE( 11, FILE_READ_WRITE_ACCESS, ARG_DWORD)		// LONG lGain in 1/10 dB

//==========================================================================
//--------------------------------------------------------------------------
//	Playback support
//--------------------------------------------------------------------------
//
#define FILE_DEVICE_PLAYBACK 0x8004

#define	PLAYBACK_IOCTL_CODE( fn, Access, ArgSize ) CTL_CODE( FILE_DEVICE_PLAYBACK, (0x800 + ArgSize + fn ), METHOD_BUFFERED, Access )

#define IOCTL_Playback_SetTFRMode				PLAYBACK_IOCTL_CODE( 0, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wNew)
#define IOCTL_Playback_GetTFRMode				PLAYBACK_IOCTL_CODE( 1, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Playback_SetPLAYMODE				PLAYBACK_IOCTL_CODE( 2, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wNew)
#define IOCTL_Playback_GetPLAYMODE				PLAYBACK_IOCTL_CODE( 3, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Playback_GetDTMF_VALID			PLAYBACK_IOCTL_CODE( 4, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Playback_GetCPF_VALID				PLAYBACK_IOCTL_CODE( 5, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Playback_GetDTMF_DIGIT			PLAYBACK_IOCTL_CODE( 6, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Playback_SetRate					PLAYBACK_IOCTL_CODE( 7, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wNew)
#define IOCTL_Playback_GetRate					PLAYBACK_IOCTL_CODE( 8, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Playback_Start_Old				PLAYBACK_IOCTL_CODE( 9, FILE_READ_ACCESS, ARG_VOID)	// (void)
//#define IOCTL_Playback_Continue					PLAYBACK_IOCTL_CODE( 10, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Playback_Continue					CTL_CODE( FILE_DEVICE_PLAYBACK, 0x80a, METHOD_NEITHER, FILE_READ_ACCESS )	// (void)
#define IOCTL_Playback_Stop						PLAYBACK_IOCTL_CODE( 11, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Playback_SetVolume				PLAYBACK_IOCTL_CODE( 12, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wNew)
#define IOCTL_Playback_GetVolume				PLAYBACK_IOCTL_CODE( 13, FILE_READ_ACCESS, ARG_DWORD)	// (WORD wNew)
#define IOCTL_Playback_SetSyncMode				PLAYBACK_IOCTL_CODE( 14, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wNew)
#define IOCTL_Playback_GetSyncMode				PLAYBACK_IOCTL_CODE( 15, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Playback_SetBufferChannelLimit	PLAYBACK_IOCTL_CODE( 16, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wNew)
#define IOCTL_Playback_GetBufferChannelLimit	PLAYBACK_IOCTL_CODE( 17, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Playback_GetFrameSize				PLAYBACK_IOCTL_CODE( 18, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Playback_GetAvgPlaybackLevel		PLAYBACK_IOCTL_CODE( 19, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Playback_ContinueLogFrame			PLAYBACK_IOCTL_CODE( 20, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Playback_Open						PLAYBACK_IOCTL_CODE( 21, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Playback_Close					PLAYBACK_IOCTL_CODE( 22, FILE_READ_ACCESS, ARG_DWORD)	// (DWORD)
#define IOCTL_Playback_SetMute					PLAYBACK_IOCTL_CODE( 23, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (WORD wNew)
#define IOCTL_Playback_GetMute					PLAYBACK_IOCTL_CODE( 24, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Playback_GetBufferDepth			PLAYBACK_IOCTL_CODE( 25, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_Playback_GetPlaybackLevelValue	PLAYBACK_IOCTL_CODE( 26, FILE_READ_ACCESS, ARG_VOID) // (void)
#define IOCTL_Playback_IsPlaying				PLAYBACK_IOCTL_CODE( 27, FILE_READ_ACCESS, ARG_VOID) // (void)
#define IOCTL_Playback_Start					PLAYBACK_IOCTL_CODE( 28, FILE_READ_ACCESS, ARG_VOID)	// (void)

#define fnPlayback_SetTFRMode				IOCTL_Playback_SetTFRMode 
#define fnPlayback_GetTFRMode				IOCTL_Playback_GetTFRMode 
#define fnPlayback_SetPLAYMODE				IOCTL_Playback_SetPLAYMODE 
#define fnPlayback_GetPLAYMODE				IOCTL_Playback_GetPLAYMODE 
#define fnPlayback_GetDTMF_VALID			IOCTL_Playback_GetDTMF_VALID 
#define fnPlayback_GetCPF_VALID				IOCTL_Playback_GetCPF_VALID 
#define fnPlayback_GetDTMF_DIGIT			IOCTL_Playback_GetDTMF_DIGIT 
#define fnPlayback_SetRate					IOCTL_Playback_SetRate 
#define fnPlayback_GetRate					IOCTL_Playback_GetRate 
#define fnPlayback_Start					IOCTL_Playback_Start 
#define fnPlayback_Continue					IOCTL_Playback_Continue 
#define fnPlayback_Stop						IOCTL_Playback_Stop 
#define fnPlayback_SetVolume				IOCTL_Playback_SetVolume 
#define fnPlayback_GetVolume				IOCTL_Playback_GetVolume 
#define fnPlayback_SetSyncMode				IOCTL_Playback_SetSyncMode 
#define fnPlayback_GetSyncMode				IOCTL_Playback_GetSyncMode 
#define fnPlayback_SetBufferChannelLimit	IOCTL_Playback_SetBufferChannelLimit 
#define fnPlayback_GetBufferChannelLimit	IOCTL_Playback_GetBufferChannelLimit 
#define fnPlayback_GetFrameSize				IOCTL_Playback_GetFrameSize 
#define fnPlayback_GetAvgPlaybackLevel		IOCTL_Playback_GetAvgPlaybackLevel 
#define fnPlayback_ContinueLogFrame			IOCTL_Playback_ContinueLogFrame
#define fnPlayback_Open						IOCTL_Playback_Open
#define fnPlayback_Close					IOCTL_Playback_Close
#define fnPlayback_SetMute					IOCTL_Playback_SetMute 
#define fnPlayback_GetMute					IOCTL_Playback_GetMute 
#define fnPlayback_GetBufferDepth			IOCTL_Playback_GetBufferDepth 
#define fnPlayback_GetPlaybackLevelValue	IOCTL_Playback_GetPlaybackLevelValue
#define fnPlayback_IsPlaying				IOCTL_Playback_IsPlaying

//==========================================================================
//--------------------------------------------------------------------------
//	Record support
//--------------------------------------------------------------------------
//
#define FILE_DEVICE_RECORD 0x8003

#define RECORD_IOCTL_CODE( fn, Access, ArgSize ) CTL_CODE( FILE_DEVICE_RECORD, (0x800 + ArgSize + fn ), METHOD_BUFFERED, Access )

#define	IOCTL_Record_SetTFRMode				RECORD_IOCTL_CODE( 0, FILE_READ_WRITE_ACCESS, ARG_DWORD) // (WORD wNew)
#define	IOCTL_Record_GetTFRMode				RECORD_IOCTL_CODE( 1, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_SetRECMODE				RECORD_IOCTL_CODE( 2, FILE_READ_WRITE_ACCESS, ARG_DWORD) // (WORD wNew)
#define	IOCTL_Record_GetRECMODE				RECORD_IOCTL_CODE( 3, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_GetPEAK				RECORD_IOCTL_CODE( 4, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_GetDTMF_VALID			RECORD_IOCTL_CODE( 5, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_GetCPF_VALID			RECORD_IOCTL_CODE( 6, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_GetDTMF_DIGIT			RECORD_IOCTL_CODE( 7, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_SetThresholdValue		RECORD_IOCTL_CODE( 8, FILE_READ_WRITE_ACCESS, ARG_DWORD) // (WORD wNew)
#define	IOCTL_Record_GetThresholdValue		RECORD_IOCTL_CODE( 9, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_GetRecordLevelValue	RECORD_IOCTL_CODE( 10, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_Start_Old				RECORD_IOCTL_CODE( 11, FILE_READ_ACCESS, ARG_VOID) // (void)
//#define	IOCTL_Record_Continue				RECORD_IOCTL_CODE( 12, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_Continue				CTL_CODE( FILE_DEVICE_RECORD, 0x80c, METHOD_NEITHER, FILE_READ_ACCESS ) // (void)
#define	IOCTL_Record_Stop					RECORD_IOCTL_CODE( 13, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_SetRate				RECORD_IOCTL_CODE( 14, FILE_READ_WRITE_ACCESS, ARG_DWORD) // (WORD wNew)
#define	IOCTL_Record_GetRate				RECORD_IOCTL_CODE( 15, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_SetVolume				RECORD_IOCTL_CODE( 16, FILE_READ_WRITE_ACCESS, ARG_DWORD) // (WORD wNew)
#define	IOCTL_Record_GetVolume				RECORD_IOCTL_CODE( 17, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_SetAGCMinGain			RECORD_IOCTL_CODE( 18, FILE_READ_WRITE_ACCESS, ARG_DWORD) // (WORD wNew)
#define	IOCTL_Record_GetAGCMinGain			RECORD_IOCTL_CODE( 19, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_SetAGCMaxGain			RECORD_IOCTL_CODE( 20, FILE_READ_WRITE_ACCESS, ARG_DWORD) // (WORD wNew)
#define	IOCTL_Record_GetAGCMaxGain			RECORD_IOCTL_CODE( 21, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_SetAGCStartGain		RECORD_IOCTL_CODE( 22, FILE_READ_WRITE_ACCESS, ARG_DWORD) // (WORD wNew)
#define	IOCTL_Record_GetAGCStartGain		RECORD_IOCTL_CODE( 23, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_SetAGCHoldTime			RECORD_IOCTL_CODE( 24, FILE_READ_WRITE_ACCESS, ARG_DWORD) // (WORD wNew)
#define	IOCTL_Record_GetAGCHoldTime			RECORD_IOCTL_CODE( 25, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_SetAGCAttackTime		RECORD_IOCTL_CODE( 26, FILE_READ_WRITE_ACCESS, ARG_DWORD) // (WORD wNew)
#define	IOCTL_Record_GetAGCAttackTime		RECORD_IOCTL_CODE( 27, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_SetAGCDecayTime		RECORD_IOCTL_CODE( 28, FILE_READ_WRITE_ACCESS, ARG_DWORD) // (WORD wNew)
#define	IOCTL_Record_GetAGCDecayTime		RECORD_IOCTL_CODE( 29, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_SetAGCAttackThreshold	RECORD_IOCTL_CODE( 30, FILE_READ_WRITE_ACCESS, ARG_DWORD) // (WORD wNew)
#define	IOCTL_Record_GetAGCAttackThreshold	RECORD_IOCTL_CODE( 31, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_SetAGCOnOff			RECORD_IOCTL_CODE( 32, FILE_READ_WRITE_ACCESS, ARG_DWORD) // (WORD wNew)
#define	IOCTL_Record_GetAGCOnOff			RECORD_IOCTL_CODE( 33, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_SetSyncMode			RECORD_IOCTL_CODE( 34, FILE_READ_WRITE_ACCESS, ARG_DWORD) // (WORD wNew)
#define	IOCTL_Record_GetSyncMode			RECORD_IOCTL_CODE( 35, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_SetBufferChannelLimit	RECORD_IOCTL_CODE( 36, FILE_READ_WRITE_ACCESS, ARG_DWORD) // (WORD wNew)
#define	IOCTL_Record_GetBufferChannelLimit	RECORD_IOCTL_CODE( 37, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_GetFrameSize			RECORD_IOCTL_CODE( 38, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_GetAvgRecordLevel		RECORD_IOCTL_CODE( 39, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_ContinueLogFrame		RECORD_IOCTL_CODE( 40, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_Open					RECORD_IOCTL_CODE( 41, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_Close					RECORD_IOCTL_CODE( 42, FILE_READ_ACCESS, ARG_DWORD) // (DWORD)
#define	IOCTL_Record_SetMute				RECORD_IOCTL_CODE( 43, FILE_READ_WRITE_ACCESS, ARG_DWORD) // (WORD wNew)
#define	IOCTL_Record_GetMute				RECORD_IOCTL_CODE( 44, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_EnableVAD				RECORD_IOCTL_CODE( 45, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_DisableVAD				RECORD_IOCTL_CODE( 46, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_SetDisableOnDTMFDetect		RECORD_IOCTL_CODE( 47, FILE_READ_WRITE_ACCESS, ARG_DWORD) // (WORD wNew)
#define	IOCTL_Record_GetDisableOnDTMFDetect		RECORD_IOCTL_CODE( 48, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_IsRecording			RECORD_IOCTL_CODE( 49, FILE_READ_ACCESS, ARG_VOID) // (void)
#define	IOCTL_Record_Start					RECORD_IOCTL_CODE( 50, FILE_READ_ACCESS, ARG_VOID) // (void)

#define fnRecord_SetTFRMode				IOCTL_Record_SetTFRMode 
#define fnRecord_GetTFRMode				IOCTL_Record_GetTFRMode 
#define fnRecord_SetRECMODE				IOCTL_Record_SetRECMODE 
#define fnRecord_GetRECMODE				IOCTL_Record_GetRECMODE 
#define fnRecord_GetPEAK				IOCTL_Record_GetPEAK 
#define fnRecord_GetDTMF_VALID			IOCTL_Record_GetDTMF_VALID 
#define fnRecord_GetCPF_VALID			IOCTL_Record_GetCPF_VALID 
#define fnRecord_GetDTMF_DIGIT			IOCTL_Record_GetDTMF_DIGIT 
#define fnRecord_SetThresholdValue		IOCTL_Record_SetThresholdValue 
#define fnRecord_GetThresholdValue		IOCTL_Record_GetThresholdValue 
#define fnRecord_GetRecordLevelValue	IOCTL_Record_GetRecordLevelValue 
#define fnRecord_Start					IOCTL_Record_Start 
#define fnRecord_Continue				IOCTL_Record_Continue 
#define fnRecord_Stop					IOCTL_Record_Stop 
#define fnRecord_SetRate				IOCTL_Record_SetRate 
#define fnRecord_GetRate				IOCTL_Record_GetRate 
#define fnRecord_SetVolume				IOCTL_Record_SetVolume 
#define fnRecord_GetVolume				IOCTL_Record_GetVolume 
#define fnRecord_SetAGCMinGain			IOCTL_Record_SetAGCMinGain 
#define fnRecord_GetAGCMinGain			IOCTL_Record_GetAGCMinGain 
#define fnRecord_SetAGCMaxGain			IOCTL_Record_SetAGCMaxGain 
#define fnRecord_GetAGCMaxGain			IOCTL_Record_GetAGCMaxGain 
#define fnRecord_SetAGCStartGain		IOCTL_Record_SetAGCStartGain 
#define fnRecord_GetAGCStartGain		IOCTL_Record_GetAGCStartGain 
#define fnRecord_SetAGCHoldTime			IOCTL_Record_SetAGCHoldTime 
#define fnRecord_GetAGCHoldTime			IOCTL_Record_GetAGCHoldTime 
#define fnRecord_SetAGCAttackTime		IOCTL_Record_SetAGCAttackTime 
#define fnRecord_GetAGCAttackTime		IOCTL_Record_GetAGCAttackTime 
#define fnRecord_SetAGCDecayTime		IOCTL_Record_SetAGCDecayTime 
#define fnRecord_GetAGCDecayTime		IOCTL_Record_GetAGCDecayTime 
#define fnRecord_SetAGCAttackThreshold	IOCTL_Record_SetAGCAttackThreshold 
#define fnRecord_GetAGCAttackThreshold	IOCTL_Record_GetAGCAttackThreshold 
#define fnRecord_SetAGCOnOff			IOCTL_Record_SetAGCOnOff 
#define fnRecord_GetAGCOnOff			IOCTL_Record_GetAGCOnOff 
#define fnRecord_SetSyncMode			IOCTL_Record_SetSyncMode 
#define fnRecord_GetSyncMode			IOCTL_Record_GetSyncMode 
#define fnRecord_SetBufferChannelLimit	IOCTL_Record_SetBufferChannelLimit 
#define fnRecord_GetBufferChannelLimit	IOCTL_Record_GetBufferChannelLimit 
#define fnRecord_GetFrameSize			IOCTL_Record_GetFrameSize 
#define fnRecord_GetAvgRecordLevel		IOCTL_Record_GetAvgRecordLevel 
#define fnRecord_SetMute				IOCTL_Record_SetMute 
#define fnRecord_GetMute				IOCTL_Record_GetMute 
#define fnRecord_ContinueLogFrame       IOCTL_Record_ContinueLogFrame
#define fnRecord_IsRecording	        IOCTL_Record_IsRecording

//==========================================================================
//--------------------------------------------------------------------------
//	Speakerphone support
//--------------------------------------------------------------------------
//
#define FILE_DEVICE_SPEAKERPHONE 0x8005

#define SPEAKERPHONE_IOCTL_CODE( fn, Access, ArgSize ) CTL_CODE( FILE_DEVICE_SPEAKERPHONE, (0x800 + ArgSize + fn ), METHOD_BUFFERED, Access )

#define IOCTL_Speakerphone_SetSpeakerVolume		SPEAKERPHONE_IOCTL_CODE( 0, FILE_READ_WRITE_ACCESS, ARG_DWORD) // (WORD wNew)
#define IOCTL_Speakerphone_GetSpeakerVolume		SPEAKERPHONE_IOCTL_CODE( 1, FILE_READ_ACCESS, ARG_VOID) // (void)
#define IOCTL_Speakerphone_AECOn				SPEAKERPHONE_IOCTL_CODE( 2, FILE_READ_ACCESS, ARG_VOID) // (void)
#define IOCTL_Speakerphone_AECOff				SPEAKERPHONE_IOCTL_CODE( 3, FILE_READ_ACCESS, ARG_VOID) // (void)
#define IOCTL_Speakerphone_AECAdvancedLoOn		SPEAKERPHONE_IOCTL_CODE( 4, FILE_READ_ACCESS, ARG_VOID) // (void)
#define IOCTL_Speakerphone_AECAdvancedHiOn		SPEAKERPHONE_IOCTL_CODE( 5, FILE_READ_ACCESS, ARG_VOID) // (void)
#define IOCTL_Speakerphone_AECAdvancedLoOff		SPEAKERPHONE_IOCTL_CODE( 6, FILE_READ_ACCESS, ARG_VOID) // (void)
#define IOCTL_Speakerphone_AECAdvancedHiOff		SPEAKERPHONE_IOCTL_CODE( 7, FILE_READ_ACCESS, ARG_VOID) // (void)
#define IOCTL_Speakerphone_SetAEC				SPEAKERPHONE_IOCTL_CODE( 8, FILE_READ_WRITE_ACCESS, ARG_DWORD) // (WORD wNew)
#define IOCTL_Speakerphone_GetAEC				SPEAKERPHONE_IOCTL_CODE( 9, FILE_READ_ACCESS, ARG_VOID) // (void)
#define IOCTL_Speakerphone_SetBaseFrameSize  SPEAKERPHONE_IOCTL_CODE( 10, FILE_READ_WRITE_ACCESS, ARG_DWORD) // (WORD wNew)
#define IOCTL_Speakerphone_GetBaseFrameSize				SPEAKERPHONE_IOCTL_CODE( 11, FILE_READ_ACCESS, ARG_VOID) // (void)

#define fnSpeakerphone_SetSpeakerVolume		IOCTL_Speakerphone_SetSpeakerVolume 
#define fnSpeakerphone_GetSpeakerVolume		IOCTL_Speakerphone_GetSpeakerVolume 
#define fnSpeakerphone_AECOn				IOCTL_Speakerphone_AECOn 
#define fnSpeakerphone_AECOff				IOCTL_Speakerphone_AECOff 
#define fnSpeakerphone_AECAdvancedLoOn		IOCTL_Speakerphone_AECAdvancedLoOn 
#define fnSpeakerphone_AECAdvancedHiOn		IOCTL_Speakerphone_AECAdvancedHiOn 
#define fnSpeakerphone_AECAdvancedLoOff		IOCTL_Speakerphone_AECAdvancedLoOff 
#define fnSpeakerphone_AECAdvancedHiOff		IOCTL_Speakerphone_AECAdvancedHiOff 
#define fnSpeakerphone_SetAEC				IOCTL_Speakerphone_SetAEC 
#define fnSpeakerphone_GetAEC				IOCTL_Speakerphone_GetAEC 

//==========================================================================
//--------------------------------------------------------------------------
//	Fax support
//--------------------------------------------------------------------------
//
#define FILE_DEVICE_FAX 0x800B

#define FAX_IOCTL_CODE( fn, Access, ArgSize ) CTL_CODE( FILE_DEVICE_FAX, (0x800 + ArgSize + fn ), METHOD_BUFFERED, Access )

#define IOCTL_Fax_Start						FAX_IOCTL_CODE( 0, FILE_READ_ACCESS, ARG_VOID) // (void)
#define IOCTL_Fax_Stop						FAX_IOCTL_CODE( 1, FILE_READ_ACCESS, ARG_VOID) // (void)
#define IOCTL_Fax_Write						FAX_IOCTL_CODE( 2, FILE_READ_WRITE_ACCESS, ARG_DWORD) // (WORD *buf)
#define IOCTL_Fax_Read						FAX_IOCTL_CODE( 3, FILE_READ_ACCESS, ARG_VOID) // (void)

#define fnFax_Start							IOCTL_Fax_Start 
#define fnFax_Stop							IOCTL_Fax_Stop 
#define fnFax_Fax_Write						IOCTL_Fax_Write 
#define fnFax_Read							IOCTL_Fax_Read 

//==========================================================================
//--------------------------------------------------------------------------
//	FSK support
//--------------------------------------------------------------------------
//
#define FILE_DEVICE_FSK 0x800C

#define FSK_IOCTL_CODE( fn, Access, ArgSize ) CTL_CODE( FILE_DEVICE_FSK, (0x800 + ArgSize + fn ), METHOD_BUFFERED, Access )

#define IOCTL_FSK_SetMsgData				FSK_IOCTL_CODE( 0, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (BYTE*)

#define	fnFSK_SetMsgData					IOCTL_FSK_SetMsgData

//==========================================================================
//--------------------------------------------------------------------------
//	Tone support
//--------------------------------------------------------------------------
//
#define FILE_DEVICE_TONE 0x800D

#define TONE_IOCTL_CODE( fn, Access, ArgSize ) CTL_CODE( FILE_DEVICE_TONE, (0x800 + ArgSize + fn ), METHOD_BUFFERED, Access )

#define IOCTL_Tone_PlayToneCadence		TONE_IOCTL_CODE( 0, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (BYTE*)

#define	fnTone_PlayToneCadence			IOCTL_Tone_PlayToneCadence

//==========================================================================
//--------------------------------------------------------------------------
//	VxD support
//
//	NOTE: These names will be changed in the future to a generic 'driver'
//        naming convention.
//--------------------------------------------------------------------------
//
#define FILE_DEVICE_VXD 0x8001

#define VXD_IOCTL_CODE( fn, Access, ArgSize ) CTL_CODE( FILE_DEVICE_VXD, (0x800 + ArgSize + fn ), METHOD_BUFFERED, Access )

#define IOCTL_VxD_SetCallback			VXD_IOCTL_CODE( 0, FILE_READ_WRITE_ACCESS, ARG_VOID)	// (FARPROC pfnCallback) - Callback address
#define IOCTL_VxD_GetInterruptEvents	VXD_IOCTL_CODE( 1, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_VxD_EnableInterrupts		VXD_IOCTL_CODE( 2, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_VxD_DisableInterrupts		VXD_IOCTL_CODE( 3, FILE_READ_ACCESS, ARG_VOID)	// (void)
#define IOCTL_VxD_AddPerformanceStat	VXD_IOCTL_CODE( 4, FILE_READ_WRITE_ACCESS, ARG_DWORD)	// (LPPERF_STAT lpPerfStat)
#define IOCTL_VxD_GetVersion			VXD_IOCTL_CODE( 5, FILE_READ_ACCESS, ARG_VOID)	// (void)

#define fnVxD_SetCallback				IOCTL_VxD_SetCallback
#define fnVxD_GetInterruptEvents		IOCTL_VxD_GetInterruptEvents
#define fnVxD_EnableInterrupts			IOCTL_VxD_EnableInterrupts
#define fnVxD_DisableInterrupts			IOCTL_VxD_DisableInterrupts
#define fnVxD_AddPerformanceStat		IOCTL_VxD_AddPerformanceStat
#define fnVxD_GetVersion				IOCTL_VxD_GetVersion

#endif

//	eof: QTIoctl.h
