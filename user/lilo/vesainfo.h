/* vesainfo.h */
/*
Copyright 2003-2004 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/

#ifndef _VESAINFO_H
#define _VESAINFO_H

#ifndef LILO_ASM
#pragma pack(2)

typedef
   union {
      char  space[512];
      struct {
         char  Signature[4];
         short Version;
         char  *OEMstring;		/* far pointer */
         int  Capabilities;
         short *VideoModePtr;		/* far pointer */
         } ident;
      struct {
         short ModeAttributes;
         char  WinAAttributes;
         char  WinBAttributes;
         short WinGranularity;
         short WinSize;
         short WinASegment;
         short WinBSegment;
         char *WinFuncPtr;          /* window swapping function */
         short BytesPerScanLine;

         /* Optional Information */
         short Xresolution;
         short Yresolution;
 unsigned char XcharSize;
 unsigned char YcharSize;
         char  NumberOfPlanes;
         char  BitsPerPixel;
 unsigned char NumberOfBanks;
         char  MemoryModel;
 unsigned char BankSize;
         } info;
      } VESAINFO;

#pragma pack()

#else	/* LILO_ASM is defined */
v_Signature	= 0		; offset to Signature (int)
v_Capabilities	= 10		; offset to Capabilities (int)

v_ModeAttributes = 0		; short
v_WinAAttributes = 2		; char
v_WinBAttributes = 3		; char
v_WinGranularity = 4		; short
v_WinSize	= 6		; short
v_WinASegment	= 8		; short
v_WinBSegment	= 10		; short
v_WinFuncPointer = 12		; far pointer
v_BytesPerScanLine = 16		; short

#endif

#define SIG_VBE2 0x32454256
#define SIG_VESA 0x41534556

#endif
/* end vesainfo.h */

