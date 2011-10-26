/* This file is part of the Hardware Control Functions Light (HCF-light) library
   to control the Lucent Technologies WaveLAN/IEEE Network I/F Card.
   The HCF is the implementation of the Wireless Connection I/F (WCI).
   
   The HCF-light files are a subset of the HCF files. The complete set offers a
   number of additional facilities, e.g. firmware download, Etherner-II encapsulation,
   additional diagnostic facilities, ASSERT logic to support debugging, 802.11 support,
   Configuration Management.
   This complete set is explicitely not in the Public Domain but can be made 
   available under certain restriction. (see the pointer below for support)
   
   The HCF-light files are free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 2 of the License, or (at your
   option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. 
   
   At the time of this writing, you can request for support at:
   betasupport@wavelan.com
   
   Documentation is expected to be available in the week of 8 Februari 1999

*/
#include <asm/byteorder.h>

#ifndef HCFCFG_H                                                     
#define HCFCFG_H 1

/**************************************************************************************************************
*
* FILE	 : hcfcfg.tpl // hcfcfg.h **************************** 2.0 ********************************************
*
* DATE   : 2001/03/01 00:59:03   1.4
*
* AUTHOR : Nico Valster
*
* DESC   : HCF Customization Macros
*
***************************************************************************************************************
* COPYRIGHT (c) 1994, 1995		 by AT&T.	 				All Rights Reserved.
* COPYRIGHT (c) 1996, 1997, 1998 by Lucent Technologies.	All Rights Reserved.
*
***************************************************************************************************************
*
* hcfcfg.tpl list all #defines which must be specified to:
*    I:	adjust the HCF functions defined in HCF.CPP to the characteristics of a specific environment
* 		o maximum sizes for messages and notification frames, persistent configuration storage
* 		o Endianess
*
*	II:	Compiler specific macros
* 		o port I/O macros
* 		o type definitions
*
*  III:	Environment specific ASSERT macro
*
*   IV: Compiler specific 
*
*    V: ;? specific 
*
*
* By copying HCFCFG.TPL to HCFCFG.H and -if needed- modifying the #defines the WCI functionality can be 
* tailored
* T O   D O :  A D D   A   R E C I P E   T O   D O   T H I S
*
**************************************************************************************************************/

/****************************************************************************
wvlan_hcfcfg.h,v
Revision 1.4  2001/03/01 00:59:03  root
*** empty log message ***

Revision 1.3  2000/12/13 22:58:23  root
*** empty log message ***

Revision 1.2  2000/01/06 23:30:52  root
*** empty log message ***

 * 
 *    Rev 1.0   02 Feb 1999 14:32:32   NVALST
 * Initial revision.
Revision 1.2  1999/02/01 21:01:41  nico
*** empty log message ***

Revision 1.1  1999/01/30 19:24:39  nico
Initial revision

Revision 1.1  1999/01/30 19:07:57  nico
Initial revision

 * 
 *    Rev 1.110   29 Jan 1999 15:52:44   NVALST
 * intermediate, maybe working but seems to need two times to load in 
 * light-version
 * 
 *    Rev 1.109   29 Jan 1999 12:50:26   NVALST
 * intermediate
 * 
 *    Rev 1.108   28 Jan 1999 14:43:24   NVALST
 * intermediate, once more correction of loop in hcf_service_nic + download
 * passed to Marc
 * 
 *    Rev 1.107   27 Jan 1999 13:53:24   NVALST
 * intermediate, once more correction of loop in hcf_service_nic
 * 
 *    Rev 1.106   26 Jan 1999 16:42:46   NVALST
 * intermediate, corrected loop in hcf_service_nic (which was as result of a 
 * walkthrough, changed from a bug without consequences into one with consequences
 * 
 *    Rev 1.105   25 Jan 1999 14:24:48   NVALST
 * intermediate, hopefully suitable for release
 * 
 *    Rev 1.104   22 Jan 1999 16:59:34   NVALST
 * intermediate, minor corrections + some HCF-L stuff
 * 
 *    Rev 1.103   15 Jan 1999 15:14:46   NVALST
 * intermediate, deposited as HCF2.10
 * 
*************************************************************************************************/


/****************************************************************************
*
* CHANGE HISTORY
*

  960702 - NV
	Original Entry - derived from HCF 2.12
*************************************************************************************************/


/*  * * * * * * * * * * * * * * * * * * * * * *  I * * * * * * * * * * * * * * * * * * * * * * */

/*	Endianess
 *	Default: HCF_LITTLE_ENDIAN
 *	Little Endian (a.k.a. Intel), least significant byte first
 *	Big Endian (a.k.a. Motorola), most significant byte first
 *
 * If neither HCF_LITTLE_ENDIAN nor HCF_BIG_ENDIAN, the defintion of the following macros must be supplied
 * by the MSF programmer:
 *  o CNV_LITTLE_TO_INT(w)			interprets the 16-bits input value as Little Endian, returns an hcf_16
 * 	o CNV_BIG_TO_INT(w)				interprets the 16-bits input value as Big Endian, returns an hcf_16
 * 	o CNV_INT_TO_BIG_NP(addr)		converts in place the 16-bit value addressed by a near pointer from hcf_16
 * 									to Big Endian
 * 	o CNV_LITTLE_TO_INT_NP(addr)	converts in place the 16-bit value addressed by a near pointer from 
 *									Little endian to hcf_16
 *
 * At a number of places in the HCF code, the CNV_INT_TO_BIG_NP macro is used. While it does have the desired 
 * effect on all platforms, it's naming is misleading, so revisit all places where these CNV macros are used
 * to assure the right name is used at the right place.
 * Hint: introduce CNV_HOST_TO_NETWORK names if appropriate
 *
 */

#ifdef __BIG_ENDIAN
#define HCF_BIG_ENDIAN				// selects Big Endian (a.k.a. Motorola), most significant byte first
#else
#define HCF_LITTLE_ENDIAN			// selects Little Endian (a.k.a. Intel), least significant byte first
#endif

/*	I/O Address size
 *	Platforms which use port mapped I/O will (in general) have a 64k I/O space, conveniently expressed in
 *	a 16-bits quantity
 *	Platforms which use memory mapped I/O will (in general) have an I/O space much larger than 64k,
 *	and need a 32-bits quantity to express the I/O base
 *	To accomodate this the macros HCF_PORT_IO and HCF_MEM_IO are available. Exactly 1 of these must be
 *	defined. If HCF_PORT_IO is defined, the HCF will use an hcf_16 to express I/O base and store in the
 *	IFB. If HCF_MEM_IO, an hcf_32 is used for this purpose. The default is HCF_PORT_IO
 */
#define HCF_PORT_IO
//#define HCF_MEM_IO

/*	Alignment
 *	Some platforms can access words on odd boundaries (with possibly an performance impact), at other
 *	platforms such an access may result in a memory access violation.
 *	It is assumed that everywhere where the HCF casts a char pointer into a word pointer, the 
 *	alignment criteria are met. This put some restrictions on the MSF, which are assumed to be 
 *	"automatically" fullfilled at the applicable platforms
 *	To assert this assumption, the macro HCF_ALIGN can be defined. The default vaslue is 0, meaning no
 *	alignment, a value of 2 means word alignment, other values are invalid
 */

/*  * * * * * * * * * * * * * * * * * * * * * * II * * * * * * * * * * * * * * * * * * * * * * */



/************************************************************************************************/
/******************  C O M P I L E R   S P E C I F I C   M A C R O S  ***************************/
/************************************************************************************************/
/*************************************************************************************************
*
* The platforms supported by this version are:
*	- Microsoft Visual C 1.5 (16 bits platform)
*	- Microsoft Visual C 2.0 (32 bits platform)
*	- Watcom C/C++ 9.5
*	- SCO UNIX
*
* In this version of hcfiocfg.tpl all macros except the MSVC 1.5 versions are either dependent on
* compiler/environment supplied macros (e.g. _MSC_VER or "def-ed out"
*
* By selecting the appropriate Macro definitions by means of modifying the
* "#ifdef 0/1" lines, the HCF can be adjusted for the I/O chararcteristics of
* a specific compiler
*
* If needed the macros can be modified or replaced with definitions appropriate
* for your personal platform
* If you need to make such changes it is appreciated if you inform Lucent Technologies WCND Utrecht
* That way the changes can become part of the next release of the WCI
*
*
*	The prototypes and functional description of the macros are:
*
*	hcf_8	IN_PORT_BYTE(  hcf_16 port)
*			Reads a byte (8 bits) from the specified port
*
*	hcf_16	IN_PORT_WORD(  hcf_16 port)
*			Reads a word (16 bits) from the specified port
*
*	void	OUT_PORT_BYTE( hcf_16 port, hcf_8 value)
*			Writes a byte (8 bits) to the specified port
*
*	void	OUT_PORT_WORD( hcf_16 port, hcf_16 value)
*			Writes a word (16 bits) to the specified port
*
*	void	IN_PORT_STRING( port, dest, len)
*			Reads len number of words from the specified port to the (FAR) address dest in PC-RAM
*			Note that len specifies the number of words, NOT the number of bytes
*			!!!NOTE, although len specifies the number of words, dest MUST be a char pointer NOTE!!!
*			See also the common notes for IN_PORT_STRING and OUT_PORT_STRING
*
*	void	OUT_PORT_STRING( port, src, len)
*			Writes len number of words from the (FAR) address src in PC-RAM to the specified port
*			Note that len specifies the number of words, NOT the number of bytes.
*			!!!NOTE, although len specifies the number of words, src MUST be a char pointer NOTE!!!
*
*			The peculiar combination of word-length and char pointers for IN_PORT_STRING as well as
*			OUT_PORT_STRING is justified by the assumption that it offers a more optimal algorithm
*
*			Note to the HCF-implementor:
*			Due to the passing of the parameters to compiler specific blabla.........
*			do not use "expressions" as parameters, e.g. don't use "ifbp->IFB_IOBase + HREG_AUX_DATA" but
*			assign this to a temporary variable.
*
*
*  NOTE!!	For convenience of the MSF-programmer, all {IN|OUT}_PORT_{BYTE|WORD|STRING} macros are allowed to 
*			modify their parameters (although some might argue that this would constitute bad coding
*			practice). This has its implications on the HCF, e.g. as a consequence these macros should not
*			be called with parameters which have side effects, e.g auto-increment.
*
*  NOTE!!	in the Micosoft implementation of inline assembly it is O.K. to corrupt all flags except
*			the direction flag and to corrupt all registers except the segment registers and EDI, ESI, 
*			ESP and EBP (or their 16 bits equivalents).
*			Other environments may have other constraints
*
*  NOTE!!	in the Intel environment it is O.K to have a word (as a 16 bits quantity) at a byte boundary, 
*			hence IN_/OUT_PORT_STRING can move words between PC-memory and NIC-memory with as only
*			constraint that the words are on a word boundary in NIC-memory. This does not hold true
*			for all conceivalble environments, e.g. an Motorola 68xxx does not allow this, in other
*			words whenever there is a move from address in 2*n in one memory type to address 2*m+1 in the
*			other type, the current templates for IN_/OUT_PORT_STRING are unsuitable. Probably the
*			boundary conditions imposed by these type of platforms prevent this case from materializing
*
*************************************************************************************************/

/************************************************************************************************/
/****************************  N E T W A R E   3 8 6  *******************************************/
/************************************************************************************************/

#if defined  __NETWARE_386__	/* WATCOM */

#define	MSF_COMPONENT_ID			COMP_ID_ODI_32
#define HCF_STA						//station characteristics

#include <conio.h>

//#define CNV_LITTLE_TO_INT(x) (x)			// No endianess conversion needed

typedef unsigned char				hcf_8;
typedef unsigned short				hcf_16;
typedef unsigned long				hcf_32;

#define FAR							// flat 32-bits code
#define BASED 

#define IN_PORT_BYTE(port)			((hcf_8)inp( (hcf_io)(port) ))  //;?leave out cast to hcf_8;?
#define IN_PORT_WORD(port)			(inpw( (hcf_io)(port) ))
#define OUT_PORT_BYTE(port, value)	(outp( (hcf_io)(port), value ))
#define OUT_PORT_WORD(port, value)	(outpw( (hcf_io)(port), value ))

#define IN_PORT_STRING( prt, dst, n)	while ( n-- ) { *(hcf_16 FAR*)dst = IN_PORT_WORD( prt ); dst += 2; }
#define OUT_PORT_STRING( prt, src, n)	while ( n-- ) { OUT_PORT_WORD( prt, *(hcf_16 FAR*)src ) ; src  += 2; }

#endif	// __NETWARE_386__


// Note:
// Visual C++ 1.5 : _MSC_VER ==  800
// Visual C++ 4.0 : _MSC_VER == 1000
// Visual C++ 4.2 : _MSC_VER == 1020


/************************************************************************************************/
/****************************  P A C K E T   D R I V E R  ***************************************/
/**********************************  D O S   O D I  *********************************************/
/************************************************************************************************/

#if defined WVLAN_42 || defined WVLAN_43|| defined WVLAN43L

#pragma warning ( disable: 4001 )
										
#define HCF_STA						//station characteristics

#if defined WVLAN_43
#define	MSF_COMPONENT_ID			COMP_ID_ODI_16
#define	MSF_COMPONENT_VAR			1
#define	MSF_COMPONENT_MAJOR_VER		1
#define	MSF_COMPONENT_MINOR_VER		4

#elif defined WVLAN_42
#define	MSF_COMPONENT_ID			COMP_ID_PACKET
#define	MSF_COMPONENT_VAR			1
#define	MSF_COMPONENT_MAJOR_VER		1
#define	MSF_COMPONENT_MINOR_VER		24

#elif defined WVLAN43L
#define	HCF_MAX_CONFIG				0

#define	MSF_COMPONENT_MAJOR_VER		0
#define	MSF_COMPONENT_MINOR_VER		1

#endif //WVLAN_xx
										
#define FAR  __far					// segmented 16 bits mode
#if defined _M_I86TM
#define BASED __based(__segname("_CODE"))
#else
#define BASED 
#endif // _M_I86TM

typedef unsigned char				hcf_8;
typedef unsigned short				hcf_16;
typedef unsigned long				hcf_32;

#include <stdio.h>
#include <conio.h>
//#ifndef _DEBUG 
#pragma intrinsic( _inp, _inpw, _outp, _outpw )
//#endif // _DEBUG

#define IN_PORT_BYTE(port)			((hcf_8)_inp( (hcf_io)(port) ))
#define IN_PORT_WORD(port)			((hcf_16)_inpw( (hcf_io)(port) ))
#define OUT_PORT_BYTE(port, value)	((void)_outp( (hcf_io)(port), value ))
#define OUT_PORT_WORD(port, value)	((void)_outpw( (hcf_io)(port), value ))

#if defined HCF_STRICT
#define IN_PORT_STRING( prt, dst, n)	{ ips( prt, dst, n); }
#define OUT_PORT_STRING( prt, dst, n)	{ ops( prt, dst, n); }
#elif 0												// C implementation
#define IN_PORT_STRING( prt, dst, n)	while ( n-- ) { *(hcf_16 FAR*)dst = IN_PORT_WORD( prt ); dst += 2; }
#define OUT_PORT_STRING( prt, src, n)	while ( n-- ) { OUT_PORT_WORD( prt, *(hcf_16 FAR*)src ) ; src  += 2; }
//;?  WHY hcf_16 FAR*)src and not unsigned char FAR*)src
#else												// Assembler implementation
#define IN_PORT_STRING( port, dest, len) __asm 		\
{													\
	__asm push di                               	\
	__asm push es                                 	\
	__asm mov cx,len                            	\
	__asm les di,dest                           	\
	__asm mov dx,port                           	\
	__asm rep insw                              	\
	__asm pop es	                            	\
	__asm pop di	                            	\
}

#define OUT_PORT_STRING( port, src, len) __asm		\
{                                               	\
	__asm push si                                 	\
	__asm push ds                                 	\
	__asm mov cx,len                              	\
	__asm lds si,src                             	\
	__asm mov dx,port                             	\
	__asm rep outsw	                            	\
	__asm pop ds                                  	\
	__asm pop si                                  	\
}

#endif	// Asm or C implementation

#endif	/* WVLAN_43, WVLAN_42 (DOS ODI, Packet Driver) */


/************************************************************************************************/
/*************************************  W C I T S T *********************************************/
/************************************************************************************************/

#if defined WCITST

#pragma warning ( disable: 4001 )
										
#define HCF_STA						//station characteristics
#define HCF_AP						//AccesPoint characteristics

#if _CONSOLE
#define FAR							// flat 32 bits mode  (also defined in WINDEF.H)
#define BASED 
#else
#define FAR  __far					// segmented 16 bits mode
#if defined _M_I86TM
#define BASED __based(__segname("_CODE"))
#else
#define BASED 
#endif // _M_I86TM
#endif  //_CONSOLE

typedef unsigned char				hcf_8;
typedef unsigned short				hcf_16;
typedef unsigned long				hcf_32;

#include <stdio.h>
#include <conio.h>
#ifndef _DEBUG
#pragma intrinsic( _inp, _inpw, _outp, _outpw )
#endif // _DEBUG

#ifdef LOG
extern FILE* utm_logfile;
hcf_16	ipw( hcf_16 port );
hcf_8	ipb( hcf_16 port );
void	opw( hcf_16 port, hcf_16 value );
void	opb( hcf_16 port, hcf_8 value );

#define IN_PORT_BYTE(port)			ipb( (hcf_io)(port) )
#define IN_PORT_WORD(port)			ipw( (hcf_io)(port) )
#define OUT_PORT_BYTE(port, value)	opb( (hcf_io)(port), (hcf_8)(value) )
#define OUT_PORT_WORD(port, value)	opw( (hcf_io)(port), (hcf_16)(value) )
#else //LOG
#define IN_PORT_BYTE(port)			((hcf_8)_inp( (hcf_io)(port) ))
#define IN_PORT_WORD(port)			((hcf_16)_inpw( (hcf_io)(port) ))
#define OUT_PORT_BYTE(port, value)	((void)_outp( (hcf_io)(port), value ))
#define OUT_PORT_WORD(port, value)	((void)_outpw( (hcf_io)(port), value ))
#endif //LOG

#define	toch_maar_geen_asm
#if defined(toch_maar_asm)  && !defined(__DA_C__)  //;? temporary solution to satisfy DA-C
#define IN_PORT_STRING( port, dest, len) __asm 		\
{													\
	__asm push di                               	\
	__asm push es                                 	\
	__asm mov cx,len                            	\
	__asm les di,dest                           	\
	__asm mov dx,port                           	\
	__asm rep insw                              	\
	__asm pop es	                            	\
	__asm pop di	                            	\
}

#define OUT_PORT_STRING( port, src, len) __asm		\
{                                               	\
	__asm push si                                 	\
	__asm push ds                                 	\
	__asm mov cx,len                              	\
	__asm lds si,src                             	\
	__asm mov dx,port                             	\
	__asm rep outsw	                            	\
	__asm pop ds                                  	\
	__asm pop si                                  	\
}

#else	//toch_maar_asm  && !__DA_C__
#define IN_PORT_STRING( prt, dst, n)	while ( n-- ) { *(hcf_16 FAR*)dst = IN_PORT_WORD( prt ); dst += 2; }
#define OUT_PORT_STRING( prt, src, n)	while ( n-- ) { OUT_PORT_WORD( prt, *(hcf_16 FAR*)src ) ; src  += 2; }
//;?  WHY hcf_16 FAR*)src and not unsigned char FAR*)src
#endif	//toch_maar_asm  && !__DA_C__

#endif	/* WCITST */

/************************************************************************************************/
/********************************************  W S U  *******************************************/
/************************************************************************************************/

#if 0 //;? conflicts with WIN_CE _MSC_VER >= 1000 	/* Microsoft Visual C ++ 4.x, 5.x */

// Note:
// Visual C++ 4.0 : _MSC_VER == 1000
// Visual C++ 4.2 : _MSC_VER == 1020

										
#pragma warning ( disable: 4001 )
										
#define HCF_STA						//station characteristics

//#if defined WVLAN_43
//#define	MSF_COMPONENT_ID			COMP_ID_ODI_16
//#else if defined WVLAN_42
//#define	MSF_COMPONENT_ID			COMP_ID_PACKET
//#endif //WVLAN_xx
										
#if !defined FAR
//#if _CONSOLE
//#define FAR							// flat 32 bits mode  (also defined in WINDEF.H)
//#define BASED 
//#else
#define FAR							// far is an obsolete key in Visual C++ 4.x
//#if defined _M_I86TM
//#define BASED __based(__segname("_CODE"))
//#else
#define BASED 
//#endif // _M_I86TM
//#endif  //_CONSOLE
#endif	//!defined FAR

typedef unsigned char				hcf_8;
typedef unsigned short				hcf_16;
typedef unsigned long				hcf_32;

#include <stdio.h>
#include <conio.h>

#define IN_PORT_BYTE(port)			((hcf_8)_inp( (hcf_io)(port) ))
#define IN_PORT_WORD(port)			((hcf_16)_inpw( (hcf_io)(port) ))
#define OUT_PORT_BYTE(port, value)	((void)_outp( (hcf_io)(port), value ))
#define OUT_PORT_WORD(port, value)	((void)_outpw( (hcf_io)(port), value ))

#define	toch_maar_geen_asm
#if defined(toch_maar_asm)
#define IN_PORT_STRING( port, dest, len) __asm 		\
{													\
	__asm push di                               	\
	__asm push es                                 	\
	__asm mov cx,len                            	\
	__asm les di,dest                           	\
	__asm mov dx,port                           	\
	__asm rep insw                              	\
	__asm pop es	                            	\
	__asm pop di	                            	\
}

#define OUT_PORT_STRING( port, src, len) __asm		\
{                                               	\
	__asm push si                                 	\
	__asm push ds                                 	\
	__asm mov cx,len                              	\
	__asm lds si,src                             	\
	__asm mov dx,port                             	\
	__asm rep outsw	                            	\
	__asm pop ds                                  	\
	__asm pop si                                  	\
}

#else	//toch_maar_asm
#define IN_PORT_STRING( prt, dst, n)	while ( n-- ) { *(hcf_16 FAR*)dst = IN_PORT_WORD( prt ); dst += 2; }
#define OUT_PORT_STRING( prt, src, n)	while ( n-- ) { OUT_PORT_WORD( prt, *(hcf_16 FAR*)src ) ; src  += 2; }
//;?  WHY hcf_16 FAR*)src and not unsigned char FAR*)src
#endif	//toch_maar_asm

#endif	/* _MSC_VER >= 1000 (Microsoft Visual C++ 4.0 ) */




/************************************************************************************************/
/******************************************  L I N U X  *****************************************/
/************************************************************************************************/

#if defined __linux__

#define HCF_STA						//station characteristics
#define	MSF_COMPONENT_ID	COMP_ID_LINUX
#define	MSF_COMPONENT_VAR			1
#define	MSF_COMPONENT_MAJOR_VER		0
#define	MSF_COMPONENT_MINOR_VER		4

#include <asm/io.h>

#define FAR							// flat 32-bits code
#define BASED 

typedef unsigned char				hcf_8;
typedef unsigned short				hcf_16;
typedef unsigned long				hcf_32;

#define IN_PORT_BYTE(port)		((hcf_8)inb((hcf_io)(port)))
#define IN_PORT_WORD(port)		((hcf_16)inw((hcf_io)(port)))
#define OUT_PORT_BYTE(port, value)	outb((hcf_8)(value), (hcf_io)(port))
#define OUT_PORT_WORD(port, value)	outw((hcf_16)(value), (hcf_io)(port))

#define IN_PORT_STRING			insw
#define OUT_PORT_STRING			outsw

#endif	/* LINUX */



/************************************************************************************************/
/********************************** S C O   U N I X  ********************************************/
/************************************************************************************************/

#if 0

#define HCF_STA						//station characteristics
#define	MSF_COMPONENT_ID

//#define CNV_LITTLE_TO_INT(x)			// No endianess conversion needed										

#define FAR							// flat 32-bits code
#define BASED 

typedef unsigned char				hcf_8;
typedef unsigned short				hcf_16;
typedef unsigned long				hcf_32;

#define IN_PORT_BYTE(port)			((hcf_8)inb( (hcf_io)(port) ))
#define IN_PORT_WORD(port)			((hcf_16)inw( (hcf_io)(port) ))
#define OUT_PORT_BYTE(port, value)	(outb( (hcf_io)(port), (hcf_8) (value) ))
#define OUT_PORT_WORD(port, value)	(outw( (hcf_io)(port), (hcf_16) (value) ))

#define FAR							// flat 32-bits code
#define BASED 


#endif	/* SCO UNIX */


/************************************************************************************************/
/*********************************  M I N I P O R T  ********************************************/
/************************************************************************************************/

#if 0

#define	MSF_COMPONENT_ID			COMP_ID_MINIPORT
#define HCF_STA						//station characteristics

#include <ndis.h>
#include <version.h>

#define	MSF_COMPONENT_VAR			1
#define	MSF_COMPONENT_MAJOR_VER		TPI_MAJOR_VERSION
#define	MSF_COMPONENT_MINOR_VER		TPI_MINOR_VERSION


//#define CNV_LITTLE_TO_INT(x)			// No endianess conversion needed										

#if !defined FAR
#define FAR							// flat 32-bits code
#endif //!defined FAR

#define BASED 

__inline UCHAR NDIS_IN_BYTE( ULONG port )
{
    UCHAR value;
    NdisRawReadPortUchar(port , &value);
    return (value);
}

__inline USHORT NDIS_IN_WORD( ULONG port )
{
    USHORT value;
    NdisRawReadPortUshort(port , &value);
    return (value);
}

#define IN_PORT_BYTE(port)			NDIS_IN_BYTE( (ULONG) (port) )
#define IN_PORT_WORD(port)			NDIS_IN_WORD( (ULONG) (port) )
#define OUT_PORT_BYTE(port, value)	NdisRawWritePortUchar( (ULONG) (port) , (UCHAR) (value))
#define OUT_PORT_WORD(port, value)	NdisRawWritePortUshort((ULONG) (port) , (USHORT) (value))

#define IN_PORT_STRING(port, addr, len)		NdisRawReadPortBufferUshort(port, addr, (len));
#define OUT_PORT_STRING(port, addr, len)	NdisRawWritePortBufferUshort(port, addr, (len));

typedef UCHAR	hcf_8;
typedef USHORT	hcf_16;
typedef ULONG	hcf_32;

#endif	/* MINIPORT */

/************************************************************************************************/
/*********************************  W A V E P O I N T  ******************************************/
/************************************************************************************************/

#if defined WVLAN_81	/* BORLANDC */

#define HCF_AP						//access point characteristics
#define	MSF_COMPONENT_ID	COMP_ID_AP1
#define	MSF_COMPONENT_VAR			1
#define	MSF_COMPONENT_MAJOR_VER		3
#define	MSF_COMPONENT_MINOR_VER		34

#include <dos.h>

//#define CNV_LITTLE_TO_INT(x)			// No endianess conversion needed										

typedef unsigned char				hcf_8;
typedef unsigned short				hcf_16;
typedef unsigned long				hcf_32;

//#define HCF_ASSERT					0  /* debug build only */

#if !defined FAR
#define FAR  far					// segmented 16 bits mode
#endif //!defined FAR
#define BASED 


#define IN_PORT_BYTE(port)					(inportb( (hcf_io)(port) ))
#define IN_PORT_WORD(port)					(inport( (hcf_io)(port) ))
#define OUT_PORT_BYTE(port, value)      	(outportb( (hcf_io)(port), value ))
#define OUT_PORT_WORD(port, value)      	(outport( (hcf_io)(port), value ))

#define IN_PORT_STRING(port, addr, len) 	\
	asm { push di; push es; mov cx,len; les di,addr; mov dx,port; rep insw; pop es; pop di }

#define OUT_PORT_STRING(port, addr, len)	\
	asm { push si; push ds; mov cx,len; lds si,addr; mov dx,port; rep outsw; pop ds; pop si }

#endif /* WavePoint */

/************************************************************************************************/
/**************************  MPC860 - Diab or High C 29K   **************************************/
/************************************************************************************************/

#if defined(__ppc) || defined(_AM29K) //|| (CPU == PPC860)

#define HCF_AP						//AccesPoint characteristics
#define MSF_COMPONENT_VAR       0
#define MSF_COMPONENT_ID        0
#define MSF_COMPONENT_MAJOR_VER 1
#define MSF_COMPONENT_MINOR_VER 0

#define FAR			// flat 32-bits code
#define BASED

typedef unsigned char				hcf_8;
typedef unsigned short				hcf_16;
typedef unsigned long				hcf_32;

#define SwapBytes(t)    /*lint -e572*/(((t) >> 8) + (((t) & 0xff) << 8))/*lint +e572*/

#if defined(__ppc) || (CPU == PPC860)
    #ifndef __GNUC__
        #define __asm__     asm
    #endif

    #if !defined(_lint)
        #define EIEIO()     __asm__(" eieio")
    #else
        #define EIEIO()
    #endif

    hcf_8 IN_PORT_BYTE(int port) {
        hcf_8 value = *(volatile hcf_8 *)(port); EIEIO();
        return value;
    }

    hcf_16 IN_PORT_WORD(int port) {
        hcf_16 value = *(volatile hcf_16 *)(port); EIEIO();
        value = SwapBytes(value);
        return value;
    }

    #define OUT_PORT_BYTE(port, value) { *(volatile hcf_8 *)(port) = (value); EIEIO(); }
    #define OUT_PORT_WORD(port, value)      \
            { *(volatile hcf_16 *)(port) = SwapBytes(value); EIEIO(); }
#else
    #define IN_PORT_BYTE(port) (*(volatile hcf_8 *)(port))
    #define IN_PORT_WORD(port) (*(volatile hcf_16 *)(port))
    #define OUT_PORT_BYTE(port, value) (*(volatile hcf_8 *)(port) = (value))
    #define OUT_PORT_WORD(port, value) (*(volatile hcf_16 *)(port) = (value))
#endif

/***************************************************************************/

#define IN_PORT_STRING( port, dest, len)        {                       \
                        unsigned l = (len);                             \
                        hcf_16 t, *d = (volatile hcf_16 *)(dest);       \
                        while (l--) {                                   \
                            t = IN_PORT_WORD(port);                     \
                            *d++ = SwapBytes(t);                        \
                        }                                               \
                                                }

#define OUT_PORT_STRING( port, src, len)        {                       \
                        unsigned l = (len);                             \
                        hcf_16 t, *s = (volatile hcf_16 *)(src);        \
                        while (l--) {                                   \
                            t = *s++;                                   \
                            OUT_PORT_WORD(port, SwapBytes(t));          \
                        }                                               \
                                                }

#if PRODUCT == 9150
    #define HCF_AP
    #define HCF_ASSERT
    #undef MSF_COMPONENT_ID
#endif

#endif	/* MPC860 - Diab or High C 29K */

/************************************************************************************************/
/***********************************  M A C  O S   **********************************************/
/************************************************************************************************/

        /**********/
#if 0   /* MAC_OS */
        /**********/

#define HCF_STA                     //station characteristics
#define MSF_COMPONENT_ID            COMP_ID_MAC_OS
#define MSF_COMPONENT_VAR           0
#define MSF_COMPONENT_MAJOR_VER     3
#define MSF_COMPONENT_MINOR_VER     0

#define MAC_OS                      1
#define FAR                         // flat 32-bits code
#define BASED

#undef  HCF_LITTLE_ENDIAN           // selects Little Endian (a.k.a. Intel), least significant byte first
#define HCF_BIG_ENDIAN              // selects Big Endian (a.k.a. Motorola), most significant byte first

#if defined(DEBUG)
#define HCF_ASSERT                  1
#endif // DEBUG

typedef unsigned char               hcf_8;
typedef unsigned short              hcf_16;
typedef unsigned long               hcf_32;

#ifdef  __cplusplus
extern "C" {
#endif
extern volatile unsigned char *MacIOaddr;
extern hcf_8  IN_PORT_BYTE(hcf_16 port);
extern void   OUT_PORT_BYTE(hcf_16 port, hcf_8 value);
extern hcf_16 IN_PORT_WORD(hcf_16 port);
extern void   OUT_PORT_WORD(hcf_16 port, hcf_16 value);
extern void   IN_PORT_STRING(hcf_16 port, void *dest, hcf_16 len);
extern void   OUT_PORT_STRING(hcf_16 port, void *src, hcf_16 len);

#define SwapBytes(t)    (((t) >> 8) + (((t) & 0xff) << 8))

#ifdef  __cplusplus
}
#endif

#endif  /* MAC_OS */

/************************************************************************************************/
/***********************************  W I N C E *************************************************/
/************************************************************************************************/

                  /*********/
#ifdef _WIN32_WCE /* WINCE */
                  /*********/

#define	MSF_COMPONENT_ID			COMP_ID_WIN_CE
#define HCF_STA						//station characteristics

#include <ndis.h>
#include <version.h>
#include <ntcompat.h>

#define	MSF_COMPONENT_VAR			1
#define	MSF_COMPONENT_MAJOR_VER		TPI_MAJOR_VERSION
#define	MSF_COMPONENT_MINOR_VER		TPI_MINOR_VERSION

#define BASED 

#undef  HCF_LITTLE_ENDIAN           // selects Little Endian (a.k.a. Intel), least significant byte first
#undef  HCF_BIG_ENDIAN              // selects Big Endian (a.k.a. Motorola), most significant byte first

#if defined(_SH3_) || defined (_SHx_) || defined(_MIPS_) || defined(_X86_)
#define HCF_LITTLE_ENDIAN
#endif

#if defined(DEBUG) || defined(_WIN32_WCE_DEBUG)
#define HCF_ASSERT                  1
#endif // DEBUG

typedef UCHAR   hcf_8;
typedef USHORT  hcf_16;
typedef ULONG   hcf_32;

#ifdef  __cplusplus
extern "C" {
#endif

#define WCE_IO_OFFSET   0x40
extern ULONG  WceIoAddr;

extern hcf_8  IN_PORT_BYTE(hcf_16 port);
extern void   OUT_PORT_BYTE(hcf_16 port, hcf_8 value);
extern hcf_16 IN_PORT_WORD(hcf_16 port);
extern void   OUT_PORT_WORD(hcf_16 port, hcf_16 value);
extern void   IN_PORT_STRING(hcf_16 port, void *dest, hcf_16 len);
extern void   OUT_PORT_STRING(hcf_16 port, void *src, hcf_16 len);

#ifdef  __cplusplus
}
#endif

#endif	/* _WIN32_WCE */


/*  * * * * * * * * * * * * * * * * * * * * * *  IV  * * * * * * * * * * * * * * * * * * * * * * */

/***************************************Compiler specific ****************************************/

#ifdef __cplusplus
#define EXTERN_C extern "C"
#else
#define EXTERN_C
#endif //__cplusplus
                                                                                                            

/************************************************************************************************/
/********** M A C R O S derived of C O M P I L E R   S P E C I F I C   M A C R O S  *************/
/************************************************************************************************/

typedef hcf_8  FAR *wci_bufp;			 // segmented 16-bits or flat 32-bits pointer to 8 bits unit
typedef hcf_16 FAR *wci_recordp;		 // segmented 16-bits or flat 32-bits pointer to 16 bits unit

typedef hcf_8  FAR *hcf_8fp;			 // segmented 16-bits or flat 32-bits pointer to 8 bits unit
typedef hcf_16 FAR *hcf_16fp;			 // segmented 16-bits or flat 32-bits pointer to 16 bits unit
typedef hcf_32 FAR *hcf_32fp;			 // segmented 16-bits or flat 32-bits pointer to 8 bits unit


#if defined HCF_STA && defined HCF_AP
#if defined WCITST
#pragma message( "you should also test both in isolation" )
#else
error; define exactly one of these terms;
#endif
#endif
#if ! defined HCF_STA && ! defined HCF_AP
error; define exactly one of these terms;
#endif

/*  * * * * * * * * * * * * * * * * * * * * * *  V  * * * * * * * * * * * * * * * * * * * * * * */

#if defined HCF_PORT_IO
#if defined HCF_MEM_IO
error;
#else
typedef hcf_16 hcf_io;
#endif //HCF_MEM_IO
#endif //HCF_PORT_IO
#if defined HCF_MEM_IO
#if defined HCF_PORT_IO
error;
#else
typedef hcf_32 hcf_io;
#endif //HCF_PORT_IO
#endif //HCF_MEM_IO



/* MSF_COMPONENT_ID is used to define the CFG_IDENTITY_STRCT in HCF.C
 * CFG_IDENTITY_STRCT is defined in HCF.C purely based on convenience arguments
 * The HCF can not have the knowledge to determine the ComponentId field of the
 * Identity record (aka as Version Record), therefore the MSF part of the Drivers
 * must supply this value via the System Constant MSF_COMPONENT_ID
 * There is a set of values predefined in MDD.H (format COMP_ID_.....)
 */

#if defined	MSF_COMPONENT_ID
#define	DUI_COMPAT_VAR				MSF_COMPONENT_ID
#define	DUI_COMPAT_BOT              4
#define	DUI_COMPAT_TOP              4
#endif // MSF_COMPONENT_ID

/************************************************************************************************/
/***************  E N V I R O N M E N T   S P E C I F I C   M A C R O S  ************************/
/************************************************************************************************/


#if defined HCF_ASSERT	//the next line may need modification for a specific environment
extern int	BASED HCF_VAR_0; //Revision 2.0 gives an explanation of the need for HCF_VAR_0
#endif

#if defined HCF_PROFILING
#endif

/************************************************************************************************/
/******  M S F    S U P P O R T    F U N C T I O N S    P R O T O T Y P E S   *******************/
/************************************************************************************************/

EXTERN_C void msf_assert ( wci_bufp file_namep, unsigned int line_number, hcf_16 trace, int qual );

/* To increase portability, use unsigned char and unsigned char * when accessing parts of larger
 * types to convert their Endianess
 */

#if defined HCF_BIG_ENDIAN
#if defined HCF_LITTLE_ENDIAN
	error
#else	//************************************* B I G   E N D I A N *******************************************
#define CNV_LITTLE_TO_INT(w)    ( ((hcf_16)(w) & 0x00ff) << 8 | ((hcf_16)(w) & 0xff00) >> 8 )
#define CNV_BIG_TO_INT(w)		(w)		// No endianess conversion needed

#define CNV_INT_TO_BIG_NP(addr)
#define CNV_LITTLE_TO_INT_NP(addr) {							\
	hcf_8 temp;													\
	temp = ((hcf_8 FAR *)(addr))[0];							\
	((hcf_8 FAR *)(addr))[0] = ((hcf_8 FAR *)(addr))[1];		\
	((hcf_8 FAR *)(addr))[1] = temp;							\
}

#endif // HCF_LITTLE_ENDIAN
#endif // HCF_BIG_ENDIAN

#if defined HCF_LITTLE_ENDIAN
#if defined HCF_BIG_ENDIAN
	error; 
#else	//************************************* L I T T L E   E N D I A N *************************************

#define CNV_LITTLE_TO_INT(w) 	(w)		// No endianess conversion needed
#define CNV_BIG_TO_INT(w)       ( ((hcf_16)(w) & 0x00ff) << 8 | ((hcf_16)(w) & 0xff00) >> 8 )

#define CNV_INT_TO_BIG_NP(addr) {								\
	hcf_8 temp;													\
	temp = ((hcf_8 FAR *)(addr))[0];							\
	((hcf_8 FAR *)(addr))[0] = ((hcf_8 FAR *)(addr))[1];		\
	((hcf_8 FAR *)(addr))[1] = temp;							\
}
#define CNV_LITTLE_TO_INT_NP(addr)

#endif // HCF_BIG_ENDIAN
#endif // HCF_LITTLE_ENDIAN

// conversion macros which can be expressed in other macros
#define CNV_INT_TO_LITTLE(w)	CNV_LITTLE_TO_INT(w)
#define CNV_INT_TO_BIG(w)		CNV_BIG_TO_INT(w)

#endif //HCFCFG_H

//******************************************* A L I G N M E N T  **********************************************
#if defined HCF_ALIGN 
#if HCF_ALIGN != 0 && HCF_ALIGN != 2
	error;
#endif // HCF_ALIGN != 0 && HCF_ALIGN != 2
#else
#define HCF_ALIGN 0			//default to no alignment
#endif // HCF_ALIGN  




/*  * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *	
 *	The routines ips and ops (short for InPutString and OutPutString) are created to use the 
 *	compiler to do the type checking. It turned out that it is too easy to accidentally pass
 *	a word pointer to the macros IN_PORT_STRING and OUT_PORT_STRING rather than a byte pointer.
 *	The "+2" as some macro implementations use, does not have the intended effect in those cases.
 *	The HCF_STRICT business can be ignored by MSF programmers.
 *	
 *  * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


#if defined HCF_STRICT
void ips( hcf_io prt, wci_bufp dst, int n);
void ops( hcf_io prt, wci_bufp src, int n);
#endif //HCF_STRICT







#if !defined HCF_MAX_CONFIG
#define HCF_MAX_CONFIG		256		// maximum accumulated size in hcf_16 of LTV records used in hcf_put_config
#endif

#if !defined HCF_MAX_MSG
#define HCF_MAX_MSG			2304	/* WaveLAN Pakket Size										*/
#endif

#if !defined HCF_MAX_NOTIFY		
#define HCF_MAX_NOTIFY		6		// maximum size in bytes of "real" data in Notify command
#endif
