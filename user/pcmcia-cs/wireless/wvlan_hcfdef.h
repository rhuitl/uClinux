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


#ifndef HCFDEFC_H
#define HCFDEFC_H 1


/*************************************************************************************************
*
* FILE	 : HCFDEFC.H *************** 2.0 *********************
*
* DATE   : 2000/01/06 23:30:53   1.2
*
* AUTHOR : Nico Valster
*
* DESC   : Definitions and Prototypes for HCF only
*
**************************************************************************************************
* COPYRIGHT (c) 1996, 1997, 1998 by Lucent Technologies.	 All Rights Reserved.
*************************************************************************************************/


/****************************************************************************
wvlan_hcfdef.h,v
Revision 1.2  2000/01/06 23:30:53  root
*** empty log message ***

 * 
 *    Rev 1.0   02 Feb 1999 14:32:34   NVALST
 * Initial revision.
Revision 1.1  1999/01/30 19:24:39  nico
Initial revision

Revision 1.1  1999/01/30 19:07:57  nico
Initial revision

 * 
 *    Rev 1.110   29 Jan 1999 15:52:44   NVALST
 * intermediate, maybe working but seems to need two times to load in 
 * light-version
 * 
 *    Rev 2.12   29 Jan 1999 10:48:44   NVALST
 * 
 *    Rev 1.108   28 Jan 1999 14:43:24   NVALST
 * intermediate, once more correction of loop in hcf_service_nic + download
 * passed to Marc
 * 
 *    Rev 2.11   27 Jan 1999 16:57:42   NVALST
 * 
 *    Rev 1.107   27 Jan 1999 13:53:24   NVALST
 * intermediate, once more correction of loop in hcf_service_nic
 * 
 *    Rev 1.106   26 Jan 1999 16:42:46   NVALST
 * intermediate, corrected loop in hcf_service_nic (which was as result of a 
 * walkthrough, changed from a bug without consequences into one with consequences
 * 
 *    Rev 1.105   25 Jan 1999 14:24:46   NVALST
 * intermediate, hopefully suitable for release
 * 
 *    Rev 1.104   22 Jan 1999 16:59:34   NVALST
 * intermediate, minor corrections + some HCF-L stuff
 * 
 *    Rev 1.103   15 Jan 1999 15:14:46   NVALST
 * intermediate, deposited as HCF2.10
 * 
 *    Rev 2.10   15 Jan 1999 14:54:34   NVALST
 * 
****************************************************************************/


/****************************************************************************
*
* CHANGE HISTORY
*
  961018 - NV
	Original Entry

**************************************************************************************************/

/************************************************************************************************/
/*********************************  P R E F I X E S  ********************************************/
/************************************************************************************************/
//IFB_		Interface Block
//HCMD_		Hermes Command
//HFS_		Hermes (Transmit/Receive) Frame Structure
//HREG_		Hermes Register

/*************************************************************************************************/


/************************************************************************************************/
/********************************* GENERAL EQUATES **********************************************/
/************************************************************************************************/
//#define STATIC			//;?cheap way out to get things compiled while intransition for ObjectOutline
//#if ! defined STATIC	//;? change to HCF_STATIC some day
//#if defined _DEBUG || defined OOL
#define STATIC		EXTERN_C
//#else
//#define STATIC		static
//#endif //_DEBUG
//#endif // STATIC


#define AUX_MAGIC_0				0xFE01
#define AUX_MAGIC_1				0xDC23
#define AUX_MAGIC_2				0xBA45
#define HCF_MAGIC				0x7D37	// "}7" Handle validation
#define DIAG_MAGIC				0x5A5A

#define	PLUG_DATA_OFFSET        0x3F0000L


#define ONE_SECOND				977		// 977 times a Hermes Timer Tick of 1K microseconds ~ 1 second
#define INI_TICK_INI			0x20000L

#define IO_IN					0		//hcfio_in_string
#define IO_OUT					1		//hcfio_out_string
#define IO_OUT_CHECK			2		//enable Data Corruption Detect on hcfio_out_string

#define CARD_STAT_ENA_PRES		(CARD_STAT_ENABLED|CARD_STAT_PRESENT)
#define CARD_STAT_PRI_PRES		(CARD_STAT_PRESENT|CARD_STAT_INCOMP_PRI)
#define CARD_STAT_PRI_STA_PRES	(CARD_STAT_PRI_PRES|CARD_STAT_INCOMP_STA)

#define DO_ASSERT				( ifbp->IFB_Magic != HCF_MAGIC && ifbp->IFB_Magic == HCF_MAGIC )	//FALSE without the nasty compiler warning

#define HCF_ASSERT_ACTION			0x0001
//#define HCF_ASSERT_CONNECT		no use to trace this
#define HCF_ASSERT_DISABLE			0x0002
#define HCF_ASSERT_DISCONNECT		0x0004
#define HCF_ASSERT_ENABLE			0x0008
#define HCF_ASSERT_GET_DATA			0x0010
#define HCF_ASSERT_GET_INFO			0x0020
#define HCF_ASSERT_INITIALIZE		0x0040
#define HCF_ASSERT_RESEND			0x0080
#define HCF_ASSERT_SERVICE_NIC		0x0100
#define HCF_ASSERT_PUT_DATA			0x0200
#define HCF_ASSERT_PUT_INFO			0x0400
#define HCF_ASSERT_PUT_HDR			0x0800
#define HCF_ASSERT_SEND				0x1000
#define HCF_ASSERT_SEND_DIAG_MSG	0x2000
#define HCF_ASSERT_INT_OFF			0x4000
#define HCF_ASSERT_MISC				0x8000	


#define	CFG_CONFIG_RID_MASK			0xFC00		//CONFIGURATION RECORDS

#define BAP_0					HREG_DATA_0		//Tx-related register set for WMAC buffer access
#define BAP_1					HREG_DATA_1		//non Tx-related register set for WMAC buffer access
/************************************************************************************************/
/***************************** STRUCTURES *******************************************************/
/************************************************************************************************/
                            
                            
//************************* Hermes Receive/Transmit Frame Structures
//HFS_STAT
//see MMD.H for HFS_STAT_ERR
#define 	HFS_STAT_MSG_TYPE	0xE000	//Hermes reported Message Type
#define 	HFS_STAT_1042		0x2000	//RFC1042 Encoded
#define 	HFS_STAT_TUNNEL		0x4000	//Bridge-Tunnel Encoded
#define 	HFS_STAT_WMP_MSG	0x6000	//WaveLAN-II Management Protocol Frame

//HFS_TX_CNTL
//see ENC_802_3/ENC_802_11 definition
                            
                            
//************************* Hermes Register Offsets and Command bits
#define HREG_IO_RANGE			0x40		//I/O Range used by Hermes


//************************* Command/Status
#define HREG_CMD				0x00		//
#define 	HCMD_CMD_CODE			0x3F
#define HREG_PARAM_0			0x02		//
#define HREG_PARAM_1			0x04		//
#define HREG_PARAM_2			0x06		//
#define HREG_STAT				0x08		//
#define 	HREG_STAT_CMD_CODE		0x003F	//
#define		HREG_STAT_DIAG_ERR		0x0100
#define		HREG_STAT_INQUIRE_ERR	0x0500
#define 	HREG_STAT_CMD_RESULT	0x7F00	//
#define HREG_RESP_0				0x0A		//
#define HREG_RESP_1				0x0C		//
#define HREG_RESP_2				0x0E		//


//************************* FID Management
#define HREG_INFO_FID			0x10		//
#define HREG_RX_FID				0x20		//
#define HREG_ALLOC_FID  		0x22		//
//rsrvd #define HREG_TX_COMPL_FID  	0x24		//


//************************* BAP
#define HREG_SELECT_0			0x18		//
#define HREG_OFFSET_0			0x1C		//
//#define 	HREG_OFFSET_BUSY		0x8000	// use HCMD_BUSY
#define 	HREG_OFFSET_ERR			0x4000	//
//rsrvd #define 	HREG_OFFSET_DATA_OFFSET	0x0FFF	//

#define HREG_DATA_0				0x36		//
//rsrvd #define HREG_SELECT_1	0x1A		//
//rsrvd #define HREG_OFFSET_1	0x1E		//

#define HREG_DATA_1				0x38		//


//************************* Event
#define HREG_EV_STAT			0x30		//
#define HREG_INT_EN				0x32		//
#define HREG_EV_ACK				0x34		//


//************************* Host Software
#define HREG_SW_0				0x28		//
#define HREG_SW_1				0x2A		//
#define HREG_SW_2				0x2C		//
//rsrvd #define HREG_SW_3		0x2E		//
//************************* Control and Auxiliary Port

#define HREG_CNTL				0x14		//
#define		HREG_CNTL_AUX_ENA		0xC000
#define		HREG_CNTL_AUX_ENA_STAT	0xC000
#define		HREG_CNTL_AUX_DIS_STAT	0x0000
#define		HREG_CNTL_AUX_ENA_CNTL	0x8000
#define		HREG_CNTL_AUX_DIS_CNTL	0x4000
#define HREG_AUX_PAGE			0x3A		//
#define HREG_AUX_OFFSET			0x3C		//
#define HREG_AUX_DATA			0x3E		//


/************************************************************************************************/
/***************************** END OF STRUCTURES ***********************************************/
/************************************************************************************************/


/************************************************************************************************/
/**********************************  EQUATES  ***************************************************/
/************************************************************************************************/

// Tx/Rx frame Structure
//
#define HFS_STAT_ABS		(0x2E + HFS_STAT)    		//0x0000
#define HFS_Q_INFO_ABS		(0x2E + HFS_Q_INFO)			//0x0006
#define HFS_TX_CNTL_ABS		(0x2E + HFS_TX_CNTL)		//0x000C
#define HFS_FRAME_CNTL_ABS	(0x2E + HFS_FRAME_CNTL)		//0X000E
#define HFS_ID_ABS			(0x2E + HFS_ID)				//0X0010

#define HFS_ADDR_1_ABS		(0x12 + HFS_ADDR_1)  		//0x0012
#define HFS_ADDR_2_ABS		(0x12 + HFS_ADDR_2)  		//0x0018
#define HFS_ADDR_3_ABS		(0x12 + HFS_ADDR_3)  		//0x001E
#define HFS_SEQ_CNTL_ABS	(0x12 + HFS_SEQ_CNTL)		//0x0024
#define HFS_ADDR_4_ABS		(0x12 + HFS_ADDR_4) 		//0x0026
#define HFS_DAT_LEN_ABS		(0x12 + HFS_DAT_LEN)		//0x002C

#define HFS_ADDR_DEST_ABS   (0x2E + HFS_ADDR_DEST)		//0x002E
#define HFS_ADDR_SRC_ABS    (0x2E + HFS_ADDR_SRC)		//0x0034
#define HFS_LEN_ABS	       	(0x2E + HFS_LEN)			//0x003A
#define HFS_DAT_ABS	       	(0x2E + HFS_DAT)			//0x003C
#define HFS_TYPE_ABS	    (0x2E + HFS_TYPE)			//0x0042	Eternet-II type in 1042/Bridge-Tunnel encapsulated frame

#define HFS_802_11_GAP		(HFS_DAT_ABS  - HFS_ADDR_DEST_ABS)
#define HFS_E_II_GAP       	(HFS_TYPE_ABS - HFS_LEN_ABS)

#define KLUDGE_MARGIN		8							//safety margin for Tx Data Corruption workaround

#define HFS_TX_ALLOC_SIZE	HCF_MAX_MSG + HFS_DAT_ABS + KLUDGE_MARGIN

// IFB field related
//		IFB_TxFrameType
//#define ENC_TX_802_3           	0x00
//#define ENC_TX_802_11         	0x11
#define ENC_TX_E_II				0x0E	//encapsulation flag

// SNAP header for E-II Encapsulation
#define ENC_TX_1042             0x00
#define ENC_TX_TUNNEL           0xF8

// Hermes Command Codes and Qualifier bits
#define 	HCMD_BUSY			0x8000	// Busy bit, applicable for all commands
#define 	HCMD_RECL			0x0100	// Reclaim bit, applicable for Tx and Inquire

#define HCMD_INI				0x0000	//
#define HCMD_ENABLE				0x0001	//
#define HCMD_DISABLE			0x0002	//
#define HCMD_DIAG				0x0003	//
#define HCMD_ALLOC				0x000A	//
#define HCMD_TX					0x000B	//
#define HCMD_NOTIFY				0x0010	//
#define HCMD_INQUIRE			0x0011	//
#define HCMD_ACCESS				0x0021	//
#define 	HCMD_ACCESS_WRITE		0x0100	//
#define HCMD_PROGRAM			0x0022	//
#define 	HCMD_PROGRAM_DISABLE				0x0000	//
#define 	HCMD_PROGRAM_ENABLE_VOLATILE	 	0x0100	//
#define 	HCMD_PROGRAM_ENABLE_NON_VOLATILE	0x0200	//
#define 	HCMD_PROGRAM_NON_VOLATILE			0x0300	//

// Miscellanuos 
//
#define REV_OFFSET 16					// offset of Major version within the PVCS generated Version String


/************************************************************************************************/
/**********************************  END OF EQUATES  ********************************************/
/************************************************************************************************/


/************************************************************************************************/
/**************************************  MACROS  ************************************************/
/************************************************************************************************/

/************************************************************************************************
	DEBUG_INT is an undocumented feature to assist the HCF debugger
	By expanding INT_3 to either an "int 3" or a NOP, it is very easy to check
	by means of a binary file compare whether a "debug" version really corresponds
	with a "non-debug" version.
	;? is is currently unknown whether there is a real reason to restrict this
	implemenation to the MSVC environment
*/
#if defined (_MSC_VER)
#ifdef DEBUG_INT
//#pragma message( Reminder "int 3, should be removed before releasing" )
#define INT_3 __asm int 3
#else
#define INT_3 __asm nop
#endif /*DEBUG_INT*/
#else
#define INT_3
#endif /*_MSC_VER*/

#define MUL_BY_2( x )	( (x) << 1 )	//used to multiply by 2
#define DIV_BY_2( x )	( (x) >> 1 )	//used to divide by 2

/************************************************************************************************/
/**************************************  END OF MACROS  *****************************************/
/************************************************************************************************/

/************************************************************************************************/
/***************************************  PROTOTYPES  *******************************************/
/************************************************************************************************/

int 	hcfio_string( IFBP ifbp, int bap, int fid, int offset, wci_bufp pc_addr, int wlen, int blen, int type );


#endif	//HCFDEFC_H
