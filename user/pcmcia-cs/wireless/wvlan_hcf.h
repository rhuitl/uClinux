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


#ifndef HCF_H
#define HCF_H 1

/*************************************************************************************************************
*
* FILE	 : hcf.h *************** 2.0 *************************************************************************
*
* DATE   : 2000/01/06 23:30:52   1.2
*
* AUTHOR : Nico Valster
*
* DESC   : Definitions and Prototypes for MSF as well as HCF sources
*
*			Customizable via HCFCFG.H
*
*
**************************************************************************************************************
Instructions to convert HCF.H to HCF.INC by means of H2INC

Use a command line which defines the specific macros and command line options
needed to build the C-part, e.g. for the DOS ODI driver
		`h2inc /C /Ni /Zp /Zn hcf	 hcf.h`


**************************************************************************************************************
* COPYRIGHT (c) 1996, 1997, 1998 by Lucent Technologies.	 All Rights Reserved.
**************************************************************************************************************/

/****************************************************************************
wvlan_hcf.h,v
Revision 1.2  2000/01/06 23:30:52  root
*** empty log message ***

 * 
 *    Rev 1.0   02 Feb 1999 14:32:30   NVALST
 * Initial revision.
Revision 1.2  1999/02/01 22:58:35  nico
*** empty log message ***

Revision 1.1  1999/01/30 19:24:39  nico
Initial revision

Revision 1.1  1999/01/30 19:07:57  nico
Initial revision

 * 
 *    Rev 1.110   29 Jan 1999 15:52:42   NVALST
 * intermediate, maybe working but seems to need two times to load in 
 * light-version
 * 
 *    Rev 2.12   29 Jan 1999 10:48:44   NVALST
 * 
 *    Rev 1.108   28 Jan 1999 14:43:22   NVALST
 * 
****************************************************************************/

/**************************************************************************************************************
*
* CHANGE HISTORY
*
  961018 - NV
	Original Entry

*************************************************************************************************************/


                                                                                                            
#include "wvlan_hcfcfg.h"	// System Constants to be defined by the MSF-programmer to tailor the HCF
#include <stddef.h> //do not move to hcf.cpp to keep Chris (Borland) and Marc (MSVC 4)happy (defines NULL)

#include "wvlan_mdd.h"	// Include file common for HCF, MSF, UIL, USF

/************************************************************************************************************/
/******************   H C F  F U N C T I O N   P A R A M E T E R	 ****************************************/
/************************************************************************************************************/

//offsets for hcf_put_data and hcf_get_data
				

// 802.3/E-II/802.11 offsets to access Hermes control fields
#define HFS_STAT				-0x2E	//0x0000
#define 	HFS_STAT_ERR		RX_STAT_ERR	//link "natural" HCF name to "natural" MSF name

#define HFS_Q_INFO				-0x28	//0x0006
#define HFS_TX_CNTL				-0x22	//0x000C
#define HFS_FRAME_CNTL			-0x20	//0x000E
#define HFS_ID					-0x1E	//0x0010

// 802.11 relative offsets to access 802.11 header fields 
#define HFS_ADDR_1				0x00	//0x0012
#define HFS_ADDR_2				0x06	//0x0018
#define HFS_ADDR_3				0x0C	//0x001E
#define HFS_SEQ_CNTL			0x12	//0x0024
#define HFS_ADDR_4				0x14	//0x0026
#define HFS_DAT_LEN				0x1A	//0x002C

// 802.3 / E-II relative offsets to access 802.3 header fields
#define HFS_ADDR_DEST			0x00	//0x002E
#define HFS_ADDR_SRC			0x06	//0x0034
#define HFS_LEN					0x0C	//0x003A
#define HFS_DAT					0x0E	//0x003C

// E-II relative offsets to access SNAP header fields
#define HFS_TYPE				0x14	//0x0042	//Eternet-II type in 1042/Bridge-Tunnel encapsulated frame


//#define HCF_ACT_INT_PENDING	0x0001		//interrupt pending, return status HCF_ACT_INT_OFF



/*************************************************************************************************************/
/****************   H C F  F U N C T I O N   R E T U R N   C O D E S   ***************************************/
/*************************************************************************************************************/

//Debug Purposes only				!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#define HREG_EV_TICK		0x8000	//WMAC Controller Auxiliary Timer Tick
#define HREG_EV_RES			0x4000	//WMAC Controller H/W error (Wait Time-out)
#define HREG_EV_INFO_DROP	0x2000	//WMAC did not have sufficient RAM to build Unsollicited Frame
#define HREG_EV_NO_CARD		0x0800	/* PSEUDO event: card removed											  */
#define HREG_EV_DUIF_RX     0x0400  /* PSEUDO event: WMP frame received										  */
#define HREG_EV_INFO		0x0080	//WMAC Controller Asynchronous Information Frame
#define HREG_EV_CMD			0x0010	//WMAC Controller Command completed, Status and Response avaialble
#define HREG_EV_ALLOC		0x0008	//WMAC Controller Asynchronous part of Allocation/Reclaim completed
#define HREG_EV_TX_EXC		0x0004	//WMAC Controller Asynchronous Transmission unsuccessful completed
#define HREG_EV_TX			0x0002	//WMAC Controller Asynchronous Transmission successful completed
#define HREG_EV_RX			0x0001	//WMAC Controller Asynchronous Receive Frame



//=========================================  T A L L I E S  ===================================================

typedef struct CFG_HERMES_TALLIES_STRCT {  //Hermes Tallies (IFB substructure)
  hcf_32	TxUnicastFrames;
  hcf_32	TxMulticastFrames;
  hcf_32	TxFragments;
  hcf_32	TxUnicastOctets;
  hcf_32	TxMulticastOctets;
  hcf_32	TxDeferredTransmissions;
  hcf_32	TxSingleRetryFrames;
  hcf_32	TxMultipleRetryFrames;
  hcf_32	TxRetryLimitExceeded;
  hcf_32	TxDiscards;
  hcf_32	RxUnicastFrames;
  hcf_32	RxMulticastFrames;
  hcf_32	RxFragments;
  hcf_32	RxUnicastOctets;
  hcf_32	RxMulticastOctets;
  hcf_32	RxFCSErrors;
  hcf_32	RxDiscards_NoBuffer;
  hcf_32	TxDiscardsWrongSA;
  hcf_32	RxWEPUndecryptable;
  hcf_32	RxMsgInMsgFragments;
  hcf_32	RxMsgInBadMsgFragments;
}CFG_HERMES_TALLIES_STRCT;


//Note this way to define CFG_TALLIES_STRCT_SIZE implies that all tallies must keep the same (hcf_32) size
#define		HCF_NIC_TAL_CNT	(sizeof(CFG_HERMES_TALLIES_STRCT)/ sizeof(hcf_32))
#define		HCF_TOT_TAL_CNT	(HCF_NIC_TAL_CNT)

/************************************************************************************************************/
/***********   W C I    F U N C T I O N S    P R O T O T Y P E S   ******************************************/
/************************************************************************************************************/

#define IFB_VERSION 0x82	 			/* initially 80, to be incremented by every IFB layout change		*/



/* identifier IFB_STRCT on typedef line needed to get the individual fields in the MS Browser DataBase	*/
typedef struct IFB_STRCT{               //I/F Block
/* MSF readable part of Result block structure							*************************************/
  hcf_io		IFB_IOBase;				/* I/O address of Hermes chip as passed by MSF at hcf_connect call	*/
#if defined HCF_PORT_IO
  hcf_16		IFB_IOBase_pad;			// Optional field, makes IFB-layout independent of IFB_IOBase size
#endif //HCF_PORT_IO
  hcf_16		IFB_IORange;			// I/O Range used by Hermes chip
  hcf_8			IFB_Version;			/* initially 0, to be incremented by every IFB layout change		*/
  hcf_8			IFB_Slack_2;			/* align/slack space												*/
  hcf_8			IFB_HCFVersionMajor;	// Major version of the HCF.0x01 for this release
  hcf_8			IFB_HCFVersionMinor;	/* Minor version of the HCF.  Incremented for each coding maintenance 
  										 * cycle. 0x01 for the Initial release								*/
  CFG_HERMES_TALLIES_STRCT	IFB_NIC_Tallies;	//Hermes tallies

/* part I (survives hcf_disable)    ************************************************************************/
  hcf_16		IFB_CardStat;			/* see Design spec													*/
  hcf_16		IFB_FSBase;				// frame type dependent offset (HFS_ADDR_1_ABS or HFS_ADDR_DEST_ABS)
  hcf_16		IFB_RxFence;			// frame type dependent gap fence (HFS_ADDR_DEST_ABS or HFS_LEN_ABS)
  hcf_16		IFB_IntOffCnt;			/* see Design spec													*/
  hcf_32	 	IFB_TickIni;			/* initialization of counter for 1 ms processor loop				*/
  										/* keep this unsigned otherwise the "clever" ASSERT in hcf_disable 
  										 * has a higher risk to get into trouble on slow machines
  										 * keep this hcf_16 to prevent a "close to infinity" time out if
  										 * calibration fails on 32-bits machine								*/
  hcf_16		IFB_Magic;				/* see Design spec													*/
  hcf_16		IFB_Slack_4[2];			/* align/slack space												*/

/* part II (cleared or re-initialized at hcf_disable/hcf_enable)   *****************************************/
  hcf_8  		IFB_PIFRscInd;			/* see Design spec   //;?Q:int better than hcf_8 A: No!				*/
  hcf_8			IFB_DUIFRscInd;			/* Value indicating the command resource availability for the 
  										 * Driver-Utility I/F (i.e. hcf_send_diag_msg).						*/
  										/* Values: */                                                       
  										/* * No command resource		0									*/
  										/* * Command resource available	01h-FFh								*/
  hcf_8  		IFB_NotifyRscInd;		/* see Design spec   //;?Q:int better than hcf_8 A: No!				*/
  hcf_8			IFB_Slack_6;			/* align/slack space												*/
  hcf_16		IFB_PIF_FID;			/* see Design spec													*/
  hcf_16		IFB_DUIF_FID;			/* field which contains FID value identifying the Tx Frame Structure,
  										 * to be used by hcf_send_diag_msg									*/
  hcf_16		IFB_Notify_FID;			/* field which contains FID value identifying the Notify Frame Struct
  										 * to be used by hcf_put_info in case of Notify type codes			*/
  hcf_16		IFB_RxFID;				/* see Design spec													*/
  hcf_16		IFB_MB_FID;				/* pass appropriate FID to hcf_put_mb_info							*/
  hcf_16		IFB_TxFrameType;		/* see Design spec													*/
  hcf_16		IFB_RxLen;				/* see Design spec													*/
  hcf_16		IFB_RxStat;				/* see Design spec													*/
  hcf_16		IFB_UnloadIdx;			/* see Design spec													*/
  hcf_16		IFB_PIFLoadIdx;			/* see Design spec													*/
  hcf_8 		IFB_TxCntl[2];			/* contents of HFS_TX_CNTL field of TFS
  										 * 0: MACPort, 1: StrucType,TxEx,TxOK								*/
  hcf_16		IFB_BAP_0[2];			/* offset
  										 * RID/FID															*/
  hcf_16		IFB_BAP_1[2];			/* offset
  										 * RID/FID															*/
  hcf_16		IFB_IntEnMask;			/* see Design spec													*/
  hcf_16		IFB_TimStat;			/* BAP initialization or Cmd Completion failed once					*/

}IFB_STRCT;



typedef IFB_STRCT*	IFBP;


EXTERN_C int	hcf_action			(IFBP ifbp, hcf_action_cmd cmd );
EXTERN_C void	hcf_assert			(IFBP ifbp, wci_bufp file_name, unsigned int line_number, int q );
EXTERN_C void	hcf_connect			(IFBP ifbp, hcf_io io_base );
EXTERN_C int	hcf_disable			(IFBP ifbp, hcf_16 port );
EXTERN_C void	hcf_disconnect		(IFBP ifbp );
EXTERN_C int	hcf_enable			(IFBP ifbp, hcf_16 port );
EXTERN_C int	hcf_get_info		(IFBP ifbp, LTVP ltvp );
EXTERN_C int	hcf_get_data		(IFBP ifbp, int offset, wci_bufp bufp, int len );
EXTERN_C int	hcf_service_nic		(IFBP ifbp );
//EXTERN_C void	hcf_put_data		(IFBP ifbp, wci_bufp bufp, int len );
EXTERN_C void	hcf_put_data		(IFBP ifbp, wci_bufp bufp, int len, hcf_16 port );
EXTERN_C int	hcf_put_info		(IFBP ifbp, LTVP ltvp );
EXTERN_C int	hcf_put_header		(IFBP ifbp, int offset, wci_bufp bufp, int len, hcf_8 check );
EXTERN_C int	hcf_send			(IFBP ifbp, hcf_16 type );
EXTERN_C int	hcf_send_diag_msg	(IFBP ifbp, hcf_16 type, wci_bufp bufp, int len );




#endif  /* HCF_H */

