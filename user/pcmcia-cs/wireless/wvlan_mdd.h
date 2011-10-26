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


#ifndef MDD_H
#define MDD_H 1

/*************************************************************************************************************
*
* FILE	 : mdd.h
*
* DATE   : 2000/07/14 23:27:51   1.4
*
* AUTHOR : Nico Valster
*
* DESC   : Definitions and Prototypes for HCF, MSF, UIL as well as USF sources
*
*
*
* Implementation Notes
*
 -	Typ rather than type is used as field names in structures like CFG_CIS_STRCT because type leads to
 	conflicts with MASM when the H-file is converted to an INC-file
*
**************************************************************************************************************
Instructions to convert MDD.H to MDD.INC by means of H2INC

Use a command line which defines the specific macros and command line options
needed to build the C-part, e.g. for the DOS ODI driver
		`h2inc /C /Ni /Zp /Zn mdd	 mdd.h`


**************************************************************************************************************
* COPYRIGHT (c) 1998 by Lucent Technologies.	 All Rights Reserved.
*************************************************************************************************************/

/****************************************************************************
wvlan_mdd.h,v
Revision 1.4  2000/07/14 23:27:51  root
*** empty log message ***

Revision 1.3  2000/02/28 23:09:38  root
*** empty log message ***

Revision 1.2  2000/01/06 23:30:53  root
*** empty log message ***

 * 
 *    Rev 1.0   02 Feb 1999 14:32:36   NVALST
 * Initial revision.
Revision 1.3  1999/02/01 22:58:35  nico
*** empty log message ***

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
 *    Rev 2.12   29 Jan 1999 10:48:46   NVALST
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
 *    Rev 1.105   25 Jan 1999 14:24:48   NVALST
 * intermediate, hopefully suitable for release
 * 
 *    Rev 1.104   22 Jan 1999 16:59:34   NVALST
 * intermediate, minor corrections + some HCF-L stuff
 * 
 *    Rev 1.103   15 Jan 1999 15:14:46   NVALST
 * intermediate, deposited as HCF2.10
 * 
 *    Rev 2.10   15 Jan 1999 14:54:36   NVALST
 * 
 *
****************************************************************************/


/****************************************************************************
*
* CHANGE HISTORY
*
  961018 - NV
	Original Entry, split of from HCF.H

*************************************************************************************************************/

/******************************      M A C R O S     ********************************************************/

/* min and max macros */
#if !defined(max)
#define max(a,b)  (((a) > (b)) ? (a) : (b))
#endif
#if !defined(min)
#define min(a,b)  (((a) < (b)) ? (a) : (b))
#endif


/*************************************************************************************************************/

/****************************** General define ***************************************************************/

#define MAC_ADDR_SIZE			6
#define GROUP_ADDR_SIZE			(32 * MAC_ADDR_SIZE)
#define STAT_NAME_SIZE			32



//IFB field related
//		IFB_CardStat
#define CARD_STAT_PRESENT				0x8000U	/* MSF defines card as being present
												 * controls whether hcf-function is allowed to do I/O		*/
#define CARD_STAT_ENABLED				0x4000U	// one or more MAC Ports enabled
#define CARD_STAT_INI					0x0800U	// Hermes Initiliazed

//		IFB_RxStat
#define RX_STAT_ERR						0x0003U	//Error mask
#define 	RX_STAT_UNDECR				0x0002U	//Non-decryptable encrypted message
#define 	RX_STAT_FCS_ERR				0x0001U	//FCS error

/****************************** Xxxxxxxx *********************************************************************/

enum /*hcf_stat*/ {
	HCF_FAILURE			= 0xFF,		/* An (unspecified) failure, 0xFF is choosen to have a non-ubiquitous value
	                                 *	Note that HCF_xxxx errors which can end up in the CFG_DIAG LTV should
	                                 *	never exceed 0xFF, because the high order byte of VAL[0] is reserved
	                                 *	for Hermes errors
	                                 */
	HCF_SUCCESS			= 0x00,		// 0x00: OK
	//gap for ODI related status
	HCF_ERR_DIAG_0		= 0x02,		// 0x02: HCF noticed an error after hcf_disable, before diagnose command
	HCF_ERR_DIAG_1,					// 0x03: HCF noticed an error after succesful diagnose command
	HCF_ERR_TIME_OUT,               // 0x04: Expected Hermes event did not occure in expected time
	HCF_ERR_NO_NIC,					// 0x05: card not found (usually yanked away during hcfio_in_string
	HCF_ERR_BUSY,					// 0x06: ;?Inquire cmd while another Inquire in progress
	HCF_ERR_SEQ_BUG,				// 0x07: other cmd than the expected completed, probably HCF-bug
	HCF_ERR_LEN,					// 0x08: buffer size insufficient
									//		  -	hcf_get_info buffer has a size of 0 or 1 or less than needed
									//			to accomodate all data
};

#define	HCF_INT_PENDING			1	// (ODI initiated) return status of hcf_act( HCF_ACT_INT_OFF )



/* hard coded values (e.g. for HCF_ACT_TALLIES and HCF_ACT_INT_OFF) are needed for HCFL							*/
typedef enum  { /*hcf_action_cmd*/
										/*	gap left over by swapping 3 frame mode action with 4 INT_OFF/_ON
										 *	CARD_IN/_OUT. This was done to have HCFL default automagically
										 *	to HCF_ACT_802_3_PURE
										 *	This gap available for future features								*/
	HCF_ACT_SPARE_03,					//03 gap available for future features
										/* DUI code 0x04 -> DON'T EVER MOVE 									*/
										/* DUI code 0x05 -> DON'T EVER MOVE 									*/
	HCF_ACT_TALLIES = 0x05,				//05 Hermes Inquire Tallies (F100) command
#if defined HCF_ASSERT
	HCF_ACT_ASSERT_OFF,					//09 de-activate Assert reporting
	HCF_ACT_ASSERT_ON,					//0A activate Assert reporting	
#else	
#endif // HCF_ASSERT
										/* DUI code 0x0B -> DON'T EVER MOVE 									*/
										/* DUI code 0x0C -> DON'T EVER MOVE 									*/
	HCF_ACT_INT_OFF = 0x0D,				//0D Disable Interrupt generation
	HCF_ACT_INT_ON,						//0E Enable Interrupt generation
	HCF_ACT_CARD_IN,					//0F MSF reported Card insertion
	HCF_ACT_CARD_OUT,  					//10 MSF reported Card removal
/*	HCF_ACT_MAX							// xxxx: start value for UIL-range, NOT to be passed to HCF
 *										Too bad, there was originally no spare room created to use
 *										HCF_ACT_MAX as an equivalent of HCF_ERR_MAX. Since creating
 *										this room in retrospect would create a backward incompatibilty
 *										we will just have to live with the haphazard sequence of
 *										UIL- and HCF specific codes. Theoretically this could be
 *										corrected when and if there will ever be an overall 
 *										incompatibilty introduced for another reason
 */										 
} hcf_action_cmd;








/*============================================================= HCF Defined RECORDS	=========================*/
/*============================================================= INFORMATION FRRAMES		=====================*/
#define CFG_INFO_FRAME_MIN				0xF000		//lowest value representing an Informatio Frame
	
#define CFG_TALLIES						0xF100		//Communications Tallies
#define CFG_SCAN						0xF101		//Scan results
	                        	
#define CFG_LINK_STAT 					0xF200		//Link Status
	
/*============================================================= CONFIGURATION RECORDS	=====================*/
/*============================================================= mask 0xFCxx				=====================*/						
//	NETWORK PARAMETERS, STATIC CONFIGURATION ENTITIES
//FC05, FC0A, FC0B, FC0C, FC0D: SEE W2DN149
	
#define CFG_RID_CFG_MIN					0xFC00		//lowest value representing a Configuration RID
#define CFG_CNF_PORT_TYPE				0xFC00		//[STA] Connection control characteristics
#define CFG_CNF_OWN_MAC_ADDR			0xFC01		//[STA] MAC Address of this node
#define CFG_CNF_DESIRED_SSID			0xFC02		//[STA] Service Set identification for connection
#define CFG_CNF_OWN_CHANNEL				0xFC03		//Communication channel for BSS creation
#define CFG_CNF_OWN_SSID				0xFC04		//IBSS creation (STA) or ESS (AP) Service Set Ident
#define CFG_CNF_OWN_ATIM_WINDOW			0xFC05		//[STA] ATIM Window time for IBSS creation
#define CFG_CNF_SYSTEM_SCALE			0xFC06		//System Scale that specifies the AP density
#define CFG_CNF_MAX_DATA_LEN			0xFC07		//Maximum length of MAC Frame Body data
#define CFG_CNF_WDS_ADDR				0xFC08		//[STA] MAC Address of corresponding WDS Link node
#define CFG_CNF_PM_ENABLED				0xFC09		//[STA] Switch for ESS Power Management (PM) On/Off
#define CFG_CNF_PM_EPS					0xFC0A		//[STA] Switch for ESS PM EPS/PS Mode
#define CFG_CNF_MCAST_RX				0xFC0B		//[STA] Switch for ESS PM Multicast reception On/Off
#define CFG_CNF_MAX_SLEEP_DURATION		0xFC0C		//[STA] Maximum sleep time for ESS PM
#define CFG_CNF_HOLDOVER_DURATION		0xFC0D		//[STA] Holdover time for ESS PM
#define CFG_CNF_OWN_NAME				0xFC0E		//Identification text for diagnostic purposes

#define CFG_CNF_ENCRYPTION				0xFC20		//select en/de-cryption of Tx/Rx messages
#define CFG_CNF_MICRO_WAVE              0xFC25      //MicroWave (Robustness)
	
	
//	NETWORK PARAMETERS, DYNAMIC CONFIGURATION ENTITIES
#define CFG_GROUP_ADDR					0xFC80		//[STA] Multicast MAC Addresses for Rx-message
#define CFG_CREATE_IBSS					0xFC81		//[STA] Switch for IBSS creation On/Off
#define CFG_FRAGMENTATION_THRH			0xFC82		//[STA] Fragment length for unicast Tx-message
#define CFG_RTS_THRH					0xFC83		//[STA] Frame length used for RTS/CTS handshake
#define CFG_TX_RATE_CONTROL				0xFC84		//[STA] Data rate control for message transmission
#define CFG_PROMISCUOUS_MODE			0xFC85		//[STA] Switch for Promiscuous mode reception On/Off

#define CFG_CNF_DEFAULT_KEYS			0xFCB0		//defines set of encryption keys
#define CFG_CNF_TX_KEY_ID			0xFCB1		//select key for encryption of Tx messages
	

//	BEHAVIOR PARAMETERS	
#define CFG_TICK_TIME					0xFCE0		//[PRI] Auxiliary Timer tick interval
#define CFG_RID_CFG_MAX					0xFCFF		//highest value representing an Configuration RID


/*============================================================= INFORMATION RECORDS 	=====================*/
/*============================================================= mask 0xFDxx				=====================*/
//	NIC INFORMATION	
#define CFG_RID_INF_MIN					0xFD00		//lowest value representing an Information RID
#define CFG_PRI_IDENTITY				0xFD02
#define CFG_PRI_SUP_RANGE				0xFD03		//Primary supplier range
#define CFG_CFI_ACT_RANGES_PRI			0xFD04

#define CFG_HSI_SUP_RANGE				0xFD09		//H/W - S/W I/F supplier range
#define CFG_NIC_SERIAL_NUMBER			0xFD0A
#define CFG_NIC_IDENTITY				0xFD0B
#define CFG_MFI_SUP_RANGE				0xFD0C
#define CFG_CFI_SUP_RANGE				0xFD0D

#define CFG_CHANNEL_LIST				0xFD10		//Allowed communication channels
#define CFG_REG_DOMAINS					0xFD11		//List of intended regulatory domains
#define CFG_TEMP_TYPE  					0xFD12		//Hardware temperature range code
#define CFG_CIS							0xFD13		//PC Card Standard Card Information Structure

#define CFG_STA_IDENTITY				0xFD20
#define CFG_STA_SUP_RANGE				0xFD21		//Station supplier range
#define CFG_MFI_ACT_RANGES_STA			0xFD22
#define CFG_CFI_ACT_RANGES_STA			0xFD23

//	MAC INFORMATION
#define CFG_PORT_STAT					0xFD40		//[STA] Actual MAC Port connection control status
#define CFG_CURRENT_SSID				0xFD41		//[STA] Identification of the actually connected SS
#define CFG_CURRENT_BSSID				0xFD42		//[STA] Identification of the actually connected BSS
#define CFG_COMMS_QUALITY				0xFD43		//[STA] Quality of the Basic Service Set connection
#define CFG_CURRENT_TX_RATE				0xFD44		//[STA] Actual transmit data rate
#define CFG_OWN_BEACON_INTERVAL			0xFD45		//Beacon transmit interval time for BSS creation
#define CFG_CUR_SCALE_THRH				0xFD46		//Actual System Scale thresholds settings
#define CFG_PROTOCOL_RSP_TIME			0xFD47		//Max time to await a response to a request message
#define CFG_SHORT_RETRY_LIMIT			0xFD48		//Max number of transmit attempts for short frames
#define CFG_LONG_RETRY_LIMIT			0xFD49		//Max number of transmit attempts for long frames
#define CFG_MAX_TX_LIFETIME				0xFD4A		//Max transmit frame handling duration
#define CFG_MAX_RX_LIFETIME				0xFD4B		//Max received frame handling duration
#define CFG_CF_POLLABLE					0xFD4C		//[STA] Contention Free pollable capability indication
#define CFG_AUTHENTICATION_ALGORITHMS	0xFD4D		//Available Authentication Algorithms indication
#define CFG_AUTHENTICATION_TYPE			0xFD4E		//Available Authentication Types indication
#define CFG_PRIVACY_OPTION_IMPLEMENTED	0xFD4F		//WEP Option availability indication
	

//	MODEM INFORMATION	
#define CFG_PHY_TYPE					0xFDC0		//		// 	Physical layer type indication
#define CFG_CURRENT_CHANNEL				0xFDC1		//Actual frequency channel used for transmission
#define CFG_CURRENT_POWER_STATE			0xFDC2		//Actual power consumption status
#define CFG_CCAMODE						0xFDC3		//Clear channel assessment mode indication
#define CFG_CCATIME						0xFDC4		//Clear channel assessment time
#define CFG_MAC_PROCESSING_DELAY		0xFDC5		//MAC processing delay time
#define CFG_SUPPORTED_DATA_RATES		0xFDC6		//Data rates capability information

#define CFG_RID_INF_MAX					0xFDFF		//highest value representing an Information RID

//} hcf_info_type;




/*************************************************************************************************************/

/****************************** S T R U C T U R E   D E F I N I T I O N S ************************************/

typedef struct LTV_STRCT {	//used for all "minimal" LTV records
	hcf_16	len;					//default length of RID
	hcf_16	typ;					//RID identification as defined by Hermes
	hcf_16	val[1];					//do not change this, some dynamic structures are defined based on this !!
}LTV_STRCT;

typedef LTV_STRCT FAR *	LTVP;





#define COMP_ID_MINIPORT	41				//Windows 9x/NT Miniport
#define COMP_ID_PACKET		42				//Packet
#define COMP_ID_ODI_16		43				//DOS ODI
#define COMP_ID_ODI_32		44				//32-bits ODI
#define COMP_ID_MAC_OS		45				//Macintosh OS
#define COMP_ID_WIN_CE		46				//Windows CE Miniport
#define COMP_ID_LINUX		47				//You never guessed, Linux
#define COMP_ID_AP1			81				//WaveLAN/IEEE AP



#define COMP_ROLE_SUPL	00				//supplier
#define COMP_ROLE_ACT	01				//actor

#define COMP_ID_MFI		01				//Modem		 		- Firmware	I/F
#define COMP_ID_CFI		02				//Controller		- Firmware	I/F
#define COMP_ID_PRI		03				//Primary Firmware	- Driver	I/F
#define COMP_ID_STA		04				//Station Firmware	- Driver	I/F
#define COMP_ID_DUI		05				//Driver			- Utility	I/F
#define COMP_ID_HSI		06				//H/W               - Driver	I/F

typedef struct KEY_STRCT {
	hcf_16	len;			//length of key
	hcf_8	key[14];		//encryption key
} KEY_STRCT;

typedef struct CFG_CNF_DEFAULT_KEYS_STRCT {	//CFG_CNF_DEFAULT_KEYS (0xFCB0) defines set of encrypti
	hcf_16		len;		//default length of RID
	hcf_16		typ;		//RID identification as defined by Hermes
	KEY_STRCT	key[4];		//encryption keys
} CFG_CNF_DEFAULT_KEYS_STRCT;


typedef struct CFG_REG_DOMAINS_STRCT {	//CFG_REG_DOMAINS (0xFD11) List of intended regulatory domains.
	hcf_16	len;					//length of RID
	hcf_16	typ;					//RID identification as defined by Hermes
	hcf_16	domains[6];
}CFG_REG_DOMAINS_STRCT;

typedef struct CFG_CIS_STRCT {			//CFG_CIS (0xFD13) PC Card Standard Card Information Structure
	hcf_16	len;					//length of RID
	hcf_16	typ;					//RID identification as defined by Hermes
	hcf_16	cis[240];				//Compact CIS Area, a linked list of tuples
}CFG_CIS_STRCT;


typedef struct CFG_COMMS_QUALITY_STRCT {//CFG_COMMS_QUALITY (0xFD43) Quality of the Basic Service Set connection [STA]
	hcf_16	len;					//length of RID
	hcf_16	typ;					//RID identification as defined by Hermes
	hcf_16	coms_qual;              //Communication Quality of the BSS the station is connected to
	hcf_16	signal_lvl;				//Average Signal Level of the BSS the station is connected to
	hcf_16	noise_lvl;				//Average Noise Level of the currently used Frequency Channel
}CFG_COMMS_QUALITY_STRCT;



typedef struct CFG_CUR_SCALE_THRH_STRCT {//CFG_CUR_SCALE_THRH (0xFD46) Actual System Scale thresholds
	hcf_16	len;					//default length of RID [STA: 6  AP: 4]
	hcf_16	typ;					//RID identification as defined by Hermes
	hcf_16	energy_detect_thrh;		//Receiver H/W Energy Detect Threshold
	hcf_16	carrier_detect_thrh;	//Receiver H/W Carrier Detect Threshold
	hcf_16	defer_thrh;				//Receiver H/W Defer Threshold
	hcf_16	cell_search_thrh;		//Firmware Roaming Cell Search Threshold [STA]
	hcf_16	out_of_range_thrh;		//Firmware Roaming Out of Range Threshold [STA]
	hcf_16	delta_snr;				//Firmware Roaming Delta SNR value [STA]
}CFG_CUR_SCALE_THRH_STRCT;


typedef struct CFG_PCF_INFO_STRCT {		//CFG_PCF_INFO (0xFD87) Point Coordination Function capability info [AP]
	hcf_16	len;					//default length of RID
	hcf_16	typ;					//RID identification as defined by Hermes
	hcf_16	energy_detect_thrh;
	hcf_16	carrier_detect_thrh;
	hcf_16	defer_thrh;
	hcf_16	cell_search_thrh;
	hcf_16	range_thrh;
}CFG_PCF_INFO_STRCT;


typedef struct CFG_MAC_ADDR_STRCT{			//0xFC01	[STA] MAC Address of this node.
											//0xFC08	STA] MAC Address of corresponding WDS Link node.
											//0xFC11	[AP] Port 1 MAC Adrs of corresponding WDS Link node
											//0xFC12	[AP] Port 2 MAC Adrs of corresponding WDS Link node
											//0xFC13	[AP] Port 3 MAC Adrs of corresponding WDS Link node
											//0xFC14	[AP] Port 4 MAC Adrs of corresponding WDS Link node
											//0xFC15	[AP] Port 5 MAC Adrs of corresponding WDS Link node
											//0xFC16	[AP] Port 6 MAC Adrs of corresponding WDS Link node
	hcf_16	len;					//default length of RID
	hcf_16	typ;					//RID identification as defined by Hermes
	hcf_16	mac_addr[3];
}CFG_MAC_ADDR_STRCT;

typedef struct CFG_GROUP_ADDR_STRCT{			//0xFC80	//[STA] Multicast MAC Addresses for
	hcf_16	len;					//default length of RID
	hcf_16	typ;					//RID identification as defined by Hermes
	hcf_16	mac_addr[GROUP_ADDR_SIZE/6][3];
}CFG_GROUP_ADDR_STRCT;


typedef struct CFG_ID_STRCT {				//0xFC02	[STA] Service Set identification for connection.
											//0xFC04	IBSS creation (STA) or ESS (AP) Service Set Ident
											//0xFC0E	Identification text for diagnostic purposes.
	hcf_16	len;					//default length of RID
	hcf_16	typ;					//RID identification as defined by Hermes
	hcf_16	id[17];
}CFG_ID_STRCT;


typedef void *	DUIP;

#endif // MDD_H


