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


/**************************************************************************************************************
*
* FILE   :	HCF.CPP *************** 2.0 ***********************************************************************
*
* DATE    :	2000/01/06 23:30:52   1.2
*
* AUTHOR :	Nico Valster
*
* DESC   :	HCF Routines hcf_action, hcf_connect, hcf_disable
*						 hcf_disconnect, hcf_download, hcf_enable, hcf_generate_int
*						 hcf_get_info, hcf_get_data, hcf_service_nic
*						 hcf_put_info, hcf_put_data, hcf_register_mailbox, hcf_send,
*						 hcf_send_diag_msg
*			Local Support Routines for above procedures
*
*			Customizable via HCFCFG.H, which is included by HCF.H
*
***************************************************************************************************************
* COPYRIGHT (c) 1995			 by AT&T.	 				All Rights Reserved
* COPYRIGHT (c) 1996, 1997, 1998 by Lucent Technologies.	All Rights Reserved
*
* At the sole discretion of Lucent Technologies parts of this source may be extracted
* and placed in the Public Domain under the GPL.
* This extraction takes place by means of an AWK-script acting on embedded tags.
* The AWK script is:
 *	BEGIN { c = 0 }
 *	{ if ( c == 0 ) i = 1}			#if in @HCF_L>..@HCF_L< block, skip
 *	{ if (name != FILENAME ) name = FILENAME }
 *	
 *	{ if ( i && c == 0  ) { print ; hcf_l_cnt++ } }
 *	#{ if ( i ) { print ; hcf_l_cnt++ } }
 *	#{if ( c == 0 ) { printf("N%d", c) ; hcf_l_cnt++ } }
 *	#{if ( c == 1 ) { printf("E%d", c) ; hcf_l_cnt++ } }
 *	
 *	#END { printf("%s:: HCF lines: %d, HCF_Light lines: %d", name, NR, hcf_l_cnt ) }
*
* and is not in any sense derived from the extracted source. 
*
**************************************************************************************************************/





/****************************************************************************
wvlan_hcf.c,v
Revision 1.2  2000/01/06 23:30:52  root
*** empty log message ***

 * 
 *    Rev 1.0   02 Feb 1999 14:32:28   NVALST
 * Initial revision.
Revision 1.3  1999/02/01 22:58:40  nico
*** empty log message ***
 * 
 *    Rev 2.12   29 Jan 1999 10:48:40   NVALST
 * 
 *    Rev 1.108   28 Jan 1999 14:43:18   NVALST
 * intermediate, once more correction of loop in hcf_service_nic + download
 * passed to Marc
 * 
****************************************************************************/

/**************************************************************************************************************
*
* CHANGE HISTORY
*

  960702 - NV
	Original Entry - derived from WaveLAN-I HCF 2.12


*
* ToDo
*
 1:	For all/most functions, update "MSF-accessible fields of Result Block:" entry
 2: Use the "numbered comments" in the NARRATIVE consistently, i.e. hcf_put_info
 3: hcf_put_data, hcf_send, hcf_send_diag_msg
	once the dust is settled whether hcf_put_data or hcf_send is the appropriate place is to specify port,
	it can be considered whether part of the hcf_send_diag_msg and hcf_send can be isolated in a common
	routine.
 4:	hcf_send_diag_msg:
  	- what are the appropriate return values
	- once the dust is settled whether type should or shouldn't be parameter of hcf_send_diag_msg, it can
	  be decided whether the HFX_TX_CNTL_ABS update at each call is needed
 5:	hcf_service_nic, hcf_send, hcf_send_diag_msg etc
 	check for a CONSISTENT strategy for the testing of IFB_CardStat, for presence, enabled, ports
 6:	Decide on the relative merits of HCF_ACT_ASSERT_OFF/_ON versus CFG_REG_MSF_ASSERT
	

*
* Implementation Notes
*
 -	C++ style cast is not used to keep DA-C happy
 -	a leading marker of //! is used. The purpose of such a sequence is to help the
	(maintenance) programmer to understand the flow
 	An example in hcf_action( HCF_ACT_802_3 ) is
	//!		ifbp->IFB_RxFence = 0;
	which is superfluous because IFB_RxFence gets set at every hcf_service_nic but
	it shows to the (maintenance) programmer it is an intentional omission at
	the place where someone could consider it most appropriate at first glance
 -	using near pointers in a model where ss!=ds is an invitation for disaster, so be aware of how you specify
 	your model and how you define variables which are used at interrupt time
 -	Once the comment "the value of -1 for parameter len is meaningless but it guarantees that the next call
 	to bap_ini is interpreted as an initial call, causing the BAP to be really initialized." was considered
 	useful information. Does this trick still lingers somewhere;?
 -	remember that sign extension on 32 bit platforms may cause problems unless code is carefully constructed,
 	e.g. use "(hcf_16)~foo" rather than "~foo"

	
*
* Miscellaneous Notes
*
 -	AccessPoint performance could be improved by adding a hcf_send_pif_msg equivalent of hcf_send_diag_msg


*************************************************************************************************************/

#include "wvlan_hcf.h"				// HCF and MSF common include file
#include "wvlan_hcfdef.h"			// HCF specific include file

/*************************************************************************************************************/
/***************************************  PROTOTYPES  ********************************************************/
/*************************************************************************************************************/
// moving these prototypes to HCFDEF.H turned out to be less attractive in the HCF-light generation
STATIC int			aux_cntl( IFBP ifbp, hcf_16 cmd );
STATIC int			calibrate( IFBP ifbp );
STATIC int			cmd_wait( IFBP ifbp, int cmd_code, int par_0 );
STATIC void			enable_int(IFBP ifbp, int event );
       int			hcf_initialize( IFBP ifbp );
STATIC int			ini_hermes( IFBP ifbp );
STATIC void	 		isr_info( IFBP ifbp );
STATIC int			put_info( IFBP ifbp, LTVP ltvp	);
STATIC hcf_16		alloc( IFBP ifbp, int len );


/**************************************************************************************************************
******************************* D A T A    D E F I N I T I O N S **********************************************
**************************************************************************************************************/

STATIC hcf_8 BASED hcf_rev[] = "\nHCF1.2\n";

/* Note that the "BASED" construction (supposedly) only amounts to something in the small memory model.
 * In that case CS and DS are equal, so we can ignore the consequences of casting the BASED cfg_drv_...
 * structure to hcf_16
 * Note that the whole BASED riggamarole is needlessly complicated because both the Microsoft Compiler and
 * Linker are unnecessary restrictive in what far pointer manipulation they allow
 */


/* 
	The below table accessed via a computed index was the original implementation for hcf_get_info with 
	CFG_DRV_IDENTITY, CFG_DRV_SUP_RANGE, CFG_DRV_ACT_RANGE_PRI, CFG_DRV_ACT_RANGE_STA, CFG_DRV_ACT_RANGE_HSI
	as type. However it was reported that the 68K compiler for MAC OS is unable to initialize pointers.
	Accepting this story at face value, the HCF is coded around this problem by implementing a direct access..
	To save part of the invested effort, the original table is kept as comment.

STATIC LTV_STRCT*   BASED xxxx[ ] = {
	(LTV_STRCT*)&cfg_drv_identity,      //CFG_DRV_IDENTITY              0x0826
	(LTV_STRCT*)&cfg_drv_sup_range,     //CFG_DRV_SUP_RANGE             0x0827
	(LTV_STRCT*)&cfg_drv_act_range_pri, //CFG_DRV_ACT_RANGE_PRI         0x0828
	(LTV_STRCT*)&cfg_drv_act_range_sta  //CFG_DRV_ACT_RANGE_STA         0x0829
	(LTV_STRCT*)&cfg_drv_act_range_hsi	//CFG_DRV_ACT_RANGE_HSI			0x082A
  };
*/


/**************************************************************************************************************
************************** T O P   L E V E L   H C F   R O U T I N E S ****************************************
**************************************************************************************************************/


/*******************************************************************************************************************


.MODULE			hcf_action
.LIBRARY 		HCF
.TYPE 			function
.SYSTEM			msdos
.SYSTEM			NW4
.APPLICATION	Card configuration
.DESCRIPTION	Changes the run-time Card behavior

.ARGUMENTS
  int hcf_action(IFBP ifbp, hcf_action_cmd action )
.RETURNS
  int

  MSF-accessible fields of Result Block: -

.NARRATIVE

 Name:	hcf_action

 Summary: Changes the run-time Card behavior

 Parameters:
  ifbp	address of the Interface Block

  action	number identifying the type of change

  o HCF_ACT_INT_ON		enable interrupt generation by WaveLAN NIC
  o HCF_ACT_INT_OFF		disable interrupt generation by WaveLAN NIC
  o HCF_ACT_CARD_IN		MSF reported Card insertion
  o HCF_ACT_CARD_OUT	MSF reported Card removal

 Returns:
  o	HCF_ACT_INT_OFF
		0: no interrupt pending
		1: interrupt pending
  o	all other
		0 (((however, see the special treatment for HCF_ACT_INT_ON)))

 Remarks:
  o	HCF_ACT_INT_OFF/HCF_ACT_INT_ON codes may be nested but must be balanced. The INT_OFF/INT_ON housekeeping
	is initialized by hcf_connect with a call of hcf_action with INT_OFF, causing the interrupt generation
	mechanism to be disabled at first. This suits MSF implementation based on a polling strategy. An MSFT
	based on a interrupt strategy must call hcf_action with INT_ON in its initialization logic.

  o To prevent I/O while the I/O space is no longer owned by the HCF, due to a card swap, no I/O is allowed
	when the CARD_STAT_PRESENT bit of IFB_CardStat is off.

.DIAGRAM
 2: IFB_IntOffCnt is used to balance the INT_OFF and INT_ON calls.
 4: Disabling of the interrupts is simply achieved by writing a zero to the Hermes IntEn register
 5: To be able to return the information to the MSF whether an interrupt is actually pending, the Hermes
	EvStat register is sampled and compared against the current IFB_IntEnMask value
 6:	Originally the construction "if ( ifbp->IFB_IntOffCnt-- <= 1 )" was used in stead of
 	"if ( --ifbp->IFB_IntOffCnt == 0 )". This serviced to get around the unsigned logic, but as additional
 	"benefit" it seemed the most optimal "fail safe" code (in the sense of shortest/quickest path in error
 	free flows, fail safe in the sense of too many INT_ON invocations compared to INT_OFF). However when a
 	real life MSF programmer ran to a MSF sequence problem, exactly causing that problem, he was annoyed
 	with this fail safe code. As a consequence it is taken out. As a side-effect of this unhappy MSF programmer
 	adventures to find his problem, the return status is defined to reflect the IFBIntOffCnt, Note that this 
 	is solely intended for aid debugging, no MSF logic should depend on this feature, No garuantees for the 
 	future are given.
 	Enabling of the interrupts is achieved by writing the contents of IFB_IntEnMask to the Hermes IntEn
 	register.
 7:	Since the card is present again, it must be re-initialized. Since this may be another card we may as well 
 	clear all bits in IFB_CardStat and set only the "present" bit. 
 	The first call to hcf_enable will restore the contents of HREG_INT_EN register taking the 
 	HCF_ACT_IN_ON/OFF history in account.
 9:	The MSF must call hcf_action with HCF_ACT_CARD_OUT when the MSF detects a card removal (e.g. when the MSF
	is notified by the CAD). As a minimum, the "present" bit in IFB_CardStat must be reset, however since
	the card insertion will clear all other bits, the simplest solution is to clear IFB_CardStat here as well.
	As a result of the resetting of the CARD_STAT_PRESENT bit, no hcf-function except hcf_action with
	HCF_ACT_CARD_IN results in card I/O anymore. However hcf_functions may still perform their other
	activities, e.g. hcf_get_info_mb still supplies a MBIB if one is available.
	As a result of the resetting of the CARD_STAT_INI bit, the call to hcf_initialize by hcf_action with
	HCF_ACT_CARD_IN results in re-initialization of the NIC.
.ENDOC				END DOCUMENTATION


**************************************************************************************************************/
int hcf_action( IFBP ifbp, 					//address of the Interface Block
				hcf_action_cmd action		/*number identifying the type of change
											*/
 				) {

int		rc = HCF_SUCCESS;
//int		i, j;
//hcf_16	scratch[2];

	

	switch (action) {
	  case HCF_ACT_INT_OFF:						// Disable Interrupt generation
		ifbp->IFB_IntOffCnt++;																			/* 2 */
		if ( ifbp->IFB_CardStat & CARD_STAT_PRESENT ) {
			OUT_PORT_WORD( ifbp->IFB_IOBase + HREG_INT_EN, 0 ); 										/* 4 */
			if ( IN_PORT_WORD( ifbp->IFB_IOBase + HREG_EV_STAT ) & ifbp->IFB_IntEnMask ) {				/* 5 */
				rc = HCF_INT_PENDING;
			}
		}
		break;
		
	  case HCF_ACT_INT_ON:						// Enable Interrupt generation
		if ( --ifbp->IFB_IntOffCnt == 0 ) {																/* 6 */
			if ( ifbp->IFB_CardStat & CARD_STAT_PRESENT ) {
				OUT_PORT_WORD( ifbp->IFB_IOBase + HREG_INT_EN, ifbp->IFB_IntEnMask );
			}
		}
		rc = ifbp->IFB_IntOffCnt;
		break;
		
	  case  HCF_ACT_CARD_IN:					// MSF reported Card insertion							/* 7 */
		ifbp->IFB_CardStat = CARD_STAT_PRESENT;
		hcf_initialize ( ifbp );

		if ( ifbp->IFB_CardStat & CARD_STAT_ENABLED ) {
		  (void)hcf_enable( ifbp, 0 );
		}
		break;
	
	  case 	HCF_ACT_CARD_OUT:  					// MSF reported Card removal							/* 9 */
		ifbp->IFB_CardStat = 0;
		break;
		
		
	  case 	HCF_ACT_TALLIES:					// Hermes Inquire Tallies (F100) command				/*12 */
		action = (hcf_action_cmd)(action - HCF_ACT_TALLIES + CFG_TALLIES);
		if ( ifbp->IFB_CardStat & CARD_STAT_ENABLED ) {
		  rc = cmd_wait( ifbp, HCMD_INQUIRE, action );
		}  		
		break;
		
		
		

	  default:
		break;
	}
	return rc;
}/* hcf_action */



/*******************************************************************************************************************

.MODULE			hcf_connect
.LIBRARY 		HCF
.TYPE 			function
.SYSTEM			msdos
.SYSTEM			unix
.SYSTEM			NW4
.APPLICATION	Card Initialization Group for WaveLAN based drivers and utilities
.DESCRIPTION	Initializes Card and HCF housekeeping

.ARGUMENTS
  void hcf_connect( IFBP ifbp, hcf_io io_base )

.RETURNS
	n.a.

  MSF-accessible fields of Result Block:
	IFB_IOBase				entry parameter io_base
	IFB_IORange				HREG_IO_RANGE (0x40)
	IFB_HCFVersionMajor		the major part of the PVCS maintained version number
	IFB_HCFVersionMinor		the minor part of the PVCS maintained version number
	IFB_Version				version of the IFB layout (0x01 for this release)
	
.NARRATIVE

 Parameters:
	ifbp		address of the Interface Block
	io_base		I/O Base address of the NIC


  Hcf_connect grants access right for the HCF to the IFB and initializes the HCF housekeeping part of the
  IFB. Hcf_connect does not perform any I/O.

  The HCF-Version fields are set dynamically, because I do not know of any C mechanism to have the compiler
  and the version control system (PVCS) cooperate to achieve this at compile time.  The HCFVersions fields are
  constructed by collecting and shifting the low order nibbles of the PVCS controlled ASCII representation.
  Note that the low order nibble of a space (0x20) nicely coincides with the low order nibble of an ASCII '0'
  (0x30). Also note that the code breaks when major or minor number exceeds 99.


.DIAGRAM
 1:	patch_catch is called as early in the flow as the C-entry code allows to help the HCF debugger as much as
	possible.  The philosophy behind patch_catch versus a simple direct usage of the INT_3 macro is explained
	in the description of patch_catch
 2:	The IFB is zero-filled.
 	This presets IFB_CardStat and IFB_TickIni at appropriate values for hcf_initialize.
10: In addition to the MSF readable fields mentioned in the description section, the following HCF specific
	fields are given their actual value:
	  -	a number of fields as side effect of the calls of hcf_action (see item 14)
	  -	IFB_Magic
	IFB_VERSION, which reflects the version of the IFB layout, is defined in HCF.H
14:	Hcf_connect defaults to "no interrupt generation" (by calling hcf_action with the appropriate parameter),
	"802.3 frame type" and "no card present" (implicitly achieved by the zero-filling of the IFB).
	Depending on HCFL, the 802.3 frame type is either initialized in line or by calling hcf_action.
	
.NOTICE
  If io_base ever needs to be dynamic, it may be more logical to pass
	- io_base at hcf_enable or
	- have a separate hcf_put_config command or
	- demand a hcf_disconnect - hcf_connect sequence
	
.NOTICE
  On platforms where the NULL-pointer is not a bit-pattern of all zeros, the zero-filling of the IFB results
  in an seemingly incorrect initialization of IFB_MBp. The implementation of the MailBox manipulation in
  put_mb_info protects against the absence of a MailBox based on IFB_MBSize, IFB_MBWp and ifbp->IFB_MBRp. This
  has ramifications on the initialization of the MailBox via hcf_put_info with the CFG_REG_MB type.

.ENDOC				END DOCUMENTATION
-------------------------------------------------------------------------------------------------------------*/
void hcf_connect( IFBP ifbp, 					//address of the Interface Block
				  hcf_io io_base				//I/O Base address of the NIC
				) {

hcf_8 *q;

#if defined _M_I86TM
#endif // _M_I86TM
	

	for ( q = (hcf_8*)&ifbp[1]; q > (hcf_8*)ifbp; *--q = 0) /*NOP*/;									/* 2 */

	ifbp->IFB_Version	= IFB_VERSION;					  												/* 10*/
	ifbp->IFB_IOBase	= io_base;
	ifbp->IFB_IORange	= HREG_IO_RANGE;
	ifbp->IFB_Magic		= HCF_MAGIC;
	ifbp->IFB_HCFVersionMajor	= (hcf_8)( (hcf_rev[REV_OFFSET] << 4 | hcf_rev[REV_OFFSET+1]) & 0x0F );
	ifbp->IFB_HCFVersionMinor	= (hcf_8)( hcf_rev[REV_OFFSET+4] == ' ' ?
								  		   hcf_rev[REV_OFFSET+3] & 0x0F :
								  		   (hcf_rev[REV_OFFSET+3] << 4 | hcf_rev[REV_OFFSET+4]) & 0x0F );

	(void)hcf_action(ifbp, HCF_ACT_INT_OFF );															/* 14*/
    ifbp->IFB_FSBase = HFS_ADDR_DEST_ABS;
	return;
}/* hcf_connect	*/





/*******************************************************************************************************************

.MODULE			hcf_disable
.LIBRARY 		HCF
.TYPE 			function
.SYSTEM			msdos
.SYSTEM			unix
.SYSTEM			NW4
.APPLICATION	Card Initialization Group for WaveLAN based drivers and utilities
.DESCRIPTION    Disables data transmission and reception
.ARGUMENTS
  int hcf_disable( IFBP ifbp, hcf_16 port )

.RETURNS
	HCF_SUCCESS
	HCF_ERR_NO_NIC
	HCF_ERR_TIME_OUT (via cmd_wait)
	HCF_FAILURE (via cmd_wait)
	
  MSF-accessible fields of Result Block:
   	IFB_CardStat  -	reset CARD_STAT_ENABLED bit iff at completion no port enabled anymore

.NARRATIVE

  Parameters:
	ifbp		address of the Interface Block

  Condition Settings:
	Card Interrupts	  - Unchanged
					  -	Disabled (Note that the value of IFB_IntOffCnt is unchanged)
					    					  

.NOTICE
 o  hcf_disable may disable the card interrupts, however it does NOT influence IFB_IntOffCnt.
	This way it is symmetrical with hcf_enable, which does NOT enable the card interrupts.	
	
**************************************************************************************************************/
int hcf_disable( IFBP ifbp, hcf_16 port ) {

int					rc;
//hcf_16				p_bit;

		rc = cmd_wait( ifbp, HCMD_DISABLE | (port << 8 ), 0 );
		ifbp->IFB_CardStat &= (hcf_16)~CARD_STAT_ENABLED;
		(void)hcf_action( ifbp, HCF_ACT_INT_OFF );														/* 40 */
		ifbp->IFB_IntOffCnt--;
	return rc;
}/* hcf_disable */



/*******************************************************************************************************************


.MODULE			hcf_disconnect
.LIBRARY 		HCF
.TYPE 			function
.SYSTEM			msdos
.SYSTEM			NW4
.APPLICATION	Card Connection for WaveLAN based drivers and utilities
.DESCRIPTION
  Disable transmission and reception, release the IFB
.ARGUMENTS
  void hcf_disconnect( IFBP ifbp )
.RETURNS
  void

  MSF-accessible fields of Result Block:
  	IFB_CardStat	cleared

.NARRATIVE
  Parameters:
	ifbp		address of the Interface Block

  Description:
	Brings the NIC in quiescent state by calling hcf_initialize, thus preventing any interrupts in the future.

.DIAGRAM
 1:	hcf_initialize gives a justification to execute the Hermes Initialize command only when really needed.
 	Despite this basic philosophy and although the HCF can determine whether the NIC is initialized based
 	on IFB_CardStat, the minimal set of actions to initialize the Hermes is always done by calling
 	ini_hermes.
 5:	clear all IFB fields
 	The clearing of IFB_CardStat prevents I/O on any subsequent hcf_function

.ENDOC				END DOCUMENTATION
-------------------------------------------------------------------------------------------------------------*/
void hcf_disconnect( IFBP ifbp ) {

hcf_8 *q;


	ini_hermes( ifbp );

	for ( q = (hcf_8*)&ifbp[1]; q > (hcf_8*)ifbp; *--q = 0) /*NOP*/;									/* 5 */

}/* hcf_disconnect */





/*******************************************************************************************************************


.MODULE			hcf_enable
.LIBRARY 		HCF
.TYPE 			function
.SYSTEM			msdos
.SYSTEM			unix
.SYSTEM			NW4
.APPLICATION	Card Initialization Group for WaveLAN based drivers and utilities
.DESCRIPTION    Enables data transmission and reception
.ARGUMENTS
  int hcf_enable( IFBP ifbp, hcf_16 port )
.RETURNS
	HCF_SUCCESS
	HCF_ERR_TIME_OUT (via cmd_wait)
	HCF_FAILURE (via cmd_wait)

  MSF-accessible fields of Result Block

  Condition Settings:
	Card Interrupts: Off if IFB_IntOffCnt > 0; On if IFB_IntOffCnt == 0
					 (Note that the value of IFB_IntOffCnt is unchanged)

.NARRATIVE
  Parameters:
  	ifbp	address of the Interface Block

  Description:

	hcf_enable takes successively the following actions:
 6:	If the requested port is disabled and if the NIC is present, the Hermes Enable command is executed.
	If CARD_STAT_PRESENT is off, the body of hcf_enable must be skipped to prevent I/O because the I/O space
	may no longer owned by the HCF, due to a card swap.
	The IFB_IntEnMask is set to allow Info events, Receive events and Allocate events to generate interrupts
	and effectuated if appropriate based on IFB_IntOffCnt by calling enable_int.
	Note that since the effect of interrupt enabling has no effect on IFB_IntOffCnt, this code may
	be called not only at the transition from disabled to enabled but whenever a port is enabled.
12:	When the port successfully changes from disabled to enabled - including the case when no NIC is
	present - , the NIC status as reflected by IFB_CardStat must change to enabled

.DIAGRAM

.NOTICE
  When the Hermes enable cmd is given, the static configuration of the Hermes is done.
.ENDOC				END DOCUMENTATION

-------------------------------------------------------------------------------------------------------------*/
int hcf_enable( IFBP ifbp, hcf_16 port ) {

int	rc;


	
	if ( (ifbp->IFB_CardStat & CARD_STAT_PRESENT) == 0 
	   ) { rc = HCF_ERR_NO_NIC;	}	/* 6 */
	else {
		rc = HCF_SUCCESS;
			rc = cmd_wait( ifbp, HCMD_ENABLE | ( port << 8 ), 0 );
			if ( rc == HCF_SUCCESS ) enable_int( ifbp, HREG_EV_INFO | HREG_EV_RX | HREG_EV_ALLOC );		/* 8 */
	}
	if ( rc == HCF_SUCCESS || rc == HCF_ERR_NO_NIC ) {
		ifbp->IFB_CardStat |= CARD_STAT_ENABLED;
	}
	return rc;

}/* hcf_enable */



/*******************************************************************************************************************


.MODULE			hcf_get_data
.LIBRARY 		HCF
.TYPE 			function
.SYSTEM			msdos
.SYSTEM			unix
.APPLICATION	Data Transfer Function for WaveLAN based drivers and utilities
.DESCRIPTION
	Obtains received message data parts from NIC RAM
.ARGUMENTS
	int hcf_get_data( IFBP ifbp, int offset, wci_bufp bufp, int len )
	Card Interrupts disabled
.RETURNS
	hcf_16
		zero			NIC not removed during data copying process
		HCF_ERR_NO_NIC	NIC removed during data copying process
		......

  MSF-accessible fields of Result Block: -

.NARRATIVE
	parameters:
		ifbp		address of the Interface Block
		offset		offset (in bytes) in buffer in NIC RAM to start copy process
		len			length (in bytes) of data to be copied
		bufp		char pointer, address of buffer in PC RAM

	When hcf_service_nic reports the availability of data, hcf_get_data can be
	called to copy that data from NIC RAM to PC RAM.

	Hcf_get_data copies the number of bytes requested by the parameter len from
	NIC RAM to PC RAM. If len is larger than the (remaining) length of the
	message, undefined data is appended to the message. This implies that if
	hcf_get_data is called while the last hcf_service_nic reported no data
	available, undefined data is copied.

	Hcf_get_data starts the copy process at the offset requested by the
	parameter offset, e.g. offset HFS_ADDR_DEST will start copying from the
	Destination Address, the very begin of the 802.3 framemessage.
	In case of a fragmented PC RAM buffer, it is the responsibility of the MSF,
	to specify as offset the cumulative values of the len parameters of the
	preceeding hcf_get_data calls. This I/F gives a MSF the facility to read
	(part of) a message and then read it again.
	
.DIAGRAM
.ENDOC				END DOCUMENTATION


-------------------------------------------------------------------------------------------------------------*/
int hcf_get_data( IFBP ifbp, int offset, wci_bufp bufp, int len ) {

int rc = HCF_SUCCESS;
//int	tlen;


	if ( ifbp->IFB_CardStat & CARD_STAT_PRESENT ) {	
		if ( offset < 0 ) offset -= HFS_STAT;
		else {
			offset += ifbp->IFB_FSBase;
	    }
		if ( rc == HCF_SUCCESS ) rc = hcfio_string( ifbp, BAP_1, ifbp->IFB_RxFID, offset, bufp, 0, len, IO_IN );
	}
	return rc;
}/* hcf_get_data */




/**************************************************************************************************************


 Name:	hcf_get_info

 Summary: Obtains transient and persistent configuration information from the
	Card and from the HCF

 Parameters:
  ifbp	address of the Interface Block

  ltvp	address of LengthTypeValue structure specifying the "what" and the "how much" of the information
  		to be collected from the HCF or from the Hermes

 Returns:
	int
		..... ????????????????	

 Remarks: Transfers operation information and transient and persistent
 	configuration information from the Card and from the HCF to the MSF.
	The exact layout of the provided data structure
	depends on the action code. Copying stops if either the complete
	Configuration Information is copied or if the number of bytes indicated
	by len is copied.  Len acts as a safe guard against Configuration
	Information blocks which have different sizes for different Hermes
	versions, e.g. when later versions support more tallies than earlier
	versions. It is a consious decision that unused parts of the PC RAM buffer are not cleared.

 Remarks: The only error against which is protected is the "Read error"
	as result of Card removal. Only the last hcf_io_string need
	to be protected because if the first fails the second will fail
	as well. Checking for cmd_wait errors is supposed superfluous because
	problems in cmd_wait are already caught or will be caught by
	hcf_enable.
	
	
 3:	tallying of "No inquire space" is done by cmd_wait

 Note:
	the codes for type are "cleverly" chosen to be identical to the RID
	

 7:	The return status of cmd_wait and the first hcfio_in_string can be ignored, because when one fails, the
 	other fails via the IFB_TimStat mechanism
		
**************************************************************************************************************/
int hcf_get_info(IFBP ifbp, LTVP ltvp ) {

int				rc = HCF_ERR_LEN;
//hcf_io			reg;
hcf_16			i, len;
hcf_16			type;						//don't change type to unsigned cause of "is it a RID" test
hcf_16 			*q;							//source pointer (Tally-part of IFB)
//hcf_16 FAR 		*bq;						//source pointer (Identity or Range records)	;?why bq and not e.g. wq
wci_recordp		p = ltvp->val;				//destination word pointer (in LTV record)
//wci_bufp		cp = (wci_bufp)ltvp->val;	//destination char pointer (in LTV record)

	
	len = ltvp->len;
	type = ltvp->typ;
	
	if ( len > 1 ) {
	
		rc = HCF_SUCCESS;
		switch ( type ) {
			
#if MSF_COMPONENT_ID != COMP_ID_AP1
		  case CFG_TALLIES:																				/* 3 */
			ltvp->len = len = min( len, (hcf_16)(HCF_TOT_TAL_CNT + HCF_TOT_TAL_CNT + 1) );
			q = (hcf_16*)/*(wci_recordp)*/&ifbp->IFB_NIC_Tallies; //.TxUnicastFrames;
			while ( --len ) *p++ = *q++;
			(void)hcf_action( ifbp, HCF_ACT_TALLIES );
			break;
#endif //COMP_ID_AP1

			

			
			
		  default:
			rc = HCF_ERR_NO_NIC;
			if ( ifbp->IFB_CardStat & CARD_STAT_PRESENT ) {
				rc = HCF_ERR_TIME_OUT;			
				  	if ( type < CFG_RID_CFG_MIN ) {
				  		ltvp->len = 0;
				  	} else {
						(void)cmd_wait( ifbp, HCMD_ACCESS, type );											/* 7 */
						(void)hcfio_string( ifbp, BAP_1, type, 0, (wci_bufp)&i, 1, sizeof(hcf_16), IO_IN );
						ltvp->len = min( i, len );
						rc = hcfio_string( ifbp, BAP_1, type, sizeof(hcf_16), (wci_bufp)&ltvp->typ, 1, MUL_BY_2(ltvp->len), IO_IN );
						if ( rc == HCF_SUCCESS && i > len ) rc = HCF_ERR_LEN;
					}
			}
		}
	}
	return rc;

}/* hcf_get_info */


/*******************************************************************************************************************

.MODULE			hcf_initialize  ;?in fact an hcf-support routine, given an hcf_... name just in case we want to
								  export it over the WCI later
.LIBRARY 		HCF
.TYPE 			function
.SYSTEM			msdos
.SYSTEM			unix
.SYSTEM			NW4
.APPLICATION	Card Initialization Group for WaveLAN based drivers and utilities
.DESCRIPTION    ..........., in addition, a light-weight diagnostic test of the NIC
.ARGUMENTS
  int hcf_initialize( IFBP ifbp )

.RETURNS
	HCF_SUCCESS
	HCF_ERR_NO_NIC
	HCF_ERR_TIME_OUT;
	HCF_FAILURE (via cmd_wait)
				(via hcf_get_info)
	HCF_ERR_INCOMP_PRI
	HCF_ERR_INCOMP_STA	
	
  MSF-accessible fields of Result Block:
   	IFB_DUIFRscInd, IFB_NotifyRscInd, IFB_PIFRscInd cleared
   	IFB_MBInfoLen, IFB_RxLen, IFB_RxStat cleared
   	IFB_CardStat  -	CARD_STAT_ENA_0	through CARD_STAT_ENA_6
				  -	CARD_STAT_INCOMP_PRI
				  -	CARD_STAT_INCOMP_STA
   	

.NARRATIVE

  Parameters:
	ifbp		address of the Interface Block

  hcf_initialize will successively:
  -	initialize the NIC by calling ini_hermes
  -	calibrate the S/W protection timer against the Hermes Timer by calling calibrate

  Condition Settings:
	Card Interrupts: Disabled  (Note that the value of IFB_IntOffCnt is unchanged)

  Remarks: since hcf_initialize is the first step in the initialization of the card and since the strategy is to
   detect problems as a side effect of "necessary" actions, hcf_initialize has, in deviation of the general
   strategy, an additional "wait for busy bit drop" at all places where Hermes commands are executed. An
   additional complication is that no calibrated value for the protection count can be assumed since it is
   part of the first execution of hcf_disable to determine this calibrated value (a catch 22). The initial
   value (set at INI_TICK_INI by hcf_connect) of the protection count is considered safe, because:
   o the HCF does not use the pipeline mechanism of Hermes commands.
   o the likelihood of failure (the only time when protection count is relevant) is small.
   o the time will be sufficiently large on a fast machine (busy bit drops on good NIC before counter expires)
   o the time will be sufficiently small on a slow machine (counter expires on bad NIC before the enduser
     switches the power off in despair
	IFB_TickIni is used in cmd_wait to protect the Initialize command. The time needed to wrap a 32 bit counter
	around is longer than many humans want to wait, hence the more or less arbitrary value of 0x10000L is
	chosen, assuming it does not take too long on an XT and is not too short on a scream-machine.
	Once we passed the CARD_STAT_PRESENT test on IFB_CardStat, the other bits can be reset. This is needed
	to have a dynamical adjustment of the Station/Primary Incompatibility flags.
	Especially IFB_TimStat must be cleared (new round, new chances)

 Remarks: First the HCF disables the generation of card interrupts. Next it waits for the Busy bit in the
   Command register to drop (the additional safety required for hcf_initialize as described above). If the Hermes
   passes this superficial health test, the Hermes Initialize command is executed. The Initialize command acts
   as the "best possible" reset under HCF control. A more "severe/reliable" reset is under MSF control via the
   COR register.

 Remarks: If the Initialize of the Hermes succeeds, the S/W protection counter is calibrated if not already
   calibrated. This calibration is "reasonably" accurate because the Hermes is in a quiet state as a result of
   the Initialize command. The hcf_put_info function is used to program the Hermes Tick for its minimum
   interval (1024 microseconds). Programming the Tick interval terminates the old interval timing immediately
   and starts the new interval. Due to this ad-hoc switch the first interval has a larger inaccuracy. By
   timing immediately a second interval the accuracy improves due to the synchronization of HCF and Hermes.
   After this second interval, the Hermes Tick is programmed for its default value of 1 second again.

.NARRATIVE
 2:	Clear all fields of the IFB except those which need to survive hcf_initialize. This is intended to make
 	the behavior and - as a consequence - the debugging of the HCF more reproduceable.

 3:	Disable the interrupt generation facility (see also #30)
 5: Depending on whether there is selective disabling of a single port or a collective disabling of
	all ports a specific bit or all bits representing the enabled ports are reset. In case of "all ports"
	none of the other bits except CARD_STAT_ENABLED is relevant, so as an easy implementation all those
	other bits are cleared.
	The individual bits conveyed in IFB_CardStat are historically grown. To leave the WCI unchanged, the
	individual "port enabled" bits are scattered through IFB_CardStat. As a consequence there is some bit
	arithmetic involved to convert a port number to a bit flag
	The masking of port with HCF_PORT_MASK is a cheap safeguard against I/F violations by the MSF. If the MSF
	supplies an invalid bit pattern, unwanted bits may end up in Hermes Command register via Disable command
	with unpredictable effects.
 7: Check whether CARD_STAT_PRESENT bit of IFB_CardStat is on. If not the remainder of hcf_initialize must be
	skipped to prevent I/O because the I/O space may no longer owned by the HCF, due to a card swap.
12:	When a single port must be disabled AND it is not the only enabled port, that port is selectively
	disabled. If all ports or the only enabled port is to be disabled, the disabling is skipped and the
	Hermes Initiate command is supposed to take care of it all.
16: perform a superficial Hermes health test. Note that in hcf_initialize all (or at least most) activities are
	checked for conditions like "Busy bit should drop". If such a condition is not met in time, hcf_initialize
	returns an error code. Hcf_functions which are only called during "normal" operations may ignore such
	events. Their only obligation is to prevent that the code hangs.
	Note that early models of the Hermes needed some arbitrary read before the first write activity to operate
	stable (ref tracker 27). This code achieves that function as a side effect.
18:	Initialize the Hermes. The results of this way of initialization depends on the capabilities of the Hermes
  	firmware. Therefore, the Hermes H/W controlled bits, like those in the evitable register are not guaranteed
  	to be cleared as result of the initialize command. However it is guaranteed that no more events are in the
    pipeline. Ack-ing indiscriminately all events resolves this problem. An alternative would be to use the
    resulting value of "IN_PORT_WORD( ifbp->IFB_IOBase + HREG_EV_STAT )" rather than 0xFFFF to specifically
    only reset those events which are set. This strategy is considered to be only more aesthetically pleasing
    (if that).
20:	Perform some housekeeping tasks
  - Write HCF_MAGIC as signature to S/W support register 0.  This signature is used to detect card removal
	wherever the presence of the card is critical while HCF may not yet have been informed by the MSF of the
	removal of the card.  Note that this task can not be postponed because that would cause the hcfio_in_string
	called by hcf_get_info to fail
22:

	  -	IFB_TickIni	must be initialized (at INI_TICK_INI) to prevent that actions like hcf_put_info immediately
	    after hcf_connect (that is without intervening hcf_disable) at an absent (or failing) NIC take too
	    long.  Note that this is a legal hcf-sequence according to the WCI-specification.




	IFB_TickIni is the value used to initialize the S/W protection counter in a way which makes the
	expiration period more or less independent of the processor speed. If IFB_TickIni is not yet calibrated,
	it is done now.
	First off all the Hermes Tick period is programmed for a "reasonable" interval, currently 8092 or 8k
	microseconds, by means of hcf_put_info. Note that IFB_DLTarget, which is guaranteed to get the correct
	value later on in hcf_enable, is misused as re-entrant storage for the RID used to program the Tick period.
	The HCF synchronizes itself with the Hermes timer by waiting for the first timer tick. This synchronizing is done by
	ack-ing the Tick regardless of its current value. This guarantees Tick becomes low. Then Tick is sampled
	till it is high, which guarantees a new complete interval starts in the Hermes. Tick is acked again and
	another Tick is awaited. This period is as accurate as we can get.
	To diminish the chance that in a pre-emptive environment IFB_TickIni is calibrated too low because the HCF
	just happens to loose control during this calibration, the calibration is performed 10 times and the
	largest value is used.
	IFB_TickIni is then set at approximately 1 second by multiplying that largest value by 128. The 8k
	microseconds interval and the multiplication by 128 are chosen as a compromise between accuracy of
	the calibration. time consumed by the calibration and possibilities for the compiler to optimize
	the arithmetic.
26:	Finally the Hermes Tick period is programmed for a "reasonable" runtime interval, currently 1 second
	(1,000,000/1,024 kilo-microseconds), by means of hcf_put_info (again the available CONCATENATED storage
	is misused)
	Note that in case of failure, IFB_TickIni ends up as INI_TICK_INI, which is a supposedly acceptable
	value to handle the rare case of a broken card.
30: The Supplier Range of the Primary Firmware function is retrieved from the Hermes and checked against
	the Top and Bottom level supported by this HCF.
	If the primary firmware does not supply this RID or supplies the "old" HardwareStructure Info, the
	Primary Compatibility check is skipped. These conditions are recognized based on the length field supplied
	by the Hermes. ;?is this wise in the post-GCA area
32: In case of a HCF compiled for station functionality, the Supplier Range of the Station Firmware function
	is retrieved from the Hermes and checked against the Top and Bottom level supported by this HCF.
	Note that the Firmware can have multiple Variants, but that the HCF currently only supports a single
	variant.
40:	Perform some more housekeeping tasks
  -	Decrement ifbp->IFB_IntOffCnt to compensate side effect of ACT_INT_OFF action at begin of hcf_initialize (see
	#2). This can not be handled by calling hcf_action with HCF_ACT_ON, because this could as undesirable
	side effect actually enable interrupts
	
.NOTICE
 o  For all practical WCI purposes there is no practical difference between a Hermes disable command at all
	individual ports and an hermes initialize command
 o  hcf_initialize disables the card interrupts, however it does NOT influence IFB_IntOffCnt.
	This way it is symmetrical with hcf_enable, which does NOT enable the card interrupts.	


   	IFB_CardStat  -	CARD_STAT_INCOMP_PRI
				  -	CARD_STAT_INCOMP_STA
   	
 5:	The house keeping is done, consisting of the steps:
	- allocate a Tx Frame Structure for the protocol stack
	- allocate a Tx Frame Structure for the utility
	- allocate a Information Frame Structure for the Notify command
	Note that a subsequent allocate is only performed if the preceding one
	succeeded
	- if all allocates succeeded, the Resource Indicators corresponding
	  with the Tx Frames are set


**************************************************************************************************************/
int hcf_initialize( IFBP ifbp ) {

int		rc;
//hcf_16	*p;
hcf_8	*q;


	for ( q = (hcf_8*)&ifbp->IFB_PIFRscInd; q < (hcf_8*)&ifbp[1]; *q++ = 0) /*NOP*/;					/* 2 */

//	if ( (ifbp->IFB_CardStat & CARD_STAT_INI) == 0 ) {				//present but not initialized	/* 7 */
	do { //;?CARD_STAT_PRESENT check superfluous as long as hcf_initialize is not defined on the WCI
		rc = ini_hermes( ifbp );
		if ( rc != HCF_SUCCESS ) break;																/* 32*/
		OUT_PORT_WORD( ifbp->IFB_IOBase + HREG_SW_0, HCF_MAGIC );									/* 20*/
		rc = calibrate( ifbp );   																	/* 22*/
		if ( rc != HCF_SUCCESS ) break;

#if defined MSF_COMPONENT_ID  //;?interesting question at which level HCFL interacts		
#endif // MSF_COMPONENT_ID
        ifbp->IFB_CardStat |= CARD_STAT_INI;	//consider this as sufficient to reach CARD_STAT_INI?	/* 24*/
		if ( rc != HCF_SUCCESS ) break;   //;? apparently this still should follow the moved IFB_DLTarget logic but
											//;? think this over for the different scenarios
		if ( ( ifbp->IFB_PIF_FID    = alloc( ifbp, HFS_TX_ALLOC_SIZE )  ) == 0		||				/* 5 */
			 ( ifbp->IFB_DUIF_FID   = alloc( ifbp, HFS_TX_ALLOC_SIZE )  ) == 0  ) {
			rc = HCF_FAILURE;
		} else {
			ifbp->IFB_PIFRscInd = ifbp->IFB_DUIFRscInd = 1;

		}
	} while ( 0 ); //pseudo goto-less, accept "warning: conditional expression is constant"

	return rc;
}/* hcf_initialize */


/*******************************************************************************************************************


.MODULE			hcf_put_data
.LIBRARY 		HCF
.TYPE 			function
.SYSTEM			msdos
.SYSTEM			unix
.SYSTEM			NW4
.APPLICATION	Data Transfer Function for WaveLAN based drivers and utilities
.ARGUMENTS
	void hcf_put_data( IFBP ifbp, wci_bufp bufp, int len, hcf_16 port )
	Card Interrupts disabled

.RETURNS
	void

  MSF-accessible fields of Result Block: -

.DESCRIPTION	Transfers (part of) transmit message to the NIC and handles
	the Ethernet-II encapsulation if applicable
.NARRATIVE
	parameters:
		ifbp		address of the Interface Block
		bufp		char pointer, address of buffer in PC RAM
		len			length (in bytes) of data to be copied
		port		HCF_PORT_0 - HCF_PORT_6 .........;?
					HCF_PUT_DATA_RESET


	Refer to hcf_service;?non-existing reference, for a concise description about possible
	relation/sequencing of hcf_put_data in the Interrupt Service Routine
	
	In essence, hcf_put_data copies the number of bytes specified by parameter len from the location in PC
	RAM specified by bufp to the NIC RAM buffer associated with the Protocol Stack dedicated FID.
	The first call succeeding hcf_send (or hcf_enable), writes the first byte at offset HFS_ADDR_DEST in
	the transmit data buffer, successive hcf_put_data calls continue where the preceeding hcf_put_data stopped.
	
	IFB_FrameType determines whether the message in the PC RAM buffer is interpreted as an 802.3 or 802.11
	frame.  This influences:
 	o the position where the first byte of the initial hcf_put_data is stored
 	o Only in case of the 802.3 frame type, hcf_put_data checks whether the frame is an Ethernet-II rather
 	  than an "official" 802.3 frame. The E-II check is based on the length/type field in the MAC header. If
 	  this field has a value larger than 1500, E-II is assumed. The implementation of this test fails if the
	  length/type field is split over 2 hcf_put_data calls.
	  If E-II is recognized, the length field HFS_LEN_ABS is skipped for the time being and a SNAP header is
	  inserted starting at HFS_DAT_ABS. This SNAP header represents either RFC1042 or Bridge-Tunnel
	  encapsulation, depending on whether the type is absent or present in enc_trans_tbl.
 	o In case of the 802.11 frame type, hcf_put_data checks whether the complete header + length field is
 	  written (note that part of the header may be written by previous hcf_put_data calls and part may be
 	  written by this call).  If so, the next byte is written at HFS_DAT_ABS (the 802.3 header area is skipped)

	It is allowed to write the 802.3 header, 802.11 header and/or data in fragments, e.g. the first
	hcf_put_data call writes 18 bytes starting at location HFS_ADDR_1_ABS and the second call writes 6 more
	bytes starting at location HFS_ADDR_4. Although Address part #4 is not present in some 802.11 headers,
	all 4 addressing parts and the length field must be written in case of 802.11. Once the complete header
	is written, the data part is written starting from offset HFS_DAT_ABS.

	Hcf_put_data does not check for transmit buffer overflow because the Hermes does this protection.
	In case of a transmit buffer overflow, the surplus which does not fit in the buffer is simply dropped.
	Note that this possibly results in the transmission of incomplete frames.

.DIAGRAM
1*: If the card is not present, prevent all I/O because "our" I/O base may have been given away to someone
	else in a CS/SS environment.  Also no I/O should be performed if the NIC is not enabled. However
	an MSF which calls hcf_put_data while the NIC is not enabled probably contains a logic flaw (or has a
	strategy which was not foreseen at the time this was written)
10* HCF_PUT_DATA_RESET discards all the data put by preceeding hcf_put_data calls and resets the HCF
	housekeeping just the same as after an hcf_send triggered allocate event.
	Note: To make the WCI fail-safe, invalid port numbers are silently rejected by treating them as 
	HCF_PUT_DATA_RESET. Note that the assumption is that this should never ever occure in a debugged MSF and 
	that during debugging the ASSERT is sufficient support to help the MSF programmer.
2*:	This statement is only true at the first hcf_put_data call after an hcf_send result or hcf_enable
	The housekeeping is done.
 	o the PIFRscInd is cleared, so the MSF can not begin another hcf_put_data/hcf_send sequence
	before completing the current one
 	o the Tx Encoding flag (TxFrameType) is cleared
 	o the index to the first free position in the FID (IFB_PIFLoadIdx) is initialized based on IFB_FSBase.
 	  IFB_FSBase is initialized when hcf_action is called with HCF_ACT_802_3 or HCF_ACT_802_11
3*:	Pay Attention: it may seem attractive to change this code, e.g. to save the superfluous call to
	hcfio_out_string when the Destination and Source address are written by the preceeding call and the
	current call starts at the length/type field. However this code is "reasonably carefully" crafted
	to take in account all boundary conditions. It is very easy to make a change which does not work under
	all feasible split ups of the message in fragments.
	First IFB_PIFLoadIdx is checked.
	  - If IFB_PIFLoadIdx points past HFS_LEN_ABS, the preceeding call(s) to hcf_put_data already passed the
	  length/type field. As a consequence the fragment can be concatenated to the data already copied to
	  NIC RAM.
	  - If IFB_PIFLoadIdx does not point past HFS_LEN_ABS, the current fragment may or may not contain part of
	  the Destination and/or Source Address and it may or may not contain the length/type field.
	  If the fragment contains addressing information or -in case of 802.11- length info , this information
	  is copied/concatenated to the NIC RAM buffer. The working variables (pointer and length of fragment) as
	  well as the IFB_PIFLoadIdx are adjusted.
	The semi-obscure differences in the boundary testing are caused by:
	  o 802.11: the "below the boundary" area is Addr1, Addr2, Addr3, Ctrl, Adrr4 + DataLen and the "above"
	  	area is the "real" data
	  o 802.3: the "below the boundary" area is DestAddr + SrcAddr and the "above" area is the length +
	  	"real" data
	  o E-II: the "below the boundary" area is DestAddr + SrcAddr, then there is a "virtual" area with the
	  	SNAP header (which will in the end include the HCF calculated length)  and the "above" area is the
	  	"protocol stack length" (is in reality the type code) + "real" data
4*:	If there is still data left, IFB_PIFLoadIdx may need adjustment (802.11 and E-II encapsulation).  Again
	note that this length check is crucial to prevent mis-manipulation of IFB_PIFLoadIdx in case the header
	is written in multiple fragments.
	In case of 802.3, the E-II check is done. In case of E-II, the encapsulation type (RFC1042 versus
	Bridge-Tunnel) is determined and the corresponding SNAP header is written to NIC RAM and
	IFB_PIFLoadIdx is adjusted.
6*:	All data which is not already copied under 3*, is copied here.
	In case of 802.11, the HFS_DAT field is the first field written by this code.
	In case of 802.3, the HFS_LEN field is the first field written by this code.
	In case of E-II encapsulation, the HFS_TYPE field is the first field written by this code.
	Note that in case of E-II encapsulation, the HFS_LEN field is not written by hcf_put_data at all, but by
	hcf_send because the data length is not	known till all fragments have been processed.
	
.NOTE	
	The possible split of a single hcf_put_data call into 2 calls to hcfio_out_string results in 2 calls
	to bap_ini, which may be unexpected while you are debugging, but is never the less the intended behavior.
	Along the same line a call of hcfio_out_string with a value of 0 for parameter len may be unexpected, e.g.
	when the len parameter of hcf_put_data is either 1 or 2, the latter depending on the odd/even aspects of
	IFB_PIFLoadIdx.	
	
	
	
.NOTE
	The test on PIFRscInd to distinguish the initial hcf_put_data from subsequent calls is not thread safe.
	It is assumed that threaded MSFs have their own mechanism to assure that hcf_put_data calls belonging to
	a single frame are atomic with respect to each other. It is also assumed that the MSF takes care that
	the hcf_put_data calls of multiple frames do not run concurrent
	
	
.ENDOC				END DOCUMENTATION


-------------------------------------------------------------------------------------------------------------*/
void hcf_put_data( IFBP ifbp, wci_bufp bufp, int len, hcf_16 port ) {

int		idx;				//working index into Tx Frame structure, presume MSF control
//int		tlen;				//working type/length of frame, working length for partial copy of frame
	

	if ( ifbp->IFB_CardStat & CARD_STAT_PRESENT ) {															/* 1 */
			if ( ifbp->IFB_PIFRscInd ) {																	/* 2 */
				ifbp->IFB_PIFRscInd = 0;
				ifbp->IFB_PIFLoadIdx = ifbp->IFB_FSBase;    //;?<HCF_L> should result in 0
			}
			
			idx = ifbp->IFB_PIFLoadIdx;
			ifbp->IFB_PIFLoadIdx += (hcf_16)len;
			(void)hcfio_string( ifbp, BAP_0, ifbp->IFB_PIF_FID, idx, bufp, 0, len, IO_OUT);		/* 6 */
	}
	return;
}/* hcf_put_data */


/**************************************************************************************************************


 Name:	hcf_put_info

 Summary: Transfers operation information and transient and persistent
 	configuration information to the Card.

 Parameters:
  ifbp	address of the Interface Block

  type	specifies the RID (as defined by Hermes I/F)

  bufp	address in NIC RAM where record data is located

   len	length of data (in bytes)

.NARRATIVE

 Remarks:
	CFG_NOTIFY: only runs after hcf_enable

 Remarks: Configuration information is copied from the provided data
	structure into the Card. The exact layout of the provided data
	structure depends on the action code. Also the mechanism used to copy
	the data to the card depends on the action code. In order to make the
	changes which are based on the Access command (see support routine put_info)
	sustain over activities like hcf_diagnose and recovery from PCMCIA card
	insertion, the data associated with these particular action codes, is
	saved in the IF-block. The codes for this type are "cleverly" chosen to
	be identical to the RID.
	
	bufp is defined as a pointer to items of type hcf_16 because of the
	correlation with the Hermes definition
	
	
.DIAGRAM

.NOTICE
	Future enhancements in the functionality offered by the WCI and/or implementation aspects of the HCF
	may warrant filtering on the type-field of the LTV to recognize non-MSF accessible records, e.g. CFG_TICK
	
**************************************************************************************************************/

int hcf_put_info( IFBP ifbp,
				  LTVP ltvp		/*number identifying the type of change
<PRE>
									CFG_INFO_FRAME_MIN	lowest value representing an Information Frame
									CFG_NOTIFY			Handover Address
										
									CFG_TALLIES			Communications Tallies
									CFG_SCAN			Scan results
										                        	
									CFG_LINK_STAT 		Link Status
									CFG_ASSOC_STAT		Association Status
								
</PRE>							*/
			    ) {

//int			cnt = 3;
//hcf_16		i = ltvp->len - 1;
int			rc = HCF_SUCCESS;

	
	if ( CFG_RID_CFG_MIN <= ltvp->typ && ltvp->typ <= CFG_RID_CFG_MAX ) {
      	//all codes between 0xFC00 and 0xFCFF are passed to Hermes)
//		if ( ( ifbp->IFB_CardStat & CARD_STAT_PRI_STA_PRES ) == CARD_STAT_PRESENT ) {
//			do {
//				rc = hcfio_string( ifbp, BAP_1,
//								   ltvp->typ, 0, (wci_bufp)ltvp, 2, MUL_BY_2(ltvp->len + 1), IO_OUT_CHECK );
//			} while ( cnt-- && rc != HCF_SUCCESS );
//			if ( rc == HCF_SUCCESS ) rc = cmd_wait( ifbp, HCMD_ACCESS + HCMD_ACCESS_WRITE, ltvp->typ );
//			if ( rc == HCF_SUCCESS ) rc = put_info( ifbp, ltvp );

		rc = put_info( ifbp, ltvp );
//		}
	}	
	return rc;
}/* hcf_put_info */





/******************************************************************************************************************

.MODULE			hcf_send
.LIBRARY 		HCF
.TYPE 			function
.SYSTEM			msdos
.SYSTEM			unix
.SYSTEM			NW4
.APPLICATION	Data Transfer Function for WaveLAN based drivers and utilities
.DESCRIPTION	Transmit a message on behalf of the protocol stack
.ARGUMENTS
	void hcf_send( IFBP ifbp , hcf_send_type type )
	Card Interrupts disabled

.RETURNS
	void

  MSF-accessible fields of Result Block: -

.NARRATIVE
	Hcf_send transmits the Protocol Stack message loaded in NIC RAM by the
	preceeding hcf_put_data calls.

.DIAGRAM
1:	The actual data length (the number of bytes in the Tx Frame structure
	following the 802.3/802.11 Header Info blocks, is determined by
	IFB_PIFLoadIdx, the index in the Transmit Frame Structure to store the
	"next" byte. Note that this value must be compensated for the header info
	by subtracting HFS_DAT.
2/3:TxFrameType - which is based on the preceding hcf_put_data calls - defines
	whether the actual data length is written to the 802.11 or 802.3 Header Info
	block.
2:	In case of 802.11, the entry parameter type is augmented to reflect	802.11
	before it is written to the Control Field block.
3:	In case of 802.3, the actual length must be converted from the native
	format of the Host (Little Endian in case of an 80x86) to Big Endian before
	it is written to the 802.3 Header Info block.
4:	The actual send+reclaim command is performed by the routine send.
7:	The return status of hcfio_in_string can be ignored, because when it fails, cmd_wait will fail via the
 	IFB_TimStat mechanism
.NOTICE
  ;?This comment is definitely out of date
  The choice to let hcf_send calculate the actual data length as
  IFB_PIFLoadIdx - HFS_DAT, implies that hcf_put_data with the HFS_LUCENT
  mechanism MUST be used to write the Data Info Block. A change in this I/F
  will impact hcf_send as well.
  An alternative would be to have a parameter datlen. If datlen is zero, the
  current behavior is used. If datlen has a non-zero value, its value is used
  as the actual data length (without validating against HCF_MAX_MSG and without
  validating the total number of bytes put by hcf_put_data).

.NOTICE
  hcf_put_data/send leave the responsibility to only send messages on enabled ports at the MSF level.
  This is considered the strategy which is sufficiently adequate for all "robust" MSFs, have the least
  processor utilization and being still acceptable robust at the WCI !!!!!
.ENDOC				END DOCUMENTATION

------------------------------------------------------------------------------------------------------------*/
int hcf_send( IFBP ifbp , hcf_16 port ) {	//;?note that port is unused due to ambivalence about what the "right" I/F is

int	rc = HCF_SUCCESS;


	if ( ifbp->IFB_CardStat & CARD_STAT_PRESENT ) {												/* 1 */	
		/* H/W Pointer problem detection */	
		if ( ifbp->IFB_BAP_0[0] != ifbp->IFB_FSBase ) {	//;?<HCF _L> should BE HARD CODED, also add to send diag msg	/* 30*/
			rc = hcfio_string( ifbp, BAP_0, ifbp->IFB_PIF_FID, ifbp->IFB_PIFLoadIdx, NULL, 0, 0, IO_OUT_CHECK );
			
			if ( rc == HCF_FAILURE ) {
				ifbp->IFB_PIFRscInd = 1;
			}
		}
		if ( rc == HCF_SUCCESS ) {
			if ( /*ifbp->IFB_FrameType == ENC_802_11 || */ ifbp->IFB_TxFrameType == ENC_TX_E_II ) {		/* 2 */
				ifbp->IFB_PIFLoadIdx -= HFS_DAT_ABS;		//actual length of frame					/* 1 */
				CNV_INT_TO_BIG_NP(&ifbp->IFB_PIFLoadIdx);  //;?is it worthwhile to have this additional macro
				(void)hcfio_string( ifbp, BAP_0, ifbp->IFB_PIF_FID, HFS_LEN_ABS,
										(wci_bufp)&ifbp->IFB_PIFLoadIdx, 0, 2, IO_OUT );			/* 7 */
			}
//			send( ifbp, ifbp->IFB_PIF_FID, port | ifbp->IFB_FrameType );								/* 4 */
			(void)cmd_wait( ifbp, HCMD_TX + HCMD_RECL, ifbp->IFB_PIF_FID );			//justify "void"
		}
		/* reset the BAP pointer for the Tx Framestructure, note that we access the BAP not the NIC RAM
		 * after we relinguished control of the Tx FID to the Hermes
		 */
		(void)hcfio_string( ifbp, BAP_0, ifbp->IFB_PIF_FID, ifbp->IFB_FSBase, NULL, 0, 0, IO_IN );
	}
	return rc;
} /* hcf_send */



/*******************************************************************************************************************

.MODULE			hcf_send_diag_msg
.LIBRARY 		HCF
.TYPE 			function
.SYSTEM			msdos
.SYSTEM			unix
.SYSTEM			NW4
.APPLICATION	Data Transfer Function for WaveLAN based drivers and utilities
.DESCRIPTION	Transmit a message on behalf of the Driver-Utility I/F
.ARGUMENTS
	void hcf_send_diag_msg( IFBP ifbp, wci_bufp bufp, hcf_16 len )
	Card Interrupts disabled

.RETURNS
	void

  MSF-accessible fields of Result Block: -

.NARRATIVE
	Hcf_send_diag_msg transmits the message
.DIAGRAM

 2:

 4: Based on the assumption that hcf_send_diag_msg is called at a low frequency, HFS_TX_CNTL_ABS is written
  	on each call rather than using an IFB-field to remember the previous value and update only if needed


.ENDOC				END DOCUMENTATION

-------------------------------------------------------------------------------------------------------------*/
int hcf_send_diag_msg( IFBP ifbp, hcf_16 type, wci_bufp bufp, int len ) {

int rc = HCF_SUCCESS;


	if ( ifbp->IFB_CardStat & CARD_STAT_PRESENT ) {
		rc = HCF_ERR_BUSY; //;?more appropriate value needed
		if ( ifbp->IFB_DUIFRscInd ) {																	/* 2 */
			rc = hcfio_string( ifbp, BAP_0, ifbp->IFB_DUIF_FID, HFS_ADDR_DEST_ABS, bufp, 0, len, IO_OUT_CHECK );
			if ( rc == HCF_SUCCESS ) {
				ifbp->IFB_DUIFRscInd = 0;
				(void)hcfio_string( ifbp, BAP_0, ifbp->IFB_PIF_FID, HFS_TX_CNTL_ABS, 		//justify void
								  (wci_bufp)&type, 1, 2, IO_OUT );								/* 4 */
				(void)cmd_wait( ifbp, HCMD_TX + HCMD_RECL, ifbp->IFB_DUIF_FID );			
			}
		}
	}
	return rc;
} /* hcf_send_diag_msg */





/*******************************************************************************************************************


.MODULE			hcf_service_nic
.LIBRARY 		HCF
.TYPE 			function
.SYSTEM			msdos
.APPLICATION	Data Transfer Function for WaveLAN based drivers and utilities
.DESCRIPTION	Provides received message and link status information
.ARGUMENTS
	int	hcf_service_nic(IFBP ifbp )
	Card Interrupts disabled

.RETURNS
	int
		all the bits of the Hermes evitable register, which are encountered during execution of hcf_service_nic
		the "pseudo"-events HREG_EV_NO_CARD, HREG_EV_DUIF_RX
	MSF-accessible fields of Result Block
		IFB_RxLen			0 or Frame size as reported by LAN Controller
		IFB_RxStat
		IFB_MBInfoLen
		IFB_PIFRscInd
		IFB_DUIFRscInd
		IFB_NotifyRscInd
		IFB_HCF_Tallies


.NARRATIVE
	hcf_service_nic is primarily intended to be part of the Interrupt Service Routine.
	hcf_service_nic is presumed to neither interrupt other HCF-tasks nor to be interrupted by other HCF-tasks.
	A way to achieve this is to precede hcf_service_nic as well as all other HCF-tasks with a call to
	hcf_action to disable the card interrupts and, after all work is completed, with a call to hcf_action to
	restore (which is not necessarily the same as enabling) the card interrupts.
	In case of a polled environment, it is assumed that the MSF programmer is sufficiently familiar with the
	specific requirements of that environment to translate the interrupt strategy to a polled strategy.
	
	hcf_service_nic services the following Hermes events:
		HREG_EV_INFO		Asynchronous Information Frame
		HREG_EV_INFO_DROP	WMAC did not have sufficient RAM to build Unsolicited Information Frame
		HREG_EV_ALLOC		Asynchronous part of Allocation/Reclaim completed
		HREG_EV_RX			the detection of the availability of received messages

	If a message is available, its length is reflected by the IFB_RxLen field of the IFB. This length
	reflects the 802.3 message length (i.e. the data itself but not the Destination Address, Source Address,
	DataLength field nor the SAP-header in case of decapsulation by the HCF).
	If no message is available, IFB_RxLen is zero.

  **Buffer free strategy
	When hcf_service_nic reports the availability of a message, the MSF can access that message or parts
	thereof, by means of hcf_get_data calls till the next call of hcf_service_nic. Therefore it must be
	prevented that the LAN Controller writes new data in the buffer associated with the last hcf_service_nic
	report.
	As a consequence hcf_service_nic is the only procedure which can free receive buffers for re-use by the
	LAN Controller. Freeing a buffer is done implicitly by acknowledging the Rx event to the Hermes. The
	strategy of hcf_service_nic is to free the buffer it has reported as containing an available message in
	the preceeding call (assuming there was an available message).
	A consequence of this strategy is that the Interrupt Service Routine of the MSF must repeatedly call
	hcf_service_nic till hcf_service_nic returns "no message available". It can be reasoned that
	hcf_action( INT_ON ) should not be given before the MSF has completely processed a reported Rx-frame. The
	reason is that the INT_ON action is guaranteed to cause a (Rx-)interrupt (the MSF is processing a
	Rx-frame, hence the Rx-event bit in the Hermes register must be active). This interrupt will cause
	hcf_service_nic to be called, which will cause the ack-ing of the "last" Rx-event to the Hermes,
	causing the Hermes to discard the associated NIC RAM buffer.


.DIAGRAM
 2: IFB_RxLen and IFB_RxStat must be cleared before the NIC presence check otherwise these values may stay
 	non-zero if the NIC is pulled out at an inconvenient moment
 4: If the card is not present, prevent all I/O because "our" I/O base may have been given away to someone
	else in a CS/SS environment.
	The MSF may have considerable latency in informing the HCF of the card removal by means of an hcf_disable.
	To prevent that hcf_service_nic reports bogus information to the MSF with all - possibly difficult to
	debug - undesirable side effects, hcf_service_nic pays performance wise the prize to use the momentanuous
	NIC presence test by checking the contents of the Hermes register HREG_SW_0 against the value HCF_MAGIC.
 6:	The return status of hcf_service_nic is defined as reflecting all interrupt causes this call has run into,
 	hence an accumulator is needed. This return status services ONLY to help the MSF programmer to debug the
 	total system.
 	When the card is removed, the pseudo event HREG_EV_NO_CARD is reported.
 	NOTE, the HREG_EV_NO_CARD bit is explicitly not intended for the MSF to detect NIC removal. The MSF must
 	use its own - environment specific - means for that.
10:	ack the "old" Rx-event. See "Buffer free strategy" above for more explanation.
    IFB_RxFID, IFB_RxLen and IFB_RxStat must be cleared to bring both the internal HCF house keeping as the
    information supplied to the MSF in the state "no frame received"
12:	The evitable register of the Hermes is sampled and all non-Rx activities are handled.
 	The non-Rx activities are:
	 -	Alloc.  The corresponding FID register is sampled, and based on this FID, either the IFB_PIFRscInd,
	 	the IFB_DUIFRscInd or the IFB_NotifyRscInd is raised.
	 	Note that no ASSERT is performed to check whether the RscInd corresponding with the sampled 
	 	HREG_ALLOC_FID has a zero value. It is felt that this obscures the code to the reader while adding
	 	little practical value
	 -	LinkEvent (including solicited and unsolicited tallies) are handled by procedure isr_info.
	 -	Info drop events are handled by incrementing a tally
14:	All the non-Rx/non-Cmd activities are acknowledged. Combining all these acknowledgements to a single 
	place, is considered an optimization.
	Note that the Rx-acknowledgement is explicitly not included, as justified in "Buffer free strategy" above.
	Note that the Cmd-acknowledgement is explicitly not included, because all command handling is handled 
	in line.
16:	The handling of the non-Rx activities, may have bought the Hermes sufficient time to raise an Rx event
	in the evitable register (assuming an other Rx event was pending and this loop through hcf_service_nic
	acknowledged an Rx event). Therefore the evitable register is sampled again. If a frame is available,
	the FID of that frame and the characteristics (status and length) are read from the NIC. These values are, 
	after Endianess conversion if needed, stored in IFB_RxStat and IFB_RxLen. IFB_RxLen is also adjusted for 
	the size of the 802.3 MAC header. Note: Whether this adjustment is the correct/most optimal for 802.11
	is debatable, however it is paramount that IFB_RxFID and IFB_RxLEN must either be both zero or both
	non-zero to get a coherent behavior of the MSF+HCF.
18:	If the Hermes frame status reflects an error - which can only occure in promiscuous mode - the frame
	is not further processed and control is passed back to the MSF
20:	WMP messages are processed by copying them to the MailBox. Accu is updated to reflect the reception
	of the WMP frame to the debugger and sample is modified to go once more through the loop in the hope 
	to process the next pending Rx frame.
22: Both in 802.11 mode and 802.3_pure mode, the frame is not further processed (no decapsulation) and 
	control is passed back to the MSF.
	In 802.3 mode the HCF checks whether decaposulation is needed (i.e. the Hermes reported Tunnel
	encapsulation or the Hermes reported 1042 Encapsulation and the frame type does not match one of the 
	values in enc_trans_tbl.
	The actual decapsulation takes place on the fly in hcf_get_data, based on the value of IFB_RxFence.
	Note that in case of decapsulation the SNAP header is not passed to the MSF, hence IFB_RxLen must be 
	compensated for the SNAP header length
	
.NOTICES
    To make it possible to discriminate between a message without payload (only MAC addresses and implicit
    the length) it is a convenient I/F to add 14 ( space occupied by MAC addresses and Length) to the
    Hermes reported payload. So the maintenance programmer should be forwarned when considering changing
    this strategy. Also the impact on 802.11 should be considered ;?
.ENDOC				END DOCUMENTATION

-------------------------------------------------------------------------------------------------------------*/
int	hcf_service_nic(IFBP ifbp ) {

int		accu = HREG_EV_NO_CARD;
hcf_16	sample, tmp;


    ifbp->IFB_RxLen = ifbp->IFB_RxStat = 0;																		/* 2 */
	if ( ifbp->IFB_CardStat & CARD_STAT_PRESENT && IN_PORT_WORD( ifbp->IFB_IOBase + HREG_SW_0) == HCF_MAGIC ) {	/* 4 */
		accu = 0;																								/* 6 */
        if ( ifbp->IFB_RxFID ) {								    											/*10 */
            OUT_PORT_WORD( ifbp->IFB_IOBase + HREG_EV_ACK, HREG_EV_RX );
            ifbp->IFB_RxFID = ifbp->IFB_RxLen = ifbp->IFB_RxStat = 0;
        }
        sample = IN_PORT_WORD( ifbp->IFB_IOBase + HREG_EV_STAT );												/*12*/
        accu |= sample;

        if ( sample & HREG_EV_INFO )		isr_info( ifbp );
        if ( sample & HREG_EV_ALLOC ) {
            tmp = IN_PORT_WORD(ifbp->IFB_IOBase + HREG_ALLOC_FID );
            if ( tmp == ifbp->IFB_PIF_FID ) ifbp->IFB_PIFRscInd = 1;
            else if ( tmp == ifbp->IFB_DUIF_FID ) ifbp->IFB_DUIFRscInd = 1;
                 else {
                    ifbp->IFB_NotifyRscInd = 1;
                 }
        }
        tmp = sample & (hcf_16)~(HREG_EV_RX | HREG_EV_CMD );													/*14 */
        if ( tmp ) OUT_PORT_WORD( ifbp->IFB_IOBase + HREG_EV_ACK, tmp );

        sample = IN_PORT_WORD( ifbp->IFB_IOBase + HREG_EV_STAT );												/*16 */
        if ( sample & HREG_EV_RX ) {
            ifbp->IFB_RxFID = IN_PORT_WORD( ifbp->IFB_IOBase + HREG_RX_FID);
            (void)hcfio_string(ifbp, BAP_1, ifbp->IFB_RxFID, HFS_STAT_ABS, (wci_bufp)&ifbp->IFB_RxStat, 1, 2, IO_IN );
            (void)hcfio_string(ifbp, BAP_1, ifbp->IFB_RxFID, HFS_DAT_LEN_ABS, (wci_bufp)&ifbp->IFB_RxLen, 1,2,IO_IN );
            ifbp->IFB_RxLen += HFS_DAT;
        }
    }
	return accu;
}/* hcf_service_nic */





/**************************************************************************************************************
************************** H C F   S U P P O R T   R O U T I N E S ********************************************
**************************************************************************************************************/



/******************************************************************************************************************


.MODULE			alloc
.LIBRARY 		HCF_SUP
.TYPE 			function
.SYSTEM			msdos
.SYSTEM			unix
.SYSTEM			NW4
.APPLICATION	Support for HCFR routines
.DESCRIPTION	allocates a (TX or Notify) FID in NIC RAM and clears it

.ARGUMENTS

.RETURNS
  0:	failure
  <>0:	PIF value

.NARRATIVE


.DIAGRAM
 1:	execute the allocate command by calling cmd_wait
 2: wait till either the alloc event or a time-out occures
 3: if the alloc event occures,
 	- read the FID to return it to the caller of alloc
 	- acknowledge the alloc event
 	- clear the storage allocated in NIC RAM (see notice below)
 4:	since alloc is only called after an Hermes initialize command but before the Hermes enable, a failing
	allocation is considered a H/W failure, hence the Miscellaneous Error tally is incremented
	
.NOTICE
 o  Clearing the FID is not only an aesthetical matter, it is also the cheapest (code-size) way to enforce
 	  -	correlation between IFB_TxCntl (which is cleared by hcf_disable) and the field HFS_TX_CNTL_ABS of a
 		IFB_PIF_FID
 	  -	zero value of the field HFS_TX_CNTL_ABS of a IFB_DUIF_FID (hcf_send_diag_msg only supports port 0)
 	
  Note that Card Interrupts are disabled as a side effect of hcf_disable when alloc is called.  This is a
  necessary condition, otherwise the ISR can get control, causing hcf_service_nic to run.  This would
  constitute an error because hcf_service_nic needs a defined IFB_PIF_FID and IFB_DUIF_FID to manipulate
  IFB_PIFRscInd and IFB_DUIFRscInd

  The put_info functions must be called before the alloc calls because of cnfMaxDataLength ;?Really, what is the catch
 	
 	
.DIAGRAM
.ENDOC				END DOCUMENTATION
*/
/*-----------------------------------------------------------------------------------------------------------*/
hcf_16 alloc( IFBP ifbp, int len ) {

hcf_32 prot_cnt = ifbp->IFB_TickIni;
hcf_16 pif		= 0;
hcf_16 zero		= 0;

	if ( cmd_wait( ifbp, HCMD_ALLOC, len ) == HCF_SUCCESS ) {											/* 1 */
		while ( prot_cnt ) {
			prot_cnt--;
			if ( IN_PORT_WORD(ifbp->IFB_IOBase + HREG_EV_STAT ) & HREG_EV_ALLOC ) {						/* 2 */
				pif = IN_PORT_WORD(ifbp->IFB_IOBase + HREG_ALLOC_FID );									/* 3 */
				OUT_PORT_WORD(ifbp->IFB_IOBase + HREG_EV_ACK, HREG_EV_ALLOC );
				(void)hcfio_string( ifbp, BAP_0, pif, 0, (wci_bufp)&zero, 0, 2, IO_OUT );	//justify void
				len = DIV_BY_2( len );
				while ( --len ) OUT_PORT_WORD( ifbp->IFB_IOBase + BAP_0, 0 );
				break;
			}
		}
	}
	return pif;
}/* alloc */









/******************************************************************************************************************

.MODULE			calibrate
.LIBRARY 		HCF_SUP
.TYPE 			function
.SYSTEM			msdos
.SYSTEM			unix
.SYSTEM			NW4
.APPLICATION	Support for HCFR routines
.DESCRIPTION	

.ARGUMENTS
  int calibrate( IFBP ifbp )
	
.RETURNS
  HCF_SUCCESS
  HCF_ERR_TIME_OUT
  HCF_..... (via hcf_put_info)

.NARRATIVE
  o
  o


.DIAGRAM
 1:	
 2:
 	
.NOTICE
 o
 	
.DIAGRAM
.ENDOC				END DOCUMENTATION
*/
/*-----------------------------------------------------------------------------------------------------------*/
int calibrate( IFBP ifbp ) {

LTV_STRCT	x;					// initialization with "= { 2, CFG_TICK_TIME};" causes memset 
								// to be used under some compilers
int			cnt = 10;
int			rc = HCF_SUCCESS;
hcf_32		prot_cnt;

//	if ( ifbp->IFB_TickIni == 0 ) {										                        	/* 22*/
	x.len = 2;
	x.typ = CFG_TICK_TIME;
	x.val[0] = CNV_LITTLE_TO_INT( 8 );	//no compile time conversion available
	rc = hcf_put_info( ifbp, &x );
	ifbp->IFB_TickIni = 0;												                        	/* 22*/
	while ( rc == HCF_SUCCESS && --cnt ) {
		prot_cnt = 0;
		OUT_PORT_WORD( ifbp->IFB_IOBase + HREG_EV_ACK, HREG_EV_TICK );
		while ( (IN_PORT_WORD( ifbp->IFB_IOBase + HREG_EV_STAT ) & HREG_EV_TICK) == 0 &&
				++prot_cnt <= INI_TICK_INI ) /*NOP*/;
		ifbp->IFB_TickIni = max( ifbp->IFB_TickIni, prot_cnt);
	}
	if ( ifbp->IFB_TickIni == INI_TICK_INI ) rc = HCF_ERR_TIME_OUT;
	ifbp->IFB_TickIni *= 128;						//time out value of 8*128 = 1024 k microseconds
//	}
	x.val[0] = CNV_LITTLE_TO_INT( ONE_SECOND );
	rc = hcf_put_info( ifbp, &x );
	return rc;
} /* calibrate */






/**************************************************************************************************************


.MODULE			cmd_wait
.LIBRARY 		HCF_SUP
.TYPE 			function
.SYSTEM			msdos
.SYSTEM			unix
.SYSTEM			NW4
.APPLICATION	Support for HCFR routines
.DESCRIPTION

.ARGUMENTS

.RETURNS
  hcf_16
	HCF_SUCCESS
	HCF_ERR_TIME_OUT
	HCF_FAILURE
	HCF_ERR_BUSY
	
.NARRATIVE
.DIAGRAM

 1:	the test on rc checks whether a BAP initialization or a call to cmd_wait did ever fail. If so, the Hermes
	is assumed inoperable/defect, and all subsequent bap_ini/cmd_wait calls are nullified till hcf_disable
	clears the IFB_TimStat field.
 	
 2:	Based on the Hermes design, the read of the busy bit is superfluous because we wait for the Cmd bit in
	the Event Status register.

 3:	When the Hermes reports on another command than the Host just issued, the two are apparently out of
 	sync and all bets are off about the consequences. Therefore this situation is treated the same as an
 	Hermes failure as indicated by time-out (blocking all further bap_ini/cmd_wait calls till hcf_disable.
 	
 5:	If HREG_STAT reflects an error it is either an HCF bug or a H/W problem. Since
	no distinction can be made at forehand, the "vague" HCF_FAILURE code is used
	
.NOTICE
	Due to the general HCF strategy to wait for command completion, a 2nd command can never be excuted
	overlapping a previous command. As a consequence the Hermes requirement that no Inquiry command may be
	executed if there is still an unacknowledged Inquiry command outstanding, is automatically met.
	However, there are two pseudo-asynchronous commands (Diagnose and Download) which do not adhere to this
	general HCF strategy. In that case we rely on the MSF to do not overlap these commands, but no protection
	is offered by the HCF
.ENDOC				END DOCUMENTATION
*/
/* -------------------------------------------------------------------------------------------------------------------*/
int cmd_wait( IFBP ifbp, int cmd_code, int par_0 ) {

int		rc = ifbp->IFB_TimStat;
hcf_32	prot_cnt = ifbp->IFB_TickIni;


	if ( rc == HCF_SUCCESS ) {																			/* 1 */
		OUT_PORT_WORD( ifbp->IFB_IOBase + HREG_PARAM_0, par_0 );
		OUT_PORT_WORD( ifbp->IFB_IOBase + HREG_CMD, cmd_code );
		while (prot_cnt && (IN_PORT_WORD(ifbp->IFB_IOBase + HREG_EV_STAT) & HREG_EV_CMD) == 0 ) prot_cnt--;/*2 */
		if ( prot_cnt == 0 ) {
			rc = ifbp->IFB_TimStat = HCF_ERR_TIME_OUT;
		} else {
			rc = IN_PORT_WORD( ifbp->IFB_IOBase + HREG_STAT );
			OUT_PORT_WORD( ifbp->IFB_IOBase + HREG_EV_ACK, HREG_EV_CMD );
			if ( (rc ^ cmd_code) & HREG_STAT_CMD_CODE ) {												/* 3 */
				rc = ifbp->IFB_TimStat = HCF_FAILURE;
			} else {
				rc &= HREG_STAT_CMD_RESULT;									//Hermes defined Result Code
			}
			if ( rc ) rc = HCF_FAILURE;																	/* 5 */
		}
	}
	return rc;
}/* cmd_wait */



/***********************************************************************************************************************


 Name:	enable_int

 Summary: Enables a specific Hermes interrupt

 Parameters:
  ifbp	address of the Interface Block
  event	Hermes event to be enabled as interrupt source

 Remarks: To get the contents of the IntEn register changed is a two step process:

 	o change the "shadow" in IFB_IntEnMask

 	o call hcf_action to actually copy the shadow to the IntEn register.

 	To prevent a change in the "Card Interrupt En/Disabled state, a balancing
 	pair of HCF_ACT_INT_OFF and HCF_ACT_INT_ON must be used. To prevent
 	a temporary enabling as undesirable side effect, the first call must be
 	HCF_ACT_INT_OFF.
 	Note that at the very first interrupt, hcf_service_nic causes the removal of
 	the Tick and Cmd bit in the IntEn register.
 	
 	
.DIAGRAM
***********************************************************************************************************************/
//#pragma  Reminder2( "enable_int: shouldn't this be used in more places" )
void	enable_int(IFBP ifbp, int event ) {

	ifbp->IFB_IntEnMask |= event;
	(void)hcf_action( ifbp, HCF_ACT_INT_OFF );
	(void)hcf_action( ifbp, HCF_ACT_INT_ON );
	return;

}/* enable_int */





/****************************************************************************************************************************


.MODULE			ini_hermes
.LIBRARY 		HCF_SUP
.TYPE 			function
.SYSTEM			msdos
.SYSTEM			unix
.SYSTEM			NW4
.APPLICATION	Support for HCF routines
.DESCRIPTION

.ARGUMENTS

.RETURNS
  void
            
            
	As side effect of the Hermes Initialize command, the interrupts are disabled            
.NARRATIVE
 1:	
 2:	
.DIAGRAM

.ENDOC				END DOCUMENTATION
-------------------------------------------------------------------------------------------------------------*/
int ini_hermes( IFBP ifbp ) {

int		rc = HCF_ERR_NO_NIC;
//hcf_32	prot_cnt  = ifbp->IFB_TickIni = INI_TICK_INI;	//initialize at best guess before calibration
hcf_32	prot_cnt;

    if ( ifbp->IFB_CardStat & CARD_STAT_PRESENT ) {//present										/* 7 */
		if ( ifbp->IFB_TickIni == 0)  ifbp->IFB_TickIni = INI_TICK_INI;	//initialize at best guess before calibration
		prot_cnt  = ifbp->IFB_TickIni;
		while (prot_cnt && IN_PORT_WORD(ifbp->IFB_IOBase + HREG_CMD ) & HCMD_BUSY ) prot_cnt--;		/* 16*/
			
		rc = HCF_ERR_TIME_OUT;
		if ( prot_cnt != 0 ) {
			rc = cmd_wait( ifbp, HCMD_INI, 0 );														/* 18*/
			OUT_PORT_WORD( ifbp->IFB_IOBase + HREG_EV_ACK, 0xFFFF );
		}

	}
	return rc;
}/* ini_hermes */


/****************************************************************************************************************************


.MODULE			isr_info
.LIBRARY 		HCF_SUP
.TYPE 			function
.SYSTEM			msdos
.SYSTEM			unix
.SYSTEM			NW4
.APPLICATION	Support for HCF routines
.DESCRIPTION

.ARGUMENTS

.RETURNS
  void

.NARRATIVE
 1:	info[0] becomes the length of the T-field + the length of the Value-field in words. Note that it is
	dangerous to determine the length of the Value field by decrementing info[0], because if -e.g. as a
	result of a bug in the Hermes as has happened in real life- info[0] becomes 0, a decrement results in
	a very large number. Therefore all code is crafted around an unchanged info[0], with the intention to
	make the HCF more robust against I/F violations.
 2:	This is an example of the strategy described in #1 above. Info[0] is expected to be HCF_NIC_TAL_CNT + 1.
	By using a pre-decrement, this value results in HCF_NIC_TAL_CNT movements of a single tally value into
	the IFB_NIC_Tallies area of the IFB.
 3:	Although put_info_mb is robust against a len-parameter with value zero, it accepts any bogus value
	for the type-parameter.
.DIAGRAM

.ENDOC				END DOCUMENTATION
-------------------------------------------------------------------------------------------------------------*/
void isr_info( IFBP ifbp ) {

hcf_16	info[2], tmp;
hcf_32	*p;

	tmp = IN_PORT_WORD( ifbp->IFB_IOBase + HREG_INFO_FID );
	(void)hcfio_string(ifbp, BAP_1, tmp, 0, (wci_bufp)info, 2, sizeof(info), IO_IN );						/* 1 */
	
	if ( info[1] == CFG_TALLIES ) {
		if ( info[0] > HCF_NIC_TAL_CNT ) info[0] = HCF_NIC_TAL_CNT + 1;										/* 2 */
		p = (hcf_32*)&ifbp->IFB_NIC_Tallies;//.TxUnicastFrames;
		while ( --info[0] ) *p++ += IN_PORT_WORD( ifbp->IFB_IOBase + BAP_1 );
	}
	return;
}/* isr_info */






#if defined _M_I86TM
#endif //_M_I86TM

/***********************************************************************************************************************


 Name:	put_info

 Summary: stores Hermes configuration information in the ConfigTable of the IFB

 Parameters:
  ifbp	address of the Interface Block
  ltvp	address in NIC RAM where LVT-records are located


.NARRATIVE

**************************************************************************************************************/
int put_info( IFBP ifbp, LTVP ltvp	) {

int					cnt = 3;
//hcf_16				i = ltvp->len - 1;
int					rc = HCF_SUCCESS;

	
	if ( ifbp->IFB_CardStat & CARD_STAT_PRESENT ) {
	

		do {
			rc = hcfio_string( ifbp, BAP_1,
							   ltvp->typ, 0, (wci_bufp)ltvp, 2, MUL_BY_2(ltvp->len + 1), IO_OUT_CHECK );
		} while ( cnt-- && rc != HCF_SUCCESS );
		if ( rc == HCF_SUCCESS ) rc = cmd_wait( ifbp, HCMD_ACCESS + HCMD_ACCESS_WRITE, ltvp->typ );
	}	
	
	return rc;
}/* put_info */







