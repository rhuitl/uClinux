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
* FILE	  : hcfio.cpp
*
* DATE    : 2001/03/01 01:03:15   1.3
*
* AUTHOR  : Nico Valster
*
* DESC    : WCI-II HCF I/O Support Routines
*           These routines are isolated in their own *.CPP file to facilitate porting
*
*           Customizable via HCFCFG.H which is included by HCF.H
*
***************************************************************************************************************
* COPYRIGHT (c) 1994, 1995 by AT&T. 	   						All Rights Reserved.
* COPYRIGHT (c) 1996, 1997, 1998 by Lucent Technologies.     	All Rights Reserved.
**************************************************************************************************************/

/****************************************************************************
wvlan_hcfio.c,v
Revision 1.3  2001/03/01 01:03:15  root
*** empty log message ***

Revision 1.2  2000/01/06 23:30:53  root
*** empty log message ***

 * 
 *    Rev 1.0   02 Feb 1999 14:32:30   NVALST
 * Initial revision.
Revision 1.1  1999/01/30 19:34:40  nico
Initial revision

Revision 1.1  1999/01/30 19:24:39  nico
Initial revision

Revision 1.1  1999/01/30 19:07:33  nico
Initial revision

 * 
 *    Rev 1.110   29 Jan 1999 15:52:40   NVALST
 * intermediate, maybe working but seems to need two times to load in 
 * light-version
 * 
 *    Rev 2.12   29 Jan 1999 10:48:46   NVALST
 * 
 *    Rev 1.108   28 Jan 1999 14:43:18   NVALST
 * intermediate, once more correction of loop in hcf_service_nic + download
 * passed to Marc
 * 
 *    Rev 2.11   27 Jan 1999 16:57:42   NVALST
 * 
 *    Rev 1.107   27 Jan 1999 13:53:22   NVALST
 * intermediate, once more correction of loop in hcf_service_nic
 * 
 *    Rev 1.106   26 Jan 1999 16:42:44   NVALST
 * intermediate, corrected loop in hcf_service_nic (which was as result of a 
 * walkthrough, changed from a bug without consequences into one with consequences
 * 
 *    Rev 1.105   25 Jan 1999 14:24:46   NVALST
 * intermediate, hopefully suitable for release
 * 
 *    Rev 1.104   22 Jan 1999 16:59:30   NVALST
 * intermediate, minor corrections + some HCF-L stuff
 * 
 *    Rev 1.103   15 Jan 1999 15:14:40   NVALST
 * intermediate, deposited as HCF2.10
 * 
****************************************************************************/


/****************************************************************************
*
* CHANGE HISTORY
*
  961121 - NV
    Original Entry

**************************************************************************************************************/

/* ToDo
 * the CNV_LITTLE_TO_INT does have the desired effect on all platforms, but it's naming is
 * misleading, so revisit all these CNV macros to assure the right name is used at the right
 * place. Hint: introduce CNV_HOST_TO_NETWORK names if appropriate
 */


#include "wvlan_hcf.h"
#include "wvlan_hcfdef.h"

#ifdef HCF_ASSERT
static char BASED HCF__FILE__[] = { "  " __FILE__};	/* 6 spaces to supply room to build an LTV record for 
													 * runtime HCF_ASSERTs.  This record is constructed as:
													 * - L:		 self explanatory
													 * - T:		 CFG_MB_ASSERT
													 * - V[0]:	 line_number
													 * - V[1..]: (unchanged) file name						*/
#endif

/*  * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *	
 *	Refer to HCFCFG.H for more information on the routines ips and ops (short for InPutString 
 *	and OutPutString)
 *	
 *  * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
 
#if defined HCF_STRICT
void ips( hcf_io prt, wci_bufp dst, int n) {

	while ( n-- ) { 
		*(hcf_16 FAR*)dst = IN_PORT_WORD( prt );
		dst += 2;
	}
} // ips

void ops( hcf_io prt, wci_bufp src, int n) {

	while ( n-- ) {
		OUT_PORT_WORD( prt, *(hcf_16 FAR*)src );
		src  += 2;
	}
} // ops
#endif // HCF_STRICT

/***************************************** DOCZ Header ********************************************************


.MODULE         hcfio_string
.LIBRARY        HCF_SUP
.TYPE           function
.SYSTEM         msdos
.SYSTEM         unix
.SYSTEM         NW4
.APPLICATION    I/O Support for HCF routines
.DESCRIPTION    read/write string with specified length from/to WaveLAN NIC RAM to/from PC RAM


int hcfio_string( IFBP ifbp, int bap, int fid, 
				  int offset, wci_bufp pc_addr, int word_len, int tot_len, int type ) {
.ARGUMENTS
  IFBP			ifbp			I/F Block
  int			bap				BAP0/1
  int			fid				FID/RID
  int			offset			offset in FID/RID
  wci_bufp		pc_addr			begin address in PC RAM to write to or read from
  int			word_len		number of leading words of which the Endianess must be converted
  int			tot_len			number of bytes to write or read
  int			type            action code
								  -	IO_IN			read from NIC RAM
								  -	IO_OUT			write to NIC RAM
								  -	IO_OUT_CHECK	Data Corruption Detect

.RETURNS
  int
	HCF_SUCCESS     	O.K
	HCF_ERR_TIME_OUT    BAP can not be initialized
	HCF_ERR_NO_NIC		card is removed
	HCF_FAILURE			Data Corruption Detection catched

.NARRATIVE

  hcfio_string has the following tasks:
  -	copy data from NIC RAM to Host RAM or vice versa
  - optionally convert the data or part of the data from/to Little Endian format (as used by the NIC) 
  	to/from the Native Endian format (as used by the Host)
  -	check for Data Corruption in the data written to the NIC
	
  Data is a string with specified length copied from/to a specified offset in a specified Receive Frame 
  Structure (FID), Transmit Frame Structure (FID) or Record (RID) to/from a Host RAM buffer with a specified
  begin address.
  A length of 0 can be specified, resulting in no data transfer. This feature accomodates MSFs in certain
  Host environments (i.e. ODI) and it is used in the Data Corruption detection.
  Which Buffer Acces Path (BAP0 or BAP1) is used, is defined by a parameter.  
  A non-zero return status indicates:
  -	the selected BAP could not properly be initialized
  -	the card is removed before completion of the data transfer
  - the Data Corruption Detection triggered
  - the NIC is considered inoperational due to a time-out of some Hermes activity in the past
  In all other cases, a zero is returned.
  If a card removal is returned, the MSF has the option to drop the message or recover in any other way it 
  sees fit.
  BAP Initialization failure indicates an H/W error which is very likely to signal complete H/W failure. Once
  a BAP Initialization failure has occurred all subsequent interactions with the Hermes will return a time out
  status till the Hermes is re-initialized by means of an hcf_disable (at all ports in case of a multi-port
  environment)

.DIAGRAM

 1:	the test on rc checks whether a BAP initialization or a call to cmd_wait did ever fail. If so, the Hermes 
	is assumed inoperable/defect, and all subsequent bap_ini/cmd_wait calls are nullified till hcf_disable 
	clears the IFB_TimStat field.
 2:	The PCMCIA card can be removed in the middle of the transfer. By depositing a "magic number" in the 
	HREG_SW_0 register of the Hermes at initialization time and by verifying this location after 
    reading the string, it can be determined whether the card is still present and the return status is 
    set accordingly.
 3:	The test on offset and fid in the IFB_BAP_<n> structure corresponding with the BAP entry parameter, 
	assures that the BAP is only initialized if the current set of parameters specifies a location wich is 
	not consecutive with the last read/write access. If initialization is needed, then:
	  -	the select register is set
	  -	the offset register is set
	  -	the IFB_BAP_<n> structure is initialized
	  - the offset register is monitored till a successful condition (no busy bit and no error bit) is 
	  	detected or till the protection counter (calibrated at approx 1 second) expires
	If the counter expires, this is reflected in IFB_TimStat, so all subsequent calls to hcfio_string
	fail immediately ( see step 1)
 4:	the offset register in the IFB_BAP_<n> structure is updated to be used as described in item 3 above 
 	on the next call
10:	The NIC I/F is optimized for word transfer but it can only handle word transfer at a word boundary. 
	Therefore an additional test must be done to handle the read preparation in case the begin address in 
	NIC RAM is odd.
    This situation is handled by first reading a single byte and secondly reading a string of WORDS with a
    BYTE length of the requested length minus 1.
	NOTE: MACRO IN_PORT_STRING possibly modifies p (depending on how the MSF-programmer chooses to construct
	this macro, so pc_addr can not be used as parameter
11:	At completion of the word based transfer, a test is made to determine whether 1 additional byte must be 
	read (odd length starting at even address or even length starting at odd boundary)
12: finally the optionally conversion of the first words from Little Endian to Native Endian format is done.
20: first the optionally conversion of the first words from Native Endian to Little Endian format is done.
	This implies that Endian conversion can ONLY take place at word boundaries.
	Note that the difference with the IO_IN part of the logic is based on optimization considerations (both
	speed and size) and the boundary condition to return the output buffer unchanged to the caller
	Note also that the check on zero-length for output can not be the simple "skip all" as used for input, 
	because the Data Corruption Detection needs some of the side effects of this code, specifically the 
	BAP initialization
21: As for the IO_IN part, the logic must first cope with odd begin addresses in NIC RAM and the bulk of the
	transfer is done via OUT_PORT_STRING. Due to a flaw in the Hermes, writing the high byte corrupts the 
	low byte. As a work around, the HCF reads the low byte deposited in NIC RAM by the previous 
	hcfio_string, merges that byte with the first byte of the current Host RAM buffer into a word and
	writes that word to NIC RAM via OUT_PORT_WORD. Since OUT_PORT_WORD converts from Native Endian to
	Little Endian, while at this point of the procedure the Host buffer must have the correct Endianess,
	the macro CNV_LITTLE_TO_INT counteracts this unwanted adjustment of OUT_PORT_WORD.
22: At completion of the word based transfer, a test is made to determine whether 1 additional byte must be 
	written
30: The case of Data Corruption Detection:
	First the NIC RAM pointer is aligned on a word boundary to cope with the problem of an odd number of
	bytes written before. This is done by skipping one additional byte before the Data Corruption 
	Detection Pattern is appended to the data already written to the NIC RAM.
	Then 8 bytes fixed pattern is written. The justification of this is given in the NOTICE section below
31: In order to read the pattern back, the BAP must be initialized to address the begin of the pattern.
	The select register does not change, so only the offset register needs to be written, followed by
	a wait for successful completion.
40: To recognize the case that the NIC is removed during execution of hcfio_string, the same check as in
	step 2 is done again.
99:	In the past, one of the asserts in bap_ini (which no longer exists now it is assimilated in hcfio_string) 
	catched if "offset" was invalid. By calling bap_ini with the original (offset + length), bap_ini would 
	catch when the MSF passes the RID/FID boundary during the read process. It turned out that this feature 
	did obscure the tracing during debugging so much that its total effect on the debugging process was 
	considered detrimental, however re-institution can be considered depending on the bug you are chasing


.NOTICE
The problem is that without known cause, the Hermes internal NIC RAM pointer misses its auto-increment causing 
two successive writes to NIC RAM to address the same location. As a consequence word <n> is overwritten and 
a word <n+j> is written at position <n+j-1>. Since the Hermes is unaware of this, nothing in the system is 
going to catch this, e.g. the frame is received on the other side with correct FCS. As a workaround, the HCF 
keeps track of where the NIC RAM pointer SHOULD be. After all hcf_put_data calls are done, in other words, 
when hcf_send is called, the HCF writes a number of words - the kludge pattern - after the MSF-data. Then it 
sets the NIC RAM pointer by means of a re-initialization of the BAP to where this kludge pattern SHOULD be and 
reads the first word. This first word must match the kludge pattern, otherwise, apparently, the auto-increment 
failed. We need to write more than 1 word otherwise if the previous use of that piece of NIC RAM would have 
left by chance the right "kludge" value just after the newly but incorrectly put data, the test would not 
trigger. By overwriting the next 3 words as well, we assume the likelihood of this to be sufficiently small. 
The frequency observed of this problem varies from 1 out of 1000 frames till to low to be noticeable. Just to 
be on the safe side we assume that the chance of an error is 10E-3. By writing 4 words we reduce the 
likelihood of an unnoticed problem to 10E-12, but of course this becomes tricky because we don't know whether 
the chances are independent. Note that the HCF notion of the NIC RAM pointer is a "logical" view in the 
RID/FID address space, while the Hermes has a completely different physical address value for this pointer, 
however that difference does not influence above reasoning.

.NOTE
  Depending on the selected optimization options, using "register int reg" causes some obscure 
  optimization with si. As a result the code is longer. Therefore, do not invest time to optimize this code 
  that way during a "maintenance cycle".
 
.NOTE
  The IN_/OUT_PORT_WORD_/STRING macros are MSF-programmer defined and may or may not have side effects 
  on their parameters, therefore they can not handle expressions like "len/2". As a solution all these macros
  must be called via "simple" variables, with no side effects like ++ and their contents is unpredictable
  at completion of the macro
  
.NOTE
  The implementation is choosen to have input, output and BAP setup all rolled into one monolithic
  function rather than a more ameniable hcfio_in_string, hcfio_out_string and bap_ini to minimize the 
  stack usage during Interrupt Service (especially relevant for DOS drivers)

.NOTE
  The local variable reg corresponds with a register of the appropriate BAP. This is possible by the 
  intentional choice of the addresses of the individual registers of the two BAPs and the macro used to 
  specify whether BAP_0 or BAP_1 should be used. The value of reg is changed in the flow of hcfio_string
  because, depending on the context, reg is most optimal addressing the offset register or the data register.

	

 .ENDOC                          END DOCUMENTATION

-------------------------------------------------------------------------------------------------------------*/


int hcfio_string( IFBP ifbp, int bap, int fid, 
				  int offset, wci_bufp pc_addr, int word_len, int tot_len, int type ) {

hcf_io		reg = ifbp->IFB_IOBase + bap - HREG_DATA_0 + HREG_OFFSET_0;				//reg = offset register
hcf_32		prot_cnt = ifbp->IFB_TickIni;
hcf_16  	*p1 = bap == BAP_0 ? ifbp->IFB_BAP_0 : ifbp->IFB_BAP_1;
wci_bufp	cp;
wci_recordp	wp = (wci_recordp)pc_addr;
int			rc;
int			tlen;

#if HCF_ALIGN != 0
#endif // HCF_ALIGN
			/* assumption, writing words takes place only initial, never at odd NIC RAM addresses nor odd PC 
			 * addresses	*/

	if ( ( rc = ifbp->IFB_TimStat ) == HCF_SUCCESS ) {													/* 1 */
	    if ( IN_PORT_WORD( ifbp->IFB_IOBase + HREG_SW_0 ) != HCF_MAGIC ) rc =  HCF_ERR_NO_NIC;			/* 2 */
	}	
	if ( rc == HCF_SUCCESS ) {
	
		/* make sure all preceeding BAP manipulation is settled */
		while ( prot_cnt && IN_PORT_WORD( reg ) & (HCMD_BUSY|HREG_OFFSET_ERR) ) prot_cnt--;
	
		if ( offset != (int)*p1 || fid != (int)*(p1+1) ) {												/* 3 */
			OUT_PORT_WORD( reg - HREG_OFFSET_0 + HREG_SELECT_0, fid );
			OUT_PORT_WORD( reg, offset & 0xFFFE );
			*p1 = (hcf_16)offset;
			*(p1+1) = (hcf_16)fid;
			/* use type == IO_IN and len == 0 as a way to set the BAP for the futute, e.g. at the end of hcf_send */
//			while ( prot_cnt-- && IN_PORT_WORD( reg ) & (HCMD_BUSY|HREG_OFFSET_ERR) ) /*NOP*/;
			while ( tot_len && prot_cnt && IN_PORT_WORD( reg ) & (HCMD_BUSY|HREG_OFFSET_ERR) ) prot_cnt--;
			if ( prot_cnt == 0 ) {
				/* ;? It could be discussed whether the HREG_OFFSET_ERR bit should result in blocking NIC access 
				 *	till next initialize */
				rc = ifbp->IFB_TimStat = HCF_ERR_TIME_OUT;
			}
		}
		*p1 += (hcf_16)tot_len;																			/* 4 */
	}
	reg += HREG_DATA_0 - HREG_OFFSET_0;												     // reg = data register
	if ( rc == HCF_SUCCESS && type == IO_IN ) { 														//input
		if ( tot_len ) {
			if ( offset & 0x01 ) { /*odd	*/															/* 10*/
				*pc_addr++ = IN_PORT_BYTE( reg+1 );
				tot_len--;
			}
			cp = pc_addr;
			tlen = DIV_BY_2( tot_len );
			IN_PORT_STRING( reg, cp, tlen );
			if ( tot_len & 1 ) *(pc_addr + tot_len - 1) = IN_PORT_BYTE( reg );							/* 11*/
			while ( word_len-- ) {
				CNV_LITTLE_TO_INT_NP( wp );																/* 12*/
				wp++;
			}
		}
	}
	if ( rc == HCF_SUCCESS && type != IO_IN ) {											  //output and/or check
		tlen = word_len;                                                                                /* 20*/
		while ( tlen-- ) {                                                                              /* 20*/
			OUT_PORT_WORD( reg, *(wci_recordp)pc_addr );
			pc_addr += 2;
		}
//		tlen = offset + tot_len;
		if ( tot_len && offset & 0x01 ) {																/* 21*/
			OUT_PORT_WORD( reg, CNV_LITTLE_TO_INT( (*pc_addr <<8) + IN_PORT_BYTE( reg ) ) );
			pc_addr++;
			tot_len--;
		}
		word_len = DIV_BY_2( tot_len ) - word_len;	  //misuse no longer needed parameter as temporary variable
		cp = pc_addr;
		OUT_PORT_STRING( reg, cp, word_len );
		if ( tot_len & 1 ) OUT_PORT_BYTE( reg, *(pc_addr + tot_len - 1) );								/* 22*/


		if ( type == IO_OUT_CHECK /*&& *p1 != ifbp->IFB_FSBase */) {	//;?<HCF _L> should BE HARD CODED	/* 30*/
			if ( *p1 & 0X01 ) (void)IN_PORT_WORD( reg );	//align on word boundary
			OUT_PORT_WORD( reg, 0xCAFE );
			OUT_PORT_WORD( reg, 0xABBA );
			OUT_PORT_WORD( reg, 0xDEAD );
			OUT_PORT_WORD( reg, 0xD00F );
//!!		OUT_PORT_WORD( bap - HREG_OFFSET_0 + HREG_SELECT_0, fid );									/* 31*/
			OUT_PORT_WORD( reg - HREG_DATA_0 + HREG_OFFSET_0, (*p1 + 1)&0xFFFE );
			prot_cnt = ifbp->IFB_TickIni;
			while ( prot_cnt && IN_PORT_WORD(reg - HREG_DATA_0 + HREG_OFFSET_0) & (HCMD_BUSY|HREG_OFFSET_ERR) ) prot_cnt--;
			if ( prot_cnt == 0 ) {
				rc = ifbp->IFB_TimStat = HCF_ERR_TIME_OUT;
			}
			if ( IN_PORT_WORD( reg ) != 0xCAFE ) {
	 			rc = HCF_FAILURE;
				ifbp->IFB_PIFRscInd = 1;
//!			} else {
//!				rc = HCF_SUCCESS;
			}
		}
	}
	if ( rc == HCF_SUCCESS ) {																			/* 40*/
	    if ( IN_PORT_WORD( ifbp->IFB_IOBase + HREG_SW_0 ) != HCF_MAGIC ) rc =  HCF_ERR_NO_NIC;
	}	

//!	ASSERT( bap_ini( ifbp, bap, fid, (offset + len) & 0xFFFE) == HCF_SUCCESS )							/*99 */
    return rc;
}/* hcfio_string */

