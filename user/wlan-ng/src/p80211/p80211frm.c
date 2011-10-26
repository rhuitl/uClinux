/* src/p80211/p80211frm.c
*
* ieee 802.11 frame format support functions
*
* Copyright (C) 1999 AbsoluteValue Systems, Inc.  All Rights Reserved.
* --------------------------------------------------------------------
*
* linux-wlan
*
*   The contents of this file are subject to the Mozilla Public
*   License Version 1.1 (the "License"); you may not use this file
*   except in compliance with the License. You may obtain a copy of
*   the License at http://www.mozilla.org/MPL/
*
*   Software distributed under the License is distributed on an "AS
*   IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
*   implied. See the License for the specific language governing
*   rights and limitations under the License.
*
*   Alternatively, the contents of this file may be used under the
*   terms of the GNU Public License version 2 (the "GPL"), in which
*   case the provisions of the GPL are applicable instead of the
*   above.  If you wish to allow the use of your version of this file
*   only under the terms of the GPL and not to allow others to use
*   your version of this file under the MPL, indicate your decision
*   by deleting the provisions above and replace them with the notice
*   and other provisions required by the GPL.  If you do not delete
*   the provisions above, a recipient may use your version of this
*   file under either the MPL or the GPL.
*
* --------------------------------------------------------------------
*
* Inquiries regarding the linux-wlan Open Source project can be
* made directly to:
*
* AbsoluteValue Systems Inc.
* info@linux-wlan.com
* http://www.linux-wlan.com
*
* --------------------------------------------------------------------
*
* Portions of the development of this software were funded by 
* Intersil Corporation as part of PRISM(R) chipset product development.
*
* --------------------------------------------------------------------
*
* Support functions for encoding/decoding 802.11 frames, particularly
* management frames.  It's important that these functions be extern,
* they're used by other linux-wlan kernel components.
*
* --------------------------------------------------------------------
*/


/*================================================================*/
/* System Includes */

#define __NO_VERSION__

#include <linux/config.h>
#include <linux/version.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/byteorder.h>

#include <wlan/wlan_compat.h>

/*================================================================*/
/* Project Includes */

#include <wlan/p80211hdr.h>
#include <wlan/p80211mgmt.h>

/*================================================================*/
/* Local Constants */


/*================================================================*/
/* Local Types */


/*================================================================*/
/* Local statics */


/*================================================================*/
/* Local Function Declarations */


/*================================================================*/
/* Local Function Definitions */


/*--------------------------------------------------------------
* p80211addr_to_str
*
* Formats a 6 byte IEEE 802 address as a string of the form
* xx:xx:xx:xx:xx:xx  where the bytes are in hex.  No library
* functions are used to enhance portability.
*
* Arguments:
*	buf	char buffer, destination for string format
*		48 bit address.  Must be at least 18 bytes long.
*	addr	UINT8 buffer containing the ieee802 48 bit address
*		we're converting from.
*
* Returns:
*	nothing
*
* Side effects:
*	the contents of the space pointed to by buf is filled
*	with the textual representation of addr.
--------------------------------------------------------------*/
void p802addr_to_str( char *buf, UINT8 *addr)
{
        int strindex = 0;
        int addrindex;

        for( addrindex = 0; addrindex < 6; addrindex++) {
                buf[strindex] = ((addr[addrindex] & 0xf0) >> 4) > 9 ?
                                'a' + (((addr[addrindex] & 0xf0) >> 4) - 10) :
                                '0' +  ((addr[addrindex] & 0xf0) >> 4);
                buf[strindex +  1] = (addr[addrindex] & 0x0f) > 9 ?
                                     'a' + ((addr[addrindex] & 0x0f) - 10) :
                                     '0' +  (addr[addrindex] & 0x0f);
                buf[strindex + 2] = ':';

                strindex += 3;
        }
        buf[strindex-1] = '\0';
        return;
}

/*--------------------------------------------------------------
* wlan_mgmt_encode_beacon
*
* Receives an fr_mgmt struct with its len and buf set.  Fills
* in the rest of the members as far as possible.  On entry len
* is the length of the buffer, on return len is the actual length
* of the frame with all the currently encoded fields.  For 
* frames where the caller adds variable/optional IEs, the caller
* will have to update the len field.
* On entry Assumptions:
*	1) f->len and f->buf are already set
*	2) f->len is the length of the MAC header + data, the CRC
*	   is NOT included
*	3) all members except len, buf, and priv are zero
*
* Arguments:
*	f	frame structure 
*
* Returns:
*	nothing
*
* Side effects:
*	frame  structure members are pointing at their
*	respective portions of the frame buffer.
--------------------------------------------------------------*/
void wlan_mgmt_encode_beacon( wlan_fr_beacon_t  *f )
{
        f->type = WLAN_FSTYPE_BEACON;
        f->hdr = (p80211_hdr_t*)f->buf;

        WLAN_ASSERT( f->len >= WLAN_BEACON_FR_MAXLEN );

        /*-- Fixed Fields ----*/
        f->ts		= (UINT64*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                           + WLAN_BEACON_OFF_TS);
        f->bcn_int	= (UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                               + WLAN_BEACON_OFF_BCN_INT);
        f->cap_info	= (UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                                + WLAN_BEACON_OFF_CAPINFO);

        f->len = WLAN_HDR_A3_LEN + WLAN_BEACON_OFF_CAPINFO + sizeof(*(f->cap_info));

        return;
}

/*--------------------------------------------------------------
* wlan_mgmt_decode_beacon
*
* Given a complete frame in f->buf, sets the pointers in f to 
* the areas that correspond to the parts of the frame.
*
* Assumptions:
*	1) f->len and f->buf are already set
*	2) f->len is the length of the MAC header + data, the CRC
*	   is NOT included
*	3) all members except len and buf are zero
* Arguments:
*	f	frame structure 
*
* Returns:
*	nothing
*
* Side effects:
*	frame  structure members are pointing at their
*	respective portions of the frame buffer.
--------------------------------------------------------------*/
void wlan_mgmt_decode_beacon( wlan_fr_beacon_t  *f )
{
        wlan_ie_t	*ie_ptr;

        f->type = WLAN_FSTYPE_BEACON;
        f->hdr = (p80211_hdr_t*)f->buf;

        WLAN_ASSERT(WLAN_FTYPE_MGMT ==
                    WLAN_GET_FC_FTYPE(ieee2host16(f->hdr->a3.fc)));
        WLAN_ASSERT(WLAN_FSTYPE_BEACON ==
                    WLAN_GET_FC_FSTYPE(ieee2host16(f->hdr->a3.fc)));

        /*-- Fixed Fields ----*/
        f->ts		= (UINT64*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                           + WLAN_BEACON_OFF_TS);
        f->bcn_int	= (UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                               + WLAN_BEACON_OFF_BCN_INT);
        f->cap_info	= (UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                                + WLAN_BEACON_OFF_CAPINFO);

        /*-- Information elements */
        ie_ptr = (wlan_ie_t*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                              + WLAN_BEACON_OFF_SSID);
        while( ((UINT8*)ie_ptr) < (f->buf + f->len) ) {
                switch (ie_ptr->eid) {
                case WLAN_EID_SSID:
                        f->ssid = (wlan_ie_ssid_t*)ie_ptr;
                        break;
                case WLAN_EID_SUPP_RATES:
                        f->supp_rates = (wlan_ie_supp_rates_t*)ie_ptr;
                        break;
                case WLAN_EID_FH_PARMS:
                        f->fh_parms = (wlan_ie_fh_parms_t*)ie_ptr;
                        break;
                case WLAN_EID_DS_PARMS:
                        f->ds_parms = (wlan_ie_ds_parms_t*)ie_ptr;
                        break;
                case WLAN_EID_CF_PARMS:
                        f->cf_parms = (wlan_ie_cf_parms_t*)ie_ptr;
                        break;
                case WLAN_EID_IBSS_PARMS:
                        f->ibss_parms = (wlan_ie_ibss_parms_t*)ie_ptr;
                        break;
                case WLAN_EID_TIM:
                        f->tim = (wlan_ie_tim_t*)ie_ptr;
                        break;
                default:
                        WLAN_LOG_WARNING(
                                "Unrecognized EID=%dd in beacon decode.\n",ie_ptr->eid);
                        WLAN_HEX_DUMP(3, "frm w/ bad eid:", f->buf, f->len );
                        break;
                }
                ie_ptr = (wlan_ie_t*)(((UINT8*)ie_ptr) + 2 + ie_ptr->len);
        }

        return;
}


/*--------------------------------------------------------------
* wlan_mgmt_encode_ibssatim
*
* Receives an fr_mgmt struct with its len and buf set.  Fills
* in the rest of the members as far as possible.  On entry len
* is the length of the buffer, on return len is the actual length
* of the frame with all the currently encoded fields.  For 
* frames where the caller adds variable/optional IEs, the caller
* will have to update the len field.
* On entry Assumptions:
*	1) f->len and f->buf are already set
*	2) f->len is the length of the MAC header + data, the CRC
*	   is NOT included
*	3) all members except len, buf, and priv are zero
*
* Arguments:
*	f	frame structure 
*
* Returns:
*	nothing
*
* Side effects:
*	frame  structure members are pointing at their
*	respective portions of the frame buffer.
--------------------------------------------------------------*/
void  wlan_mgmt_encode_ibssatim( wlan_fr_ibssatim_t  *f )
{
        f->type = WLAN_FSTYPE_ATIM;
        f->hdr = (p80211_hdr_t*)f->buf;

        WLAN_ASSERT( f->len >= WLAN_ATIM_FR_MAXLEN );

        /*-- Fixed Fields ----*/
        /*-- Information elements */

        f->len = WLAN_HDR_A3_LEN;

        return;
}


/*--------------------------------------------------------------
* wlan_mgmt_decode_ibssatim
*
* Given a complete frame in f->buf, sets the pointers in f to 
* the areas that correspond to the parts of the frame.
*
* Assumptions:
*	1) f->len and f->buf are already set
*	2) f->len is the length of the MAC header + data, the CRC
*	   is NOT included
*	3) all members except len and buf are zero
*
* Arguments:
*	f	frame structure 
*
* Returns:
*	nothing
*
* Side effects:
*	frame  structure members are pointing at their
*	respective portions of the frame buffer.
--------------------------------------------------------------*/
void  wlan_mgmt_decode_ibssatim( wlan_fr_ibssatim_t  *f )
{
        f->type = WLAN_FSTYPE_ATIM;
        f->hdr = (p80211_hdr_t*)f->buf;

        WLAN_ASSERT(WLAN_FTYPE_MGMT ==
                    WLAN_GET_FC_FTYPE(ieee2host16(f->hdr->a3.fc)));
        WLAN_ASSERT(WLAN_FSTYPE_ATIM ==
                    WLAN_GET_FC_FSTYPE(ieee2host16(f->hdr->a3.fc)));

        /*-- Fixed Fields ----*/
        /*-- Information elements */

        return;
}


/*--------------------------------------------------------------
* wlan_mgmt_encode_disassoc
*
* Receives an fr_mgmt struct with its len and buf set.  Fills
* in the rest of the members as far as possible.  On entry len
* is the length of the buffer, on return len is the actual length
* of the frame with all the currently encoded fields.  For 
* frames where the caller adds variable/optional IEs, the caller
* will have to update the len field.
* On entry Assumptions:
*	1) f->len and f->buf are already set
*	2) f->len is the length of the MAC header + data, the CRC
*	   is NOT included
*	3) all members except len, buf, and priv are zero
*
* Arguments:
*	f	frame structure 
*
* Returns:
*	nothing
*
* Side effects:
*	frame  structure members are pointing at their
*	respective portions of the frame buffer.
--------------------------------------------------------------*/
void wlan_mgmt_encode_disassoc( wlan_fr_disassoc_t  *f )
{
        f->type = WLAN_FSTYPE_DISASSOC;
        f->hdr = (p80211_hdr_t*)f->buf;

        WLAN_ASSERT( f->len >= WLAN_DISASSOC_FR_MAXLEN );

        /*-- Fixed Fields ----*/
        f->reason	= (UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                              + WLAN_DISASSOC_OFF_REASON);

        f->len = WLAN_HDR_A3_LEN + WLAN_DISASSOC_OFF_REASON + sizeof(*(f->reason));

        return;
}


/*--------------------------------------------------------------
* wlan_mgmt_decode_disassoc
*
* Given a complete frame in f->buf, sets the pointers in f to 
* the areas that correspond to the parts of the frame.
*
* Assumptions:
*	1) f->len and f->buf are already set
*	2) f->len is the length of the MAC header + data, the CRC
*	   is NOT included
*	3) all members except len and buf are zero
*
* Arguments:
*	f	frame structure 
*
* Returns:
*	nothing
*
* Side effects:
*	frame  structure members are pointing at their
*	respective portions of the frame buffer.
--------------------------------------------------------------*/
void wlan_mgmt_decode_disassoc( wlan_fr_disassoc_t  *f )
{
        f->type = WLAN_FSTYPE_DISASSOC;
        f->hdr = (p80211_hdr_t*)f->buf;

        WLAN_ASSERT(WLAN_FTYPE_MGMT ==
                    WLAN_GET_FC_FTYPE(ieee2host16(f->hdr->a3.fc)));
        WLAN_ASSERT(WLAN_FSTYPE_DISASSOC ==
                    WLAN_GET_FC_FSTYPE(ieee2host16(f->hdr->a3.fc)));

        /*-- Fixed Fields ----*/
        f->reason	= (UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                              + WLAN_DISASSOC_OFF_REASON);

        /*-- Information elements */

        return;
}


/*--------------------------------------------------------------
* wlan_mgmt_encode_assocreq
*
* Receives an fr_mgmt struct with its len and buf set.  Fills
* in the rest of the members as far as possible.  On entry len
* is the length of the buffer, on return len is the actual length
* of the frame with all the currently encoded fields.  For 
* frames where the caller adds variable/optional IEs, the caller
* will have to update the len field.
* On entry Assumptions:
*	1) f->len and f->buf are already set
*	2) f->len is the length of the MAC header + data, the CRC
*	   is NOT included
*	3) all members except len, buf, and priv are zero
*
* Arguments:
*	f	frame structure 
*
* Returns:
*	nothing
*
* Side effects:
*	frame  structure members are pointing at their
*	respective portions of the frame buffer.
--------------------------------------------------------------*/
void wlan_mgmt_encode_assocreq( wlan_fr_assocreq_t  *f )
{
        f->type = WLAN_FSTYPE_ASSOCREQ;
        f->hdr = (p80211_hdr_t*)f->buf;

        WLAN_ASSERT( f->len >= WLAN_ASSOCREQ_FR_MAXLEN );

        /*-- Fixed Fields ----*/
        f->cap_info		= (UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                                 + WLAN_ASSOCREQ_OFF_CAP_INFO);
        f->listen_int	= (UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                                  + WLAN_ASSOCREQ_OFF_LISTEN_INT);

        f->len = WLAN_HDR_A3_LEN +
                 WLAN_ASSOCREQ_OFF_LISTEN_INT +
                 sizeof(*(f->listen_int));

        return;
}


/*--------------------------------------------------------------
* wlan_mgmt_decode_assocreq
*
* Given a complete frame in f->buf, sets the pointers in f to 
* the areas that correspond to the parts of the frame.
*
* Assumptions:
*	1) f->len and f->buf are already set
*	2) f->len is the length of the MAC header + data, the CRC
*	   is NOT included
*	3) all members except len and buf are zero
*
* Arguments:
*	f	frame structure 
*
* Returns:
*	nothing
*
* Side effects:
*	frame  structure members are pointing at their
*	respective portions of the frame buffer.
--------------------------------------------------------------*/
void wlan_mgmt_decode_assocreq( wlan_fr_assocreq_t  *f )
{
        wlan_ie_t	*ie_ptr;

        f->type = WLAN_FSTYPE_ASSOCREQ;
        f->hdr = (p80211_hdr_t*)f->buf;

        WLAN_ASSERT(WLAN_FTYPE_MGMT ==
                    WLAN_GET_FC_FTYPE(ieee2host16(f->hdr->a3.fc)));
        WLAN_ASSERT(WLAN_FSTYPE_ASSOCREQ ==
                    WLAN_GET_FC_FSTYPE(ieee2host16(f->hdr->a3.fc)));

        /*-- Fixed Fields ----*/
        f->cap_info		= (UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                                 + WLAN_ASSOCREQ_OFF_CAP_INFO);
        f->listen_int	= (UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                                  + WLAN_ASSOCREQ_OFF_LISTEN_INT);

        /*-- Information elements */
        ie_ptr = (wlan_ie_t*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                              + WLAN_ASSOCREQ_OFF_SSID);
        while( ((UINT8*)ie_ptr) < (f->buf + f->len) ) {
                switch (ie_ptr->eid) {
                case WLAN_EID_SSID:
                        f->ssid = (wlan_ie_ssid_t*)ie_ptr;
                        break;
                case WLAN_EID_SUPP_RATES:
                        f->supp_rates = (wlan_ie_supp_rates_t*)ie_ptr;
                        break;
                default:
                        WLAN_LOG_WARNING(
                                "Unrecognized EID=%dd in assocreq decode.\n",
                                ie_ptr->eid);
                        WLAN_HEX_DUMP(3, "frm w/ bad eid:", f->buf, f->len );
                        break;
                }
                ie_ptr = (wlan_ie_t*)(((UINT8*)ie_ptr) + 2 + ie_ptr->len);
        }
        return;
}


/*--------------------------------------------------------------
* wlan_mgmt_encode_assocresp
*
* Receives an fr_mgmt struct with its len and buf set.  Fills
* in the rest of the members as far as possible.  On entry len
* is the length of the buffer, on return len is the actual length
* of the frame with all the currently encoded fields.  For 
* frames where the caller adds variable/optional IEs, the caller
* will have to update the len field.
* On entry Assumptions:
*	1) f->len and f->buf are already set
*	2) f->len is the length of the MAC header + data, the CRC
*	   is NOT included
*	3) all members except len, buf, and priv are zero
*
* Arguments:
*	f	frame structure 
*
* Returns:
*	nothing
*
* Side effects:
*	frame  structure members are pointing at their
*	respective portions of the frame buffer.
--------------------------------------------------------------*/
void wlan_mgmt_encode_assocresp( wlan_fr_assocresp_t  *f )
{
        f->type = WLAN_FSTYPE_ASSOCRESP;
        f->hdr = (p80211_hdr_t*)f->buf;

        WLAN_ASSERT( f->len >= WLAN_ASSOCRESP_FR_MAXLEN );

        /*-- Fixed Fields ----*/
        f->cap_info		= (UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                                 + WLAN_ASSOCRESP_OFF_CAP_INFO);
        f->status		= (UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                               + WLAN_ASSOCRESP_OFF_STATUS);
        f->aid			= (UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                             + WLAN_ASSOCRESP_OFF_AID);

        f->len = WLAN_HDR_A3_LEN + WLAN_ASSOCRESP_OFF_AID + sizeof(*(f->aid));

        return;
}


/*--------------------------------------------------------------
* wlan_mgmt_decode_assocresp
*
* Given a complete frame in f->buf, sets the pointers in f to 
* the areas that correspond to the parts of the frame.
*
* Assumptions:
*	1) f->len and f->buf are already set
*	2) f->len is the length of the MAC header + data, the CRC
*	   is NOT included
*	3) all members except len and buf are zero
*
* Arguments:
*	f	frame structure 
*
* Returns:
*	nothing
*
* Side effects:
*	frame  structure members are pointing at their
*	respective portions of the frame buffer.
--------------------------------------------------------------*/
void wlan_mgmt_decode_assocresp( wlan_fr_assocresp_t  *f )
{
        f->type = WLAN_FSTYPE_ASSOCRESP;
        f->hdr = (p80211_hdr_t*)f->buf;

        WLAN_ASSERT(WLAN_FTYPE_MGMT ==
                    WLAN_GET_FC_FTYPE(ieee2host16(f->hdr->a3.fc)));
        WLAN_ASSERT(WLAN_FSTYPE_ASSOCRESP ==
                    WLAN_GET_FC_FSTYPE(ieee2host16(f->hdr->a3.fc)));

        /*-- Fixed Fields ----*/
        f->cap_info		= (UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                                 + WLAN_ASSOCRESP_OFF_CAP_INFO);
        f->status		= (UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                               + WLAN_ASSOCRESP_OFF_STATUS);
        f->aid			= (UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                             + WLAN_ASSOCRESP_OFF_AID);

        /*-- Information elements */
        f->supp_rates	= (wlan_ie_supp_rates_t*)
                        (WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                         + WLAN_ASSOCRESP_OFF_SUPP_RATES);

        return;
}


/*--------------------------------------------------------------
* wlan_mgmt_encode_reassocreq
*
* Receives an fr_mgmt struct with its len and buf set.  Fills
* in the rest of the members as far as possible.  On entry len
* is the length of the buffer, on return len is the actual length
* of the frame with all the currently encoded fields.  For 
* frames where the caller adds variable/optional IEs, the caller
* will have to update the len field.
* On entry Assumptions:
*	1) f->len and f->buf are already set
*	2) f->len is the length of the MAC header + data, the CRC
*	   is NOT included
*	3) all members except len, buf, and priv are zero
*
* Arguments:
*	f	frame structure 
*
* Returns:
*	nothing
*
* Side effects:
*	frame  structure members are pointing at their
*	respective portions of the frame buffer.
--------------------------------------------------------------*/
void wlan_mgmt_encode_reassocreq( wlan_fr_reassocreq_t  *f )
{
        f->type = WLAN_FSTYPE_REASSOCREQ;
        f->hdr = (p80211_hdr_t*)f->buf;

        WLAN_ASSERT( f->len >= WLAN_REASSOCREQ_FR_MAXLEN );

        /*-- Fixed Fields ----*/
        f->cap_info		=(UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                                + WLAN_REASSOCREQ_OFF_CAP_INFO);
        f->listen_int	=(UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                                 + WLAN_REASSOCREQ_OFF_LISTEN_INT);
        f->curr_ap		=(UINT8*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                              + WLAN_REASSOCREQ_OFF_CURR_AP);

        f->len = WLAN_HDR_A3_LEN + WLAN_REASSOCREQ_OFF_CURR_AP + sizeof(*(f->curr_ap));

        return;
}


/*--------------------------------------------------------------
* wlan_mgmt_decode_reassocreq
*
* Given a complete frame in f->buf, sets the pointers in f to 
* the areas that correspond to the parts of the frame.
*
* Assumptions:
*	1) f->len and f->buf are already set
*	2) f->len is the length of the MAC header + data, the CRC
*	   is NOT included
*	3) all members except len and buf are zero
*
* Arguments:
*	f	frame structure 
*
* Returns:
*	nothing
*
* Side effects:
*	frame  structure members are pointing at their
*	respective portions of the frame buffer.
--------------------------------------------------------------*/
void wlan_mgmt_decode_reassocreq( wlan_fr_reassocreq_t  *f )
{
        wlan_ie_t	*ie_ptr;

        f->type = WLAN_FSTYPE_REASSOCREQ;
        f->hdr = (p80211_hdr_t*)f->buf;

        WLAN_ASSERT(WLAN_FTYPE_MGMT ==
                    WLAN_GET_FC_FTYPE(ieee2host16(f->hdr->a3.fc)));
        WLAN_ASSERT(WLAN_FSTYPE_REASSOCREQ ==
                    WLAN_GET_FC_FSTYPE(ieee2host16(f->hdr->a3.fc)));

        /*-- Fixed Fields ----*/
        f->cap_info		=(UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                                + WLAN_REASSOCREQ_OFF_CAP_INFO);
        f->listen_int	=(UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                                 + WLAN_REASSOCREQ_OFF_LISTEN_INT);
        f->curr_ap		=(UINT8*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                              + WLAN_REASSOCREQ_OFF_CURR_AP);

        /*-- Information elements */
        ie_ptr = (wlan_ie_t*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                              + WLAN_REASSOCREQ_OFF_SSID);
        while( ((UINT8*)ie_ptr) < (f->buf + f->len) ) {
                switch (ie_ptr->eid) {
                case WLAN_EID_SSID:
                        f->ssid = (wlan_ie_ssid_t*)ie_ptr;
                        break;
                case WLAN_EID_SUPP_RATES:
                        f->supp_rates = (wlan_ie_supp_rates_t*)ie_ptr;
                        break;
                default:
                        WLAN_LOG_WARNING(
                                "Unrecognized EID=%dd in reassocreq decode.\n",
                                ie_ptr->eid);
                        WLAN_HEX_DUMP(3, "frm w/ bad eid:", f->buf, f->len );
                        break;
                }
                ie_ptr = (wlan_ie_t*)(((UINT8*)ie_ptr) + 2 + ie_ptr->len);
        }
        return;
}


/*--------------------------------------------------------------
* wlan_mgmt_encode_reassocresp
*
* Receives an fr_mgmt struct with its len and buf set.  Fills
* in the rest of the members as far as possible.  On entry len
* is the length of the buffer, on return len is the actual length
* of the frame with all the currently encoded fields.  For 
* frames where the caller adds variable/optional IEs, the caller
* will have to update the len field.
* On entry Assumptions:
*	1) f->len and f->buf are already set
*	2) f->len is the length of the MAC header + data, the CRC
*	   is NOT included
*	3) all members except len, buf, and priv are zero
*
* Arguments:
*	f	frame structure 
*
* Returns:
*	nothing
*
* Side effects:
*	frame  structure members are pointing at their
*	respective portions of the frame buffer.
--------------------------------------------------------------*/
void wlan_mgmt_encode_reassocresp( wlan_fr_reassocresp_t  *f )
{
        f->type = WLAN_FSTYPE_REASSOCRESP;
        f->hdr = (p80211_hdr_t*)f->buf;

        WLAN_ASSERT( f->len >= WLAN_REASSOCRESP_FR_MAXLEN );

        /*-- Fixed Fields ----*/
        f->cap_info		= (UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                                 + WLAN_REASSOCRESP_OFF_CAP_INFO);
        f->status		= (UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                               + WLAN_REASSOCRESP_OFF_STATUS);
        f->aid			= (UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                             + WLAN_REASSOCRESP_OFF_AID);

        f->len = WLAN_HDR_A3_LEN + WLAN_REASSOCRESP_OFF_AID + sizeof(*(f->aid));

        return;
}


/*--------------------------------------------------------------
* wlan_mgmt_decode_reassocresp
*
* Given a complete frame in f->buf, sets the pointers in f to 
* the areas that correspond to the parts of the frame.
*
* Assumptions:
*	1) f->len and f->buf are already set
*	2) f->len is the length of the MAC header + data, the CRC
*	   is NOT included
*	3) all members except len and buf are zero
*
* Arguments:
*	f	frame structure 
*
* Returns:
*	nothing
*
* Side effects:
*	frame  structure members are pointing at their
*	respective portions of the frame buffer.
--------------------------------------------------------------*/
void wlan_mgmt_decode_reassocresp( wlan_fr_reassocresp_t  *f )
{
        f->type = WLAN_FSTYPE_REASSOCRESP;
        f->hdr = (p80211_hdr_t*)f->buf;

        WLAN_ASSERT(WLAN_FTYPE_MGMT ==
                    WLAN_GET_FC_FTYPE(ieee2host16(f->hdr->a3.fc)));
        WLAN_ASSERT(WLAN_FSTYPE_REASSOCRESP ==
                    WLAN_GET_FC_FSTYPE(ieee2host16(f->hdr->a3.fc)));

        /*-- Fixed Fields ----*/
        f->cap_info		= (UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                                 + WLAN_REASSOCRESP_OFF_CAP_INFO);
        f->status		= (UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                               + WLAN_REASSOCRESP_OFF_STATUS);
        f->aid			= (UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                             + WLAN_REASSOCRESP_OFF_AID);

        /*-- Information elements */
        f->supp_rates	= (wlan_ie_supp_rates_t*)
                        (WLAN_HDR_A3_DATAP(&(f->hdr->a3)) +
                         WLAN_REASSOCRESP_OFF_SUPP_RATES);

        return;
}


/*--------------------------------------------------------------
* wlan_mgmt_encode_probereq
*
* Receives an fr_mgmt struct with its len and buf set.  Fills
* in the rest of the members as far as possible.  On entry len
* is the length of the buffer, on return len is the actual length
* of the frame with all the currently encoded fields.  For 
* frames where the caller adds variable/optional IEs, the caller
* will have to update the len field.
* On entry Assumptions:
*	1) f->len and f->buf are already set
*	2) f->len is the length of the MAC header + data, the CRC
*	   is NOT included
*	3) all members except len, buf, and priv are zero
*
* Arguments:
*	f	frame structure 
*
* Returns:
*	nothing
*
* Side effects:
*	frame  structure members are pointing at their
*	respective portions of the frame buffer.
--------------------------------------------------------------*/
void wlan_mgmt_encode_probereq( wlan_fr_probereq_t  *f )
{
        f->type = WLAN_FSTYPE_PROBEREQ;
        f->hdr = (p80211_hdr_t*)f->buf;

        WLAN_ASSERT( f->len >= WLAN_PROBEREQ_FR_MAXLEN );

        f->len = WLAN_HDR_A3_LEN;

        return;
}


/*--------------------------------------------------------------
* wlan_mgmt_decode_probereq
*
* Given a complete frame in f->buf, sets the pointers in f to 
* the areas that correspond to the parts of the frame.
*
* Assumptions:
*	1) f->len and f->buf are already set
*	2) f->len is the length of the MAC header + data, the CRC
*	   is NOT included
*	3) all members except len and buf are zero
*
* Arguments:
*	f	frame structure 
*
* Returns:
*	nothing
*
* Side effects:
*	frame  structure members are pointing at their
*	respective portions of the frame buffer.
--------------------------------------------------------------*/
void wlan_mgmt_decode_probereq( wlan_fr_probereq_t  *f )
{
        wlan_ie_t	*ie_ptr;

        f->type = WLAN_FSTYPE_PROBEREQ;
        f->hdr = (p80211_hdr_t*)f->buf;

        WLAN_ASSERT(WLAN_FTYPE_MGMT ==
                    WLAN_GET_FC_FTYPE(ieee2host16(f->hdr->a3.fc)));
        WLAN_ASSERT(WLAN_FSTYPE_PROBEREQ ==
                    WLAN_GET_FC_FSTYPE(ieee2host16(f->hdr->a3.fc)));

        /*-- Fixed Fields ----*/

        /*-- Information elements */
        ie_ptr = (wlan_ie_t*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                              + WLAN_PROBEREQ_OFF_SSID);
        while( ((UINT8*)ie_ptr) < (f->buf + f->len) ) {
                switch (ie_ptr->eid) {
                case WLAN_EID_SSID:
                        f->ssid = (wlan_ie_ssid_t*)ie_ptr;
                        break;
                case WLAN_EID_SUPP_RATES:
                        f->supp_rates = (wlan_ie_supp_rates_t*)ie_ptr;
                        break;
                default:
                        WLAN_LOG_WARNING(
                                "Unrecognized EID=%dd in probereq decode.\n",
                                ie_ptr->eid);
                        WLAN_HEX_DUMP(3, "frm w/ bad eid:", f->buf, f->len );
                        break;
                }
                ie_ptr = (wlan_ie_t*)(((UINT8*)ie_ptr) + 2 + ie_ptr->len);
        }
        return;
}


/*--------------------------------------------------------------
* wlan_mgmt_encode_proberesp
*
* Receives an fr_mgmt struct with its len and buf set.  Fills
* in the rest of the members as far as possible.  On entry len
* is the length of the buffer, on return len is the actual length
* of the frame with all the currently encoded fields.  For 
* frames where the caller adds variable/optional IEs, the caller
* will have to update the len field.
* On entry Assumptions:
*	1) f->len and f->buf are already set
*	2) f->len is the length of the MAC header + data, the CRC
*	   is NOT included
*	3) all members except len, buf, and priv are zero
*
* Arguments:
*	f	frame structure 
*
* Returns:
*	nothing
*
* Side effects:
*	frame  structure members are pointing at their
*	respective portions of the frame buffer.
--------------------------------------------------------------*/
void wlan_mgmt_encode_proberesp( wlan_fr_proberesp_t  *f )
{
        f->type = WLAN_FSTYPE_PROBERESP;
        f->hdr = (p80211_hdr_t*)f->buf;

        WLAN_ASSERT( f->len >= WLAN_PROBERESP_FR_MAXLEN );

        /*-- Fixed Fields ----*/
        f->ts		=(UINT64*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                          + WLAN_PROBERESP_OFF_TS);
        f->bcn_int	=(UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                              + WLAN_PROBERESP_OFF_BCN_INT);
        f->cap_info	=(UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                               + WLAN_PROBERESP_OFF_CAP_INFO);

        f->len = WLAN_HDR_A3_LEN + WLAN_PROBERESP_OFF_CAP_INFO +
                 sizeof(*(f->cap_info));

        return;
}


/*--------------------------------------------------------------
* wlan_mgmt_decode_proberesp
*
* Given a complete frame in f->buf, sets the pointers in f to 
* the areas that correspond to the parts of the frame.
*
* Assumptions:
*	1) f->len and f->buf are already set
*	2) f->len is the length of the MAC header + data, the CRC
*	   is NOT included
*	3) all members except len and buf are zero
*
* Arguments:
*	f	frame structure 
*
* Returns:
*	nothing
*
* Side effects:
*	frame  structure members are pointing at their
*	respective portions of the frame buffer.
--------------------------------------------------------------*/
void wlan_mgmt_decode_proberesp( wlan_fr_proberesp_t  *f )
{
        wlan_ie_t	*ie_ptr;

        f->type = WLAN_FSTYPE_PROBERESP;
        f->hdr = (p80211_hdr_t*)f->buf;

        WLAN_ASSERT(WLAN_FTYPE_MGMT ==
                    WLAN_GET_FC_FTYPE(ieee2host16(f->hdr->a3.fc)));
        WLAN_ASSERT(WLAN_FSTYPE_PROBERESP ==
                    WLAN_GET_FC_FSTYPE(ieee2host16(f->hdr->a3.fc)));

        /*-- Fixed Fields ----*/
        f->ts		=(UINT64*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                          + WLAN_PROBERESP_OFF_TS);
        f->bcn_int	=(UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                              + WLAN_PROBERESP_OFF_BCN_INT);
        f->cap_info	=(UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                               + WLAN_PROBERESP_OFF_CAP_INFO);

        /*-- Information elements */
        ie_ptr = (wlan_ie_t*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                              + WLAN_PROBERESP_OFF_SSID);
        while( ((UINT8*)ie_ptr) < (f->buf + f->len) ) {
                switch (ie_ptr->eid) {
                case WLAN_EID_SSID:
                        f->ssid = (wlan_ie_ssid_t*)ie_ptr;
                        break;
                case WLAN_EID_SUPP_RATES:
                        f->supp_rates = (wlan_ie_supp_rates_t*)ie_ptr;
                        break;
                case WLAN_EID_FH_PARMS:
                        f->fh_parms = (wlan_ie_fh_parms_t*)ie_ptr;
                        break;
                case WLAN_EID_DS_PARMS:
                        f->ds_parms = (wlan_ie_ds_parms_t*)ie_ptr;
                        break;
                case WLAN_EID_CF_PARMS:
                        f->cf_parms = (wlan_ie_cf_parms_t*)ie_ptr;
                        break;
                case WLAN_EID_IBSS_PARMS:
                        f->ibss_parms = (wlan_ie_ibss_parms_t*)ie_ptr;
                        break;
                default:
                        WLAN_LOG_WARNING(
                                "Bad EID=%dd in proberesp, off=%d .\n",
                                ie_ptr->eid, f->buf - (UINT8*)ie_ptr);
                        WLAN_HEX_DUMP(3, "frm w/ bad eid:", f->buf, f->len );
                        break;
                }

                ie_ptr = (wlan_ie_t*)(((UINT8*)ie_ptr) + 2 +  ie_ptr->len);
        }
        return;
}


/*--------------------------------------------------------------
* wlan_mgmt_encode_authen
*
* Receives an fr_mgmt struct with its len and buf set.  Fills
* in the rest of the members as far as possible.  On entry len
* is the length of the buffer, on return len is the actual length
* of the frame with all the currently encoded fields.  For 
* frames where the caller adds variable/optional IEs, the caller
* will have to update the len field.
* On entry Assumptions:
*	1) f->len and f->buf are already set
*	2) f->len is the length of the MAC header + data, the CRC
*	   is NOT included
*	3) all members except len, buf, and priv are zero
*
* Arguments:
*	f	frame structure 
*
* Returns:
*	nothing
*
* Side effects:
*	frame  structure members are pointing at their
*	respective portions of the frame buffer.
--------------------------------------------------------------*/
void wlan_mgmt_encode_authen( wlan_fr_authen_t  *f )
{
        f->type = WLAN_FSTYPE_AUTHEN;
        f->hdr = (p80211_hdr_t*)f->buf;

        WLAN_ASSERT( f->len >= WLAN_AUTHEN_FR_MAXLEN );

        /*-- Fixed Fields ----*/
        f->auth_alg	=(UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                               + WLAN_AUTHEN_OFF_AUTH_ALG);
        f->auth_seq	=(UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                               + WLAN_AUTHEN_OFF_AUTH_SEQ);
        f->status	=(UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                             + WLAN_AUTHEN_OFF_STATUS);

        f->len = WLAN_HDR_A3_LEN + WLAN_AUTHEN_OFF_STATUS + sizeof(*(f->status));

        return;
}


/*--------------------------------------------------------------
* wlan_mgmt_decode_authen
*
* Given a complete frame in f->buf, sets the pointers in f to 
* the areas that correspond to the parts of the frame.
*
* Assumptions:
*	1) f->len and f->buf are already set
*	2) f->len is the length of the MAC header + data, the CRC
*	   is NOT included
*	3) all members except len and buf are zero
*
* Arguments:
*	f	frame structure 
*
* Returns:
*	nothing
*
* Side effects:
*	frame  structure members are pointing at their
*	respective portions of the frame buffer.
--------------------------------------------------------------*/
void wlan_mgmt_decode_authen( wlan_fr_authen_t  *f )
{
        wlan_ie_t	*ie_ptr;

        f->type = WLAN_FSTYPE_AUTHEN;
        f->hdr = (p80211_hdr_t*)f->buf;

        WLAN_ASSERT(WLAN_FTYPE_MGMT ==
                    WLAN_GET_FC_FTYPE(ieee2host16(f->hdr->a3.fc)));
        WLAN_ASSERT(WLAN_FSTYPE_AUTHEN ==
                    WLAN_GET_FC_FSTYPE(ieee2host16(f->hdr->a3.fc)));

        /*-- Fixed Fields ----*/
        f->auth_alg	=(UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                               + WLAN_AUTHEN_OFF_AUTH_ALG);
        f->auth_seq	=(UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                               + WLAN_AUTHEN_OFF_AUTH_SEQ);
        f->status	=(UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                             + WLAN_AUTHEN_OFF_STATUS);

        /*-- Information elements */
        ie_ptr = (wlan_ie_t*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                              + WLAN_AUTHEN_OFF_CHALLENGE);
        if ((((UINT8*)ie_ptr) < (f->buf + f->len)) &&
                        (ie_ptr->eid == WLAN_EID_CHALLENGE) ) {
                f->challenge = (wlan_ie_challenge_t*)ie_ptr;
        }
        return;
}


/*--------------------------------------------------------------
* wlan_mgmt_encode_deauthen
*
* Receives an fr_mgmt struct with its len and buf set.  Fills
* in the rest of the members as far as possible.  On entry len
* is the length of the buffer, on return len is the actual length
* of the frame with all the currently encoded fields.  For 
* frames where the caller adds variable/optional IEs, the caller
* will have to update the len field.
* On entry Assumptions:
*	1) f->len and f->buf are already set
*	2) f->len is the length of the MAC header + data, the CRC
*	   is NOT included
*	3) all members except len, buf, and priv are zero
*
* Arguments:
*	f	frame structure 
*
* Returns:
*	nothing
*
* Side effects:
*	frame  structure members are pointing at their
*	respective portions of the frame buffer.
--------------------------------------------------------------*/
void wlan_mgmt_encode_deauthen( wlan_fr_deauthen_t  *f )
{
        f->type = WLAN_FSTYPE_DEAUTHEN;
        f->hdr = (p80211_hdr_t*)f->buf;

        WLAN_ASSERT( f->len >= WLAN_DEAUTHEN_FR_MAXLEN );

        /*-- Fixed Fields ----*/
        f->reason	=(UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                             + WLAN_DEAUTHEN_OFF_REASON);

        f->len = WLAN_HDR_A3_LEN + WLAN_DEAUTHEN_OFF_REASON + sizeof(*(f->reason));

        return;
}


/*--------------------------------------------------------------
* wlan_mgmt_decode_deauthen
*
* Given a complete frame in f->buf, sets the pointers in f to 
* the areas that correspond to the parts of the frame.
*
* Assumptions:
*	1) f->len and f->buf are already set
*	2) f->len is the length of the MAC header + data, the CRC
*	   is NOT included
*	3) all members except len and buf are zero
*
* Arguments:
*	f	frame structure 
*
* Returns:
*	nothing
*
* Side effects:
*	frame  structure members are pointing at their
*	respective portions of the frame buffer.
--------------------------------------------------------------*/
void wlan_mgmt_decode_deauthen( wlan_fr_deauthen_t  *f )
{
        f->type = WLAN_FSTYPE_DEAUTHEN;
        f->hdr = (p80211_hdr_t*)f->buf;

        WLAN_ASSERT(WLAN_FTYPE_MGMT ==
                    WLAN_GET_FC_FTYPE(ieee2host16(f->hdr->a3.fc)));
        WLAN_ASSERT(WLAN_FSTYPE_DEAUTHEN ==
                    WLAN_GET_FC_FSTYPE(ieee2host16(f->hdr->a3.fc)));

        /*-- Fixed Fields ----*/
        f->reason	=(UINT16*)(WLAN_HDR_A3_DATAP(&(f->hdr->a3))
                             + WLAN_DEAUTHEN_OFF_REASON);

        /*-- Information elements */

        return;
}
