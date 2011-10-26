/* src/shared/p80211metamsg.c
*
* Defines the metadata 802.11 message items
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
* This file defines the metadata for message contents and argument
* metadata.
*
* --------------------------------------------------------------------
*/


/*================================================================*/
/* System Includes */

#include <stdio.h>
#include <stdlib.h>


/*================================================================*/
/* Project Includes */

#include <wlan/wlan_compat.h>
#include <wlan/p80211types.h>
#include <wlan/p80211meta.h>
#include <wlan/p80211msg.h>
#include <wlan/p80211metamsg.h>

/*================================================================*/
/* Local Constants */


/*================================================================*/
/* Local Macros */


/*================================================================*/
/* Local Types */


/*================================================================*/
/* Local Static Definitions */

/*====================================================================*/
/* Message Argument Metadata                                          */
/*====================================================================*/

/*--------------------------------------------------------------------*/
/* metadata for the mibget request message arguments */

extern	UINT32	MKREQMETASIZE(dot11req_mibget);

p80211meta_t MKREQMETANAME(dot11req_mibget)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(dot11req_mibget)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("mibattribute"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_MIBATTRIBUTE,
	/* minlen      */ MAXLEN_MIBATTRIBUTE,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_getmibattribute,
	/* fromtextptr */ p80211_fromtext_getmibattribute,
	/* validfunptr */ p80211_isvalid_getmibattribute
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of mibget request message metadata list */

UINT32	MKREQMETASIZE(dot11req_mibget) = sizeof(MKREQMETANAME(dot11req_mibget))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the dot11req_mibset request message arguments */

extern	UINT32	MKREQMETASIZE(dot11req_mibset);

p80211meta_t MKREQMETANAME(dot11req_mibset)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(dot11req_mibset)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("mibattribute"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_MIBATTRIBUTE,
	/* minlen      */ MAXLEN_MIBATTRIBUTE,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_setmibattribute,
	/* fromtextptr */ p80211_fromtext_setmibattribute,
	/* validfunptr */ p80211_isvalid_setmibattribute
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of dot11req_mibset request message metadata list */

UINT32	MKREQMETASIZE(dot11req_mibset) = 
		sizeof(MKREQMETANAME(dot11req_mibset))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the dot11req_powermgmt request message arguments */

extern	UINT32	MKREQMETASIZE(dot11req_powermgmt);

p80211meta_t MKREQMETANAME(dot11req_powermgmt)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(dot11req_powermgmt)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("powermgmtmode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(powermgmt),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("wakeup"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("receivedtims"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of dot11req_powermgmt request message metadata list */

UINT32	MKREQMETASIZE(dot11req_powermgmt) = 
		sizeof(MKREQMETANAME(dot11req_powermgmt))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the dot11req_scan request message arguments */

extern	UINT32	MKREQMETASIZE(dot11req_scan);

p80211meta_t MKREQMETANAME(dot11req_scan)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(dot11req_scan)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("bsstype"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(bsstype),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("bssid"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_PSTR6,
	/* minlen      */ MAXLEN_PSTR6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("ssid"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_PSTR32,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_displaystr,
	/* fromtextptr */ p80211_fromtext_displaystr,
	/* validfunptr */ p80211_isvalid_displaystr
},
{
	/* name        */ MKITEMNAME("scantype"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(scantype),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("probedelay"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("channellist"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_PSTR14,
	/* minlen      */ 1,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("minchanneltime"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("maxchanneltime"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("numbss"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
        /* name        */ MKITEMNAME("append"),
        /* did         */ 0,
        /* flags       */ P80211ITEM_SETFLAGS(ISREQUEST, 0UL, 0UL),
        /* min         */ 0,
        /* max         */ 0,
        /* maxlen      */ 0,
        /* minlen      */ 0,
        /* enumptr     */ &MKENUMNAME(truth),
        /* totextptr   */ p80211_totext_enumint,
        /* fromtextptr */ p80211_fromtext_enumint,
        /* validfunptr */ p80211_isvalid_enumint
} 
};  /* end of dot11req_scan request message metadata list */

UINT32	MKREQMETASIZE(dot11req_scan) = 
		sizeof(MKREQMETANAME(dot11req_scan))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the dot11req_scan_results request message arguments */

extern	UINT32	MKREQMETASIZE(dot11req_scan_results);

p80211meta_t MKREQMETANAME(dot11req_scan_results)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(dot11req_scan_results)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("bssindex"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
        /* name        */ MKITEMNAME("signal"),
        /* did         */ 0,
        /* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
        /* min         */ 0,
        /* max         */ 0,
        /* maxlen      */ 0,
        /* minlen      */ 0,
        /* enumptr     */ NULL,
        /* totextptr   */ p80211_totext_int,
        /* fromtextptr */ p80211_fromtext_int,
        /* validfunptr */ p80211_isvalid_int
},
{
        /* name        */ MKITEMNAME("noise"),
        /* did         */ 0,
        /* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
        /* min         */ 0,
        /* max         */ 0,
        /* maxlen      */ 0,
        /* minlen      */ 0,
        /* enumptr     */ NULL,
        /* totextptr   */ p80211_totext_int,
        /* fromtextptr */ p80211_fromtext_int,
        /* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("bssid"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_PSTR6,
	/* minlen      */ MAXLEN_PSTR6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("ssid"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_PSTR32,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_displaystr,
	/* fromtextptr */ p80211_fromtext_displaystr,
	/* validfunptr */ p80211_isvalid_displaystr
},
{
	/* name        */ MKITEMNAME("bsstype"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(bsstype),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("beaconperiod"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("dtimperiod"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 1,
	/* max         */ 255,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("timestamp"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("localtime"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("fhdwelltime"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 1,
	/* max         */ 65535,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("fhhopset"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 1,
	/* max         */ 255,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("fhhoppattern"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 255,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("fhhopindex"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 1,
	/* max         */ 255,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("dschannel"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 1,
	/* max         */ 14,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("cfpcount"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("cfpperiod"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 255,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("cfpmaxduration"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 65535,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("cfpdurremaining"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("ibssatimwindow"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("cfpollable"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("cfpollreq"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("privacy"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("basicrate1"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate2"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate3"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate4"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate5"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate6"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate7"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate8"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("supprate1"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("supprate2"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("supprate3"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("supprate4"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("supprate5"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("supprate6"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("supprate7"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("supprate8"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
};  /* end of dot11req_scan_results metadata list */

UINT32	MKREQMETASIZE(dot11req_scan_results) = 
		sizeof(MKREQMETANAME(dot11req_scan_results))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the dot11req_join request message arguments */

extern	UINT32	MKREQMETASIZE(dot11req_join);

p80211meta_t MKREQMETANAME(dot11req_join)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(dot11req_join)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("bssid"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_PSTR6,
	/* minlen      */ MAXLEN_PSTR6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("joinfailuretimeout"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 1,
	/* max         */ UINT32_MAX,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate1"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate2"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate3"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate4"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate5"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate6"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate7"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate8"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate1"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate2"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate3"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate4"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate5"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate6"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate7"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate8"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of dot11req_join request message metadata list */

UINT32	MKREQMETASIZE(dot11req_join) = 
		sizeof(MKREQMETANAME(dot11req_join))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the dot11req_authenticate request message arguments */

extern	UINT32	MKREQMETASIZE(dot11req_authenticate);

p80211meta_t MKREQMETANAME(dot11req_authenticate)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(dot11req_authenticate)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("peerstaaddress"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_PSTR6,
	/* minlen      */ MAXLEN_PSTR6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("authenticationtype"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(authalg),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("authenticationfailuretimeout"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 1,
	/* max         */ UINT32_MAX,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of dot11req_authenticate request message metadata list */

UINT32	MKREQMETASIZE(dot11req_authenticate) = 
		sizeof(MKREQMETANAME(dot11req_authenticate))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the dot11req_deauthenticate request message arguments */

extern	UINT32	MKREQMETASIZE(dot11req_deauthenticate);

p80211meta_t MKREQMETANAME(dot11req_deauthenticate)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(dot11req_deauthenticate)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("peerstaaddress"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_PSTR6,
	/* minlen      */ MAXLEN_PSTR6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("reasoncode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(reason),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of dot11req_deauthenticate request message metadata list */

UINT32	MKREQMETASIZE(dot11req_deauthenticate) = 
		sizeof(MKREQMETANAME(dot11req_deauthenticate))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the dot11req_associate request message arguments */

extern	UINT32	MKREQMETASIZE(dot11req_associate);

p80211meta_t MKREQMETANAME(dot11req_associate)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(dot11req_associate)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("peerstaaddress"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_PSTR6,
	/* minlen      */ MAXLEN_PSTR6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("associatefailuretimeout"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 1,
	/* max         */ UINT32_MAX,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("cfpollable"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("cfpollreq"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("privacy"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("listeninterval"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of dot11req_associate request message metadata list */

UINT32	MKREQMETASIZE(dot11req_associate) = 
		sizeof(MKREQMETANAME(dot11req_associate))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the dot11req_reassociate request message arguments */

extern	UINT32	MKREQMETASIZE(dot11req_reassociate);

p80211meta_t MKREQMETANAME(dot11req_reassociate)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(dot11req_reassociate)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("newapaddress"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_PSTR6,
	/* minlen      */ MAXLEN_PSTR6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("reassociatefailuretimeout"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 1,
	/* max         */ UINT32_MAX,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("cfpollable"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("cfpollreq"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("privacy"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("listeninterval"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of dot11req_reassociate request message metadata list */

UINT32	MKREQMETASIZE(dot11req_reassociate) = sizeof(MKREQMETANAME(dot11req_reassociate))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the dot11req_disassociate request message arguments */

extern	UINT32	MKREQMETASIZE(dot11req_disassociate);

p80211meta_t MKREQMETANAME(dot11req_disassociate)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(dot11req_disassociate)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("peerstaaddress"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_PSTR6,
	/* minlen      */ MAXLEN_PSTR6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("reasoncode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(reason),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of dot11req_disassociate request message metadata list */

UINT32	MKREQMETASIZE(dot11req_disassociate) = sizeof(MKREQMETANAME(dot11req_disassociate))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the dot11req_reset request message arguments */

extern	UINT32	MKREQMETASIZE(dot11req_reset);

p80211meta_t MKREQMETANAME(dot11req_reset)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(dot11req_reset)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("setdefaultmib"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("macaddress"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_PSTR6,
	/* minlen      */ MAXLEN_PSTR6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of dot11req_reset request message metadata list */

UINT32	MKREQMETASIZE(dot11req_reset) = sizeof(MKREQMETANAME(dot11req_reset))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the dot11req_start request message arguments */

extern	UINT32	MKREQMETASIZE(dot11req_start);

p80211meta_t MKREQMETANAME(dot11req_start)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(dot11req_start)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("ssid"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_PSTR32,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_displaystr,
	/* fromtextptr */ p80211_fromtext_displaystr,
	/* validfunptr */ p80211_isvalid_displaystr
},
{
	/* name        */ MKITEMNAME("bsstype"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(bsstype),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("beaconperiod"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 1,
	/* max         */ 65535,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("dtimperiod"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 1,
	/* max         */ 255,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("cfpperiod"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 255,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("cfpmaxduration"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 65535,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("fhdwelltime"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 1,
	/* max         */ 65535,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("fhhopset"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 1,
	/* max         */ 255,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("fhhoppattern"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 255,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("dschannel"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 1,
	/* max         */ 14,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("ibssatimwindow"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("probedelay"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("cfpollable"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("cfpollreq"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("basicrate1"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate2"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate3"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate4"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate5"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate6"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate7"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate8"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate1"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate2"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate3"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate4"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate5"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate6"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate7"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate8"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of dot11req_start request message metadata list */

UINT32	MKREQMETASIZE(dot11req_start) = 
		sizeof(MKREQMETANAME(dot11req_start))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the dot11ind_authenticate indication message arguments */

extern	UINT32	MKINDMETASIZE(dot11ind_authenticate);

p80211meta_t MKINDMETANAME(dot11ind_authenticate)[] = {
{
	/* name        */ (char *)&(MKINDMETASIZE(dot11ind_authenticate)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("peerstaaddress"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_PSTR6,
	/* minlen      */ MAXLEN_PSTR6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("authenticationtype"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(authalg),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of dot11ind_authenticate indication metadata list */

UINT32	MKINDMETASIZE(dot11ind_authenticate) = 
		sizeof(MKINDMETANAME(dot11ind_authenticate))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the authenticate indication message arguments */

extern	UINT32	MKINDMETASIZE(dot11ind_deauthenticate);

p80211meta_t MKINDMETANAME(dot11ind_deauthenticate)[] = {
{
	/* name        */ (char *)&(MKINDMETASIZE(dot11ind_deauthenticate)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("peerstaaddress"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_PSTR6,
	/* minlen      */ MAXLEN_PSTR6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("reasoncode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(reason),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of dot11ind_deauthenticate indication metadata list */

UINT32	MKINDMETASIZE(dot11ind_deauthenticate) = 
		sizeof(MKINDMETANAME(dot11ind_deauthenticate))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the dot11ind_associate indication message arguments */

extern	UINT32	MKINDMETASIZE(dot11ind_associate);

p80211meta_t MKINDMETANAME(dot11ind_associate)[] = {
{
	/* name        */ (char *)&(MKINDMETASIZE(dot11ind_associate)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("peerstaaddress"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_PSTR6,
	/* minlen      */ MAXLEN_PSTR6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("aid"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 2003,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
};  /* end of dot11ind_associate indication metadata list */

UINT32	MKINDMETASIZE(dot11ind_associate) =
		sizeof(MKINDMETANAME(dot11ind_associate))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the reassociate indication message arguments */

extern	UINT32	MKINDMETASIZE(dot11ind_reassociate);

p80211meta_t MKINDMETANAME(dot11ind_reassociate)[] = {
{
	/* name        */ (char *)&(MKINDMETASIZE(dot11ind_reassociate)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("peerstaaddress"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_PSTR6,
	/* minlen      */ MAXLEN_PSTR6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("aid"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 2003,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("oldapaddress"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_PSTR6,
	/* minlen      */ MAXLEN_PSTR6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */
},
};  /* end of dot11ind_reassociate indication metadata list */

UINT32	MKINDMETASIZE(dot11ind_reassociate) = 
		sizeof(MKINDMETANAME(dot11ind_reassociate))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the dot11ind_disassociate indication message arguments */

extern	UINT32	MKINDMETASIZE(dot11ind_disassociate);

p80211meta_t MKINDMETANAME(dot11ind_disassociate)[] = {
{
	/* name        */ (char *)&(MKINDMETASIZE(dot11ind_disassociate)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("peerstaaddress"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_PSTR6,
	/* minlen      */ MAXLEN_PSTR6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("reasoncode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(reason),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of dot11ind_disassociate indication metadata list */

UINT32	MKINDMETASIZE(dot11ind_disassociate) = 
		sizeof(MKINDMETANAME(dot11ind_disassociate))/sizeof(p80211meta_t);

extern	UINT32	MKINDMETASIZE(lnxind_roam);

p80211meta_t MKINDMETANAME(lnxind_roam)[] = {
{
	/* name        */ (char *)&(MKINDMETASIZE(lnxind_roam)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("reason"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(lnxroam_reason),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of dot11ind_associate indication metadata list */

UINT32	MKINDMETASIZE(lnxind_roam) =
		sizeof(MKINDMETANAME(lnxind_roam))/sizeof(p80211meta_t);


/*--------------------------------------------------------------------*/
/* metadata for the ifstate request message arguments */

extern	UINT32	MKREQMETASIZE(lnxreq_ifstate);

p80211meta_t MKREQMETANAME(lnxreq_ifstate)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(lnxreq_ifstate)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("ifstate"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(ifstate),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of lnxreq_ifstate request metadata list */

UINT32	MKREQMETASIZE(lnxreq_ifstate) = 
		sizeof(MKREQMETANAME(lnxreq_ifstate))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the commsquality request message arguments */
extern  UINT32  MKREQMETASIZE(lnxreq_commsquality);

p80211meta_t MKREQMETANAME(lnxreq_commsquality)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(lnxreq_commsquality)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("dbm"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("link"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("level"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("noise"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
}; /* end of lnxreq_commsquality list */

UINT32	MKREQMETASIZE(lnxreq_commsquality) = 
	sizeof(MKREQMETANAME(lnxreq_commsquality))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the hostwep request message arguments */
extern  UINT32  MKREQMETASIZE(lnxreq_hostwep);

p80211meta_t MKREQMETANAME(lnxreq_hostwep)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(lnxreq_hostwep)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("decrypt"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("encrypt"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
}; /* end of lnxreq_hostwep list */

UINT32	MKREQMETASIZE(lnxreq_hostwep) = 
		sizeof(MKREQMETANAME(lnxreq_hostwep))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the wlansnif request message arguments */

extern	UINT32	MKREQMETASIZE(lnxreq_wlansniff);

p80211meta_t MKREQMETANAME(lnxreq_wlansniff)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(lnxreq_wlansniff)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("enable"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("channel"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 1,
	/* max         */ 14,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("prismheader"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("wlanheader"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("keepwepflags"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("stripfcs"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("packet_trunc"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 2000,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of lnxreq_wlansniff request metadata list */

UINT32	MKREQMETASIZE(lnxreq_wlansniff) = 
		sizeof(MKREQMETANAME(lnxreq_wlansniff))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the autojoin request message arguments */

extern	UINT32	MKREQMETASIZE(lnxreq_autojoin);

p80211meta_t MKREQMETANAME(lnxreq_autojoin)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(lnxreq_autojoin)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("ssid"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_PSTR32,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_displaystr,
	/* fromtextptr */ p80211_fromtext_displaystr,
	/* validfunptr */ p80211_isvalid_displaystr
},
{
	/* name        */ MKITEMNAME("authtype"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(authalg),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}

};  /* end of lnxreq_autojoin request metadata list */

UINT32	MKREQMETASIZE(lnxreq_autojoin) = 
		sizeof(MKREQMETANAME(lnxreq_autojoin))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the wlansniffrm indication message arguments */

extern	UINT32	MKINDMETASIZE(lnxind_wlansniffrm);

p80211meta_t MKINDMETANAME(lnxind_wlansniffrm)[] = {
{
	/* name        */ (char *)&(MKINDMETASIZE(lnxind_wlansniffrm)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("hosttime"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("mactime"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, 0UL, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("channel"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, 0UL, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("rssi"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, 0UL, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("sq"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, 0UL, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("signal"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, 0UL, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("noise"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, 0UL, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("rate"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, 0UL, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("istx"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("frmlen"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
}
};  /* end of lnxind_wlansniffrm indication message */

UINT32	MKINDMETASIZE(lnxind_wlansniffrm) = 
		sizeof(MKINDMETANAME(lnxind_wlansniffrm))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the p2req_join request message arguments */

extern	UINT32	MKREQMETASIZE(p2req_join);

p80211meta_t MKREQMETANAME(p2req_join)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(p2req_join)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("bssid"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_PSTR6,
	/* minlen      */ MAXLEN_PSTR6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("basicrate1"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate2"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate3"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate4"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate5"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate6"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate7"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("basicrate8"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate1"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate2"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate3"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate4"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate5"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate6"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate7"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("operationalrate8"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("ssid"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ MAXLEN_PSTR32,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_displaystr,
	/* fromtextptr */ p80211_fromtext_displaystr,
	/* validfunptr */ p80211_isvalid_displaystr
},
{
	/* name        */ MKITEMNAME("channel"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 1,
	/* max         */ 14,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("authtype"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(authalg),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of p2req_join request message metadata list */

UINT32	MKREQMETASIZE(p2req_join) = 
		sizeof(MKREQMETANAME(p2req_join))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the p2req_readpda request message arguments */

extern	UINT32	MKREQMETASIZE(p2req_readpda);

p80211meta_t MKREQMETANAME(p2req_readpda)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(p2req_readpda)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("pda"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 1024,
	/* minlen      */ 1024,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,  /* data only used by program...*/
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of p2req_readpda request metadata list */

UINT32	MKREQMETASIZE(p2req_readpda) = 
		sizeof(MKREQMETANAME(p2req_readpda))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the p2req_readcis request message arguments */

extern	UINT32	MKREQMETASIZE(p2req_readcis);

p80211meta_t MKREQMETANAME(p2req_readcis)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(p2req_readcis)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("cis"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 1024,
	/* minlen      */ 1024,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,  /* data only used by program...*/
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of p2req_readcis request metadata list */

UINT32	MKREQMETASIZE(p2req_readcis) = 
		sizeof(MKREQMETANAME(p2req_readcis))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the p2req_auxport_state request message arguments */

extern	UINT32	MKREQMETASIZE(p2req_auxport_state);

p80211meta_t MKREQMETANAME(p2req_auxport_state)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(p2req_auxport_state)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("enable"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of p2req_auxport_state request metadata list */

UINT32	MKREQMETASIZE(p2req_auxport_state) = 
		sizeof(MKREQMETANAME(p2req_auxport_state))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the p2req_auxport_read request message arguments */

extern	UINT32	MKREQMETASIZE(p2req_auxport_read);

p80211meta_t MKREQMETANAME(p2req_auxport_read)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(p2req_auxport_read)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("addr"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("len"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("data"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 1024,
	/* minlen      */ 1024,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,	/* data only handled by programs */
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of p2req_auxport_read request metadata list */

UINT32	MKREQMETASIZE(p2req_auxport_read) = 
		sizeof(MKREQMETANAME(p2req_auxport_read))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the p2req_auxport_write request message arguments */

extern	UINT32	MKREQMETASIZE(p2req_auxport_write);

p80211meta_t MKREQMETANAME(p2req_auxport_write)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(p2req_auxport_write)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("addr"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("len"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("data"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 1024,
	/* minlen      */ 1024,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,	/* data only handled by programs */
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of p2req_auxport_write request metadata list */

UINT32	MKREQMETASIZE(p2req_auxport_write) = 
		sizeof(MKREQMETANAME(p2req_auxport_write))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the p2req_low_level request message arguments */

extern	UINT32	MKREQMETASIZE(p2req_low_level);

p80211meta_t MKREQMETANAME(p2req_low_level)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(p2req_low_level)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("command"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("param0"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("param1"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("param2"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("resp0"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("resp1"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("resp2"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}

/* Lets add the status and resp register values. */

};  /* end of p2req_low_level request metadata list */

UINT32	MKREQMETASIZE(p2req_low_level) = 
		sizeof(MKREQMETANAME(p2req_low_level))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the p2req_test_command request message arguments */

extern	UINT32	MKREQMETASIZE(p2req_test_command);

p80211meta_t MKREQMETANAME(p2req_test_command)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(p2req_test_command)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("testcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("testparam"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("status"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("resp0"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("resp1"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("resp2"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
}

/* Lets add the status and resp register values. */

};  /* end of p2req_test_command request metadata list */

UINT32	MKREQMETASIZE(p2req_test_command) = 
		sizeof(MKREQMETANAME(p2req_test_command))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the p2req_mmi_read request message arguments */

extern	UINT32	MKREQMETASIZE(p2req_mmi_read);

p80211meta_t MKREQMETANAME(p2req_mmi_read)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(p2req_mmi_read)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("addr"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("value"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of p2req_mmi_read request metadata list */

UINT32	MKREQMETASIZE(p2req_mmi_read) = 
		sizeof(MKREQMETANAME(p2req_mmi_read))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the p2req_mmi_write request message arguments */

extern	UINT32	MKREQMETASIZE(p2req_mmi_write);

p80211meta_t MKREQMETANAME(p2req_mmi_write)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(p2req_mmi_write)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("addr"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("data"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of p2req_mmi_write request metadata list */

UINT32	MKREQMETASIZE(p2req_mmi_write) = 
		sizeof(MKREQMETANAME(p2req_mmi_write))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the p2req_ramdl_state request message arguments */

extern	UINT32	MKREQMETASIZE(p2req_ramdl_state);

p80211meta_t MKREQMETANAME(p2req_ramdl_state)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(p2req_ramdl_state)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("enable"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("exeaddr"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of p2req_ramdl_state request metadata list */

UINT32	MKREQMETASIZE(p2req_ramdl_state) = 
		sizeof(MKREQMETANAME(p2req_ramdl_state))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the p2req_ramdl_write request message arguments */

extern	UINT32	MKREQMETASIZE(p2req_ramdl_write);

p80211meta_t MKREQMETANAME(p2req_ramdl_write)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(p2req_ramdl_write)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("addr"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("len"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("data"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 4096,
	/* minlen      */ 4096,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,	/* data only handled by programs */
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of p2req_ramdl_write request metadata list */

UINT32	MKREQMETASIZE(p2req_ramdl_write) = 
		sizeof(MKREQMETANAME(p2req_ramdl_write))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the p2req_flashdl_state request message arguments */

extern	UINT32	MKREQMETASIZE(p2req_flashdl_state);

p80211meta_t MKREQMETANAME(p2req_flashdl_state)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(p2req_flashdl_state)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("enable"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of p2req_flashdl_state request metadata list */

UINT32	MKREQMETASIZE(p2req_flashdl_state) = 
		sizeof(MKREQMETANAME(p2req_flashdl_state))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the p2req_flashdl_write request message arguments */

extern	UINT32	MKREQMETASIZE(p2req_flashdl_write);

p80211meta_t MKREQMETANAME(p2req_flashdl_write)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(p2req_flashdl_write)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("addr"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("len"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("data"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 4096,
	/* minlen      */ 4096,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,	/* data only handled by programs */
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of p2req_flashdl_write request metadata list */

UINT32	MKREQMETASIZE(p2req_flashdl_write) = 
		sizeof(MKREQMETANAME(p2req_flashdl_write))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the p2req_mm_state request message arguments */

extern	UINT32	MKREQMETASIZE(p2req_mm_state);

p80211meta_t MKREQMETANAME(p2req_mm_state)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(p2req_mm_state)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("enable"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of p2req_mm_state request metadata list */

UINT32	MKREQMETASIZE(p2req_mm_state) = 
		sizeof(MKREQMETANAME(p2req_mm_state))/sizeof(p80211meta_t);

	
/*--------------------------------------------------------------------*/
/* metadata for the p2req_dump_state request message arguments */

extern	UINT32	MKREQMETASIZE(p2req_dump_state);

p80211meta_t MKREQMETANAME(p2req_dump_state)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(p2req_dump_state)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("level"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 0,
	/* max         */ 63,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of p2req_dump_state request metadata list */

UINT32	MKREQMETASIZE(p2req_dump_state) = 
		sizeof(MKREQMETANAME(p2req_dump_state))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the p2req_channel_info request message arguments */

extern	UINT32	MKREQMETASIZE(p2req_channel_info);

p80211meta_t MKREQMETANAME(p2req_channel_info)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(p2req_channel_info)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("channellist"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 1,
	/* max         */ 14,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_bitarray,
	/* fromtextptr */ p80211_fromtext_bitarray,
	/* validfunptr */ p80211_isvalid_bitarray
},
{
	/* name        */ MKITEMNAME("channeldwelltime"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(0UL, ISREQUEST, 0UL),
	/* min         */ 1,
	/* max         */ 65535,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("numchinfo"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
}
};  /* end of p2req_channel_info request metadata list */

UINT32	MKREQMETASIZE(p2req_channel_info) = 
		sizeof(MKREQMETANAME(p2req_channel_info))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the p2req_channel_info_results request message arguments */

extern	UINT32	MKREQMETASIZE(p2req_channel_info_results);

p80211meta_t MKREQMETANAME(p2req_channel_info_results)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(p2req_channel_info_results)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("channel"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, ISREQUEST, 0UL),
	/* min         */ 1,
	/* max         */ 14,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("avgnoiselevel"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("peaknoiselevel"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("bssactive"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("pcfactive"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of p2req_channel_info_results request metadata list */

UINT32	MKREQMETASIZE(p2req_channel_info_results) = 
		sizeof(MKREQMETANAME(p2req_channel_info_results))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* metadata for the p2req_enable request message arguments */

extern	UINT32	MKREQMETASIZE(p2req_enable);

p80211meta_t MKREQMETANAME(p2req_enable)[] = {
{
	/* name        */ (char *)&(MKREQMETASIZE(p2req_enable)),
	/* did         */ 0,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ NULL,
	/* fromtextptr */ NULL,
	/* validfunptr */ NULL
},
{
	/* name        */ MKITEMNAME("resultcode"),
	/* did         */ 0,
	/* flags       */ P80211ITEM_SETFLAGS(ISREQUIRED, 0UL, ISCONFIRM),
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(resultcode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
};  /* end of p2req_enable request metadata list */

UINT32	MKREQMETASIZE(p2req_enable) = 
		sizeof(MKREQMETANAME(p2req_enable))/sizeof(p80211meta_t);

/*--------------------------------------------------------------------*/
/* Messages Group arrays */


extern UINT32 MKGRPMETASIZE(dot11req);

grplistitem_t MKGRPMETANAME(dot11req)[] = {
	{
		(char *)&MKGRPMETASIZE(dot11req),
		NULL
	},
	{
		"dot11req_mibget",
		MKREQMETANAME(dot11req_mibget)
	},
	{
		"dot11req_mibset",
		MKREQMETANAME(dot11req_mibset)
	},
	{
		"dot11req_powermgmt",
		MKREQMETANAME(dot11req_powermgmt)
	},
	{
		"dot11req_scan",
		MKREQMETANAME(dot11req_scan)
	},
	{
		"dot11req_scan_results",
		MKREQMETANAME(dot11req_scan_results)
	},
	{
		"dot11req_join",
		MKREQMETANAME(dot11req_join)
	},
	{
		"dot11req_authenticate",
		MKREQMETANAME(dot11req_authenticate)
	},
	{
		"dot11req_deauthenticate",
		MKREQMETANAME(dot11req_deauthenticate)
	},
	{
		"dot11req_associate",
		MKREQMETANAME(dot11req_associate)
	},
	{
		"dot11req_reassociate",
		MKREQMETANAME(dot11req_reassociate)
	},
	{
		"dot11req_disassociate",
		MKREQMETANAME(dot11req_disassociate)
	},
	{
		"dot11req_reset",
		MKREQMETANAME(dot11req_reset)
	},
	{
		"dot11req_start",
		MKREQMETANAME(dot11req_start)
	}
};

UINT32 MKGRPMETASIZE(dot11req) =sizeof(MKGRPMETANAME(dot11req)) /
				sizeof(grplistitem_t);

extern UINT32 MKGRPMETASIZE(dot11ind);

grplistitem_t MKGRPMETANAME(dot11ind)[] = {
	{
		(char *)&MKGRPMETASIZE(dot11ind),
		NULL
	},
	{
		"dot11ind_authenticate",
		MKINDMETANAME(dot11ind_authenticate)
	},
	{
		"dot11ind_deauthenticate",
		MKINDMETANAME(dot11ind_deauthenticate)
	},
	{
		"dot11ind_associate",
		MKINDMETANAME(dot11ind_associate)
	},
	{
		"dot11ind_reassociate",
		MKINDMETANAME(dot11ind_reassociate)
	},
	{
		"dot11ind_disassociate",
		MKINDMETANAME(dot11ind_disassociate)
	}
};

UINT32 MKGRPMETASIZE(dot11ind) =sizeof(MKGRPMETANAME(dot11ind)) /
				sizeof(grplistitem_t);

extern UINT32 MKGRPMETASIZE(lnxreq);

grplistitem_t MKGRPMETANAME(lnxreq)[] = {
	{
		(char *)&MKGRPMETASIZE(lnxreq),
		NULL
	},
	{
		"lnxreq_ifstate",
		MKREQMETANAME(lnxreq_ifstate)
	},
	{
		"lnxreq_wlansniff",
		MKREQMETANAME(lnxreq_wlansniff)
	},
	{
		"lnxreq_hostwep",
		MKREQMETANAME(lnxreq_hostwep)
	},
	{
		"lnxreq_commsquality",
		MKREQMETANAME(lnxreq_commsquality)
	},
	{
		"lnxreq_autojoin",
		MKREQMETANAME(lnxreq_autojoin)
	}

};

UINT32 MKGRPMETASIZE(lnxreq) =sizeof(MKGRPMETANAME(lnxreq)) /
				sizeof(grplistitem_t);


extern UINT32 MKGRPMETASIZE(lnxind);

grplistitem_t MKGRPMETANAME(lnxind)[] = {
	{
		(char *)&MKGRPMETASIZE(lnxind),
		NULL
	},
	{
		"lnxind_wlansniffrm",
		MKINDMETANAME(lnxind_wlansniffrm)
	},
	{
		"lnxind_roam",
		MKINDMETANAME(lnxind_roam)
	},
};

UINT32 MKGRPMETASIZE(lnxind) =sizeof(MKGRPMETANAME(lnxind)) /
				sizeof(grplistitem_t);


extern UINT32 MKGRPMETASIZE(p2req);

grplistitem_t MKGRPMETANAME(p2req)[] = {
	{
		(char *)&MKGRPMETASIZE(p2req),
		NULL
	},
	{
		"p2req_join",
		MKREQMETANAME(p2req_join)
	},
	{
		"p2req_readpda",
		MKREQMETANAME(p2req_readpda)
	},
	{
		"p2req_readcis",
		MKREQMETANAME(p2req_readcis)
	},
	{
		"p2req_auxport_state",	/* enable=true|false */
		MKREQMETANAME(p2req_auxport_state)
	},
	{
		"p2req_auxport_read",	/* addr, len[2-1024], datap */
		MKREQMETANAME(p2req_auxport_read)
	},
	{
		"p2req_auxport_write",	/* addr, len[2-1024], datap */
		MKREQMETANAME(p2req_auxport_write)
	},
	{
		"p2req_low_level",   /* testcode=UINT32 testparam=UINT32 */
		MKREQMETANAME(p2req_low_level)
	},
	{
		"p2req_test_command",   /* testcode=UINT32 testparam=UINT32 */
		MKREQMETANAME(p2req_test_command)
	},
	{
		"p2req_mmi_read",   /* cmd_code=UINT32 register=UINT32 */
		MKREQMETANAME(p2req_mmi_read)
	},
	{
		"p2req_mmi_write",   /* cmd_code=UINT32 register=UINT32 */
		MKREQMETANAME(p2req_mmi_write)
	},
	{
		"p2req_ramdl_state",	/* enable=true|false, exeaddr=UINT32 */
		MKREQMETANAME(p2req_ramdl_state)
	},
	{
		"p2req_ramdl_write",	/* addr, len[2-1024], datap */
		MKREQMETANAME(p2req_ramdl_write)
	},
	{
		"p2req_flashdl_state",	/* enable=true|false */
		MKREQMETANAME(p2req_flashdl_state)
	},
	{
		"p2req_flashdl_write",	/* addr, len[2-1024], datap */
		MKREQMETANAME(p2req_flashdl_write)
	},
	{
		"p2req_mm_state",	/* enable=true|false, level=[0-3] */
		MKREQMETANAME(p2req_mm_state)
	},
	{
		"p2req_dump_state",	/* level=0-63 */
		MKREQMETANAME(p2req_dump_state)
	},
	{
		"p2req_channel_info",	/* channellist[1..14], channeldwelltime=UINT16 */
		MKREQMETANAME(p2req_channel_info)
	},
	{
		"p2req_channel_info_results",	/* channel, asl, psl, bssactive, pcfactive */
		MKREQMETANAME(p2req_channel_info_results)
	},
	{
		"p2req_enable",
		MKREQMETANAME(p2req_enable)
	}
};


UINT32 MKGRPMETASIZE(p2req) = sizeof(MKGRPMETANAME(p2req)) /
				sizeof(grplistitem_t);

extern UINT32 msg_catlist_size;

catlistitem_t msg_catlist[] =
{
	{
		(char *)&msg_catlist_size,
		NULL
	},
	{
		"dot11req",
		MKGRPMETANAME(dot11req)
	},
	/* dot11cfm does not exist at this time */
	{
		"dot11ind",
		MKGRPMETANAME(dot11ind)
	},
	{
		"lnxreq",
		MKGRPMETANAME(lnxreq)
	},
	{
		"lnxind",
		MKGRPMETANAME(lnxind)
	},
	{
		"p2req",
		MKGRPMETANAME(p2req)
	}
};

UINT32 msg_catlist_size = sizeof(msg_catlist)/sizeof(catlistitem_t);


/*================================================================*/
/* Local Function Declarations */

/*================================================================*/
/* Function Definitions */
