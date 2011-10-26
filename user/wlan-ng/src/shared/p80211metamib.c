/* src/shared/p80211metamib.c
*
* Defines the metadata for the MIB items
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
* This file contains the arrays defining the metadata for each 802.11 
* MIB items.
*
* This file contains only initialized variable definitions, no functions.
* --------------------------------------------------------------------
*
* The following MIB's are read-write according to the IEEE 802.11 standard
* but seem to be read-only with the Prism2.  They have been made read-only
* here:
*
*    dot11AssociationResponseTimeOut
*    dot11ShortRetryLimit
*    dot11LongRetryLimit
*    dot11MaxTransmitMSDULifetime
*    dot11MaxReceiveLifetime
*    dot11CurrentChannel
*    dot11CurrentCCAMode
*
* The following MIB's do not seem to be implemented by the Prism2.  They
* have been flagged as unimplemented (i.e. neither read nor write) here:
*
*    dot11AuthenticationResponseTimeOut  (Station)
*    dot11MediumOccupancyLimit           (AP)
*    dot11CFPPeriod                      (AP)
*    dot11CFPMaxDuration                 (AP)
*    p2EarlyBeacon                       (AP)
*    p2CnfMediumOccupancyLimit           (AP)
*    p2CnfCFPPeriod                      (AP)
*    p2CnfCFPMaxDuration                 (AP)
*    p2CnfCFPFlags                       (AP)
*    p2CnfPriorityQUsage                 (Station & AP)
*    p2CnfTIMCtrl                        (Station & AP)
*    p2CnfThirty2Tally                   (Station & AP)
*    p2CnfExcludeLongPreamble            (AP)
*    p2CnfAuthenticationRspTO            (Station)
*/

/*================================================================*/
/* System Includes */

#include <stdlib.h>

/*================================================================*/
/* Project Includes */

#include <wlan/wlan_compat.h>
#include <wlan/p80211types.h>
#include <wlan/p80211meta.h>
#include <wlan/p80211metamib.h>

/*================================================================*/
/* Local Constants */


/*================================================================*/
/* Local Macros */


/*================================================================*/
/* Local Types */


/*================================================================*/
/* Local Static Definitions */

extern UINT32 MKMIBMETASIZE(p80211Table);

p80211meta_t MKMIBMETANAME(p80211Table)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(p80211Table)),
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
	/* name        */ MKITEMNAME("p80211_ifstate"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(ifstate),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
};

UINT32 MKMIBMETASIZE(p80211Table) = sizeof(MKMIBMETANAME(p80211Table)) / sizeof(p80211meta_t);

extern UINT32 MKMIBMETASIZE(dot11StationConfigTable);

p80211meta_t MKMIBMETANAME(dot11StationConfigTable)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(dot11StationConfigTable)),
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
	/* name        */ MKITEMNAME("dot11StationID"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* ??????? Appears to be not supported by Prism2! ??????? */
	/* name        */ MKITEMNAME("dot11MediumOccupancyLimit"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 1000,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("dot11CFPollable"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* ??????? Appears to be not supported by Prism2! ??????? */
	/* name        */ MKITEMNAME("dot11CFPPeriod"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* ??????? Appears to be not supported by Prism2! ??????? */
	/* name        */ MKITEMNAME("dot11CFPMaxDuration"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* ??????? Appears to be not supported by Prism2! ??????? */
	/* name        */ MKITEMNAME("dot11AuthenticationResponseTimeOut"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11PrivacyOptionImplemented"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11PowerManagementMode"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11DesiredSSID"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 32,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_displaystr,
	/* fromtextptr */ p80211_fromtext_displaystr,
	/* validfunptr */ p80211_isvalid_displaystr
},
{
	/* name        */ MKITEMNAME("dot11DesiredBSSType"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11OperationalRateSet"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 126,
	/* minlen      */ 1,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11BeaconPeriod"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11DTIMPeriod"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* ??????? Read-write in 802.11 but read-only for Prism2! ??????? */
	/* name        */ MKITEMNAME("dot11AssociationResponseTimeOut"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11DisassociateReason"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 1,
	/* max         */ 9,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("dot11DisassociateStation"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11DeauthenticateReason"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 1,
	/* max         */ 9,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("dot11DeauthenticateStation"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11AuthenticateFailStatus"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 1,
	/* max         */ 18,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("dot11AuthenticateFailStation"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
}
	};

UINT32 MKMIBMETASIZE(dot11StationConfigTable) = sizeof(MKMIBMETANAME(dot11StationConfigTable)) / sizeof(p80211meta_t);

extern UINT32 MKMIBMETASIZE(dot11AuthenticationAlgorithmsTable);

p80211meta_t MKMIBMETANAME(dot11AuthenticationAlgorithmsTable)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(dot11AuthenticationAlgorithmsTable)),
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
	/* name        */ MKITEMNAME("dot11AuthenticationAlgorithm1"),
	/* did         */ P80211DID_ACCESS_READ |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11AuthenticationAlgorithmsEnable1"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11AuthenticationAlgorithm2"),
	/* did         */ P80211DID_ACCESS_READ |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11AuthenticationAlgorithmsEnable2"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11AuthenticationAlgorithm3"),
	/* did         */ P80211DID_ACCESS_READ |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11AuthenticationAlgorithmsEnable3"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11AuthenticationAlgorithm4"),
	/* did         */ P80211DID_ACCESS_READ |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11AuthenticationAlgorithmsEnable4"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11AuthenticationAlgorithm5"),
	/* did         */ P80211DID_ACCESS_READ |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11AuthenticationAlgorithmsEnable5"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11AuthenticationAlgorithm6"),
	/* did         */ P80211DID_ACCESS_READ |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11AuthenticationAlgorithmsEnable6"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
	};

UINT32 MKMIBMETASIZE(dot11AuthenticationAlgorithmsTable) = sizeof(MKMIBMETANAME(dot11AuthenticationAlgorithmsTable)) / sizeof(p80211meta_t);

extern UINT32 MKMIBMETASIZE(dot11WEPDefaultKeysTable);

p80211meta_t MKMIBMETANAME(dot11WEPDefaultKeysTable)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(dot11WEPDefaultKeysTable)),
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
	/* name        */ MKITEMNAME("dot11WEPDefaultKey0"),
	/* did         */ P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 13,
	/* minlen      */ 5,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11WEPDefaultKey1"),
	/* did         */ P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 13,
	/* minlen      */ 5,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11WEPDefaultKey2"),
	/* did         */ P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 13,
	/* minlen      */ 5,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11WEPDefaultKey3"),
	/* did         */ P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 13,
	/* minlen      */ 5,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
}
	};

UINT32 MKMIBMETASIZE(dot11WEPDefaultKeysTable) = sizeof(MKMIBMETANAME(dot11WEPDefaultKeysTable)) / sizeof(p80211meta_t);

extern UINT32 MKMIBMETASIZE(dot11WEPKeyMappingsTable);

p80211meta_t MKMIBMETANAME(dot11WEPKeyMappingsTable)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(dot11WEPKeyMappingsTable)),
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
	/* name        */ MKITEMNAME("dot11WEPKeyMappingIndex"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11WEPKeyMappingAddress"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11WEPKeyMappingWEPOn"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11WEPKeyMappingValue"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 13,
	/* minlen      */ 5,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
}
	};

UINT32 MKMIBMETASIZE(dot11WEPKeyMappingsTable) = sizeof(MKMIBMETANAME(dot11WEPKeyMappingsTable)) / sizeof(p80211meta_t);

extern UINT32 MKMIBMETASIZE(dot11PrivacyTable);

p80211meta_t MKMIBMETANAME(dot11PrivacyTable)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(dot11PrivacyTable)),
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
	/* name        */ MKITEMNAME("dot11PrivacyInvoked"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11WEPDefaultKeyID"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 3,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("dot11WEPKeyMappingLength"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11ExcludeUnencrypted"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11WEPICVErrorCount"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11WEPExcludedCount"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
}
	};

UINT32 MKMIBMETASIZE(dot11PrivacyTable) = sizeof(MKMIBMETANAME(dot11PrivacyTable)) / sizeof(p80211meta_t);


extern UINT32 MKGRPMETASIZE(dot11smt);

grplistitem_t MKGRPMETANAME(dot11smt)[] = {
	{
		(char *)&MKGRPMETASIZE(dot11smt),
		NULL
	},
	{
		"p80211Table",
		MKMIBMETANAME(p80211Table),
	},
	{
		"dot11StationConfigTable",
		MKMIBMETANAME(dot11StationConfigTable),
	},
	{
		"dot11AuthenticationAlgorithmsTable",
		MKMIBMETANAME(dot11AuthenticationAlgorithmsTable)
	},
	{
		"dot11WEPDefaultKeysTable",
		MKMIBMETANAME(dot11WEPDefaultKeysTable)
	},
	{
		"dot11WEPKeyMappingsTable",
		MKMIBMETANAME(dot11WEPKeyMappingsTable)
	},
	{
		"dot11PrivacyTable",
		MKMIBMETANAME(dot11PrivacyTable)
	}
};

UINT32 MKGRPMETASIZE(dot11smt) = sizeof(MKGRPMETANAME(dot11smt)) / sizeof(grplistitem_t);

extern UINT32 MKMIBMETASIZE(dot11OperationTable);

p80211meta_t MKMIBMETANAME(dot11OperationTable)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(dot11OperationTable)),
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
	/* name        */ MKITEMNAME("dot11MACAddress"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11RTSThreshold"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 2347,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* ??????? Read-write in 802.11 but read-only for Prism2! ??????? */
	/* name        */ MKITEMNAME("dot11ShortRetryLimit"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* ??????? Read-write in 802.11 but read-only for Prism2! ??????? */
	/* name        */ MKITEMNAME("dot11LongRetryLimit"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11FragmentationThreshold"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 256,
	/* max         */ 2346,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* ??????? Read-write in 802.11 but read-only for Prism2! ??????? */
	/* name        */ MKITEMNAME("dot11MaxTransmitMSDULifetime"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* ??????? Read-write in 802.11 but read-only for Prism2! ??????? */
	/* name        */ MKITEMNAME("dot11MaxReceiveLifetime"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11ManufacturerID"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 128,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_displaystr,
	/* fromtextptr */ p80211_fromtext_displaystr,
	/* validfunptr */ p80211_isvalid_displaystr
},
{
	/* name        */ MKITEMNAME("dot11ProductID"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 128,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_displaystr,
	/* fromtextptr */ p80211_fromtext_displaystr,
	/* validfunptr */ p80211_isvalid_displaystr
}
	};

UINT32 MKMIBMETASIZE(dot11OperationTable) = sizeof(MKMIBMETANAME(dot11OperationTable)) / sizeof(p80211meta_t);

extern UINT32 MKMIBMETASIZE(dot11CountersTable);

p80211meta_t MKMIBMETANAME(dot11CountersTable)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(dot11CountersTable)),
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
	/* name        */ MKITEMNAME("dot11TransmittedFragmentCount"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11MulticastTransmittedFrameCount"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11FailedCount"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11RetryCount"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11MultipleRetryCount"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11FrameDuplicateCount"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11RTSSuccessCount"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11RTSFailureCount"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11ACKFailureCount"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11ReceivedFragmentCount"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11MulticastReceivedFrameCount"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11FCSErrorCount"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11TransmittedFrameCount"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11WEPUndecryptableCount"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
}
	};

UINT32 MKMIBMETASIZE(dot11CountersTable) = sizeof(MKMIBMETANAME(dot11CountersTable)) / sizeof(p80211meta_t);

extern UINT32 MKMIBMETASIZE(dot11GroupAddressesTable);

p80211meta_t MKMIBMETANAME(dot11GroupAddressesTable)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(dot11GroupAddressesTable)),
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
	/* name        */ MKITEMNAME("dot11Address1"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address2"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address3"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address4"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address5"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address6"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address7"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address8"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address9"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address10"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address11"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address12"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address13"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address14"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address15"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address16"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address17"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address18"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address19"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address20"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address21"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address22"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address23"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address24"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address25"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address26"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address27"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address28"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address29"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address30"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address31"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("dot11Address32"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
}
	};

UINT32 MKMIBMETASIZE(dot11GroupAddressesTable) = sizeof(MKMIBMETANAME(dot11GroupAddressesTable)) / sizeof(p80211meta_t);


extern UINT32 MKGRPMETASIZE(dot11mac);

grplistitem_t MKGRPMETANAME(dot11mac)[] = {
	{
		(char *)&MKGRPMETASIZE(dot11mac),
		NULL
	},
	{
		"dot11OperationTable",
		MKMIBMETANAME(dot11OperationTable)
	},
	{
		"dot11CountersTable",
		MKMIBMETANAME(dot11CountersTable)
	},
	{
		"dot11GroupAddressesTable",
		MKMIBMETANAME(dot11GroupAddressesTable)
	}
};

UINT32 MKGRPMETASIZE(dot11mac) = sizeof(MKGRPMETANAME(dot11mac)) / sizeof(grplistitem_t);

extern UINT32 MKMIBMETASIZE(dot11PhyOperationTable);

p80211meta_t MKMIBMETANAME(dot11PhyOperationTable)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(dot11PhyOperationTable)),
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
	/* name        */ MKITEMNAME("dot11PHYType"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(phytype),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("dot11CurrentRegDomain"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(regdomain),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("dot11TempType"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(temptype),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("dot11ChannelAgilityPresent"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11ChannelAgilityEnabled"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11ShortPreambleEnabled"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
	};

UINT32 MKMIBMETASIZE(dot11PhyOperationTable) = sizeof(MKMIBMETANAME(dot11PhyOperationTable)) / sizeof(p80211meta_t);

extern UINT32 MKMIBMETASIZE(dot11PhyAntennaTable);

p80211meta_t MKMIBMETANAME(dot11PhyAntennaTable)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(dot11PhyAntennaTable)),
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
	/* name        */ MKITEMNAME("dot11CurrentTxAntenna"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11DiversitySupport"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(diversity),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("dot11CurrentRxAntenna"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 1,
	/* max         */ 255,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
}
	};

UINT32 MKMIBMETASIZE(dot11PhyAntennaTable) = sizeof(MKMIBMETANAME(dot11PhyAntennaTable)) / sizeof(p80211meta_t);

extern UINT32 MKMIBMETASIZE(dot11PhyTxPowerTable);

p80211meta_t MKMIBMETANAME(dot11PhyTxPowerTable)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(dot11PhyTxPowerTable)),
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
	/* name        */ MKITEMNAME("dot11NumberSupportedPowerLevels"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 1,
	/* max         */ 8,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("dot11TxPowerLevel1"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 10000,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("dot11TxPowerLevel2"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 10000,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("dot11TxPowerLevel3"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 10000,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("dot11TxPowerLevel4"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 10000,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("dot11TxPowerLevel5"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 10000,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("dot11TxPowerLevel6"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 10000,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("dot11TxPowerLevel7"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 10000,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("dot11TxPowerLevel8"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 10000,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("dot11CurrentTxPowerLevel"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 1,
	/* max         */ 8,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
}
	};

UINT32 MKMIBMETASIZE(dot11PhyTxPowerTable) = sizeof(MKMIBMETANAME(dot11PhyTxPowerTable)) / sizeof(p80211meta_t);

extern UINT32 MKMIBMETASIZE(dot11PhyFHSSTable);

p80211meta_t MKMIBMETANAME(dot11PhyFHSSTable)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(dot11PhyFHSSTable)),
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
	/* name        */ MKITEMNAME("dot11HopTime"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11CurrentChannelNumber"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 99,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("dot11MaxDwellTime"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11CurrentDwellTime"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11CurrentSet"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11CurrentPattern"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11CurrentIndex"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 1,
	/* max         */ 255,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
}
	};

UINT32 MKMIBMETASIZE(dot11PhyFHSSTable) = sizeof(MKMIBMETANAME(dot11PhyFHSSTable)) / sizeof(p80211meta_t);

extern UINT32 MKMIBMETASIZE(dot11PhyDSSSTable);

p80211meta_t MKMIBMETANAME(dot11PhyDSSSTable)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(dot11PhyDSSSTable)),
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
	/* ??????? Read-write in 802.11 but read-only for Prism2! ??????? */
	/* name        */ MKITEMNAME("dot11CurrentChannel"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11CCAModeSupported"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11CurrentCCAMode"),
	/* ??????? Read-write in 802.11 but read-only for Prism2! ??????? */
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(ccamode),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* name        */ MKITEMNAME("dot11EDThreshold"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11ShortPreambleOptionImplemented"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11PBCCOptionImplemented"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
	};

UINT32 MKMIBMETASIZE(dot11PhyDSSSTable) = sizeof(MKMIBMETANAME(dot11PhyDSSSTable)) / sizeof(p80211meta_t);

extern UINT32 MKMIBMETASIZE(dot11PhyIRTable);

p80211meta_t MKMIBMETANAME(dot11PhyIRTable)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(dot11PhyIRTable)),
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
	/* name        */ MKITEMNAME("dot11CCAWatchdogTimerMax"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11CCAWatchdogCountMax"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11CCAWatchdogTimerMin"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11CCAWatchdogCountMin"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
}
	};

UINT32 MKMIBMETASIZE(dot11PhyIRTable) = sizeof(MKMIBMETANAME(dot11PhyIRTable)) / sizeof(p80211meta_t);

extern UINT32 MKMIBMETASIZE(dot11RegDomainsSupportedTable);

p80211meta_t MKMIBMETANAME(dot11RegDomainsSupportedTable)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(dot11RegDomainsSupportedTable)),
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
	/* name        */ MKITEMNAME("dot11RegDomainsSupportIndex"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 1,
	/* max         */ 8,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("dot11RegDomainsSupportValue"),
	/* did         */ P80211DID_ACCESS_READ |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(regdomain),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
	};

UINT32 MKMIBMETASIZE(dot11RegDomainsSupportedTable) = sizeof(MKMIBMETANAME(dot11RegDomainsSupportedTable)) / sizeof(p80211meta_t);

extern UINT32 MKMIBMETASIZE(dot11AntennasListTable);

p80211meta_t MKMIBMETANAME(dot11AntennasListTable)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(dot11AntennasListTable)),
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
	/* name        */ MKITEMNAME("dot11AntennaListIndex"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11SupportedTxAntenna"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11SupportedRxAntenna"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("dot11DiversitySelectionRx"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(truth),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
}
	};

UINT32 MKMIBMETASIZE(dot11AntennasListTable) = sizeof(MKMIBMETANAME(dot11AntennasListTable)) / sizeof(p80211meta_t);

extern UINT32 MKMIBMETASIZE(dot11SupportedDataRatesTxTable);

p80211meta_t MKMIBMETANAME(dot11SupportedDataRatesTxTable)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(dot11SupportedDataRatesTxTable)),
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
	/* name        */ MKITEMNAME("dot11SupportedDataRatesTxIndex"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 1,
	/* max         */ 8,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("dot11SupportedDataRatesTxValue"),
	/* did         */ P80211DID_ACCESS_READ |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
}
	};

UINT32 MKMIBMETASIZE(dot11SupportedDataRatesTxTable) = sizeof(MKMIBMETANAME(dot11SupportedDataRatesTxTable)) / sizeof(p80211meta_t);

extern UINT32 MKMIBMETASIZE(dot11SupportedDataRatesRxTable);

p80211meta_t MKMIBMETANAME(dot11SupportedDataRatesRxTable)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(dot11SupportedDataRatesRxTable)),
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
	/* name        */ MKITEMNAME("dot11SupportedDataRatesRxIndex"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 1,
	/* max         */ 8,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("dot11SupportedDataRatesRxValue"),
	/* did         */ P80211DID_ACCESS_READ |
				P80211DID_MKISTABLE(P80211DID_ISTABLE_TRUE),
	/* flags       */ 0,
	/* min         */ 2,
	/* max         */ 127,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
}
	};

UINT32 MKMIBMETASIZE(dot11SupportedDataRatesRxTable) = sizeof(MKMIBMETANAME(dot11SupportedDataRatesRxTable)) / sizeof(p80211meta_t);


extern UINT32 MKGRPMETASIZE(dot11phy);

grplistitem_t MKGRPMETANAME(dot11phy)[] = {
		{
			(char *)&MKGRPMETASIZE(dot11phy),
			NULL
		},
		{
			"dot11PhyOperationTable",
			MKMIBMETANAME(dot11PhyOperationTable)
		},
		{
			"dot11PhyAntennaTable",
			MKMIBMETANAME(dot11PhyAntennaTable)
		},
		{
			"dot11PhyTxPowerTable",
			MKMIBMETANAME(dot11PhyTxPowerTable)
		},
		{
			"dot11PhyFHSSTable",
			MKMIBMETANAME(dot11PhyFHSSTable)
		},
		{
			"dot11PhyDSSSTable",
			MKMIBMETANAME(dot11PhyDSSSTable)
		},
		{
			"dot11PhyIRTable",
			MKMIBMETANAME(dot11PhyIRTable)
		},
		{
			"dot11RegDomainsSupportedTable",
			MKMIBMETANAME(dot11RegDomainsSupportedTable)
		},
		{
			"dot11AntennasListTable",
			MKMIBMETANAME(dot11AntennasListTable)
		},
		{
			"dot11SupportedDataRatesTxTable",
			MKMIBMETANAME(dot11SupportedDataRatesTxTable)
		},
		{
			"dot11SupportedDataRatesRxTable",
			MKMIBMETANAME(dot11SupportedDataRatesRxTable)
		}
};

UINT32 MKGRPMETASIZE(dot11phy) = sizeof(MKGRPMETANAME(dot11phy)) / sizeof(grplistitem_t);


extern UINT32 MKMIBMETASIZE(p2Table);

p80211meta_t MKMIBMETANAME(p2Table)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(p2Table)),
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
	/* name        */ MKITEMNAME("p2MMTx"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* ??????? Appears to be not supported by Prism2! ??????? */
	/* name        */ MKITEMNAME("p2EarlyBeacon"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2ReceivedFrameStatistics"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 31,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_intarray,
	/* fromtextptr */ p80211_fromtext_intarray,
	/* validfunptr */ p80211_isvalid_intarray
},
{
	/* name        */ MKITEMNAME("p2CommunicationTallies"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 21,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_intarray,
	/* fromtextptr */ p80211_fromtext_intarray,
	/* validfunptr */ p80211_isvalid_intarray
},
{
	/* name        */ MKITEMNAME("p2Authenticated"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 60,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_macarray,
	/* fromtextptr */ p80211_fromtext_macarray,
	/* validfunptr */ p80211_isvalid_macarray
},
{
	/* name        */ MKITEMNAME("p2Associated"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 60,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_macarray,
	/* fromtextptr */ p80211_fromtext_macarray,
	/* validfunptr */ p80211_isvalid_macarray
},
{
	/* name        */ MKITEMNAME("p2PowerSaveUserCount"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2Comment"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 80,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_displaystr,
	/* fromtextptr */ p80211_fromtext_displaystr,
	/* validfunptr */ p80211_isvalid_displaystr
},
{
	/* name        */ MKITEMNAME("p2AccessMode"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 1,
	/* max         */ 3,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2AccessAllow"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 60,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_macarray,
	/* fromtextptr */ p80211_fromtext_macarray,
	/* validfunptr */ p80211_isvalid_macarray
},
{
	/* name        */ MKITEMNAME("p2AccessDeny"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 60,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_macarray,
	/* fromtextptr */ p80211_fromtext_macarray,
	/* validfunptr */ p80211_isvalid_macarray
},
{
	/* name        */ MKITEMNAME("p2ChannelInfoResults"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 70,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_intarray,
	/* fromtextptr */ p80211_fromtext_intarray,
	/* validfunptr */ p80211_isvalid_intarray
}
	};

UINT32 MKMIBMETASIZE(p2Table) = sizeof(MKMIBMETANAME(p2Table)) / sizeof(p80211meta_t);


extern UINT32 MKMIBMETASIZE(p2Static);

p80211meta_t MKMIBMETANAME(p2Static)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(p2Static)),
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
	/* name        */ MKITEMNAME("p2CnfPortType"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 1,
	/* max         */ 6,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2CnfOwnMACAddress"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("p2CnfDesiredSSID"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 32,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_displaystr,
	/* fromtextptr */ p80211_fromtext_displaystr,
	/* validfunptr */ p80211_isvalid_displaystr
},
{
	/* name        */ MKITEMNAME("p2CnfOwnChannel"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 14,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2CnfOwnSSID"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 32,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_displaystr,
	/* fromtextptr */ p80211_fromtext_displaystr,
	/* validfunptr */ p80211_isvalid_displaystr
},
{
	/* name        */ MKITEMNAME("p2CnfOwnATIMWindow"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 100,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2CnfSystemScale"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 1,
	/* max         */ 3,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2CnfMaxDataLength"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 350,
	/* max         */ 2312,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2CnfWDSAddress"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("p2CnfPMEnabled"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CnfPMEPS"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CnfMulticastReceive"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CnfMaxSleepDuration"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CnfPMHoldoverDuration"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 1,
	/* max         */ 1000,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2CnfOwnName"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 32,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_displaystr,
	/* fromtextptr */ p80211_fromtext_displaystr,
	/* validfunptr */ p80211_isvalid_displaystr
},
{
	/* name        */ MKITEMNAME("p2CnfOwnDTIMPeriod"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CnfWDSAddress1"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("p2CnfWDSAddress2"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("p2CnfWDSAddress3"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("p2CnfWDSAddress4"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("p2CnfWDSAddress5"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("p2CnfWDSAddress6"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("p2CnfMulticastPMBuffering"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CnfWEPDefaultKeyID"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 3,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2CnfWEPDefaultKey0"),
	/* did         */ P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 13,
	/* minlen      */ 5,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("p2CnfWEPDefaultKey1"),
	/* did         */ P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 13,
	/* minlen      */ 5,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("p2CnfWEPDefaultKey2"),
	/* did         */ P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 13,
	/* minlen      */ 5,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("p2CnfWEPDefaultKey3"),
	/* did         */ P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 13,
	/* minlen      */ 5,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("p2CnfWEPFlags"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 7,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_bitarray,
	/* fromtextptr */ p80211_fromtext_bitarray,
},
{
	/* name        */ MKITEMNAME("p2CnfAuthentication"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 1,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_bitarray,
	/* fromtextptr */ p80211_fromtext_bitarray,
	/* validfunptr */ p80211_isvalid_bitarray
},
{
	/* name        */ MKITEMNAME("p2CnfMaxAssociatedStations"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CnfTxControl"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CnfRoamingMode"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 1,
	/* max         */ 3,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2CnfHostAuthentication"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CnfRcvCrcError"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 1,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_bitarray,
	/* fromtextptr */ p80211_fromtext_bitarray,
	/* validfunptr */ p80211_isvalid_bitarray
},
{
	/* name        */ MKITEMNAME("p2CnfAltRetryCount"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CnfBeaconInterval"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* ??????? Appears to be not supported by Prism2! ??????? */
	/* name        */ MKITEMNAME("p2CnfMediumOccupancyLimit"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 1000,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* ??????? Appears to be not supported by Prism2! ??????? */
	/* name        */ MKITEMNAME("p2CnfCFPPeriod"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* ??????? Appears to be not supported by Prism2! ??????? */
	/* name        */ MKITEMNAME("p2CnfCFPMaxDuration"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* ??????? Appears to be not supported by Prism2! ??????? */
	/* name        */ MKITEMNAME("p2CnfCFPFlags"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 15,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_bitarray,
	/* fromtextptr */ p80211_fromtext_bitarray,
	/* validfunptr */ p80211_isvalid_bitarray
},
{
	/* name        */ MKITEMNAME("p2CnfSTAPCFInfo"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 2,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* ??????? Appears to be not supported by Prism2! ??????? */
	/* name        */ MKITEMNAME("p2CnfPriorityQUsage"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 2,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_intarray,
	/* fromtextptr */ p80211_fromtext_intarray,
	/* validfunptr */ p80211_isvalid_intarray
},
{
	/* ??????? Appears to be not supported by Prism2! ??????? */
	/* name        */ MKITEMNAME("p2CnfTIMCtrl"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* ??????? Appears to be not supported by Prism2! ??????? */
	/* name        */ MKITEMNAME("p2CnfThirty2Tally"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CnfEnhSecurity"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 1,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_bitarray,
	/* fromtextptr */ p80211_fromtext_bitarray,
	/* validfunptr */ p80211_isvalid_bitarray
},
{
	/* name        */ MKITEMNAME("p2CnfShortPreamble"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ &MKENUMNAME(p2preamble),
	/* totextptr   */ p80211_totext_enumint,
	/* fromtextptr */ p80211_fromtext_enumint,
	/* validfunptr */ p80211_isvalid_enumint
},
{
	/* ??????? Appears to be not supported by Prism2! ??????? */
	/* name        */ MKITEMNAME("p2CnfExcludeLongPreamble"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CnfAuthenticationRspTO"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 20,
	/* max         */ 65535,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2CnfBasicRates"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 3,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_bitarray,
	/* fromtextptr */ p80211_fromtext_bitarray,
	/* validfunptr */ p80211_isvalid_bitarray
},
{
	/* name        */ MKITEMNAME("p2CnfSupportedRates"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 3,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_bitarray,
	/* fromtextptr */ p80211_fromtext_bitarray,
	/* validfunptr */ p80211_isvalid_bitarray
}
	};

UINT32 MKMIBMETASIZE(p2Static) = sizeof(MKMIBMETANAME(p2Static)) / sizeof(p80211meta_t);


extern UINT32 MKMIBMETASIZE(p2Dynamic);

p80211meta_t MKMIBMETANAME(p2Dynamic)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(p2Dynamic)),
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
	/* name        */ MKITEMNAME("p2CreateIBSS"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2FragmentationThreshold"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 256,
	/* max         */ 2346,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2RTSThreshold"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 3000,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2TxRateControl"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 3,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_bitarray,
	/* fromtextptr */ p80211_fromtext_bitarray,
	/* validfunptr */ p80211_isvalid_bitarray
},
{
	/* name        */ MKITEMNAME("p2PromiscuousMode"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2FragmentationThreshold0"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 256,
	/* max         */ 2346,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2FragmentationThreshold1"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 256,
	/* max         */ 2346,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2FragmentationThreshold2"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 256,
	/* max         */ 2346,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2FragmentationThreshold3"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 256,
	/* max         */ 2346,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2FragmentationThreshold4"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 256,
	/* max         */ 2346,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2FragmentationThreshold5"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 256,
	/* max         */ 2346,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2FragmentationThreshold6"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 256,
	/* max         */ 2346,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2RTSThreshold0"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 3000,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2RTSThreshold1"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 3000,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2RTSThreshold2"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 3000,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2RTSThreshold3"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 3000,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2RTSThreshold4"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 3000,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2RTSThreshold5"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 3000,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2RTSThreshold6"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 3000,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
{
	/* name        */ MKITEMNAME("p2TxRateControl0"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 3,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_bitarray,
	/* fromtextptr */ p80211_fromtext_bitarray,
	/* validfunptr */ p80211_isvalid_bitarray
},
{
	/* name        */ MKITEMNAME("p2TxRateControl1"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 3,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_bitarray,
	/* fromtextptr */ p80211_fromtext_bitarray,
	/* validfunptr */ p80211_isvalid_bitarray
},
{
	/* name        */ MKITEMNAME("p2TxRateControl2"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 3,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_bitarray,
	/* fromtextptr */ p80211_fromtext_bitarray,
	/* validfunptr */ p80211_isvalid_bitarray
},
{
	/* name        */ MKITEMNAME("p2TxRateControl3"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 3,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_bitarray,
	/* fromtextptr */ p80211_fromtext_bitarray,
	/* validfunptr */ p80211_isvalid_bitarray
},
{
	/* name        */ MKITEMNAME("p2TxRateControl4"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 3,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_bitarray,
	/* fromtextptr */ p80211_fromtext_bitarray,
	/* validfunptr */ p80211_isvalid_bitarray
},
{
	/* name        */ MKITEMNAME("p2TxRateControl5"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 3,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_bitarray,
	/* fromtextptr */ p80211_fromtext_bitarray,
	/* validfunptr */ p80211_isvalid_bitarray
},
{
	/* name        */ MKITEMNAME("p2TxRateControl6"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 3,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_bitarray,
	/* fromtextptr */ p80211_fromtext_bitarray,
	/* validfunptr */ p80211_isvalid_bitarray
}
	};

UINT32 MKMIBMETASIZE(p2Dynamic) = sizeof(MKMIBMETANAME(p2Dynamic)) / sizeof(p80211meta_t);


extern UINT32 MKMIBMETASIZE(p2Behavior);

p80211meta_t MKMIBMETANAME(p2Behavior)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(p2Behavior)),
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
	/* name        */ MKITEMNAME("p2TickTime"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 65535,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
}
	};

UINT32 MKMIBMETASIZE(p2Behavior) = sizeof(MKMIBMETANAME(p2Behavior)) / sizeof(p80211meta_t);


extern UINT32 MKMIBMETASIZE(p2NIC);

p80211meta_t MKMIBMETANAME(p2NIC)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(p2NIC)),
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
	/* name        */ MKITEMNAME("p2MaxLoadTime"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2DLBufferPage"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2DLBufferOffset"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2DLBufferLength"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2PRIIdentity"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 4,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_intarray,
	/* fromtextptr */ p80211_fromtext_intarray,
	/* validfunptr */ p80211_isvalid_intarray
},
{
	/* name        */ MKITEMNAME("p2PRISupRange"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 5,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_intarray,
	/* fromtextptr */ p80211_fromtext_intarray,
	/* validfunptr */ p80211_isvalid_intarray
},
{
	/* name        */ MKITEMNAME("p2CFIActRanges"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 5,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_intarray,
	/* fromtextptr */ p80211_fromtext_intarray,
	/* validfunptr */ p80211_isvalid_intarray
},
{
	/* name        */ MKITEMNAME("p2NICSerialNumber"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 12,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_displaystr,
	/* fromtextptr */ p80211_fromtext_displaystr,
	/* validfunptr */ p80211_isvalid_displaystr
},
{
	/* name        */ MKITEMNAME("p2NICIdentity"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 4,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_intarray,
	/* fromtextptr */ p80211_fromtext_intarray,
	/* validfunptr */ p80211_isvalid_intarray
},
{
	/* name        */ MKITEMNAME("p2MFISupRange"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 5,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_intarray,
	/* fromtextptr */ p80211_fromtext_intarray,
	/* validfunptr */ p80211_isvalid_intarray
},
{
	/* name        */ MKITEMNAME("p2CFISupRange"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 5,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_intarray,
	/* fromtextptr */ p80211_fromtext_intarray,
	/* validfunptr */ p80211_isvalid_intarray
},
{
	/* name        */ MKITEMNAME("p2ChannelList"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 13,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_bitarray,
	/* fromtextptr */ p80211_fromtext_bitarray,
	/* validfunptr */ p80211_isvalid_bitarray
},
{
	/* name        */ MKITEMNAME("p2RegulatoryDomains"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 10,
	/* minlen      */ 10,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("p2TempType"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2STAIdentity"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 4,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_intarray,
	/* fromtextptr */ p80211_fromtext_intarray,
	/* validfunptr */ p80211_isvalid_intarray
},
{
	/* name        */ MKITEMNAME("p2STASupRange"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 5,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_intarray,
	/* fromtextptr */ p80211_fromtext_intarray,
	/* validfunptr */ p80211_isvalid_intarray
},
{
	/* name        */ MKITEMNAME("p2MFIActRanges"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 5,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_intarray,
	/* fromtextptr */ p80211_fromtext_intarray,
	/* validfunptr */ p80211_isvalid_intarray
},
{
	/* name        */ MKITEMNAME("p2STACFIActRanges"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 5,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_intarray,
	/* fromtextptr */ p80211_fromtext_intarray,
	/* validfunptr */ p80211_isvalid_intarray
},
{
	/* name        */ MKITEMNAME("p2BuildSequence"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 2,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_intarray,
	/* fromtextptr */ p80211_fromtext_intarray,
	/* validfunptr */ p80211_isvalid_intarray
},
{
	/* name        */ MKITEMNAME("p2PrimaryFWID"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 13,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_displaystr,
	/* fromtextptr */ p80211_fromtext_displaystr,
	/* validfunptr */ p80211_isvalid_displaystr
},
{
	/* name        */ MKITEMNAME("p2SecondaryFWID"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 13,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_displaystr,
	/* fromtextptr */ p80211_fromtext_displaystr,
	/* validfunptr */ p80211_isvalid_displaystr
},
{
	/* name        */ MKITEMNAME("p2TertiaryFWID"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 13,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_displaystr,
	/* fromtextptr */ p80211_fromtext_displaystr,
	/* validfunptr */ p80211_isvalid_displaystr
}
	};

UINT32 MKMIBMETASIZE(p2NIC) = sizeof(MKMIBMETANAME(p2NIC)) / sizeof(p80211meta_t);


extern UINT32 MKMIBMETASIZE(p2MAC);

p80211meta_t MKMIBMETANAME(p2MAC)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(p2MAC)),
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
	/* name        */ MKITEMNAME("p2PortStatus"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CurrentSSID"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 32,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_displaystr,
	/* fromtextptr */ p80211_fromtext_displaystr,
	/* validfunptr */ p80211_isvalid_displaystr
},
{
	/* name        */ MKITEMNAME("p2CurrentBSSID"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("p2CommsQuality"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 3,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_intarray,
	/* fromtextptr */ p80211_fromtext_intarray,
	/* validfunptr */ p80211_isvalid_intarray
},
{
	/* name        */ MKITEMNAME("p2CommsQualityCQ"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CommsQualityASL"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CommsQualityANL"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2dbmCommsQuality"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 3,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_intarray,
	/* fromtextptr */ p80211_fromtext_intarray,
	/* validfunptr */ p80211_isvalid_intarray
},
{
	/* name        */ MKITEMNAME("p2dbmCommsQualityCQ"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2dbmCommsQualityASL"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2dbmCommsQualityANL"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CurrentTxRate"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CurrentBeaconInterval"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2StaCurrentScaleThresholds"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_intarray,
	/* fromtextptr */ p80211_fromtext_intarray,
	/* validfunptr */ p80211_isvalid_intarray
},
{
	/* name        */ MKITEMNAME("p2APCurrentScaleThresholds"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 3,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_intarray,
	/* fromtextptr */ p80211_fromtext_intarray,
	/* validfunptr */ p80211_isvalid_intarray
},
{
	/* name        */ MKITEMNAME("p2ProtocolRspTime"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2ShortRetryLimit"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2LongRetryLimit"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2MaxTransmitLifetime"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2MaxReceiveLifetime"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CFPollable"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2AuthenticationAlgorithms"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 2,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_intarray,
	/* fromtextptr */ p80211_fromtext_intarray,
	/* validfunptr */ p80211_isvalid_intarray
},
{
	/* name        */ MKITEMNAME("p2PrivacyOptionImplemented"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CurrentTxRate1"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CurrentTxRate2"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CurrentTxRate3"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CurrentTxRate4"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CurrentTxRate5"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CurrentTxRate6"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2OwnMACAddress"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 6,
	/* minlen      */ 6,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
}
	};

UINT32 MKMIBMETASIZE(p2MAC) = sizeof(MKMIBMETANAME(p2MAC)) / sizeof(p80211meta_t);


extern UINT32 MKMIBMETASIZE(p2Modem);

p80211meta_t MKMIBMETANAME(p2Modem)[] = {
{
	/* name        */ (char *)&(MKMIBMETASIZE(p2Modem)),
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
	/* name        */ MKITEMNAME("p2PHYType"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CurrentChannel"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CurrentPowerState"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2CCAMode"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
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
	/* name        */ MKITEMNAME("p2SupportedDataRates"),
	/* did         */ P80211DID_ACCESS_READ,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 0,
	/* maxlen      */ 10,
	/* minlen      */ 10,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_octetstr,
	/* fromtextptr */ p80211_fromtext_octetstr,
	/* validfunptr */ p80211_isvalid_octetstr
},
{
	/* name        */ MKITEMNAME("p2TxPowerMax"),
	/* did         */ P80211DID_ACCESS_READ | P80211DID_ACCESS_WRITE,
	/* flags       */ 0,
	/* min         */ 0,
	/* max         */ 30,
	/* maxlen      */ 0,
	/* minlen      */ 0,
	/* enumptr     */ NULL,
	/* totextptr   */ p80211_totext_int,
	/* fromtextptr */ p80211_fromtext_int,
	/* validfunptr */ p80211_isvalid_int
},
	};

UINT32 MKMIBMETASIZE(p2Modem) = sizeof(MKMIBMETANAME(p2Modem)) / sizeof(p80211meta_t);


extern UINT32 MKGRPMETASIZE(p2);

grplistitem_t MKGRPMETANAME(p2)[] = {
		{
			(char *)&MKGRPMETASIZE(p2),
			NULL
		},
		{
			"p2Table",
			MKMIBMETANAME(p2Table)
		},
		{
			"p2Static",
			MKMIBMETANAME(p2Static)
		},
		{
			"p2Dynamic",
			MKMIBMETANAME(p2Dynamic)
		},
		{
			"p2Behavior",
			MKMIBMETANAME(p2Behavior)
		},
		{
			"p2NIC",
			MKMIBMETANAME(p2NIC)
		},
		{
			"p2MAC",
			MKMIBMETANAME(p2MAC)
		},
		{
			"p2Modem",
			MKMIBMETANAME(p2Modem)
		}
};

UINT32 MKGRPMETASIZE(p2) = sizeof(MKGRPMETANAME(p2)) / sizeof(grplistitem_t);


extern UINT32 mib_catlist_size;

catlistitem_t mib_catlist[] =
{
	{
		(char *)&mib_catlist_size,
		NULL
	},
	{
		"dot11smt",
		MKGRPMETANAME(dot11smt)
	},
	{
		"dot11mac",
		MKGRPMETANAME(dot11mac)
	},
	{
		"dot11phy",
		MKGRPMETANAME(dot11phy)
	},
/*
	{
		"lnx",
		MKGRPMETANAME(lnx)
	},
*/

	{
		"p2",
		MKGRPMETANAME(p2)
	}
};

UINT32 mib_catlist_size = sizeof(mib_catlist)/sizeof(catlistitem_t);


/*================================================================*/
/* Local Function Declarations */


/*================================================================*/
/* Function Definitions */

