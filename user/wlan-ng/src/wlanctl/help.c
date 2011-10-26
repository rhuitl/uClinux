/* src/wlanctl/help.c
*
* wlanctl-ng help messages
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
*/

/*================================================================*/
/* System Includes */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*================================================================*/
/* Project Includes */

#include <wlan/wlan_compat.h>
#include <wlan/version.h>
#include <wlan/p80211types.h>
#include <wlan/p80211meta.h>
#include <wlan/p80211metamsg.h>
#include <wlan/p80211metamib.h>
#include <wlan/p80211msg.h>
#include "wlanctl.h"

/*================================================================*/
/* Local Constants */


/*================================================================*/
/* Local Macros */


/*================================================================*/
/* Local Types */


/*================================================================*/
/* Local Static Definitions */


/*================================================================*/
/* Local Function Declarations */

void	usage(void);
void	print_allrequests(void);			
void	print_allmibs(void);

/*================================================================*/
/* Function Definitions */


/*----------------------------------------------------------------
* usage
*
* Print a short usage message
*
* Arguments:
*	none
*
* Returns: 
*	nothing
----------------------------------------------------------------*/
void usage(void)
{
	printf("wlanctl-ng: - control utility for 802.11 devices\n");
	printf("  usage: wlanctl-ng interface|version|commands|mibs cmd cmdarg [cmdarg...]\n\n");

	printf("         where \"interface\" is the name of a wireless\n");
	printf("         network interface.  Running \'ifconfig\' will list\n");
	printf("         all network interfaces.\n\n");

	printf("         For a list of available commands, run \'wlanctl-ng commands\'\n\n");
	printf("         For a list of available mib items, run \'wlanctl-ng mibs\'\n");
}


/*----------------------------------------------------------------
* print_allrequests
*
* Traverse all of the requests in the message and message argument 
* metadata.  Print the name of the request, the name of each request
* argument and any validation requirements.
*
* Arguments:
*	none
*
* Returns: 
*	nothing
----------------------------------------------------------------*/
void print_allrequests(void)
{
	int		i;
	int		j;
	int		k;
	UINT32		did;
	p80211meta_t	*msg_item;
	grplistitem_t	*grp;
	int		msg_cat;
	int		ncats;
	int		ncmds;
	int		nitems;
	p80211enum_t	*enump;

	ncats = GETMETASIZE(msg_catlist);

	for (msg_cat = 1; msg_cat < ncats; msg_cat++ ) {

		if ( strstr(msg_catlist[msg_cat].name, "req") == NULL ) {
			continue;
		}

		ncmds = GETMETASIZE(msg_catlist[msg_cat].grplist);

		for (i = 1; i < ncmds; i++ ) {
			did = P80211DID_MKSECTION(msg_cat) | P80211DID_MKGROUP(i);
			if ( (grp = p80211_did2grp(msg_catlist, did)) != NULL ) {

				printf("Command: %s\n", grp->name);
				msg_item = grp->itemlist;
				nitems = GETMETASIZE(msg_item);

				for ( j = 1; j < nitems; j++)
				{
					if  ( P80211ITEM_ISREQUEST(msg_item[j].flags) ) {

						printf( "    %s(%s):",
						msg_item[j].name,
						P80211ITEM_ISREQUIRED(msg_item[j].flags) ?
							"required" :  "optional");

						switch (p80211item_gettype(&msg_item[j])) {
						case P80211_TYPE_OCTETSTR:
							printf("OCTETSTR{");
							printf("minlen=%ld, ", msg_item[j].minlen);
							printf("maxlen=%ld}", msg_item[j].maxlen);
							break;
						case P80211_TYPE_DISPLAYSTR:
							printf("DISPLAYSTR{");
							printf("minlen=%ld, ", msg_item[j].minlen);
							printf("maxlen=%ld}", msg_item[j].maxlen);
							break;
						case P80211_TYPE_INT:
							if (msg_item[j].min || msg_item[j].max) {
								printf("INT{min=%ld, max=%ld}", 	
								       msg_item[j].min,
								       msg_item[j].max);	
							} else {
								printf("INT{}");
							}
							break;
						case P80211_TYPE_ENUMINT:
							printf("ENUMINT{");
							enump = msg_item[j].enumptr;
							for ( k = 0; k < enump->nitems; k++){
								printf("%s", enump->list[k].name);
								if ( k < enump->nitems - 1) {
									printf("|");
								}
							}
							printf("}");
							break;
						case P80211_TYPE_BITARRAY:
							printf("BITARRAY{");
							printf("min=%ld, max=%ld}", msg_item[j].min, msg_item[j].max);
							break;
						case P80211_TYPE_INTARRAY:
							printf("INTARRAY{");
							printf("maxlen=%ld}", msg_item[j].maxlen);
							break;
						case P80211_TYPE_MACARRAY:
							printf("MACARRAY{");
							printf("maxlen=%ld}", msg_item[j].maxlen);
							break;
						case P80211_TYPE_UNKDATA:
							printf("UNKDATA{");
							printf("maxlen=%ld}", msg_item[j].maxlen);
							break;
						default:
							printf("ERROR: unknown type!\n");
							break;
						}
						printf("\n");
					}
				}
			}
			else {
				printf("help.c: invalid group did\n");
			}
		}
	}
}


/*----------------------------------------------------------------
* print_allmibs
*
* Traverse all of the mib items in the mib metadata.  Print the
* name of the group, the name of each mib item and any 
* validation requirements.
*
* Arguments:
*	none
*
* Returns: 
*	nothing
----------------------------------------------------------------*/
void print_allmibs(void)
{
	int		i;
	int		j;
	int		k;
	UINT32		did;
	p80211meta_t	*mib_item;
	grplistitem_t	*grp;
	int		mib_cat;
	int		ncats;
	int		ncmds;
	int		nitems;
	p80211enum_t	*enump;

	ncats = GETMETASIZE(mib_catlist);

	for (mib_cat = 1; mib_cat < ncats; mib_cat++ ) {

		ncmds = GETMETASIZE(mib_catlist[mib_cat].grplist);

		for (i = 1; i < ncmds; i++ ) {
			did = P80211DID_MKSECTION(mib_cat) | P80211DID_MKGROUP(i);
			if ( (grp = p80211_did2grp(mib_catlist, did)) != NULL ) {

				printf("Mib Group: %s\n", grp->name);
				mib_item = grp->itemlist;
				nitems = GETMETASIZE(mib_item);

				for ( j = 1; j < nitems; j++) {
					char access_type[8];

					switch (P80211DID_ACCESS(mib_item[j].did)) {
					case P80211DID_WRITEONLY:
						strcpy(access_type,"-w" );
						break;
					case P80211DID_READONLY:
						strcpy(access_type,"r-" );
						break;
					case P80211DID_READWRITE:
						strcpy(access_type,"rw" );
						break;
					default:
						strcpy(access_type,"--" );
						break;
					}

					printf( "    %s(%s):",
					mib_item[j].name, access_type);

					switch (p80211item_gettype(&mib_item[j])) {
					case P80211_TYPE_OCTETSTR:
						printf("OCTETSTR{");
						printf("minlen=%ld, ", mib_item[j].minlen);
						printf("maxlen=%ld}", mib_item[j].maxlen);
						break;
					case P80211_TYPE_DISPLAYSTR:
						printf("DISPLAYSTR{");
						printf("minlen=%ld, ", mib_item[j].minlen);
						printf("maxlen=%ld}", mib_item[j].maxlen);
						break;
					case P80211_TYPE_INT:
						if (mib_item[j].min || mib_item[j].max) {
							printf("INT{min=%ld, max=%ld}", 	
							       mib_item[j].min,
							       mib_item[j].max);	
						} else {
							printf("INT{}");
						}
						break;
					case P80211_TYPE_ENUMINT:
						printf("ENUMINT{");
						enump = mib_item[j].enumptr;
						for ( k = 0; k < enump->nitems; k++){
							printf("%s", enump->list[k].name);
							if ( k < enump->nitems - 1) {
								printf("|");
							}
						}
						printf("}");
						break;
					case P80211_TYPE_BITARRAY:
						printf("BITARRAY{");
						printf("min=%ld, max=%ld}", mib_item[j].min, mib_item[j].max);
						break;
					case P80211_TYPE_INTARRAY:
						printf("INTARRAY{");
						printf("maxlen=%ld}", mib_item[j].maxlen);
						break;
					case P80211_TYPE_MACARRAY:
						printf("MACARRAY{");
						printf("maxlen=%ld}", mib_item[j].maxlen);
						break;
					case P80211_TYPE_UNKDATA:
						printf("UNKDATA{");
						printf("maxlen=%ld}", mib_item[j].maxlen);
						break;
					default:
						printf("ERROR: unknown type!\n");
						break;
					}
					printf("\n");
				}
			}
			else {
				printf("help.c: invalid group did\n");
			}
		}
	}
}
