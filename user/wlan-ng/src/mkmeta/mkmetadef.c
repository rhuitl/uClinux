/* src/mkmeta/mkmetadef.c
*
* Generates #defines for all msg and mib DIDs
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
* The purpose of this program is to generate a header file containing
* all the defines for all message and mib metadata category names,
* group names and data item names.
*/

#include <stdlib.h>
#include <stdio.h>
#include <wlan/wlan_compat.h>
#include <wlan/p80211types.h>
#include <wlan/p80211meta.h>
#include <wlan/p80211metamsg.h>
#include <wlan/p80211metamib.h>

int main(int argc, char **argv)
{
    int     c, g, i, totgrps, totitems;

/* Metadata for the Message Category List */
    for ( c = 1; c < msg_catlist_size; c++ )
    {
        printf("#define DIDmsg_cat_%s \\\n", msg_catlist[c].name);
        printf("\t\t\tP80211DID_MKSECTION(%d)\n", c);
        totgrps = GETMETASIZE(msg_catlist[c].grplist);
        for ( g = 1; g < totgrps; g++ )
        {
            printf("#define DIDmsg_%s \\\n", 
	    	msg_catlist[c].grplist[g].name);
            printf("\t\t\t(P80211DID_MKSECTION(%d) | \\\n", c);
            printf("\t\t\tP80211DID_MKGROUP(%d))\n", g);
            totitems = GETMETASIZE(msg_catlist[c].grplist[g].itemlist);
            for ( i = 1; i < totitems; i++ )
            {
                printf("#define DIDmsg_%s_%s \\\n", 
			msg_catlist[c].grplist[g].name,
                	msg_catlist[c].grplist[g].itemlist[i].name);
                printf("\t\t\t(P80211DID_MKSECTION(%d) | \\\n", c);
                printf("\t\t\tP80211DID_MKGROUP(%d) | \\\n", g);
                printf("\t\t\tP80211DID_MKITEM(%d) | ", i);
                printf("0x%08x)\n",(unsigned int)
			msg_catlist[c].grplist[g].itemlist[i].did);
            }
        }
    }

/* Metadata for the Mib Category List */
    for ( c = 1; c < mib_catlist_size; c++ )
    {
        printf("#define DIDmib_cat_%s \\\n", mib_catlist[c].name);
        printf("\t\t\tP80211DID_MKSECTION(%d)\n", c);
        totgrps = GETMETASIZE(mib_catlist[c].grplist);
        for ( g = 1; g < totgrps; g++ )
        {
            printf("#define DIDmib_%s_%s \\\n", 
		mib_catlist[c].name, mib_catlist[c].grplist[g].name);
            printf("\t\t\t(P80211DID_MKSECTION(%d) | \\\n", c);
            printf("\t\t\tP80211DID_MKGROUP(%d))\n", g);
            totitems = GETMETASIZE(mib_catlist[c].grplist[g].itemlist);
            for ( i = 1; i < totitems; i++ )
            {
                printf("#define DIDmib_%s_%s_%s \\\n",
                	mib_catlist[c].name,
                	mib_catlist[c].grplist[g].name,
                	mib_catlist[c].grplist[g].itemlist[i].name);
                printf("\t\t\t(P80211DID_MKSECTION(%d) | \\\n", c);
                printf("\t\t\tP80211DID_MKGROUP(%d) | \\\n", g);
                printf("\t\t\tP80211DID_MKITEM(%d) | ", i);
                printf("0x%08x)\n", (unsigned int)
			mib_catlist[c].grplist[g].itemlist[i].did);
            }
        }
    }

    return 0;
}

