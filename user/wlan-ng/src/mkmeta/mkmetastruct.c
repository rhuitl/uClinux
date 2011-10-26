/* src/mkmeta/mkmetastruct.c
*
* Generates the message structures and typedefs
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wlan/wlan_compat.h>
#include <wlan/p80211types.h>
#include <wlan/p80211meta.h>
#include <wlan/p80211metamsg.h>
#include <wlan/p80211metamib.h>

int main(int argc, char **argv)
{
    int     c, g, i, totgrps, totitems, type;
    char    name[82];

    int pad_id = 0;

/* traverse the message metadata to build the structures and typedefs */
    for ( c = 1; c < msg_catlist_size; c++ )
    {
        totgrps = GETMETASIZE(msg_catlist[c].grplist);
        for ( g = 1; g < totgrps; g++ )
        {
	    strcpy(name, "p80211msg");
            printf("typedef struct %s_%s\n{\n", name,
                msg_catlist[c].grplist[g].name);
            printf("\tUINT32\t\tmsgcode\t__WLAN_ATTRIB_PACK__;\n");
            printf("\tUINT32\t\tmsglen\t__WLAN_ATTRIB_PACK__;\n");
            printf("\tUINT8\t\tdevname[WLAN_DEVNAMELEN_MAX]\t__WLAN_ATTRIB_PACK__;\n");
            totitems = GETMETASIZE(msg_catlist[c].grplist[g].itemlist);
            for ( i = 1; i < totitems; i++ )
            {
                type = p80211item_gettype(&msg_catlist[c].grplist[g].itemlist[i]);
		switch ( type )
		{
                    case P80211_TYPE_INT:
                    case P80211_TYPE_ENUMINT:
                    case P80211_TYPE_BITARRAY:
			    /* already aligned */
                         printf("\tp80211item_uint32_t");
                         printf("\t%s\t__WLAN_ATTRIB_PACK__;\n",
                             msg_catlist[c].grplist[g].itemlist[i].name);
	                break;
		    case P80211_TYPE_UNKDATA:
			    /* already aligned */
		        printf("\tp80211item_unk%ld_t",
                            msg_catlist[c].grplist[g].itemlist[i].maxlen);
                        printf("\t%s\t__WLAN_ATTRIB_PACK__;\n",
                            msg_catlist[c].grplist[g].itemlist[i].name);
			break;
		    case P80211_TYPE_INTARRAY:
			    /* already aligned */
		        printf("\tstruct {\n");
		        printf("\t\tUINT32\tdid\t__WLAN_ATTRIB_PACK__;\n");
		        printf("\t\tUINT16\tstatus\t__WLAN_ATTRIB_PACK__;\n");
		        printf("\t\tUINT16\tlen\t__WLAN_ATTRIB_PACK__;\n");
                        printf("\t\tUINT32\tdata[%ld]\t__WLAN_ATTRIB_PACK__;\n",
                            msg_catlist[c].grplist[g].itemlist[i].maxlen);
		        printf("\t\t} %s\t__WLAN_ATTRIB_PACK__;\n",
                            msg_catlist[c].grplist[g].itemlist[i].name);
			break;
		    case P80211_TYPE_MACARRAY:
			    /* May not be aligned, thanks to variable-length array. */
		        printf("\tstruct {\n");
		        printf("\t\tUINT32\tdid\t__WLAN_ATTRIB_PACK__;\n");
		        printf("\t\tUINT16\tstatus\t__WLAN_ATTRIB_PACK__;\n");
		        printf("\t\tUINT16\tlen\t__WLAN_ATTRIB_PACK__;\n");
		        printf("\t\tUINT32\tcnt\t__WLAN_ATTRIB_PACK__;\n");
                        printf("\t\tUINT8\tdata[%ld][WLAN_ADDR_LEN]\t__WLAN_ATTRIB_PACK__;\n",
                            msg_catlist[c].grplist[g].itemlist[i].maxlen);

			if (msg_catlist[c].grplist[g].itemlist[i].maxlen % 4)
				printf("\t\tUINT8\tpad_%dB[%ld]\t__WLAN_ATTRIB_PACK__;\n",
				       pad_id++,
				       (4 - ((msg_catlist[c].grplist[g].itemlist[i].maxlen * 6) % 4))); 
			
		        printf("\t\t} %s\t__WLAN_ATTRIB_PACK__;\n",
                            msg_catlist[c].grplist[g].itemlist[i].name);
			break;
	            case P80211_TYPE_OCTETSTR:
			    /* May not be aligned.  it's a string. */
                         printf("\tp80211item_pstr%ld_t",
                            msg_catlist[c].grplist[g].itemlist[i].maxlen);
                         printf("\t%s\t__WLAN_ATTRIB_PACK__;\n",
                             msg_catlist[c].grplist[g].itemlist[i].name);

			 if ((msg_catlist[c].grplist[g].itemlist[i].maxlen + 1) % 4)
				 printf("\tUINT8\tpad_%dC[%ld]\t__WLAN_ATTRIB_PACK__;\n",
					pad_id++,
					(4 - ((msg_catlist[c].grplist[g].itemlist[i].maxlen + 1) % 4))); 

	                break;
	            default:
			    /* May not be aligned.  it's a string. */
                         printf("\tp80211item_pstr%ld_t",
                            msg_catlist[c].grplist[g].itemlist[i].maxlen);
                         printf("\t%s\t__WLAN_ATTRIB_PACK__;\n",
                             msg_catlist[c].grplist[g].itemlist[i].name);

			 if ((msg_catlist[c].grplist[g].itemlist[i].maxlen + 1) % 4)
				 printf("\tUINT8\tpad_%dD[%ld]\t__WLAN_ATTRIB_PACK__;\n",
					pad_id++,
					(4 - ((msg_catlist[c].grplist[g].itemlist[i].maxlen + 1) % 4))); 
	                break;
		}
            }
            printf("} __WLAN_ATTRIB_PACK__ %s_%s_t;\n\n", 
	    	name,
                msg_catlist[c].grplist[g].name);
        }
    }

    return 0;
}
