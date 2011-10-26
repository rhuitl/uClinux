/* src/prism2/ridlist/mkmiblist.c
*
* Generates a variation of the PRISM2 to MibItem Name Mapping List
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

#define	BUFF_LEN	(256)

int main(int argc, char **argv)
{
	FILE	*data_fptr;
	FILE	*txt_fptr;
	char	buff[BUFF_LEN + 2];
	char	ifname[BUFF_LEN + 2];
	char	ofname1[BUFF_LEN + 2];
	char	*cptr;
	char	*nptr;

	if ( argc < 3 ) {
		fprintf(stderr, "usage:\n");
		fprintf(stderr, "    mkridlist <ifilename> < ofilename\n");
		fprintf(stderr, "       ifilename - name of input file with extension\n");
		fprintf(stderr, "       ofilename - name of output file w/o extension\n");
		exit(0);
	}

	sprintf( ifname, "%s", argv[1] );
	sprintf( ofname1, "%s.txt", argv[2] );

	if ( (data_fptr = fopen(ifname, "r")) == NULL ) {
		fprintf(stderr, "Failed to open ridlist.dat\n");
		exit(0);
	}

	if ( (txt_fptr = fopen(ofname1, "w")) == NULL ) {
		fprintf(stderr, "Failed to open %s\n", ofname1);
		fclose(data_fptr);
		exit(0);
	}


	/* write text file column headings */
	fprintf(txt_fptr, "src/prism2/ridlist/%s\n", ofname1);
	fprintf(txt_fptr, " Copyright (C) 2000 AbsoluteValue Software, Inc."
		" All Rights Reserved.\n\n");
	fprintf(txt_fptr,	"======"
				"==="
				"===================="
				"==="
				"=====================================\n");
	fprintf(txt_fptr, "%-6.6s | %-20.20s | %s\n",
		"PRISM2", "PRISM2", " " );
	fprintf(txt_fptr, "%-6.6s | %-20.20s | %s\n",
		"RID", "RID", " ");
	fprintf(txt_fptr, "%-6.6s | %-20.20s | %s\n",
		"VALUE", "NAME", "MibItem NAME");
	fprintf(txt_fptr,	"======"
				"==="
				"===================="
				"==="
				"=====================================\n");

/* read the data file and produce HTML and text output */
	while ( fgets( buff, BUFF_LEN + 1, data_fptr) != NULL ) {
		if ( buff[strlen(buff) - 1] == '\n' ) {
			buff[strlen(buff) - 1] = '\0';
		}
		cptr = buff;
		
		/* get and print RID value */
		nptr = strchr( cptr, ':' );
		*nptr = '\0';
		fprintf(txt_fptr, "%-6.6s | ", cptr);
		cptr = nptr + 1;

		/* get and print RID name */
		nptr = strchr( cptr, ':' );
		*nptr = '\0';
		fprintf(txt_fptr, "%-20.20s | ", cptr);
		cptr = nptr + 1;

		/* get and print MibItem Name */
		fprintf(txt_fptr, "%-37.37s\n", cptr);

		fprintf(txt_fptr,	"------"
			"---"
			"--------------------"
			"---"
			"-------------------------------------\n");
	}

	fclose(txt_fptr);
	fclose(data_fptr);

	return 0;
}
