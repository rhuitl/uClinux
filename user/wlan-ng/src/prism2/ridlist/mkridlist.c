/* src/prism2/ridlits/mkridlist.c
*
* Generates an HTML and text file version of the PRISM2 to MibItem
* Name Mapping List
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
	FILE	*html_fptr;
	FILE	*txt_fptr;
	char	buff[BUFF_LEN + 2];
	char	ifname[BUFF_LEN + 2];
	char	ofname1[BUFF_LEN + 2];
	char	ofname2[BUFF_LEN + 2];
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
	sprintf( ofname1, "%s.html", argv[2] );
	sprintf( ofname2, "%s.txt", argv[2] );

	if ( (data_fptr = fopen(ifname, "r")) == NULL ) {
		fprintf(stderr, "Failed to open ridlist.dat\n");
		exit(0);
	}

	if ( (html_fptr = fopen(ofname1, "w")) == NULL ) {
		fprintf(stderr, "Failed to open %s\n", ofname1);
		fclose(data_fptr);
		exit(0);
	}

	if ( (txt_fptr = fopen(ofname2, "w")) == NULL ) {
		fprintf(stderr, "Failed to open %s\n", ofname2);
		fclose(html_fptr);
		fclose(data_fptr);
		exit(0);
	}

	/* write HTML tags */
	fprintf(html_fptr, "<HTML>\n");
	fprintf(html_fptr, "<HEAD>\n");
	fprintf(html_fptr, "\t<TITLE>802.11 to PRISM2 RID Mapping List</TITLE>\n");
	fprintf(html_fptr, "</HEAD>\n");
	fprintf(html_fptr, "<BODY>\n");
	fprintf(html_fptr, "<P>\n");
	fprintf(html_fptr, "<B>doc/prism2/%s<BR>Copyright"
		" (C) 2000 AbsoluteValue Software, Inc."
		" All Rights Reserved.</B>\n", ofname1);
	fprintf(html_fptr, "</P>\n");
	fprintf(html_fptr, "<P>\n");
	fprintf(html_fptr, "<BR>API - The document source for this RID is the API Enhancements Document\n");
	fprintf(html_fptr, "</P>\n");
	fprintf(html_fptr, "<P>\n");
	fprintf(html_fptr, "<BR>PRO - The document source for this RID is the CW10 Programmer's Manual\n");
	fprintf(html_fptr, "</P>\n");
	fprintf(html_fptr, "<P>\n");
	fprintf(html_fptr, "<BR>[1] - read mode is implemented internally within the driver\n");
	fprintf(html_fptr, "</P>\n");
	fprintf(html_fptr, "<P>\n");
	fprintf(html_fptr, "<BR>[2] - This RID is implemented internally in the driver"
		" during implementation of the Group Addresses RID (0xFC80)\n");
	fprintf(html_fptr, "</P>\n");
	fprintf(html_fptr, "<P>\n");
	fprintf(html_fptr, "<BR>[3] - This RID is implemented internally in the driver\n");
	fprintf(html_fptr, "</P>\n");
	fprintf(html_fptr, "<P>\n");
	fprintf(html_fptr, "<BR>\n");
	fprintf(html_fptr, "</P>\n");
	fprintf(html_fptr, "<P>\n");
	fprintf(html_fptr, "<CENTER>\n");
	fprintf(html_fptr, "<TABLE border=1>\n");
	fprintf(html_fptr, "\t<TR>\n");
	fprintf(html_fptr, "\t\t<TD valign=bottom><B>PRISM2<BR>RID<BR>VALUE</B>\n");
	fprintf(html_fptr, "\t\t<TD valign=bottom><B>PRISM2<BR>RID<BR>NAME</B>\n");
	fprintf(html_fptr, "\t\t<TD valign=bottom><B>STA</B>\n");
	fprintf(html_fptr, "\t\t<TD valign=bottom><B>AP</B>\n");
	fprintf(html_fptr, "\t\t<TD valign=bottom><B>802.11 MibItem Name</B>\n");
	fprintf(html_fptr, "\t\t<TD valign=bottom><B>Doc<BR>Src</B>\n");
	fprintf(html_fptr, "\t\t<TD valign=bottom><B>Implemented?</B>\n");

	/* write text file column headings */
	fprintf(txt_fptr, "doc/prism2/%s\n", ofname2);
	fprintf(txt_fptr, " Copyright (C) 2000 AbsoluteValue Software, Inc."
		" All Rights Reserved.\n\n\n");
	fprintf(txt_fptr, "\nAPI - The document source for this RID is the API Enhancements Document\n");
	fprintf(txt_fptr, "\nPRO - The document source for this RID is the CW10 Programmer's Manual\n");
	fprintf(txt_fptr, "\n[1] - read mode is implemented internally within the driver\n");
	fprintf(txt_fptr, "\n[2] - This RID is implemented internally in the driver"
		" during implementation of the Group Addresses RID (0xFC80)\n");
	fprintf(txt_fptr, "\n[3] - This RID is implemented internally in the driver\n");
	fprintf(txt_fptr, "\n");
	fprintf(txt_fptr,	"======"
				"==="
				"===================="
				"==="
				"==="
				"==="
				"==="
				"==="
				"====================================="
				"==="
				"==="
				"==="
				"=============\n");
	fprintf(txt_fptr, "%-6.6s | %-20.20s | %-3.3s | %-3.3s | %-37.37s | %-3.3s | %s\n",
		"PRISM2", "PRISM2", " ", " ", " ", " ", " ");
	fprintf(txt_fptr, "%-6.6s | %-20.20s | %-3.3s | %-3.3s | %-37.37s | %-3.3s | %s\n",
		"RID", "RID", " ", " ", " ", "Doc", " ");
	fprintf(txt_fptr, "%-6.6s | %-20.20s | %-3.3s | %-3.3s | %-37.37s | %-3.3s | %s\n",
		"VALUE", "NAME", "STA", "AP", "MibItem NAME", "Src", "Implemented?");
	fprintf(txt_fptr,	"======"
				"==="
				"===================="
				"==="
				"==="
				"==="
				"==="
				"==="
				"====================================="
				"==="
				"==="
				"==="
				"=============\n");

/* read the data file and produce HTML and text output */
	while ( fgets( buff, BUFF_LEN + 1, data_fptr) != NULL ) {
		cptr = buff;
		fprintf(html_fptr, "\t<TR>\n");
		/* get and print RID value */
		nptr = strchr( cptr, ':' );
		*nptr = '\0';
		fprintf(txt_fptr, "%-6.6s | ", cptr);
		if ( strlen( cptr) != 0 ) {
			fprintf(html_fptr, "\t\t<TD valign=bottom>%s\n", cptr);
		} else {
			fprintf(html_fptr, "\t\t<TD valign=bottom><PRE>   </PRE>\n");
		}
		cptr = nptr + 1;
		/* get and print RID name */
		nptr = strchr( cptr, ':' );
		*nptr = '\0';
		fprintf(txt_fptr, "%-20.20s | ", cptr);
		if ( strlen( cptr) != 0 ) {
			fprintf(html_fptr, "\t\t<TD valign=bottom>%s\n", cptr);
		} else {
			fprintf(html_fptr, "\t\t<TD valign=bottom><PRE>   </PRE>\n");
		}
		cptr = nptr + 1;
		/* get and print STA */
		nptr = strchr( cptr, ':' );
		*nptr = '\0';
		fprintf(txt_fptr, "%-3.3s | ", cptr);
		if ( strlen( cptr) != 0 ) {
			fprintf(html_fptr, "\t\t<TD valign=bottom>%s\n", cptr);
		} else {
			fprintf(html_fptr, "\t\t<TD valign=bottom><PRE>   </PRE>\n");
		}
		cptr = nptr + 1;
		/* get and print AP */
		nptr = strchr( cptr, ':' );
		*nptr = '\0';
		fprintf(txt_fptr, "%-3.3s | ", cptr);
		if ( strlen( cptr) != 0 ) {
			fprintf(html_fptr, "\t\t<TD valign=bottom>%s\n", cptr);
		} else {
			fprintf(html_fptr, "\t\t<TD valign=bottom><PRE>   </PRE>\n");
		}
		cptr = nptr + 1;
		/* get and print MibItem Name */
		nptr = strchr( cptr, ':' );
		*nptr = '\0';
		fprintf(txt_fptr, "%-37.37s | ", cptr);
		if ( strlen( cptr) != 0 ) {
			fprintf(html_fptr, "\t\t<TD valign=bottom>%s\n", cptr);
		} else {
			fprintf(html_fptr, "\t\t<TD valign=bottom><PRE>   </PRE>\n");
		}
		cptr = nptr + 1;
		/* get and print Document Source */
		nptr = strchr( cptr, ':' );
		*nptr = '\0';
		fprintf(txt_fptr, "%-3.3s | ", cptr);
		if ( strlen( cptr) != 0 ) {
			fprintf(html_fptr, "\t\t<TD valign=bottom>%s\n", cptr);
		} else {
			fprintf(html_fptr, "\t\t<TD valign=bottom><PRE>   </PRE>\n");
		}
		cptr = nptr + 1;
		/* get and print Implemented */
		nptr = strchr( cptr, ':' );
		*nptr = '\0';
		fprintf(txt_fptr, "%s\n", cptr);
		fprintf(txt_fptr,	"------"
					"---"
					"--------------------"
					"---"
					"---"
					"---"
					"---"
					"---"
					"-------------------------------------"
					"---"
					"---"
					"---"
					"-------------\n");
		if ( strlen( cptr) != 0 ) {
			fprintf(html_fptr, "\t\t<TD valign=bottom>%s\n", cptr);
		} else {
			fprintf(html_fptr, "\t\t<TD valign=bottom><PRE>   </PRE>\n");
		}
	}

	fprintf(html_fptr, "</TABLE>\n");
	fprintf(html_fptr, "</CENTER>\n");
	fprintf(html_fptr, "</BODY>\n");
	fprintf(html_fptr, "</HTML>\n");

	fclose(txt_fptr);
	fclose(data_fptr);
	fclose(html_fptr);

	return 0;
}
