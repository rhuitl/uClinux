/* src/nwepgen/nwepgen.c
*
* Management request handler functions.
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
* This program generates a set of WEP keys in a manner that is compatible
* with the windows based config utility developed by Neesus Datacom.
*
* The algorithm was supplied by Neesus, but was dependent on the srand()
* and rand() functions in a binary-only driver.  Juan Arango of Zoom
* Telephonics developed the code in the nwepgen() function to match
* the behavior of that library.
*
* --------------------------------------------------------------------
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wlan/wlan_compat.h>
#include <wlan/p80211hdr.h>


void nwepgen(char *genstr, int keylen, UINT8 wep_key[WLAN_WEP_NKEYS][WLAN_WEP_MAXKEYLEN]);

int main(int argc, char *argv[])
{
	UINT8	wep_key[WLAN_WEP_NKEYS][WLAN_WEP_MAXKEYLEN];
	int	i;
	int	j;
	int	keylen;

	if ( argc < 2 || argc > 3 )
	{
		printf("nwepgen: generates Neesus Datacom compatible WEP keys from a string\n");
		printf("  Usage:  nwepgen <genstr> <length>\n");
		return 0;
	}

	keylen = (argc < 3) ? 5 : atoi(argv[2]);
	if ( keylen < 1 || keylen > WLAN_WEP_MAXKEYLEN )
	{
		printf(" Invalid key length.  Valid range is 1-%d.\n", WLAN_WEP_MAXKEYLEN);
		return 0;
	}

	nwepgen( argv[1], keylen, wep_key);

	for ( i = 0; i < WLAN_WEP_NKEYS; i++)
	{
		/* printf("%d-", i); */
		for ( j=0; j < keylen; j++)
		{
			printf((j < keylen-1) ? "%02x:" : "%02x\n", wep_key[i][j]);
		}
	}

	return 0;
}

/*----------------------------------------------------------------
* nwepgen
*
* Generates a set of WEP keys from a generator string.  This is 
* intended as a convenience.  Entering hex bytes can be a pain.
*
* Based on an algorithm supplied by Neesus Datacom, 
* http://www.neesus.com
*
* This function was authored by Zoom Telephonics Engineer 
* Juan Arango.
* http://www.zoomtel.com
*
* Juan's Note: 
* Changing the code in this function could make this product 
* incompatible with other ZoomAir wireless products because 
* these other products rely on Microsoft's rand() and srand() 
* function implementations!!!  This code uses the same algorithm.
*
* Distributed with permission from Zoom Telephonics.
*
* Arguments:
* 	genstr		a null terminated string
*	keylen		number of bytes in key
* 	wep_key		a 2d array that is filled with the wep keys
* Returns:
*	nothing
----------------------------------------------------------------*/
void 
nwepgen(char *genstr, int keylen, UINT8 wep_key[WLAN_WEP_NKEYS][WLAN_WEP_MAXKEYLEN])
{
	unsigned int i,j;
	unsigned char pseed[4]={0,0,0,0};
	unsigned int len;
	int randNumber=0;

	len = strlen(genstr);
	if (len) {
		/* generate seed for random number generator using */
		/* key string... */
		for (i=0; i<len; i++) {
			pseed[i%4]^= genstr[i];
		}

		/* init PRN generator... note that this is equivalent */
		/*  to the Microsoft srand() function. */
		randNumber =	(int)pseed[0] | 
				((int)pseed[1])<<8 | 
				((int)pseed[2])<<16 | 
				((int)pseed[3])<<24;

		/* generate keys. */
		for (i=0; i<WLAN_WEP_NKEYS; i++) {
			for (j=0; j<keylen; j++) {
				/* Note that these three lines are */
				/* equivalent to the Microsoft rand() */
				/* function. */
				randNumber *= 0x343fd;
				randNumber += 0x269ec3;
				wep_key[i][j] = (unsigned char)((randNumber>>16) & 0x7fff);
			}
		}
	}
	return;
}
