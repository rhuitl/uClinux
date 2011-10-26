/* src/shared/p80211types.c
*
* Defines globally used types in linux-wlan
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
* This file defines the data and functions for handling the linux-wlan
* globally recognized data types: OCTETSTR, DISPLAYSTR, INT, BOUNDEDINT,
* ENUMINT, INTARRAY, BITARRY, and MACARRAY.
*
* For each type there is a collection of 3 functions, totext_<type>,
* fromtext_<type>, and isvalid_<type>.  They all have identical
* signatures:
*
*  void p80211_totext_<type>( UINT32 did, UINT8 *itembuf, char *textbuf )
*  void p80211_fromtext_<type>( UINT32 did, UINT8 *itembuf, char *textbuf )
*  UINT32 p80211_isvalid_<type>( UINT32 did, UINT8 *itembuf )
*
* The idea is that these functions will be called via pointers stored
* in the metadata for each item.
* Here are some important notes for these functions:
*   - all of these functions assume:
*       - a valid complete DID as the first argument
*       - (for to/fromtext) a valid pointer to a buffer containing 
*         sufficient memory.
*   - All textual representations are "<itemname>=<itemvalue>"
*   - All itembufs are pointing to a p80211item_t
*   - isvalid functions return:
*       0         if item is invalid
*	non-zero  if item is valid
*
* NOTE: these functions assume that the argument "itembuf" is a
*       data item and whose data field is always the maximum data
*       size (i.e. a PSTR255) with the exception of a collection.
*       In the case of a collection, the itembuf argument is a
*       pointer to a collection data item where the data value field
*       is itself a list of data items.
*
*
* Additionally, there are functions for converting enumeration values
*  from text to binary and back.
* --------------------------------------------------------------------
*/

/*================================================================*/
/* System Includes */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/*================================================================*/
/* Project Includes */

#include <wlan/wlan_compat.h>
#include <wlan/p80211types.h>
#include <wlan/p80211meta.h>
#include <wlan/p80211metamib.h>
#include <wlan/p80211msg.h>

/*================================================================*/
/* Local Constants */


/*================================================================*/
/* Local Macros */


/* the following depends on the following defines:
	P80211_NOINCLUDESTRINGS - ifdef, all metadata name fields are empty strings 
*/

#define MKENUM(name)	\
p80211enum_t	MKENUMNAME(name) = \
{ \
sizeof((p80211enumpair_ ## name)) / sizeof(p80211enumpair_t), \
(p80211enumpair_ ## name) \
}

#ifdef P80211_NOINCLUDESTRINGS
#define MKENUMPAIR(n,s)	{ (n), ("") }
#else
#define MKENUMPAIR(n,s)	{ (n), (s) }
#endif

#define MKENUMPAIRLIST(name) p80211enumpair_t p80211enumpair_ ## name [] =


/*================================================================*/
/* Local Types */


/*================================================================*/
/* Local Static Definitions */


/* too much data in this file, we moved to the bottom for readability */


/*================================================================*/
/* Local Function Declarations */


/*================================================================*/
/* Function Definitions */


/*----------------------------------------------------------------
* p80211enum_text2int
*
* Returns the numeric value of an enum item given its textual
* name and a ptr to the enum struct.
*
* Arguments:
*	ep	ptr to enum metadata
*	text	textual enum item name
*
* Returns: 
*	P80211_ENUMBAD		no match on name
*	!P80211_ENUMBAD		success, return value is enum value
----------------------------------------------------------------*/
UINT32 p80211enum_text2int(p80211enum_t *ep, char *text)
{
	UINT32	result = P80211ENUM_BAD;
	int		i;

	for ( i = 0; i < ep->nitems; i++ ) {
		if ( strcmp(text, ep->list[i].name ) == 0 ) {
			result = ep->list[i].val;
			break;
		}
	}
	return result;
}


/*----------------------------------------------------------------
* p80211enum_int2text
*
* Fills a buffer with the name string for a given integer 
* quantity and a ptr to the enum struct.
*
* Arguments:
*	ep	ptr to enum metadata
*	val	integer value to convert
*	text	(out)buffer to write enum name to
*
* Returns: 
*	P80211_ENUMBAD		no match on number
*	!P80211_ENUMBAD		success
*
* Side effects:
*	Argument 'text' is filled with the textual name of the
*	enum value.  If the lookup fails, 'text' is set to the
*	string P80211ENUM_BADSTR
----------------------------------------------------------------*/
UINT32 p80211enum_int2text(p80211enum_t *ep, UINT32 val, char *text)
{
	UINT32	result = P80211ENUM_BAD;
	int	i;

	strcpy(text, P80211ENUM_BADSTR);

	for ( i = 0; i < ep->nitems;  i++) {
		if ( ep->list[i].val == val ) {
			strcpy( text, ep->list[i].name );
			result = val;
			break;
		}
	}
	return result;
}


/*----------------------------------------------------------------
* p80211_totext_displaystr
*
* pstr ==> cstr 
*
* Converts a pascal string to a C string appropriate for display.
* The C string format  is always  "<item name>=<item value>".
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		item triple {DID, len, value}.
*	textbuf		(out) character buffer to receive textual
*			representation.
*
* Returns: 
*	nothing
*
* Side effects:
*	Writes the converted value to the buffer pointed at by
*	textbuf.
----------------------------------------------------------------*/
void p80211_totext_displaystr( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf, char *textbuf )
{
	p80211meta_t	*meta = NULL;
	p80211itemd_t	*item = (p80211itemd_t*)itembuf;
	p80211pstrd_t	*pstr;

	*textbuf = '\0';

	if ( (meta = p80211_did2item(metalist, did)) != NULL ) {
		/* collect the C string stored in the data item */
		if ( item->status == P80211ENUM_msgitem_status_data_ok ) {
			pstr = (p80211pstrd_t*)item->data;

			if ( item->did != 0UL ) {
				sprintf( textbuf, "%s=\'", meta->name);
				strncat( textbuf, pstr->data, pstr->len);
				strncat( textbuf, "\'", 1);
			} else {
				sprintf( textbuf, "%s=\'%s\'", meta->name,
					NOT_SUPPORTED);
			}
		} else {
			char		error_msg[MSG_BUFF_LEN];

			p80211_error2text( item->status, error_msg);
			sprintf( textbuf, "%s=\'%s\'", meta->name,
				error_msg);
		}
	} else {
		char		error_msg[MSG_BUFF_LEN];

		p80211_error2text( P80211ENUM_msgitem_status_invalid_msg_did,
			error_msg);
		sprintf( textbuf, "0x%08lx=\"%s\"", did,
			error_msg);
	}

	return;
}


/*----------------------------------------------------------------
* p80211_fromtext_displaystr
*
* cstr ==> pstr
*
* Converts a C string containing the "<item name>=<item value>" format
* to a wlan data item triple.
*
* The C string format  is always  "<item name>=<item value>".
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		(out>item triple {DID, len, value}.
*	textbuf		character buffer to receive textual
*			representation.
*
* Returns: 
*	nothing
*
* Side effects:
*	Writes the converted value to the buffer pointed at by
*	itembuf.
----------------------------------------------------------------*/
void p80211_fromtext_displaystr( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf, char *textbuf )
{
	p80211meta_t	*meta = NULL;
	p80211itemd_t	*item = (p80211itemd_t*)itembuf;
	p80211pstrd_t	*pstr;
	int		len;

	/* set up the pascal string pointer, i.e. the display str data item */
	pstr = (p80211pstrd_t*)item->data;

	/* collect the metadata item */
	if ( (meta = p80211_did2item(metalist, did)) != NULL ) {

		/* set the DID and OR in the partial DID for safety */
		item->did = did | meta->did;

		/* adding 1 to the metadata maxlen takes into account
		the first byte of the pascal string containing the
		actual number of data bytes.  NOTE: the '\0' of a display
		string is included in the metadata maxlen */

		item->len = p80211item_maxdatalen(metalist, item->did);

		/* skip past the item name to its value before converting */
		textbuf = strchr(textbuf, '=');

		if ( textbuf != NULL ) {
			/* OK, got the '=', bump to the next */
			textbuf++;
			len = strlen(textbuf);
			if ( len > meta->maxlen ) {
				item->status =
					P80211ENUM_msgitem_status_string_too_long;
			} else if ( len < meta->minlen ) {
				item->status =
					P80211ENUM_msgitem_status_string_too_short;
			} else {
				pstr->len = len;
				strncpy( pstr->data, textbuf, len);
				item->status =
					P80211ENUM_msgitem_status_data_ok;
			}
		} else {
		/* bogus text string, set the item to an empty string */
			pstr->len = 0;
			item->status = P80211ENUM_msgitem_status_missing_itemdata;
		}
	} else {
		pstr->len = 0;
		pstr->data[0] = '\0';
		item->did = did;
		item->len = pstr->len + 1;
		item->status = P80211ENUM_msgitem_status_invalid_itemname;
	}

	return;
}


/*----------------------------------------------------------------
* p80211_isvalid_displaystr
*
* Tests an item triple for valid range.  Uses the validation
* information in the metadata.  Displaystr's are validated for
* length.
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		item triple {DID, len, value}.
*
* Returns: 
*	0	- data in itembuf is invalid
*	~0	- data in itembuf is valid
----------------------------------------------------------------*/
UINT32 p80211_isvalid_displaystr( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf )
{
	UINT32		result = 0;
	p80211meta_t	*meta;
	p80211itemd_t	*item = (p80211itemd_t*)itembuf;
	p80211pstrd_t	*pstr;

	if ( (item->status) == P80211ENUM_msgitem_status_data_ok ) {
		if ( (meta = p80211_did2item(metalist, did)) != NULL ) {
			/* set up the pointers */
			pstr = (p80211pstrd_t*)item->data;

			if ( pstr->len < meta->minlen ) {
				item->status =
					P80211ENUM_msgitem_status_string_too_short;
			} else if ( pstr->len > meta->maxlen ) {
				item->status =
					P80211ENUM_msgitem_status_string_too_long;
			} else {
				result =1;
			}
		} else {
			item->status = P80211ENUM_msgitem_status_invalid_did;
		}
	}

	return result;
}


/*----------------------------------------------------------------
* p80211_totext_octetstr
*
* pstr ==> "xx:xx:..."
*
* Converts a pascal string to a hex represenation of its contents.
* The C string format is always  "<item name>=<item value>".
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		item triple {DID, len, value}.
*	textbuf		(out) character buffer to receive textual
*			representation.
*
* Returns: 
*	nothing
*
* Side effects:
*	Writes the converted value to the buffer pointed at by
*	textbuf.
----------------------------------------------------------------*/
void p80211_totext_octetstr( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf, char *textbuf )
{
	p80211meta_t	*meta = NULL;
	p80211itemd_t	*item = (p80211itemd_t*)itembuf;
	p80211pstrd_t	*pstr;
	UINT8		*cstr;
	INT		len;
	INT		n;

	*textbuf = '\0';

	/* collect the metadata item */
	if ( (meta = p80211_did2item(metalist, did)) != NULL ) {
		if ( item->status == P80211ENUM_msgitem_status_data_ok ) {
			/* collect the C string stored in the data item */
			pstr = (p80211pstrd_t*)item->data;

			if ( item->did != 0UL ) {
				len = pstr->len;
				cstr = pstr->data;

				sprintf( textbuf, "%s=", meta->name);

				for ( n=0; n < len; n++ ) {
					sprintf( &textbuf[strlen(textbuf)],
						"%02x:", (UINT)(cstr[n]) );
				}

				/* get rid of trailing colon */
				textbuf[strlen(textbuf) - 1] = '\0';
			} else {
				sprintf( textbuf, "%s=%s", meta->name,
					NOT_SUPPORTED);
			}
		} else {
			char		error_msg[MSG_BUFF_LEN];

			p80211_error2text( item->status, error_msg);
			sprintf( textbuf, "%s=\"%s\"", meta->name,
				error_msg);
		}
	} else {
		char		error_msg[MSG_BUFF_LEN];

		p80211_error2text( P80211ENUM_msgitem_status_invalid_msg_did,
			error_msg);
		sprintf( textbuf, "0x%08lx=\"%s\"", did,
			error_msg);
	}

	return;
}


/*----------------------------------------------------------------
* p80211_fromtext_octetstr
*
* "xx:xx:...." ==> pstr
*
* Converts a C string containing the "<item name>=<item value>" format
* to a wlan data item triple.
*
* The C string format  is always  "<item name>=<item value>".
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		(out>item triple {DID, len, value}.
*	textbuf		character buffer to receive textual
*			representation.
*
* Returns: 
*	nothing
*
* Side effects:
*	Writes the converted value to the buffer pointed at by
*	itembuf.
----------------------------------------------------------------*/
void p80211_fromtext_octetstr( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf, char *textbuf )
{
	p80211meta_t	*meta = NULL;
	p80211itemd_t	*item = (p80211itemd_t*)itembuf;
	p80211pstrd_t	*pstr;
	UINT		hexnum;
	INT		n;

	/* set up the pascal string pointer, i.e. the display str data item */
	pstr = (p80211pstrd_t*)item->data;

	/* collect the metadata item */
	if ( (meta = p80211_did2item(metalist, did)) != NULL ) {

		/* set the DID and OR in the partial DID for safety */
		item->did = did | meta->did;

		/* adding 1 to the metadata maxlen takes into account
		the first byte of the pascal string containing the
		actual number of data bytes.  NOTE: the '\0' of a display
		string is included in the metadata maxlen */

		item->len = p80211item_maxdatalen(metalist, item->did);

		/* skip past the item name to its value before converting */
		textbuf = strchr(textbuf, '=');

		if ( textbuf != NULL ) {
			item->status = P80211ENUM_msgitem_status_data_ok;

			for ( n=0, pstr->len = (UINT8)0; (textbuf != NULL) &&
				(item->status == P80211ENUM_msgitem_status_data_ok); n++ ) {
				/* OK, got the '=' or ':', bump to the
				next char */
				textbuf++;

				if ( pstr->len < meta->maxlen ) {
					if ( sscanf( textbuf, "%x", &hexnum)
						== 1 ) {
						pstr->data[n] = (UINT8)(hexnum);
						pstr->len =
							pstr->len + (UINT8)(1);
					} else {
					item->status = 
					P80211ENUM_msgitem_status_invalid_itemdata;
					}
				} else {
					item->status = 
					P80211ENUM_msgitem_status_string_too_long;
				}

				textbuf = strchr(textbuf, ':');
			}
			if ( pstr->len < meta->minlen )
				item->status =
					P80211ENUM_msgitem_status_string_too_short;
		} else {
		/* bogus text string, set the item to an empty string */
			pstr->len = 1;
			pstr->data[0] = '\0';
			item->status = P80211ENUM_msgitem_status_missing_itemdata;
		}
	} else {
		pstr->len = 1;
		pstr->data[0] = '\0';
		item->did = did;
		item->len = pstr->len + 1;
		item->status = P80211ENUM_msgitem_status_invalid_itemname;
	}

	return;
}


/*----------------------------------------------------------------
* p80211_isvalid_octetstr
*
* Tests an item triple for valid range.  Uses the validation
* information in the metadata. Octetstr's are validated for
* length.
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		item triple {DID, len, value}.
*
* Returns: 
*	0	- data in itembuf is invalid
*	~0	- data in itembuf is valid
----------------------------------------------------------------*/
UINT32 p80211_isvalid_octetstr( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf )
{
	UINT32		result = 0;
	p80211meta_t	*meta;
	p80211itemd_t	*item = (p80211itemd_t*)itembuf;
	p80211pstrd_t	*pstr;

	if ( item->status == P80211ENUM_msgitem_status_data_ok ) {
		/* collect the metadata item */
		if ( (meta = p80211_did2item(metalist, did)) != NULL ) {
			/* set up the pointers */
			pstr = (p80211pstrd_t*)item->data;

			/* in the case of an octet string, the total number 
			   of raw data bytes must be equal or less than maximum
			   length and equal or greater than minimum length
			   specified in the metadata */
			if ( pstr->len < meta->minlen ) {
				item->status =
					P80211ENUM_msgitem_status_string_too_short;
			} else if ( pstr->len > meta->maxlen ) {
				item->status =
					P80211ENUM_msgitem_status_string_too_long;
			} else {
				result =1;
			}
		} else { 
			item->status = P80211ENUM_msgitem_status_invalid_did;
		}
	}

	return result;
}

/*----------------------------------------------------------------
* p80211_totext_int
*
* UINT32 ==> %d
*
* Converts a UINT32 to a C string appropriate for display.
* The C string format  is always  "<item name>=<item value>".
* Note: for now, this function is identical to totext_boundedint
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		item triple {DID, len, value}.
*	textbuf		(out) character buffer to receive textual
*			representation.
*
* Returns: 
*	nothing
*
* Side effects:
*	Writes the converted value to the buffer pointed at by
*	textbuf.
----------------------------------------------------------------*/
void p80211_totext_int( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf, char *textbuf )
{
	p80211meta_t	*meta = NULL;
	p80211itemd_t	*item = (p80211itemd_t*)itembuf;

	*textbuf = '\0';

	/* collect the metadata item */
	if ( (meta = p80211_did2item(metalist, did)) != NULL ) {
		if ( item->status == P80211ENUM_msgitem_status_data_ok ) {
			if ( item->did != 0UL ) {
				/* now, print the data item name and
				value into the textbuf */
				sprintf( textbuf, "%s=%lu", meta->name,
					*((UINT32 *)(item->data)));
			} else {
				sprintf( textbuf, "%s=%s", meta->name,
					NOT_SUPPORTED);
			}
		} else {
			char		error_msg[MSG_BUFF_LEN];

			p80211_error2text( item->status, error_msg);
			sprintf( textbuf, "%s=\"%s\"", meta->name,
				error_msg);
		}
	} else {
		char		error_msg[MSG_BUFF_LEN];

		p80211_error2text( P80211ENUM_msgitem_status_invalid_msg_did,
			error_msg);
		sprintf( textbuf, "0x%08lx=\"%s\"", did,
			error_msg);
	}

	return;
}


/*----------------------------------------------------------------
* p80211_fromtext_int
*
* %d ==> UINT32
*
* Converts a C string containing the "<item name>=<item value>" format
* to a wlan data item triple.
*
* The C string format  is always  "<item name>=<item value>".
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		(out>item triple {DID, len, value}.
*	textbuf		character buffer to receive textual
*			representation.
*
* Returns: 
*	nothing
*
* Side effects:
*	Writes the converted value to the buffer pointed at by
*	itembuf.
----------------------------------------------------------------*/
void p80211_fromtext_int( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf, char *textbuf )
{
	p80211meta_t	*meta = NULL;
	p80211itemd_t	*item = (p80211itemd_t*)itembuf;

	/* collect the metadata item */
	if ( (meta = p80211_did2item(metalist, did)) != NULL ) {

		/* set the DID and OR in the partial DID for safety */
		item->did = did | meta->did;
		item->len = p80211item_maxdatalen(metalist, item->did);

		/* skip past the item name to its value before converting */
		textbuf = strchr(textbuf, '=');

		if ( textbuf != NULL ) {
			/* OK, got the '=', bump to the next */
			textbuf++;
			*((UINT32 *)(item->data)) = strtoul(textbuf, NULL, 0);
			item->status =
				P80211ENUM_msgitem_status_data_ok;
		} else	{
			/* bogus text string, set the item data value to zero */
			*((UINT32 *)(item->data)) = 0UL;
			item->status = P80211ENUM_msgitem_status_missing_itemdata;
		}
	} else {
		/* invalid did */
		item->did = did;
		item->len = sizeof(int);
		item->status = P80211ENUM_msgitem_status_invalid_itemname;
	}

	return;
}


/*----------------------------------------------------------------
* p80211_isvalid_int
*
* Tests an item triple for valid range.  Uses the validation
* information in the metadata.  All values are valid, so this 
* function always returns success.
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		item triple {DID, len, value}.
*
* Returns: 
*	0	- data in itembuf is invalid
*	~0	- data in itembuf is valid
----------------------------------------------------------------*/
UINT32 p80211_isvalid_int( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf )
{
	UINT32		result = 0;
	p80211meta_t	*meta;
	p80211itemd_t	*item = (p80211itemd_t*)itembuf;

	if ( item->status == P80211ENUM_msgitem_status_data_ok ) {
		/* collect the metadata item */
		if ( (meta = p80211_did2item(metalist, did)) != NULL ) {
			/* if either min or max is non-zero, we are bound */
			if (meta->min || meta->max) {
				if ( ((*((UINT32 *)(item->data))) >= meta->min) &&
				     ((*((UINT32 *)(item->data))) <= meta->max)) {
					result = 1;
				} else {
					item->status =
						P80211ENUM_msgitem_status_data_out_of_range;
				}      
			} else {
				result = 1;
			}
			
		} else {
			item->status = P80211ENUM_msgitem_status_invalid_did;
		}
	}

	return result;
}


/*----------------------------------------------------------------
* p80211_totext_enumint
*
* UINT32 ==> <valuename>
*
* Converts a enumerated integer item quantity to it a C string 
* appropriate for display.
* The C string format  is always  "<item name>=<item value>".
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		item triple {DID, len, value}.
*	textbuf		(out) character buffer to receive textual
*			representation.
*
* Returns: 
*	nothing
*
* Side effects:
*	Writes the converted value to the buffer pointed at by
*	textbuf.
----------------------------------------------------------------*/
void p80211_totext_enumint( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf, char *textbuf )
{
	p80211meta_t		*meta = NULL;
	p80211itemd_t		*item = (p80211itemd_t*)itembuf;
	p80211enumpair_t	*enumlist = NULL;
	INT			nitems;
	INT			n;
	INT			found;

	*textbuf = '\0';

	/* collect the metadata item */
	if ( (meta = p80211_did2item(metalist, did)) != NULL ) {
		if ( item->status == P80211ENUM_msgitem_status_data_ok ) {

			nitems = meta->enumptr->nitems;
			enumlist = meta->enumptr->list;

			if ( item->did != 0UL ) {
				for ( n=0, found = 0;
					(!found) && (n < nitems); n++ ) {
					if ( enumlist[n].val ==
						(*((UINT32 *)(item->data))) ) {
						/* now, print the data item
						name and enum text value 
						into textbuf */
						sprintf( textbuf, "%s=%s",
							meta->name,
							enumlist[n].name );
						found = 1;
					}
				}

				if ( !found ) {
					char	error_msg[MSG_BUFF_LEN];

					p80211_error2text(
					P80211ENUM_msgitem_status_invalid_itemdata,
					error_msg);
					sprintf( textbuf, "%s=\"%s\"",
						meta->name, error_msg);
				}
			} else {
				sprintf( textbuf, "%s=%s", meta->name,
					NOT_SUPPORTED);
			}
		} else {
			char		error_msg[MSG_BUFF_LEN];

			p80211_error2text( item->status, error_msg);
			sprintf( textbuf, "%s=\"%s\"", meta->name,
				error_msg);
		}
	} else {
		char		error_msg[MSG_BUFF_LEN];

		p80211_error2text( P80211ENUM_msgitem_status_invalid_msg_did,
			error_msg);
		sprintf( textbuf, "0x%08lx=\"%s\"", did,
			error_msg);
	}

	return;
}


/*----------------------------------------------------------------
* p80211_fromtext_enumint
*
* <valuename> ==> UINT32
*
* Converts a C string containing the "<item name>=<item value>" format
* to a wlan data item triple.
*
* The C string format  is always  "<item name>=<item value>".
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		(out>item triple {DID, len, value}.
*	textbuf		character buffer to receive textual
*			representation.
*
* Returns: 
*	nothing
*
* Side effects:
*	Writes the converted value to the buffer pointed at by
*	itembuf.
----------------------------------------------------------------*/
void p80211_fromtext_enumint( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf, char *textbuf )
{
	p80211meta_t		*meta = NULL;
	p80211itemd_t		*item = (p80211itemd_t*)itembuf;
	p80211enumpair_t	*enumlist = NULL;
	INT			nitems;
	INT			n;
	INT			found;

	/* collect the metadata item */
	if ( (meta = p80211_did2item(metalist, did)) != NULL ) {
		nitems = meta->enumptr->nitems;
		enumlist = meta->enumptr->list;

		/* set the DID and OR in the partial DID for safety */
		item->did = did | meta->did;
		item->len = p80211item_maxdatalen(metalist, item->did);

		/* skip past the item name to its value before converting */
		textbuf = strchr(textbuf, '=');

		if ( textbuf != NULL ) {
			/* OK, got the '=', bump to the next */
			textbuf++;

			for ( n=0, found = 0; (!found) && (n < nitems); n++ ) {
				if ( strcmp(enumlist[n].name, textbuf) == 0 ) {
					*((UINT32 *)(item->data)) =
						enumlist[n].val;
					item->status =
					P80211ENUM_msgitem_status_data_ok;
					found = 1;
				}
			}

			if ( !found ) {
				*((UINT32 *)(item->data)) = P80211ENUM_BAD;
				item->status =
					P80211ENUM_msgitem_status_invalid_itemdata;
			}
		} else {
			/* bogus text string, set the item data value to zero */
			*((UINT32 *)(item->data)) = 0UL;
			item->status = P80211ENUM_msgitem_status_missing_itemdata;
		}
	} else {
		item->did = did;
		item->len = sizeof(UINT32);
		item->status = P80211ENUM_msgitem_status_invalid_itemname;
	}
	return;
}


/*----------------------------------------------------------------
* p80211_isvalid_enumint
*
* Tests an item triple for valid range.  Uses the validation
* information in the metadata.  Enumint's are validated against
* their enumeration structure.
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		item triple {DID, len, value}.
*
* Returns: 
*	0	- data in itembuf is invalid
*	~0	- data in itembuf is valid
----------------------------------------------------------------*/
UINT32 p80211_isvalid_enumint( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf )
{
	UINT32		result = 0;
	p80211meta_t	*meta;
	p80211itemd_t	*item = (p80211itemd_t*)itembuf;

	if ( item->status == P80211ENUM_msgitem_status_data_ok ) {
		/* collect the metadata item */
		if ( (meta = p80211_did2item(metalist, did)) != NULL ) {
			if ( (*((UINT32 *)(item->data))) != P80211ENUM_BAD ) {
				result = 1;
			} else {
				item->status =
					P80211ENUM_msgitem_status_invalid_itemdata;
			}
		} else {
			item->status = P80211ENUM_msgitem_status_invalid_did;
		}
	}

	return result;
}


/*----------------------------------------------------------------
* p80211_totext_getmibattribute
*
* Converts the mibattribute of a "mibget" message into
* a text string.  The DATA portion of the mibattribute's
* "DID-LEN-DATA" triple is itself a "DID-LEN-DATA" triple storing
* the mib item's did, length and data.  In other words:
*
* DID-LEN-DATA
*           ^
*           |__________ where DATA = DID-LEN-DATA for a MIB Item
*
* If message text format is:
*      "mibattribute=<mibitemname>=<mibvalue>"
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		item triple {DID, len, value}.
*	textbuf		(out) character buffer to receive textual
*			representation.
*
* Returns: 
*	nothing
*
* Side effects:
*	Writes the converted mib value to the buffer pointed at by
*	textbuf.
----------------------------------------------------------------*/
void p80211_totext_getmibattribute( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf, char *textbuf )
{
	char		tmpbuf[MSG_BUFF_LEN];
	UINT32		mibdid;
	p80211meta_t	*meta = NULL;
	p80211meta_t	*mibmeta = NULL;
	p80211itemd_t	*item = (p80211itemd_t*)itembuf;

	*textbuf = '\0';

	/* get the metadata item */
	if ( (meta = p80211_did2item(metalist, did)) != NULL ) {
		if ( item->status == P80211ENUM_msgitem_status_data_ok ) {
			mibdid = *((UINT32 *)(item->data));
			if ( (mibmeta =
				p80211_did2item(mib_catlist,mibdid)) != NULL ) {
				if ( item->did != 0UL ) {
					if ( mibmeta->totextptr != NULL) {
						(*(mibmeta->totextptr))
						(mib_catlist, mibdid,
						item->data, tmpbuf);
						/* now, print to the textbuf */
						sprintf( textbuf,
							"%s=%s",meta->name,
							tmpbuf);
					} else {
						sprintf( textbuf,
							"%s=%s=%s",
							meta->name,
							mibmeta->name,
							NOT_SUPPORTED);
					}
				} else {
					sprintf( textbuf, "%s=%s=%s",
						meta->name, mibmeta->name,
						NOT_SUPPORTED);
				}
			} else {
				char		error_msg[MSG_BUFF_LEN];

				p80211_error2text(
					P80211ENUM_msgitem_status_invalid_mib_did,
					error_msg);
				sprintf( textbuf, "0x%08lx=\"%s\"", mibdid,
					error_msg);
			}
		} else {
			char		error_msg[MSG_BUFF_LEN];

			p80211_error2text( item->status, error_msg);
			sprintf( textbuf, "%s=\"%s\"", meta->name,
				error_msg);
		}
	} else {
		char		error_msg[MSG_BUFF_LEN];

		p80211_error2text( P80211ENUM_msgitem_status_invalid_msg_did,
			error_msg);
		sprintf( textbuf, "0x%08lx=\"%s\"", did,
			error_msg);
	}

	return;
}


/*----------------------------------------------------------------
* p80211_totext_setmibattribute
*
* Converts the mibattribute of a "mibset" message into
* a text string.  The DATA portion of the mibattribute's
* "DID-LEN-DATA" triple is itself a "DID-LEN-DATA" triple storing
* the mib item's did, length and data.  In other words:
*
* DID-LEN-DATA
*           ^
*           |__________ where DATA = DID-LEN-DATA for a MIB Item
*
* If message text format is:
*      "mibattribute=<mibitemname>=<mibvalue>"
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		item triple {DID, len, value}.
*	textbuf		(out) character buffer to receive textual
*			representation.
*
* Returns: 
*	nothing
*
* Side effects:
*	Writes the converted mib value to the buffer pointed at by
*	textbuf.
----------------------------------------------------------------*/
void p80211_totext_setmibattribute( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf, char *textbuf )
{
	char		tmpbuf[MSG_BUFF_LEN];
	UINT32		mibdid;
	p80211meta_t	*meta = NULL;
	p80211meta_t	*mibmeta = NULL;
	p80211itemd_t	*item = (p80211itemd_t*)itembuf;

	*textbuf = '\0';

	/* get the metadata item */
	if ( (meta = p80211_did2item(metalist, did)) != NULL ) {
		if ( item->status == P80211ENUM_msgitem_status_data_ok ) {
			mibdid = *((UINT32 *)(item->data));
			if ( (mibmeta =
				p80211_did2item(mib_catlist,mibdid)) != NULL ) {
				if ( item->did != 0UL ) {
					if ( mibmeta->totextptr != NULL) {
						(*(mibmeta->totextptr))
						(mib_catlist, mibdid,
						item->data, tmpbuf);
						/* now, print to the textbuf */
						sprintf( textbuf,
							"%s=%s",meta->name,
							tmpbuf);
					} else {
						sprintf( textbuf,
							"%s=%s=%s",
							meta->name,
							mibmeta->name,
							NOT_SUPPORTED);
					}
				} else {
					sprintf( textbuf, "%s=%s=%s",
						meta->name, mibmeta->name,
						NOT_SUPPORTED);
				}
			} else {
				char		error_msg[MSG_BUFF_LEN];

				p80211_error2text(
					P80211ENUM_msgitem_status_invalid_mib_did,
					error_msg);
				sprintf( textbuf, "0x%08lx=\"%s\"", mibdid,
					error_msg);
			}
		} else {
			char		error_msg[MSG_BUFF_LEN];

			p80211_error2text( item->status, error_msg);
			sprintf( textbuf, "%s=\"%s\"", meta->name,
				error_msg);
		}
	} else {
		char		error_msg[MSG_BUFF_LEN];

		p80211_error2text( P80211ENUM_msgitem_status_invalid_msg_did,
			error_msg);
		sprintf( textbuf, "0x%08lx=\"%s\"", did,
			error_msg);
	}

	return;
}


/*----------------------------------------------------------------
* p80211_fromtext_getmibattribute
*
* If message is mibget, then the text format is:
*      "mibattribute=<mibitemname>"
* If message is mibset, then the text format is:
*      "mibattribute=<mibitemname>=<mibvalue>"
*
* Takes the mibattribute argument of a "mibget" message, and coverts
* the mib item name into a mib DID and converts the mib's value.
*
* The DATA portion of the mibattribute's "DID-LEN-DATA" triple is
* itself a "DID-LEN-DATA" triple storing the mib item's did, length
* and data.  In other words:
*
* DID-LEN-DATA
*           ^
*           |__________ where DATA = DID-LEN-DATA for a MIB Item
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		(out>item triple {DID, len, value}.
*	textbuf		character buffer to receive textual
*			representation.
*
* Returns: 
*	nothing
*
* Side effects:
*	Writes the MIB DID to the buffer pointed at by
*	itembuf.
----------------------------------------------------------------*/
void p80211_fromtext_getmibattribute( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf, char *textbuf )
{
	p80211meta_t		*meta;
	p80211meta_t		*mibmeta;
	p80211itemd_t		*item = (p80211itemd_t*)itembuf;
	char			*mibstr;
	UINT32			mibdid;

	/* collect the metadata item */
	if ( (meta = p80211_did2item(metalist, did)) != NULL ) {
		/* set the DID (OR in the partial DID for safety)
		and set the length */
		item->did = did | meta->did;
		item->len = p80211item_maxdatalen(metalist, item->did);

		/* collect the mib item name */
		textbuf = strchr(textbuf, '=');

		if ( textbuf == NULL ) {
			*((UINT32 *)(item->data)) = 0UL;
			item->status = P80211ENUM_msgitem_status_missing_itemdata;
			return;
		}

		textbuf++;
		mibstr = textbuf;

		/* get DID of mib item based on mib name */
		mibdid = p80211_metaname2did(mib_catlist,mibstr);

		if ( mibdid != 0UL ) {
			if ( (mibmeta = p80211_did2item(mib_catlist,
				mibdid)) != NULL ) {
				item= (p80211itemd_t *)(item->data);
				item->did = mibdid;
				if ( mibmeta-> maxlen > 0 ) {
					item->len =
						p80211item_maxdatalen(
							mib_catlist,
							item->did);
				} else {
					item->len = 4;
				}
				*((UINT32 *)(item->data)) = 0UL;
				item->status =
					P80211ENUM_msgitem_status_data_ok;
			} else {
				item->status =
				P80211ENUM_msgitem_status_invalid_mib_did;
				*((UINT32 *)(item->data)) = 0UL;
				return;
			}
		} else {
			item->status =
				P80211ENUM_msgitem_status_invalid_mib_did;
			*((UINT32 *)(item->data)) = 0UL;
			return;
		}
	} else {
		item->did = did;
		item->len = 4;
		*((UINT32 *)(item->data)) = 0UL;
		item->status = P80211ENUM_msgitem_status_invalid_itemname;
	}

	return;
}


/*----------------------------------------------------------------
* p80211_fromtext_setmibattribute
*
* If message is mibget, then the text format is:
*      "mibattribute=<mibitemname>"
* If message is mibset, then the text format is:
*      "mibattribute=<mibitemname>=<mibvalue>"
*
* Takes the mibattribute argument of a "mibset" message, and coverts
* the mib item name into a mib DID and converts the mib's value.
*
* The DATA portion of the mibattribute's "DID-LEN-DATA" triple is
* itself a "DID-LEN-DATA" triple storing the mib item's did, length
* and data.  In other words:
*
* DID-LEN-DATA
*           ^
*           |__________ where DATA = DID-LEN-DATA for a MIB Item
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		(out>item triple {DID, len, value}.
*	textbuf		character buffer to receive textual
*			representation.
*
* Returns: 
*	nothing
*
* Side effects:
*	Writes the MIB DID to the buffer pointed at by
*	itembuf.  If message is "mibset", then the mib value is
*	coverted from text and stored after the DID and LEN
----------------------------------------------------------------*/
void p80211_fromtext_setmibattribute( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf, char *textbuf )
{
	p80211meta_t		*meta;
	p80211meta_t		*mibmeta;
	p80211itemd_t		*item = (p80211itemd_t*)itembuf;
	char			*mibstr;
	UINT32			mibdid;

	/* collect the metadata item */

	meta = p80211_did2item(metalist, did);
	if (meta == NULL) {
		item->did = did;
		item->len = 4;
		*((UINT32 *)(item->data)) = 0UL;
		item->status = P80211ENUM_msgitem_status_invalid_msg_did;
                return;
	}

	/* set the DID (OR in the partial DID for safety) and set the length */

	item->did = did | meta->did;
	item->len = p80211item_maxdatalen(metalist, item->did);

	/* collect the mib item name */

	textbuf = strchr(textbuf, '=');

	if ( textbuf == NULL ) {
		*((UINT32 *)(item->data)) = 0UL;
		item->status = P80211ENUM_msgitem_status_missing_itemdata;
		return;
	}

	textbuf++;
	mibstr = textbuf;

	/* set the '=' between mib name and mib value to
	end of string character for call to metaname2did */

	textbuf = strchr(textbuf, '=');
	if (textbuf == NULL) {
		*((UINT32 *)(item->data)) = 0UL;
		item->status = P80211ENUM_msgitem_status_incomplete_itemdata;
		return;
	}
	*textbuf = '\0';

	/* get DID of mib item based on mib name */

	mibdid = p80211_metaname2did(mib_catlist,mibstr);
	if (mibdid == 0UL) {
		*((UINT32 *)(item->data)) = 0UL;
		item->status = P80211ENUM_msgitem_status_invalid_mib_did;
		return;
	}

	/* put '=' back for call to mib's fromtext function */

	*textbuf = '=';
	mibmeta = p80211_did2item(mib_catlist, mibdid);
	if (mibmeta == NULL) {
		*((UINT32 *)(item->data)) = 0UL;
		item->status = P80211ENUM_msgitem_status_invalid_mib_did;
		return;
	}

	if (mibmeta->fromtextptr == NULL) {
		*((UINT32 *)(item->data)) = 0UL;
		item->status = P80211ENUM_msgitem_status_missing_conv_func;
		return;
	}

	(*(mibmeta->fromtextptr)) (mib_catlist, mibdid, item->data, mibstr);
	item->status = ((p80211itemd_t *)(item->data))->status;

	return;
}


/*----------------------------------------------------------------
* p80211_isvalid_getmibattribute
*
* This function checks the validity of the data portion of the
* mibattribute DID-LEN-DATA triple.  The DATA portion of the
* mibattribute's "DID-LEN-DATA" triple is itself a "DID-LEN-DATA"
* triple storing the mib item's did, length and data, so it's this
* "data" that is actually checked for validity.
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		item triple {DID, len, value}.
*
* Returns: 
*	0	- data in itembuf is invalid
*	~0	- data in itembuf is valid
----------------------------------------------------------------*/
UINT32 p80211_isvalid_getmibattribute( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf )
{
	UINT32		result = 0;
	p80211meta_t	*msgmeta = NULL;
	p80211meta_t	*mibmeta = NULL;
	p80211itemd_t	*item = (p80211itemd_t*)itembuf;
	p80211itemd_t	*mibitem;

	if ( item->status == P80211ENUM_msgitem_status_data_ok ) {
		if ( (msgmeta = p80211_did2item(metalist, did)) != NULL ) {
			/* set up the pointers */
			mibitem = (p80211itemd_t *)(item->data);
			if ( (mibmeta =
				p80211_did2item(mib_catlist, mibitem->did))
				!= NULL ) {
					result = 1;
			} else {
				item->status =
				P80211ENUM_msgitem_status_invalid_mib_did;
			}
		} else {
			item->status =
			P80211ENUM_msgitem_status_invalid_msg_did;
		}
	}

	return result;
}


/*----------------------------------------------------------------
* p80211_isvalid_setmibattribute
*
* This function checks the validity of the data portion of the
* mibattribute DID-LEN-DATA triple.  The DATA portion of the
* mibattribute's "DID-LEN-DATA" triple is itself a "DID-LEN-DATA"
* triple storing the mib item's did, length and data, so it's this
* "data" that is actually checked for validity.
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		item triple {DID, len, value}.
*
* Returns: 
*	0	- data in itembuf is invalid
*	~0	- data in itembuf is valid
----------------------------------------------------------------*/
UINT32 p80211_isvalid_setmibattribute( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf )
{
	UINT32		result = 0;
	p80211meta_t	*msgmeta = NULL;
	p80211meta_t	*mibmeta = NULL;
	p80211itemd_t	*item = (p80211itemd_t*)itembuf;
	p80211itemd_t	*mibitem;

	if ( item->status == P80211ENUM_msgitem_status_data_ok ) {
		if ( (msgmeta = p80211_did2item(metalist, did)) != NULL ) {
			/* set up the pointers */
			mibitem = (p80211itemd_t *)(item->data);
			if ( (mibmeta =
				p80211_did2item(mib_catlist, mibitem->did))
				!= NULL ) {
				/* call the valid function for the mib */
				if ( mibmeta->validfunptr != NULL ) {
					if ( (*(mibmeta->validfunptr))
						(mib_catlist, mibitem->did,
						(UINT8 *)mibitem) ) {
						result = 1;
					} else if ( (mibitem->status) != P80211ENUM_msgitem_status_data_ok ) {
						item->status = mibitem->status;
					}
				} else {
					item->status =
					P80211ENUM_msgitem_status_missing_valid_func;
				}
			} else {
				item->status = P80211ENUM_msgitem_status_invalid_mib_did;
			}
		} else {
			item->status =
				P80211ENUM_msgitem_status_invalid_msg_did;
		}
	}

	return result;
}


/*----------------------------------------------------------------
* p80211_totext_intarray
*
* UINT32[] ==> %d,%d,%d,...
*
* Converts an array of UINT32's to a comma-separated list.  The number
* of array elements is taken from the "maxlen" field of the DID metadata.
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		item triple {DID, len, value}.
*	textbuf		(out) character buffer to receive textual
*			representation.
*
* Returns: 
*	nothing
*
* Side effects:
*	Writes the converted value to the buffer pointed at by
*	textbuf.
----------------------------------------------------------------*/
void p80211_totext_intarray( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf, char *textbuf )
{
	p80211meta_t   *meta;
	p80211itemd_t  *item;
	UINT32         *data;
	int            i;
	char           *buf, error_msg[MSG_BUFF_LEN];

	*textbuf = '\0';

	item = (p80211itemd_t *) itembuf;
	data = (UINT32 *) item->data;
	meta = p80211_did2item(metalist, did);
	if (meta == NULL) {
		p80211_error2text(P80211ENUM_msgitem_status_invalid_msg_did, error_msg);
		sprintf(textbuf, "0x%08lx=\"%s\"", did, error_msg);
		return;
	}

	if (item->status != P80211ENUM_msgitem_status_data_ok) {
		p80211_error2text(item->status, error_msg);
		sprintf(textbuf, "%s=\"%s\"", meta->name, error_msg);
		return;
	}

	if (item->did == 0UL) {
		sprintf(textbuf, "%s=%s", meta->name, NOT_SUPPORTED);
		return;
	}

	buf = textbuf + sprintf(textbuf, "%s=", meta->name);

	for (i = 0; i < meta->maxlen; i++)
		buf += sprintf(buf, (i == 0) ? "%lu" : ",%lu", data[i]);

	return;
}

/*----------------------------------------------------------------
* p80211_fromtext_intarray
*
* %d,%d,%d,... ==> UINT32[]
*
* Converts a C string containing the "<item name>=<value>,<value>,..." format
* to a wlan data item triple.  The "values" must be integers.  The number
* of array elements is taken from the "maxlen" field of the DID metadata.
* There must be at least 1 element in the array.
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		(out) item triple {DID, len, value}.
*	textbuf		character buffer containing textual representation.
*
* Returns: 
*	nothing
*
* Side effects:
*	Writes the converted value to the buffer pointed at by
*	itembuf.
----------------------------------------------------------------*/
void p80211_fromtext_intarray( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf, char *textbuf )
{
	p80211meta_t   *meta;
	p80211itemd_t  *item;
	UINT32         *data;
	int            cnt;
	char           *buf, *end, dlm;

	item = (p80211itemd_t *) itembuf;
	data = (UINT32 *) item->data;
	meta = p80211_did2item(metalist, did);
	if (meta == NULL) {
		item->did = did;
		item->len = sizeof(int);
		item->status = P80211ENUM_msgitem_status_invalid_itemname;
		return;
	}

	/*
	** Set the DID and OR in the partial DID for safety.
	*/

	item->did = did | meta->did;
	item->len = p80211item_maxdatalen(metalist, item->did);

	/*
	** Skip past the item name to its value before converting.  The
	** delimiter will be '='.
	*/

	dlm = '=';
	buf = strchr(textbuf, dlm);
	if (buf == NULL) {
		memset(data, 0, item->len);
		item->status = P80211ENUM_msgitem_status_missing_itemdata;
		return;
	}

	/*
	** Keep reading array elements...
	*/

	cnt = 0;

	while (1) {

		/*
		** Quit if we now have all array elements.
		*/

		if (cnt >= meta->maxlen) break;

		/*
		** If we're not pointing at the delimiter, then something went
		** wrong.  Note that the first delimiter will be '=' and all
		** subsequent delimiters will be ','.  Skip past the delimiter
		** and any following whitespace.
		*/

		if (*buf != dlm) goto invalid;
		dlm = ',';

		buf++;
		buf += strspn(buf, " \t\n\r\f\v");

		/*
		** Get the next array element.  Make sure that at least
		** something was found (i.e. end != buf).  Skip any trailing
		** whitespace.  This should leave us at either the next ',' or
		** at '\0'.
		*/

		data[cnt] = strtol(buf, &end, 10);
		if (end == buf) goto invalid;
		cnt++;
		buf = end + strspn(end, " \t\n\r\f\v");
	}

	/*
	** Make sure there is no left-over stuff at the end of the sting.
	*/

	if (*buf != '\0') goto invalid;

	item->status = P80211ENUM_msgitem_status_data_ok;

	return;

invalid:
	memset(data, 0, item->len);
	item->status = P80211ENUM_msgitem_status_invalid_itemdata;

	return;
}

/*----------------------------------------------------------------
* p80211_isvalid_intarray
*
* Tests an item triple for valid range.  Uses the validation
* information in the metadata.  All values are valid, so this 
* function always returns success.
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		item triple {DID, len, value}.
*
* Returns: 
*	0	- data in itembuf is invalid
*	~0	- data in itembuf is valid
----------------------------------------------------------------*/
UINT32 p80211_isvalid_intarray( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf )
{
	UINT32		result = 0;
	p80211meta_t	*meta;
	p80211itemd_t	*item = (p80211itemd_t*)itembuf;

	if ( item->status == P80211ENUM_msgitem_status_data_ok ) {
		/* collect the metadata item */
		if ( (meta = p80211_did2item(metalist, did)) != NULL ) {
			/* since integers aren't bounded, there's
			nothing to check */
			result = 1;
		} else {
			item->status = P80211ENUM_msgitem_status_invalid_did;
		}
	}

	return result;
}

/*----------------------------------------------------------------
* p80211_totext_bitarray
*
* UINT32 ==> %d,%d,%d,...
*
* Converts the first "maxlen" bits of a UINT32 to a comma-separated list
* of bit numbers of the bits which are set.  Other bits are ignored.
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		item triple {DID, len, value}.
*	textbuf		(out) character buffer to receive textual
*			representation.
*
* Returns: 
*	nothing
*
* Side effects:
*	Writes the converted value to the buffer pointed at by
*	textbuf.
----------------------------------------------------------------*/
void p80211_totext_bitarray( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf, char *textbuf )
{
	p80211meta_t   *meta;
	p80211itemd_t  *item;
	UINT32         array;
	int            found, i;
	char           *buf, error_msg[MSG_BUFF_LEN];

	*textbuf = '\0';

	item = (p80211itemd_t *) itembuf;
	meta = p80211_did2item(metalist, did);
	if (meta == NULL) {
		p80211_error2text(P80211ENUM_msgitem_status_invalid_msg_did, error_msg);
		sprintf(textbuf, "0x%08lx=\"%s\"", did, error_msg);
		return;
	}

	if (item->status != P80211ENUM_msgitem_status_data_ok) {
		p80211_error2text(item->status, error_msg);
		sprintf(textbuf, "%s=\"%s\"", meta->name, error_msg);
		return;
	}

	if (item->did == 0UL) {
		sprintf(textbuf, "%s=%s", meta->name, NOT_SUPPORTED);
		return;
	}

	array = *((UINT32 *) item->data);

	buf = textbuf + sprintf(textbuf, "%s=", meta->name);

	found = 0;

	for (i = meta->min; i <= meta->max; i++)
		if (array & (0x1 << i)) {
			found = 1;
			buf += sprintf(buf, "%lu,", (UINT32) i);
		}

	if (found != 0) *(buf-1) = '\0';

	return;
}

/*----------------------------------------------------------------
* p80211_fromtext_bitarray
*
* %d,%d,%d,... ==> UINT32
*
* Converts a C string containing the "<item name>=<value>,<value>,..." format
* to a wlan data item triple.  Bit numbers must be less than "maxlen".
*
* The C string format  is always  "<item name>=<value>,<value>,<value>,...".
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		(out) item triple {DID, len, value}.
*	textbuf		character buffer containing textual representation.
*
* Returns: 
*	nothing
*
* Side effects:
*	Writes the converted value to the buffer pointed at by
*	itembuf.
----------------------------------------------------------------*/
void p80211_fromtext_bitarray( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf, char *textbuf )
{
	p80211meta_t   *meta;
	p80211itemd_t  *item;
	UINT32         array, value;

	item = (p80211itemd_t *) itembuf;
	meta = p80211_did2item(metalist, did);
	if (meta == NULL) {
		item->did = did;
		item->len = sizeof(int);
		item->status = P80211ENUM_msgitem_status_invalid_itemname;
		return;
	}

	/*
	** Set the DID and OR in the partial DID for safety.
	*/

	item->did = did | meta->did;
	item->len = p80211item_maxdatalen(metalist, item->did);

	/*
	** Skip past the item name to its value before converting.
	*/

	textbuf = strchr(textbuf, '=');
	if (textbuf == NULL) {
		*((UINT32 *) item->data) = 0;
		item->status = P80211ENUM_msgitem_status_missing_itemdata;
		return;
	}

	array = 0;

	while (textbuf != NULL) {

		/* OK, got the '=' or ',', bump to the next char */

		textbuf++;
		if (textbuf[0] == '\0') break;

		if (sscanf(textbuf, "%lu", &value) != 1) {
			*((UINT32 *) item->data) = 0;
			item->status = P80211ENUM_msgitem_status_invalid_itemdata;
			return;
		}

		if (value < meta->min || value > meta->max) {
			*((UINT32 *) item->data) = 0;
			item->status = P80211ENUM_msgitem_status_invalid_itemdata;
			return;
		}

		array |= 0x1 << value;

		textbuf = strchr(textbuf, ',');
	}

	*((UINT32 *) item->data) = array;
	item->status = P80211ENUM_msgitem_status_data_ok;

	return;
}

/*----------------------------------------------------------------
* p80211_isvalid_bitarray
*
* Tests an item triple for valid range.  Uses the validation
* information in the metadata.
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		item triple {DID, len, value}.
*
* Returns: 
*	0	- data in itembuf is invalid
*	~0	- data in itembuf is valid
----------------------------------------------------------------*/
UINT32 p80211_isvalid_bitarray( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf )
{
	UINT32		result = 0;
	p80211meta_t	*meta;
	p80211itemd_t	*item = (p80211itemd_t*)itembuf;
	UINT32          i, value, mask;

	if ( item->status == P80211ENUM_msgitem_status_data_ok ) {
		/* collect the metadata item */
		if ( (meta = p80211_did2item(metalist, did)) != NULL ) {

			mask = 0;
			for (i = meta->min; i <= meta->max; i++)
				mask |= 1 << i;

			value = *((UINT32 *)(item->data));
			if ( value == (value & mask) ) {
				result = 1;
			} else {
				item->status =
					P80211ENUM_msgitem_status_invalid_itemdata;
			}
		} else {
			item->status = P80211ENUM_msgitem_status_invalid_did;
		}
	}

	return result;
}

/*----------------------------------------------------------------
* p80211_totext_macarray
*
* Converts an array of MAC addresses to a comma-separated list.
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		item triple {DID, len, value}.
*	textbuf		(out) character buffer to receive textual
*			representation.
*
* Returns: 
*	nothing
*
* Side effects:
*	Writes the converted value to the buffer pointed at by
*	textbuf.
----------------------------------------------------------------*/
void p80211_totext_macarray( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf, char *textbuf )
{
	p80211meta_t      *meta;
	p80211itemd_t     *item;
	p80211macarray_t  *macarray;
	int               i, cnt;
	char              error_msg[MSG_BUFF_LEN];

	*textbuf = '\0';

	item = (p80211itemd_t *) itembuf;
	meta = p80211_did2item(metalist, did);
	if (meta == NULL) {
		p80211_error2text(P80211ENUM_msgitem_status_invalid_msg_did, error_msg);
		sprintf(textbuf, "0x%08lx=\"%s\"", did, error_msg);
		return;
	}

	if (item->status != P80211ENUM_msgitem_status_data_ok) {
		p80211_error2text(item->status, error_msg);
		sprintf(textbuf, "%s=\"%s\"", meta->name, error_msg);
		return;
	}

	if (item->did == 0UL) {
		sprintf(textbuf, "%s=%s", meta->name, NOT_SUPPORTED);
		return;
	}

	macarray = (p80211macarray_t *) item->data;

	cnt = sprintf(textbuf, "%s=", meta->name);

	for (i = 0; i < macarray->cnt; i++)
		cnt += sprintf(textbuf+cnt, (i==0) ?
			"%02x:%02x:%02x:%02x:%02x:%02x" :
			",%02x:%02x:%02x:%02x:%02x:%02x",
			(UINT) macarray->data[i][0],
			(UINT) macarray->data[i][1],
			(UINT) macarray->data[i][2],
			(UINT) macarray->data[i][3],
			(UINT) macarray->data[i][4],
			(UINT) macarray->data[i][5]);

	return;
}

/*----------------------------------------------------------------
* p80211_fromtext_macarray
*
* Converts a C string containing the "<item name>=<value>,<value>,..." format
* to a wlan data item triple.
*
* The C string format  is always  "<item name>=<value>,<value>,<value>,...".
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		(out) item triple {DID, len, value}.
*	textbuf		character buffer containing textual representation.
*
* Returns: 
*	nothing
*
* Side effects:
*	Writes the converted value to the buffer pointed at by
*	itembuf.
----------------------------------------------------------------*/
void p80211_fromtext_macarray( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf, char *textbuf )
{
	p80211meta_t      *meta;
	p80211itemd_t     *item;
	p80211macarray_t  *macarray;
	int               cnt, x1, x2, x3, x4, x5, x6;

	item = (p80211itemd_t *) itembuf;
	meta = p80211_did2item(metalist, did);
	if (meta == NULL) {
		item->did = did;
		item->len = sizeof(int);
		item->status = P80211ENUM_msgitem_status_invalid_itemname;
		return;
	}

	/*
	** Set the DID and OR in the partial DID for safety.
	*/

	item->did = did | meta->did;
	item->len = p80211item_maxdatalen(metalist, item->did);

	/*
	** Skip past the item name to its value before converting.
	*/

	macarray = (p80211macarray_t *) item->data;
	macarray->cnt = 0;

	textbuf = strchr(textbuf, '=');
	if (textbuf == NULL) {
		item->status = P80211ENUM_msgitem_status_missing_itemdata;
		return;
	}

	cnt = 0;

	while (textbuf != NULL) {

		/* OK, got the '=' or ',', bump to the next char */

		textbuf++;
		if (textbuf[0] == '\0') break;

		if (cnt >= meta->maxlen) {
			item->status = P80211ENUM_msgitem_status_invalid_itemdata;
			return;
		}

		if (sscanf(textbuf, "%x:%x:%x:%x:%x:%x",
				&x1, &x2, &x3, &x4, &x5, &x6) != 6) {
			item->status = P80211ENUM_msgitem_status_invalid_itemdata;
			return;
		}

		macarray->data[cnt][0] = (UINT8) x1;
		macarray->data[cnt][1] = (UINT8) x2;
		macarray->data[cnt][2] = (UINT8) x3;
		macarray->data[cnt][3] = (UINT8) x4;
		macarray->data[cnt][4] = (UINT8) x5;
		macarray->data[cnt][5] = (UINT8) x6;
		cnt++;

		textbuf = strchr(textbuf, ',');
	}

	macarray->cnt = cnt;
	item->status = P80211ENUM_msgitem_status_data_ok;

	return;
}

/*----------------------------------------------------------------
* p80211_isvalid_macarray
*
* Tests an item triple for valid range.  Uses the validation
* information in the metadata.  All values are valid, so this 
* function always returns success.
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		complete, validated, DID.
*	itembuf		item triple {DID, len, value}.
*
* Returns: 
*	0	- data in itembuf is invalid
*	~0	- data in itembuf is valid
----------------------------------------------------------------*/
UINT32 p80211_isvalid_macarray( catlistitem_t *metalist, UINT32 did, UINT8 *itembuf )
{
	UINT32		result = 0;
	p80211meta_t	*meta;
	p80211itemd_t	*item = (p80211itemd_t*)itembuf;

	if ( item->status == P80211ENUM_msgitem_status_data_ok ) {
		/* collect the metadata item */
		if ( (meta = p80211_did2item(metalist, did)) != NULL ) {
			/* since integers aren't bounded, there's
			nothing to check */
			result = 1;
		} else {
			item->status = P80211ENUM_msgitem_status_invalid_did;
		}
	}

	return result;
}

/*----------------------------------------------------------------
* p80211_error2text
*
* This function converts an error code into an appropriate error
* string.
*
* Arguments:
*	err_code	error code reflecting index into 
*			the error enumerated list.
*	err_str		(out) will contain the appropriate
*			error string.
*
* Returns: 
*	Nothing
----------------------------------------------------------------*/
void p80211_error2text( int err_code, char *err_str )
{
	p80211enum_int2text(&MKENUMNAME(msgitem_status), err_code, err_str);
}

/*--------------------------------------------------------------------*/
/* Item enumerations */
/*  The following arrays list the numbers and names for each of the */
/*  enumerations present in the 802.11 MIB and MLME. */

MKENUMPAIRLIST(truth)
{
	MKENUMPAIR( 0, "false" ),
	MKENUMPAIR( 1, "true")
};
MKENUM(truth);

MKENUMPAIRLIST(ifstate)
{
	MKENUMPAIR( 0, "disable" ),
	MKENUMPAIR( 1, "fwload"),
	MKENUMPAIR( 2, "enable")
};
MKENUM(ifstate);

MKENUMPAIRLIST(powermgmt)
{
	MKENUMPAIR( 1, "active" ),
	MKENUMPAIR( 2, "powersave" )
};
MKENUM(powermgmt);

MKENUMPAIRLIST(bsstype)
{
	MKENUMPAIR( 1, "infrastructure" ),
	MKENUMPAIR( 2, "independent" ),
	MKENUMPAIR( 3, "any" )
};
MKENUM(bsstype);

MKENUMPAIRLIST(authalg)
{
	MKENUMPAIR( 1, "opensystem" ),
	MKENUMPAIR( 2, "sharedkey" ),
	MKENUMPAIR( 3, "not_set" )
};
MKENUM(authalg);

MKENUMPAIRLIST(phytype)
{
	MKENUMPAIR( 1, "fhss" ),
	MKENUMPAIR( 2, "dsss" ),
	MKENUMPAIR( 3, "irbaseband" )
};
MKENUM(phytype);

MKENUMPAIRLIST(temptype)
{
	MKENUMPAIR( 1, "commercial" ),
	MKENUMPAIR( 2, "industrial" )
};
MKENUM(temptype);

MKENUMPAIRLIST(regdomain)
{
	MKENUMPAIR( 0x10, "fcc" ),
	MKENUMPAIR( 0x20, "doc" ),
	MKENUMPAIR( 0x30, "etsi" ),
	MKENUMPAIR( 0x31, "spain" ),
	MKENUMPAIR( 0x32, "france" ),
	MKENUMPAIR( 0x40, "mkk" )
};
MKENUM(regdomain);

MKENUMPAIRLIST(ccamode)
{
	MKENUMPAIR( 0x01, "edonly" ),
	MKENUMPAIR( 0x02, "csonly" ),
	MKENUMPAIR( 0x04, "edandcs" ),
	MKENUMPAIR( 0x08, "cswithtimer" ),
	MKENUMPAIR( 0x0f, "hrcsanded" )
};
MKENUM(ccamode);

MKENUMPAIRLIST(diversity)
{
	MKENUMPAIR( 1, "fixedlist" ),
	MKENUMPAIR( 2, "notsupported" ),
	MKENUMPAIR( 3, "dynamic" )
};
MKENUM(diversity);

MKENUMPAIRLIST(scantype)
{
	MKENUMPAIR( 1, "active" ),
	MKENUMPAIR( 2, "passive" ),
	MKENUMPAIR( 3, "both" ),
};
MKENUM(scantype);

MKENUMPAIRLIST(resultcode)
{
	MKENUMPAIR( P80211ENUM_resultcode_success,
		"success" ),
	MKENUMPAIR( P80211ENUM_resultcode_invalid_parameters,
		"invalid_parameters" ),
	MKENUMPAIR( P80211ENUM_resultcode_not_supported,
		"not_supported" ),
	MKENUMPAIR( P80211ENUM_resultcode_timeout,
		"timeout" ),
	MKENUMPAIR( P80211ENUM_resultcode_too_many_req,
		"too_many_req" ),
	MKENUMPAIR( P80211ENUM_resultcode_refused,
		"refused" ),
	MKENUMPAIR( P80211ENUM_resultcode_bss_already,
		"bss_already" ),
	MKENUMPAIR( P80211ENUM_resultcode_invalid_access,
		"invalid_access" ),
	MKENUMPAIR( P80211ENUM_resultcode_invalid_mibattribute,
		"invalid_mibattribute" ),
	MKENUMPAIR( P80211ENUM_resultcode_cant_set_readonly_mib,
		"cant_set_readonly_mib" ),
	MKENUMPAIR( P80211ENUM_resultcode_implementation_failure,
		"implementation_failure" ),
	MKENUMPAIR( P80211ENUM_resultcode_cant_get_writeonly_mib,
		"cant_get_writeonly_mib" )
};
MKENUM(resultcode);

/*--------------------------------------------------------------------*/
/* Note: the following names are from the 802.11 SDL, the comment */
/*       lists the 802.11 Chapter 7 description. */

MKENUMPAIRLIST(reason)
{
	MKENUMPAIR( 1, "unspec_reason" ),
	/* Unspecified Reason */
	MKENUMPAIR( 2, "auth_not_valid" ),
	/* Previous authentication no longer valid */
	MKENUMPAIR( 3, "deauth_lv_ss" ),
	/* Deauthenticated because sending station is leaving (has left) IBSS or ESS */
	MKENUMPAIR( 4, "inactivity" ),
	/* Disassociated due to  inactivity */
	MKENUMPAIR( 5, "ap_overload" ),
	/* Disassociated because AP is unable to handle all currently associated stations */
	MKENUMPAIR( 6, "class23_err" ),
	/* Class 2 or 3 frame received from nonauthenticated station */
	MKENUMPAIR( 7, "class3_err" ),
	/* Class 3 frame received from nonassociated station */
	MKENUMPAIR( 8, "disas_lv_ss" ),
	/* Disassociated because sending station is leaving (has left BSS) */
	MKENUMPAIR( 9, "asoc_not_auth" )
	/* Station requesting (re)association is not authenticated with responding station */
};
MKENUM(reason);

/*--------------------------------------------------------------------*/
/* Note: the following names are from the 802.11 SDL, the comment */
/*       lists the 802.11 Chapter 7 description. */

MKENUMPAIRLIST(status)
{
	MKENUMPAIR( 0, "successful" ),
	/* Successful */
	MKENUMPAIR( 1, "unspec_failure" ),
	/* Unspecified failure */
	MKENUMPAIR( 10, "unsup_cap" ),
	/* Cannot support all requested capabilities in Capability Information field */
	MKENUMPAIR( 11, "reasoc_no_asoc" ),
	/* Reassociation denied due to inability to confirm that association exists */
	MKENUMPAIR( 12, "fail_other" ),
	/* Association denied due to to reason outside scope of this standard */
	MKENUMPAIR( 13, "unspt_alg" ),
	/* Responding station does not support the specified authentication algorithm */
	MKENUMPAIR( 14, "auth_seq_fail" ),
	/* Received and authentication frame with authentication transaction sequence number out of expected sequence */
	MKENUMPAIR( 15, "chlng_fail" ),
	/* Authentication rejected because of challenge failure */
	MKENUMPAIR( 16, "auth_timeout" ),
	/* Authentication rejected due to timeout waiting for next frame in sequence */
	MKENUMPAIR( 17, "ap_full" ),
	/* Association denied because AP is unable to handle additional associated stations */
	MKENUMPAIR( 18, "unsup_rate" )
	/* Association denied due to requesting station not supporting all of the data rates in the BSSBasicRateSet  parameter */
};
MKENUM(status);

/*--------------------------------------------------------------------*/
/* Note: the following are various error codes for command line input */

MKENUMPAIRLIST(msgitem_status)
{
	MKENUMPAIR( 1, "no_value"),
	/* the argument data doesn't have a value; it wasn't set */
	MKENUMPAIR( 2, "argument_item_name_is_invalid" ),
	/* the argument name doesn't exist in any item name */
	MKENUMPAIR( 3, "argument_item_data_is_invalid" ),
	/* the argument data isn't valid  */
	MKENUMPAIR( 4, "argument_item_data_is_missing" ),
	/* the argument data is missing */
	MKENUMPAIR( 5, "argument_item_data_is_incomplete" ),
	/* the argument data is incomplete */
	MKENUMPAIR( 6, "invalid_message_did_for_item" ),
	/* the message did is invalid for argument name  */
	MKENUMPAIR( 7, "invalid_mib_did_for_item" ),
	/* the mib did is invalid for argument name  */
	MKENUMPAIR( 8, "conversion_function_missing_for_item" ),
	/* a conversion function for the item doesn't exist  */
	MKENUMPAIR( 9, "data_string_too_long" ),
	/* the data string exceeds maximum allowed length  */
	MKENUMPAIR( 10, "data_out_of_range" ),
	/* the data is out of the allowed range  */
	MKENUMPAIR( 11, "data_string_too_short" ),
	/* the data string less than required length  */
	MKENUMPAIR( 12, "validity_function_missing_for_item" ),
	/* a validity function for the item doesn't exist  */
	MKENUMPAIR( 13, "invalid_for_unknown_reason" ),
	/* data or message is invalid for an unknown reason not caught */
	MKENUMPAIR( 14, "invalid_did" ),
	/* invalid did; not certain if it's a msg or mib did */
	MKENUMPAIR( 15, "print_function_missing_for_item" )
	/* a print function for the item doesn't exist  */
};
MKENUM(msgitem_status);

MKENUMPAIRLIST(lnxroam_reason)
{
	MKENUMPAIR(0, "unknown"),
	MKENUMPAIR(1, "beacon"),
	MKENUMPAIR(2, "signal"),
	MKENUMPAIR(3, "txretry"),
	MKENUMPAIR(4, "notjoined")
};
MKENUM(lnxroam_reason);

MKENUMPAIRLIST(p2preamble)
{
	MKENUMPAIR( 0, "long"),
	MKENUMPAIR( 2, "short"),
	MKENUMPAIR( 3, "mixed")
};
MKENUM(p2preamble);
