/* src/shared/p80211meta.c
*
* Defines the functions for handling mib and msg metadata
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
* This file defines the metadata for both mib and message contents and
* argument metadata.
*
* --------------------------------------------------------------------
*/


/*================================================================*/
/* System Includes */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*================================================================*/
/* Project Includes */

#include <wlan/wlan_compat.h>
#include <wlan/p80211types.h>
#include <wlan/p80211meta.h>

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

/*================================================================*/
/* Function Definitions */


/*----------------------------------------------------------------
* p80211_text2did
*
* Returns the numeric DID value for any textual metadata name.
*
* Arguments:
*	catlist		ptr to a category metadata list
*	catname		string containing category name
*	grpname		string containing group name
*	iitemname	string containing item name
*
* Returns: 
*	P80211DID_INVALID		no match on name(s)
*	Valid DID		success, returns a valid DID
----------------------------------------------------------------*/
UINT32 p80211_text2did(catlistitem_t *catlist, char *catname, char *grpname, char *itemname)
{
	UINT32		catdid = 0UL;
	UINT32		grpdid = 0UL;
	UINT32		itemdid = 0UL;
	int		c;
	int		cat;
	int		g;
	int		grp;
	int		i;
	int		catsize;
	int		grpsize;
	int		itemsize;


	if ( (catname == NULL) && (grpname == NULL) && (itemname == NULL) ) {
		return P80211DID_INVALID;
	} else {
		/* traverse category metadata list */
		catsize = GETMETASIZE(catlist);
		for ( c = 1; c < catsize; c++ ) {
			cat = c;
			if ( catname != NULL ){
				if ( (catdid = p80211_text2catdid( catlist, catname)) != P80211DID_INVALID ) {
					cat = P80211DID_SECTION(catdid);
					/*
					printf("category %s found, cat = %d\n", catname, cat );
					*/
					/* set loop counter to size of category list 
					   to stop further execution of loop */
					c = catsize;
				} else {
					return catdid;
				}
			}
			/* traverse group metadata list */
			grpsize = GETMETASIZE(catlist[cat].grplist);
			for ( g = 1; g < grpsize; g++ ) {
				grp = g;
				if ( grpname != NULL ){
					if ( (grpdid = p80211_text2grpdid( catlist[cat].grplist, grpname)) != P80211DID_INVALID ) {
						if ( catdid == 0UL ) {
							catdid = P80211DID_MKSECTION(cat);
						}
						grp = P80211DID_GROUP(grpdid);
						/*
						printf("group %s found, cat = %d, grp=%d\n", grpname, cat, grp );
						*/
						/* set category and group loop
						   counters equal to list sizes 
						   to stop further execution of loops */
						g = grpsize;
						c = catsize;
					} else {
						g = grpsize;
						continue;
					}
				}
				/* traverse item metadata list */
				itemsize = GETMETASIZE(catlist[cat].grplist[grp].itemlist);
				for ( i = 1; i < itemsize; i++ ) {
					if ( itemname != NULL ){
						if ( (itemdid = p80211_text2itemdid( catlist[cat].grplist[grp].itemlist, itemname)) != P80211DID_INVALID ) {
							if ( catdid == 0UL ) {
								catdid = P80211DID_MKSECTION(cat);
							}
							if ( grpdid == 0UL ) {
								grpdid = P80211DID_MKGROUP(grp);
							}
							/*
							printf("item %s found, cat = %d, grp=%d, item=%d\n",
								itemname, cat, grp, P80211DID_ITEM(itemdid) );
							*/
							/* set category, group & items loop
							   counters equal to list sizes 
						   	   to stop further execution of loops */
							i = itemsize;
							g = grpsize;
							c = catsize;
						} else {
							i = itemsize;
						}
					}
				}
			}
		}
	}

	/*
	printf("catdid = 0x%08x, grpdid=0x%08x, itemdid=0x%08x\n", catdid, grpdid, itemdid);
	*/

	/* check to make sure each non-NULL string was found and assigned a did */

	if ( (catname != NULL) && ((catdid == 0UL) || (catdid == P80211DID_INVALID)) ) {
		return P80211DID_INVALID;
	}
	if ( (grpname != NULL) && ((grpdid == 0UL) || (grpdid == P80211DID_INVALID)) ) {
		return P80211DID_INVALID;
	}
	if ( (itemname != NULL) && ((itemdid == 0UL) || (itemdid == P80211DID_INVALID)) ) {
		return P80211DID_INVALID;
	}
	return (catdid | grpdid | itemdid);
}


/*----------------------------------------------------------------
* p80211_text2catdid
*
* Returns the numeric DID value for a category metadata name.
*
* Arguments:
*	list		ptr to a category metadata list
*	name		string containing category name
*
* Returns: 
*	P80211DID_INVALID		no match on name
*	Valid DID		success, returns a valid category DID
----------------------------------------------------------------*/
UINT32 p80211_text2catdid(catlistitem_t *list, char *name )
{
	UINT32		did;
	int		i;
	int		size;

	did = P80211DID_INVALID;
	size = GETMETASIZE(list);

	if ( (list != NULL) && (name != NULL) ) {
		for ( i = 1; i < size; i++ ) {
			if ( strcmp(list[i].name, name ) == 0 ) {
				did = P80211DID_MKSECTION(i);
				break;
			}
		}
	}

	return did;
}


/*----------------------------------------------------------------
* p80211_text2grpdid
*
* Returns the numeric DID value for a group metadata name.
*
* Arguments:
*	list		ptr to a group metadata list
*	name		string containing group name
*
* Returns: 
*	P80211DID_INVALID		no match on name
*	Valid DID		success, returns a valid group DID
----------------------------------------------------------------*/
UINT32 p80211_text2grpdid(grplistitem_t *list, char *name )
{
	UINT32		did;
	int		i;
	int		size;

	did = P80211DID_INVALID;
	size = GETMETASIZE(list);

	if ( (list != NULL) && (name != NULL) ) {
		for ( i = 1; i < size; i++ ) {
			if ( strcmp(list[i].name, name ) == 0 ) {
				did = P80211DID_MKGROUP(i);
				break;
			}
		}
	}

	return did;
}


/*----------------------------------------------------------------
* p80211_text2itemdid
*
* Returns the numeric DID value for an item metadata name.
*
* Arguments:
*	list	ptr to an item metadata list
*	name	string containing item name
*
* Returns: 
*	P80211DID_INVALID		no match on name
*	Valid DID		success, returns a valid item DID
----------------------------------------------------------------*/
UINT32 p80211_text2itemdid(p80211meta_t *list, char *name )
{
	UINT32		did;
	int		i;
	int		size;

	did = P80211DID_INVALID;
	size = GETMETASIZE(list);

	if ( (list != NULL) && (name != NULL) ) {
		for ( i = 1; i < size; i++ ) {
			if ( strcmp(list[i].name, name ) == 0 ) {
				did = list[i].did | P80211DID_MKITEM(i);
				break;
			}
		}
	}

	return did;
}


/*----------------------------------------------------------------
* p80211_isvalid_did
*
* Verifies whether the category, group and item portions of a did
* are valid.
*
* Arguments:
*	catlist		ptr to a category metadata list
*	did		data id
*
* Returns: 
*	P80211DID_INVALID	if DID is an invalid DID
*	!P80211DID_INVALID	if DID is a valid DID
----------------------------------------------------------------*/
INT p80211_isvalid_did( catlistitem_t *catlist, UINT32 did )
{
	int		result;

	result = p80211_isvalid_itemdid( catlist, did );

	return result;
}


/*----------------------------------------------------------------
* p80211_isvalid_catdid
*
* Verifies whether the category portion of a did is valid.
*
* Arguments:
*	catlist		ptr to a category metadata list
*	did		data id
*
* Returns: 
*	P80211DID_INVALID	if DID is an invalid DID
*	!P80211DID_INVALID	if DID is a valid DID
----------------------------------------------------------------*/
INT p80211_isvalid_catdid( catlistitem_t *catlist, UINT32 did )
{
	int		result;
	int		cat;
	int		size;

	result = P80211DID_INVALID;

	cat = P80211DID_SECTION(did);
	size = GETMETASIZE(catlist);

	if ( (cat > 0UL) && (cat < size) ) {
		result = P80211DID_VALID; 
	}

	return result;
}


/*----------------------------------------------------------------
* p80211_isvalid_grpdid
*
* Verifies whether the group portion of a did is valid.
*
* Arguments:
*	catlist		ptr to a category metadata list
*	did		data id
*
* Returns: 
*	P80211DID_INVALID	if DID is an invalid DID
*	!P80211DID_INVALID	if DID is a valid DID
----------------------------------------------------------------*/
INT p80211_isvalid_grpdid( catlistitem_t *catlist, UINT32 did )
{
	int		result;
	int		cat;
	int		grp;
	int		size;

	result = P80211DID_INVALID;

	if ( (result = p80211_isvalid_catdid( catlist, did )) == P80211DID_VALID ) {
		cat = P80211DID_SECTION(did);
		grp = P80211DID_GROUP(did);
		size = GETMETASIZE(catlist[cat].grplist);
		if ( (grp > 0UL) && (grp < size) ) {
			result = P80211DID_VALID; 
		}
	}

	return result;
}


/*----------------------------------------------------------------
* p80211_isvalid_itemdid
*
* Verifies whether the item portion of a did is valid.
*
* Arguments:
*	catlist		ptr to a category metadata list
*	did		data id
*
* Returns: 
*	P80211DID_INVALID	if DID is an invalid DID
*	!P80211DID_INVALID	if DID is a valid DID
----------------------------------------------------------------*/
INT p80211_isvalid_itemdid( catlistitem_t *catlist, UINT32 did )
{
	int		result;
	int		cat;
	int		grp;
	int		item;
	int		size;

	result = P80211DID_INVALID;

	if ( (result = p80211_isvalid_catdid( catlist, did )) == P80211DID_VALID ) {
		if ( (result = p80211_isvalid_grpdid( catlist, did )) == P80211DID_VALID ) {
			cat = P80211DID_SECTION(did);
			grp = P80211DID_GROUP(did);
			size = GETMETASIZE(catlist[cat].grplist[grp].itemlist);
			item = P80211DID_ITEM(did);

			if ( (item > 0UL) && (item < size) ) {
				result = P80211DID_VALID; 
			}
		}
	}

	return result;
}


/*----------------------------------------------------------------
* p80211_did2cat
*
* Returns address of a category in the category metadata list
*
* Arguments:
*	catlist		ptr to a category metadata list
*	did		data id
*
* Returns: 
*	NULL				if DID is an invalid DID
*	ptr to a category list item	if DID is a valid DID
----------------------------------------------------------------*/
catlistitem_t *p80211_did2cat( catlistitem_t *catlist, UINT32 did )
{
	catlistitem_t	*category;
	int		result;

	category = NULL;
	result = P80211DID_INVALID;

	if ( (result = p80211_isvalid_catdid( catlist, did )) == P80211DID_VALID ) {
		category = &(catlist[P80211DID_SECTION(did)]);
	}

	return category;
}	


/*----------------------------------------------------------------
* p80211_did2grp
*
* Returns address of a group in the group metadata list
*
* Arguments:
*	catlist		ptr to a category metadata list
*	did		data id
*
* Returns: 
*	NULL				if DID is an invalid DID
*	ptr to group list item		if DID is a valid DID
----------------------------------------------------------------*/
grplistitem_t *p80211_did2grp( catlistitem_t *catlist, UINT32 did )
{
	grplistitem_t	*group;
	int		result;

	group = NULL;
	result = P80211DID_INVALID;

	if ( (result = p80211_isvalid_catdid( catlist, did )) == P80211DID_VALID ) {
		if ( (result = p80211_isvalid_grpdid( catlist, did )) == P80211DID_VALID ) {
			group = &(catlist[P80211DID_SECTION(did)].
				grplist[P80211DID_GROUP(did)]);
		}
	}

	return group;
}


/*----------------------------------------------------------------
* p80211_did2item
*
* Returns address of an item in the item metadata list
*
* Arguments:
*	catlist		ptr to a category metadata list
*	did		data id
*
* Returns: 
*	NULL				if DID is an invalid DID
*	ptr to item list item		if DID is a valid DID
----------------------------------------------------------------*/
p80211meta_t *p80211_did2item( catlistitem_t *catlist, UINT32 did )
{
	p80211meta_t	*item;
	int		result;

	item = NULL;
	result = P80211DID_INVALID;

	if ( (result = p80211_isvalid_catdid( catlist, did )) == P80211DID_VALID ) {
		if ( (result = p80211_isvalid_grpdid( catlist, did )) == P80211DID_VALID ) {
			if ( (result = p80211_isvalid_itemdid( catlist, did )) == P80211DID_VALID ) {
				item = &(catlist[P80211DID_SECTION(did)].
					grplist[P80211DID_GROUP(did)].
					itemlist[P80211DID_ITEM(did)]);
			}
		}
	}

	return item;
}


/*----------------------------------------------------------------
* p80211item_getoffset
*
*   Returns the offset of the data item identified by a given DID.
*   This function assumes a valid did is passed to the function.  
*
* Arguments:
*	did	a valid, complete DID
*
* Returns: 
*	0xffffffff	if the type from the did doesn't match a 
*			known type
*	offset		on success
----------------------------------------------------------------*/
UINT32 p80211item_getoffset( catlistitem_t *metalist, UINT32 did )
{
	UINT32			catgrp;
	UINT32			offset, len;
	UINT32			tmpdid;
	UINT32			item;
	INT			i;
	p80211meta_t 		*alist=NULL;

	offset = 0UL;

	if ( (p80211_isvalid_did(metalist, did )) != P80211DID_INVALID ) {
		alist = metalist[P80211DID_SECTION(did)].
			grplist[P80211DID_GROUP(did)].itemlist;
		item = P80211DID_ITEM(did);

		catgrp = P80211DID_MKSECTION(P80211DID_SECTION(did)) |
			P80211DID_MKGROUP(P80211DID_GROUP(did));

		for ( i = 1; i < item; i++ ) {
			tmpdid = catgrp | P80211DID_MKITEM(i) | alist[i].did;
			len = p80211item_maxdatalen(metalist, tmpdid);
			if (len == 0xffffffffUL) {
				printf("Undefined data type for %s\n",
					alist[i].name );
				offset = 0xffffffff;
				return offset;
			}
			offset += len + sizeof(p80211item_t);
		} /* for each arg meta data item up to current item */
	} else {
		offset = 0xffffffff;
	}

	return offset;
}


/*----------------------------------------------------------------
* p80211item_gettype
*
* Returns the type of the item identified by a given DID.
*
* Arguments:
*	meta	pointer to a metadata item
*
* Returns: 
*	0		Unrecognized type in metadata.
*	anything else	Success, return value is item type.
----------------------------------------------------------------*/

int p80211item_gettype(p80211meta_t *meta)
{
	int  type;

	if (meta->totextptr == p80211_totext_octetstr)
		type = P80211_TYPE_OCTETSTR;
	else if (meta->totextptr == p80211_totext_displaystr)
		type = P80211_TYPE_DISPLAYSTR;
	else if (meta->totextptr == p80211_totext_int)
		type = P80211_TYPE_INT;
	else if (meta->totextptr == p80211_totext_enumint)
		type = P80211_TYPE_ENUMINT;
	else if (meta->totextptr == NULL ||
		 meta->totextptr == p80211_totext_getmibattribute ||
		 meta->totextptr == p80211_totext_setmibattribute)
		type = P80211_TYPE_UNKDATA;
	else if (meta->totextptr == p80211_totext_intarray)
		type = P80211_TYPE_INTARRAY;
	else if (meta->totextptr == p80211_totext_bitarray)
		type = P80211_TYPE_BITARRAY;
	else if (meta->totextptr == p80211_totext_macarray)
		type = P80211_TYPE_MACARRAY;
	else
		type = 0;

    return type;
}


/*----------------------------------------------------------------
* p80211item_getaccess
*
* Returns the access type (read, write or read-write) of the item
* identified by a given DID.
*
* Arguments:
*	meta	pointer to a metadata item
*
* Returns: 
*	0		Unrecognized access type in metadata.
*	1		Read Only
*	2		Write Only
*	3		Read-Write
----------------------------------------------------------------*/

int p80211item_getaccess(p80211meta_t *meta)
{
	int  access_type;

	access_type = 0;


    return access_type;
}


/*----------------------------------------------------------------
* p80211item_maxdatalen
*
* Returns the total maximum data size of an item identified
* by a given DID.  This is  the length of the data part of the
* item triple.  
*
* Arguments:
*	metalist	pointer to a category metadata list
*	did		A complete DID
*
* Returns: 
*	0xffffffff	Bad DID or unrecognized type in metadata
*	anything else	success, return value is maxdatalen
----------------------------------------------------------------*/
UINT32 p80211item_maxdatalen( catlistitem_t *metalist, UINT32 did )
{
	UINT32		maxlen;
	p80211meta_t 	*meta;

	if ( (meta = p80211_did2item(metalist, did)) != NULL ) {
		switch( p80211item_gettype(meta) ) {
			case P80211_TYPE_OCTETSTR:
				/* add size of pstr length byte */
				maxlen = meta->maxlen + sizeof(UINT8);
				break;
			case P80211_TYPE_DISPLAYSTR:
				/* add size of pstr length byte */
				maxlen = meta->maxlen + sizeof(UINT8);
				break;

			case P80211_TYPE_INT:
			case P80211_TYPE_ENUMINT:
			case P80211_TYPE_BITARRAY:
				/* all int types are 4 bytes */
				maxlen = 4;
				break;

			case P80211_TYPE_INTARRAY:
				/* int types are 4 bytes */
				maxlen = meta->maxlen * 4;
				break;

			case P80211_TYPE_MACARRAY:
				/* Addresses are 6 bytes, add a 4 byte count */
				maxlen = (meta->maxlen * 6) + 4;
				break;

			case P80211_TYPE_UNKDATA:
				maxlen = meta->maxlen;
				break;

			default:
				maxlen = 0xffffffffUL;
		}
	} else {
		maxlen = 0xffffffffUL;
	}

	/* pad for 32-bit aligmnent. */
	if (maxlen != 0xffffffffUL)
		if (maxlen % 4)
			maxlen += (4 - (maxlen % 4));

	return maxlen;
}

/*----------------------------------------------------------------
* p80211_metaname2did
*
* Traverses the metadata looking for an item whose name matches
* the given name.
*
* Arguments:
*	metalist	pointer to a category metadata list
*	itemname	buffer containing the name to search for.
*
* Returns: 
*	0	- name not found
*	~0	- complete DID of item having "itemname"
----------------------------------------------------------------*/
UINT32 p80211_metaname2did(catlistitem_t *metalist, char *itemname)
{
	UINT32	result = 0UL;
	int	sec;
	int	nsec;
	int	grp;
	int	ngrp;
	int	item;
	int	nitem;

	/* traverse the entire metadata for the item that matches */
	nsec = GETMETASIZE(metalist);
	for ( sec = 1; (sec < nsec) && (result == 0); sec++) {
		if ( metalist[sec].grplist == NULL ) continue;
		ngrp = GETMETASIZE(metalist[sec].grplist);
		for ( grp = 1; (grp < ngrp) && (result == 0); grp++) {
			if ( metalist[sec].grplist[grp].itemlist == NULL ) continue;
			nitem = GETMETASIZE(metalist[sec].grplist[grp].itemlist);
			for (item = 1;(item < nitem) && (result == 0);item++) {
				if ( strcmp(itemname, metalist[sec].grplist
					[grp].itemlist[item].name) == 0 ) {

					/* found it */
					result = P80211DID_MKID( sec, grp, item, 0, 0, 0);
					result |= metalist[sec].grplist
					[grp].itemlist[item].did;
				}
			}  /* for all items */
		}  /* for all groups */
	} /*  for all sections */
	return result;
}
