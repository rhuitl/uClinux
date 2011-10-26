/* src/wlanctl/wlanctl.c
*
* user utility for the wlan card
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
#include <unistd.h>

/* Ugly hack for LinuxPPC R4, don't have time to figure it out right now */
#if defined(__WLAN_PPC__)
#undef __GLIBC__
#endif

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

/*================================================================*/
/* Project Includes */

#include <wlan/wlan_compat.h>
#include <wlan/version.h>
#include <wlan/p80211types.h>
#include <wlan/p80211meta.h>
#include <wlan/p80211metamsg.h>
#include <wlan/p80211msg.h>
#include <wlan/p80211ioctl.h>
#include "wlanctl.h"

/*================================================================*/
/* Local Constants */

/*================================================================*/
/* Local Macros */


/*================================================================*/
/* Local Types */


/*================================================================*/
/* Local Static Definitions */

char	*devname;

char	*cmdcats[] = {
	"dot11req",
	"lnxreq",
	"p2req"
};

static int debug = 0;

/*================================================================*/
/* Local Function Declarations */

INT	cmdline2requestmsg( UINT8 *msg, UINT32 msgcode, int argc, char **argv );
void	printmsg( UINT8 *msg, UINT32 msgcode );
void	sim_ioctl( UINT8 *msg, UINT32 msgcode );
int	do_ioctl( UINT8 *msg, UINT32 msgcode );
void	dump_msg(void *msg);

/*================================================================*/
/* Function Definitions */


/*----------------------------------------------------------------
* main
*
* wlanctl-ng entry point.
*
* Arguments:
*	argc	number of command line arguments
*	argv	array of argument strings
*
* Returns: 
*	0	- success 
*	~0	- failure
----------------------------------------------------------------*/
int main ( int argc, char **argv )
{
	UINT8	message[MSG_BUFF_LEN];
	UINT32	msgcode = P80211DID_INVALID;
	INT	result = 0;
	INT	i;

	if ( argc < 4 && argc >= 2 && strcmp( argv[1], "version") == 0) {
		printf("wlanctl-ng: %s\n", WLAN_RELEASE);			
	}
	else if ( argc < 4 && argc >= 2 && strcmp( argv[1], "commands") == 0) {
		print_allrequests();			
	}
	else if ( argc < 4 && argc >= 2 && strcmp( argv[1], "mibs") == 0) {
		print_allmibs();			
	}
	else if ( argc <  3 ) {
		usage();
	} else {
		/* stuff the device name in a global */
		devname = argv[1];

		/* returns P80211DID_INVALID no match */
		for ( i = 0; i < sizeof(cmdcats)/sizeof(cmdcats[0]); i++) {
			msgcode = p80211_text2did(msg_catlist, 
					cmdcats[i], argv[2], NULL);
			if ( msgcode != P80211DID_INVALID ) {
				break;
			}
		}

		if (msgcode != P80211DID_INVALID) { /* msgcode valid */
			result = cmdline2requestmsg( message, msgcode, argc, argv );

			if ( result == 0 ) {
				if ( (result = do_ioctl( message, msgcode )) == 0 ){
				printmsg( message, msgcode );
				}
			} else {
				printmsg( message, msgcode );
/*
				printf("Message \"%s\" was unable to be created\n", argv[2]);
*/
			}
		} else { /* msgcode invalid */
			printf("The cmd \'%s\' is invalid\n", argv[2]);
			result=msgcode;
		} 
	}

	return(result);
}


/*----------------------------------------------------------------
* do_ioctl
*
* TODO: describe
*
* Arguments:
*	argc	number of command line arguments
*	argv	array of argument strings
*
* Returns: 
*	0	- success 
*	~0	- failure
----------------------------------------------------------------*/
int do_ioctl( UINT8 *msg, UINT32 msgcode )
{
	int			result = -1;
	int			fd;
	p80211ioctl_req_t	req;

	/* set the magic */
	req.magic = P80211_IOCTL_MAGIC;

	/* get a socket */
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if ( fd == -1 ) {
		perror("wlanctl-ng");
		return result;
	}

	req.len = MSG_BUFF_LEN;		/* TODO: need to fix the length */
	req.data = msg;
	strcpy( req.name, devname);
	req.result = 0;

	if ( debug ) {
		fprintf(stderr, "raw msg before ioctl:\n");
		dump_msg(msg);
	}

	result = ioctl( fd, P80211_IFREQ, &req);

	if ( debug ) {
		fprintf(stderr, "raw msg after ioctl:\n");
		dump_msg(msg);
	}

	if ( result == -1 ) {
		perror("wlanctl-ng");
	}
	close(fd);
	return result;
}


void dump_msg(void *msg)
{
	p80211msgd_t	*msgp = msg;
	int 		i;
	int		bodylen;

	fprintf(stderr, "  msgcode=0x%08lx  msglen=%lu  devname=%s\n",
			msgp->msgcode, msgp->msglen, msgp->devname);
	fprintf(stderr, "body: ");
	bodylen=msgp->msglen - 
		(sizeof(msgp->msgcode) +
		 sizeof(msgp->msglen) +
		 sizeof(msgp->devname));
	for ( i = 0; i < bodylen; i+=4) {
		fprintf(stderr, "%02x%02x%02x%02x ", 
			msgp->args[i], msgp->args[i+1], 
			msgp->args[i+2], msgp->args[i+3]);
	}
	fprintf(stderr,"\n");
}

/*----------------------------------------------------------------
* cmdline2requestmsg
*
* Default command line to request message converter.  Takes the
* command (request) code and the cmdline arguments, compares them
* to the metadata for the request arguments for the given request
* and if all required arguments are present and valid, builds a
* message structure.  This function handles the general case.
*
* Arguments:
*	msg	buffer to build msg in (assumed to be at least MSG_BUFF_LEN bytes)
*	msgcode	partial did containing category and group indices
*	argc	number of command line arguments
*	argv	array of argument strings
*
* Returns: 
*	0	- success 
*	~0	- failure
----------------------------------------------------------------*/
INT cmdline2requestmsg( UINT8 *msg, UINT32 msgcode, int argc, char **argv )
{
	UINT8		*cmdlinelist;
	UINT8		*msgptr;
	UINT8		*start;
	UINT8		tmpitem[MSG_BUFF_LEN];
	p80211meta_t	*alist = NULL;
	grplistitem_t	*grp = NULL;
	INT		found;
	INT		i;
	INT		j;
	INT32		narg;
	UINT32		tmpdid;
	size_t		itemlen;
	size_t		offset;

	/* Create an array of bytes where each byte represents a flag for
	each command line argument.  For each argument on the command line
	following the msg code, the repsective byte will contain either
	a 0 (for not found) or 1 (found) after an attempt to match the 
	command line argument to one of the metadata arguments for the
	user entered 'valid' msg, such as 'scan' or 'powermgmt'. */

	if ( (cmdlinelist = (UINT8 *)malloc(argc)) == NULL ) {
		printf("wlanctl-ng: cmdlinelist memory allocation failed\n");
		return 1;
	}

	/* initialize all the bytes to 0 for not found */
	memset( cmdlinelist, 0, argc);
	memset( msg, 0, MSG_BUFF_LEN);
	memset( tmpitem, 0, MSG_BUFF_LEN);

	((p80211msg_t *)msg)->msgcode = msgcode;
	strncpy(((p80211msg_t *)msg)->devname, devname,
		WLAN_DEVNAMELEN_MAX - 1 );
	((p80211msg_t *)msg)->msglen = sizeof(p80211msg_t);

	start = msg + sizeof( p80211msg_t );
	msgptr = start;

	/* acquire the msg argument metadata list */
	if ( (grp = p80211_did2grp(msg_catlist, msgcode)) != NULL ) {
		alist = grp->itemlist;
		narg = GETMETASIZE(alist);
	} else {
		printf("wlanctl-ng: Invalid msgcode of %u\n", (unsigned int)msgcode);
		free( cmdlinelist );
		return 1;
	}

	/*
	printf("The cmd %s is valid with a code of 0x%08lx\n", 
		argv[2], msgcode);
	printf("   argc=%d, narg is %lu\n", argc, narg);
	*/

	/* Loop through the metadata for all the arguments of the message
	and initialize the did, the len and set the status to
	status code of "no value" (i.e. the data isn't set) */

	for ( i = 1; i < narg; i++) {
		tmpdid = msgcode | P80211DID_MKITEM(i) | alist[i].did;

		if ( (offset = p80211item_getoffset(msg_catlist, tmpdid)) !=
			0xffffffff ) {

			msgptr = start + offset;

			((p80211item_t *)msgptr)->did = tmpdid;
			((p80211item_t *)msgptr)->status =
				(short)P80211ENUM_msgitem_status_no_value;
			if ( (((p80211item_t *)msgptr)->len =
				(short)(p80211item_maxdatalen(msg_catlist,
					tmpdid))) != 0xffffffffUL ) {
				((p80211msg_t *)msg)->msglen +=
					( sizeof(p80211item_t) + 
					((p80211item_t *)msgptr)->len );
			} else {
				printf("wlanctl-ng: invalid data length for %s\n",
					alist[i].name);
				free( cmdlinelist );
				return 1;
			}
		} else {
			printf("wlanctl-ng: [1] error creating offset for %s\n",
				alist[i].name);
			free( cmdlinelist );
			return 1;
		}
	}

	/* Build message in the same order as the metadata argument list by
	by looping through msg arg metadata, args always start at index 1 */

	msgptr = start;

	for ( i = 1; i < narg; i++) {
		found = 0;
		tmpdid = msgcode | P80211DID_MKITEM(i) | alist[i].did;

		if ( (offset = p80211item_getoffset(msg_catlist, tmpdid)) !=
			0xffffffff ) {
			/*
			printf("cmdline2request: "
				"curr meta data item %s: "
				"offset=%d\n", alist[i].name, offset);
			*/
			msgptr = start + offset;
		} else {
			printf("wlanctl-ng: [2] error creating offset for %s\n",
				alist[i].name);
			free( cmdlinelist );
			return 1;
		}

		/* loop through msg arguments on cmdline */
		for ( j = 3; (j < argc) && (!found); j++) {
			/* does meta match cmdline arg? */
			if ( strncmp(alist[i].name,argv[j],
				strlen(alist[i].name)) == 0 ) {

				if ( P80211ITEM_ISREQUEST(alist[i].flags) ) {
					found = 1;
					cmdlinelist[j] = (UINT8)1;

					if ( alist[i].fromtextptr != NULL ) {
						(*(alist[i].fromtextptr))
						(msg_catlist, tmpdid, tmpitem, argv[j]);
					}

					itemlen = sizeof(p80211item_t) +
						p80211item_maxdatalen(msg_catlist, tmpdid);

					memcpy(msgptr, tmpitem, itemlen);

				} else {
					printf("non-request argument found on cmdline.\n");
					free( cmdlinelist );
					return 1;
				}
			} /* if cmdline match */
		} /* for each cmdline arg */

	} /* for each msg argument metadata */

	/* Loop through the built message and check the status field.
	For required request arguments, the status must be "data ok"
	or it's an error.  If the status code is "no value", the
	argument can not be a required request argument; otherwise,
	it's an error.  Any other status code is an error. */

	msgptr = start;

	for ( i = 1; i < narg; i++) {
		if ( ((p80211item_t *)msgptr)->status >
				(short)P80211ENUM_msgitem_status_no_value ) {

			p80211_error2text( ((p80211item_t *)msgptr)->status,
				tmpitem );
			printf("%s=\"%s\"\n", alist[i].name, tmpitem);
			free( cmdlinelist );
			return 1;
		} else if ( ((p80211item_t *)msgptr)->status == 
				(short)P80211ENUM_msgitem_status_no_value ) {
			if ( (P80211ITEM_ISREQUIRED(alist[i].flags)) &&
				(P80211ITEM_ISREQUEST(alist[i].flags)) )
			{
				printf("The required argument \'%s\' has no value.\n", alist[i].name);
				free( cmdlinelist );
				return 1;
			}
		}

		msgptr += (sizeof(p80211item_t) + ((p80211item_t *)msgptr)->len);
	}

	/* check to see that each message argument on the command line was */
	/* matched to an argument metadata for the message */
	for ( j = 3; j < argc; j++) {
		if ( !(cmdlinelist[j]) ) {
			printf("\'%s\' entered on the command line "
				"was either an invalid\n" 
				"argument to the cmd \'%s\' or an extra "
				"occurence of a valid argument.\n",
			       argv[j], argv[2]);
			free( cmdlinelist );
			return 1;
		}
	}

	free( cmdlinelist );
	return 0;
}


/*----------------------------------------------------------------
* printmsg
*
* Traverse the message items printing each.
*
* Arguments:
*	msg	buffer containing a complete msg
*	msgcode	integer identifying the msg
*
* Returns: 
*	0	- success 
*	~0	- failure
----------------------------------------------------------------*/
void printmsg( UINT8 *msg, UINT32 msgcode )
{
	UINT8			tmpitem[MSG_BUFF_LEN];
	UINT8			*msgptr;
	UINT8			*start;
	INT			i;
	grplistitem_t		*grp;
	UINT32			narg;
	UINT32			offset;
	UINT32			tmpdid;
	p80211meta_t		*alist;


	msgptr = msg;

	/* acquire the msg argument metadata list */
	if ( (grp = p80211_did2grp(msg_catlist, msgcode)) != NULL ) {
		alist = grp->itemlist;
		narg = GETMETASIZE(alist);
	} else {
		printf("wlanctl-ng: Invalid msgcode of %u\n", (unsigned int)msgcode);
		return;
	}

	/* print the message code */
	printf("message=%s\n", grp->name);

	start =  msg + sizeof(p80211msg_t);

	for ( i = 1; i < narg; i++ ) {
		tmpdid = msgcode | P80211DID_MKITEM(i) | alist[i].did;
		offset = p80211item_getoffset(msg_catlist, tmpdid);
		msgptr = start + offset;
		
		/* pass tmpdid since the 'totext' functions */
		/* expect a non-zero did */
		if ( ((p80211item_t *)msgptr)->status ==
			P80211ENUM_msgitem_status_data_ok ) {
			if ( alist[i].totextptr != NULL ) {
				(*(alist[i].totextptr))
					( msg_catlist, tmpdid, msgptr, tmpitem);
				printf("  %s\n", tmpitem);
			} else {
				p80211_error2text(
					P80211ENUM_msgitem_status_missing_print_func,
					tmpitem);
				printf("  %s=%s\n", alist[i].name, tmpitem);
			}
		} else {
			p80211_error2text( ((p80211item_t *)msgptr)->status,
				tmpitem);
			printf("  %s=%s\n", alist[i].name, tmpitem);
		}

	} /* for each argument in the metadata */
}
