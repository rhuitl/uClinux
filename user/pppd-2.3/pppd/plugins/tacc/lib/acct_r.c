/*
 * Copyright 1997-2000 by Pawel Krawczyk <kravietz@ceti.pl>
 *
 * See http://www.ceti.com.pl/~kravietz/progs/tacacs.html
 * for details.
 *
 * tac_account_read  Read accounting reply from server.
 */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <netinet/in.h>

#include "tacplus.h"
#include "libtac.h"
#include "messages.h"

char *tac_account_read(int fd) {
	HDR th;
	struct acct_reply *tb;
	int len_from_header, r, len_from_body;
	char *msg = NULL;

	r=read(fd, &th, TAC_PLUS_HDR_SIZE);
	if(r < TAC_PLUS_HDR_SIZE) {
  		syslog(LOG_ERR,
 			"%s: short PAP acct header, %d of %d: %m", __FUNCTION__,
		 	r, TAC_PLUS_HDR_SIZE);
  		return(system_err_msg);
 	}

 	/* check the reply fields in header */
	msg = _tac_check_header(&th, TAC_PLUS_ACCT);
	if(msg != NULL) 
			return(msg);

 	len_from_header=ntohl(th.datalength);
 	tb=(struct acct_reply *) xcalloc(1, len_from_header);

 	/* read reply packet body */
 	r=read(fd, tb, len_from_header);
 	if(r < len_from_header) {
  		syslog(LOG_ERR,
			 "%s: incomplete message body, %d bytes, expected %d: %m",
			 __FUNCTION__,
			 r, len_from_header);
  		return(system_err_msg);
 	}

 	/* decrypt the body */
 	_tac_crypt((u_char *) tb, &th, len_from_header);

 	/* check the length fields */
 	len_from_body=sizeof(tb->msg_len) + sizeof(tb->data_len) +
            sizeof(tb->status) + tb->msg_len + tb->data_len;

 	if(len_from_header != len_from_body) {
  		syslog(LOG_ERR,
			"%s: invalid reply content, incorrect key?",
			__FUNCTION__);
  		return(system_err_msg);
 	}

 	/* save status and clean up */
 	r=tb->status;
	if(tb->msg_len) {
		msg=(char *) xcalloc(1, tb->msg_len);
		bcopy(tb+TAC_ACCT_REPLY_FIXED_FIELDS_SIZE, msg, tb->msg_len); 
	} else
		msg="Accounting failed";

 	free(tb);

 	/* server logged our request successfully */
	if(r == TAC_PLUS_ACCT_STATUS_SUCCESS) {
		TACDEBUG((LOG_DEBUG, "%s: accounted ok", __FUNCTION__))
		return(NULL);
	}
	/* return pointer to server message */
	syslog(LOG_DEBUG, "%s: accounting failed, server reply was %d (%s)", 
					__FUNCTION__, r, msg);
 	return(msg);

}
