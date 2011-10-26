/*
 * Copyright 1997-2000 by Pawel Krawczyk <kravietz@ceti.pl>
 *
 * See http://www.ceti.com.pl/~kravietz/progs/tacacs.html
 * for details.
 *
 * authen_r.c  Read PAP authentication reply from server.
 */

#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <netinet/in.h>

#include "tacplus.h"
#include "libtac.h"
#include "messages.h"

/* reads packet from TACACS+ server; returns:
 *            NULL    if the authentication succeded
 *  string pointer    if it failed
 */
char *tac_authen_pap_read(int fd) {
 	HDR th;
 	struct authen_reply *tb;
 	int len_from_header, r, len_from_body;
	char *msg = NULL;

 	/* read the reply header */
 	r=read(fd, &th, TAC_PLUS_HDR_SIZE);
 	if(r < TAC_PLUS_HDR_SIZE) {
  		syslog(LOG_ERR,
 			"%s: error reading PAP authen header, read %d of %d: %m",
			__FUNCTION__,
		 	r, TAC_PLUS_HDR_SIZE);
  		return(system_err_msg);
 	}

 	/* check the reply fields in header */
	msg = _tac_check_header(&th, TAC_PLUS_AUTHEN);
	if(msg != NULL)
			return(msg);
 
 	len_from_header=ntohl(th.datalength);
 	tb=(struct authen_reply *) xcalloc(1, len_from_header);

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
 	len_from_body=sizeof(tb->status) + sizeof(tb->flags) +
            sizeof(tb->msg_len) + sizeof(tb->data_len) +
            tb->msg_len + tb->data_len;

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
		bcopy(tb+TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE, msg, tb->msg_len); 
	} else
		msg="Login incorrect";

 	free(tb);

 	/* server authenticated username and password successfully */
 	if(r == TAC_PLUS_AUTHEN_STATUS_PASS) {
		TACDEBUG((LOG_DEBUG, "%s: authentication ok", __FUNCTION__))
		return(NULL);
	}
		
	/* return pointer to server message */
	syslog(LOG_DEBUG, "%s: authentication failed, server reply was %d (%s)", 
					__FUNCTION__, r, msg);
 	return(msg);

} /* tac_authen_pap_read */
