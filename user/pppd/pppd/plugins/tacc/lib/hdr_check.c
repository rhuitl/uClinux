/*
 * Copyright 1997-2000 by Pawel Krawczyk <kravietz@ceti.pl>
 *
 * See http://www.ceti.com.pl/~kravietz/progs/tacacs.html
 * for details.
 *
 * hdr_check.c  Perform basic sanity checks on received packet.
 */

#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "tacplus.h"
#include "messages.h"
#include "libtac.h"

/* Checks given reply header for possible inconsistencies:
 *  1. reply type other than expected
 *  2. sequence number other than 2
 *  3. session_id different from one sent in request
 * Returns pointer to error message
 * or NULL when the header seems to be correct
 */
char *_tac_check_header(HDR *th, int type) {

 	if(th->type != type) {
  		syslog(LOG_ERR,
			 "%s: unrelated reply, type %d, expected %d", 
			 __FUNCTION__, th->type, type);
  		return(protocol_err_msg);
 	} else if(th->seq_no != 2) {
  		syslog(LOG_ERR, "%s: not a reply - seq_no %d != 2", 
						__FUNCTION__, th->seq_no);
  		return(protocol_err_msg);
 	} else if(ntohl(th->session_id) != session_id) {
  		syslog(LOG_ERR, 
			"%s: unrelated reply, received session_id %d != sent %d",
			__FUNCTION__, ntohl(th->session_id), session_id);
  		return(protocol_err_msg);
 	}
	
	return(NULL); /* header is ok */	

} /* check header */
