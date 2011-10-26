/*
 * Copyright 1997-2000 by Pawel Krawczyk <kravietz@ceti.pl>
 * Portions copyright 2000 by Jean-Louis Noel <jln@stben.be>
 *
 * See http://www.ceti.com.pl/~kravietz/progs/tacacs.html
 * for details.
 *
 * tac_account_send  Send accounting event information to server.
 */

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <syslog.h>

#include "tacplus.h"
#include "libtac.h"
#include "xalloc.h"

int tac_account_send(int fd, int type, char *user, char *tty, char *rem_addr,
	 struct tac_attrib *attr) {
	HDR *th;
	struct acct tb;
	u_char user_len, port_len;
	u_char rem_addr_len = 0;
	struct tac_attrib *a;
	int i = 0; 	/* arg count */
	int pkt_len = 0;
	int pktl = 0;
	int w; /* write count */
	u_char *pkt;
	int ret = 0;

	th=_tac_req_header(TAC_PLUS_ACCT);

	if(!user || !tty)
			return -1;
	
	/* set header options */
 	th->version=TAC_PLUS_VER_0;
 	th->encryption=tac_encryption ? TAC_PLUS_ENCRYPTED : TAC_PLUS_CLEAR;

	TACDEBUG((LOG_DEBUG, "%s: user '%s', tty '%s', encrypt: %s, type: %s", \
			__FUNCTION__, user, tty, \
			(tac_encryption) ? "yes" : "no", \
			(type == TAC_PLUS_ACCT_FLAG_START) ? "START" : "STOP"))
	
	user_len=(u_char) strlen(user);
	port_len=(u_char) strlen(tty);
	if(rem_addr)
		rem_addr_len=(u_char) strlen(rem_addr);

	tb.flags=(u_char) type;
	tb.authen_method=AUTHEN_METH_TACACSPLUS;
	tb.priv_lvl=TAC_PLUS_PRIV_LVL_MIN;
	tb.authen_type=TAC_PLUS_AUTHEN_TYPE_PAP;
	tb.authen_service=TAC_PLUS_AUTHEN_SVC_PPP;
	tb.user_len=user_len;
	tb.port_len=port_len;
	tb.rem_addr_len=rem_addr_len;

	/* allocate packet */
	pkt=(u_char *) xcalloc(1, TAC_ACCT_REQ_FIXED_FIELDS_SIZE);
	pkt_len=sizeof(tb);

	/* fill attribute length fields */
	a = attr;
	while(a) {
		
		pktl = pkt_len;
		pkt_len += sizeof(a->attr_len);
	    pkt = xrealloc(pkt, pkt_len);

		bcopy(&a->attr_len, pkt + pktl, sizeof(a->attr_len));
		i++;

		a = a->next;
	}

	/* fill the arg count field and add the fixed fields to packet */
	tb.arg_cnt = i;
	bcopy(&tb, pkt, TAC_ACCT_REQ_FIXED_FIELDS_SIZE);

#define PUTATTR(data, len) \
	pktl = pkt_len; \
	pkt_len += len; \
	pkt = xrealloc(pkt, pkt_len); \
	bcopy(data, pkt + pktl, len);

	/* fill user and port fields */
	PUTATTR(user, user_len)
	PUTATTR(tty, port_len)
	if(rem_addr)
		PUTATTR(rem_addr, rem_addr_len)

	/* fill attributes */
	a = attr;
	while(a) {
		PUTATTR(a->attr, a->attr_len)

		a = a->next;
	}

	/* finished building packet, fill len_from_header in header */
	th->datalength = htonl(pkt_len);

	/* write header */
 	w=write(fd, th, TAC_PLUS_HDR_SIZE);

	if(w < TAC_PLUS_HDR_SIZE) {
		syslog(LOG_ERR, "%s: acct hdr send failed: wrote %d of %d",
				__FUNCTION__, w,
				TAC_PLUS_HDR_SIZE);
		ret = -1;
	}
	
	/* encrypt packet body  */
 	_tac_crypt(pkt, th, pkt_len);

	/* write body */
	w=write(fd, pkt, pkt_len);
	if(w < pkt_len) {
		syslog(LOG_ERR, "%s: acct body send failed: wrote %d of %d", 
				__FUNCTION__, w,
				pkt_len);
		ret = -1;
	}

	free(pkt);
	free(th);

	return(ret);
}
