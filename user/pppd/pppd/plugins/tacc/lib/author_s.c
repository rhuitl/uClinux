/*
 * Copyright 1997-2000 by Pawel Krawczyk <kravietz@ceti.pl>
 *
 * See http://www.ceti.com.pl/~kravietz/progs/tacacs.html
 * for details.
 *
 * author_s.c  Send authorization request to the server.
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <netinet/in.h>
#include <sys/param.h>

#include "tacplus.h"
#include "libtac.h"
#include "xalloc.h"

/* Send authorization request to the server, along with attributes
   specified in attribute list prepared with tac_add_attrib.
*/
int tac_author_send(int fd, char *user, char *tty, struct tac_attrib *attr) {
	HDR *th;
	struct author tb;
	u_char user_len, port_len;
	struct tac_attrib *a;
	int i = 0; 			/* attributes count */
	int pkt_len = 0; 	/* current packet length */
	int pktl = 0;		/* temporary storage for previous pkt_len values */
	int w; 				/* write() return value */
	u_char *pkt;		/* packet building pointer */
	int ret = 0;

	th=_tac_req_header(TAC_PLUS_AUTHOR);

	/* set header options */
 	th->version=TAC_PLUS_VER_0;
 	th->encryption=tac_encryption ? TAC_PLUS_ENCRYPTED : TAC_PLUS_CLEAR;

	TACDEBUG((LOG_DEBUG, "%s: user '%s', tty '%s', encrypt: %s", \
		       	__FUNCTION__, user, \
			tty, tac_encryption ? "yes" : "no"))
	
	user_len=(u_char) strlen(user);
	port_len=(u_char) strlen(tty);

	tb.authen_method=AUTHEN_METH_TACACSPLUS;
	tb.priv_lvl=TAC_PLUS_PRIV_LVL_MIN;
	tb.authen_type=TAC_PLUS_AUTHEN_TYPE_PAP;
	tb.service=TAC_PLUS_AUTHEN_SVC_PPP;
	tb.user_len=user_len;
	tb.port_len=port_len;
	tb.rem_addr_len=0;

	/* allocate packet */
	pkt=(u_char *) xcalloc(1, TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE);
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
	bcopy(&tb, pkt, TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE);

#define PUTATTR(data, len) \
	pktl = pkt_len; \
	pkt_len += len; \
	pkt = xrealloc(pkt, pkt_len); \
	bcopy(data, pkt + pktl, len);

	/* fill user and port fields */
	PUTATTR(user, user_len)
	PUTATTR(tty, port_len)

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
		syslog(LOG_ERR, "%s: author hdr send failed: wrote %d of %d", 
				__FUNCTION__, w,
				TAC_PLUS_HDR_SIZE);
		ret = -1;
	}
	
	/* encrypt packet body  */
 	_tac_crypt(pkt, th, pkt_len);

	/* write body */
	w=write(fd, pkt, pkt_len);
	if(w < pkt_len) {
		syslog(LOG_ERR, "%s: author body send failed: wrote %d of %d", 
				__FUNCTION__, w,
				pkt_len);
		ret = -1;
	}

	free(pkt);
	free(th);

	return(ret);
}
