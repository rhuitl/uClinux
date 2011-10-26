/*
 * Copyright 1997-2000 by Pawel Krawczyk <kravietz@ceti.pl>
 *
 * See http://www.ceti.com.pl/~kravietz/progs/tacacs.html
 * for details.
 *
 * authen_s.c  Send PAP authentication request to the server.
 */

#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <syslog.h>
#include <string.h>

#include "tacplus.h"
#include "libtac.h"

/* this function sends a packet do TACACS+ server, asking
 * for validation of given username and password
 */
int tac_authen_pap_send(int fd, char *user, char *pass, char *tty)
{
 	HDR *th; 		 /* TACACS+ packet header */
 	struct authen_start tb; /* message body */
 	int user_len, port_len, pass_len, bodylength, w;
 	int pkt_len=0;
 	u_char *pkt;
	int ret=0;

 	th=_tac_req_header(TAC_PLUS_AUTHEN);

 	/* set some header options */
 	th->version=TAC_PLUS_VER_1;
 	th->encryption=tac_encryption ? TAC_PLUS_ENCRYPTED : TAC_PLUS_CLEAR;

	TACDEBUG((LOG_DEBUG, "%s: user '%s', pass '%s', tty '%s', encrypt: %s", \
		 __FUNCTION__, user, pass, tty, \
	 	(tac_encryption) ? "yes" : "no"))	 
	
 	/* get size of submitted data */
 	user_len=strlen(user);
 	port_len=strlen(tty);
 	pass_len=strlen(pass);

 	/* fill the body of message */
 	tb.action=TAC_PLUS_AUTHEN_LOGIN;
 	tb.priv_lvl=TAC_PLUS_PRIV_LVL_MIN;
 	tb.authen_type=TAC_PLUS_AUTHEN_TYPE_PAP;
 	tb.service=TAC_PLUS_AUTHEN_SVC_PPP;
 	tb.user_len=user_len;
 	tb.port_len=port_len;
 	tb.rem_addr_len=0;          /* may be e.g Caller-ID in future */
 	tb.data_len=pass_len;

 	/* fill body length in header */
 	bodylength=sizeof(tb) + user_len
		+ port_len + pass_len; /* + rem_addr_len */

 	th->datalength= htonl(bodylength);

 	/* we can now write the header */
 	w=write(fd, th, TAC_PLUS_HDR_SIZE);
	if(w < 0 || w < TAC_PLUS_HDR_SIZE) {
		syslog(LOG_ERR, "%s: short write on PAP header: wrote %d of %d: %m", 
						__FUNCTION__, w, TAC_PLUS_HDR_SIZE);
		ret=-1;
	}

 	/* build the packet */
 	pkt=(u_char *) xcalloc(1, bodylength+10);

 	bcopy(&tb, pkt+pkt_len, sizeof(tb)); /* packet body beginning */
 	pkt_len+=sizeof(tb);
 	bcopy(user, pkt+pkt_len, user_len);  /* user */
 	pkt_len+=user_len;
 	bcopy(tty, pkt+pkt_len, port_len);   /* tty */
 	pkt_len+=port_len;
 	bcopy(pass, pkt+pkt_len, pass_len);  /* password */
 	pkt_len+=pass_len;

 	/* pkt_len == bodylength ? */
	if(pkt_len != bodylength) {
		TACDEBUG((LOG_DEBUG, "tac_authen_send: bodylength %d != pkt_len %d", bodylength, pkt_len));
	} 
 	
	/* encrypt the body */
 	_tac_crypt(pkt, th, bodylength);

 	w=write(fd, pkt, pkt_len);
	if(w < 0 || w < pkt_len) {
		syslog(LOG_ERR, "%s: short write on PAP body: wrote %d of %d: %m",
					   __FUNCTION__, w, pkt_len);
		ret=-1;
	}

 	free(pkt);
 	free(th);

 	return(ret);
} /* tac_authen_pap_send */
