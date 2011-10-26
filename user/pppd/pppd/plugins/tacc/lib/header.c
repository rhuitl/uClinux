/*
 * Copyright 1997-2000 by Pawel Krawczyk <kravietz@ceti.pl>
 *
 * See http://www.ceti.com.pl/~kravietz/progs/tacacs.html
 * for details.
 *
 * header.c  Create pre-filled header for TACACS+ request.
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/param.h>
#include "tacplus.h"
#include "libtac.h"
#include "xalloc.h"
#include "magic.h"

/* Miscellaneous variables that are global, because we need
 * store their values between different functions and connections.
 */
/* Session identifier. */
int session_id;

/* Encryption flag. */
int tac_encryption;

/* Pointer to TACACS+ shared secret string. */
char *tac_secret;

/* Returns pre-filled TACACS+ packet header of given type.
 * 1. you MUST fill th->datalength and th->version
 * 2. you MAY fill th->encryption
 * 3. you are responsible for freeing allocated header 
 * By default packet encryption is enabled. The version
 * field depends on the TACACS+ request type and thus it
 * cannot be predefined.
 */
HDR *_tac_req_header(u_char type) {
 	HDR *th;

 	th=(HDR *) xcalloc(1, TAC_PLUS_HDR_SIZE);

 	/* preset some packet options in header */
 	th->type=type;
 	th->seq_no=1; /* always 1 for request */
 	th->encryption=TAC_PLUS_ENCRYPTED;
 
 	/* make session_id from pseudo-random number */
 	session_id = magic();
 	th->session_id = htonl(session_id);

 	return(th);
}
