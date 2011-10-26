#ifndef lint
static char rcsid[] = "$Id: md2wrapper.c,v 1.8 1994/07/25 15:46:37 gkim Exp $";
#endif

/*
 * md2wrapper.c
 *
 *	signature function hook for MD2 (the RSA Data Security, Inc. MD2 
 *	Message Digesting Algorithm) for Tripwire.
 *
 *	The original MD2 code is contained in md2.c in its entirety.
 *
 * Gene Kim
 * Purdue University
 * September 27, 1992
 */

#include "../../include/config.h"
#include <stdio.h>
#include <sys/types.h>
#ifdef STDLIBH
#include <stdlib.h>
#include <unistd.h>
#endif
#ifdef STRINGH
#include <string.h>
#else
#include <strings.h>
#endif
#include "global.h"
#include "md2.h"
#include "../../include/sigs.h"
#define BUFSIZE 4096

static MD2_CTX mdbucket;			/* MD2 data structure */

char *btob64();

/*
 * int
 * pf_signature(int fd_in, char *ps_signature, int siglen)
 *
 *	fd_in: 		pointer to input file descriptor
 *	ps_signature: 	pointer to array where signature will be stored
 *	siglen: 	length of the signature array (for overflow checking)
 */

int 
sig_md2_get (fd_in, ps_signature, siglen)
    int fd_in;
    char *ps_signature;
    int siglen; 
{
    unsigned char buffer[BUFSIZE];
    int		readin = -1;
    int 	i;
    MD2_CTX	*mdbuf;
    char	s[128];
    unsigned char digest[16];

    mdbuf = &mdbucket;

    ps_signature[0] = '\0';

    /* rewind the file descriptor */
    if (lseek(fd_in, 0, SEEK_SET) < 0) {
	perror("sig_md2_get: lseek()");
	exit(1);
    }
     
    MD2Init (mdbuf);

    while ((readin = read(fd_in, (char *)buffer, (off_t) BUFSIZE)) > 0) {
	MD2Update(mdbuf, buffer, readin);
    }
    if (readin < 0) {
	perror("sig_md2_get: read()");
	exit(1);
    }
    MD2Final (digest, mdbuf);

    if (printhex) {
	for (i = 0; i < 16; i++) {

#if (TW_TYPE32 == int)
	    sprintf (s, "%02x", digest[i]);
#else
	    sprintf (s, "%02lx", digest[i]);
#endif

	    strcat(ps_signature, s);
	}
    }
    /* base 64 */ 
    else {
	btob64(digest, ps_signature, 128);
    }
    return 0;
}
