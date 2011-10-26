#ifndef lint
static char rcsid[] = "$Id: md5wrapper.c,v 1.10 1994/07/25 15:46:43 gkim Exp $";
#endif

/*
 * md5wrapper.c
 *
 *	signature function hook for MD5 (the RSA Data Security, Inc. MD5 
 *	Message Digesting Algorithm) for Tripwire.
 *
 *	The original MD5 code is contained in md5.c in its entirety.
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
#include "../../include/sigs.h"
#include "md5.h"
#define BUFSIZE 4096

static MD5_CTX mdbucket;			/* MD5 data structure */

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
sig_md5_get (fd_in, ps_signature, siglen)
    int fd_in;
    char *ps_signature;
    int siglen; 
{
    unsigned char buffer[BUFSIZE];
    int		readin;
    int 	i;
    MD5_CTX	*mdbuf;
    char	s[128];
    FILE *fp;

    mdbuf = &mdbucket;

    ps_signature[0] = '\0';

    /* get stdio handle 
     *		we use dup() so we can close() it later
     */
    if (!(fp = (FILE *) fdopen(dup(fd_in), "rb"))) {
	perror("sig_haval_get: fdopen()");
	exit(1);
    }

    /* rewind the file descriptor */
    rewind(fp);
     
    MD5Init (mdbuf);

    while ((readin = fread(buffer, 1, BUFSIZE, fp)) > 0) { 
	MD5Update(mdbuf, buffer, readin);
    }
    if (readin < 0) {
	perror("sig_md5_get: read()");
	exit(1);
    }
    MD5Final (mdbuf);

    if (printhex) {
	for (i = 0; i < 16; i++) {

#if (TW_TYPE32 == int)
	    sprintf (s, "%02x", mdbuf->digest[i]);
#else
	    sprintf (s, "%02lx", mdbuf->digest[i]);
#endif

	    strcat(ps_signature, s);
	}
    }
    /* base 64 */
    else {
	btob64(mdbuf->digest, ps_signature, 128);
    }

    fclose(fp);
    return 0;
}
