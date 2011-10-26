#ifndef lint
static char rcsid[] = "$Id: md4wrapper.c,v 1.8 1994/07/25 15:46:41 gkim Exp $";
#endif

/*
 * md4wrapper.c
 *
 *	signature function hook for MD4 (the RSA Data Security, Inc. MD4 
 *	Message Digesting Algorithm) for Tripwire.
 *
 *	The original MD4 code is contained in md4.c in its entirety.
 *
 * Gene Kim
 * Purdue University
 * October 14, 1992 
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
#include "md4.h"
#define BUFSIZE 64			/* limit of in-struct buffer size */

static MDstruct mdbucket;			/* MD4 data structure */

extern void MDsprint(), MDsprint64();

/*
 * int
 * pf_signature(int fd_in, char *ps_signature, int siglen)
 *
 *	fd_in: 		pointer to input file descriptor
 *	ps_signature: 	pointer to array where signature will be stored
 *	siglen: 	length of the signature array (for overflow checking)
 */

int 
sig_md4_get (fd_in, ps_signature, siglen)
    int fd_in;
    char *ps_signature;
    int siglen; 
{
    unsigned char buffer[BUFSIZE];
    int		readin = -1;
    MDstruct	*mdbuf;
    FILE	*fp;

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
     
    MDbegin (mdbuf);

    while ((readin = fread(buffer, 1, BUFSIZE, fp)) > 0) { 
	MDupdate(mdbuf, buffer, readin*8);
    }
    if (readin < 0) {
	perror("sig_md4_get: read()");
	exit(1);
    }
    MDupdate(mdbuf, buffer, (unsigned)readin);

    if (printhex) {
	MDsprint(ps_signature, mdbuf);
    } else {
	MDsprint64(ps_signature, mdbuf);
    }

    fclose(fp);
    return 0;
}
