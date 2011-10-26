#ifndef lint
static char rcsid[] = "$Id: havalwrapper.c,v 1.4 1994/07/25 15:46:35 gkim Exp $";
#endif

/*
 * havalwrapper.c
 *
 *	signature function hook for Haval.
 *
 * Gene Kim
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
#include "havalapp.h"
#include "haval.h"

#define BUFSIZE 1024			/* limit of in-struct buffer size */

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
sig_haval_get (fd_in, ps_signature, siglen)
    int fd_in;
    char *ps_signature;
    int siglen; 
{
    unsigned char buffer[BUFSIZE];
    int		readin = -1;
    int 	i;
    haval_state state;
    FILE	*fp;
    unsigned char fingerprint[1024];
    int numbytes = FPTLEN >> 3;

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
    haval_start(&state);

    while ((readin = fread(buffer, 1, BUFSIZE, fp)) > 0) { 
	haval_hash(&state, buffer, readin);
    }
    if (readin < 0) {
	perror("sig_haval_get: fread()");
	exit(1);
    }
    haval_end(&state, fingerprint);

    if (printhex) {
	char *pc = ps_signature;
	for (i = 0; i < numbytes; i++) {
	    sprintf(pc, "%02x", fingerprint[i] & 0xff);
	    pc += 2;
	}
	*pc = '\0';
    } else {
	btob64(fingerprint, ps_signature, numbytes * 8);
    }

    fclose(fp);

    return 0;
}

