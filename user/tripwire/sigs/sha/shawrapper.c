#ifndef lint
static char rcsid[] = "$Id: shawrapper.c,v 1.6 1994/07/25 15:46:48 gkim Exp $";
#endif

/*
 * shawrapper.c
 *
 *	signature function hook for SHA for Tripwire.
 *
 *	The original SHA code is contained in sha.c in its entirety.
 *
 * Gene Kim
 * Purdue University
 * August 10, 1993
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
#include "sha.h"

char *pltob64();

/*
 * int
 * pf_signature(int fd_in, char *ps_signature, int siglen)
 *
 *	fd_in: 		pointer to input file descriptor
 *	ps_signature: 	pointer to array where signature will be stored
 *	siglen: 	length of the signature array (for overflow checking)
 */


#define BLOCKSIZE 		SHS_BLOCKSIZE

int 
sig_sha_get (fd_in, ps_signature, siglen)
    int fd_in;
    char *ps_signature;
    int siglen; 
{
    SHS_INFO shsInfo;
    unsigned char buffer[BLOCKSIZE];
    int readin = -1;
    int i;
    char s[128];
    FILE *fp;
    extern void shsInit(), shsUpdate(), shsFinal();

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
     
    shsInit( &shsInfo );

    while ((readin = fread((char *)buffer, 1, BLOCKSIZE, fp)) == BLOCKSIZE) {
	shsUpdate(&shsInfo, buffer, readin);
    }
    if (readin < 0) {
	perror("sig_sha_get: read()");
	exit(1);
    }
    if (readin >= 0) {
	shsUpdate(&shsInfo, buffer, readin);
    }


    shsFinal( &shsInfo );

    /* print out the signature */
    if (printhex) {
	for (i = 0; i < 5; i++) {
#if (TW_TYPE32 == int)
	    sprintf(s, "%08x", shsInfo.digest[i]); 
#else
	    sprintf(s, "%08lx", shsInfo.digest[i]); 
#endif
	    strcat(ps_signature, s);
	}
    }
    /* base 64 */
    else {
	pltob64(shsInfo.digest, ps_signature, 5);
    }

    fclose(fp);

    return 0;
}
