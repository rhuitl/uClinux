#ifndef lint
static char rcsid[] = "$Id: nullsig.c,v 1.12 1994/07/17 04:51:47 gkim Exp $";
#endif

/*
 * nullsig.c
 *
 *	hook for null signature
 *
 * Gene Kim
 * Purdue University
 */

#include "../include/config.h"
#include <stdio.h>
#ifdef STDLIBH
#include <stdlib.h>
#include <unistd.h>
#endif
#if !defined(SYSV) || (SYSV > 3)
# include <sys/file.h>
#else
# include <unistd.h>
#endif 	/* SYSV */
#include <sys/types.h>
#include <sys/stat.h>
#include "../include/tripwire.h"
#include "../include/sigs.h"

#ifndef SEEK_SET
# define SEEK_SET L_SET
#endif

/*
 * int
 * pf_signature(int fd_in, char *ps_signature, int siglen)
 *
 *	fd_in: 		pointer to input file descriptor
 *	ps_signature: 	pointer to array where signature will be stored
 *	siglen: 	length of the signature array (for overflow checking)
 */

int
sig_null_get (fd_in, ps_signature, siglen)
    int fd_in;
    char *ps_signature;
    int siglen;
{
    /* rewind the file descriptor */
    if (lseek(fd_in, 0, SEEK_SET) < 0) {
	die_with_err("sig_null_get: lseek()", (char *) NULL);
    }

    /* lint pacifier */
    siglen += 0;

    sprintf(ps_signature, "0");
    return 0;
}
