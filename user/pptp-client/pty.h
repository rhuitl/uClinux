
#include <stdio.h>
#include <config/autoconf.h>

#define PTYMAX  32
#define TTYMAX  32

#ifndef __UC_LIBC__
#include <pty.h>
#else
/* pty.h ....... find a free pty/tty pair.  
 *               Inspired/stolen from the xterm source.
 *               NOTE: This is very likely to be highly non-portable.
 *               C. Scott Ananian <cananian@alumni.princeton.edu>
 *
 * $Id: pty.h,v 1.3 2004-06-21 03:07:24 davidm Exp $
 */

/* Hmm.  PTYs can be anywhere.... */

#ifdef __linux__
#define PTYDEV	"/dev/ptyxx"
#define TTYDEV	"/dev/ttyxx"

#define PTYCHAR1	"abcdepqrstuvwxyz"
#define PTYCHAR2	"0123456789abcdef"
#endif

/* Get pty/tty pair, put filename in ttydev, ptydev (which must be
 * at least PTYMAX characters long), and return file descriptor of
 * open pty.
 * Return value < 0 indicates failure.
 */
int openpty(int *master,int *slave,char *ttydev,void *unused1,void *unused2);

#endif /* __UC_LIBC__ */
