
#include <stdio.h>
#include <config/autoconf.h>

#ifdef __UC_LIBC__
/*
 * Finds a free PTY/TTY pair.
 *
 * This is derived from C.S. Ananian's pty.c that was with his pptp client.
 *
 *************************************************************************
 * pty.c - find a free pty/tty pair.
 *         inspired by the xterm source.
 *         NOTE: This is very likely to be highly non-portable.
 *         C. Scott Ananian <cananian@alumni.princeton.edu>
 *
 * Heavily modified to chage from getpseudopty() to openpty().
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>

/* These are the Linux values - and fairly sane defaults.
 * Since we search from the start and just skip errors, they'll do.
 * Note that Unix98 has an openpty() call so we don't need to worry
 * about the new pty names here.
 */
#define PTYDEV		"/dev/ptyxx"
#define TTYDEV		"/dev/ttyxx"
#define PTYMAX		11
#define TTYMAX		11
#define PTYCHAR1	"pqrstuvwxyzabcde"
#define PTYCHAR2	"0123456789abcdef"

int openpty(int *master, int *slave, char *name, void *unused1, void *unused2)
{
	int devindex = 0, letter = 0;
	int fd1, fd2;
	char ttydev[PTYMAX], ptydev[TTYMAX];

	syslog(LOG_DEBUG, "CTRL: Allocating pty/tty pair");
	strcpy(ttydev, TTYDEV);
	strcpy(ptydev, PTYDEV);
	while (PTYCHAR1[letter]) {
		ttydev[TTYMAX - 3] = ptydev[PTYMAX - 3] = PTYCHAR1[letter];
		while (PTYCHAR2[devindex]) {
			ttydev[TTYMAX - 2] = ptydev[PTYMAX - 2] = PTYCHAR2[devindex];
			if ((fd1 = open(ptydev, O_RDWR)) >= 0) {
				if ((fd2 = open(ttydev, O_RDWR)) >= 0) {
					goto out;
				} else {
					close(fd1);
				}
			}
			devindex++;
		}
		devindex = 0;
		letter++;
	}
	syslog(LOG_ERR, "CTRL: Failed to allocate pty");
	return -1;		/* Unable to allocate pty */

      out:
	syslog(LOG_INFO, "CTRL: Allocated pty/tty pair (%s,%s)", ptydev, ttydev);
	if (master)
		*master = fd1;
	if (slave)
		*slave = fd2;
	if (name)
		strcpy(name, ttydev);	/* no way to bounds check */
	return 0;
}

#endif

