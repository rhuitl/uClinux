/*
  Author: Benoit PAPILLAULT <benoit.papillault@free.fr>
  Creation: 01/02/2002

  Goal: test if the HDLC support is ok and if the HDLC bug is corrected or not.

  Note: pppd has the slave side of /dev/ptmx. pppoeci has the master side of
  /dev/ptmx (ie /dev/ptmx itself). The bug is that closing the slave side
  has no effect on the master side.

  03/02/2002: added a signal handler for SIGALRM.
    added support for /dev/ptyXX. There was previously only /dev/ptmx
*/

#define _XOPEN_SOURCE /* for grantpt in <stdlib.h> */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>

/* for ident(1) command */
static const char id[] =
	"@(#) $Id: check-hdlc-bug.c,v 1.1 2002/02/21 20:47:23 papillau Exp $";

int get_master_slave_ptmx(int *master, int *slave)
{
	const char *pts;

	/* try to open the master side, using /dev/ptmx */
	*master = open("/dev/ptmx",O_RDWR);
	if (*master < 0)
		return -1;

	/* open the slave side */
	grantpt(*master);
	unlockpt(*master);
	pts = ptsname(*master);

	*slave = open(pts,O_RDWR|O_NOCTTY);
	if (*slave < 0)
		return -1;

	/* gotcha! */
	return 0;
}

int get_master_slave_pty(int *master, int *slave)
{
	int i;
	char pty_name[50];

	/* try to open the master side, using /dev/ptyXX */

	for (i=0;i<64;i++)
	{
		sprintf(pty_name,"/dev/pty%c%x", 'p' + i/16, i%16);
		*master = open(pty_name,O_RDWR);
		if (*master < 0)
			continue;
		
		/* open the slave side, using /dev/ttyXX */
		pty_name[5] = 't';
		*slave = open(pty_name,O_RDWR|O_NOCTTY);
		if (*slave < 0)
			continue;
		
		/* ok, success! */
		return 0;
	}

	/* we have tried everything ... failure! */
	return -1;
}
	
/*
  Get a master/slave pseudo terminal. File descriptor for the master
  is returned in *master and the same for the slave side. In case of error,
  -1 is returned and 0 for success
*/

int get_master_slave(int *master, int *slave)
{
	int r;

	/* try using /dev/ptmx first */
	r = get_master_slave_ptmx(master,slave);
	if (r < 0)
		r = get_master_slave_pty(master,slave);

	return r;
}

void sigalrm()
{
	exit (-1);
}

int main()
{
	int fd_master, fd_slave;
	int disc = N_HDLC;
	int r;
	char buf[10];

	/* handle the SIGALARM signal */
	signal(SIGALRM, sigalrm);

	if (get_master_slave(&fd_master,&fd_slave) < 0)
	{
		fprintf(stderr,"Can't get a master/slave pair\n");
		return -1;
	}

	/* install the HDLC line discipline */
	if (ioctl(fd_master,TIOCSETD,&disc) < 0)
	{
		/* HDLC support is not ok! */
		perror("N_HDLC");
		return -1;
	}

	/* we close the slave side */
	close(fd_slave);

	/* we try to read on the master side */
	alarm(1);

	r = read(fd_master, buf, sizeof(buf));
	/* we don't care about errors returned by read().
	   we only test if read() returns or blocks */

	close (fd_master);

	return 0;
}
	
