/*
  Author: Benoit PAPILLAULT <benoit.papillault@free.fr>
  Creation: 01/02/2002

  Goal: test if the HDLC support is ok and return status 0 in this case

  03/02/2002: added support for /dev/ptyXX. There was previously only /dev/ptmx
*/

#define _XOPEN_SOURCE /* for grantpt in <stdlib.h> */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

/* for ident(1) command */
static const char id[] = "@(#) $Id: check-hdlc.c,v 1.1 2002/02/21 20:46:17 papillau Exp $";

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

int main()
{
	int master, slave;
	int disc = N_HDLC;

	if (get_master_slave(&master,&slave) < 0)
	{
		fprintf(stderr,"Can't get a master/slave pair\n");
		return -1;
	}

	if (ioctl(master,TIOCSETD,&disc) < 0)
	{
		/* HDLC support is not ok! */
		return -1;
	}

	close (master);
	close (slave);

	return 0;
}
	
