/*      $Id: irw.c,v 5.2 2001/02/28 17:25:01 columbus Exp $      */

/****************************************************************************
 ** irw.c *******************************************************************
 ****************************************************************************
 *
 * irw - watch the codes as lircd recognize them
 *
 * Copyright (C) 1998 Trent Piepho <xyzzy@u.washington.edu>
 * Copyright (C) 1998 Christoph Bartelmus <lirc@bartelmus.de>
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>

int main(int argc,char *argv[])
{
	int fd,i;
	char buf[128];
	struct sockaddr_un addr;

	addr.sun_family=AF_UNIX;
	if(argc>2)  {
		fprintf(stderr,"Usage: %s <socket>\n",argv[0]);
		fprintf(stderr,"sends data from UNIX domain socket to stdout\n");
		exit(1);
	} else if(argc==2)  {
		if(!strncmp(argv[1],"-h",2))  {
			fprintf(stderr,"Usage: %s <socket>\n",argv[0]);
			fprintf(stderr,"sends data from UNIX domain socket to stdout\n");
			exit(1);
		};
		strcpy(addr.sun_path,argv[1]);
	} else {
		strcpy(addr.sun_path,LIRCD);
	};
	fd=socket(AF_UNIX,SOCK_STREAM,0);
	if(fd==-1)  {
		perror("socket");
		exit(errno);
	};
	if(connect(fd,(struct sockaddr *)&addr,sizeof(addr))==-1)  {
		perror("connect");
		exit(errno);
	};

	for(;;)  {
		i=read(fd,buf,128);
		if(i==-1)  {
			perror("read");
			exit(errno);
		};
		if(!i)  exit(0);
		write(STDOUT_FILENO,buf,i);
	};
}

