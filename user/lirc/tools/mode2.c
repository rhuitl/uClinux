/*      $Id: mode2.c,v 5.6 2000/12/08 23:36:30 columbus Exp $      */

/****************************************************************************
 ** mode2.c *****************************************************************
 ****************************************************************************
 *
 * mode2 - shows the pulse/space length of a remote button
 *
 * Copyright (C) 1998 Trent Piepho <xyzzy@u.washington.edu>
 * Copyright (C) 1998 Christoph Bartelmus <lirc@bartelmus.de>
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include "drivers/lirc.h"

int main(int argc,char **argv)
{
	int fd;
	lirc_t data;
	unsigned long mode;
	char *device=LIRC_DRIVER_DEVICE;
	char *progname;

	progname="mode2";
	while(1)
	{
		int c;
		static struct option long_options[] =
		{
			{"help",no_argument,NULL,'h'},
			{"version",no_argument,NULL,'v'},
			{"device",required_argument,NULL,'d'},
			{0, 0, 0, 0}
		};
		c = getopt_long(argc,argv,"hvd:",long_options,NULL);
		if(c==-1)
			break;
		switch (c)
		{
		case 'h':
			printf("Usage: %s [options]\n",progname);
			printf("\t -h --help\t\tdisplay this message\n");
			printf("\t -v --version\t\tdisplay version\n");
			printf("\t -d --device=device\tread from given device\n");
			return(EXIT_SUCCESS);
		case 'v':
			printf("%s\n",progname);
			return(EXIT_SUCCESS);
		case 'd':
			device=optarg;
			break;
		default:
			printf("Usage: %s [options]\n",progname);
			return(EXIT_FAILURE);
		}
	}
	if (optind < argc-1)
	{
		fprintf(stderr,"%s: too many arguments\n",progname);
		return(EXIT_FAILURE);
	}
	
	fd=open(device,O_RDONLY);
	if(fd==-1)  {
		fprintf(stderr,"%s: error opening %s\n",progname,device);
		perror(progname);
		exit(EXIT_FAILURE);
	};
	if(ioctl(fd,LIRC_GET_REC_MODE,&mode)==-1 || mode!=LIRC_MODE_MODE2)
	{
		printf("This program is only intended for receivers "
		       "supporting the pulse/space layer.\n");
		printf("Note that this is no error, but this program simply "
		       "makes no sense for your\n"
		       "receiver.\n");
		close(fd);
		exit(EXIT_FAILURE);
	}
	while(1)
	{
		int result;

		result=read(fd,&data,sizeof(data));
		if(result!=sizeof(data))
		{
			fprintf(stderr,"read() failed\n");
			break;
		}
		
		printf("%s %lu\n",(data&PULSE_BIT)?"pulse":"space",
		       (unsigned long) (data&PULSE_MASK));
		fflush(stdout);
	};
	return(EXIT_SUCCESS);
}
