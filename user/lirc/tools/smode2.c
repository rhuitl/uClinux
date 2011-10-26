/*      $Id: smode2.c,v 5.6 2000/12/08 23:36:30 columbus Exp $      */

/****************************************************************************
 ** smode2.c ****************************************************************
 ****************************************************************************
 *
 * smode2 - shows the ir waveform of an IR signal
 *
 * Copyright (C) 1998.11.18 Sinkovics Zoltan <sinko@szarvas.hu>
 *
 * This program is based on the mode2.c file which is a part of the
 * LIRC distribution. The main purpose of this program is to check
 * operation of LIRC receiver hardware, and to see the IR waveform of
 * the remote controller without an expensive oscilloscope. The time
 * division is variable from 1 ms/div to extremely high values (integer
 * type) but there is no point increasing this value above 20 ms/div,
 * because one pulse is about 1 ms. I think this kind of presentation
 * is much more exciting than the simple pulse&space output showed by
 * mode2.
 *
 * Usage: smode2 [-t (ms/div)] , default division is 5 ms/div
 * */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <vga.h>
#include <vgagl.h>

#include "drivers/lirc.h"

GraphicsContext *screen;
GraphicsContext *physicalscreen;
GraphicsContext *backscreen;

void initscreen(void)
{
    int vgamode;
    
    vga_init();
    
    vgamode = G640x480x16;

    if (!vga_hasmode(vgamode)) {
	printf("Mode not available.\n");
	exit(-1);
    }
    vga_setmode(vgamode);
    
	/* Create virtual screen. */
	gl_setcontextvgavirtual(vgamode);
	backscreen = gl_allocatecontext();
	gl_getcontext(backscreen);

	/* Physical screen context. */
	vga_setmode(vgamode);
	gl_setcontextvga(vgamode);
	physicalscreen = gl_allocatecontext();
	gl_getcontext(physicalscreen);
	
	gl_setcontext(backscreen);
	/*drawgraypalette();*/

	gl_clearscreen(0);

//    gl_setcontextvga(vgamode);
    printf("1\n");
    gl_enableclipping();
    printf("1\n");    
    gl_setclippingwindow(0,0,639,479);
    printf("1\n");
    gl_setwritemode(WRITEMODE_OVERWRITE | FONT_COMPRESSED);
    printf("1\n");
    gl_setfont(8, 8, gl_font8x8);
    printf("1\n");
    gl_setfontcolors(0, 1) ;
    printf("1\n");    
}

void closescreen(void)
{
    vga_setmode(TEXT);
}

int main(int argc, char **argv)
{
	int fd;
	unsigned long mode;
	lirc_t data;
	lirc_t x1,y1,x2,y2;
	int result;
	int c=10;
	char textbuffer[80];
	int d,div=5;
	char *device=LIRC_DRIVER_DEVICE;
	char *progname;

	progname="smode2";
	while(1)
	{
		int c;
		static struct option long_options[] =
		{
			{"help",no_argument,NULL,'h'},
			{"version",no_argument,NULL,'v'},
			{"device",required_argument,NULL,'d'},
			{"timediv",required_argument,NULL,'t'},
			{0, 0, 0, 0}
		};
		c = getopt_long(argc,argv,"hvd:t:",long_options,NULL);
		if(c==-1)
			break;
		switch (c)
		{
		case 'h':
			printf("Usage: %s [options]\n",progname);
			printf("\t -h --help\t\tdisplay this message\n");
			printf("\t -v --version\t\tdisplay version\n");
			printf("\t -d --device=device\tread from given device\n");
			printf("\t -t --timediv=value\tms per unit\n");
			return(EXIT_SUCCESS);
		case 'v':
			printf("%s\n",progname);
			return(EXIT_SUCCESS);
		case 'd':
			device=optarg;
			break;
		case 't': /* timediv */
			div = strtol(optarg,NULL,10);
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
		perror(progname);
		fprintf(stderr,"%s: error opening %s\n",progname,device);
		exit(EXIT_FAILURE);
	};
	if(ioctl(fd,LIRC_GET_REC_MODE,&mode)==-1 || mode!=LIRC_MODE_MODE2)
	{
		printf("This program is only intended for receivers "
		       "supporting the pulse/space layer.\n");
		printf("Note that this is no error, but this program simply "
		       "makes no sense for your\nreceiver.\n");
		close(fd);
		exit(EXIT_FAILURE);
	}
	
	initscreen();
	
	y1=20;
	x1=x2=0;
	printf("5\n");
	for (y2=0;y2<640;y2+=20) gl_line(y2,0,y2,480,1);
	printf("6\n");
	sprintf(textbuffer,"%d ms/unit",div);
	printf("7\n");
	gl_write(500,10,textbuffer);
	printf("7\n");
	gl_copyscreen(physicalscreen);

	while(1)
	{
		result=read(fd,&data,sizeof(data));
		if (result==sizeof(data))
		    {
//		    printf("%.8lx\t",(unsigned long) data);
		    x2=(data&PULSE_MASK)/(div*50);
		    if (x2>400)
			{
			y1+=15;
			x1=0;
			gl_copyscreen(physicalscreen);
			}
		      else
			{
			if (x1<640) 
			    {
			    gl_line(x1, ((data&PULSE_BIT)?y1:y1+10), x1+x2, ((data&PULSE_BIT)?y1:y1+10), c) ;
			    x1+=x2;
			    gl_line(x1, ((data&PULSE_BIT)?y1:y1+10), x1, ((data&PULSE_BIT)?y1+10:y1), c) ;
			    }
			}
		    if (y1>480) 
			{
			y1=20;
			gl_clearscreen(0);
			for (y2=0;y2<640;y2+=10) gl_line(y2,0,y2,480,1);
			gl_write(500,10,textbuffer);
			}
		    }
//		gl_copyscreen(physicalscreen);
	};
    closescreen();
    exit(EXIT_SUCCESS);
}
