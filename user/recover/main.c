/****************************************************************************/

/*
 *	main.c -- recover FLASH contents after network load.
 *
 *	(C) Copyright 2000, Lineo Inc (www.lineo.com)
 */

/****************************************************************************/

#include <stdio.h>
#include <setjmp.h>
#include <unistd.h>

/****************************************************************************/

char	serverbuf[128];
jmp_buf	doflash;

/*
 *	Define the ethernet interface to use.
 */
#ifndef ETHER_INTERFACE
#define	ETHER_INTERFACE		"eth0"
#endif

/****************************************************************************/

int main()
{
	char	*localargv[16];
	int	i;

	fprintf(stderr, "RECOVER: launching DHCP client.\n");
	if (setjmp(doflash) == 0) {
		localargv[0] = "dhcpcd";
		localargv[1] = "-a";
		localargv[2] = "-p";
		localargv[3] = ETHER_INTERFACE;
		localargv[4] = NULL;
		dhcpcdmain(4, localargv, NULL);
	}

	fprintf(stderr, "RECOVER: fetching new images from %s\n", serverbuf);

	optind = 0;
	i = 0;

	localargv[i++] = "netflash";
	localargv[i++] = "-k";
	localargv[i++] = "-i";
	localargv[i++] = "-H";

#ifdef BOOT_RECOVER
	localargv[i++] = "-n";
#endif


#ifndef BOOT_RECOVER 
#ifdef HMACMD5_KEY
	localargv[i++] = "-m";
	localargv[i++] = HMACMD5_KEY;
#endif
#endif

	localargv[i++] = "-r";

#ifdef BOOT_RECOVER 
	localargv[i++] = "/dev/flash/boot";
#else
#ifdef PRESERVE_CONFIG_FS
	localargv[i++] = "/dev/flash/image";
#else
	localargv[i++] = "/dev/flash/all";
#endif
#endif

#ifdef STATIC_SERVER_IP
	localargv[i++] = STATIC_SERVER_IP;
#else
	localargv[i++] = serverbuf;
#endif

#ifdef BOOT_RECOVER 
	localargv[i++] = "/tftpboot/bios.bin";
#else
	localargv[i++] = "/tftpboot/flash.bin";
#endif

	localargv[i] = NULL;
	netflashmain(i, localargv);

	exit(0);
}
/****************************************************************************/
