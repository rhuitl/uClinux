/* shutdown.c:
 *
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>,
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * JUN/99 -- copied from shutdown.c to make new reboot command.
 *           (gerg@snapgear.com)
 * AUG/99 -- added delay option to reboot
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

#include <sys/stat.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <signal.h>

#include <getopt.h>

#if __GNU_LIBRARY__ > 5
#include <sys/reboot.h>
#endif

int main(int argc, char *argv[])
{
	int delay = 0; /* delay in seconds before rebooting */
	int rc;
  
	while ((rc = getopt(argc, argv, "h?d:")) > 0) {
		switch (rc) {
		case 'd':
			delay = atoi(optarg);
			break;
		case 'h':
		case '?':
		default:
			printf("usage: reboot [-h] [-d <delay>]\n");
			exit(0);
			break;
		}
	}

	if(delay > 0)
		sleep(delay);

	kill(1, SIGTSTP);
	sync();
	signal(SIGTERM,SIG_IGN);
	setpgrp();
	kill(-1, SIGTERM);
	kill(-1, SIGHUP);
	sleep(1);
	kill(-1, SIGKILL);
	sync();
	sleep(1);
#if __GNU_LIBRARY__ > 5
	reboot(0x01234567);
#else
	reboot(0xfee1dead, 672274793, 0x01234567);
#endif
	exit(0); /* Shrug */
}

