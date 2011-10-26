/* vi: set sw=4 ts=4: */
/*
 * _reboot() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <sys/reboot.h>
#define __NR__reboot __NR_reboot

#include <config/autoconf.h>
#ifdef CONFIG_PROP_LOGD_LOGD
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#endif

static inline _syscall3(int, _reboot, int, magic, int, magic2, int, flag);
int reboot(int flag)
{
#ifdef CONFIG_PROP_LOGD_LOGD
	int pid = getpid();
	char tmp[10];
	char tmp1[50];
	FILE *fp;
	sprintf(tmp1, "/proc/%d/stat", pid);
	fp = fopen(tmp1, "r");
	if (fp) {
		int pid1;
		if (fscanf(fp, "%d (%[^)] ", &pid1, tmp) != 2)
			strcpy(tmp, "NA");
		else
			if (pid1 != pid)
				strcpy(tmp, "INVALID");
		fclose(fp);
	} else
		strcpy(tmp, "unknown");
	sprintf(tmp1, "/bin/logd reboot %d: %s", pid, tmp);
	system(tmp1);
	sleep(1);
#endif
	return (_reboot((int) 0xfee1dead, 672274793, flag));
}
