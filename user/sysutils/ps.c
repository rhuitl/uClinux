/* ps.c:
 *
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>
 * Copyright (C) 1999  D. Jeff Dionne     <jeff@lineo.ca>
 * Copyright (C) 2000  Lineo, Inc.  (www.lineo.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <linux/major.h>
#include <linux/types.h>
#include <sys/time.h>
#include <asm/param.h>
#include <math.h>

char psbuf[256];
char name[40];
int pid, state;
char statec;
int ppid, pgrp, session;
dev_t tty;
char tty_name[10];

char master[] = "pqrstuvwxyzabcde";

#define MAJOR(x) ((x) >> 8)
#define MINOR(x) ((x) & 0xff)
#ifndef isdigit
#define isdigit(X) ((X) >= '0' && (X) <= '9' ? 1 : 0)
#endif

int port_xlate[16] = {1, 3, 5, 7,9 ,11,13,15,
                      2, 4, 6, 8,10,12,14,16};

void dev_to_name(dev_t dev, char * ttyname)
{
	strcpy(ttyname, "");
	if (MAJOR(dev) == 75)
		sprintf(ttyname,"X%d", MINOR(dev));
	else if (MAJOR(dev) == TTY_MAJOR)
		sprintf(ttyname,"S%d", MINOR(dev)-64);
	else if (MAJOR(dev) == PTY_SLAVE_MAJOR)
		sprintf(ttyname,"%c%x", master[MINOR(dev) / 16], MINOR(dev) & 0xf);
}

int
main(argc, argv)
	char	**argv;
{
	int i;
	int h;
	FILE * f;
	DIR * d;
	unsigned long bytes, sbytes;
	struct dirent * de;
	char *ext;
	int l;
	time_t time_now;
	long uptime_secs;
	float seconds, start, total_time;
	int utime, stime, start_time;
	int pcpu;
	/*extern int _vfprintf_fp_ref, _vfscanf_fp_ref;*/

	fclose(stdin);

	printf("  PID PORT STAT SIZE SHARED %%CPU COMMAND\n"/*, _vfprintf_fp_ref, _vfscanf_fp_ref*/);

	h = open("/proc/uptime", O_RDONLY);
		
	if (h==-1) {
		perror("Unable to open /proc/uptime\n");
		exit(0);
	}
	
	l = read(h, psbuf, 255);

	close(h);  


	if (l<=0) {
		perror("Unable to read uptime");
		exit(0);
	}


	psbuf[l] = '\0';
	psbuf[255] = '\0';
		
	ext = psbuf;


	uptime_secs = atol(ext);

	
	time_now = time(0);
	
	d = opendir("/proc");
	if (!d)
		return 1;
	
	while ((de = readdir(d)) != NULL) {
	
	
		for(i=0;i<strlen(de->d_name);i++)
			if (!isdigit(de->d_name[i]))
				goto next;

		sprintf(psbuf, "/proc/%s/stat", de->d_name);
		
		h = open(psbuf, O_RDONLY);
		
		if (h==-1)
			continue;
			
		l = read(h, psbuf, 255);
		if (l<=0) {
			perror("Unable to read status");
			close(h);
			continue;
		}
		
		psbuf[l] = '\0';
		psbuf[255] = '\0';
		
		ext = strrchr(psbuf, ')');
		ext[0] = '\0';

		statec = ext[2];

		ext += 4;
		
		ppid = atoi(ext);
		ext = strchr(ext, ' ')+1;

		pgrp = atoi(ext);
		ext = strchr(ext, ' ')+1;
		
		session = atoi(ext);
		ext = strchr(ext, ' ')+1;

		tty = atoi(ext);
		ext = strchr(ext, ' ')+1;

		//printf("1|%s\n", ext);
		//tpgid
		ext = strchr(ext, ' ')+1;
		
		//printf("2|%s\n", ext);
		//flags
		ext = strchr(ext, ' ')+1;

		//printf("3|%s\n", ext);
		//min_flt
		ext = strchr(ext, ' ')+1;

		//printf("4|%s\n", ext);
		//cmin_flt
		ext = strchr(ext, ' ')+1;

		//printf("5|%s\n", ext);
		//maj_flt
		ext = strchr(ext, ' ')+1;

		//printf("6|%s\n", ext);
		//cmaj_flt
		ext = strchr(ext, ' ')+1;

		//printf("7|%s\n", ext);
		utime = atoi(ext);
		ext = strchr(ext, ' ')+1;

		//printf("8|%s\n", ext);
		stime = atoi(ext);
		ext = strchr(ext, ' ')+1;
		
		//printf("9|%s\n", ext);
		//cutime
		ext = strchr(ext, ' ')+1;

		//printf("10|%s\n", ext);
		//cstime
		ext = strchr(ext, ' ')+1;
		
		//priority
		ext = strchr(ext, ' ')+1;
		
		//nice
		ext = strchr(ext, ' ')+1;
		
		//timeout
		ext = strchr(ext, ' ')+1;

		//it_real_value
		ext = strchr(ext, ' ')+1;

		start_time = atoi(ext);
		
		ext = strchr(psbuf, '(');
		ext++;
		strcpy(name, ext);
		
		pid = atoi(psbuf);
		
		
		state = statec;
		
		close(h);
		
		dev_to_name(tty, tty_name);
		
		bytes = 0;
		sbytes = 0;
		sprintf(psbuf, "/proc/%s/status", de->d_name);

		f = fopen(psbuf, "r");
		
		if (f) {
			while (fgets(psbuf, 250, f)) {
				if (strncmp(psbuf, "Mem:", 4) == 0) {
					bytes = atol(psbuf+5);
				} else if (strncmp(psbuf, "Shared:", 7) == 0) {
					sbytes = atol(psbuf+8);
				}
			}
			fclose(f);
		}
		
		bytes /= 1024;
		sbytes /= 1024;

		seconds = ((uptime_secs * (long)HZ) - start_time) / HZ;
		
		/*printf("seconds=%s\n", gcvt(seconds, 15, psbuf));*/
		
		start = time_now - seconds;
		
		/*
		printf("1\n");

		gcvt(start, 15, psbuf);

		printf("2\n");
		
		printf("start=%s\n", psbuf);
		
		printf("utime=%d, stime=%d. start_time=%d\n", utime, stime, start_time);
		*/
		
		total_time = (utime + stime);

		/*printf("total_time=%s\n", gcvt(total_time, 15, psbuf));*/

		pcpu = 	seconds ? 
			(total_time * 10.0f * 100.0f / (float)HZ) / seconds :
			0; 
		if (pcpu > 999) pcpu = 999;


		sprintf(psbuf, "/proc/%s/cmdline", de->d_name);
		h = open(psbuf, O_RDONLY);
		
		if (h == -1) {
			perror("Unable to open cmdline");
			continue;
		}
		
		l = read(h, psbuf, 255);
		if (l < 0) {
			perror("Unable to read cmdline");
			close(h);
			continue;
		}
		
		close(h);
		
		/*
		 * the args are NUL seperated,  substitue spaces instead
		 */
		for (i = 0; i < l; i++)
			if (psbuf[i] == '\0')
				psbuf[i] = ' ';
		psbuf[255] = psbuf[l] = '\0';

		
		printf("%5d %4s %c    %3ldK   %3ldK %2u.%u %s\n", pid, tty_name, state,
			bytes, sbytes, 
			 pcpu / 10, pcpu % 10, 
			 /*(int)seconds / 60, (int)seconds % 60,*/
			 l ? psbuf : name);
	next: ;
	}
	
	closedir(d);
	exit(0);
}

