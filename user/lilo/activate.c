/* activate.c  -  Simple partition activator */

/* Copyright 1992-1995 Werner Almesberger. See file COPYING for details. */


#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>


#define PART_BEGIN	0x1be
#define PART_NUM	4
#define PART_SIZE	16
#define PART_ACTIVE	0x80
#define PART_INACTIVE	0


static void die(char *fmt,...)
{
    va_list ap;

    va_start(ap,fmt);
    vfprintf(stderr,fmt,ap);
    va_end(ap);
    fprintf(stderr,"\n");
    exit(1);
}


int main(int argc,char **argv)
{
    struct stat st;
    int fd,number,count;
    unsigned char flag;

    if (argc != 2 && argc != 3) {
	fprintf(stderr,"usage: %s device [ partition ]\n",argv[0]);
	fprintf(stderr,"  i.e. %s /dev/hda 2\n",argv[0]);
	exit(1);
    }
    if ((fd = open(argv[1],argc == 2 ? O_RDONLY : O_WRONLY)) < 0)
	die("open %s: %s",argv[1],strerror(errno));
    if (fstat(fd,&st) < 0) die("stat %s: %s",argv[1],strerror(errno));
    if (!S_ISBLK(st.st_mode)) die("%s: not a block device",argv[1]);
    if (argc == 2) {
	for (count = 1; count <= PART_NUM; count++) {
	    if (lseek(fd,PART_BEGIN+(count-1)*PART_SIZE,SEEK_SET) < 0)
		die("lseek: %s",strerror(errno));
	    if (read(fd,&flag,1) != 1) die("read: %s",strerror(errno));
	    if (flag == PART_ACTIVE) {
		printf("%s%d\n",argv[1],count);
		exit(0);
	    }
	}
	die("No active partition found on %s",argv[1]);
    }
    number = atoi(argv[2]);
    if (number < 1 || number > 4)
	die("%s: not a valid partition number (1-4)",argv[2]);
    for (count = 1; count <= PART_NUM; count++) {
	if (lseek(fd,PART_BEGIN+(count-1)*PART_SIZE,SEEK_SET) < 0)
	    die("lseek: %s",strerror(errno));
	flag = count == number ? PART_ACTIVE : PART_INACTIVE;
	if (write(fd,&flag,1) != 1) die("write: %s",strerror(errno));
    }
    return 0;
}
