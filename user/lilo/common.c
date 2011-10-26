/* common.c  -  Common data structures and functions. */
/*
Copyright 1992-1998 Werner Almesberger.
Copyright 1999-2005 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/


#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "lilo.h"
#include "common.h"

#ifndef SHS_MAIN
LILO_EXTRA extra;
char *identify = NULL;
int boot_dev_nr, raid_index, do_md_install;
int verbose = 0, test = 0, compact = 0, linear = 0, raid_flags = 0, zflag = 0,
      ireloc = 0, force_fs = 0, force_raid = 0, extended_pt = 0, query = 0,
      nowarn = 0, lba32 = 0, autoauto = 0, passw = 0, geometric = 0, eflag = 0;
int colormax = 15, warnings = 0;
DL_BIOS bios_passes_dl = DL_NOT_SET;

#if !__MSDOS__
FILE *pp_fd = NULL;
int bios_boot, bios_map;
unsigned short drv_map[DRVMAP_SIZE+1]; /* fixup maps ... */
int curr_drv_map;
unsigned int prt_map[PRTMAP_SIZE+1];
int curr_prt_map;
#endif /* !__MSDOS__ */

/*volatile*/ void pdie(char *msg)
{
    fflush(stdout);
#if !__MSDOS__
    perror(msg);
#else
    fprintf(errstd, "%s\n", msg);
#endif /* !__MSDOS__ */
    exit(1);
}


/*volatile*/ void die(char *fmt,...)
{
    va_list ap;

    fflush(stdout);
    fprintf(errstd,"Fatal: ");       /* JRC */
    va_start(ap,fmt);
    vfprintf(errstd,fmt,ap);
    va_end(ap);
    fputc('\n',errstd);
    exit(1);
}


/*volatile*/ void warn(char *fmt,...)
{
    va_list ap;

    warnings++;
    if (nowarn > 0) return;
    
    fflush(stdout);
    fprintf(errstd,"Warning: ");
    va_start(ap,fmt);
    vfprintf(errstd,fmt,ap);
    va_end(ap);
    fputc('\n',errstd);
    
    return;
}


void *alloc(int size)
{
    void *this;

    if ((this = malloc(size)) == NULL) pdie("Out of memory");
    memset(this, 0, size);	/* insure consistency */

    return this;
}


void *ralloc(void *old,int size)
{
    void *this;

    if ((this = realloc(old,size)) == NULL) pdie("Out of memory");
    return this;
}


char *stralloc(const char *str)
{
    char *this;

    if ((this = strdup(str)) == NULL) pdie("Out of memory");
    return this;
}


int to_number(char *num)
{
    int number;
    char *end;

    number = strtol(num,&end,0);
    if (end && *end) die("Not a number: \"%s\"",num);
    return number;
}


int timer_number(char *num)
{
    int number;
    char *end;

    number = strtol(num,&end,0);
    if (end && *end) {
	switch (*end) {
	    case 'h':
	    case 'H':
		number *= 60;
	    case 'm':
	    case 'M':
		number *= 60;
	    case 's':
	    case 'S':
		number *= 10;		/* convert seconds to tenths */
	    case 't':
	    case 'T':
		break;
	    default:
		number = -1;
	}
    }
    if (number < 0  ||  number > 36000)  die("Not a valid timer value: \"%s\"",num);
    return number;
}


static char *name(int stage)
{
    switch (stage) {
	case STAGE_FIRST:
	    return "First boot sector";
	case STAGE_SECOND:
	    return "Second boot sector";
	case STAGE_CHAIN:
	    return "Chain loader";
	default:
	    die("Internal error: Unknown stage code %d",stage);
    }
    return NULL; /* for GCC */
}


void check_version(BOOT_SECTOR *sect,int stage)
{
    int bs_major, bs_minor;

    if (!strncmp(sect->par_1.signature-4,"LILO",4))
	die("%s has a pre-21 LILO signature",name(stage));
    if (strncmp(sect->par_1.signature,"LILO",4))
	die("%s doesn't have a valid LILO signature",name(stage));
    if ((sect->par_1.stage&0xFF) != stage)
	die("%s has an invalid stage code (%d)",name(stage),sect->par_1.stage);

    bs_major = sect->par_1.version & 255;
    bs_minor = sect->par_1.version >> 8;
    if (sect->par_1.version != VERSION)
	die("%s is version %d.%d. Expecting version %d.%d.",name(stage),
	    bs_major,bs_minor, VERSION_MAJOR,VERSION_MINOR);
}


#if !__MSDOS__
int stat_equal(struct stat *a,struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
#endif /* !__MSDOS__ */

#endif	/*  !SHS_MAIN */


#if !__MSDOS__
/* accumulate a partial CRC-32 */

unsigned int crc32partial(unsigned char *cp, int nsize,
			unsigned int polynomial, unsigned int *accum)
{
   unsigned int poly, crc;
   int i;
   unsigned char ch;

   crc = ~*accum;
   while (nsize--) {
      ch = *cp++;
      for (i=0; i<8; i++) {
         if ( ( (crc>>31) ^ (ch>>(7-i)) ) & 1) poly = polynomial;
         else poly = 0UL;
         crc = (crc<<1) ^ poly;
      }
   }
   return (*accum = ~crc);
}


/* calculate a CRC-32 polynomial */

unsigned int crc32 (unsigned char *cp, int nsize, unsigned int polynomial)
{
    unsigned int crc = 0;
    return crc32partial(cp, nsize, polynomial, &crc);
}


/* show what a link resolves to */

void show_link(char *name)
{
    int count;
    char lname[1024];
    
    count = readlink(name, lname, sizeof(lname)-1);
    if (count>0) {
    	lname[count] = 0;
    	printf(" -> %s", lname);
    }
}
#else /* __MSDOS__ */
char * strerror(int err)
{
    return NULL;
}
#endif /* !__MSDOS__ */


#ifdef SHS_MAIN
#include <fcntl.h>

int main(int argc, char *argv[])
{
    unsigned char buf[4096];
    int fd, n;
    unsigned int crc;
    
    fd = open(argv[1],O_RDONLY);
    crc = 0;
    n = read(fd,buf,sizeof(buf));
    while (n>0) {
	crc32partial(buf, n, CRC_POLY1, &crc);
	n = read(fd,buf,sizeof(buf));
    }
    close(fd);

    printf("0x%08x\n", (int)crc);
    if (sizeof(short)!=2) {
	fprintf(stderr,"***Fatal:  SHORT != 2\n");
	return 1;
    }
    if (sizeof(int)!=4) {
	fprintf(stderr, "*****Fatal:  INT != 4\n");
	return 1;
    }
    if (sizeof(long)>sizeof(int))
	fprintf(stderr, "**Note:  LONG is bigger than INT\n");
	
    return 0;
}
#endif	/* SHS_MAIN */
