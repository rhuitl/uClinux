/* partition.h  -  Partition table handling */

/*
Copyright 1992-1998 Werner Almesberger.
Copyright 1999-2004 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/


#ifndef PARTITION_H
#define PARTITION_H

#include <unistd.h>
#include <linux/unistd.h>

typedef struct _change_rule {
    const char *type;
    unsigned char normal;
    unsigned char hidden;
    struct _change_rule *next;
} CHANGE_RULE;

enum {PTW_OKAY=0, PTW_DOS=1, PTW_OS2=2, PTW_SWAP, PTW_XFS,
		PTW_mask=7, PTW_NTFS=8};


#define LLSECTORSIZE ((long long)SECTOR_SIZE)

#if __GLIBC__ < 2 || __GLIBC_MINOR__ < 1
typedef long long lloff_t;

#ifdef _syscall5
       lloff_t lseek64(unsigned int fd, lloff_t offs, unsigned int whence);
#endif
#endif

struct partition {
	unsigned char boot_ind;		/* 0x80 - active */
	unsigned char head;		/* starting head */
	unsigned char sector;		/* starting sector */
	unsigned char cyl;		/* starting cylinder */
	unsigned char sys_ind;		/* What partition type */
	unsigned char end_head;		/* end head */
	unsigned char end_sector;	/* end sector */
	unsigned char end_cyl;		/* end cylinder */
	unsigned int start_sect;	/* starting sector counting from 0 */
	unsigned int nr_sects;		/* nr of sectors in partition */
};


int part_nowrite(char* device);
/* identify partitions which would be destroyed if the boot block
   is overwritten:
   
   known problems occur for:
   	XFS
   	NTFS
   	DOS FAT (relocation will fix)
*/

#define is_extd_part(x) ((x)==PART_DOS_EXTD||(x)==PART_WIN_EXTD_LBA||(x)==PART_LINUX_EXTD)

void part_verify(int dev_nr,int type);
/* Verify the partition table of the disk of which dev_nr is a partition. May
   also try to "fix" a partition table. Fail on non-Linux partitions if the
   TYPE flag is non-zero (unless IGNORE-TABLE is set too). */

void do_cr_auto(void);
/* do automatic change-rules */

void preload_types(void);
/* Preload some partition types for convenience */

void do_activate(char *where, char *which);
/* Activate the specified partition */

void do_install_mbr(char *where, char *what);
/* Install a new MBR (Master Boot Record) */

int read_partitions(char *part, int max, int *volid,
		struct partition *p, long long *where);
/* read all partitions & partition tables */

#endif
