/* geometry.h  -  Device and file geometry computation */
/*
Copyright 1992-1998 Werner Almesberger.
Copyright 1999-2005 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/
#ifndef GEOMETRY_H
#define GEOMETRY_H

#define LINUX 1

#if LINUX
#include <linux/fd.h>
#include <linux/hdreg.h>
#else
struct hd_geometry {
      unsigned char heads;
      unsigned char sectors;
      unsigned short cylinders;
      unsigned long start;
};

/* hd/ide ctl's that pass (arg) ptrs to user space are numbered 0x030n/0x031n */
#define HDIO_GETGEO		0x0301	/* get device geometry */
struct floppy_struct {
	unsigned int	size,		/* nr of sectors total */
			sect,		/* sectors per track */
			head,		/* nr of heads */
			track,		/* nr of tracks */
			stretch;	/* !=0 means double track steps */
#define FD_STRETCH 1
#define FD_SWAPSIDES 2
#define FD_ZEROBASED 4

	unsigned char	gap,		/* gap1 size */

			rate,		/* data rate. |= 0x40 for perpendicular */
#define FD_2M 0x4
#define FD_SIZECODEMASK 0x38
#define FD_SIZECODE(floppy) (((((floppy)->rate&FD_SIZECODEMASK)>> 3)+ 2) %8)
#define FD_SECTSIZE(floppy) ( (floppy)->rate & FD_2M ? \
			     512 : 128 << FD_SIZECODE(floppy) )
#define FD_PERP 0x40

			spec1,		/* stepping rate, head unload time */
			fmt_gap;	/* gap2 size */
	const char	* name; /* used only for predefined formats */
};
#define FDGETPRM _IOR(2, 0x04, struct floppy_struct)
#endif

#if 1
#define MAJOR(dev) (unsigned int)((((dev_t)(dev) >> 8) & 0xfff) | ((unsigned int) ((dev_t)(dev) >> 32) & ~0xfff))
#define MINOR(dev) (unsigned int)(((dev_t)(dev) & 0xff) | ((unsigned int) ((dev_t)(dev) >> 12) & ~0xff))
#define MKDEV(major,minor) (((minor & 0xff) | ((major & 0xfff) << 8) \
	  | (((unsigned long long int) (minor & ~0xff)) << 12) \
	  | (((unsigned long long int) (major & ~0xfff)) << 32)))
#else
#include <sys/sysmacros.h>
#ifdef major
#define MAJOR(dev) major(dev)
#define MINOR(dev) minor(dev)
#define MKDEV(maj,min) makedev(maj,min)
#else
/* from <linux/kdev_t.h>  */
/* These are for user-level "dev_t" */
#define MINORBITS	8
#define MINORMASK	((1U << MINORBITS) - 1)
#error "Should not get here:  MAJOR/MINOR (geometry.h)"
#define MAJOR(dev)	((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)	((unsigned int) ((dev) & MINORMASK))
#define MKDEV(ma,mi)	(((ma) << MINORBITS) | (mi))
#endif
#endif

/*  from <linux/fs.h> */
#define BMAP_IOCTL 1		/* obsolete - kept for compatibility */
#define FIBMAP	   _IO(0x00,1)	/* bmap access */
#define FIGETBSZ   _IO(0x00,2)	/* get the block size used for bmap */



typedef struct {
    int device,heads;
    int cylinders,sectors;
    int start; /* partition offset */
    int spb; /* sectors per block */
    int fd,file;
    int boot; /* non-zero after geo_open_boot */
    int raid; /* file references require raid1 relocation */
    dev_t dev, base_dev; /* real device if remapping (LVM, etc) */
} GEOMETRY;

typedef struct _dt_entry {
    unsigned int device;
    int bios;
    int sectors;
    int heads; /* 0 if inaccessible */
    int cylinders;
    int start;
    struct _dt_entry *next;
} DT_ENTRY;

extern DT_ENTRY *disktab;


/* unsigned char max_partno[256]; */
/* index by major device number; entries must be 2**n-1 (7,15, or 63) */


int has_partitions(dev_t dev);
/* indicates that the specified device is a block hard disk device */
/* returns the partition mask or 0 */


void geo_init(char *name);
/* Loads the disk geometry table. */

int is_first(int device);
/* Returns a non-zero integer if the specified device could be the first (i.e.
   boot) disk, zero otherwise. */


void geo_get(GEOMETRY *geo,int device,int user_device,int all);
/* Obtains geometry information of the specified device. Sets the BIOS device
   number to user_device unless -1. If ALL is zero, only the BIOS device number
   is retrieved and the other geometry information is undefined. */


int geo_open(GEOMETRY *geo,char *name,int flags);
/* Opens the specified file or block device, obtains the necessary geometry
   information and returns the file descriptor. If the name contains a BIOS
   device specification (xxx:yyy), it is removed and stored in the geometry
   descriptor. Returns the file descriptor of the opened object. */


int geo_open_boot(GEOMETRY *geo,char *name);
/* Like get_open, but only the first sector of the device is accessed. This
   way, no geometry information is needed. */


void geo_close(GEOMETRY *geo);
/* Closes a file or device that has previously been opened by geo_open. */


int geo_comp_addr(GEOMETRY *geo,int offset,SECTOR_ADDR *addr);
/* Determines the address of the disk sector that contains the offset'th
   byte of the specified file or device. Returns a non-zero value if such
   a sector exists, zero if it doesn't. */


int geo_find(GEOMETRY *geo,SECTOR_ADDR addr);
/* lseeks in the file associated with GEO for the sector at address ADDR.
   Returns a non-zero integer on success, zero on failure. */


void geo_query_dev(GEOMETRY *geo,int device,int all);
/* opens the specified device and gets the geometry information.  That
   information is then stored in *geo */


int is_dm_major(int major);
/* tell whether the specified major device number is one of the
   device-mapper major devices */
   

#if 0
int geo_devscan(int device);
/* called to fill in a disktab with arbitrary BIOS codes */
#endif


#endif
