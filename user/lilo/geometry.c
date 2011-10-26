/* geometry.c  -  Device and file geometry computation */
/*
Copyright 1992-1998 Werner Almesberger.
Copyright 1999-2005 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/
/* Patched for linux-2.4.0 - Glibc-2.2 by Sergey Ostrovsky 11/16/2000 */

#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <sys/types.h>

#ifdef LCF_REISERFS
#include <sys/statfs.h>

#ifdef	_SYS_STATFS_H
#define	_I386_STATFS_H	/* two versions of statfs is not good ... */
#endif
#endif

#include <string.h>


#include "config.h"
#ifdef LCF_DEVMAPPER
# include <libdevmapper.h>
#endif
#include "lilo.h"
#include "common.h"
#include "device.h"
#include "raid.h"
#include "geometry.h"
#include "cfg.h"
#include "md-int.h"
#include "probe.h"

#ifdef LCF_REISERFS
#ifndef REISERFS_SUPER_MAGIC
#define REISERFS_SUPER_MAGIC 0x52654973
#endif

#if 0
#ifndef REISERFS_SUPER_MAGIC_STRING
#define REISERFS_SUPER_MAGIC_STRING "ReIsErFs"
#endif
#endif

#ifndef REISERFS_IOC_UNPACK
#define REISERFS_IOC_UNPACK		_IOW(0xCD,1,long)
#endif

#ifndef REISER4_SUPER_MAGIC
#define REISER4_SUPER_MAGIC  0x52345362
 /* (*(__u32 *)"R4Sb"); */
#endif
#ifndef REISER4_IOC_UNPACK
#define REISER4_IOC_UNPACK              _IOW(0xCD,1,long)
#endif
#endif

#ifdef LCF_DEVMAPPER
typedef struct _dm_target {
    struct _dm_target *next;
    uint64_t start,length,offset;
    int device;
} DM_TARGET;

typedef struct _dm_table {
    struct _dm_table *next;
    int device;
    struct _dm_target *target;
} DM_TABLE;

DM_TABLE *dmtab = NULL;
int dm_version_nr = 0;
#endif

int dm_major_list[16];
int dm_major_nr;

#ifdef LCF_LVM
struct lv_bmap {
    __u32 lv_block;
    dev_t lv_dev;			/* was __u16, which is wrong */
};

#ifndef LV_BMAP
/*	Should the definition be:					*/
#define LV_BMAP				_IOWR(0xfe, 0x30, int)
/*	As defined in the 2.4 kernels:					*/
/*#define LV_BMAP				_IOWR(0xfe, 0x30, 1)  */
#endif
#ifndef LVM_GET_IOP_VERSION
/*	Should the definition be:					*/
#define LVM_GET_IOP_VERSION		_IOR(0xfe, 0x98, unsigned short)
/*	As defined in the 2.4 kernels:					*/
/*#define LVM_GET_IOP_VERSION		_IOR(0xfe, 0x98, 1) */
#endif
#endif

#ifdef LCF_EVMS
struct evms_get_bmap_t {
    __u64 rsector;
    __u32 dev;
    int status;
};

struct evms_version_t {
    __u32 major;
    __u32 minor;
    __u32 patch;
};

#ifndef EVMS_GET_BMAP
#define EVMS_GET_BMAP		_IOWR(MAJOR_EVMS, 0xC7, struct evms_get_bmap_t)
#endif
#ifndef EVMS_GET_IOCTL_VERSION
#define EVMS_GET_IOCTL_VERSION	_IOR(MAJOR_EVMS, 0x0, struct evms_version_t)
#endif
#endif

#ifndef HDIO_GETGEO
#define HDIO_GETGEO HDIO_REQ
#endif


typedef struct _st_buf {
    struct _st_buf *next;
    struct stat st;
} ST_BUF;


DT_ENTRY *disktab = NULL;
int old_disktab = 0;


void geo_init(char *name)
{
    FILE *file = NULL;
    char line[MAX_LINE+1];
#ifdef LCF_DEVMAPPER
    struct dm_task *dmt;
    char dm_version[32];
#endif
    char major_name[32];
    int major;
    char *here;
    DT_ENTRY *entry;
    int disk_section,items;

    if (name) {
	if ((file = fopen(name,"r")) == NULL)
	    die("open %s: %s",name,strerror(errno));
    }
    if (name || (file = fopen(DFL_DISKTAB,"r")) != NULL) {
	disk_section = !!disktab;
	while (fgets(line,MAX_LINE,file)) {
	    here = strchr(line,'\n');
	    if (here) *here = 0;
	    here = strchr(line,'#');
	    if (here) *here = 0;
	    if (strspn(line," \t") != strlen(line)) {
		entry = alloc_t(DT_ENTRY);
		items = sscanf(line,"0x%x 0x%x %d %d %d %d",&entry->device,
		  &entry->bios,&entry->sectors,&entry->heads,&entry->cylinders,
		  &entry->start);
		if (items == 5) entry->start = -1;
		if (items < 5)
		    die("Invalid line in %s:\n\"%s\"",name ? name : DFL_DISKTAB,
		      line);
		entry->next = disktab;
		disktab = entry;
		if (disk_section) die("DISKTAB and DISK are mutually exclusive");
		old_disktab = 1;
	    }
	}
	(void) fclose(file);
    }

    dm_major_nr = 0;
    file = fopen("/proc/devices", "r");
    if (!file) return;

    do {
	if (!fgets(line, (sizeof line)-1, file)) {
	    (void) fclose(file);
	    return;
	}
	line[(sizeof line)-1] = 0;
    } while(strncmp(line, "Block", 5) != 0);

    while(fgets(line, (sizeof line)-1, file)) {
	if (sscanf(line, "%d %31s\n", &major, major_name) != 2) continue;
	if (strcmp(major_name, "device-mapper") != 0) continue;
	dm_major_list[dm_major_nr] = major;
	if (verbose >= 3) {
	    printf("device-mapper major = %d\n", major);
	}
	if (++dm_major_nr > nelem(dm_major_list) ) break;
    }

    (void) fclose(file);


#ifdef LCF_DEVMAPPER
    if (!(dmt = dm_task_create(DM_DEVICE_VERSION)))
	return;
    if (!dm_task_run(dmt))
	return;
    if (!dm_task_get_driver_version(dmt, dm_version, sizeof dm_version))
	return;

    /*
     * to not confuse returned device number formats %02x:%02x and %d:%d
     * we assume here that the %02x:%02x format is only found in the ioctl
     * interface version < 4 (this is really getting ugly...)
     */
    dm_version_nr = atoi(dm_version);

    dm_task_destroy(dmt);
#endif
}


int is_dm_major(int major)
{
    int i;
    
    for(i=0; i<dm_major_nr; i++) {
        if (dm_major_list[i] == major) return 1;
    }
    return 0;
}



void do_partition(void)
{
    DT_ENTRY *entry,*walk;
    struct stat st;
    char *partition,*start;

    entry = alloc_t(DT_ENTRY);
    *entry = *disktab;
    entry->start = -1;
    partition = cfg_get_strg(cf_partitions,"partition");
    if (stat(partition,&st) < 0) die("stat %s: %s",partition,strerror(errno));
    if (!S_ISBLK(st.st_mode) || ((st.st_rdev ^ disktab->device) & D_MASK(st.st_rdev)))
	die("%s is not a valid partition device",partition);
    entry->device = st.st_rdev;
    cfg_init(cf_partition);
    (void) cfg_parse(cf_partition);
    start = cfg_get_strg(cf_partition,"start");
    entry->start = start ? to_number(start) : -1;
    for (walk = disktab; walk; walk = walk->next)
	if (entry->device == walk->device)
	    die("Duplicate geometry definition for %s",partition);
    entry->next = disktab;
    disktab = entry;
    cfg_init(cf_partitions);
}

#if BETA_TEST
int has_partitions_beta(dev_t dev)
{
    int major = MAJOR(dev);
    
    if (
      major == MAJOR_HD || major == MAJOR_IDE2 ||
      major == MAJOR_IDE3 || major == MAJOR_IDE4 ||
      major == MAJOR_IDE5 || major == MAJOR_IDE6 ||
      major == MAJOR_EMD  ||
      (major >= MAJOR_IDE7 && major <= MAJOR_IDE10) ||
      major == MAJOR_XT || major == MAJOR_ESDI || major == MAJOR_ACORN
      	) return 0xFFFFFFC0;	/* 6 bit partition mask */
      
    if (
      major == MAJOR_SD || (major >= MAJOR_SD2 && major <= MAJOR_SD8) ||
      major == MAJOR_AMI_HYP || major == MAJOR_HPT370 ||
      (major >= MAJOR_EXPR && major <= MAJOR_EXPR+3) ||
      (major >= MAJOR_I2O && major <= MAJOR_I2O+7) ||
      (major >= MAJOR_SMART2 && major <= MAJOR_SMART2+7) ||
      (major >= MAJOR_CISS && major <= MAJOR_CISS+7) ||
      major == MAJOR_FTL || major == MAJOR_NFTL || major == MAJOR_DOC ||
      (major >= MAJOR_SD9 && major <= MAJOR_SD16)
        ) return 0xFFFFFFF0;	/* 4 bit partition mask */

    if ( major == MAJOR_SATA || major == MAJOR_SATA2
        )  return 0xFFFFFFE0;	/* 5 bit partition mask */

    if ( major == MAJOR_IBM_iSER ||
      (major >= MAJOR_DAC960 && major <= MAJOR_DAC960+7) ||
      (major >= MAJOR_DAC960_8 && major <= MAJOR_DAC960_8+7)
        )  return 0xFFFFFFF8;	/* 3 bit partition mask */

    return 0;
}
#endif

static
unsigned char max_partno[512] = {
/*
  0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
*/
  0,  0,  0, 63,  0,  0,  0,  0, 15,  0,  0,  0,  0, 63,  0,  0,   /*  0x   */
  0,  0,  0,  0,  0, 63, 63,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  0, 63, 63,  0, 63,  0,  0,  0,  0,  0,  0,  0, 15,  0,  0,  0,
#ifndef MAJOR_IDE5
  7,  7,  7,  7,  7,  7,  7,  7,  0, 63,  0,  0, 15, 15, 15, 15,
#else
  7,  7,  7,  7,  7,  7,  7,  7, 63, 63,  0,  0, 15, 15, 15, 15,
#endif

  0, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,   /*  4x   */
 15, 15, 15, 15, 15, 15, 15, 15, 63, 63, 63, 63,  0, 15,  0,  0,
  0,  0,  0,  0, 15, 15,  0,  0, 15, 15, 15, 15, 15, 15, 15, 15,
  7,  0, 15,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
/*
  0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
*/
 15, 15, 15, 15, 15, 15, 15, 15,  7,  7,  7,  7,  7,  7,  7,  7,   /*  8x   */
  0,  0,  0,  0,  0,  0,  0,  0,  0, 63,  0,  0,  0,  0,  0,  0,
 31, 31,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,

  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,   /*  Cx   */
  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0
/*								   
  0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
*/
};

int has_partitions(dev_t dev)
{
   int major = MAJOR(dev);
   int ret=0;
   
   if (major >= nelem(max_partno)) {
	warn("Major Device (%d) > %d",
		major, nelem(max_partno)-1);
   }
   else if ( (ret=max_partno[major]) )  ret ^= 0xFFFFFFFF;
   
   return ret;
}


void do_disk(void)
{
    DT_ENTRY *entry,*walk;
    struct stat st;
    char *disk,*bios,*sectors,*heads,*cylinders,*maxpart;
    int major;

    disk = cfg_get_strg(cf_options,"disk");
    cfg_init(cf_disk);
    (void) cfg_parse(cf_disk);
    if (stat(disk,&st) < 0) {
        if (cfg_get_flag(cf_disk,"inaccessible")) {
            cfg_unset(cf_options,"disk");
            return;
        }
        die("do_disk: stat %s: %s",disk,strerror(errno));
    }
    if (!S_ISBLK(st.st_mode) || 
    	(has_partitions(st.st_rdev) && (MINOR(st.st_rdev) & P_MASK(st.st_rdev))))
		die(" '%s' is not a whole disk device",disk);

    entry = alloc_t(DT_ENTRY);
    entry->device = st.st_rdev;
    major = MAJOR(st.st_rdev);
    bios = cfg_get_strg(cf_disk,"bios");
    sectors = cfg_get_strg(cf_disk,"sectors");
    heads = cfg_get_strg(cf_disk,"heads");
    cylinders = cfg_get_strg(cf_disk,"cylinders");
    maxpart = cfg_get_strg(cf_disk,"max-partitions");
    if (maxpart) {
      if (major<nelem(max_partno)) {
	int i = to_number(maxpart);
	if (max_partno[major] && max_partno[major]!=i) die("Cannot alter 'max-partitions' for known disk  %s", disk);
	max_partno[major] = i;
	if (i!=7 && i!=15 && i!=31 && i!=63) die("disk=%s:  illegal value for max-partitions(%d)", disk, i);
      }
      else {
        die("Implementation restriction: max-partitions on major device > %d", nelem(max_partno)-1);
      }
    }
    entry->bios = bios ? to_number(bios) : -1;
    if (!sectors && !heads) entry->sectors = entry->heads = -1;
    else if (!(sectors && heads))
	    die("Must specify SECTORS and HEADS together");
	else {
	    entry->sectors = to_number(sectors);
	    entry->heads = to_number(heads);
	}
    if (cfg_get_flag(cf_disk,"inaccessible")) {
	entry->heads = 0;
	if (bios) die("INACCESSIBLE and BIOS are mutually exclusive");
	if ( sectors || heads || cylinders )
	    die("No geometry variables allowed if INACCESSIBLE");
    }
    entry->cylinders = cylinders ? to_number(cylinders) : -1;
    entry->start = 0;
    for (walk = disktab; walk; walk = walk->next) {
	if (entry->device == walk->device)
	    die("Duplicate \"disk =\" definition for %s",disk);
    }
    entry->next = disktab;
    disktab = entry;
    if (verbose >= 6) {
	printf("do_disk: %s %04X 0x%02X  %d:%d:%d\n",
		disk, entry->device, entry->bios, entry->cylinders,
		entry->heads, entry->sectors);
    }
    cfg_init(cf_partitions);
    (void) cfg_parse(cf_partitions);
    cfg_unset(cf_options,"disk");
}


static int exists(const char *name)
{
    struct hd_geometry dummy;
    int fd,yes;
    char buff;

    if ((fd = open(name,O_RDWR)) < 0) return 0; /* was O_RDONLY */
    yes = read(fd,&buff,1) == 1 && ioctl(fd,HDIO_GETGEO,&dummy) >= 0;
    (void) close(fd);
    return yes;
}


#if 0

static int scan_last_dev(ST_BUF *next,char *parent,int major,int increment)
{
    DIR *dp;
    struct dirent *dir;
    char name[PATH_MAX+1];
    ST_BUF st,*walk;
    int max,this;

    st.next = next;
    max = 0;
    if ((dp = opendir(parent)) == NULL)
	die("opendir %s: %s",parent,strerror(errno));
    while ((dir = readdir(dp))) {
	sprintf(name,"%s/%s",parent,dir->d_name);
	if (stat(name,&st.st) >= 0) {
	    if (S_ISBLK(st.st.st_mode) && MAJOR(st.st.st_rdev) == major &&
	      (MINOR(st.st.st_rdev) & (increment-1)) == 0) {
		this = MINOR(st.st.st_rdev)/increment+1;
		if (this > max && exists(name)) max = this;
	    }
	    if (S_ISDIR(st.st.st_mode) && strcmp(dir->d_name,".") &&
	      strcmp(dir->d_name,"..")) {
		for (walk = next; walk; walk = walk->next)
		    if (stat_equal(&walk->st,&st.st)) break;
		if (!walk) {
		    this = scan_last_dev(&st,name,major,increment);
		    if (this > max) max = this;
		}
	    }
	}
    }
    (void) closedir(dp);
    return max;
}

#endif


static int last_dev(int major,int increment)
{
/*
 * In version 12 to 18, LILO only relied on scan_last_dev (or last_dev). This
 * obviously didn't work if entries in /dev were missing. Versions 18 and 19
 * added the probe loop, which seems to be okay, but which may probe for
 * invalid minor numbers. The IDE driver objects to that. Since last_dev is
 * only used to count IDE drives anyway, we try now only the first two devices
 * and forget about scan_last_dev.
 */
    DEVICE dev;
    int devs;

    for (devs = 0;
	devs < 2 && dev_open(&dev,MKDEV(major,increment*devs),O_BYPASS);
	    devs++)
	if (exists(dev.name)) dev_close(&dev);
        else {
	    dev_close(&dev);
	    break;
	}
    return devs;
}


#ifdef LCF_LVM
void lvm_bmap(struct lv_bmap *lbm)
{
    DEVICE dev;
    static int lvmfd = -1;
    static dev_t last_dev = 0;

    if (lbm->lv_dev != last_dev) {
	char lvm_char[] = DEV_DIR "/lvm";
	unsigned short iop;

	if (lvmfd != -1)
	    close(lvmfd);

	if ((lvmfd = open(lvm_char, lbm->lv_dev, O_RDONLY)) < 0)
	    die("can't open LVM char device %s\n", lvm_char);

	if (ioctl(lvmfd, LVM_GET_IOP_VERSION, &iop) < 0)
	    die("LVM_GET_IOP_VERSION failed on %s\n", lvm_char);

	if (iop < 10)
	    die("LVM IOP %d not supported for booting\n", iop);
	close(lvmfd);

	lvmfd = dev_open(&dev, lbm->lv_dev, O_RDONLY);
	if (lvmfd < 0)
	    die("can't open LVM block device %#x\n", lbm->lv_dev);
	last_dev = lbm->lv_dev;
    }
    if (ioctl(lvmfd, LV_BMAP, lbm) < 0) {
	perror(__FUNCTION__);
	pdie("LV_BMAP error or ioctl unsupported, can't have image in LVM.\n");
    }
}
#endif


#ifdef LCF_EVMS
void evms_bmap(struct evms_get_bmap_t *ebm)
{                                  
    DEVICE dev;
    static int evms_fd = -1;
    static dev_t evms_last_dev = 0;

    if (ebm->dev != evms_last_dev) {
        char evms_blk[] = DEV_DIR "/evms/block_device";
        struct evms_version_t evms_ver;

        /* Open the EVMS device */
        if (evms_fd != -1)
            close(evms_fd);

        evms_fd = open(evms_blk, O_RDONLY);
        if (evms_fd < 0)
            die("Can't open EVMS block device %s.\n", evms_blk);

        /* Get EVMS ioctl version number. */
        if (ioctl(evms_fd, EVMS_GET_IOCTL_VERSION, &evms_ver) < 0)
            die("EVMS_GET_IOCTL_VERSION failed on %s.\n", evms_blk);

        /* Check that the ioctl version is >= 7.1.0 */
        if (evms_ver.major < 7 ||
            (evms_ver.major == 7 && evms_ver.minor < 1))
            die("EVMS ioctl version %d.%d.%d does not support booting.\n",
                evms_ver.major, evms_ver.minor, evms_ver.patch);
        close(evms_fd);

        evms_fd = dev_open(&dev, ebm->dev, O_RDONLY);
        if (evms_fd < 0)
            die("Can't open EVMS block device %#x\n", ebm->dev);
        evms_last_dev = ebm->dev;
    }

    if (ioctl(evms_fd, EVMS_GET_BMAP, ebm) < 0) {
        perror(__FUNCTION__);
        pdie("EVMS_GET_BMAP error or ioctl unsupported. Can't have image on EVMS volume.\n");
    }
}
#endif


void geo_query_dev(GEOMETRY *geo,int device,int all)
{
    DEVICE dev;
    int fd,get_all,major;
    struct floppy_struct fdprm;
    struct hd_geometry hdprm;

    if (verbose>=5) printf("geo_query_dev: device=%04X\n", device);
#if 0
/*  Werner's original */
    get_all = all || MAJOR(device) != MAJOR_FD; */
#else
/* simplify the condition -- JRC 2003-06-04 */
    get_all = all;
#endif
    if (!MAJOR(device))
	die("Trying to map files from unnamed device 0x%04x (NFS/RAID mirror down ?)",device);
    if (device == MAJMIN_RAM)
	die("Trying to map files from your RAM disk. "
	  "Please check -r option or ROOT environment variable.");
    if (get_all) {
	fd = dev_open(&dev,device,O_NOACCESS);
    }
    else {
	fd = -1; /* pacify GCC */
	geo->heads = geo->cylinders = geo->sectors = 1;
	geo->start = 0;
	geo->device = -1;
    }
    switch ((major=MAJOR(device))) {
	case MAJOR_FD:
	    geo->device = device & 3;
	    if (!get_all) break;
	    if (ioctl(fd,FDGETPRM,&fdprm) < 0)
		die("geo_query_dev FDGETPRM (dev 0x%04x): %s",device,
		  strerror(errno));
	    geo->heads = fdprm.head;
	    geo->cylinders = fdprm.track;
	    geo->sectors = fdprm.sect;
	    geo->start = 0;
	    break;
	case MAJOR_HD:
	case MAJOR_IDE2:
	case MAJOR_IDE3:
	case MAJOR_IDE4:
#ifdef MAJOR_IDE5
	case MAJOR_IDE5:
#endif
	case MAJOR_IDE6:
	case MAJOR_IDE7:
	case MAJOR_IDE8:
	case MAJOR_IDE9:
	case MAJOR_IDE10:
	case MAJOR_ESDI:
	case MAJOR_XT:
	case MAJOR_ACORN:
	MASK63:
	    geo->device = 0x80 + (MINOR(device) >> 6) +
		    (MAJOR(device) == MAJOR_HD ? 0 : last_dev(MAJOR_HD,64));
	    if (!get_all) break;
	    if (ioctl(fd,HDIO_GETGEO,&hdprm) < 0)
		die("geo_query_dev HDIO_GETGEO (dev 0x%04x): %s",device,
		  strerror(errno));
	    geo->heads = hdprm.heads;
	    geo->cylinders = hdprm.cylinders;
	    geo->sectors = hdprm.sectors;
	    geo->start = hdprm.start;
	    break;
	case MAJOR_SD:
	case MAJOR_SD2:
	case MAJOR_SD3:
	case MAJOR_SD4:
	case MAJOR_SD5:
	case MAJOR_SD6:
	case MAJOR_SD7:
	case MAJOR_SD8:
	MASK15:
	    geo->device = 0x80 + last_dev(MAJOR_HD,64) + (MINOR(device) >> 4);
	    if (!get_all) break;
	    if (ioctl(fd,HDIO_GETGEO,&hdprm) < 0)
		die("geo_query_dev HDIO_GETGEO (dev 0x%04x): %s",device,
		  strerror(errno));
	    if (all && !hdprm.sectors)
		die("HDIO_REQ not supported for your SCSI controller. Please "
		  "use a DISK section");
	    geo->heads = hdprm.heads;
	    geo->cylinders = hdprm.cylinders;
	    geo->sectors = hdprm.sectors;
	    geo->start = hdprm.start;
	    break;
	MASK31:
	    geo->device = 0x80 + last_dev(MAJOR_HD,64) + (MINOR(device) >> 5);
	    if (!get_all) break;
	    if (ioctl(fd,HDIO_GETGEO,&hdprm) < 0)
		die("geo_query_dev HDIO_GETGEO (dev 0x%04x): %s",device,
		  strerror(errno));
	    if (all && !hdprm.sectors)
		die("HDIO_REQ not supported for your Disk controller. Please "
		  "use a DISK section");
	    geo->heads = hdprm.heads;
	    geo->cylinders = hdprm.cylinders;
	    geo->sectors = hdprm.sectors;
	    geo->start = hdprm.start;
	    break;
	case MAJOR_DAC960:
	case MAJOR_DAC960+1:
	case MAJOR_DAC960+2:
	case MAJOR_DAC960+3:
	case MAJOR_DAC960+4:
	case MAJOR_DAC960+5:
	case MAJOR_DAC960+6:
	case MAJOR_DAC960+7:
	case MAJOR_IBM_iSER:
	MASK7:
	    geo->device = 0x80 + last_dev(MAJOR_HD,64) + (MINOR(device) >> 3);
	    if (!get_all) break;
	    if (ioctl(fd,HDIO_GETGEO,&hdprm) < 0)
		die("geo_query_dev HDIO_GETGEO (dev 0x%04x): %s",device,
		  strerror(errno));
	    if (all && !hdprm.sectors)
		die("HDIO_REQ not supported for your DAC960/IBM controller. "
		  "Please use a DISK section");
	    geo->heads = hdprm.heads;
	    geo->cylinders = hdprm.cylinders;
	    geo->sectors = hdprm.sectors;
	    geo->start = hdprm.start;
	    break;
	case MAJOR_AMI_HYP:
	case MAJOR_HPT370:
	case MAJOR_EXPR:
	case MAJOR_EXPR+1:
	case MAJOR_EXPR+2:
	case MAJOR_EXPR+3:
	case MAJOR_FTL:
	case MAJOR_NFTL:
	case MAJOR_DOC:
	case MAJOR_SMART2+0:
	case MAJOR_SMART2+1:
	case MAJOR_SMART2+2:
	case MAJOR_SMART2+3:
	case MAJOR_SMART2+4:
	case MAJOR_SMART2+5:
	case MAJOR_SMART2+6:
	case MAJOR_SMART2+7:
	case MAJOR_CISS+0:
	case MAJOR_CISS+1:
	case MAJOR_CISS+2:
	case MAJOR_CISS+3:
	case MAJOR_CISS+4:
	case MAJOR_CISS+5:
	case MAJOR_CISS+6:
	case MAJOR_CISS+7:
	case MAJOR_I2O:
	case MAJOR_I2O+1:
	case MAJOR_I2O+2:
	case MAJOR_I2O+3:
	case MAJOR_I2O+4:
	case MAJOR_I2O+5:
	case MAJOR_I2O+6:
	case MAJOR_I2O+7:
	    geo->device = 0x80 + last_dev(MAJOR_HD,64) + (MINOR(device) >> 4);
	    if (!get_all) break;
	    if (ioctl(fd,HDIO_GETGEO,&hdprm) < 0)
		die("geo_query_dev HDIO_GETGEO (dev 0x%04x): %s",device,
		  strerror(errno));
	    if (all && !hdprm.sectors)
		die("HDIO_REQ not supported for your Array controller. Please "
		  "use a DISK section");
	    geo->heads = hdprm.heads;
	    geo->cylinders = hdprm.cylinders;
	    geo->sectors = hdprm.sectors;
	    geo->start = hdprm.start;
	    break;

	default:
	    if (max_partno[major] && major==MAJOR_LOOP) break;
	    if (max_partno[major] == 63)  goto MASK63;
	    if (max_partno[major] == 31)  goto MASK31;
	    if (max_partno[major] == 15)  goto MASK15;
	    if (max_partno[major] == 7)   goto MASK7;
	    
	    if ((MAJOR(device)>=120 && MAJOR(device)<=127)  ||
	        (MAJOR(device)>=240 && MAJOR(device)<=254) )
		die("Linux experimental device 0x04x needs to be defined.\n"
		    "Check 'man lilo.conf' under 'disk=' and 'max-partitions='", device);
	    else die("Sorry, don't know how to handle device 0x%04x",device);
    }
    if (get_all) dev_close(&dev);
    if (verbose>=5) printf("exit geo_query_dev\n");
}


int is_first(int device)
{
    DT_ENTRY *walk;

    for (walk = disktab; walk; walk = walk->next)
	if (walk->device == device) break;
    if (!walk && !old_disktab)
	for (walk = disktab; walk; walk = walk->next)
	    if (walk->device == (device & D_MASK(device))) break;
    if (walk && !walk->heads)
	die("Device 0x%04X: Configured as inaccessible.\n",device);
    if (walk && walk->bios != -1) return !(walk->bios & 0x7f);
    switch (MAJOR(device)) {
	case MAJOR_FD:
	    return !(device & 3);

	case MAJOR_HD:
	    return !(MINOR(device) >> 6);

	case MAJOR_IDE2:
	case MAJOR_IDE3:
	case MAJOR_IDE4:
#ifdef MAJOR_IDE5
	case MAJOR_IDE5:
#endif
	case MAJOR_IDE6:
	case MAJOR_IDE7:
	case MAJOR_IDE8:
	case MAJOR_IDE9:
	case MAJOR_IDE10:
	case MAJOR_ESDI:
	case MAJOR_XT:
	    return MINOR(device) >> 6 ? 0 : !last_dev(MAJOR_HD,64);

	case MAJOR_SD:
	case MAJOR_SD2:
	case MAJOR_SD3:
	case MAJOR_SD4:
	case MAJOR_SD5:
	case MAJOR_SD6:
	case MAJOR_SD7:
	case MAJOR_SD8:
	case MAJOR_AMI_HYP:
	case MAJOR_HPT370:
	case MAJOR_EXPR+0:
	case MAJOR_EXPR+1:
	case MAJOR_EXPR+2:
	case MAJOR_EXPR+3:
	case MAJOR_NFTL:
	case MAJOR_DOC:
	case MAJOR_SMART2+0:
	case MAJOR_SMART2+1:
	case MAJOR_SMART2+2:
	case MAJOR_SMART2+3:
	case MAJOR_SMART2+4:
	case MAJOR_SMART2+5:
	case MAJOR_SMART2+6:
	case MAJOR_SMART2+7:
	case MAJOR_CISS+0:
	case MAJOR_CISS+1:
	case MAJOR_CISS+2:
	case MAJOR_CISS+3:
	case MAJOR_CISS+4:
	case MAJOR_CISS+5:
	case MAJOR_CISS+6:
	case MAJOR_CISS+7:
	case MAJOR_I2O:
	case MAJOR_I2O+1:
	case MAJOR_I2O+2:
	case MAJOR_I2O+3:
	case MAJOR_I2O+4:
	case MAJOR_I2O+5:
	case MAJOR_I2O+6:
	case MAJOR_I2O+7:
	    return MINOR(device) >> 4 ? 0 : !last_dev(MAJOR_HD,64);

	case MAJOR_DAC960:
	case MAJOR_DAC960+1:
	case MAJOR_DAC960+2:
	case MAJOR_DAC960+3:
	case MAJOR_DAC960+4:
	case MAJOR_DAC960+5:
	case MAJOR_DAC960+6:
	case MAJOR_DAC960+7:
	case MAJOR_IBM_iSER:
	    return MINOR(device) >> 3 ? 0 : !last_dev(MAJOR_HD,64);

	default:
	    return 1; /* user knows what (s)he's doing ... I hope */
    }
}


void geo_get(GEOMETRY *geo,int device,int user_device,int all)
{
    DT_ENTRY *walk;
    int inherited,keep_cyls,is_raid=0;
#ifdef LCF_DEVMAPPER
    int i;

    for(i = 0; i < dm_major_nr; i++)
	if (MAJOR(device) == dm_major_list[i])
	    break;
    while (i < dm_major_nr) {
	DM_TABLE *dm_table;

	for(dm_table = dmtab; dm_table; dm_table = dm_table->next)
	    if (dm_table->device == device)
		break;

	if (dm_table) {
	    DM_TARGET *target;

	     device = 0;
	    for(target = dm_table->target; target; target = target->next)
		device = target->device;
	} else {
	    DEVICE dev;
	    struct dm_task *dmt;
	    void *next = NULL;
	    char dmdev[PATH_MAX+1];
	    char buf[PATH_MAX+1];
	    char *slash;
	    int result;

	    dev_open(&dev, device, -1);
	    strncpy(dmdev, dev.name, PATH_MAX);
	    dmdev[PATH_MAX] = 0;
	    do {
		memset(buf, 0, PATH_MAX + 1);
		if ((result = readlink(dmdev, buf, PATH_MAX)) < 0 && errno != EINVAL)
		    die("device-mapper: readlink(\"%s\") failed with: %s",buf,
			strerror(errno));
		if (result >= 0) {
		    if (buf[0] != '/' && (slash = strrchr(dmdev, '/')) != NULL)
			slash++;
		    else
			slash = dmdev;
		    strncpy(slash, buf, PATH_MAX - (slash-dmdev));
		}
		if (realpath(dmdev, buf) == NULL)
		    die("device-mapper: realpath(\"%s\") failed with: %s",dmdev,
			strerror(errno));
		strncpy(dmdev, buf, PATH_MAX);
	    } while (result >= 0);
	    dmdev[PATH_MAX] = 0;

	    if (!(dmt = dm_task_create(DM_DEVICE_TABLE)))
		die("device-mapper: dm_task_create(DM_DEVICE_TABLE) failed");
	    slash = strrchr(dmdev, '/');
		if (slash)
	    slash++;
		else
	    slash = dmdev;
	    if (!dm_task_set_name(dmt, slash))
		die("device-mapper: dm_task_set_name(\"%s\") failed",dmdev);
	    if (!dm_task_run(dmt))
		die("device-mapper: dm_task_run(DM_DEVICE_TABLE) failed");

	    dm_table = alloc_t(DM_TABLE);
	    dm_table->device = device;
	    dm_table->target = NULL;
	    dm_table->next = dmtab;
	    dmtab = dm_table;

	    device = 0;

	    do {
		DM_TARGET *target;
		uint64_t start,length;
		int major,minor;
		char *target_type,*params;
		char *p;

		next = dm_get_next_target(dmt, next, &start, &length,
		  &target_type, &params);

		if (!target_type) continue;

		if (strcmp(target_type, "linear") != 0)
		    die("device-mapper: only linear boot device supported");

		target = alloc_t(DM_TARGET);
		target->start = start;
		target->length = length;
		if (dm_version_nr < 4 &&
		    isxdigit(params[0]) &&
		    isxdigit(params[1]) &&
		    params[2] == ':' &&
		    isxdigit(params[3]) &&
		    isxdigit(params[4])) { /* old 2.4 format */
		    if (sscanf(params, "%02x:%02x %"PRIu64, &major, &minor, &target->offset) != 3)
			die("device-mapper: parse error in linear params (\"%s\")", params);
		} else if (isdigit(params[0]) &&
			   strchr(params, ':')) { /* dm_bdevname/format_dev_t (>= 2.6.0-test4?) format */
		    if (sscanf(params, "%u:%u %"PRIu64, &major, &minor, &target->offset) != 3)
			die("device-mapper: parse error in linear params (\"%s\")", params);
		} else { /* >= 2.5.69 format, this should go away soon */
		    struct stat st;
		    FILE *file;

		    p = strrchr(params, ' ');
		    if (p == NULL)
			die("device-mapper: parse error in linear params (\"%s\")", params);
		    *p = 0;
		    sprintf(buf, DEV_DIR "/%s", params);	/* let's hope it's there */
		    if (stat(buf, &st) == 0) {
			if (!S_ISBLK(st.st_mode))
			    die("device-mapper: %s is not a valid block device", buf);
			major = MAJOR(st.st_rdev);
			minor = MINOR(st.st_rdev);
		    } else {				/* let's try sysfs */
			int dev;
			sprintf(buf, "/sys/block/%s/dev", params);
			file = fopen(buf, "r");
 			if (!file)
			    die("device-mapper: \"%s\" could not be opened. /sys mounted?", buf);
			if (!fgets(buf, PATH_MAX, file))
			    die("device-mapper: read error from \"/sys/block/%s/dev\"", params);
			if (sscanf(buf, "%u:%u", &major, &minor) != 2) {
			    if (sscanf(buf, "%x", &dev) != 1)
				die("device-mapper: error getting device from \"%s\"", buf);
			    major = MAJOR(dev);
			    minor = MINOR(dev);
			}
			(void) fclose(file);
		    }
		    *p = ' ';
		    if (sscanf(p+1, "%"PRIu64, &target->offset) != 1)
			die("device-mapper: parse error in linear params (\"%s\")", params);
		}
		target->device = (major << 8) | minor;
		if (!device)
		    device = target->device;
		target->next = dm_table->target;
		dm_table->target = target;
	    } while(next);

	    dm_task_destroy(dmt);

	    dev_close(&dev);
	}

	if (!device)
	    die("device-mapper: Error finding real device");
	geo->base_dev = device;

	for(i = 0; i < dm_major_nr; i++)
	    if (MAJOR(device) == dm_major_list[i])
		break;
    }
#endif

    if (verbose>=5) printf("geo_get: device %04X, all=%d\n", device, all);
#ifdef LCF_LVM
    /*
     * Find underlying device (PV) for LVM.  It is OK if the underlying PV is
     * really an MD RAID1 device, because the geometry of the RAID1 device is
     * exactly the same as the underlying disk, so FIBMAP and LV_BMAP should
     * return the correct block numbers regardless of MD.
     *
     * We do a quick test to see if the LVM LV_BMAP ioctl is working correctly.
     * It should map the two blocks with the same difference as they were input,
     * with a constant offset from their original block numbers.  If this is not
     * the case then LV_BMAP is not working correctly (some widely distributed
     * kernels did not have working LV_BMAP support, some just oops here).
     */
    if (MAJOR(device) == MAJOR_LVM)
    {
	struct lv_bmap lbmA, lbmB;
#define DIFF 255

	lbmA.lv_dev = lbmB.lv_dev = device;
	lbmA.lv_block = 0;
	lbmB.lv_block = DIFF;

	lvm_bmap(&lbmA);
	lvm_bmap(&lbmB);
	if (lbmB.lv_block - lbmA.lv_block != DIFF)
	    die("This version of LVM does not support boot LVs");
	device = geo->base_dev = lbmA.lv_dev;
    }
#endif

#ifdef LCF_EVMS
    if (MAJOR(device) == MAJOR_EVMS) {
        struct evms_get_bmap_t ebm;
        
        ebm.rsector = 0;
        ebm.dev = device;
        ebm.status = 0;
        
        evms_bmap(&ebm);
        
        device = geo->base_dev = ebm.dev;
    }
#endif

    /* Find underlying device for MD RAID */
    if (MAJOR(device) == MD_MAJOR) {
        char mdxxx[16];
	int md_fd;
/*	int pass;	*/
	struct md_version md_version_info;
	md_array_info_t md_array_info;
	md_disk_info_t md_disk_info;
	int raid_limit;

	sprintf(mdxxx, DEV_DISK_DIR "/md%d", MINOR(device));
	if ((md_fd=open(mdxxx,O_NOACCESS)) < 0)
	{
	    sprintf(mdxxx, DEV_DIR "/md/%d", MINOR(device));
	    if ((md_fd=open(mdxxx,O_NOACCESS)) < 0)
		die("Unable to open %s", mdxxx);
	}
	if (ioctl(md_fd,RAID_VERSION,&md_version_info) < 0)
	    die("Unable to get RAID version on %s", mdxxx);
	if (md_version_info.major > 0)
	    die("Raid major versions > 0 are not supported");
	if (md_version_info.minor < 90)
	    die("Raid versions < 0.90 are not supported");
	
	if (ioctl(md_fd,GET_ARRAY_INFO,&md_array_info) < 0)
	    die("Unable to get RAID info on %s", mdxxx);
	if ((md_array_info.major_version != md_version_info.major) &&
		(md_array_info.minor_version != md_version_info.minor))
	    die("Inconsistent Raid version information on %s", mdxxx);
	if (md_array_info.level != 1)
	    die("Only RAID1 devices are supported for boot images");
	raid_limit = md_array_info.raid_disks + md_array_info.spare_disks;

	/* version 22.7 */
#if 1
	is_raid = (device==boot_dev_nr);
	md_disk_info.number = raid_index;
	if (ioctl(md_fd,GET_DISK_INFO,&md_disk_info) < 0)
	    die("GET_DISK_INFO: %s", mdxxx);
	device = MKDEV(md_disk_info.major, md_disk_info.minor);

#else		/* prior to 22.7 */
{
int pass;
   	for (pass = 0; pass < raid_limit; pass++) {
	    md_disk_info.number = pass;
	    if (ioctl(md_fd,GET_DISK_INFO,&md_disk_info) < 0)
#if BETA_TEST
	    {
		printf("(raid) GET_DISK_INFO: failed for pass=%d\n", pass);
		continue;
	    }
#else
	        die("GET_DISK_INFO: %s", mdxxx);
#endif
	    if (!(md_disk_info.state & (1 << MD_DISK_FAULTY))) {
#if 1
		is_raid = (device==boot_dev_nr);
#else
/* this change may be in error; the correct comparison is == */
		is_raid = (device!=boot_dev_nr);
#endif
	        device = MKDEV(md_disk_info.major, md_disk_info.minor);
		break;
	    }
	}
}
#endif	/* end of code prior to version 22.7 */

	close(md_fd);
    }

#if BETA_TEST
	if (verbose>=5) printf("geo_get(2):  device=%04X, all=%d\n", device, all);
#endif

/* if using hard disk, scan the devices in /proc/partitions */
    if (has_partitions(device) && all)   pf_hard_disk_scan();




    for (walk = disktab; walk; walk = walk->next)
	if (walk->device == device) break;
    inherited = !walk && !old_disktab;
#if BETA_TEST
    if (verbose>=5) printf("inherited=%d\n", inherited);
#endif
    if (inherited)
	for (walk = disktab; walk; walk = walk->next)
	    if (walk->device == (device & D_MASK(device))) break;
#if BETA_TEST
    if (verbose>=5) printf("walk=%08lx\n", (long)walk);
#endif

#if 1
/* add 'all' to conditional below -- JRC 2002-08-20 */
    if (walk && !walk->heads && all)
#else
/* Werner's original conditional */
    if (walk && !walk->heads)
#endif
	die("Device 0x%04X: Configured as inaccessible.\n",device);
    keep_cyls = !walk || walk->bios == -1 || walk->heads == -1 ||
      walk->sectors == -1 || inherited || walk->start == -1;
#if BETA_TEST
    if (verbose>=5) printf("inherited=%d  keep_cyls=%d\n", inherited, keep_cyls);
#endif

#if 1
/* add 'all' to conditional below -- JRC 2002-08-20 */
    if (keep_cyls && (all || MAJOR(device)==MAJOR_FD) ) {
#else
/* Werner's original conditional */
    if (keep_cyls) {
#endif
	geo_query_dev(geo,device,all);
	
	if (all) bios_device(geo, device);
	
	if ((geo->device & 0x7f) >= bios_max_devs() &&
	  user_device == -1 && (!walk || walk->bios == -1))
	    warn("BIOS drive 0x%02x may not be accessible",
	      geo->device);
    }
    if (walk) {
	if (walk->bios != -1) geo->device = walk->bios;
	if (walk->heads != -1) geo->heads = walk->heads;
	if (walk->cylinders != -1 || !keep_cyls)
	    geo->cylinders = walk->cylinders;
	if (walk->sectors != -1) geo->sectors = walk->sectors;
	if (walk->start != -1 && !inherited) geo->start = walk->start;
    }
    if (user_device != -1) geo->device = user_device;
    if (!all) {
	if (verbose > 2)
	    printf("Device 0x%04x: BIOS drive 0x%02x, no geometry.\n",device,
	      geo->device);
	return;
    }
    if (!geo->heads || !geo->cylinders || !geo->sectors)
	die("Device 0x%04X: Got bad geometry %d/%d/%d\n",device,
	  geo->sectors,geo->heads,geo->cylinders);
    if (geo->heads > BIOS_MAX_HEADS)
	die("Device 0x%04X: Maximum number of heads is %d, not %d\n",device,
	  BIOS_MAX_HEADS,geo->heads);
    if (geo->heads == BIOS_MAX_HEADS)
	warn("Maximum number of heads = %d (as specified)\n"
			"   exceeds standard BIOS maximum of 255.", geo->heads);
    if (geo->sectors > BIOS_MAX_SECS)
	die("Device 0x%04X: Maximum number of sectors is %d, not %d\n",
	  device,BIOS_MAX_SECS,geo->sectors);
    if (geo->sectors == BIOS_MAX_SECS)
        warn("Maximum number of heads = %d (as specified)\n"
                        "   exceeds standard BIOS maximum of 63.", geo->sectors);
    if (!lba32 &&
      (geo->start+geo->sectors-1)/geo->heads/geo->sectors >= BIOS_MAX_CYLS
    ) {
	warn("device 0x%04x exceeds %d cylinder limit.\n"
        "   Use of the 'lba32' option may help on newer (EDD-BIOS) systems.",
	  device, BIOS_MAX_CYLS);
    }
    if (verbose >= 3) {
	printf("Device 0x%04x: BIOS drive 0x%02x, %d heads, %d cylinders,\n",
	  device,geo->device,geo->heads,geo->cylinders == -1 ? BIOS_MAX_CYLS :
	  geo->cylinders);
	printf("%15s%d sectors. Partition offset: %d sectors.\n","",
	  geo->sectors,geo->start);
    }
    geo->raid = is_raid;

/* make the serial number association */
    if (!is_raid) register_bios(geo->device, device);
    else geo->device = md_bios;		/* 22.5.7 add this else */
    
    return;
} /* end of geo_get */


int geo_open(GEOMETRY *geo,char *name,int flags)
{
    char *here;
    int user_dev,block_size;
    struct stat st;

    if ((here = strrchr(name,':')) == NULL) user_dev = -1;
    else {
	*here++ = 0;
        warn("%s:BIOS syntax is no longer supported.\n    Please use a "
	  "DISK section.", name);
	user_dev = to_number(here);
    }
    if ((geo->fd = open(name,flags)) < 0)
	die("open %s: %s",name,strerror(errno));
    if (fstat(geo->fd,&st) < 0) die("fstat %s: %s",name,strerror(errno));
    if (!S_ISREG(st.st_mode) && !S_ISBLK(st.st_mode))
	die("%s: neither a reg. file nor a block dev.",name);
    geo->dev = S_ISREG(st.st_mode) ? st.st_dev : st.st_rdev;
#if BETA_TEST
	if (verbose>=4) {
		printf("geo_open: (%s) st_dev(file)=%04X  st_rdev(blk)=%04X\n",
		name,
		(int)st.st_dev,
		(int)st.st_rdev );
	}
#endif

    geo_get(geo, geo->dev, user_dev, 1);
    geo->file = S_ISREG(st.st_mode) ? st.st_dev : 0;
    geo->boot = 0;
#ifndef FIGETBSZ
    geo->spb = 2;
#else
    if (!geo->file) geo->spb = 2;
    else {
	if (ioctl(geo->fd,FIGETBSZ,&block_size) < 0) {
	    warn("FIGETBSZ %s: %s",name,strerror(errno));
	    geo->spb = 2;
	}
	else {
	    if (!block_size || (block_size & (SECTOR_SIZE-1)))
		die("Incompatible block size: %d\n",block_size);
	    geo->spb = block_size/SECTOR_SIZE;
	}
    }
#endif
    return geo->fd;
}


int geo_open_boot(GEOMETRY *geo,char *name)
{
    struct stat st;

    if (verbose>=5) printf("geo_open_boot: %s\n", name);
    if (stat(name,&st) < 0) die("stat %s: %s",name,strerror(errno));
    if (!S_ISREG(st.st_mode) && !S_ISBLK(st.st_mode))
	die("%s: neither a reg. file nor a block dev.",name);
    geo->dev = S_ISREG(st.st_mode) ? st.st_dev : st.st_rdev;
#if 1
    if (MAJOR(geo->dev) == MAJOR_FD) geo->fd = 0;
    else if ((geo->fd = open(name,O_NOACCESS)) < 0)
	    die("open %s: %s",name,strerror(errno));
#else
    if (MAJOR(geo->dev) != MAJOR_FD) {
	if ((P_MASK(geo->dev) & geo->dev) != 0)
	    die("UNSAFE may be used with floppy or MBR only");
    }
    geo->fd = 0;
#endif
    geo_get(geo, geo->dev, -1, 0);
    geo->file = S_ISREG(st.st_mode);
    geo->raid = 0;
    geo->boot = 1;
    geo->spb = 1;
    return geo->fd;
}


void geo_close(GEOMETRY *geo)
{
    if (geo->fd) (void) close(geo->fd);
    geo->fd = 0;
}


#ifndef FIBMAP
#define FIBMAP BMAP_IOCTL
#endif


int geo_comp_addr(GEOMETRY *geo,int offset,SECTOR_ADDR *addr)
{
    int block,sector;
    static int linear_warnings = 0;

#if BETA_TEST
    if (verbose>=6)
	printf("geo_comp_addr: dev = %x, offset=%d\n",
		geo->device, offset);
#endif

#if 0
    if (linear && lba32)
       die("'linear' and 'lba32' (-l and -L) are mutually exclusive.");
#endif
    if (geo->boot && offset >= SECTOR_SIZE)
	die("Internal error: sector > 0 after geo_open_boot");
    block = offset/geo->spb/SECTOR_SIZE;
    if (geo->file) {
#ifdef LCF_REISERFS
	    struct statfs buf;

	    fstatfs(geo->fd, &buf);
	    if (buf.f_type == REISERFS_SUPER_MAGIC) {
		if (ioctl (geo->fd, REISERFS_IOC_UNPACK, 1) == ENOSPC)
			die("Cannot unpack ReiserFS file");
		if (verbose > 3) printf("fd %d: REISERFS_IOC_UNPACK\n", geo->fd);
	    }
        /* Forcing reiser4 to perform tail2extent converstion */
           if (buf.f_type == REISER4_SUPER_MAGIC) {
               if (ioctl (geo->fd, REISER4_IOC_UNPACK, 1) != 0)
                       die("Cannot unpack Reiser4 file");
               if (verbose > 3) printf("fd %d: REISER4_IOC_UNPACK\n", geo->fd);

           /* 
               As we may have the situation when extent will be included
               into transaction, and its item(s) will not be have the real block
               numbers assigned, we should perform fsync() in order to guarantee,
               that current atom is flushed and real block numbers assigned to 
               the extent(s) file was converted in.
           */
		if (fdatasync(geo->fd) != 0)
		    die("Cannot perform fdatasync");
           
		if (verbose > 3) printf("fd %d: fdatasync()\n", geo->fd);
           }
#endif
	if (ioctl(geo->fd,FIBMAP,&block) < 0) pdie("ioctl FIBMAP");
	if (!block) {
	    return 0;
	}
    }
#ifdef LCF_LVM
    if (MAJOR(geo->dev) == MAJOR_LVM) {
	struct lv_bmap lbm;

	lbm.lv_dev = geo->dev;
	lbm.lv_block = block;

	lvm_bmap(&lbm);
	if (lbm.lv_dev != geo->base_dev)
	    die("LVM boot LV cannot be on multiple PVs\n");
	block = lbm.lv_block;
    }
#endif

#ifdef LCF_EVMS
    if (MAJOR(geo->dev) == MAJOR_EVMS) {
        struct evms_get_bmap_t ebm;
                          
        ebm.rsector = block * geo->spb;
        ebm.dev = geo->dev;
        ebm.status = 0;
                            
        evms_bmap(&ebm);
        if (ebm.dev != geo->base_dev)
            die("EVMS boot volume cannot be on multiple disks.\n");
        sector = ebm.rsector + ((offset/SECTOR_SIZE) % geo->spb) + geo->start;
    }
    else
#endif
    {
#ifdef LCF_DEVMAPPER 
	int dev = geo->dev;
	int i;
#endif
	sector = block*geo->spb+((offset/SECTOR_SIZE) % geo->spb);
#ifdef LCF_DEVMAPPER 
	for(i = 0; i < dm_major_nr; i++)
	    if (MAJOR(dev) == dm_major_list[i])
		break;
	while (i < dm_major_nr) {
	    DM_TABLE *dm_table;
	    DM_TARGET *dm_target;

	    for(dm_table = dmtab; dm_table; dm_table = dm_table->next)
		if (dm_table->device == dev)
		    break;
	    if (!dm_table)
		die("device-mapper: Mapped device suddenly lost? (%d)", dev);

	    for(dm_target = dm_table->target; dm_target; dm_target = dm_target->next)
		if (dm_target->start <= sector && sector < (dm_target->start+dm_target->length))
		    break;
	    if (!dm_target)
		die("device-mapper: Sector outside mapped device? (%d: %u/%"PRIu64")",
		    geo->base_dev, sector, (uint64_t)(dm_table->target ?
		      (dm_table->target->start+dm_table->target->length) : 0));

	    dev = dm_target->device;
	    sector = dm_target->offset+(sector-dm_target->start);

	    for(i = 0; i < dm_major_nr; i++)
		if (MAJOR(dev) == dm_major_list[i])
		    break;
	}

	if (dev != geo->dev && dev != geo->base_dev)
	    die("device-mapper: mapped boot device cannot be on multiple real devices\n");
#endif
	sector += geo->start;
    }

 /*   DON'T always use CHS addressing on floppies:     JRC   */
/*    if ((geo->device & 0x80) && (linear || lba32)) {	*/
    if ((linear || lba32)) {
        addr->device = geo->device | (linear ? LINEAR_FLAG : (LBA32_FLAG|LBA32_NOCOUNT))
#if 0
       		| (do_md_install && geo->file==boot_dev_nr ? RAID_REL_FLAG : 0);
#else
       		| (do_md_install && geo->raid ? RAID_REL_FLAG : 0);
#endif
        addr->num_sect = linear ? 1 : (sector >> 24);
	addr->sector = sector & 0xff;
	addr->track = (sector >> 8) & 0xff;
	addr->head = sector >> 16;
	if (linear) {
	    int cyl = sector;
	    if (geo->sectors>0 && geo->heads>0) {
	    	cyl /= geo->sectors;
	    	cyl /= geo->heads;
	    	if (cyl >= BIOS_MAX_CYLS && linear_warnings++ < 8) {
		    warn("LINEAR may generate cylinder# above 1023 at boot-time.");
	    	}
	    }
            if (sector/(63*255) >= BIOS_MAX_CYLS)
		die("Sector address %d too large for LINEAR"
					" (try LBA32 instead).", sector);
	}
	if (verbose > 4)
	    printf("fd %d: offset %d -> dev 0x%02x, %s %d\n",
		         geo->fd, offset, addr->device,
		         lba32 ? "LBA" : "linear",
		         sector);
    }
    else {
	addr->device = geo->device;
	addr->sector = 1;
	addr->head = 0;
	if (sector) {
	    if (geo->heads == 0)
		die("BIOS device 0x%02x is inaccessible", geo->device);
	    addr->sector = (sector % geo->sectors)+1;
 	    sector /= geo->sectors;
	    addr->head = sector % geo->heads;
	    sector /= geo->heads;
	}
	if (sector >= BIOS_MAX_CYLS)
	    die("geo_comp_addr: Cylinder number is too big (%d > %d)",sector,
	      BIOS_MAX_CYLS-1);
	if (sector >= geo->cylinders && geo->cylinders != -1)
	    die("geo_comp_addr: Cylinder %d beyond end of media (%d)",sector,
	      geo->cylinders);
	if (verbose > 4)
	    printf("fd %d: offset %d -> dev 0x%02x, head %d, track %d, sector %d\n",
	      geo->fd,offset,addr->device,addr->head,sector,addr->sector);
	addr->track = sector & 255;
	addr->sector |= (sector >> 8) << 6;
        addr->num_sect = 1;
    }

    return 1;
}


int geo_find(GEOMETRY *geo,SECTOR_ADDR addr)
{
    SECTOR_ADDR here;
    struct stat st;
    int i;

#if DEBUG_NEW
    if (verbose>=2) {
	printf("Find:  AL=%02x  CX=%04x  DX=%04x  LBA=%d\n", (int)addr.num_sect,
		addr.sector + (addr.track<<8),
		addr.device + (addr.head<<8),
		addr.sector + (addr.track<<8) + (addr.head<<16) +
		(addr.device&(LBA32_FLAG|LBA32_NOCOUNT)?addr.num_sect<<24:0) );
    }
#endif
    if (fstat(geo->fd,&st) < 0) return 0;
    geo_get(geo,st.st_dev,-1,1);
    for (i = 0; i < (st.st_size+SECTOR_SIZE-1)/SECTOR_SIZE; i++)
	if (geo_comp_addr(geo,i*SECTOR_SIZE,&here))
	    if (here.sector == addr.sector && here.track == addr.track &&
	      here.device == addr.device && here.head == addr.head &&
	      here.num_sect == addr.num_sect ) {
		if (lseek(geo->fd,i*SECTOR_SIZE,SEEK_SET) < 0) return 0;
		else return 1;
	    }
    return 1;
}


#if 0
int geo_devscan(int device)
{
    DT_ENTRY *walk;
    unsigned int mask, codes = 0;
    int bios;
    int maxbios = 0;
    
    device &= D_MASK(device);

/* mark those BIOS codes that are already used */
    for (walk=disktab; walk; walk=walk->next) {
	if (has_partitions(walk->device) && walk->bios != -1) {
	    bios = walk->bios & 0x7F;
	    if (bios >= 4*sizeof(codes) ) die("BIOS code %02X is too big (device %04X)", bios, device);
	    codes |= 1 << bios;	
	}
    }

    bios = -1;
/* extract BIOS code of master device, or -1 */
    for (walk=disktab; walk; walk=walk->next) {
	if (device == walk->device) {
	    bios = walk->bios;
	}
    }
    if (bios > maxbios) maxbios = bios;

/* if device has no BIOS code assigned, assign the next one */
    if (bios == -1)
	for (bios=0x80, mask=1; mask; mask<<=1, bios++)
		if (!(mask&codes)) break;
    
    if (bios > DEV_MASK) die("geo_devscan:  ran out of device codes");
    
    for (walk=disktab; walk; walk=walk->next) {
	if (device == walk->device) {
	    if (walk->bios == -1) walk->bios = bios;
	    else bios = walk->bios;
	    break;
	}
    }
    if (bios > maxbios) maxbios = bios;
    
    if (verbose >= 2) printf("geo_devscan:  maxbios = %02X\n", maxbios);
    
    if (walk) return maxbios;	/* there was an entry in the disktab */
    
    walk = alloc_t(DT_ENTRY);
    walk->device = device;
    walk->bios = bios;
    walk->sectors = walk->heads = walk->cylinders = walk->start = -1;
    walk->next = disktab;
    disktab = walk;
    if (verbose>=2)
	printf("geo_devscan: arbitrary bios assignment  dev=%04X  bios=0x%02X\n",
			device, bios);

    for (walk=disktab; walk; walk=walk->next) {
	if (device == (walk->device & D_MASK(walk->device))) {
	    if (walk->bios != -1) walk->bios = bios;
	}
    }

    return maxbios;
}

#endif

