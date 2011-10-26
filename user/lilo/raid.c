/* raid.c  -  The RAID-1 hooks for LILO */
/*
Copyright 2001-2005 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

/*#include <asm/page.h>*/

#include "config.h"
#include "lilo.h"
#include "common.h"
#include "raid.h"
#include "boot.h"
#include "device.h"
#include "geometry.h"
#include "bsect.h"
#include "cfg.h"
#include "partition.h"
#include "md-int.h"

static int lowest;
static DT_ENTRY *md_disk;
static DT_ENTRY *disk;
static unsigned int raid_base, raid_offset[MAX_RAID];
static char *raid_mbr[MAX_RAID];
static int raid_device[MAX_RAID+1];
static int raid_bios[MAX_RAID+1];
static int device;
enum {MD_NULL=0, MD_PARALLEL, MD_MIXED, MD_SKEWED};
int do_md_install, ndisk, md_bios;
static char *raid_list[MAX_RAID];
static int list_index[MAX_RAID];
static int nlist, faulty;
static int autocount;
static char *boot;

#define IS_COVERED    0x1000
#define TO_BE_COVERED 0x2000
#define COVERED   (IS_COVERED|TO_BE_COVERED)

static int is_primary(int device)
{
    int mask;
    
    mask = has_partitions(device);
    if (!mask) die("is_primary:  Not a valid device  0x%04X", device);
    mask = device & ~mask;
    return (mask && mask<=PART_MAX);
}



static int master(int device)
{
    int mask;
    
    if (MAJOR(device) == MAJOR_FD) return device;
    
    mask = has_partitions(device);
    if (!mask) die("master:  Not a valid device  0x%04X", device);
    return device & mask;
}


static int is_accessible(int device)
{
    int mask;
    
    mask = has_partitions(device);
    if (!mask) die("is_accessible:  Not a valid device  0x%04X", device);
    mask = device & ~mask;
    return (mask<=PART_MAX);
}


int raid_setup(void)
{
    int pass, mask;
    struct stat st;
    int md_fd;
    struct md_version md_version_info;
    md_disk_info_t md_disk_info;
    md_array_info_t md_array_info;
    GEOMETRY geo;
    DEVICE dev;
    char *extrap;
    int raid_offset_set, all_pri_eq, pri_index;
    int pri_offset;
    int raid_limit;
    
    if (!(boot=cfg_get_strg(cf_options,"boot"))) {
	boot = "/";
#if 0
      warn("RAID1 install implied by omitted 'boot='");
#endif
    }
    if (stat(boot,&st)<0) die("raid_setup: stat(\"%s\")", boot);

    if (verbose>=5)
	printf("raid_setup: dev=%04X  rdev=%04X\n",
				(int)st.st_dev, (int)st.st_rdev);

#if BETA_TEST
	fflush(stdout);
#endif

    if ( MAJOR(st.st_rdev) != MAJOR_MD ) {	/* not raid */
	if (cfg_get_strg(cf_options, RAID_EXTRA_BOOT))
	    die("Not a RAID install, '" RAID_EXTRA_BOOT "=' not allowed");
	return 0;
    }
    else {	/* It is a RAID installation */

	if (!nowarn && boot[0]=='/' && !boot[1])
	   warn("RAID1 install implied by 'boot=/'\n");
	   
/* scan the devices in /proc/partitions */
	pf_hard_disk_scan();


	if ((md_fd=dev_open(&dev, st.st_rdev, O_NOACCESS) ) < 0)
	    die("Unable to open %s",boot);
	boot = stralloc(dev.name);
	if (fstat(md_fd,&st) < 0)
	    die("Unable to stat %s",boot);
	if (!S_ISBLK(st.st_mode))
	    die("%s is not a block device",boot);

	boot_dev_nr = st.st_rdev;	/* set this very early */

	if (ioctl(md_fd,RAID_VERSION,&md_version_info) < 0)
	    die("Unable to get RAID version on %s", boot);
        if (verbose >= 4) printf("RAID_VERSION = %d.%d\n",
                (int)md_version_info.major,
                (int)md_version_info.minor);
	if (md_version_info.major > 0)
	    die("Raid major versions > 0 are not supported");
	if (md_version_info.minor < 90)
	    die("Raid versions < 0.90 are not supported");
	
	if (ioctl(md_fd,GET_ARRAY_INFO,&md_array_info) < 0)
	    die("Unable to get RAID info on %s",boot);
        if (verbose >= 4) printf("GET_ARRAY_INFO version = %d.%d\n",
                (int)md_array_info.major_version,
                (int)md_array_info.minor_version);
	if ((md_array_info.major_version != md_version_info.major) &&
		(md_array_info.minor_version != md_version_info.minor)) {
	    die("Inconsistent Raid version information on %s   (RV=%d.%d GAI=%d.%d)",
	        boot,
                (int)md_version_info.major,
                (int)md_version_info.minor,
                (int)md_array_info.major_version,
                (int)md_array_info.minor_version);
	    }
	if (md_array_info.level != 1)
	    die("Only RAID1 devices are supported as boot devices");
	if (!linear && !lba32) {
	    lba32 = 1;
	    if (!nowarn)
		warn("RAID install requires LBA32 or LINEAR;"
			" LBA32 assumed.\n");
	}
	extrap = cfg_get_strg(cf_options, RAID_EXTRA_BOOT);
	extra = !extrap ? X_AUTO :
		!strcasecmp(extrap,"none") ? X_NONE :
		!strcasecmp(extrap,"auto") ? X_AUTO :
		!strcasecmp(extrap,"mbr-only") ? X_MBR_ONLY :
		!strcasecmp(extrap,"mbr") ? X_MBR :
		    X_SPEC;
	
	do_md_install = MD_PARALLEL;

	all_pri_eq = 1;
	raid_offset_set = pri_index = pri_offset = 0;
	raid_flags = FLAG_RAID;
	md_bios = 0xFF;			/* we want to find the minimum */
	ndisk = 0;			/* count the number of disks on-line */
	nlist = 0;
	faulty = 0;
	
	device = MKDEV(MD_MAJOR, md_array_info.md_minor);
	
    /* search the disk table for a definition */
	md_disk = disktab;
	while (md_disk && md_disk->device != device)
	    md_disk = md_disk->next;
	    
	if (!md_disk) {
	    md_disk = alloc_t(DT_ENTRY);
	    md_disk->device = MKDEV(MD_MAJOR, md_array_info.md_minor);
	    md_disk->bios = -1;	/* use the default */
	    md_disk->next = disktab;
	    disktab = md_disk;
	}

	if (verbose >= 2) {
	   printf("RAID info:  nr=%d, raid=%d, active=%d, working=%d, failed=%d, spare=%d\n",
		md_array_info.nr_disks,
		md_array_info.raid_disks,
		md_array_info.active_disks,
		md_array_info.working_disks,
		md_array_info.failed_disks,
		md_array_info.spare_disks );
	}

    /* scan through all the RAID devices */
	raid_limit = md_array_info.raid_disks;
	if (md_array_info.active_disks < md_array_info.raid_disks) {
	    if (!force_raid) die("Not all RAID-1 disks are active; use '-H' to install to active disks only");
	    else {
		warn("Partial RAID-1 install on active disks only; booting is not failsafe\n");
		raid_limit = md_array_info.active_disks;
	    }
	}
	raid_index = 0;
   	for (pass=0; pass < raid_limit; pass++) {
	    DEVICE dev;
	    int disk_fd;
	    char new_name[MAX_TOKEN+1];
	    char *np;
	    
	    md_disk_info.number = pass;
	    if (ioctl(md_fd,GET_DISK_INFO,&md_disk_info) < 0)
#if 1
		die("raid: GET_DISK_INFO: %s, pass=%d", strerror(errno), pass);
#else
		{
		printf("raid: GET_DISK_INFO: %s, pass=%d\n", strerror(errno), pass);
		continue;
		}
#endif
	    device = MKDEV(md_disk_info.major, md_disk_info.minor);
            if(verbose>=3) printf("md: RAIDset device %d = 0x%04X\n", pass, device);	    
	    if (device == 0) { /* empty slot left over from recovery process */
		faulty++;
		warn("Faulty disk in RAID-1 array; boot with caution!!");
		continue;
	    }
	    disk_fd = dev_open(&dev,device,O_NOACCESS);
	    if (md_disk_info.state & (1 << MD_DISK_FAULTY)) {
		printf("disk %s marked as faulty, skipping\n",dev.name);
		faulty++;
		continue;
	    }
	    geo_get(&geo, device, -1, 1);
	    disk = alloc_t(DT_ENTRY);
	    if (verbose>=3)
		printf("RAID scan: geo_get: returns geo->device = 0x%02X"
		      " for device %04X\n", geo.device, device);
	      
	    disk->bios = geo.device;	/* will be overwritten */
	    disk->device = device;
	      /* used to mask above with 0xFFF0; forces MBR; sloppy, mask may be: 0xFFF8 */
	    disk->sectors = geo.sectors;
	    disk->heads = geo.heads;
	    disk->cylinders = geo.cylinders;
	    disk->start = geo.start;
	    if (ndisk==0) {
		raid_base = geo.start;
		raid_index = pass;
	    }
	    raid_offset[ndisk] = geo.start - raid_base;
	    raid_device[ndisk] = device;

	    if (raid_offset[ndisk]) {
	        do_md_install = MD_SKEWED;	 /* flag non-zero raid_offset */
	    }

	    if (all_pri_eq && is_primary(device)) {
		if (raid_offset_set) {
		    all_pri_eq &= (pri_offset == raid_offset[ndisk]);
		} else {
		    pri_offset = raid_offset[ndisk];
		    raid_offset_set = 1;
		    pri_index = ndisk;
		}
	    }

#if 1
	    if (geo.device < md_bios) {	/* OLD: use smallest device code */
#else
	    if (ndisk==0) {	/* NEW: use the device code of the first device */
#endif
	        md_bios = geo.device;	/* find smallest device code, period */
	        lowest = ndisk;		/* record where */
	    }
	    raid_bios[ndisk] = geo.device;  /* record device code */

	    disk->next = disktab;
	    disktab = disk;

	    if (verbose >= 3 && do_md_install) {
		printf("disk->start = %d\t\traid_offset = %d (%08X)\n",
		   disk->start, (int)raid_offset[ndisk], (int)raid_offset[ndisk]);
	    }
   	
	/* derive the MBR name, which may be needed later */
	    strncpy(new_name,dev.name,MAX_TOKEN);
	    new_name[MAX_TOKEN] = '\0';
	    np = boot_mbr(dev.name, 0);
	    if (!np) np = stralloc(new_name);
	    raid_mbr[ndisk] = np;

	    if (ndisk==0) {	/* use the first disk geometry */
		md_disk->sectors = geo.sectors;
		md_disk->heads = geo.heads;
		md_disk->cylinders = geo.cylinders;
		md_disk->start = geo.start;
	    }
	    
	    ndisk++;  /* count the disk */
   	}  /* for (pass=...    */

	dev_close(&dev);
   	raid_bios[ndisk] = 0;		/* mark the end */
   	raid_device[ndisk] = 0;

	all_pri_eq &= raid_offset_set;
	if (all_pri_eq && do_md_install == MD_SKEWED) {
	    do_md_install = MD_MIXED;
	}
	else pri_index = lowest;

	autocount = 0;
	/* check that all devices have an accessible block for writeback info */
	for (pass=0; pass < ndisk; pass++) {
	    if (extra == X_MBR_ONLY || extra == X_MBR)
		raid_bios[pass] |= TO_BE_COVERED;

	    if (extra == X_AUTO /*&& raid_bios[pass] != 0x80*/) {
		if (do_md_install == MD_SKEWED)  {
		    raid_bios[pass] |= TO_BE_COVERED;
		    autocount++;
		}
		if (do_md_install == MD_MIXED) {
		    if (is_primary(raid_device[pass])) raid_bios[pass] |= IS_COVERED;
		    else  {
			raid_bios[pass] |= TO_BE_COVERED;
			autocount++;
		    }
		}
	    }
	    if (extra != X_MBR)
	    if ((do_md_install == MD_PARALLEL && is_accessible(raid_device[pass]))
		|| (do_md_install == MD_MIXED && pri_offset == raid_offset[pass]
		        && is_primary(raid_device[pass]))
		)    
		raid_bios[pass] |= IS_COVERED;
	}
	   	
	nlist = 0;
	if (extra==X_SPEC) {
	    char *next, *scan;
	    
	    scan = next = extrap;
	    while (next && *next) {
		scan = next;
		while (isspace(*scan)) scan++;	/* deblank the line */
		next = strchr(scan, ',');	/* find the separator */
		if (next) *next++ = 0;		/* NUL terminate  scan */
		    
		if ((md_fd=open(scan,O_NOACCESS)) < 0)
		    die("Unable to open %s", scan);
		if (fstat(md_fd,&st) < 0)
		    die("Unable to stat %s",scan);
		if (!S_ISBLK(st.st_mode))
		    die("%s (%04X) not a block device", scan, (int)st.st_rdev);
		if (verbose>=4) printf("RAID list: %s is device 0x%04X\n",
				scan, (int)st.st_rdev);	    	
		close(md_fd);
		
		list_index[nlist] = ndisk;  /* raid_bios==0 here */
		for (pass=0; pass < ndisk; pass++) {
		    if (master(st.st_rdev) == master(raid_device[pass])) {
		    	list_index[nlist] = pass;
		    	if (st.st_rdev == raid_device[pass])
			    die("Cannot write to a partition within a RAID set:  %s", scan);
		    	else if (is_accessible(st.st_rdev))
		    	    raid_bios[pass] |= IS_COVERED;
		    	break;
		    }
		}
		if (list_index[nlist] == ndisk) {
#ifdef FLAG_RAID_NOWRITE
		    raid_flags |= FLAG_RAID_NOWRITE;  /* disk is outside RAID set */
#endif
		    if (!nowarn) printf("Warning: device outside of RAID set  %s  0x%04X\n", 
		    				scan, (int)st.st_rdev);
		}
		raid_list[nlist++] = stralloc(scan);
	    }
	    
	}
	
	   	
    /* if the install is to MBRs, then change the boot= name */
	if (extra == X_MBR_ONLY) {
#if 0
	    if (cfg_get_strg(cf_options,"boot")) cfg_unset(cf_options,"boot");
	    cfg_set(cf_options, "boot", (boot=raid_mbr[0]), NULL);
#endif
	}
	else {	/* if skewed install, disable mdX boot records as 
							source of writeback info */
	    if (do_md_install == MD_SKEWED) raid_flags |= FLAG_RAID_DEFEAT
#ifdef FLAG_RAID_NOWRITE
			| (extra == X_NONE ? FLAG_RAID_NOWRITE : 0)
#endif
			;
	}

	mask = 1;
	for (pass=0; pass < ndisk; pass++) {
	    mask &= !!(raid_bios[pass] & COVERED);
	}
#ifdef FLAG_RAID_NOWRITE
	if (!mask) {
	    raid_flags |= FLAG_RAID_NOWRITE;
	}

	if (raid_flags & FLAG_RAID_NOWRITE) {
	    warn("FLAG_RAID_NOWRITE has been set.");
	}
#endif

    /* if the disk= bios= did not specify the bios, then this is the default */
	if (md_disk->bios < 0) {
	    md_disk->bios = md_bios;
	}
	md_bios = md_disk->bios;
	if (md_disk->bios < 0x80 || md_disk->bios > DEV_MASK)
	   die("Unusual RAID bios device code: 0x%02X", md_disk->bios);
#if 0
/* Assigning all disks the same bios code is OBSOLETE in 22.5.6 */
	disk = disktab;
	for (pass=0; pass < ndisk; pass++) {
	    disk->bios = md_disk->bios;	  /* all disks in the array are */
	    disk = disk->next;		  /*  assigned the same bios code */
	}
#endif
	if (verbose) {
	    printf(
	       "Using BIOS device code 0x%02X for RAID boot blocks\n",
	    	                            md_disk->bios);
	}

#if 0
	if ( mask &&  ( extra == X_NONE ||
			(extra == X_AUTO  &&  autocount == 0) ) )  {
	    if (bios_passes_dl > DL_BAD) bios_passes_dl = DL_GOOD;
	}
#endif
	
	if (bios_passes_dl==DL_GOOD  &&  !(extra == X_MBR_ONLY || extra == X_MBR))
	    warn("Boot sector on  %s  will depend upon the BIOS device code\n"
		"  passed in the DL register being accurate.  Install Master Boot Records\n"
		"  with the 'lilo -M' command, and activate the RAID1 partitions with the\n"
		"  'lilo -A' command.",
		boot );
	
	return raid_offset[pri_index];
    }	/* IF (test for a raid installation */
}  /* int raid_setup(void) */



void raid_final(void)
{
    int pass, force = 0;
    char *cp = NULL;
    int mask = FLAG_SAVE;


    if (bios_passes_dl < DL_GOOD) mask &= ~FLAG_MAP_ON_BOOT;
    
    if (test) /* do nothing */;
    else if ((cp=cfg_get_strg(cf_options,"force-backup"))) force=1;
    else cp=cfg_get_strg(cf_options,"backup");
	    
    if (verbose>=2) {
	printf("do_md_install: %s\n", do_md_install == MD_PARALLEL ? "MD_PARALLEL" :
		do_md_install == MD_MIXED ? "MD_MIXED" :
		do_md_install == MD_SKEWED ? "MD_SKEWED" : "unknown");
	for (pass=0; pass<ndisk; pass++)
	    printf("  offset %08X  %s\n", raid_offset[pass], raid_mbr[pass]);
    }
    		
    if (extra == X_MBR_ONLY) {    
        pass = 0;
        while (pass < ndisk) {
#ifndef LCF_UNIFY
# error "Bios Translation algorithms require '-DUNIFY' in Makefile"
#endif
	    if (pass==0 && test) {
	    	bsect_cancel();
		if (passw) printf("The password crc file has *NOT* been updated.\n");
		printf("The map file has *NOT* been altered.\n");
	    }

	    if (!test) {
		bsect_raid_update(raid_mbr[pass], raid_offset[pass],
			cp, force, pass ? pass : -1, mask );
	    }

	    printf("The Master boot "
	        "record of  %s  has%s been updated.\n",
	        	raid_mbr[pass],
	        	test ? " *NOT*" : "" );
	    pass++;
        }
    } 
    else {	/*  extra != X_MBR_ONLY   */
        
#ifdef FLAG_RAID_DEFEAT
	raid_flags &= ~FLAG_RAID_DEFEAT;    /* change won't affect /dev/mdX */
#endif
	{
	  if (test) {
	    bsect_cancel();
	    if (passw) printf("The password crc file has *NOT* been updated.\n");
	    printf("The map file has *NOT* been updated.\n");
	  }
	  else {
	/* write out the /dev/mdX boot records */	    
	    bsect_raid_update(boot, 0L, cp, force, 0, FLAG_SAVE);
	  }
	    printf("The boot record of  %s  has%s been updated.\n", 
	    		boot,
	    		test ? " *NOT*" : "");
	}

	if (extra == X_NONE ||
		(extra == X_AUTO  &&  autocount == 0) ) return;

	if (extra == X_SPEC)
	for (pass = 0; pass < nlist; pass++) {
	    int index;

	    if (raid_bios[list_index[pass]] & 0xFF) {
	    	index = list_index[pass];	/* within RAID set */
	    }
	    else {  /* not in the RAID set */
#ifdef FLAG_RAID_DEFEAT
	    	raid_flags |= FLAG_RAID_DEFEAT;  /* make outsider invisible */
#endif
	    	index = lowest;
	    }

	    if (verbose>=3) printf("Specifed partition:  %s  raid offset = %08X\n",
					raid_list[pass], raid_offset[index]);

	    if (!test)
		bsect_raid_update(raid_list[pass], raid_offset[index], cp, force, 1, mask);
	    
	    printf("The boot record of  %s  has%s been updated.\n",
			raid_list[pass], (test ? " *NOT*" : ""));

#ifdef FLAG_RAID_DEFEAT
	    raid_flags &= ~FLAG_RAID_DEFEAT; /* restore DEFEAT flag to 0 */
#endif
	}
	else {		/* extra = X_AUTO or X_MBR*/
	    for (pass = 0; pass < ndisk; pass++) {
		if (!(raid_bios[pass] & IS_COVERED)) {
		    if ((raid_bios[pass] & 0xFF) != 0x80  || extra == X_MBR) {
			if (!test)
			    bsect_raid_update(raid_mbr[pass], raid_offset[pass],
							cp, force, 1, mask);
			printf("The Master boot record of  %s  has%s been updated.\n",
					raid_mbr[pass], (test ? " *NOT*" : ""));
		    } else {
			warn("%splicit AUTO does not allow updating the Master Boot Record\n"
				"  of '%s' on BIOS device code 0x80, the System Master Boot Record.\n"
				"  You must explicitly specify updating of this boot sector with\n"
				"  '-x %s' or 'raid-extra-boot = %s' in the\n"
				"  configuration file.",
                                cfg_get_strg(cf_options, RAID_EXTRA_BOOT) ? "Ex" : "Im",
				raid_mbr[pass],
				raid_mbr[pass],
				raid_mbr[pass] 
				);
		    }
		}
	    }
	}
    }


#ifdef FLAG_RAID_NOWRITE
    if (raid_flags & FLAG_RAID_NOWRITE) {
	warn("FLAG_RAID_NOWRITE has been set.%s", verbose>=1 ?
	        "\n  The boot loader will be unable to update the stored command line;\n"
	        "  'lock' and 'fallback' are not operable; the 'lilo -R' boot command\n"
	        "  line will be locked." : "" );
    }
#endif

}

/* form the mask of the raid bios codes and the list of offsets */
/* this information goes into the MENUTABLE passed to the loader */
int raid_mask(int *offsets)
{
    int mask = 0;
    int i, j;
    int offset[MAX_BIOS_DEVICES];
    
    if (ndisk > MAX_RAID_DEVICES)
	die("More than %d active RAID1 disks", MAX_RAID_DEVICES);
	
    memset(offset, 0, sizeof(offset));
    for (i=0; i<ndisk; i++) {
	offset[j = raid_bios[i] & (DEV_MASK & 0x7F) ] = raid_offset[i];
	mask |= 1<<j;
    }
    for (i=0; i<nelem(offset); i++) {
	if ( (mask>>i) & 1 ) *offsets++ = offset[i];
	if (do_md_install && verbose>=3) printf("RAID offset entry %d  0x%08X\n", offset[i], offset[i]);
    }
    
    if (verbose>=2) printf("RAID device mask 0x%04X\n", mask);
    
    return mask;
}


