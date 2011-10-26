/* device.c  -  Device access */
/*
Copyright 1992-1997 Werner Almesberger.
Copyright 1999-2006 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/

#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "config.h"
#include "lilo.h"
#include "common.h"
#include "temp.h"
#include "device.h"
#include "geometry.h"
#include "partition.h"
#include "cfg.h"
#include "probe.h"
#include "md-int.h"


typedef struct _cache_entry {
    const char *name;
    int number;
    struct _cache_entry *next;
} CACHE_ENTRY;

typedef struct _st_buf {
    struct _st_buf *next;
    struct stat st;
} ST_BUF;


static CACHE_ENTRY *cache = NULL;


#if 1
int yesno(char *prompt, int expect)
{
    char *line, *pr2;
    int i;
    size_t n;
    int ret;
    if (expect) pr2 = "[Y/n]";
    else pr2 = "[N/y]";
    
    fflush(stdout);
    do {
	fprintf(stderr, "%s%s", prompt, pr2);
	fflush(stderr);
	n = ret = 0;
	line = NULL;
	i = getline(&line, &n, stdin);
	if (i<0) exit(1);
	if (i==1) ret=expect|2;
	if (i>1) {
		if (*line=='y'||*line=='Y') ret=1;
		if (*line=='n'||*line=='N') ret=2;
	}
	if (ret) break;
	if (line) free(line);
    } while(1);

    return ret&1;
}
#endif

static int scan_dir(ST_BUF *next,DEVICE *dev,char *parent,int number)
{
    DIR *dp;
    struct dirent *dir;
    ST_BUF st,*walk;
    char *start;

    if (verbose >= 5) printf("scan_dir: %s\n", parent);
    st.next = next;
    if ((dp = opendir(parent)) == NULL)
	die("opendir %s: %s",parent,strerror(errno));
    *(start = strchr(parent,0)) = '/';
    while ((dir = readdir(dp))) {
	strcpy(start+1,dir->d_name);
	if (stat(parent,&st.st) >= 0) {
	    dev->st = st.st;
	    if (S_ISBLK(dev->st.st_mode) && dev->st.st_rdev == number) {
		(void) closedir(dp);
		return 1;
	    }
#if 0
	    if (S_ISDIR(dev->st.st_mode) && strcmp(dir->d_name,".") &&
	      strcmp(dir->d_name,"..")) {
#else
    /* stay out of all hidden directories (good for 2.6 kernel) */
	    if (S_ISDIR(dev->st.st_mode) && (dir->d_name)[0] != '.') {
#endif
		for (walk = next; walk; walk = walk->next)
		    if (stat_equal(&walk->st,&st.st)) break;
		if (!walk && scan_dir(&st,dev,parent,number)) {
		    (void) closedir(dp);
		    return 1;
		}
	    }
	}
    }
    (void) closedir(dp);
    *start = 0;
    return 0;
}


static int lookup_dev(char *name,DEVICE *dev,int number)
{
    CACHE_ENTRY **walk;

    if (verbose>=5) printf("lookup_dev:  number=%04X\n", number);
    for (walk = &cache; *walk; walk = &(*walk)->next)
	if ((*walk)->number == number) {
#if 0
	    CACHE_ENTRY *here;

	    if (stat((*walk)->name,&dev->st) >= 0)
		if (S_ISBLK(dev->st.st_mode) && dev->st.st_rdev == number) {
		    strcpy(name,(*walk)->name);
		    return 1;
		}
	    here = *walk; /* remove entry from cache */
	    if (verbose >= 2)
		printf("Invalidating cache entry for %s (0x%04X)\n",here->name,
		  here->number);
	    *walk = here->next;
	    free((char *) here->name);
	    free(here);
	    return 0;
#else
	    strcpy(name,(*walk)->name);
	    return 1;
#endif
	}
    return 0;
}


static int is_devfs(void)
{
static int yesno = 0;
    struct stat st;
   
    if (!yesno) {
	if (stat(DEV_DIR "/.devfsd", &st) < 0)  yesno=1;
	else yesno=2;
    }
   
   return yesno-1;
}



static void cache_add(const char *name,int number)
{
    CACHE_ENTRY *entry;

    entry = cache;
    while (entry) {
	if (strcmp(entry->name, name) == 0) {
	    if (entry->number != number) die("cache_add: LILO internal error");
	    return;
	}
	entry = entry->next;
    }
    if (verbose >= 5) printf("Caching device %s (0x%04X)\n",name,number);
    entry = alloc_t(CACHE_ENTRY);
    entry->name = stralloc(name);
    entry->number = number;
    entry->next = cache;
    cache = entry;
}


int dev_open(DEVICE *dev,int number,int flags)
{
    char name[PATH_MAX];
    ST_BUF st;
    int count;

    if (lookup_dev(name,dev,number)) dev->delete = 0;
    else {
	if (stat(DEV_DIR,&st.st) < 0)
	    die("stat " DEV_DIR ": %s",strerror(errno));
	st.next = NULL;
	dev->delete = !scan_dir(&st,dev,strcpy(name,DEV_DIR),number);
	if (dev->delete) {
	    for (count = 0; count <= MAX_TMP_DEV; count++) {
#ifdef LCF_USE_TMPDIR
		if (!strncmp(TMP_DEV,"/tmp/",5) && getenv("TMPDIR")) {
		    strcpy(name,getenv("TMPDIR"));
		    sprintf(name+strlen(name),TMP_DEV+4,count);
		}
		else
#endif
		    sprintf(name,TMP_DEV,count);
		if (stat(name,&dev->st) < 0) break;
	    }
	    if (count > MAX_TMP_DEV)
		die("Failed to create a temporary device");
	    if (mknod(name,0600 | S_IFBLK,number) < 0)
		die("mknod %s: %s",name,strerror(errno));
	    if (stat(name,&dev->st) < 0)
		die("stat %s: %s",name,strerror(errno));
	    if (verbose > 1)
		printf("Created temporary device %s (0x%04X)\n",name,number);
	    temp_register(name);
	}
	else cache_add(name,number);
    }
#if BETA_TEST
	if (verbose >= 4) printf("stat-ing %s\n", name);
	fflush(stdout);
	stat(name, &st.st);
#endif
    if (flags == O_BYPASS) dev->fd = -1;
    else if ((dev->fd = open(name,flags)) < 0)
	    die("open %s: %s",name,strerror(errno));
    dev->name = stralloc(name);
    return dev->fd;
}


void dev_close(DEVICE *dev)
{
    if (dev->fd != -1)
	if (close(dev->fd) < 0) die("close %s: %s",dev->name,strerror(errno));
    if (dev->delete) {
	if (verbose > 1)
	    printf("Removed temporary device %s (0x%04X)\n",dev->name,
	      (unsigned int) dev->st.st_rdev);
	(void) remove(dev->name);
	temp_unregister(dev->name);
    }
    free(dev->name);
}

#define MAX 15

void cache_scsi (char *name, int major)
{
    char tem[PATH_MAX], format[PATH_MAX];
    int i, j, dev;
    int k = strlen(DEV_DISK_DIR) + 3;
    
    for (i=15; i>=0; i--) {
	dev = MKDEV(major,(i<<4));
#if 0
	if (is_devfs()) {
	    sprintf(tem,"/dev/scsi/host%d/bus0/target0/lun0/", i);
	    strcat(strcpy(format,tem),"disc");
	    cache_add(format, dev);
	    strcat(strcpy(format,tem),"part%d");
	}
	else
#endif
	{
	    strcpy(format, name);
	    format[k] += i;
	    cache_add(format, dev);
	    strcat(format, "%d");
	}
	for (j = MAX; j; j--) {
	    sprintf(tem, format, j);
	    cache_add(tem, dev | j);
	}
    }
}


void cache_ide (char *name, int major)
{
    char tem[PATH_MAX], tem2[PATH_MAX];
    char format[PATH_MAX];
    char *disc;
    int i, dev, minor, host, bus, target;
    int j = strlen(DEV_DISK_DIR) + 3;
    
    i = name[j] - 'a';
    target = i&1;
    minor = target<<6;
    i >>= 1;
    bus = i&1;
    host = i&(-2);
    if (is_devfs()) {
	sprintf(tem2, DEV_DIR "/ide/host%d/bus%d/target%d/lun0/", host, bus, target);
	strcat(strcpy(format,tem2), "part%d");
	disc = strcat(tem2, "disc");
    }
    else {
        strcat(strcpy(format, name), "%d");
        disc = name;
    }
    dev = MKDEV(major,minor);
    for (i = MAX; i; i--) {
	sprintf(tem, format, i);
	cache_add(tem, dev | i);
    }
    cache_add(disc, dev);
}

void preload_dev_cache(void)
{
    char tmp[PATH_MAX];
    int i;
    int vsave;


    vsave = verbose;
#if !BETA_TEST
    if (verbose>0) verbose--;
#endif

    if (is_devfs()) {
	cache_add(DEV_DIR "/floppy/0", 0x0200);
	cache_add(DEV_DIR "/floppy/1", 0x0201);
    }
    else {
	cache_add(DEV_DIR "/fd0", 0x0200);
	cache_add(DEV_DIR "/fd1", 0x0201);
    }
    
#if 1
    cache_ide(DEV_DISK_DIR "/hdt", MAJOR_IDE10);
    cache_ide(DEV_DISK_DIR "/hds", MAJOR_IDE10);
    cache_ide(DEV_DISK_DIR "/hdr", MAJOR_IDE9);
    cache_ide(DEV_DISK_DIR "/hdq", MAJOR_IDE9);

    cache_ide(DEV_DISK_DIR "/hdp", MAJOR_IDE8);
    cache_ide(DEV_DISK_DIR "/hdo", MAJOR_IDE8);
    cache_ide(DEV_DISK_DIR "/hdn", MAJOR_IDE7);
    cache_ide(DEV_DISK_DIR "/hdm", MAJOR_IDE7);
    
    cache_ide(DEV_DISK_DIR "/hdl", MAJOR_IDE6);
    cache_ide(DEV_DISK_DIR "/hdk", MAJOR_IDE6);
#ifdef MAJOR_IDE5
    cache_ide(DEV_DISK_DIR "/hdj", MAJOR_IDE5);
    cache_ide(DEV_DISK_DIR "/hdi", MAJOR_IDE5);
#endif
#endif
    
    for (i = MAX; i >= 0; i--) {
	sprintf(tmp, is_devfs() ? DEV_DISK_DIR "/md/%d" : DEV_DISK_DIR "/md%d", i);
	cache_add(tmp, MKDEV(MAJOR_MD,i));
    }

    if (!is_devfs()) cache_scsi(DEV_DISK_DIR "/sda", MAJOR_SD);
    
    cache_ide(DEV_DISK_DIR "/hdh", MAJOR_IDE4);
    cache_ide(DEV_DISK_DIR "/hdg", MAJOR_IDE4);
    cache_ide(DEV_DISK_DIR "/hdf", MAJOR_IDE3);
    cache_ide(DEV_DISK_DIR "/hde", MAJOR_IDE3);

    for (i = 0; i <= 7; i++) {
	sprintf(tmp, is_devfs() ? DEV_DIR "/loop/%d" : DEV_DIR "/loop%d", i);
	cache_add(tmp,0x700+i);
    }

    cache_ide(DEV_DISK_DIR "/hdd", MAJOR_IDE2);
    cache_ide(DEV_DISK_DIR "/hdc", MAJOR_IDE2);
    cache_ide(DEV_DISK_DIR "/hdb", MAJOR_HD);
    cache_ide(DEV_DISK_DIR "/hda", MAJOR_HD);
    
    verbose = vsave;
}

#undef MAX

#define NDEVICE 256
static unsigned int idevices[NDEVICE];
static int maxdev = 0;

/* return 0 if device has not been backed up,		*/
/*	  1 if it has been backed up			*/

static int dev_listed(unsigned short dev)
{
    int i;

/* scan the device list */
    for (i=0; i<maxdev; i++) {
	if (dev==idevices[i]) return 1;		/* already backed up */
    }
    
    if (maxdev < NDEVICE-1) idevices[maxdev++] = dev;

    return 0;	/* new to the list, not listed if too many devices */
}


/* make a backup, returning the timestamp of the backup file */
/* 0 if no timestamp returned, and no backup file created */

int make_backup(char *backup_file, int force_backup, BOOT_SECTOR *bsect,
	unsigned int device, char *id)
{
    struct stat st;
    char temp_name[PATH_MAX];
    int bck_file;
    int timestamp=0;
    char *filename = "boot";

    char *cp = NULL;
    int force = 0;


    if ((cp=cfg_get_strg(cf_options,"force-backup"))) force=1;
    else cp=cfg_get_strg(cf_options,"backup");
    if (!backup_file) {
	backup_file = cp;
	force_backup = force;
    }

    if (backup_file && stat(backup_file, &st) >= 0) {
/* file or directory exists */
    	if (S_ISDIR(st.st_mode)) {
    	    if (strcmp(backup_file,"/")==0) backup_file = "";
	    sprintf(temp_name, "%s/%s.%04X", backup_file, filename, device);
	    backup_file = temp_name;
	}
    /* test for /dev/null */
	else if (S_ISCHR(st.st_mode) && st.st_rdev==0x0103) return 0;
	else if (!S_ISREG(st.st_mode))
	    die("make_backup: %s not a directory or regular file", backup_file);
    }

/* could not stat it, or it was a directory, or it was a regular file */

    if (backup_file) {
	char *name, *dir, suffix[16];
	
	backup_file = strcpy(temp_name, backup_file);
	sprintf(suffix, "%04X", device);
	dir = strrchr(backup_file, '/');
	if (!dir) dir = backup_file;
	name = strrchr(dir, '.');
	if (name) {  /* there is a '.' in the name */
	    if (strcmp(name+1, suffix)==0) ; /* do nothing */
	    else if (strlen(name+1)==4) {  /* && the suffix doesn't match */
	    	strcpy(name+1,suffix);
	    }
	    else if (name[1]==0) strcat(name,suffix);	/* ended with '.' */
	    else {
		strcat(name+1,".");
		strcat(backup_file,suffix);
	    }
	  /* we now have the filename with the correct suffix */
	}
	else {
    /* no '.' in the name, take it as a template */
	    strcat(backup_file,".");
	    strcat(backup_file,suffix);
	}
    }
    else
  /*  if (!backup_file) */ {
	sprintf(temp_name, BACKUP_DIR "/%s.%04X", filename, device);
	backup_file = temp_name;
    }
    
    bck_file = open(backup_file, O_RDONLY);
    if (bck_file >= 0 && force_backup) {
	(void) close(bck_file);
	bck_file = -1;
    }
    if (bck_file >= 0) {
	if (verbose)
	    printf("%s exists - no %s backup copy made.\n", backup_file, id);
    }
    else {
    	if (dev_listed(device)) {
	    if (verbose)
		printf("Backup copy of %s has already been made in %s\n",
			id, backup_file);
    	}
    	else if (!test) {
	    if ((bck_file = creat(backup_file, 0644)) < 0)
		die("creat %s: %s",backup_file, strerror(errno));
	    if (write(bck_file, (char *)bsect, SECTOR_SIZE) != SECTOR_SIZE)
		die("write %s: %s", backup_file, strerror(errno));
	    if (verbose)
		printf("Backup copy of %s in %s\n", id, backup_file);
	    if (fstat(bck_file, &st) < 0)
		die("fstat %s: %s",backup_file,strerror(errno));
	    timestamp = st.st_mtime;
	}
	else {
	    if (verbose)
		printf("Backup copy of %s in %s (test mode)\n", id, backup_file);
	}
    }
    if (bck_file >= 0 && close(bck_file) < 0) die("close %s: %s",backup_file,strerror(errno));
    
    return timestamp;
}




int serial_valid(unsigned int serial, int disk_bios)
{
#if 1
    return (serial != 0);
#elif 1
    if (serial == -1 || serial == 0) return 0;
    return 1;
#else
/* if ID is replicated characters, it is invalid */
/*	Examples of invalid Volume ID's are:
		00000000
		6C6C6C6C
		FFFFFFFF
BUT: any Volume ID (except 0 or -1) is valid on drive C:
 - - - - - - - - - - - - - - - - - - - - - - - - - - */
    unsigned int temp;
    
    temp = serial & 0xFF;
    temp |= temp << 8;
    temp |= temp << 16;

    return (serial != temp ||
    		(serial!=0 && serial!=0xFFFFFFFFUL && disk_bios==0x80));
#endif
}

int new_serial(int dev)
{
static int inited = 0;
   
    if (!inited) {
	struct stat st;
	int fd, random;
#define RANDOM DEV_DIR "/urandom"	

	inited = time(NULL);
	if ( stat(RANDOM, &st)==0 && S_ISCHR(st.st_mode)
	    && (fd = open(RANDOM, O_RDONLY)) > 0
	    && read(fd, &random, sizeof(random)) == sizeof(random) )  {
#if BETA_TEST
if(verbose>=5) printf("Using " RANDOM " for seeding random number generator\n");	    
#endif
		close(fd);
		inited ^= random;
	}

	srand(inited);
    }
    dev = dev % PRIME + SMALL_PRIME;
    while(dev--) inited = rand();
    
    return inited;
#undef RANDOM
}




static int inited = 0;
unsigned int serial_no[MAX_BIOS_DEVICES];
static int device_code[MAX_BIOS_DEVICES];

/*  register references to various bios devices
 *  compiles the list of volume IDs
 *    returns volume ID on success
 *	0 = no volume ID
 *	-1 = error
 */
unsigned int register_bios(int bios, int device)
{
    int i, fd, valid, disk_bios;
    DEVICE dev;
    BOOT_SECTOR buff;
    unsigned int serial = -1;
    
#if 0
    if (!inited) {
	for (i=0; i<MAX_BIOS_DEVICES; i++) {
	    device_code[i] = 0;
	    serial_no[i] = 0;
	}
	inited = 1;
	srand(time(NULL));
    }
#else
    inited = 1;
#endif
    if (!do_md_install && cfg_get_flag(cf_options, "static-bios-codes")) return 0;
    
    if (verbose>=4) {
	printf("registering bios=0x%02X  device=0x%04X\n", bios, device);
    }
    
    disk_bios = bios;
    if (bios>=0x80 && bios<0x80+MAX_BIOS_DEVICES &&
				(i=has_partitions(device))) {
	bios &= 0x7F;	/* mask to index */
	device &= i;	/* mask to master device */
	if (device_code[bios]==0 && serial_no[bios]==0) {  /* slot empty */
	    fd = dev_open(&dev, device, O_RDWR);
	    if (lseek(fd, 0L, SEEK_SET) < 0)
		die("master boot record seek %04X: %s", device, strerror(errno));
	    if (read(fd, (char*)&buff, SECTOR_SIZE)!=SECTOR_SIZE)
		die("read master boot record %04X: %s", device, strerror(errno));
	    serial = *(int*)&buff.sector[PART_TABLE_OFFSET-6];
	    valid = serial_valid(serial, disk_bios);
	    if ((!valid || (VERSION_MINOR>=50)) && !test)
		    make_backup(NULL, 0, &buff, device,
					"master disk volume ID record");
	    if (!valid) {
		i = device % PRIME + SMALL_PRIME;
		while(i--) serial = rand();
		for (; i<5 && !serial_valid(serial, disk_bios); i++) serial = rand();
		if (!serial_valid(serial, disk_bios)) die("Volume ID generation error");

		*(int*)&buff.sector[PART_TABLE_OFFSET-6] = serial;
		if (*(short*)&buff.sector[PART_TABLE_OFFSET - 2] == 0)
		    *(short*)&buff.sector[PART_TABLE_OFFSET - 2] = MAGIC_SERIAL;
		if (verbose)
		    printf("Assigning new Volume ID to (%04X) '%s'  ID = %08X\n",
		    			device, dev.name, (int)serial);
		if (!test) {
		    i = lseek(fd, 0L, SEEK_SET);
		    if (i<0) die("master boot record2 seek %04X: %s", device, strerror(errno));
		    if (write(fd, (char*)&buff, SECTOR_SIZE)!=SECTOR_SIZE)
			die("write master boot record %04X: %s", device, strerror(errno));
		}
	    }
	    dev_close(&dev);
	    for (i=0; i<MAX_BIOS_DEVICES; i++) {
		if (device_code[i]==device)
		    die("register_bios: device code duplicated: %04X", device);
		if (serial_no[i]==serial)
		    die("register_bios: volume ID serial no. duplicated: %08lX", serial);
	    }
	    device_code[bios] = device;
	    serial_no[bios] = serial;
	}


	if (device_code[bios]==device) serial = serial_no[bios];
	else {
	    DEVICE dev, deva;
	    
	    dev_open(&dev, device_code[bios], O_BYPASS);
	    dev_open(&deva, device, O_BYPASS);

	    die("Bios device code 0x%02X is being used by two disks\n\t%s (0x%04X)  and  %s (0x%04X)",
	    	bios|0x80, dev.name, device_code[bios], deva.name, device);
	}
	if (verbose>=3) {
	    printf("Using Volume ID %08X on bios %02X\n", (int)serial, bios+0x80);
	}
    }
    else if (bios>=0 && bios <=3) serial = 0;
    else serial = -1;
    
    return serial;
}


void dump_serial_nos(void)
{
    int i,j;
    
    printf(" BIOS   VolumeID   Device\n");
    if (!inited) return;
    for (j=nelem(serial_no); serial_no[--j]==0; )   ;
    for (i=0; i<=j; i++)
	printf("  %02X    %08X    %04X\n",
		i+0x80,
		(int)serial_no[i],
		(int)device_code[i]
	);
}


enum {ID_GET=0, ID_SET};

static int volid_get_set(int device, int vol_in, int option)
{
    BOOT_SECTOR buf;
    DEVICE dev;
    int fd;
    int temp;
    unsigned short word;
    
    if (!has_partitions(device) && (device & P_MASK(device)) )
	die("VolumeID set/get bad device %04X\n", device);
	
    fd = dev_open(&dev, device, option ? O_RDWR : O_RDONLY);
    if (read(fd, &buf, sizeof(buf)) != sizeof(buf))
	die("VolumeID read error: sector 0 of %s not readable", dev.name);
    if (option==ID_SET) {
	make_backup(NULL, 0, &buf, device,
					"master disk volume ID record");
	word = temp = buf.boot.volume_id & 0xFF;	/* one char */
	word |= word << 8;
	temp = word;
	temp |= temp << 16;
	if (buf.boot.mbz==word 
		&& buf.boot.volume_id==temp
		&& buf.boot.marker==word) {
	    buf.boot.mbz = buf.boot.marker = 0;
	}
	buf.boot.volume_id = vol_in;
	if (buf.boot.marker == 0) buf.boot.marker = MAGIC_SERIAL;
	if (!test) {
	    if (lseek(fd, 0L, SEEK_SET) != 0L  ||
		    write(fd, &buf, PART_TABLE_OFFSET) != PART_TABLE_OFFSET )
		die("volid write error");
	}
    }
    dev_close(&dev);
    sync(); /* critical that this be done here */
    
    return buf.boot.volume_id;
}




/* count the number of slashes in a pathname */
static int slashes(char *cp)
{
    int n = 0;
    
    while ( (cp=strchr(++cp,'/')) )  n++;
    
    return n;
}


static int ndevs=0;
enum {INVALID=1, DUPLICATE=2, REGENERATE=3, NTCAUTION=4};

struct VolumeMgmt {
    char *name;		/* the name of the disk; e.g.  "/dev/hda" */
    unsigned int device;	/* the device number (major, minor) */
    int sort;		/* the device number used for sorting */
    int flag;		/* various flag bits */
    char nt[PART_MAX];	/* flag partitions which might be NT */
    DT_ENTRY *dt;	/* pointer to any disktab entry */
    struct {
	int kernel;	/* volume ID as read using kernel I/O */
	int probe;	/* volume ID as probed */
    } vol_id;
    struct {
    	int user;	/* user used a disk= bios= section */
    	int probe;	/* passed in from the BIOS data check */
    	int actual;	/* this is what we finally decide upon */
    } bios;		/* BIOS device codes */
};


#ifdef LCF_MDPRAID
/* return boolean if VM is a component drive of MDP-RAID */

static int is_mdp(struct VolumeMgmt *vm, struct VolumeMgmt *mdp)
{
    int mdp_fd;
    DEVICE dev;
    struct md_version md_version_info;
    md_array_info_t raid;
    int ret=0;

    if (verbose>=2) printf("is_mdp:   %04X : %04X\n",
          vm->device, mdp->device);
    
    if ((mdp_fd=dev_open(&dev, mdp->device, O_NOACCESS) ) < 0)
	die("Unable to open %s", mdp->name);

    if (ioctl(mdp_fd, RAID_VERSION, &md_version_info) < 0) ret = -1;
    else if (md_version_info.major > 0  || 
	                  md_version_info.minor < 90) {
	
	ret = -2;
	warn("RAID versions other than 0.90 are not supported");
    }
    else if (ioctl(mdp_fd, GET_ARRAY_INFO, &raid) < 0) ret = -1;
    else if (raid.level == 1) {
        md_disk_info_t disk;
	int i;
	
	for (i=0; ret==0 && i<raid.active_disks; i++) {
	    disk.number = i;
	    if (ioctl(mdp_fd, GET_DISK_INFO, &disk) < 0) ret = -1;
	    if (vm->device == MKDEV(disk.major, disk.minor)) ret = 1;
	}
    }
    /* else ret = 0;  already */
    dev_close(&dev);

    if (verbose>=2) printf("is_mdp: returns %d\n", ret);
    
    return ret;
}
#endif

/* 
   Returns 0 if not an NT, 2000, or XP boot disk (query user)
   returns 1 if it is an NT ... boot disk; abort if fatal set
*/
static int winnt_check(struct VolumeMgmt *vm, int fatal)
{
    int dev, ret;
    
    if ( !(vm->flag & NTCAUTION) ) return 0;
    
    dev = vm->device;

    fflush(stdout);
    fflush(stderr);
    
    fprintf(stderr, "\n\nReference:  disk \"%s\"  (%d,%d)  %04X\n\n"
"LILO wants to assign a new Volume ID to this disk drive.  However, changing\n"
"the Volume ID of a Windows NT, 2000, or XP boot disk is a fatal Windows error.\n"
"This caution does not apply to Windows 95 or 98, or to NT data disks.\n"
				, vm->name, MAJOR(dev), MINOR(dev), dev);
					
					
    ret = yesno("\nIs the above disk an NT boot disk? ", 1);

    if (ret && fatal) {
	fprintf(stderr, "Aborting ...\n");
	exit(0);
    }
    
    return ret;
}



#ifdef LCF_MDPRAID
#define SORT(d) (MAJOR(d)==MAJOR_SD?MKDEV(MAJOR_SD_SORT,MINOR(d)):\
		 MAJOR(d)==MAJOR_MDP?MKDEV(MAJOR_MDP_SORT,MINOR(d)):\
		 MAJOR(d)==MAJOR_EMD?MKDEV(MAJOR_EMD_SORT,MINOR(d)):\
		 MAJOR(d)==MAJOR_HPT370?MKDEV(MAJOR_HPT370_SORT,MINOR(d)):\
		 (d))
#else
#define SORT(d) (MAJOR(d)==MAJOR_SD?MKDEV(MAJOR_SD_SORT,MINOR(d)):\
		 MAJOR(d)==MAJOR_EMD?MKDEV(MAJOR_EMD_SORT,MINOR(d)):\
		 MAJOR(d)==MAJOR_HPT370?MKDEV(MAJOR_HPT370_SORT,MINOR(d)):\
		 (d))
#endif

int pf_hard_disk_scan(void)
{
    struct VolumeMgmt vm [MAX_DEVICES];
static int warned = 0, called = 0;
    char *line, *next, *name;
    int major, minor, i, ipart;
    int dev, mask, bios;
    unsigned int device;
    size_t n;
    DEVICE Dev;
    DT_ENTRY *walk;
    struct stat st;
    int duplicate = 0, invalid = 0, ret = 0, ntcaution = 0;
    int raidcaution = 0;
    long codes = 0L;

/* called from  raid_setup  &  from  geo_open */
/* allow only 1 call */
    if (called || cfg_get_flag(cf_options,"static-bios-codes")) return ret;
    called = 1;
    memset(vm,0,sizeof(vm));	/* for consistency */
            
#if 1
    if (!pp_fd  &&  (pp_fd = fopen(PARTITIONS, "r"))==NULL) {
#else
    if ((pp_fd = fopen(PARTITIONS, "r"))==NULL || fetch()) {
#endif
	warn("'" PARTITIONS "' does not exist, disk scan bypassed");
	return 1;
    }

    n = 0;
    line = NULL;
    while (!feof(pp_fd)) {
    	if (line) {
	    free(line);
	    line = NULL;
	    n = 0;
    	}
	if (getline(&line, &n, pp_fd) <= 0) break;

	major = strtoul(line, &next, 10);
	if (major==0 || line==next) continue;

        if (is_dm_major(major)) {
#ifndef LCF_DEVMAPPER
            warn("device-mapper (%d) referenced in " PARTITIONS ",\n"
                 "   but LILO is configured without DEVMAPPER option.  Skipping device.", major);
            continue;
#endif
        }
        else if ((major>=60 && major<=63) || (major>=120 && major<=127) ) {
            warn(PARTITIONS " references Experimental major device %d.", major);
        }
        else if (major==255) {
            warn(PARTITIONS " references Reserved device 255.");
            continue;
        }
        else if (major>=240 && major<255) {
            warn(PARTITIONS " references Experimental major device %d.", major);
        }

	minor = strtoul(next, &name, 10);
	if (next==name) continue;
	/* skip */ strtoull(name,&next,10);

	while (isspace(*next)) next++;
	name = next;
	while (*name && !isspace(*name)) name++;
	*name = 0;
	if (strncmp(DEV_DISK_DIR "/", next, strlen(DEV_DISK_DIR)+1) != 0) name = next-(strlen(DEV_DISK_DIR)+1);
	else name = next;
	if (*name=='/') name++;
	strncpy(name, DEV_DISK_DIR "/", strlen(DEV_DISK_DIR)+1);
	if (verbose>=5) {
	    printf("pf_hard_disk_scan: (%d,%d) %s\n", major, minor, name);
	}

	device = MKDEV(major, minor);

	Dev.delete = 0;
	if (stat(name, &st) < 0) {
	    dev_open(&Dev, device, O_BYPASS);
	    if (!warned) {
		warn("'" PARTITIONS "' does not match '" DEV_DISK_DIR "' directory structure.\n"
				"    Name change: '%s' -> '%s'%s"
				,	name, Dev.name,
				slashes(name) > 3 && slashes(Dev.name) < 3 ? "\n"
				"    The kernel was compiled with DEVFS_FS, but 'devfs=mount' was omitted\n"
				"        as a kernel command-line boot parameter; hence, the '" DEV_DISK_DIR "' directory\n"
				"        structure does not reflect DEVFS_FS device names."
			:	slashes(name) < 3 && slashes(Dev.name) > 3 ? "\n"
				"    The kernel was compiled without DEVFS, but the '" DEV_DISK_DIR "' directory structure\n"
				"        implements the DEVFS filesystem."
			:
				""
				);
		warned++;
	    }
	    else {
		warn("Name change: '%s' -> '%s'", name, Dev.name);
	    }
	    name = Dev.name;
	    if (Dev.delete) {
	        warn("'" DEV_DISK_DIR "' directory structure is incomplete; device (%d, %d) is missing.",
	    			major, minor);
	    	cache_add(name, device);
	    }
	}
	else cache_add(name, device);
		
	mask = has_partitions(device);
	dev = device & mask;	/* dev is the master device */
	ipart = device & P_MASK(device); /* ipart is the partition number */
	
#if 1
	for (walk=disktab; walk; walk=walk->next) {
	    if (walk->device == dev) {
		if (walk->heads == 0 /* inaccessible */) {
		    if (ipart==0 && !identify)
		        warn("bypassing VolumeID scan of drive flagged INACCESSIBLE:  %s", name);
		    ipart = -1;	/* causes skip below */
		}
		break;
	    }
	}
#endif
	if (mask && ipart>0) {
	    int found;
	    int serial;
	   
	    for (found=i=0; i<ndevs && !found; i++) {
		if (dev==vm[i].device) found = i+1;
	    }
	    if (!found) {
		DEVICE Dev2;
		serial = volid_get_set(dev, 0, ID_GET);

#if 0
/* take care of uninitialized Volume IDs with no fanfare */
		if (serial==0) {
		    serial = volid_get_set(dev, new_serial(dev), ID_SET);
		}
#endif
#if BETA_TEST
		if (verbose>=3) printf("**ndevs=%d\n", ndevs);
#endif
		if (ndevs>=MAX_DEVICES) {
		    die("More than %d hard disks are listed in '" PARTITIONS "'.\n"
			"    Disks beyond the %dth must be marked:\n"
			"        disk=" DEV_DISK_DIR "/XXXX  inaccessible\n"
			"    in the configuration file (" DFL_CONFIG ").\n"
			, MAX_DEVICES, MAX_DEVICES);
		}
		else
		{
		    GEOMETRY geo;
		    
		    dev_open(&Dev2,dev,O_BYPASS);

		    vm[ndevs].device = dev;

		    vm[ndevs].sort = SORT(dev);
		    
		    vm[ndevs].vol_id.kernel = serial;
		    
		    vm[ndevs].name = stralloc(Dev2.name);

		    if (verbose >= 4)
			printf("pf:  dev=%04X  id=%08X  name=%s\n", dev, (int)serial, Dev2.name);

		    for (walk = disktab; walk; walk = walk->next) {
			if (walk->device == dev) {
			    bios = walk->bios;
			    vm[ndevs].dt = walk;	/* record disktab link */
			    if (bios >= 0x80 && bios <= DEV_MASK) {
				vm[ndevs].bios.actual =
					vm[ndevs].bios.user = bios;
				bios &= 0x7F;
				if (codes & (1L<<bios)) {
				    i = ndevs-1;
				    bios += 0x80;
				    while (vm[i].bios.user != bios) i--;
				    die("Disks '%s' and '%s' are both assigned 'bios=0x%02X'",
				    		vm[ndevs].name, vm[i].name, bios);
				}
				codes |= 1L << bios;	/* mark BIOS code in use */
			    } 
			    else if (bios != -1)
				die("Hard disk '%s' bios= specification out of the range [0x80..0x%02X]", Dev2.name, DEV_MASK);

			    break;
			}
		    }

		    dev_close(&Dev2);

		    geo_query_dev(&geo, dev,
		              MAJOR(dev)!=MAJOR_LOOP
#ifdef LCF_ATARAID
                               && MAJOR(dev)!=MAJOR_DM
#endif
		                                );

		    vm[ndevs].bios.probe = bios_device(&geo, dev);

		    if (serial_valid(serial, DEV_MASK)) {
			for (i=0; i<ndevs; i++) {
			    if (vm[i].vol_id.kernel==serial) {
				duplicate++;
				vm[i].flag |= DUPLICATE;
				vm[ndevs].flag |= DUPLICATE;	/* mark both of them */
			    } /* if */
			} /* for */
		    }
		    else {
			vm[ndevs].flag |= INVALID;
			invalid++;
		    }
		    found = ++ndevs;
		} /* if (open, lseek, read ) */
				
	    } /* if (!found)  */

	    if (ipart>0 && ipart<=PART_MAX) {
		found--;
		if (part_nowrite(name) & PTW_NTFS) {
		    vm[found].flag |= NTCAUTION;
		    vm[found].nt[ipart-1] = NTCAUTION;
		    ntcaution++;
		    if (verbose>=4) printf("NT partition: %s %d %s\n",
		    			vm[found].name, ipart, name);
		}
	    }

	} /* if (mask && (device & P_MASK(device)) ) */

    } /* while (!feof())  */
   
    if (line) free(line);
    fclose(pp_fd);



	if (verbose>=5) {
	    int i;
	    for (i=0; i<ndevs; i++)
		printf("  %04X  %08X  %s\n", vm[i].device, vm[i].vol_id.kernel, vm[i].name);
	}

    if (verbose>=2) printf("pf_hard_disk_scan: ndevs=%d\n", ndevs);

/* now sort the volumes into canonical order */
  {
	int i,j,k;
	
	for (j=ndevs-1; j>0; j--)
	for (i=0; i<j; i++)
	if (vm[i].sort > vm[i+1].sort) {
	    struct VolumeMgmt temp;
	    temp = vm[i];	
	    vm[i] = vm[i+1];
	    vm[i+1] = temp;
	}

/* now automatically treat MDP-RAID devices as inaccessible */
    for (k=0; k<ndevs; k++) {
#ifdef LCF_MDPRAID
      if (MAJOR(vm[k].device) == MAJOR_MDP  ||
          MAJOR(vm[k].device) == MAJOR_EMD   ) {

        if (verbose>=2) printf("MDP-RAID detected,   k=%d\n", k);
	if (cfg_get_flag(cf_options, "noraid") ) {
	    raidcaution = 1;
	    warn("RAID controller present, with \"noraid\" keyword used.\n"
	    	"    Underlying drives individually must be marked INACCESSIBLE." );
	} else {
	    for (j=0; j<ndevs; j++) {
	        if (j==k) break;	/* skip ourselves */

		if ((i=is_mdp(&vm[j], &vm[k]))<0) {
		    if (!identify) warn("(MDP-RAID driver) the kernel does not support underlying\n"
			"    device inquiries.  Each underlying drive of  %s  must\n"
			"    individually be marked INACCESSIBLE.", vm[k].name
			);
		    j=ndevs;	/* terminate loop */
		}
		else if (i) {
		    if (!vm[j].dt) {
			walk = alloc_t(DT_ENTRY);
			walk->device = vm[j].device;
			walk->cylinders = walk->heads = walk->sectors = walk->start = -1;
			walk->next = disktab;
			vm[j].dt = disktab = walk;
#if BETA_TEST
			if (verbose >= 4) printf("Allocated DT entry for device %04X  ptr=%08lx\n", vm[j].device, (long)walk);
#endif
		    }

		    if (vm[j].dt->heads != 0) {
			vm[j].dt->heads = 0;
			warn("(MDP-RAID) underlying device flagged INACCESSIBLE: %s",
				vm[j].name);
		    }
		    --ndevs;
		    warn("bypassing VolumeID check of underlying MDP-RAID drive:\n"
		    	"\t%04X  %08X  %s",
		    		vm[j].device, vm[j].vol_id.kernel, vm[j].name);
		    for (i=j; i<ndevs; i++) vm[i] = vm[i+1];
		    if (j < k) k--;
		    j--;
		}
	    } /* for j   ... */
	}
      }
#else
      if (MAJOR(vm[k].device) == MAJOR_EMD  ||
          MAJOR(vm[k].device) == MAJOR_MDP   ) {
          raidcaution = 1;
          warn("MDP-RAID controller present; underlying drives individually\n"
	    	"    must be marked INACCESSIBLE." );
#if BETA_TEST
{
	int mdp_fd;
	DEVICE dev;

	if ((mdp_fd=dev_open(&dev, vm[k].device, O_NOACCESS) ) < 0)
	    die("Unable to open %s",vm[k].name);

	dev_close(&dev);
}
#endif
      }
#endif
#ifdef LCF_ATARAID
      if ( MAJOR(vm[k].device) == MAJOR_DM ) {
          if (verbose>=2) printf("ATA-RAID detected,   k=%d\n", k);
          raidcaution = 1;
          warn("ATA-RAID controller present;\n"
              "    Underlying drives individually must be marked INACCESSIBLE." );
      }
#endif
    } /* for (k ... */
  } /* end sort */

	if (verbose>=3) {
	    for (i=0; i<ndevs; i++)
		printf("  %04X  %08X  %s\n", vm[i].device, vm[i].vol_id.kernel, vm[i].name);
	    printf("Resolve invalid VolumeIDs\n");
	}

/* now go thru and resolve any invalid VolumeIDs */

    if (invalid)
    for (i=0; i<ndevs; i++)
    if (vm[i].flag & INVALID) {
	if (ndevs>1) winnt_check(&vm[i], 1);
	else if (vm[i].flag & NTCAUTION) break;
	
	dev = vm[i].device;
	vm[i].vol_id.kernel = volid_get_set(dev, new_serial(dev), ID_SET);
	vm[i].flag &= ~INVALID;
    }

	if (verbose>=3)
	    printf("Resolve duplicate VolumeIDs\n");
    
/* now check for duplicates */

    while (duplicate) {		/* loop until there are none */
	int j, k;
	
	if (raidcaution) {
	    raidcaution = 0;	/* print comment only once */
	    warn("Duplicated VolumeID's will be overwritten;\n"
	        "   With RAID present, this may defeat all boot redundancy.\n"
	        "   Underlying RAID-1 drives should be marked INACCESSIBLE.\n"
	        "   Check 'man lilo.conf' under 'disk=', 'inaccessible' option."
	        );
	}
	duplicate = 0;
	for (j=ndevs-1; j>0; j--) {
	    for (i=0; i<j; i++) {
		if (vm[i].vol_id.kernel == vm[j].vol_id.kernel) {
		    if (vm[i].flag & vm[j].flag & NTCAUTION) {
			if (!winnt_check(&vm[j], 0)) k = j;
			else winnt_check(&vm[k=i], 1);
		    }
		    else if (vm[i].flag & NTCAUTION) k = j;
		    else if (vm[j].flag & NTCAUTION) k = i;
		    else k = j;
		    
		    dev = vm[k].device;
		    vm[k].vol_id.kernel = volid_get_set(dev, new_serial(dev), ID_SET);
		    duplicate++;
		}
	    }
	}
    } /* while (duplicate) */



	if (verbose>=2) {
	    for (i=0; i<ndevs; i++)
		printf("  %04X  %08X  %s\n", vm[i].device, vm[i].vol_id.kernel, vm[i].name);
	}



    if (verbose>=2) printf("device codes (user assigned pf) = %lX\n", codes);

/* mark those BIOS codes that are already used in the disk=/bios= table */

    for (walk=disktab; walk; walk=walk->next) {
	if (walk->bios >= 0x80) {   /* eliminate -1 and floppies */
	    if (MAJOR(walk->device)==MAJOR_MD) continue;
	    bios = walk->bios & 0x7F;
	    if (bios >= 8*sizeof(codes) || bios >= MAX_BIOS_DEVICES)
		die("BIOS code %02X is too big (device %04X)", bios+0x80, walk->device);
	    if (codes & (1L<<bios)) {
		int j = -1;
		int k = -1;

		for (i=0; i<ndevs; i++) {
		    if (vm[i].device == walk->device) j = i;
		    else if (vm[i].bios.user == bios+0x80) k = i;
		}
#if BETA_TEST
		if (verbose>=3) printf("J=%d  K=%d\n", j, k);
#endif
		if (j<0 && k>=0) {
		    die("Devices %04X and %04X are assigned to BIOS 0x%02X",
		    	vm[k].device, walk->device, bios+0x80);
		}
	    }
	    codes |= 1L << bios;	
	}
    }

    if (verbose>=2) printf("device codes (user assigned) = %lX\n", codes);

    for (i=0; i<ndevs; i++) {
	bios = vm[i].bios.probe;
	if (bios >= 0x80) {
	    if (vm[i].bios.actual < 0x80 && !(codes & (1L<<(bios&0x7F)))) {
		vm[i].bios.actual = bios;
		bios &= 0x7F;
		codes |= 1L << bios;
	    }
	}
    }

    if (verbose>=2) printf("device codes (BIOS assigned) = %lX\n", codes);

    for (bios=i=0; i<ndevs; i++) {
	int j;
	
	
	if (vm[i].bios.actual < 0x80) {
	    while ( codes & (1L<<bios) ) bios++;
	    if (bios < MAX_BIOS_DEVICES) {
		codes |= 1L<<bios;
		vm[i].bios.actual = 0x80+bios;
		if (verbose>=3) printf("Filling in '%s' = 0x%02X\n", vm[i].name, bios+0x80);
	    }
	    else vm[i].bios.actual = -1;
	}
	if (!vm[i].dt) {
	    walk = alloc_t(DT_ENTRY);
	    walk->device = vm[i].device;
	    walk->cylinders = walk->bios = walk->heads = walk->sectors = walk->start = -1;
	    walk->next = disktab;
	    vm[i].dt = disktab = walk;
#if BETA_TEST
	    if (verbose >= 4) printf("Allocated DT entry for device %04X  ptr=%08lx\n", vm[i].device, (long)walk);
#endif
	}
	j = vm[i].dt->bios = vm[i].bios.actual;
	j &= 0x7F;

	if (j < MAX_BIOS_DEVICES) {	
	    serial_no[j] = vm[i].vol_id.kernel;
	    device_code[j] = vm[i].device;
#if BETA_TEST
	    if (verbose >= 5) {
		printf("Generated: %02X  %04X  %08X\n", j+0x80, device_code[j], (int)serial_no[j]);
	    }
#endif
	}
	else {
	    vm[i].dt->heads = 0;	/* mark inaccessible */
	    {
		static int i=0;
		if (!(i++)) warn("Internal implementation restriction. Boot may occur from the first\n"
		    "    %d disks only. Disks beyond the %dth will be flagged INACCESSIBLE."
		    , MAX_BIOS_DEVICES, MAX_BIOS_DEVICES);
		warn("'disk=%s  inaccessible' is being assumed.  (%04X)",
		vm[i].name, vm[i].device);
	    }
	}
	
	inited = 1;
    }

    if (verbose>=2) printf("device codes (canonical) = %lX\n", codes);

    for (bios=8*sizeof(codes)-1; !(codes&(1L<<bios)) && bios>=0; ) bios--;

    if (bios > ndevs)
	warn("BIOS device code 0x%02X is used (>0x%02X).  It indicates more disks\n"
			"  than those represented in '/proc/partitions' having actual partitions.\n"
			"  Booting results may be unpredictable.", bios+0x80, ndevs+0x80-1);



    return ret;
}

