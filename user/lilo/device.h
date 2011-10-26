/* device.h  -  Device access

Copyright 1992-1996 Werner Almesberger.
Copyright 1999-2004 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/


#ifndef DEVICE_H
#define DEVICE_H

#include <sys/stat.h>


typedef struct {
    int fd;
    struct stat st;
    char *name;
    int delete;
} DEVICE;


int dev_open(DEVICE *dev,int number,int flags);

/* Searches /dev for a block device with the specified number. If no device
   can be found, a temporary device is created. The device is opened with
   the specified access mode and the file descriptor is returned. If flags
   are -1, the device is not opened. */



void dev_close(DEVICE *dev);

/* Closes a device that has previously been opened by dev_open. If the device
   had to be created, it is removed now. */



void preload_dev_cache(void);

/* Preloads the device number to name cache. */



int make_backup(char *backup_file, int force_backup, BOOT_SECTOR *bsect,
	unsigned int device, char *id);

/* make a backup, returning the timestamp of the backup file */



unsigned int register_bios(int bios, int device);

/* registers the bios to device association by serial number */


void dump_serial_nos(void);

/* debugging dump of the Volume Serial number table */


int serial_valid(unsigned int serial, int disk_bios);
/* determine validity of serial number; liberally if disk_bios==0x80 */


int pf_hard_disk_scan(void);
/* scan /proc/partitions for devices & partitions */

int yesno(char *prompt, int expect);
/* prompt the user for a yes/no response */

int new_serial(int device);
/* generate a new volumeID */

#endif
