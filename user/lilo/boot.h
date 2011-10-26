/* boot.h  -  Boot image composition

Copyright 1992-1995 Werner Almesberger.
Copyright 1999-2004 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/

#ifndef BOOT_H
#define BOOT_H


void boot_image(char *spec,IMAGE_DESCR *descr);

/* Maps a "classic" boot image. */

void boot_device(char *spec,char *range,IMAGE_DESCR *descr);

/* Maps sectors from a device as the boot image. Can be used to boot raw-written
   disks. */

void boot_unstripped(char *boot,char *setup,char *kernel,IMAGE_DESCR *descr);

/* Maps an unstripped kernel image as the boot image. The setup (without the
   header) is prepended. */

char *boot_mbr(const char *boot, int table);
/* derive name of MBR from partition name; check for primary partition
   if table==1
 */

void boot_other(char *loader,char *boot,char *part,IMAGE_DESCR *descr);

/* Merges a loader with a partition table and appends a boot sector. This mix
   is used to boot non-Linux systems. */

void dump(char *spec,IMAGE_DESCR *descr);

/* Maps a crash dump file. */

#endif
