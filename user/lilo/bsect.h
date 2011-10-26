/* bsect.h  -  Boot sector handling */
/*
Copyright 1992-1998 Werner Almesberger.
Copyright 1999-2004 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/


#ifndef BSECT_H
#define BSECT_H
#include "common.h"

char *pw_input(void);
void bmp_do_timer(char *cp, MENUTABLE *menu);
void bmp_do_table(char *cp, MENUTABLE *menu);
void bmp_do_colors(char *cp, MENUTABLE *menu);


#ifdef LCF_BUILTIN
BUILTIN_FILE *select_loader(void);
/* return the pointer to the selected built-in secondary loader */
#endif

void bsect_read(char *boot_dev,BOOT_SECTOR *buffer);
/* Read the boot sector stored on BOOT_DEV into BUFFER. */

void bsect_open(char *boot_dev,char *map_file,char *install,int delay,
  int timeout, int raid_offset);

/* Loads the boot sector of the specified device and merges it with a new
   boot sector (if install != NULL). Sets the boot delay to 'delay' 1/10 sec.
   Sets the input timeout to 'timeout' 1/10 sec (no timeout if -1). Creates a
   temporary map file. */

int bsect_number(void);
/* Returns the number of successfully defined boot images. */

#ifdef LCF_VIRTUAL
void check_vmdefault(void);
/* Verify existence of vmdefault image, if vmdefault is used */
#endif

#ifdef LCF_NOKEYBOARD
void check_nokbdefault(void);
/* Verify existence of nokbdefault image, if nokbdefault is used */
#endif

void check_fallback(void);
/* Verifies that all fallback options specify valid images. */

void check_unattended(void);
/* checks that unattended won't hang up on password */

void bsect_update(char *backup_file, int force_backup, int pass);
/* Updates the boot sector and the map file. */

void bsect_raid_update(char *boot_dev, unsigned int raid_offset, 
	char *backup_file, int force_backup, int pass, int mask);

/* Update the boot sector and the map file, with RAID considerations */

void bsect_cancel(void);

/* Cancels all changes. (Deletes the temporary map file and doesn't update
   the boot sector. */

void do_image(void);

/* Define a "classic" boot image. (Called from the configuration parser.) */

void do_unstripped(void);

/* Define an unstripped kernel. */

void do_other(void);

/* Define an other operating system. */

void bsect_uninstall(char *boot_dev_name,char *backup_file,int validate);

/* Restores the backed-up boot sector of the specified device. If
   'boot_dev_name' is NULL, the current root device is used. If 'backup_file'
   is NULL, the default backup file is used. A time stamp contained in the
   boot sector is verified if 'validate' is non-zero. */

#endif
