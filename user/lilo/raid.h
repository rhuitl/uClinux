/* raid.h  -  The RAID-1 hooks for LILO */
/*
Copyright 2001-2004 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/

int do_md_install, ndisk, md_bios;

int raid_setup(void);
void raid_final(void);

/* form the mask of the raid bios codes and the list of offsets */
/* this information goes into the MENUTABLE passed to the loader */
int raid_mask(int *offsets);

