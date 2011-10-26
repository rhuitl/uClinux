/* map.h  -  Map file creation */
/*
Copyright 1992-1998 Werner Almesberger.
Copyright 1999-2004 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/

#ifndef MAP_H
#define MAP_H


#ifndef SEEK_SET
#define SEEK_SET 0
#endif
#ifndef SEEK_CUR
#define SEEK_CUR 1
#endif
#ifndef SEEK_END
#define SEEK_END 2
#endif


void map_patch_first(char *name,char *str);
/* Puts str into the first sector of a map file. */

void map_create(char *name);
/* Create and initialize the specified map file. */

void map_descrs(DESCR_SECTORS *descr, SECTOR_ADDR* addr, SECTOR_ADDR* dflcmd);
/* Updates map file with descriptors & default command line */

void map_close(BOOT_PARAMS_2 *param2, off_t here);
/* closes the map file, write second stage parameters */

void map_add_sector(void *sector);
/* Adds the specified sector to the map file and registers it in the map
   section. */

void map_begin_section(void);
/* Begins a map section. Note: maps can also be written to memory with 
   map_write. Thus, the map routines can be used even without map_create. */

void map_add(GEOMETRY *geo,int from,int num_sect);
/* Adds pointers to sectors from the specified file to the map file, starting
   "from" sectors from the beginning. */

void map_add_zero(void);
/* Adds a zero-filled sector to the current section. */

int map_end_section(SECTOR_ADDR *addr,int dont_compact);
/* Writes a map section to the map file and returns the address of the first
   sector of that section. The first DONT_COMPACT sectors are never compacted.
   Returns the number of sectors that have been mapped. */

#ifdef LCF_FIRST6
int map_write(SECTOR_ADDR *list,int max_len,int terminate,int sa6);
#else
int map_write(SECTOR_ADDR *list,int max_len,int terminate);
#endif
/* Writes a map section to an array. If terminate is non-zero, a terminating
   zero entry is written. If the section (including the terminating zero entry)
   exceeds max_len sectors, map_write dies. */

off_t map_insert_file(GEOMETRY *geo, int skip, int sectors);
/* Copies a file (second stage loader, usually) into the map file, skipping
   'skip' sectors at the beginning, and writing 'sectors' sectors.  The 
   sectors are added to the current map section. */
   
off_t map_insert_data(unsigned char *data, int size);
/* Copies data from an internal array into the map file.  The sectors
   are added to the current map section */

   
#endif
