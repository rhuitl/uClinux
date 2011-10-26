/* probe.h  -- definitions for the LILO probe utility

Copyright 1999-2005 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/

#ifndef __PROBE_H_
#define __PROBE_H_



struct disk_geom {
   unsigned int n_total_blocks;
   int n_sect;
   int n_head;
   int n_cyl;
   char type;
   char EDD_flags;
   char EDD_rev;
   char n_disks;
   struct partition *pt;
   int serial_no;		/* added at PROBE_VERSION==4 */
};

#if 0
/* structure used by int 0x13, AH=0x48 */

struct disk_param {
   short size;
   short flags;
   unsigned int n_cyl;
   unsigned int n_head;
   unsigned int n_sect;
   long long n_sectors;
   short n_byte;
   unsigned int edd_config_ptr;
};
#endif


#define EDD_DMA_BOUNDARY_TRANSP  01
#define EDD_PARAM_GEOM_VALID     02


/* the following structures are created by the biosdata.S codes */

typedef
struct Equip {
   unsigned short equipment;
   unsigned short mem;
#if PROBE_VERSION >= 5
   unsigned short boot_dx;
#endif
} equip_t;


/* BD_GET_VIDEO >= 1 */
typedef
struct Video1 {
   struct {
      unsigned char  al;
      unsigned char  ah;
      unsigned char  bl;
      unsigned char  bh;
   } vid0F;
} video_t1;


/* BD_GET_VIDEO >= 2  */
typedef
struct Video2 {
   struct {
      unsigned short ax;
      unsigned char  bl;
      unsigned char  bh;
   } vid12;
   struct {
      unsigned char  al;
      unsigned char  ah;
      unsigned short bx;
   } vid1A;
} video_t2;

/* BD_GET_VIDEO >=2 extension for PROBE_VERSION 5 */
typedef
struct Video25 {
   struct {
      unsigned short ax;
      unsigned short cx;
      unsigned short dx;
      unsigned short bp;
   } vid36;
} video_t25;


/* BD_GET_VIDEO >= 3  */
typedef
struct Video3 {
   struct {
      unsigned short ax;
               char  sig[4];
   } vid4F00;
   struct {
      unsigned short ax;
      unsigned short bits;
   } vid101;
   struct {
      unsigned short ax;
      unsigned short bits;
   } vid103;
} video_t3;


typedef
struct Video {
   unsigned short equipment;
   unsigned short mem;

/* BD_GET_VIDEO >= 1 */
   struct {
      unsigned char  al;
      unsigned char  ah;
      unsigned char  bl;
      unsigned char  bh;
   } vid0F;

/* BD_GET_VIDEO >= 2  */
   struct {
      unsigned short ax;
      unsigned char  bl;
      unsigned char  bh;
   } vid12;
   struct {
      unsigned char  al;
      unsigned char  ah;
      unsigned short bx;
   } vid1A;


/* BD_GET_VIDEO >= 3  */
   struct {
      unsigned short ax;
      unsigned char  sig[4];
   } vid4F00;
   struct {
      unsigned short ax;
      unsigned short bits;
   } vid101;
   struct {
      unsigned short ax;
      unsigned short bits;
   } vid103;
} video_t;


typedef
struct Floppy {
   struct {
      unsigned char  ah;		/* AL and AH were swapped */
      unsigned char  flags;
      unsigned short dx;
      unsigned short cx;
   } fn15;
   struct {
      unsigned char  ah;		/* AL and AH were swapped */
      unsigned char  flags;
      unsigned short cx;
      unsigned short dx;
      unsigned short di;
      unsigned short es;
   } fn08;
} floppy_t;


typedef
struct Hard {
   struct {
      unsigned char  ah;		/* AL and AH were swapped */
      unsigned char  flags;
      unsigned short dx;
      unsigned short cx;
   } fn15;
   struct {
      unsigned char  ah;		/* AL and AH were swapped */
      unsigned char  flags;
      unsigned short cx;
      unsigned short dx;
   } fn08;
   struct {
      unsigned char  ah;		/* AL and AH were swapped */
      unsigned char  flags;
      unsigned short bx;
      unsigned short cx;
   } fn41;
} hard_t;

typedef
struct Fn48 {
   unsigned char  ah;		/* AL and AH were swapped */
   unsigned char  flags;
} fn48_t;

typedef
struct Edd {
   unsigned short size;			/* 26 or 30 */
   unsigned short info;
   unsigned int  cylinders;
   unsigned int  heads;
   unsigned int  sectors;
   long long      total_sectors;
   unsigned short sector_size;

   unsigned short offset,
   		  segment;
           fn48_t reg;		/* AH & flags returned from the call */
} edd_t;				/* struct is 26; but may be 30 in mem */

/* the video adapter types */
enum {VIDEO_UNKNOWN, VIDEO_MDA, VIDEO_CGA, VIDEO_EGA, VIDEO_MCGA,
	VIDEO_VGA, VIDEO_VESA, VIDEO_VESA_800};

int fetch(void);

int purge(void);

void probe_tell (char *cmd);

int bios_max_devs(void);

int bios_device(GEOMETRY *geo, int device);

int get_video(void);	/* return -1 on error, or adapter type [0..7] */

void check_bios(void);	/* set up bios_passes_dl */

#endif
/* end probe.h */
