#if 0
  common.h  -  Common data structures and functions.

Copyright 1992-1998 Werner Almesberger.
Copyright 1999-2005 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.


#endif

#ifndef COMMON_H
#define COMMON_H

#ifndef LILO_ASM
#include <fcntl.h>
#include <asm/types.h>
#if !__MSDOS__
#include <sys/stat.h>
#endif

#ifndef PAGE_SIZE
# define PAGE_SIZE 4096U
#endif

#ifdef O_ACCMODE
# define O_NOACCESS O_ACCMODE
#else
/* open a file for "no access" */
# define O_NOACCESS 3
#endif

/* special for LILO, bypass the actual open in  dev_open( , ,-1)   */
#define O_BYPASS -1

#endif

#if __MSDOS__
#define const
#endif


/*
;*/typedef struct {		/*
							block	0
;*/    unsigned char sector,track; /* CX 
						sa_sector:	.blkb	1
						sa_track:	.blkb	1
;*/    unsigned char device,head; /* DX
						sa_device:	.blkb	1
						sa_head:	.blkb	1
;*/    unsigned char num_sect; /* AL
						sa_num_sect:	.blkb	1
;*/} __attribute__((packed)) SECTOR_ADDR; /*
						sa_size:
							endb




;*/typedef struct {			/*
							block	0
;*/    char name[MAX_IMAGE_NAME+1];	/* image name, NUL terminated 
						id_name:	.blkb	MAX_IMAGE_NAME_asm+1
;*/    unsigned short password_crc[MAX_PW_CRC*(sizeof(INT4)/sizeof(short))];  /* 4 password CRC-32 values
						id_password_crc:.blkb	MAX_PW_CRC_asm*4
;*/    unsigned short rd_size[2]; /* RAM disk size in sectors, 0 if none
						id_rd_size:	.blkb	4		;don't change the order !!!
;*/    SECTOR_ADDR initrd,start;  /* start of initrd & kernel
						id_initrd:	.blkb	sa_size		;  **
						id_start:	.blkb	sa_size		;  **
;*/    unsigned short flags,vga_mode; /* image flags & video mode
						id_flags:	.blkb	2		;  **
						id_vga_mode:	.blkb	2		;  **
;*/} IMAGE_DESCR;		/*
						id_size:
							endb



;*/typedef struct {			/*
							block	0
;*/    unsigned char  bytes_per_sector[2];	/*
						bpb_bytes_per_sector:	.blkb	2
;*/    unsigned char  sectors_per_cluster;	/*
						bpb_sectors_per_cluster:.blkb	1
;*/    unsigned char  reserved_sectors[2];	/*
								.blkb	2
;*/    unsigned char  number_of_FATs;		/*
								.blkb	1
;*/    unsigned char  root_dir_entries[2];	/*
								.blkb	2
;*/    unsigned char  total_sectors[2];		/*
							.blkb	2
;*/    unsigned char  media_descriptor;		/*
							.blkb	1
;*/    unsigned char  sectors_per_FAT[2];	/*
							.blkb	2
;*/    unsigned char  sectors_per_track[2];	/* DOS v.3
							.blkb	2
;*/    unsigned char  heads_per_cylinder[2];	/* DOS v.3
							.blkb	2
;*/    unsigned char  hidden_sectors[4];	/*
							.blkb	4
;*/    unsigned char  total_sectors_long[4];	/* if total_sectors==0
							.blkb	4
;*/    unsigned char  reserved[7];		/* pad to 32 bytes
							.blkb	7
;*/} BIOS_PARAMETER_BLOCK;	/*
						bpb_size:
							endb
							
							
							
;*/typedef struct {		/*
						block	0
;*/    unsigned char jump[3];	/* jump to boot code
						bpdos_jump:	.blkb	3
;*/    char system[8];		/* system ID
						bpdos_system:	.blkb	8
;*/    BIOS_PARAMETER_BLOCK bpb;	/* BIOS parameter block
						bpdos_bpb:	.blkb	bpb_size
;*/} BOOT_PARAMS_DOS;	/* DOS fat header
						bpdos_size:
							endb
							
							

;*/typedef struct {					/*
							block	0
;*/    unsigned char cli;     /* clear interrupt flag instruction
						par1_cli:	.blkb	1
;*/    unsigned char jmp0, jmp1;	/* short jump
						par1_jump:	.blkb	2
;*/    unsigned char stage;  /*
						par1_stage:	.blkb	1
;*/    unsigned short code_length;  /* length of the first stage code
						par1_code_len:	.blkb	2
;*/    char signature[4]; /* "LILO"
						par1_signature:	.blkb	4
;*/    unsigned short version;  /*
						par1_version:	.blkb	2
;*/    unsigned int map_stamp; /* timestamp for this installation (map creation)
						par1_mapstamp:	.blkb	4
;*/    unsigned int raid_offset; /* raid partition/partition offset
						par1_raid_offset: .blkb	4
;*/    unsigned int timestamp; /* timestamp for restoration
						par1_timestamp:	.blkb	4
;*/    unsigned int map_serial_no; /* volume serial no. / id containing the map file
						par1_map_serial_no:	.blkb	4
;*/    unsigned short prompt; /* FLAG_PROMPT=always, FLAG_RAID install
						par1_prompt:	.blkb	2
;*/    SECTOR_ADDR secondary; /* sectors of the second stage loader
						par1_secondary:	.blkb	sa_size+1
;*/} __attribute__((packed)) BOOT_PARAMS_1; /* first stage boot loader 
								.align	4
						par1_size:
							endb



;*/typedef struct {	/* second stage parameters
							block	0
;*/    char jump[6]; /* jump over the data
						par2_jump:	.blkb	6
;*/    char signature[4]; /* "LILO"
						par2_signature:	.blkb	4
;*/    unsigned short version;	/*
						par2_version:	.blkb	2
;*/    unsigned int map_stamp;		/* time of creation of the map file
						par2_mapstamp:	.blkb	4
;*/    unsigned short stage;	/*
						par2_stage:	.blkb	2
;*/    unsigned char port; /* COM port. 0 = none, 1 = COM1, etc. !!! keep these two serial bytes together !!!
;*/    unsigned char ser_param; /* RS-232 parameters, must be 0 if unused
						par2_port:	.blkb	1	; referenced together
						par2_ser_param:	.blkb	1	; **
;*/    unsigned short timeout; /* 54 msec delay until input time-out, 0xffff: never 
						par2_timeout:	.blkb	2
;*/    unsigned short delay; /* delay: wait that many 54 msec units.
						par2_delay:	.blkb	2
;*/    unsigned short msg_len; /* 0 if none
						par2_msg_len:	.blkb	2
;*/    SECTOR_ADDR keytab; /* keyboard translation table
						par2_keytab:	.blkb	sa_size
;*/    unsigned char flag2;	/*	flags specific to the second stage loader
						par2_flag2:	.blkb	1
;*/} BOOT_PARAMS_2; /* second stage boot loader
								.align	4
						par2_size:
							endb




;*/typedef struct {			/*
							block	0
;*/    char jump[6]; /* jump over the data
						parC_jump:	.blkb	6
;*/    char signature[4]; /* "LILO" 
						parC_signature:	.blkb	4
;*/    unsigned short stage,version; /* stage is 0x10
						parC_stage:	.blkb	2
						parC_version:	.blkb	2
;*/    unsigned short offset; /* partition entry offset
						parC_offset:	.blkb	2
;*/    unsigned char drive; /* BIOS drive code
						parC_drive:	.blkb	1
;*/    unsigned char head; /* head; always 0
						parC_head:	.blkb	1
;*/    unsigned short drvmap; /* offset of drive map
						parC_drvmap:	.blkb	2
;*/    unsigned char ptable[PARTITION_ENTRY*PARTITION_ENTRIES]; /* part. table
						parC_ptable:	.blkb	64
;*/    unsigned short p_devmap[2];	/* pointer to device map filled in by second.S
						parC_devmap:	.blkb	4
;*/} BOOT_PARAMS_C; /* chain loader
						parC_size:
							endb



;*/typedef struct {					/*
							block	0
;*/	char menu_sig[4];	/* "MENU" or "BMP4" signature, or NULs if not present
						mt_sig:		.blkb	4
;*/	unsigned char at_text;	/* attribute for normal menu text
						mt_at_text:	.blkb	1
;*/	unsigned char at_highlight;	/* attribute for highlighted text
						mt_at_hilite:	.blkb	1
;*/	unsigned char at_border;	/* attribute for borders
						mt_at_border:	.blkb	1
;*/	unsigned char at_title;		/* attribute for title
						mt_at_title:	.blkb	1
;*/	unsigned char len_title;	/* length of the title string
						mt_len_title:	.blkb	1
;*/	char title[MAX_MENU_TITLE+2];	/* MENU title to override default
						mt_title:	.blkb	MAX_MENU_TITLE_asm+2
;*/	short row, col, ncol;		/* BMP row, col, and ncols
						mt_row:		.blkw	1
						mt_col:		.blkw	1
						mt_ncol:	.blkw	1
;*/	short maxcol, xpitch;		/* BMP max per col, xpitch between cols
						mt_maxcol:	.blkw	1
						mt_xpitch:	.blkw	1
;*/	short fg, bg, sh;		/* BMP normal text fore, backgr, shadow
						mt_fg:		.blkw	1
						mt_bg:		.blkw	1
						mt_sh:		.blkw	1
;*/	short h_fg, h_bg, h_sh;		/* highlight fg, bg, & shadow
						mt_h_fg:	.blkw	1
						mt_h_bg:	.blkw	1
						mt_h_sh:	.blkw	1
;*/	short t_fg, t_bg, t_sh;		/* timer fg, bg, & shadow colors
						mt_t_fg:	.blkw	1
						mt_t_bg:	.blkw	1
						mt_t_sh:	.blkw	1
;*/	short t_row, t_col;		/* timer position
						mt_t_row:	.blkw	1
						mt_t_col:	.blkw	1
;*/	short mincol, reserved[3];	/* BMP min per col before spill to next, reserved spacer
						mt_mincol:	.blkw	1
								.blkw	3

;*/	unsigned int serial_no[MAX_BIOS_DEVICES];	/* Known device serial nos. 0x80 .. 0x8F
						mt_serial_no:	.blkw	MAX_BIOS_DEVICES_asm*2
;*/	unsigned int raid_offset[MAX_RAID_DEVICES];	/* RAID offsets for flagged devices
						mt_raid_offset:	.blkw	MAX_RAID_DEVICES_asm*2
;*/	unsigned short raid_dev_mask;			/* 16 bit raid device mask flagging items in serial_no
						mt_raid_dev_mask: .blkw	1
;*/	SECTOR_ADDR msg; /* initial greeting message
						mt_msg:	.blkb	sa_size
;*/	SECTOR_ADDR dflcmd; /* default command line
						mt_dflcmd:	.blkb	sa_size
;*/	SECTOR_ADDR mt_descr[MAX_DESCR_SECS];	/* descriptor disk addresses
						mt_descr:	.blkb	sa_size*MAX_DESCR_SECS_asm
;*/	char unused[150-MAX_BIOS_DEVICES*sizeof(int)-(MAX_RAID_DEVICES)*sizeof(int)-MAX_DESCR_SECS*sizeof(SECTOR_ADDR)];		/* spacer
						mt_unused:	.blkb	150-sa_size*MAX_DESCR_SECS_asm-4*MAX_BIOS_DEVICES_asm-4*MAX_RAID_DEVICES_asm
;*/	short checksum[2];		/* checksum longword
						mt_cksum:	.blkw	2
;*/	unsigned char mt_flag;		/* contains the FLAG_NOBD only
						mt_flag:	.blkb	1
;*/	char unused2;			/* spacer beyond checksum
						mt_unused2:	.blkb	1
;*/} MENUTABLE;		/* MENU and BITMAP parameters at KEYTABLE+256
						mt_size:
							endb

;*/

#ifndef LILO_ASM

typedef struct {
    unsigned char bootcode[MAX_BOOT_SIZE];
    unsigned short mbz;		/* must be zero */
    int  volume_id;
    unsigned short marker;	/* may be zero */
    unsigned char part[PART_TABLE_SIZE];
    unsigned short boot_ind;	/* 0xAA55 */
} BOOT_VOLID;
    
typedef union {
    BOOT_PARAMS_1 par_1;
    BOOT_PARAMS_2 par_2;
    BOOT_PARAMS_C par_c;
    BOOT_PARAMS_DOS par_d;
    BOOT_VOLID boot;
    unsigned char sector[SECTOR_SIZE];
} BOOT_SECTOR;

typedef union {
    struct {
	IMAGE_DESCR descr[MAX_IMAGES]; /* boot file descriptors */
    } d;
    unsigned char sector[SECTOR_SIZE*MAX_DESCR_SECS];
    struct {
    	unsigned int sector[SECTOR_SIZE/4*MAX_DESCR_SECS - 1];
    	unsigned int checksum;
    } l;
} DESCR_SECTORS;

typedef struct {
    int size;
    unsigned char data[1];
} BUILTIN_FILE;


#ifdef LCF_FIRST6
#pragma pack (2)
typedef struct {
    unsigned char device, flags;
    unsigned int sector;
} SECTOR_ADDR6;
#pragma pack ()
#endif


#endif
/*
IMAGES_numerator = SECTOR_SIZE_asm*MAX_DESCR_SECS_asm - 4 - 1
IMAGES = IMAGES_numerator / id_size
;*/
#ifndef LILO_ASM
typedef struct {
    unsigned short jump;	/*  0: jump to startup code */
    char signature[4];		/*  2: "HdrS" */
    unsigned short version;	/*  6: header version */
    unsigned short x,y,z;	/*  8: LOADLIN hacks */
    unsigned short ver_offset;	/* 14: kernel version string */
    unsigned char loader;	/* 16: loader type */
    unsigned char flags;	/* 17: loader flags */
    unsigned short a;		/* 18: more LOADLIN hacks */
    unsigned int start;	/* 20: kernel start, filled in by loader */
    unsigned int ramdisk;	/* 24: RAM disk start address */
    unsigned int ramdisk_size;	/* 28: RAM disk size */
    unsigned short b,c;		/* 32: bzImage hacks */
    unsigned short heap_end_ptr;/* 36: 2.01 end of free area after setup code */
    unsigned char d;		/* 38: padding */
    unsigned int cmd_line_ptr; /* 40: 2.02 address32 of command line */
    unsigned int ramdisk_max;	/* 44: 2.03 address32 of highest mem. for ramdisk */
} SETUP_HDR;

#define alloc_t(t) ((t *) alloc(sizeof(t)))

typedef enum {X_NULL=0, X_NONE, X_AUTO, X_MBR_ONLY, X_MBR, X_SPEC} LILO_EXTRA;
typedef enum {AD_ANY=0, AD_GEOMETRIC, AD_LINEAR, AD_LBA32=4} ADDR_MODE;
typedef enum {DL_NOT_SET=0, DL_BAD=1, DL_UNKNOWN, DL_MAYBE, DL_GOOD} DL_BIOS;

extern LILO_EXTRA extra;
extern char *identify;
extern int verbose,test,compact,linear,nowarn,lba32,autoauto,passw,geometric;
extern int bios_boot, bios_map;
extern int ireloc, force_fs, force_raid, extended_pt, query;
extern int colormax, warnings;
extern DL_BIOS bios_passes_dl;
extern int boot_dev_nr,raid_index,raid_flags,do_md_install,ndisk,zflag,eflag;
extern unsigned short drv_map[DRVMAP_SIZE+1]; /* needed for fixup maps */
extern int curr_drv_map;
extern unsigned int prt_map[PRTMAP_SIZE+1];
extern int curr_prt_map, config_read;
extern unsigned int serial_no[MAX_BIOS_DEVICES];
extern char *config_file;
extern FILE *errstd;
extern FILE *pp_fd;
extern char *identify;	/* in identify.c */
extern int dm_major_list[16];
extern int dm_major_nr;

#define crc(a,b) (~crc32((a),(b),CRC_POLY1))
#define brev(x)  \
 { register unsigned short u1,u2; register unsigned int u=(x); u1=u; u2=u>>16; \
 u1=(u1>>8)|(u1<<8); u2=(u2>>8)|(u2<<8); x=(unsigned int)u1<<16|u2; }
#define cc(x) crc(x.data,x.size)
#define comma (cc(First)|cc(Second)|cc(Third)|cc(Bitmap)|cc(Chain)|cc(Mbr)|cc(Mbr2))


/*volatile*/ void pdie(char *msg);
/* Do a perror and then exit. */


/*volatile*/ void die(char *fmt,...);
/* fprintf an error message and then exit. */


/*volatile*/ void warn(char *fmt,...);
/* issue a warning message if !nowarn */


void *alloc(int size);
/* Allocates the specified number of bytes. Dies on error. */


void *ralloc(void *old,int size);
/* Changes the size of an allocated memory area. Dies on error. */


char *stralloc(const char *str);
/* Like strdup, but dies on error. */


int to_number(char *num);
/* Converts a string to a number. Dies if the number is invalid. */


int timer_number(char *num);
/* Converts a string to a number.  Allows suffix of 't', 's', 'm', 'h'
for Tenths, Seconds, Minutes, Hours. Dies if number is invalid for 
"timeout" or "delay" */


void check_version(BOOT_SECTOR *sect, int stage);
/* Verify that a boot sector has the correct version number. */


int stat_equal(struct stat *a, struct stat *b);
/* Compares two stat structures. Returns a non-zero integer if they describe
   the same file, zero if they don't. */



unsigned int crc32partial(unsigned char *cp, int nsize,
			unsigned int polynomial, unsigned int *accum);
/* accumulate a partial CRC-32 */



unsigned int crc32 (unsigned char *cp, int nsize, unsigned int polynomial);
/* calculate a CRC-32 polynomial */


void show_link(char *name);
/* show what a link resolves to */

#if __MSDOS__
#undef comma
#define comma 0
#define semi ";"
#endif
#endif
#endif
