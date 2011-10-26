/* lilo.h  -  LILO constants

Copyright 1992-1998 Werner Almesberger.
Copyright 1999-2006 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/


/* This file is also included by the boot loader assembler code. Put
   everything that isn't legal C syntax or isn't swallowed by the
   preprocessor into #ifdef LILO_ASM ... #endif */

#ifndef LILO_H
#define LILO_H

#if !__MSDOS__
#define INT4 int
#else
#define INT4 long
#endif /* !__MSDOS__ */

/* This is the stuff to check the configuration:
 */
#if defined(LCF_READONLY) && defined(LCF_REWRITE_TABLE)
#error "Incompatible Makefile options: READONLY and REWRITE_TABLE"
#endif
#ifdef LCF_LARGE_EBDA
#error "Configuration option '-DLARGE_EBDA' is deprecated"
#endif

/*
 * Starting with 2.1.something, Linux kernels put VGA constants and segment
 * definitions into asm/boot.h instead of linux/config.h
 */

#if 0

#ifdef HAS_BOOT_H
#include <asm/boot.h>
#else
#include <linux/autoconf.h>
#endif

#else

/* Don't touch these, unless you really know what you're doing. */
#define DEF_INITSEG	0x9000
#define DEF_SYSSEG	0x1000
#define DEF_SETUPSEG	0x9020
#define DEF_SYSSIZE	0x7F00

/* Internal svga startup constants */
#define NORMAL_VGA	0xffff		/* 80x25 mode */
#define EXTENDED_VGA	0xfffe		/* 80x50 mode */
#define ASK_VGA		0xfffd		/* ask for it at bootup */

#endif

#if defined(HAS_VERSION_H) && !__MSDOS__
#include <linux/version.h>
#endif /* !__MSDOS__ */

#ifndef LINUX_VERSION_CODE
#define LINUX_VERSION_CODE 0
#endif
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif

#define nelem(a) (sizeof(a)/sizeof((a)[0]))
#define S2(x) #x
#define S(x) S2(x)

#include "version.h"
#define VERSION 256*VERSION_MINOR+VERSION_MAJOR
#if VERSION_MINOR >= 50
# define BETA_TEST 1
#else
# define BETA_TEST 0
#endif

/* definitions for pf_hard_disk_scan in device.c  */
#ifdef DEBUG_PARTITIONS
#define PARTITIONS "./devfs_partitions"
#else
#define PARTITIONS "/proc/partitions"
#endif


/* the known major device numbers */
#define MAJMIN_RAM	0x101 /* RAM disk */
#ifdef LCF_MDPRAID
#define MAJOR_MDP_SORT  1 /* Convert MAJOR_MDP to this for sorting */
#endif
#define MAJOR_EMD_SORT  2 /* Convert MAJOR_EMD to this for sorting */
#define MAJOR_HPT370_SORT  2 /* Convert MAJOR_HPT370 to this for sorting */
#define MAJOR_FD	2 /* floppy disks */
#define MAJOR_HD	3 /* IDE-type hard disks */
#define MAJOR_LOOP	7 /* Loopback devices 0-15 */
#define MAJOR_SD	8 /* SCSI disks 0-15 */
#define MAJOR_MD	9 /* multi-disk RAID sets */
#define MAJOR_XT	13 /* XT-type hard disks */
#define MAJOR_ACORN	21 /* Acorn MFM controller */
#define MAJOR_IDE2	22 /* IDE on second interface */
#define MAJOR_IDE3	33 /* IDE on third interface */
#define MAJOR_IDE4	34 /* IDE on fourth interface */
#define MAJOR_ESDI	36 /* PS/2 ESDI drives */
#define MAJOR_FTL	44 /* Flash Transition Layer on Memory Technology Device */
#define MAJOR_PP	45 /* Parallel Port IDE drive */
#define MAJOR_PPFD	47 /* Parallel Port floppy drive */
#define MAJOR_DAC960	48 /* First Mylex DAC960 PCI RAID controller */
#if !BETA_TEST || 1
#define MAJOR_IDE5	56 /* IDE on fifth interface */
#endif
#define MAJOR_IDE6	57 /* IDE on sixth interface */
#define MAJOR_LVM	58 /* Logical Volume Manager block device */
#define MAJOR_EXPR	60 /* Experimental devices 60..63 */
/*#define MAJOR_FL	62 / M-Systems Disk-On-Chip 2000 ***experimental*** */

#define MAJOR_SD_SORT	64 /*** MAJOR_SD converted to this for sorting ***/
#define MAJOR_SD2	65 /* SCSI disks 16-31 */
#define MAJOR_SD3	66 /* SCSI disks 32-47 */
#define MAJOR_SD4	67 /* SCSI disks 48-63 */
#define MAJOR_SD5	68 /* SCSI disks 64-79 */
#define MAJOR_SD6	69 /* SCSI disks 80-95 */
#define MAJOR_SD7	70 /* SCSI disks 96-111 */
#define MAJOR_SD8	71 /* SCSI disks 112-127 */
#define MAJOR_SMART2	72 /* First Compaq Smart/2 Major 72-79 */
#define MAJOR_I2O	80  /* First I2O block device 80-87 */
#define MAJOR_IDE7	88 /* IDE on seventh interface */
#define MAJOR_IDE8	89 /* IDE on eighth interface */
#define MAJOR_IDE9	90 /* IDE on ninth interface */
#define MAJOR_IDE10	91 /* IDE on tenth interface */
#define MAJOR_PPDD	92 /* PPDD encrypted disks - not supported */
#define MAJOR_NFTL	93 /* NAND Flash Translation Layer (Disk-On-Chip) */
#define MAJOR_DOC	100 /* Disk-On-Chip driver */
#define MAJOR_AMI_HYP	101 /* AMI Hyper Disk RAID controller */
#define MAJOR_CISS	104 /* First CCISS Major 104-111 */
#define MAJOR_IBM_iSER	112 /* IBM iSeries virtual disk */
#define MAJOR_HPT370	114 /* HPT370 controller */
#define MAJOR_EVMS	117 /* Enterprise Volume Management System */
#define MAJOR_SD9	128 /* SCSI disks 129     */
#define MAJOR_SD16	135 /* SCSI disks    -255 */
#define MAJOR_DAC960_8	136 /* Ninth Mylex DAC960 PCI RAID controller */
#define MAJOR_EMD	153 /* Enhanced multi-disk RAID sets */
#define MAJOR_SATA	160 /* Carmel SATA Disk on first 8-port controller */
#define MAJOR_SATA2	161 /* Carmel SATA Disk on 2nd 8-port controller */
/* don't use the following */
#define MAJOR_MDP	254 /* Enhanced multi-disk RAID sets [experimental?] */

#define MAX_TOKEN	1023 /* max device Token length */
#define MAX_IMAGE_NAME	15 /* maximum name length (w/o terminating NUL) */
#define MAX_DESCR_SECTORS  12  /* upper limit on MAX_DESCR_SECS */

#ifdef LCF_PASS160
#undef SHS_PASSWORDS
#define SHS_PASSWORDS		/* use this one if SHS passwords are in use */
#define MAX_PW_CRC	5  	/* max # of longwords in password digest */
#define PW_FILE_SUFFIX ".shs"  	/* suffix for the file that saves password digest */
#else
#define CRC_PASSWORDS		/* use this one if CRC passwords are in use */
#define MAX_PW_CRC	2  	/* max # of CRC-32's in password */
#define PW_FILE_SUFFIX ".crc"  	/* suffix for the file that saves password CRC's */
#endif

#ifdef LCF_DSECS
#define MAX_DESCR_SECS LCF_DSECS
#else
#define MAX_DESCR_SECS 2	/* maximum # of descriptor sectors */
#endif
#if MAX_DESCR_SECS > MAX_DESCR_SECTORS
#error "Maximum DSECS=x exceeded."
#endif
#define MAX_IMAGES      ((int)((SECTOR_SIZE*MAX_DESCR_SECS-sizeof(INT4)-1)/sizeof(IMAGE_DESCR)))
			  /* maximum number of images */

#define COMMAND_LINE_SIZE	512	/* CL_LENGTH */
#define SECTOR_SIZE	512 /* disk sector size */
#ifndef BLOCK_SIZE /* may also come from linux/fs.h */
#define BLOCK_SIZE	1024 /* disk block size */
#endif

#define PARTITION_ENTRY	   16	/* size of one partition entry */
#define PARTITION_ENTRIES  4    /* number of partition entries */
#define PART_TABLE_SIZE    (PARTITION_ENTRY*PARTITION_ENTRIES)
#define PART_TABLE_OFFSET  0x1be /* offset in the master boot sector */
#define PART_ACT_ENT_OFF   0	/* offset in entry for active flag */
#define PART_TYPE_ENT_OFF  4	/* offset in entry for partition type */

#define P_MASK(x) ((~has_partitions(x))&0xFFFFFFFF)
#define D_MASK(x) (has_partitions(x))
#define PART_MAX PARTITION_ENTRIES /* biggest primary partition number */
#define PART_MAX_MAX	63	/* max. partition number (on IDE disks) */

#define MAX_BOOT_SIZE	0x1b6	/* (leave some space for NT's and DR DOS' dirty
				   hacks) scream if the boot sector gets any
				   bigger -- (22.5 - we now use those hacks) */

#define BOOT_SIGNATURE0	0x55	/* boot signature */
#define BOOT_SIGNATURE1	0xaa	/* boot signature */
#define BOOT_SIG_OFFSET	510	/* boot signature offset */
#define MAGIC_SERIAL	0xC9CF	/* LILO installed serial number */
#define PRIME		271	/* prime number used for serial no generation */
#define SMALL_PRIME     17	/* another prime, but a small one */
#if VERSION_MINOR>90
#define MAX_BIOS_DEVICES  2	/* max hard disk devices used by BIOS */
#define MAX_DEVICES	4	/* max hard disk devices, total */
#else
#define MAX_BIOS_DEVICES  16	/* max hard disk devices used by BIOS */
#define MAX_DEVICES	64	/* max hard disk devices, total */
#endif
#define MAX_RAID	30	/* max number of RAID disks in a set */
#if 0
#define MAX_RAID_DEVICES  6	/* max raid devices reported to second.S */
#else
#define MAX_RAID_DEVICES MAX_DESCR_SECTORS-MAX_DESCR_SECS+6	/* max raid devices reported to second.S */
#endif

#define PART_LINUX_MINIX  0x81	/* Linux/MINIX partition */
#define PART_LINUX_SWAP	  0x82	/* Linux swap partition */
#define PART_LINUX_NATIVE 0x83	/* Linux native (file system) */
#define PART_DOS_EXTD 	  5	/* DOS Extended partition */
#define PART_WIN_EXTD_LBA 0xF	/* Win95/98 Extended partition */
#define PART_LINUX_EXTD   0x85	/* Linux Extended partition */
#define PART_OS2_BOOTMGR  0xA	/* OS/2 Boot Manager */

#define PART_DOS12	  1	/* DOS 12 bit FAT partition type */
#define PART_DOS16_SMALL  4	/* DOS 16 bit FAT partition type, < 32 MB */
#define PART_DOS16_BIG	  6	/* DOS 16 bit FAT partition type, >= 32 MB */
#define PART_HPFS	  7	/* OS/2 High Performance File System */
#define PART_NTFS	  7	/* WinNT File System */
#define PART_FAT32	  0xB	/* Win95/98 FAT32 partition on small disk */
#define PART_FAT32_LBA	  0xC	/* Win95/98 FAT32 partition on large disk */
#define PART_FAT16_LBA	  0xE	/* Win95/98 FAT16 partition on large disk */
#define PART_INVALID	  98	/* invalid partition type */

#define HIDDEN_OFF	0x10	/* type offset to hide partition (OS/2 BM) */
#define PART_HDOS12	(PART_DOS12+HIDDEN_OFF)
#define PART_HDOS16_SMALL (PART_DOS16_SMALL+HIDDEN_OFF)
#define PART_HDOS16_BIG	(PART_DOS16_BIG+HIDDEN_OFF)

#define STAGE_FIRST	1	/* first stage loader code */
#define STAGE_SECOND	2	/* second stage loader code */
#define	STAGE_CHAIN	0x10	/* chain loader code */
#define STAGE_DRIVE_MAP	0x11	/* chain loader drive mapper */
#define STAGE_MBR	0x12	/* mbr loader */
#define STAGE_MBR2	0x13	/* mbr2 loader (extended) */
#define STAGE_FLAG_SERIAL  0x0100	/* boot loader supports serial i/o */
#define STAGE_FLAG_MENU	0x0200	/* boot loader supports menu interface */
#define STAGE_FLAG_BMP4	0x0400	/* boot loader supports 640x480x4 bitmaps */

#define SETUPSECS	4	/* nr of setup sectors */
#define VSS_NUM		497	/* address where variable setup size is
				   stored */
#define VGA_SET		506	/* address of initial kernel VGA mode */
#define MAX_SETUPSECS	31	/* maximum number of sectors in kernel
				   setup code (+ bootsect) */
#define MAX_KERNEL_SECS	1024	/* absolute maximum kernel size */
#define SPECIAL_SECTORS	2	/* special sectors (don't compact) at beginning
				   of map sections */
#define SPECIAL_BOOTSECT 1	/* INITSEG bootsect.S bootloader at beginning
				   of all kernels, ahead of SETUPSECS */

#define LINEAR_FLAG	0x40	/* mark linear address */
#define LBA32_FLAG      0x20    /* mark lba 32-bit address */
#define LBA32_NOCOUNT   0x40    /* mark address with count absent */
#define RAID_REL_FLAG	0x10	/* mark address raid-relocatable */
/*
 *	FLAG	Description
 *
 *   	0x00	 pure geometric addressing (C:H:S)
 *	0x40	 Linear address (24-bits) converted to CHS at boot-time
 *	0x60	 LBA32 address (32-bits), count=1, sets the high nibble!!
 *	0x20	 LBA32 address (24-bits) + (8-bit) high nibble (implied)
 *
*/
#define DEV_MASK_EXP	0x80+MAX_BIOS_DEVICES-1
#define DEV_MASK	(DEV_MASK_EXP)

#define	EX_OFF		SETUP_STACKSIZE-8+SSDIFF /* external parameter block */
#define EX_DL_MAG	0xfe	/* magic number in DL */
#define EX_MAG_L	0x494c	/* magic number at ES:SI, "LI" */
#define EX_MAG_H	0x4f4c	/* magic number at ES:SI+2, "LO" */
#define EX_MAG_HL	0x4f4c494c  /* "LILO" */
#define EX_MAG_STRING	"LILO"	/* magic signature string as as string */

#define BIOS_MAX_DEVS	2	/* BIOS devices (2 fd, 2 hd) */
#define BIOS_MAX_HEADS  256	/* 8 bits head number; really 255 */
			/* but must account for oddball BIOS's that allow 256 */
#define BIOS_MAX_CYLS   1024	/* 10 bits cylinder number */
#define BIOS_MAX_SECS   64	/* 6 bits sector number (really 63) */

/* these are the boot record flags in the "prompt" variable */
#define FLAG_PROMPT	1	/* always issue boot: prompt */
#define FLAG_RAID	2	/* one boot record of many */
#define FLAG_RAID_DEFEAT  4	/* defeat finding this RAID boot record */
#if 0
#define FLAG_RAID_NOWRITE 8	/* defeat RAID writeback of command line */
#endif
#define FLAG_NOBD	16	/* defeat BIOS data collection at boot time */
#define FLAG_LARGEMEM	32	/* BIOS has MoveExtMemBlk support for 386 */
#define FLAG_MAP_ON_BOOT 64	/* map file is on the boot device */
#define FLAG_BD_OKAY	128	/* BIOS data collection known to work */
#ifdef FLAG_RAID_NOWRITE
#define FLAG_SAVE (~(FLAG_RAID|FLAG_RAID_DEFEAT|FLAG_RAID_NOWRITE))  /* All but raid flags */
#else
#define FLAG_SAVE (~(FLAG_RAID|FLAG_RAID_DEFEAT))  /* All but raid flags */
#endif

/* these are the second-stage specific flags */
#define FLAG2_EL_TORITO  2	/* El Torito format bootable CD */
#define FLAG2_UNATTENDED 4	/* Unattended booting option */
#define FLAG2_VIRTUAL	 8	/* vmdefault, vmdisable, vmwarn used */
#define FLAG2_NOKBD	16	/* nokbdefault, nokbdisable used */

/* these are the descriptor flags */
#define FLAG_VGA	1	/* override VGA mode */
#define FLAG_RESTR	2	/* restrict additional parameters */
#define FLAG_LOCK	4	/* lock on target */
#define FLAG_MODKRN	8	/* modern kernel with high memory support */
#define FLAG_KERNEL	16	/* image is a kernel */
#define FLAG_TOOBIG	32	/* initrd so big, kernel may overwrite */
#define FLAG_FALLBACK	64	/* fallback command line exists */
#define FLAG_PASSWORD	128	/* this image requires a password */
#define FLAG_LOADHI	256	/* this kernel loads high (>=1Mb) */
#ifdef LCF_VIRTUAL
#define FLAG_VMDISABLE	512	/* unable to boot if virtual */
#define FLAG_VMWARN	1024	/* warn on virtual boot */
#define FLAG_VMDEFAULT	2048	/* this is the default vitual load */
#endif
#define FLAG_SINGLE	4096	/* single key activation */
#define FLAG_RETAIN	0x2000	/* retain BMP screen on boot */
#ifdef LCF_NOKEYBOARD
#define FLAG_NOKBDEFAULT 0x4000	/* this is the default with no keyboard */
#define FLAG_NOKBDISABLE 0x8000	/* unable to boot if no keyboard */
#endif

#define VGA_NOCOVR	0x8000	/* VGA setting not overridden on command line */

#define SER_DFL_PRM	0xa3	/* default serial parameters: 2400n8 */

#define DC_MAGIC	0xf4f2	/* magic number of default cmd. line sector */
#define DC_MGOFF	0x6b6d	/* magic number for disabled line */

#define MAX_MESSAGE	65535	/* maximum message length */
#define MAX_MENU_TITLE	37	/* maximum MENU title length */

#define NEW_HDR_SIG	"HdrS"	/* setup header signature */
#define NEW_HDR_VERSION	0x200	/* header version number */
#define NEW2_HDR_VERSION 0x202	/* new cmdline protocol */
#define NEW3_HDR_VERSION 0X203	/* defines CL_RAMDISK_MAX */
#define LOADER_VERSION	0x02	/* loader version, for SETUP_HDR.loader */
#define LFLAG_HIGH	1	/* SETUP_HDR.flags */
#define LFLAG_USE_HEAP	0x80

#define PRTMAP_SIZE	32	/* number of partition type mappings */
#define DRVMAP_SIZE	24	/* number of drive mappings */

#define CRC_POLY1 0x04c11db7
#define CRC_POLY2 0x23a55379
#define CRC_POLY3 0x049f21c7
#define CRC_POLY4 0x1c632927
#define CRC_POLY5 0xA3139383

#define PROBE_SIGNATURE	"LiLo"	/* signature placed in low memory */
#define PROBESEG 0x60		/* must be in first 4k page in memory */
#define EDD_LTH	    30		/* length of the EDD return structure (max) */
#define EDD_PACKET  01		/* packet calls are supported */
#define EDD_LOCK    02		/* removable media may be locked */
#define EDD_SUBSET  04		/* EDD call supported */



#ifdef LILO_ASM
BOOTSEG   = 0x07C0			! original address of boot-sector
PARTS_LOAD= 0x0600			! partition sector load address
PARTS_SCR = 0x0800			! ditto, for non-boot partitions
PART_TABLE= 0x07BE			! partition table

INITSEG   = DEF_INITSEG			! we move boot here - out of the way
SETUPSEG  = DEF_SETUPSEG		! setup starts here
SYSSEG    = DEF_SYSSEG			! system loaded at 0x10000 (65536).

MAX_DESCR_SECS_asm = MAX_DESCR_SECS	! **
MAX_DESCR_SECTORS_asm = MAX_DESCR_SECTORS ! **
MAX_IMAGE_NAME_asm = MAX_IMAGE_NAME	! **
MAX_PW_CRC_asm	= MAX_PW_CRC		! **
SECTOR_SIZE_asm = SECTOR_SIZE		! **
MAX_MENU_TITLE_asm = MAX_MENU_TITLE	! **
MAX_BIOS_DEVICES_asm = MAX_BIOS_DEVICES	! **
MAX_RAID_DEVICES_asm = MAX_RAID_DEVICES	! **
DEV_MASK_asm = DEV_MASK_EXP		! **


STACKSEG  = 0x9000	     ! MUST == INITSEG for kernel 2.0.36 (and others?)
SETUP_STACKSIZE = 2048		! stacksize for kernel setup.S

#else
#define BOOTSEG 0x07c0			/* for probe.c  */
#endif

#define FIRSTSEG BOOTSEG

#ifdef LILO_ASM

STACK	  = 2048		! amount of stack space to reserve
SSDIFF	= 0

BOOTSECT  = 0x200		! kernel bootsect.S

#define SETUP_STACK_DYN  PARMLINE
#define SLA_SIZE_DYN  SETUP_STACK_DYN-SETUP_STACKSIZE-BOOTSECT

KBBEG     = 0x41A			! beginning of keyboard buffer
KBEND	  = 0x41C			! end of keyboard buffer
KBLOW	  = 0x1e
KBHIGH	  = 0x3e

!
!  Memory layout
!
! 0x007BE-0x007FD    64 B    partition table
! 0x07C00-0x07DFF   0.5 kB   HD/FD boot load address
! 0x10000-0x8FFFF 512.0 kB   kernel (zImage)
! 0x90000-0x901FF   0.5 kB   kernel floppy boot sector (bootsect.S)
! 0x90200-0x967FF  25.5 kB   kernel setup code (setup.S) and heap
! 0x96800-0x969FF   0.5 kB   LILO stack
! 0x96A00-0x96BFF   0.5 kB   LILO first stage loader
! 0x96C00-0x985FF   6.5 kB   LILO second stage loader
! 0x98600-0x987FF   0.5 kB   file map load area
! 0x98800-0x98BFF     1 kB   descriptor table load area
! 0x98C00-0x98DFF   0.5 kB   default command line load area
! 0x98E00-0x98FFF   0.5 kB   keyboard translation table load area
! 0x99000-0x991FF   0.5 kB   parameter line construction area
! 0x99200-0x9FFFF  27.5 kB   Extended BIOS Data Area

! when LILO has loaded the kernel, and control is transfered to
! the kernel setup.S code at 0x9020:0000
!
! 0x007BE-0x007FD    64 B    partition table
! 0x07C00-0x07DFF   0.5 kB   HD/FD boot load address
! 0x10000-0x8FFFF 512.0 kB   kernel (zImage)
! 0x90000-0x901FF   0.5 kB   kernel floppy boot sector (bootsect.S)
! 0x90200-0x967FF  25.5 kB   kernel setup code (setup.S) and heap
! 0x96800-0x987FF   8.0 kB   additional heap space
! 0x98800-0x98FFF   2.0 kB   stack created for (setup.S)
! 0x99000-0x991FF   0.5 kB   parameter line for kernel
! 0x99200-0x9FFFF  27.5 kB   Extended BIOS Data Area

CL_MAGIC_ADDR	= 0x20			! command line magic number
CL_MAGIC	= 0xa33f		! very unusual command sequence
CL_OFFSET	= 0x22			! command line offset
CL_LENGTH	= COMMAND_LINE_SIZE	! maximum length = 256-1

! 0x90020-0x90021     2 by   command line magic number
! 0x90022-0x90023     2 by   command line offset

CL_HEADER_ID	= 0x202			! "HdrS"
CL_HDRS_VERSION	= 0x206			! 0x0201=old;  0x0202=new
NEW_VERSION	= NEW2_HDR_VERSION	! 0x0202 for new cmdline protocol
CL_POINTER	= 0x228			! new pointer is dword address
CL_RAMDISK_MAX	= CL_POINTER+4		! ramdisk_max; header version 0x0203


#endif

/* Bug fix needed for some S-ATA controllers with the Silicon Image
   3112 or 3114 chipsets.  Early versions of the SI BIOS do not properly
   update the low memory size in the BIOS Data Area at 40h:13h when
   they allocate space in the Extended BIOS Data Area (EBDA).
*/
#ifdef LCF_BUG_SI_EBDA
# define EBDA_EXTRA LCF_BUG_SI_EBDA
#else
# define EBDA_EXTRA 0
#endif


/* the following configuration variable are now  required
   don't compile without them ...
 */

#ifndef LCF_UNIFY
# define LCF_UNIFY
#endif
#ifndef LCF_BUILTIN
# define LCF_BUILTIN
#endif
#ifndef LCF_FIRST6
# define LCF_FIRST6
#endif

#endif

