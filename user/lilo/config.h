/* config.h  -  Configurable parameters */
/*
Copyright 1992-1998 Werner Almesberger.
Copyright 1999-2006 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/


#ifndef CONFIG_H
#define CONFIG_H

/* undefine LCF_DEVMAPPER if the library is not present */
#ifdef LCF_DEVMAPPER
# ifndef HAS_LIBDEVMAPPER_H
#  undef LCF_DEVMAPPER
# endif
#endif

#if !__MSDOS__
#if !defined(__GLIBC__) || (__GLIBC__ < 2) || \
	 !defined(__GLIBC_MINOR__) || (__GLIBC_MINOR__ < 1)
# warning "glibc version 2.1 or later is recommended"
#endif /* !__MSDOS__ */

#define TMP_DEV     "/tmp/dev.%d" /* temporary devices are created here */
#define MAX_TMP_DEV 50 /* highest temp. device number */

#ifdef LCF_OLD_DIRSTR
#define LILO_DIR    "/etc/lilo" /* base directory for LILO files */
#define BACKUP_DIR  LILO_DIR /* boot sector and partition table backups */
#define DFL_CONFIG  LILO_DIR "/config" /* default configuration file */
#define DFL_DISKTAB LILO_DIR "/disktab" /* LILO's disk parameter table */
#define MAP_FILE    LILO_DIR "/map" /* default map file */
#define MAP_TMP_APP "~" /* temporary file appendix */
#define DFL_BOOT    LILO_DIR "/boot.b" /* default boot loader */
#define DFL_CHAIN   LILO_DIR "/chain.b" /* default chain loader */
#define DFL_MBR	    LILO_DIR "/mbr.b"	/* default MBR */
#else
#define CFG_DIR	    "/etc"		/* location of configuration files */
#define BOOT_DIR    "/boot"		/* location of boot files */
#define BACKUP_DIR  BOOT_DIR /* boot sector and partition table backups */
#define DFL_CONFIG  CFG_DIR "/lilo.conf"/* default configuration file */
#define DFL_DISKTAB CFG_DIR "/disktab"	/* LILO's disk parameter table */
#define MAP_FILE    BOOT_DIR "/map"	/* default map file */
#define MAP_TMP_APP "~"			/* temporary file appendix */
#define	DFL_BOOT    BOOT_DIR "/boot.b"	/* default boot loader */
#define DFL_CHAIN   BOOT_DIR "/chain.b"	/* default chain loader */
#define DFL_MBR	    BOOT_DIR "/mbr.b"	/* default MBR */
#define DFL_KEYTAB  BOOT_DIR "/us.ktl"	/* default keytable */
#endif

#define DEV_DIR	    	"/dev" 	/* devices directory (/dev/mem &c.) */
#define DEV_DISK_DIR  	DEV_DIR	/* disk devices are here */
                                /* alternate might be "/dev/disk" */

#else /* MSDOS */
#define CFG_DIR	    "C:\\ETC"		/* location of configuration files */
#define BOOT_DIR    "C:\\BOOT"		/* location of boot files */
#define BACKUP_DIR  BOOT_DIR /* boot sector and partition table backups */
#define DFL_CONFIG  CFG_DIR "\\LILO.CNF"/* default configuration file */
#define MAP_FILE    BOOT_DIR "\\MAP"	/* default map file */

#endif

#define MAX_LINE    1024 /* maximum disk parameter table line length */

#endif
