#ifndef _MNTENT_H
#define _MNTENT_H

#include <features.h>

#define MNTTAB "/etc/fstab"
#define MOUNTED "/etc/mtab"

#define MNTMAXSTR	512

#define MNTTYPE_COHERENT	"coherent"	/* Coherent file system */
#define MNTTYPE_EXT		"ext"		/* Extended file system */
#define MNTTYPE_EXT2		"ext2"		/* Second Extended file system */
#define MNTTYPE_HPFS		"hpfs"		/* OS/2's high performance file system */
#define MNTTYPE_ISO9660		"iso9660"	/* ISO CDROM file system */
#define MNTTYPE_MINIX		"minix"		/* MINIX file system */
#define MNTTYPE_MSDOS		"msdos"		/* MS-DOS file system */
#define	MNTTYPE_VFAT		"vfat"		/* VFAT (Win95) file system */
#define MNTTYPE_SYSV		"sysv"		/* System V file system */
#define MNTTYPE_UMSDOS		"umsdos"	/* U MS-DOS file system */
#define MNTTYPE_XENIX		"xenix"		/* Xenix file system */
#define MNTTYPE_XIAFS		"xiafs"		/* Frank Xia's file system */
#define MNTTYPE_NFS		"nfs"		/* Network file system */
#define MNTTYPE_PROC		"proc"		/* Linux process file system */
#define MNTTYPE_IGNORE		"ignore"	/* Ignore this entry */
#define MNTTYPE_SWAP		"swap"		/* Swap device */

/* generic mount options */
#define MNTOPT_DEFAULTS		"defaults"	/* use all default opts */
#define MNTOPT_RO		"ro"		/* read only */
#define MNTOPT_RW		"rw"		/* read/write */
#define MNTOPT_SUID		"suid"		/* set uid allowed */
#define MNTOPT_NOSUID		"nosuid"	/* no set uid allowed */
#define MNTOPT_NOAUTO		"noauto"	/* don't auto mount */

/* ext2 and msdos options */
#define	MNTOPT_CHECK		"check"		/* filesystem check level */

/* ext2 specific options */
#define	MNTOPT_BSDDF		"bsddf"		/* disable MINIX compatibility disk free counting */
#define	MNTOPT_BSDGROUPS	"bsdgroups"	/* set BSD group usage */
#define	MNTOPT_ERRORS		"errors"	/* set behaviour on error */
#define	MNTOPT_GRPID		"grpid"		/* set BSD group usage */
#define	MNTOPT_MINIXDF		"minixdf"	/* enable MINIX compatibility disk free counting */
#define	MNTOPT_NOCHECK		"nocheck"	/* reset filesystem checks */
#define	MNTOPT_NOGRPID		"nogrpid"	/* set SYSV group usage */
#define	MNTOPT_RESGID		"resgid"	/* group to consider like root for reserved blocks */
#define	MNTOPT_RESUID		"resuid"	/* user to consider like root for reserved blocks */
#define	MNTOPT_SB		"sb"		/* set used super block */
#define	MNTOPT_SYSVGROUPS	"sysvgroups"	/* set SYSV group usage */

/* options common to hpfs, isofs, and msdos */
#define	MNTOPT_CONV		"conv"		/* convert specified types of data */
#define	MNTOPT_GID		"gid"		/* use given gid */
#define	MNTOPT_UID		"uid"		/* use given uid */
#define	MNTOPT_UMASK		"umask"		/* use given umask, not isofs */

/* hpfs specific options */
#define	MNTOPT_CASE		"case"		/* case conversation */

/* isofs specific options */
#define	MNTOPT_BLOCK		"block"		/* use given block size */
#define	MNTOPT_CRUFT		"cruft"		/* ??? */
#define	MNTOPT_MAP		"map"		/* ??? */
#define	MNTOPT_NOROCK		"norock"	/* not rockwell format ??? */

/* msdos specific options */
#define	MNTOPT_FAT		"fat"		/* set FAT size */
#define	MNTOPT_QUIET		"quiet"		/* ??? */

/* swap specific options */

/* options common to ext, ext2, minix, xiafs, sysv, xenix, coherent */
#define MNTOPT_NOQUOTA		"noquota"	/* don't use any quota on this partition */
#define MNTOPT_USRQUOTA		"usrquota"	/* use userquota on this partition */
#define MNTOPT_GRPQUOTA		"grpquota"	/* use groupquota on this partition */

/* none defined yet */

__BEGIN_DECLS

struct mntent{
	char *mnt_fsname;
	char *mnt_dir;
	char *mnt_type;
	char *mnt_opts;
	int  mnt_freq;
	int  mnt_passno;
};

__END_DECLS

#define __need_file
#include <stdio.h>

__BEGIN_DECLS

extern FILE	*setmntent __P ((__const char *__filep,
			__const char *__type));
extern struct mntent
		*getmntent __P ((FILE *__filep));
extern int	addmntent __P ((FILE *__filep,
			__const struct mntent *__mnt));
extern char	*hasmntopt __P ((__const struct mntent *__mnt,
			__const char *__opt));
extern int	endmntent __P ((FILE *__filep));

__END_DECLS

#endif /* _MNTENT_H */
