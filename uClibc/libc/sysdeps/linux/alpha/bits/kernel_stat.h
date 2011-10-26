#ifndef _BITS_STAT_STRUCT_H
#define _BITS_STAT_STRUCT_H

#ifndef _LIBC
#error bits/kernel_stat.h is for internal uClibc use only!
#endif

/* This file provides whatever this particular arch's kernel thinks 
 * struct kernel_stat should look like...  It turns out each arch has a 
 * different opinion on the subject... */
struct kernel_stat {
	unsigned int	st_dev;
	unsigned int	st_ino;
	unsigned int	st_mode;
	unsigned int	st_nlink;
	unsigned int	st_uid;
	unsigned int	st_gid;
	unsigned int	st_rdev;
	long int		st_size;
	unsigned long	st_atime;
	unsigned long	st_mtime;
	unsigned long	st_ctime;
	unsigned int	st_blksize;
	int		st_blocks;
	unsigned int	st_flags;
	unsigned int	st_gen;
};

struct kernel_stat64 {
	unsigned long	st_dev;
	unsigned long	st_ino;
	unsigned long	st_rdev;
	long		st_size;
	unsigned long	st_blocks;

	unsigned int	st_mode;
	unsigned int	st_uid;
	unsigned int	st_gid;
	unsigned int	st_blksize;
	unsigned int	st_nlink;
	unsigned int	__pad0;

	unsigned long	st_atime;
	unsigned long	st_atimensec;
	unsigned long	st_mtime;
	unsigned long	st_mtimensec;
	unsigned long	st_ctime;
	unsigned long	st_ctimensec;
	long		__unused[3];
};

#endif	/*  _BITS_STAT_STRUCT_H */
