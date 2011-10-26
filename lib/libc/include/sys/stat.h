#ifndef _SYS_STAT_H
#define _SYS_STAT_H

#include <features.h>
#include <sys/types.h>
#undef __NOT_KERNEL
#define __NOT_KERNEL
#include <linux/stat.h>
#undef __NOT_KERNEL

#ifdef __SVR4_I386_ABI_L1__
#include <sys/time.h>		/* For timestruc_t */
#endif /* __SVR4_I386_ABI_L1__ */

__BEGIN_DECLS

struct stat {
	dev_t		st_dev;

#ifdef __SVR4_I386_ABI_L1__
	long st_pad1[3];
#else
	unsigned short __pad1;
#endif

	ino_t		st_ino;
	umode_t		st_mode;
	nlink_t		st_nlink;
	uid_t		st_uid;
	gid_t		st_gid;
	dev_t		st_rdev;

#ifdef __SVR4_I386_ABI_L1__
	long st_pad2[2];
#else
	unsigned short __pad2;
#endif

	off_t		st_size;

#ifdef __SVR4_I386_ABI_L1__
	timestruc_t	st_atim;
	timestruc_t	st_mtim;
	timestruc_t	st_ctim;
    	long		st_blksize;
    	long		st_blocks;

#define	FSTYPSZ		16

        char            st_fstype[FSTYPSZ];
        long		st_pad4[8];

#define st_atime	st_atim.tv_sec
#define st_mtime	st_mtim.tv_sec
#define st_ctime	st_ctim.tv_sec

#else /*! __SVR4_I386_ABI_L1__*/
	unsigned long	st_blksize;
	unsigned long	st_blocks;
	time_t		st_atime;
	unsigned long	__unused1;
	time_t		st_mtime;
	unsigned long	__unused2;
	time_t		st_ctime;
	unsigned long	__unused3;
	unsigned long	__unused4;
	unsigned long	__unused5;
#endif /*! __SVR4_I386_ABI_L1__*/
};


#define LINUX_MKNOD_VERSION 1     /* SVr4 */
#define LINUX_STAT_VERSION 1      /* SVr4 */

extern int _fxstat __P ((int __ver, int __fildes,
			struct stat *__stat_buf));

extern int _xstat __P ((int __ver, __const char *__filename,
			struct stat *__stat_buf));

extern int _lxstat __P ((int __ver, __const char *__filename,
			struct stat *__stat_buf));

#ifdef _MIT_POSIX_THREADS
extern int __machdep_sys__fxstat __P ((int __ver, int __fd,
			struct stat *__stat_buf));
#endif

extern int _xmknod __P ((int __ver, __const char *__path,
			mode_t __mode, dev_t *__dev));

/* Some synonyms used historically in the kernel and elsewhere */
#define S_IREAD		S_IRUSR /* read permission, owner */
#define S_IWRITE	S_IWUSR /* write permission, owner */
#define S_IEXEC		S_IXUSR /* execute/search permission, owner */

extern int	__chmod __P ((__const char *__path, mode_t __mode));
extern int	chmod __P ((__const char *__path, mode_t __mode));

extern int	__fchmod __P ((int __fildes, mode_t __mode));
extern int	fchmod __P ((int __fildes, mode_t __mode));

extern int	__mkdir __P ((__const char *__path, mode_t __mode));
extern int	mkdir __P ((__const char *__path, mode_t __mode));

extern int	mkfifo __P ((__const char *__path, mode_t __mode));

#if 1

extern int	__fstat __P ((int __fildes, struct stat *__stat_buf));
extern int	fstat __P ((int __fildes, struct stat *__stat_buf));

extern int	__stat __P ((__const char *__filename,
			struct stat *__stat_buf));
extern int	stat __P ((__const char *__filename,
			struct stat *__stat_buf));

extern int	__lstat __P ((__const char *__filename,
			struct stat *__stat_buf));
extern int	lstat __P ((__const char *__filename,
			struct stat *__stat_buf));

extern int	__mknod __P ((__const char *__path, mode_t __mode,
			dev_t __dev));
extern int	mknod __P ((__const char *__path, mode_t __mode,
			dev_t __dev));
#endif		/* #if 0 */

extern mode_t	__umask __P ((mode_t __mask));
extern mode_t	umask __P ((mode_t __mask));

__END_DECLS

#if 0

static __inline__ int __stat(__const char * __path, struct stat * __statbuf)
{
  return _xstat(LINUX_STAT_VERSION, __path, __statbuf);
}

static __inline__ int stat(__const char * __path, struct stat * __statbuf)
{
  return _xstat(LINUX_STAT_VERSION, __path, __statbuf);
}

static __inline__ int __lstat(__const char * __path, struct stat * __statbuf)
{
  return _lxstat(LINUX_STAT_VERSION, __path, __statbuf);
}

static __inline__ int lstat(__const char * __path, struct stat * __statbuf)
{
  return _lxstat(LINUX_STAT_VERSION, __path, __statbuf);
}

static __inline__ int __fstat(int __fd, struct stat * __statbuf)
{
  return _fxstat(LINUX_STAT_VERSION, __fd, __statbuf);
}

static __inline__ int fstat(int __fd, struct stat * __statbuf)
{
  return _fxstat(LINUX_STAT_VERSION, __fd, __statbuf);
}

static __inline__ int __mknod(__const char * __path, mode_t __mode, dev_t __dev)
{
  return _xmknod(LINUX_MKNOD_VERSION, __path, __mode, &__dev);
}

static __inline__ int mknod(__const char * __path, mode_t __mode, dev_t __dev)
{
  return _xmknod(LINUX_MKNOD_VERSION, __path, __mode, &__dev);
}

#ifdef _MIT_POSIX_THREADS

static __inline__ int __machdep_sys_fstat(int __fd, struct stat * __statbuf)
{
  return __machdep_sys__fxstat(LINUX_STAT_VERSION, __fd, __statbuf);
}

static __inline__ int machdep_sys_fstat(int __fd, struct stat * __statbuf)
{
  return __machdep_sys__fxstat(LINUX_STAT_VERSION, __fd, __statbuf);
}

#endif

#endif

#endif
