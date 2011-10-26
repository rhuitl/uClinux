/* Copyright (C) 1991, 1992 Free Software Foundation, Inc.
This file is part of the GNU C Library.

The GNU C Library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

The GNU C Library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the, 1992 Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

/*
 *	POSIX Standard: 5.1.2 Directory Operations	<dirent.h>
 */

#ifndef	_DIRENT_H

#define	_DIRENT_H	1
#include <features.h>

__BEGIN_DECLS

#include <gnu/types.h>

#define	__need_size_t
#include <stddef.h>

#include <sys/types.h>
#include <limits.h>

struct dirent {
	unsigned long long	d_ino;
	long long		d_off;
	unsigned short		d_reclen;
	unsigned char		d_type;
	char			d_name[256];
};

#if defined(__USE_GNU)
#define	d_fileno	d_ino		/* glibc compatibility.  */
#if 0
#define	d_namlen	d_reclen	/* glibc compatibility.  */
#endif
#endif

#if defined(DIRENT_ILLEGAL_ACCESS) || \
	(defined(__SVR4_I386_ABI_L1__) && !defined(INTERNAL_LINUX_C_LIB))

/* Use it at your own risk. */
typedef struct DIR
{
  /* file descriptor */
  int dd_fd;

  /* offset of the next dir entry in buffer */
  off_t dd_loc;

  /* bytes of valid entries in buffer */
  size_t dd_size;

  /* -> directory buffer */
  struct dirent *dd_buf;
} DIR;

#else

/* The internal is hidden from the user. */
typedef struct DIR DIR;

#endif


/* Open a directory stream on NAME.
   Return a DIR stream on the directory, or NULL if it could not be opened.  */
extern DIR *opendir __P ((__const char *__name));

/* Close the directory stream DIRP.
   Return 0 if successful, -1 if not.  */
extern int closedir __P ((DIR * __dirp));

/* Read a directory entry from DIRP.
   Return a pointer to a `struct dirent' describing the entry,
   or NULL for EOF or error.  The storage returned may be overwritten
   by a later readdir call on the same DIR stream.  */
extern struct dirent *readdir __P ((DIR * __dirp));

/* Rewind DIRP to the beginning of the directory.  */
extern void rewinddir __P ((DIR * __dirp));

#if defined(__USE_BSD) || defined(__USE_MISC)

#ifndef	MAXNAMLEN
/* Get the definitions of the POSIX.1 limits.  */
#include <posix1_lim.h>

/* `MAXNAMLEN' is the BSD name for what POSIX calls `NAME_MAX'.  */
#ifdef	NAME_MAX
#define	MAXNAMLEN	NAME_MAX
#else
#define	MAXNAMLEN	255
#endif
#endif

#include <gnu/types.h>

/* File types for `d_type'.  */
enum
  {
    DT_UNKNOWN = 0,
# define DT_UNKNOWN	DT_UNKNOWN
    DT_FIFO = 1,
# define DT_FIFO	DT_FIFO
    DT_CHR = 2,
# define DT_CHR		DT_CHR
    DT_DIR = 4,
# define DT_DIR		DT_DIR
    DT_BLK = 6,
# define DT_BLK		DT_BLK
    DT_REG = 8,
# define DT_REG		DT_REG
    DT_LNK = 10,
# define DT_LNK		DT_LNK
    DT_SOCK = 12,
# define DT_SOCK	DT_SOCK
    DT_WHT = 14
# define DT_WHT		DT_WHT
  };

/* Convert between stat structure types and directory types.  */
# define IFTODT(mode)	(((mode) & 0170000) >> 12)
# define DTTOIF(dirtype)	((dirtype) << 12)

/* Seek to position POS on DIRP.  */
extern void seekdir __P ((DIR * __dirp, __off_t __pos));

/* Return the current position of DIRP.  */
extern __off_t telldir __P ((DIR * __dirp));

typedef int (*__dir_select_fn_t) __P ((__const struct dirent *));

typedef int (*__dir_compar_fn_t) __P ((
		__const struct dirent * __const *,
		__const struct dirent * __const *
		));

/* Scan the directory DIR, calling SELECT on each directory entry.
   Entries for which SELECT returns nonzero are individually malloc'd,
   sorted using qsort with CMP, and collected in a malloc'd array in
   *NAMELIST.  Returns the number of entries selected, or -1 on error.  */
extern int scandir __P ((__const char *__dir,
			 struct dirent ***__namelist,
			 __dir_select_fn_t __dir_select_fn,
			 __dir_compar_fn_t __dir_compar_fn));

/* Function to compare two `struct dirent's alphabetically.  */
extern int alphasort __P ((
		__const struct dirent * __const *,
		__const struct dirent * __const *
		));


/* Read directory entries from FD into BUF, reading at most NBYTES.
   Reading starts at offset *BASEP, and *BASEP is updated with the new
   position after reading.  Returns the number of bytes read; zero when at
   end of directory; or -1 for errors.  */
extern __ssize_t __getdirentries __P ((int __fd, char *__buf,
				       size_t __nbytes, __off_t *__basep));
extern __ssize_t getdirentries __P ((int __fd, char *__buf,
				     size_t __nbytes, __off_t *__basep));

extern int dirfd __P ((DIR *__dirp));

#endif /* Use BSD or misc.  */

#if defined(_POSIX_THREAD_SAFE_FUNCTIONS) || defined(_REENTRANT)
extern int readdir_r __P((DIR *__dirp, struct dirent *__entry,
		struct dirent **__result));
#endif

__END_DECLS

#endif /* dirent.h  */
