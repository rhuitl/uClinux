/* Copyright (C) 1991,92,93,94,95,96,97,99 Free Software Foundation, Inc.
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
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <assert.h>

#include <sysdep.h>
#include <sys/syscall.h>
#include <dirstream.h>


/* Read a directory entry from DIRP.  */
struct dirent *
__readdir (DIR *dirp)
{
  struct dirent *dp;

//  __libc_lock_lock (dirp->lock);
  do
    {
      size_t reclen;

      if (dirp->dd_nextloc >= dirp->dd_size)
	  {
	  /* We've emptied out our buffer.  Refill it.  */

		  size_t maxread;
		  ssize_t bytes;
		  maxread = dirp->dd_max;


		  bytes = INLINE_SYSCALL(getdents, 3, dirp->dd_fd, dirp->dd_buf, maxread);
		  if (bytes <= 0)
		  {
			  dp = NULL;
			  break;
		  }
		  dirp->dd_getdents = have_getdents;

		  /* Reset the offset into the buffer.  */
		  dirp->dd_nextloc = 0;
                  dirp->dd_size = bytes;
	  }

      dp = (struct dirent *) (((char*)dirp->dd_buf) + dirp->dd_nextloc);

      reclen = dp->d_reclen;
      dirp->dd_nextloc += reclen;
      dirp->dd_nextoff = dp->d_off;

      /* Skip deleted files.  */
    } while (dp->d_ino == 0);

//  __libc_lock_unlock (dirp->lock);

  return dp;
}
weak_alias (__readdir, readdir)
