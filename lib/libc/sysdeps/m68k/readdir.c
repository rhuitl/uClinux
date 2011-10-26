#include <dirent.h>
#include <errno.h>
#include <sys/syscall.h>

#include "../dirstream.h"

/*
 * readdir fills up the buffer with the readdir system call. it also
 * gives a third parameter (currently ignored, but should be 1) that
 * can with a future kernel be enhanced to be the number of entries
 * to be gotten.
 *
 * Right now the readdir system call return the number of characters
 * in the name - in the future it will probably return the number of
 * entries gotten. No matter - right now we just check for positive:
 * that will always work (as we know that it cannot be bigger than 1
 * in the future: we just asked for one entry).
 */
static struct dirent *
old_readdir (DIR *dir)
{
  int result;
  int count = NUMENT;

  if (dir->dd_size <= dir->dd_nextloc) {
    /* read count of directory entries. For now it should be one. */
    __asm__ ("movel %2,%/d1\n\t"
	     "movel %3,%/d2\n\t"
	     "movel %4,%/d3\n\t"
	     "movel %1,%/d0\n\t"
	     "trap  #0\n\t"
	     "movel %/d0,%0"
	     : "=g" (result)
	     : "i" (SYS_readdir), "g" (dir->dd_fd), "g" (dir->dd_buf),
	       "g" (count)
	     : "%d0", "%d1", "%d2", "%d3" );
    if (result <= 0) {
      if (result < 0)
	errno = -result;
      return NULL;
    }

    /*
     * Right now the readdir system call return the number of
     * characters in the name - in the future it will probably return
     * the number of entries gotten. No matter - right now we just
     * check for positive:
     */
#if 0
    dir->dd_size = result;
#else
    dir->dd_size = 1;
#endif

    dir->dd_nextloc = 0;
  }

  return &(dir->dd_buf [(dir->dd_nextloc)++]);
}

#ifdef __ELF__
#pragma weak readdir = __libc_readdir
#endif

struct dirent *
__libc_readdir (DIR *dir)
{
  int result;
  struct dirent *de;

  if (!dir)
    {
      errno = EBADF;
      return NULL; 
    }

  /* Are we running an old kernel? */
  if (dir->dd_getdents == no_getdents)
    return old_readdir (dir);

  if (dir->dd_size <= dir->dd_nextloc)
    {
      /* read dir->dd_max bytes of directory entries. */
      __asm__ ("movel %2,%/d1\n\t"
	       "movel %3,%/d2\n\t"
	       "movel %4,%/d3\n\t"
	       "movel %1,%/d0\n\t"
	       "trap  #0\n\t"
	       "movel %/d0,%0"
	       : "=g" (result)
	       : "i" (SYS_getdents), "g" (dir->dd_fd), "g" (dir->dd_buf),
		 "g" (dir->dd_max)
	       : "%d0", "%d1", "%d2", "%d3");

      /* We assume we have getdents (). */
      dir->dd_getdents = have_getdents;
      if (result <= 0)
	{
	  result = -result;
	  if (result > 0)
	    {
	      /* Are we right? */
	      if (result == ENOSYS)
		{
		  dir->dd_getdents = no_getdents;
		  return old_readdir (dir);
		}
	      errno = result;
	    }

	  return NULL;
	}

      dir->dd_size = result;
      dir->dd_nextloc = 0;
    }

  de = (struct dirent *) ((char *) dir->dd_buf + dir->dd_nextloc);

  /* Am I right? H.J. */
  dir->dd_nextloc += de->d_reclen;

  /* We have to save the next offset here. */
  dir->dd_nextoff = de->d_off;

  return de;
}
