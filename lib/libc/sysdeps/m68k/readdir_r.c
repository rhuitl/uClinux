#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <sys/syscall.h>

#include "../dirstream.h"

/* readdir fills up the buffer with the readdir system call. it also
   gives a third parameter (currently ignored, but should be 1) that
   can with a future kernel be enhanced to be the number of entries to
   be gotten.

   Right now the readdir system call return the number of characters
   in the name - in the future it will probably return the number of
   entries gotten. No matter - right now we just check for positive:
   that will always work (as we know that it cannot be bigger than 1
   in the future: we just asked for one entry).  */
int
old_readdir_r (DIR *dir, struct dirent *entry,
	       struct dirent **ret)
{
  int result;
  int count = NUMENT;

  if (dir->dd_size <= dir->dd_nextloc)
    {
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
      if (result <= 0)
	{
	  result = -result;
	  *ret = NULL;
	  return result;
	}

      /* Right now the readdir system call return the number of
	 characters in the name - in the future it will probably
	 return the number of entries gotten.  No matter - right now
	 we just check for positive: */
#if 0
      dir->dd_size = result;
#else
      dir->dd_size = 1;
#endif

      dir->dd_nextloc = 0;
    }

  /* We copy the dirent entry to entry. */
  memcpy (entry, &dir->dd_buf[dir->dd_nextloc++], sizeof (struct dirent));
  *ret = entry;
  return 0;
}

#ifdef __ELF__
#pragma weak readdir_r = __libc_readdir_r
#endif

int
__libc_readdir_r (DIR *dir, struct dirent *entry, struct dirent **ret)
{
  int result;

  if (!dir || !entry || !ret || !*ret)
    return EBADF;

  /* Are we running an old kernel? */
  if (dir->dd_getdents == no_getdents)
    return old_readdir_r (dir, entry, ret);

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

	  if (result == ENOSYS)
	    {
	      dir->dd_getdents = no_getdents;
	      return old_readdir_r (dir, entry, ret);
	    }

	  *ret = NULL;
	  return result;
	}

      dir->dd_size = result;
      dir->dd_nextloc = 0;
    }

  /* We copy the dirent entry to entry. */
  memcpy (entry, (char *) dir->dd_buf + dir->dd_nextloc,
	  sizeof (struct dirent));
  *ret = entry;

  /* Am I right? H.J. */
  dir->dd_nextloc += entry->d_reclen;

  /* We have to save the next offset here. */
  dir->dd_nextoff = entry->d_off;

  return 0;
}
