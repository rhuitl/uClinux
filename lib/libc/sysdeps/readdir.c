#include <dirent.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <dirent.h>
#include <linux/types.h>
#include <linux/unistd.h>

#include "dirstream.h"

struct dirent *
readdir (DIR *dir)
{
  int result;
  struct dirent *de;

  if (!dir)
    {
      errno = EBADF;
      return NULL; 
    }

  if (dir->dd_size <= dir->dd_nextloc)
    {
      /* read dir->dd_max bytes of directory entries. */
      result = getdents(dir->dd_fd, dir->dd_buf, dir->dd_max);

      /* We must have getdents (). */
      dir->dd_getdents = have_getdents;
      if (result <= 0)
	return NULL;

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
