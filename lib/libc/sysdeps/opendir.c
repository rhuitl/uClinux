#include <sys/dirent.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#undef _POSIX_PTHREADS
#include <syscall.h>
#include <errno.h>

#include "dirstream.h"

#undef stat

/*
 * opendir just makes an open() call - it return NULL if it fails
 * (open sets errno), otherwise it returns a DIR * pointer.
 */
DIR *
opendir(const char * name)
{
  int fd;
  struct stat statbuf;
  struct dirent *buf;
  DIR *ptr;

  if (stat(name,&statbuf)) return NULL;
  if (!S_ISDIR(statbuf.st_mode)) {
    errno = ENOTDIR;
    return NULL;
  }
  if ((fd = open(name,O_RDONLY)) < 0)
    return NULL;
  /* According to POSIX, directory streams should be closed when
   * exec. From "Anna Pluzhnikov" <besp@midway.uchicago.edu>.
   */
  if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
    return NULL;
  if (!(ptr=malloc(sizeof(*ptr)))) {
    close(fd);
    errno = ENOMEM;
    return NULL;
  }

  ptr->dd_max = statbuf.st_blksize;
  if (ptr->dd_max < 512)
      ptr->dd_max = 512;

  if (!(buf=malloc(ptr->dd_max))) {
    close(fd);
    free(ptr);
    errno = ENOMEM;
    return NULL;
  }
  ptr->dd_fd = fd;
  ptr->dd_nextoff = ptr->dd_nextloc = ptr->dd_size = 0;
  ptr->dd_buf = buf;
  ptr->dd_getdents = unknown;
  return ptr;
}
