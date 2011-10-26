#include <syscall.h>
#include <errno.h>
#include <sys/stat.h>
#include <asm/stat.h>

static inline
_syscall2(int,prev_stat,const char *,path, struct stat *,statbuf)

int
_xstat(int version, const char * path, struct stat * statbuf)
{
  int result;
  struct new_stat kbuf;
  struct stat *buf = (struct stat *) statbuf;

  switch(version)
  {
  case 1:
    result = prev_stat (path, statbuf);
    break;

#if 0
  case LINUX_STAT_VERSION:
    result = oldstat (path, &kbuf);
    if (result == 0)
    {
      /* Convert to current kernel version of `struct stat'.  */
      buf->st_dev = kbuf.st_dev;
      buf->__pad1 = 0;
      buf->st_ino = kbuf.st_ino;
      buf->st_mode = kbuf.st_mode;
      buf->st_nlink = kbuf.st_nlink;
      buf->st_uid = kbuf.st_uid;
      buf->st_gid = kbuf.st_gid;
      buf->st_rdev = kbuf.st_rdev;
      buf->__pad2 = 0;
      buf->st_size = kbuf.st_size;
      buf->st_blksize = kbuf.st_blksize;
      buf->st_blocks = kbuf.st_blocks;
      buf->st_atime = kbuf.st_atime;
      buf->__unused1 = 0;
      buf->st_mtime = kbuf.st_mtime;
      buf->__unused2 = 0;
      buf->st_ctime = kbuf.st_ctime;
      buf->__unused3 = 0;
      buf->__unused4 = 0;
      buf->__unused5 = 0;
    }
    break;
#endif
  default:
    errno = EINVAL;
    result = -1;
    break;
  }

  return result;
}
