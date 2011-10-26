#include <unistd.h>
#include <syscall.h>
#include <errno.h>
#include <linux/linkage.h>

extern asmlinkage _llseek(int, off_t, off_t, loff_t *, int);

loff_t llseek (int fd, loff_t offset, int whence)
{
  int ret;
  loff_t result;

  ret = _llseek (fd, (off_t) (offset >> 32),
	(off_t) (offset & 0xffffffff), &result, whence);

  return ret ? (loff_t) ret : result;
}
