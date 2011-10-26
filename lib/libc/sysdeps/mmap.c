#define __CHECK_RETURN_ADDR
#include <syscall.h>
#include <sys/types.h>
#include <sys/mman.h>

__ptr_t
mmap(__ptr_t addr, size_t len, int prot, int flags, int fd, off_t off)
{
	unsigned long buffer[6];

	buffer[0] = (unsigned long)addr;
	buffer[1] = (unsigned long)len;
	buffer[2] = (unsigned long)prot;
	buffer[3] = (unsigned long)flags;
	buffer[4] = (unsigned long)fd;
	buffer[5] = (unsigned long)off;
	return (__ptr_t) _mmap(buffer);
}
