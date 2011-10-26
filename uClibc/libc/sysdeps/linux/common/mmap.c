/* vi: set sw=4 ts=4: */
/*
 * mmap() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>
#include <sys/mman.h>

#ifdef __NR_mmap

libc_hidden_proto(mmap)

#ifdef __UCLIBC_MMAP_HAS_6_ARGS__

_syscall6(void *, mmap, void *, start, size_t, length,
		int, prot, int, flags, int, fd, off_t, offset);

#else

# define __NR__mmap __NR_mmap
static inline _syscall1(__ptr_t, _mmap, unsigned long *, buffer);
__ptr_t mmap(__ptr_t addr, size_t len, int prot,
			 int flags, int fd, __off_t offset)
{
	unsigned long buffer[6];

	buffer[0] = (unsigned long) addr;
	buffer[1] = (unsigned long) len;
	buffer[2] = (unsigned long) prot;
	buffer[3] = (unsigned long) flags;
	buffer[4] = (unsigned long) fd;
	buffer[5] = (unsigned long) offset;
	return (__ptr_t) _mmap(buffer);
}

#endif

libc_hidden_def(mmap)
#endif
