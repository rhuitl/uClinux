/* vi: set sw=4 ts=4: */
/*
 * llseek/lseek64 syscall for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>

extern __typeof(lseek64) __libc_lseek64;

#if defined __NR__llseek && defined __UCLIBC_HAS_LFS__

# ifndef INLINE_SYSCALL
#  define INLINE_SYSCALL(name, nr, args...) __syscall_llseek (args)
#  define __NR___syscall_llseek __NR__llseek
static inline _syscall5(int, __syscall_llseek, int, fd, off_t, offset_hi, 
		off_t, offset_lo, loff_t *, result, int, whence);
# endif

loff_t __libc_lseek64(int fd, loff_t offset, int whence)
{
	loff_t result;
	return(loff_t)(INLINE_SYSCALL (_llseek, 5, fd, (off_t) (offset >> 32), 
				(off_t) (offset & 0xffffffff), &result, whence) ?: result);
}
#else
extern __typeof(lseek) __libc_lseek;
libc_hidden_proto(__libc_lseek)

loff_t __libc_lseek64(int fd, loff_t offset, int whence)
{
	return(loff_t)(__libc_lseek(fd, (off_t) (offset), whence));
}
#endif
libc_hidden_proto(lseek64)
weak_alias(__libc_lseek64,lseek64)
libc_hidden_weak(lseek64)
//strong_alias(__libc_lseek64,_llseek)
