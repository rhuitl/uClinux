/* vi: set sw=4 ts=4: */
/*
 * posix_fadvise() for ARM uClibc
 * http://www.opengroup.org/onlinepubs/009695399/functions/posix_fadvise.html
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */
#include <sys/syscall.h>
#include <fcntl.h>
#if defined __NR_arm_fadvise64_64
/* This is for the ARM version of fadvise64_64 which swaps the params
 *  * about to avoid having ABI compat issues
 *   */
#define __NR___syscall_arm_fadvise64_64 __NR_arm_fadvise64_64
int __libc_posix_fadvise(int fd, off_t offset, off_t len, int advise)
{
  INTERNAL_SYSCALL_DECL (err);
  int ret = INTERNAL_SYSCALL (arm_fadvise64_64, err, 6, fd, advise,
                              __LONG_LONG_PAIR ((long)(offset >> 32), (long)offset),
                              __LONG_LONG_PAIR ((long)(len >> 32), (long)len));

    if (INTERNAL_SYSCALL_ERROR_P (ret, err))
      return INTERNAL_SYSCALL_ERRNO (ret, err);
    return 0;

}
weak_alias(__libc_posix_fadvise, posix_fadvise);
#else
int posix_fadvise(int fd attribute_unused, off_t offset attribute_unused, off_t len attribute_unused, int advice attribute_unused)
{
        __set_errno(ENOSYS);
        return -1;
}
#endif

