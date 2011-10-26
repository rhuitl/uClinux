/* vi: set sw=4 ts=4: */
/*
 * ioctl() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <stdarg.h>
#include <sys/ioctl.h>

libc_hidden_proto(ioctl)

#define __NR___syscall_ioctl __NR_ioctl
static inline
_syscall3(int, __syscall_ioctl, int, fd, int, request, void *, arg);

int ioctl(int fd, unsigned long int request, ...)
{
    void *arg;
    va_list list;

    va_start(list, request);
    arg = va_arg(list, void *);
    va_end(list);

    return __syscall_ioctl(fd, request, arg);
}
libc_hidden_def(ioctl)
