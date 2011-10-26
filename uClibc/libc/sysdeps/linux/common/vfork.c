/*
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

/* Trivial implementation for arches that lack vfork */
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>

#ifdef __ARCH_USE_MMU__

#ifdef __NR_fork
libc_hidden_proto(fork)

extern __typeof(vfork) __vfork attribute_hidden;
pid_t __vfork(void)
{
    return fork();
}
libc_hidden_proto(vfork)
weak_alias(__vfork,vfork)
libc_hidden_weak(vfork)
#endif

#endif
