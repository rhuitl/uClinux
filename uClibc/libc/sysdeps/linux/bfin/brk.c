/*
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

libc_hidden_proto(brk)

/* This must be initialized data because commons can't have aliases.  */
void * __curbrk attribute_hidden = 0;

int brk (void *addr)
{
    void *newbrk;

	__asm__ __volatile__(
		"P0 = %2;\n\t"
		"R0 = %1;\n\t"
		"excpt 0;\n\t"
		"%0 = R0;\n\t"
		: "=r"(newbrk)
		: "r"(addr), "i" (__NR_brk): "P0" );

    __curbrk = newbrk;

    if (newbrk < addr)
    {
	__set_errno (ENOMEM);
	return -1;
    }

    return 0;
}
libc_hidden_def(brk)
