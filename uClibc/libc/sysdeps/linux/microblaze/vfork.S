/*
 * libc/sysdeps/linux/microblaze/vfork.S -- `vfork' syscall for linux/microblaze
 *
 * Copyright (C) 2001  NEC Corporation
 * Copyright (C) 2001  Miles Bader <miles@gnu.org>
 * Copyright (C) 2003  John Williams <jwilliams@itee.uq.edu.au>
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */
/* 
 * Written by Miles Bader <miles@gnu.org>
 * Microblaze port by John Williams
 */

#define _ERRNO_H	1
#include <bits/errno.h>
#define _SYSCALL_H
#include <bits/sysnum.h>

#include <clinkage.h>

/* Clone the calling process, but without copying the whole address space.
   The calling process is suspended until the new process exits or is
   replaced by a call to `execve'.  Return -1 for errors, 0 to the new process,
   and the process ID of the new process to the old process.  */

.global C_SYMBOL_NAME(errno)

C_ENTRY (__vfork):
	addi	r12, r0, SYS_vfork
	brki	r14, 0x08;
	addi	r4, r3, 125		// minimum err value
	blti	r4, 1f			// is r3 < -125?
	bri	2f			// normal return
1:	sub 	r3, r3, r0		// r3 = -r3
	swi	r3, r0, C_SYMBOL_NAME(errno);
					// state restore etc
2:	rtsd	r15, 8			// error return
	nop
C_END(__vfork)
weak_alias(__vfork,vfork)
libc_hidden_weak(vfork)
