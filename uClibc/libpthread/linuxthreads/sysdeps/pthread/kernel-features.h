/* Set flags signalling availability of kernel features based on given
   kernel version number.
   Copyright (C) 1999-2003, 2004, 2005 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

/* This file must not contain any C code.  At least it must be protected
   to allow using the file also in assembler files.  */

#if defined __mips__
# include <sgidefs.h>
#endif

#include <linux/version.h>
#define __LINUX_KERNEL_VERSION	LINUX_VERSION_CODE

/* Real-time signal became usable in 2.1.70.  */
#if __LINUX_KERNEL_VERSION >= 131398
# define __ASSUME_REALTIME_SIGNALS	1
#endif

/* Beginning with 2.5.63 support for realtime and monotonic clocks and
   timers based on them is available.  */
#if __LINUX_KERNEL_VERSION >= 132415
# define __ASSUME_POSIX_TIMERS		1
#endif

/* On x86, the set_thread_area syscall was introduced in 2.5.29, but its
   semantics was changed in 2.5.30, and again after 2.5.31.  */
#if __LINUX_KERNEL_VERSION >= 132384 && defined __i386__
# define __ASSUME_SET_THREAD_AREA_SYSCALL	1
#endif

/* We can use the LDTs for threading with Linux 2.3.99 and newer.  */
#if __LINUX_KERNEL_VERSION >= 131939
# define __ASSUME_LDT_WORKS		1
#endif

/* Starting with 2.4.5 kernels PPC passes the AUXV in the standard way
   and the vfork syscall made it into the official kernel.  */
#if __LINUX_KERNEL_VERSION >= (132096+5) && defined __powerpc__
# define __ASSUME_STD_AUXV		1
# define __ASSUME_VFORK_SYSCALL		1
#endif

/* The vfork syscall on x86 and arm was definitely available in 2.4.  */
#if __LINUX_KERNEL_VERSION >= 132097 && (defined __i386__ || defined __arm__)
# define __ASSUME_VFORK_SYSCALL		1
#endif

/* These features were surely available with 2.4.12.  */
#if __LINUX_KERNEL_VERSION >= 132108 && defined __mc68000__
# define __ASSUME_MMAP2_SYSCALL		1
# define __ASSUME_TRUNCATE64_SYSCALL	1
# define __ASSUME_STAT64_SYSCALL	1
# define __ASSUME_FCNTL64		1
# define __ASSUME_VFORK_SYSCALL		1
#endif
