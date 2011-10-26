/* Copyright (C) 1995, 1996, 1997, 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#ifndef _SYS_IPC_H
#define _SYS_IPC_H	1

#include <features.h>
#include <sys/types.h>

/* Get system dependent definition of `struct ipc_perm' and more.  */
#include <bits/ipc.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < 0x020100

#ifndef key_t
typedef __key_t key_t;
# define key_t key_t
#endif

#endif

__BEGIN_DECLS

/* Generates key for System V style IPC.  */
extern key_t ftok __P ((__const char *__pathname, int __proj_id));

__END_DECLS

#endif /* sys/ipc.h */
