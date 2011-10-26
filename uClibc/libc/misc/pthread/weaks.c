/* The weak pthread functions for Linux.
   Copyright (C) 1996, 1997, 1998 Free Software Foundation, Inc.
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

#include <libc-internal.h>

/* Weaks for internal library use only.
 *
 * We need to define weaks here to cover all the pthread functions that
 * libc itself will use so that we aren't forced to link libc against
 * libpthread.  This file is only used in libc.a and since we have
 * weaks here, they will be automatically overridden by libpthread.a
 * if it gets linked in.
 */

static int __pthread_return_0 (void) { return 0; }
static void __pthread_return_void (void) { return; }

weak_alias (__pthread_return_0, __pthread_mutex_init)
weak_alias (__pthread_return_0, __pthread_mutex_lock)
weak_alias (__pthread_return_0, __pthread_mutex_trylock)
weak_alias (__pthread_return_0, __pthread_mutex_unlock)
weak_alias (__pthread_return_void, _pthread_cleanup_push_defer)
weak_alias (__pthread_return_void, _pthread_cleanup_pop_restore)
#ifdef __UCLIBC_HAS_THREADS_NATIVE__
weak_alias (__pthread_return_0, __pthread_mutexattr_init)
weak_alias (__pthread_return_0, __pthread_mutexattr_destroy)
weak_alias (__pthread_return_0, __pthread_mutexattr_settype)
#endif
