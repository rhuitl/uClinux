/* Copyright (C) 2006 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@redhat.com>, 2006.

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

#include <sys/syscall.h>
#include <sys/poll.h>

#ifdef __NR_ppoll

libc_hidden_proto(ppoll)

# define __NR___libc_ppoll __NR_ppoll
static inline
_syscall4(int, __libc_ppoll, struct pollfd *, fds,
	nfds_t, nfds, const struct timespec *, timeout,
	const __sigset_t *, sigmask);

int
ppoll (struct pollfd *fds, nfds_t nfds, const struct timespec *timeout,
       const __sigset_t *sigmask)
{
  /* The Linux kernel can in some situations update the timeout value.
     We do not want that so use a local variable.  */
  struct timespec tval;
  if (timeout != NULL)
    {
      tval = *timeout;
      timeout = &tval;
    }

  return __libc_ppoll(fds, nfds, timeout, sigmask);
}
libc_hidden_def(ppoll)

#endif
