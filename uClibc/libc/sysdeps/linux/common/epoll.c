/* vi: set sw=4 ts=4: */
/*
 * epoll_create() / epoll_ctl() / epoll_wait() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <sys/epoll.h>

/*
 * epoll_create()
 */
#ifdef __NR_epoll_create
_syscall1(int, epoll_create, int, size);
#else
int epoll_create(int size)
{
    __set_errno(ENOSYS);
    return -1;
}
#endif

/*
 * epoll_ctl()
 */
#ifdef __NR_epoll_ctl
_syscall4(int,epoll_ctl, int, epfd, int, op, int, fd, struct epoll_event *, event);
#else
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	__set_errno(ENOSYS);
	return -1;
}
#endif

/*
 * epoll_wait()
 */
#ifdef __NR_epoll_wait
_syscall4(int, epoll_wait, int, epfd, struct epoll_event *, events, int, maxevents, int, timeout);
#else
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
	__set_errno(ENOSYS);
	return -1;
}
#endif
