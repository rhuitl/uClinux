/*
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#define __FORCE_GLIBC
#include <features.h>
#include <errno.h>
#include <syscall.h>
#include <sys/socket.h>

#ifdef __NR_socketcall
extern int __socketcall(int call, unsigned long *args) attribute_hidden;

/* Various socketcall numbers */
#define SYS_SOCKET      1
#define SYS_BIND        2
#define SYS_CONNECT     3
#define SYS_LISTEN      4
#define SYS_ACCEPT      5
#define SYS_GETSOCKNAME 6
#define SYS_GETPEERNAME 7
#define SYS_SOCKETPAIR  8
#define SYS_SEND        9
#define SYS_RECV        10
#define SYS_SENDTO      11
#define SYS_RECVFROM    12
#define SYS_SHUTDOWN    13
#define SYS_SETSOCKOPT  14
#define SYS_GETSOCKOPT  15
#define SYS_SENDMSG     16
#define SYS_RECVMSG     17
#endif


#ifdef L_accept
extern __typeof(accept) __libc_accept;
#ifdef __NR_accept
#define __NR___libc_accept  __NR_accept
_syscall3(int, __libc_accept, int, call, struct sockaddr *, addr, socklen_t *,addrlen);
#elif defined(__NR_socketcall)
int __libc_accept(int s, struct sockaddr *addr, socklen_t * addrlen)
{
	unsigned long args[3];

	args[0] = s;
	args[1] = (unsigned long) addr;
	args[2] = (unsigned long) addrlen;
	return __socketcall(SYS_ACCEPT, args);
}
#endif
libc_hidden_proto(accept)
weak_alias(__libc_accept,accept)
libc_hidden_weak(accept)
#endif

#ifdef L_bind
libc_hidden_proto(bind)
#ifdef __NR_bind
_syscall3(int, bind, int, sockfd, const struct sockaddr *, myaddr, socklen_t, addrlen);
#elif defined(__NR_socketcall)
int bind(int sockfd, const struct sockaddr *myaddr, socklen_t addrlen)
{
	unsigned long args[3];

	args[0] = sockfd;
	args[1] = (unsigned long) myaddr;
	args[2] = addrlen;
	return __socketcall(SYS_BIND, args);
}
#endif
libc_hidden_def(bind)
#endif

#ifdef L_connect
extern __typeof(connect) __libc_connect;
#ifdef __NR_connect
#define __NR___libc_connect __NR_connect
_syscall3(int, __libc_connect, int, sockfd, const struct sockaddr *, saddr, socklen_t, addrlen);
#elif defined(__NR_socketcall)
int __libc_connect(int sockfd, const struct sockaddr *saddr, socklen_t addrlen)
{
	unsigned long args[3];

	args[0] = sockfd;
	args[1] = (unsigned long) saddr;
	args[2] = addrlen;
	return __socketcall(SYS_CONNECT, args);
}
#endif
libc_hidden_proto(connect)
weak_alias(__libc_connect,connect)
libc_hidden_weak(connect)
#endif

#ifdef L_getpeername
#ifdef __NR_getpeername
_syscall3(int, getpeername, int, sockfd, struct sockaddr *, addr, socklen_t *,paddrlen);
#elif defined(__NR_socketcall)
int getpeername(int sockfd, struct sockaddr *addr, socklen_t * paddrlen)
{
	unsigned long args[3];

	args[0] = sockfd;
	args[1] = (unsigned long) addr;
	args[2] = (unsigned long) paddrlen;
	return __socketcall(SYS_GETPEERNAME, args);
}
#endif
#endif

#ifdef L_getsockname
libc_hidden_proto(getsockname)
#ifdef __NR_getsockname
_syscall3(int, getsockname, int, sockfd, struct sockaddr *, addr, socklen_t *,paddrlen);
#elif defined(__NR_socketcall)
int getsockname(int sockfd, struct sockaddr *addr, socklen_t * paddrlen)
{
	unsigned long args[3];

	args[0] = sockfd;
	args[1] = (unsigned long) addr;
	args[2] = (unsigned long) paddrlen;
	return __socketcall(SYS_GETSOCKNAME, args);
}
#endif
libc_hidden_def(getsockname)
#endif

#ifdef L_getsockopt
#ifdef __NR_getsockopt
_syscall5(int, getsockopt, int, fd, int, level, int, optname, __ptr_t, optval, socklen_t *, optlen);
#elif defined(__NR_socketcall)
int getsockopt(int fd, int level, int optname, __ptr_t optval,
		   socklen_t * optlen)
{
	unsigned long args[5];

	args[0] = fd;
	args[1] = level;
	args[2] = optname;
	args[3] = (unsigned long) optval;
	args[4] = (unsigned long) optlen;
	return (__socketcall(SYS_GETSOCKOPT, args));
}
#endif
#endif

#ifdef L_listen
libc_hidden_proto(listen)
#ifdef __NR_listen
_syscall2(int, listen, int, sockfd, int, backlog);
#elif defined(__NR_socketcall)
int listen(int sockfd, int backlog)
{
	unsigned long args[2];

	args[0] = sockfd;
	args[1] = backlog;
	return __socketcall(SYS_LISTEN, args);
}
#endif
libc_hidden_def(listen)
#endif

#ifdef L_recv
extern __typeof(recv) __libc_recv;
#ifdef __NR_recv
#define __NR___libc_recv __NR_recv
_syscall4(ssize_t, __libc_recv, int, sockfd, __ptr_t, buffer, size_t, len, int, flags);
#elif defined(__NR_socketcall)
/* recv, recvfrom added by bir7@leland.stanford.edu */
ssize_t __libc_recv(int sockfd, __ptr_t buffer, size_t len, int flags)
{
	unsigned long args[4];

	args[0] = sockfd;
	args[1] = (unsigned long) buffer;
	args[2] = len;
	args[3] = flags;
	return (__socketcall(SYS_RECV, args));
}
#elif defined(__NR_recvfrom)
libc_hidden_proto(recvfrom)
ssize_t __libc_recv(int sockfd, __ptr_t buffer, size_t len, int flags)
{
	return (recvfrom(sockfd, buffer, len, flags, NULL, NULL));
}
#endif
libc_hidden_proto(recv)
weak_alias(__libc_recv,recv)
libc_hidden_weak(recv)
#endif

#ifdef L_recvfrom
extern __typeof(recvfrom) __libc_recvfrom;
#ifdef __NR_recvfrom
#define __NR___libc_recvfrom __NR_recvfrom
_syscall6(ssize_t, __libc_recvfrom, int, sockfd, __ptr_t, buffer, size_t, len, int, flags, 
	struct sockaddr *, to, socklen_t *, tolen);
#elif defined(__NR_socketcall)
/* recv, recvfrom added by bir7@leland.stanford.edu */
ssize_t __libc_recvfrom(int sockfd, __ptr_t buffer, size_t len, int flags,
		 struct sockaddr *to, socklen_t * tolen)
{
	unsigned long args[6];

	args[0] = sockfd;
	args[1] = (unsigned long) buffer;
	args[2] = len;
	args[3] = flags;
	args[4] = (unsigned long) to;
	args[5] = (unsigned long) tolen;
	return (__socketcall(SYS_RECVFROM, args));
}
#endif
libc_hidden_proto(recvfrom)
weak_alias(__libc_recvfrom,recvfrom)
libc_hidden_weak(recvfrom)
#endif

#ifdef L_recvmsg
extern __typeof(recvmsg) __libc_recvmsg;
#ifdef __NR_recvmsg
#define __NR___libc_recvmsg __NR_recvmsg
_syscall3(ssize_t, __libc_recvmsg, int, sockfd, struct msghdr *, msg, int, flags);
#elif defined(__NR_socketcall)
ssize_t __libc_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	unsigned long args[3];

	args[0] = sockfd;
	args[1] = (unsigned long) msg;
	args[2] = flags;
	return (__socketcall(SYS_RECVMSG, args));
}
#endif
libc_hidden_proto(recvmsg)
weak_alias(__libc_recvmsg,recvmsg)
libc_hidden_weak(recvmsg)
#endif

#ifdef L_send
extern __typeof(send) __libc_send;
#ifdef __NR_send
#define __NR___libc_send    __NR_send
_syscall4(ssize_t, __libc_send, int, sockfd, const void *, buffer, size_t, len, int, flags);
#elif defined(__NR_socketcall)
/* send, sendto added by bir7@leland.stanford.edu */
ssize_t __libc_send(int sockfd, const void *buffer, size_t len, int flags)
{
	unsigned long args[4];

	args[0] = sockfd;
	args[1] = (unsigned long) buffer;
	args[2] = len;
	args[3] = flags;
	return (__socketcall(SYS_SEND, args));
}
#elif defined(__NR_sendto)
libc_hidden_proto(sendto)
ssize_t __libc_send(int sockfd, const void *buffer, size_t len, int flags)
{
	return (sendto(sockfd, buffer, len, flags, NULL, 0));
}
#endif
libc_hidden_proto(send)
weak_alias(__libc_send,send)
libc_hidden_weak(send)
#endif

#ifdef L_sendmsg
extern __typeof(sendmsg) __libc_sendmsg;
#ifdef __NR_sendmsg
#define __NR___libc_sendmsg __NR_sendmsg
_syscall3(ssize_t, __libc_sendmsg, int, sockfd, const struct msghdr *, msg, int, flags);
#elif defined(__NR_socketcall)
ssize_t __libc_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
	unsigned long args[3];

	args[0] = sockfd;
	args[1] = (unsigned long) msg;
	args[2] = flags;
	return (__socketcall(SYS_SENDMSG, args));
}
#endif
libc_hidden_proto(sendmsg)
weak_alias(__libc_sendmsg,sendmsg)
libc_hidden_weak(sendmsg)
#endif

#ifdef L_sendto
extern __typeof(sendto) __libc_sendto;
#ifdef __NR_sendto
#define __NR___libc_sendto  __NR_sendto
_syscall6(ssize_t, __libc_sendto, int, sockfd, const void *, buffer, size_t, len, 
	int, flags, const struct sockaddr *, to, socklen_t, tolen);
#elif defined(__NR_socketcall)
/* send, sendto added by bir7@leland.stanford.edu */
ssize_t __libc_sendto(int sockfd, const void *buffer, size_t len, int flags,
	   const struct sockaddr *to, socklen_t tolen)
{
	unsigned long args[6];

	args[0] = sockfd;
	args[1] = (unsigned long) buffer;
	args[2] = len;
	args[3] = flags;
	args[4] = (unsigned long) to;
	args[5] = tolen;
	return (__socketcall(SYS_SENDTO, args));
}
#endif
libc_hidden_proto(sendto)
weak_alias(__libc_sendto,sendto)
libc_hidden_weak(sendto)
#endif

#ifdef L_setsockopt
libc_hidden_proto(setsockopt)
#ifdef __NR_setsockopt
_syscall5(int, setsockopt, int, fd, int, level, int, optname, const void *, optval, socklen_t, optlen);
#elif defined(__NR_socketcall)
/* [sg]etsockoptions by bir7@leland.stanford.edu */
int setsockopt(int fd, int level, int optname, const void *optval,
		   socklen_t optlen)
{
	unsigned long args[5];

	args[0] = fd;
	args[1] = level;
	args[2] = optname;
	args[3] = (unsigned long) optval;
	args[4] = optlen;
	return (__socketcall(SYS_SETSOCKOPT, args));
}
#endif
libc_hidden_def(setsockopt)
#endif

#ifdef L_shutdown
#ifdef __NR_shutdown
_syscall2(int, shutdown, int, sockfd, int, how);
#elif defined(__NR_socketcall)
/* shutdown by bir7@leland.stanford.edu */
int shutdown(int sockfd, int how)
{
	unsigned long args[2];

	args[0] = sockfd;
	args[1] = how;
	return (__socketcall(SYS_SHUTDOWN, args));
}
#endif
#endif

#ifdef L_socket
libc_hidden_proto(socket)
#ifdef __NR_socket
_syscall3(int, socket, int, family, int, type, int, protocol);
#elif defined(__NR_socketcall)
int socket(int family, int type, int protocol)
{
	unsigned long args[3];

	args[0] = family;
	args[1] = type;
	args[2] = (unsigned long) protocol;
	return __socketcall(SYS_SOCKET, args);
}
#endif
libc_hidden_def(socket)
#endif

#ifdef L_socketpair
#ifdef __NR_socketpair
_syscall4(int, socketpair, int, family, int, type, int, protocol, int *, sockvec);
#elif defined(__NR_socketcall)
int socketpair(int family, int type, int protocol, int sockvec[2])
{
	unsigned long args[4];

	args[0] = family;
	args[1] = type;
	args[2] = protocol;
	args[3] = (unsigned long) sockvec;
	return __socketcall(SYS_SOCKETPAIR, args);
}
#endif
#endif
