#include <syscall.h>
#include <sys/socket.h>
#include <sys/socketcall.h>
#include <linux/linkage.h>

extern asmlinkage int socketcall(int, unsigned long *);

int
getpeername(int sockfd, struct sockaddr *addr, socklen_t *paddrlen)
{
	unsigned long args[3];

	args[0] = sockfd;
	args[1] = (unsigned long)addr;
	args[2] = (unsigned long)paddrlen;
	return socketcall(SYS_GETPEERNAME, args);
}
