#include <syscall.h>
#include <sys/socket.h>
#include <sys/socketcall.h>
#include <linux/linkage.h>

extern asmlinkage int socketcall(int, unsigned long *);

int
accept(int sockfd, const struct sockaddr *peer, socklen_t *paddrlen)
{
	unsigned long args[3];

	args[0] = sockfd;
	args[1] = (unsigned long)peer;
	args[2] = (unsigned long)paddrlen;
	return socketcall(SYS_ACCEPT, args);
}
