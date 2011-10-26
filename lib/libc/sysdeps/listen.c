#include <syscall.h>
#include <sys/socket.h>
#include <sys/socketcall.h>
#include <linux/linkage.h>

extern asmlinkage int socketcall(int, unsigned long *);

int
listen(int sockfd, int backlog)
{
	unsigned long args[2];

	args[0] = sockfd;
	args[1] = backlog;
	return socketcall(SYS_LISTEN, args);
}
