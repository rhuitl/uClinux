#include <sys/socket.h>
#include <syscall.h>
#include <sys/socketcall.h>
#include <linux/linkage.h>

extern asmlinkage int socketcall(int, unsigned long *);

int
socket(int family, int type, int protocol)
{
	unsigned long args[3];

	args[0] = family;
	args[1] = type;
	args[2] = protocol;
	return socketcall(SYS_SOCKET, args);
}
