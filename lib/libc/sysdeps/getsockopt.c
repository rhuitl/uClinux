#include <syscall.h>
#include <sys/socket.h>
#include <sys/socketcall.h>
#include <linux/linkage.h>

extern asmlinkage int socketcall(int, unsigned long *);

int
getsockopt (int fd, int level, int optname, void *optval, socklen_t *optlen)
{
	unsigned long args[5];
	args[0]=fd;
	args[1]=level;
	args[2]=optname;
	args[3]=(unsigned long)optval;
	args[4]=(unsigned long)optlen;
	return (socketcall (SYS_GETSOCKOPT, args));
}
