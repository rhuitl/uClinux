#include <syscall.h>
#include <sys/socket.h>
#include <sys/socketcall.h>
#include <linux/linkage.h>

extern asmlinkage int socketcall(int, unsigned long *);

/* send, sendto added by bir7@leland.stanford.edu */

int
sendto (int sockfd, const void *buffer, size_t len, unsigned flags,
	const struct sockaddr *to, socklen_t tolen)
{
  unsigned long args[6];
  args[0] = sockfd;
  args[1] = (unsigned long) buffer;
  args[2] = len;
  args[3] = flags;
  args[4] = (unsigned long) to;
  args[5] = tolen;
  return (socketcall (SYS_SENDTO, args));
}
