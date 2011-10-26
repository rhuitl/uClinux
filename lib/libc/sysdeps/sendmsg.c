#include <syscall.h>
#include <sys/socket.h>
#include <sys/socketcall.h>
#include <linux/linkage.h>

extern asmlinkage int socketcall(int, unsigned long *);

int
sendmsg (int sockfd, const struct msghdr *msg, unsigned flags)
{
  unsigned long args[3];
  args[0] = sockfd;
  args[1] = (unsigned long) msg;
  args[2] = flags;
  return (socketcall (SYS_SENDMSG, args));
}
