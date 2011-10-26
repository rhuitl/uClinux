#include <syscall.h>
#include <sys/socket.h>
#include <sys/socketcall.h>
#include <linux/linkage.h>

extern asmlinkage int socketcall(int, unsigned long *);

/* shutdown by bir7@leland.stanford.edu */

int
shutdown (int sockfd, int how)
{
  unsigned long args[2];
  args[0] = sockfd;
  args[1] = how;
  return (socketcall (SYS_SHUTDOWN, args));
}
