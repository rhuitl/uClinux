#include <syscall.h>
#include <sys/msg.h>

int
msgsnd ( int msqid, const struct msgbuf *msgp, size_t msgsz, int msgflg )
{
  return ipc( MSGSND, msqid, msgsz, msgflg, (void*)msgp );
}
