#include <syscall.h>
#include <sys/msg.h>

int
msgctl ( int msqid, int cmd, struct msqid_ds *buf )
{
  return ipc( MSGCTL, msqid, cmd, 0, buf );
}
