#include <syscall.h>
#include <sys/msg.h>

int
msgget ( key_t key, int msgflg )
{
  return ipc( MSGGET, key, msgflg, 0, 0 );
}
