#include <syscall.h>
#include <sys/msg.h>

struct ipc_kludge
{
	void * msgp;
	long int msgtyp;
};

int
msgrcv ( int msqid, struct msgbuf *msgp, size_t msgsz, long int msgtyp, int msgflg )
{
	struct ipc_kludge tmp;
	tmp.msgp = msgp;
	tmp.msgtyp = msgtyp;
	
	return ipc( MSGRCV, msqid, (int)msgsz, msgflg, (void*)&tmp );
}
