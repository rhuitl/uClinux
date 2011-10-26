#include <syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <unistd.h>

__pid_t wait(__WAIT_STATUS wait_stat)
{
	return wait4((-1) /* WAIT_ANY */, wait_stat, 0, NULL);
}
