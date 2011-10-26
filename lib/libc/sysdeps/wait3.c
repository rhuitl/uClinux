#include <syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <unistd.h>

__pid_t wait3(__WAIT_STATUS wait_stat, int options, struct rusage *reserved)
{
	return wait4((-1) /* WAIT_ANY*/, wait_stat, options, reserved);
}
