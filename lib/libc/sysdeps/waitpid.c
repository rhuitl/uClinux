#include <syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <unistd.h>

__pid_t
waitpid(__pid_t pid, int *wait_stat, int options)
{
	return wait4(pid, (__WAIT_STATUS) wait_stat, options, NULL);
}
