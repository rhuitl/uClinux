
#include <unistd.h>
#include <syscall.h>

int
setpgrp(void)
{
	return setpgid(0,0);
}
