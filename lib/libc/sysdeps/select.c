#include <errno.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <linux/linkage.h>

extern asmlinkage _select(unsigned long);

int select(int nd, fd_set *in, fd_set *out, fd_set*ex, struct timeval *tv) {
	unsigned long args[5];
	
	args[0] = (unsigned long)nd;
	args[1] = (unsigned long)in;
	args[2] = (unsigned long)out;
	args[3] = (unsigned long)ex;
	args[4] = (unsigned long)tv;
	return _select(args);
}
