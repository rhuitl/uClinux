#include <errno.h>
#include <sys/syscall.h>
#include <sys/time.h>

int
select(int nd, fd_set * in, fd_set * out, fd_set * ex,
	struct timeval * tv)
{
	long __res;
	__asm__ volatile ("movel %2, %%d1\n\t"
			  "movel %1, %%d0\n\t"
			  "trap	#0\n\t"
			  "movel %%d0, %0"
			: "=g" (__res)
			: "i" (SYS_select),"g" ((long) &nd)
			: "%d0", "%d1");
	if (__res >= 0)
		return (int) __res;
	errno = -__res;
	return -1;
}
