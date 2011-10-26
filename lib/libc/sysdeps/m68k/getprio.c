#include <errno.h>
#include <sys/resource.h>
#include <sys/syscall.h>

#define PZERO	15

int
getpriority(int which, int who)
{
	register long res asm ("%d0") = SYS_getpriority;

	__asm__ volatile ("movel %2,%/d1\n\t"
			  "movel %3,%/d2\n\t"
			  "trap  #0\n\t"
		:"=g" (res)
		:"0" (SYS_getpriority), "g" (which), "g" (who)
		: "%d0", "%d1", "%d2");
	if (res >= 0) {
		errno = 0;
		return (int) PZERO - res;
	}
	errno = -res;
	return -1;
}
