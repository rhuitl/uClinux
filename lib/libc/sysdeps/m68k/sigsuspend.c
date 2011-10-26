#include <syscall.h>
#include <sys/signal.h>

#ifdef PTHREAD_KERNEL

#pragma weak machdep_sys_sigsuspend = __machdep_sys_sigsuspend

int
__machdep_sys_sigsuspend (const sigset_t *sigmask)
{
	int res;

	__asm__("movel %1,%/d0\n\t"
		"clrl  %/d1\n\t"
		"clrl  %/d2\n\t"
		"movel %2,%/d3\n\t"
		"trap  #0\n\t"
		"movel %/d0,%0"
		: "=g" (res)
		: "i" (SYS_sigsuspend), "g" (*sigmask)
		: "%d0", "%d1", "%d2", "%d3");
	return res;
}

#else /* PTHREAD_KERNEL */

#ifdef _POSIX_THREADS
#pragma weak sigsuspend
#endif

int
sigsuspend (const sigset_t *sigmask)
{
	int res;

	__asm__("movel %1,%/d0\n\t"
		"clrl  %/d1\n\t"
		"clrl  %/d2\n\t"
		"movel %2,%/d3\n\t"
		"trap  #0\n\t"
		"movel %/d0,%0"
		:"=g" (res)
		:"i" (SYS_sigsuspend), "g" (*sigmask)
		: "%d0", "%d1", "%d2", "%d3");
	if (res >= 0)
		return res;
	errno = -res;
	return -1;
}

#endif /* PTHREAD_KERNEL */
