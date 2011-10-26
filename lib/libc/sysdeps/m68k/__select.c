#include <errno.h>
#include <sys/syscall.h>
#include <sys/time.h>

#ifdef PTHREAD_KERNEL

#pragma weak machdep_sys_select = __machdep_sys_select

int
__machdep_sys_select (int nd, fd_set *in, fd_set *out, fd_set *ex, 
		      struct timeval *tv)
{
  register long __res asm ("%d0");
  __asm__ volatile ("movel %2,%/d1\n\t"
		    "trap #0"
		    : "=g" (__res)
		    : "0" (SYS_select), "g" ((long) &nd)
		    : "%d0", "%d1");
  return (int) __res;
}

#else /* PTHREAD_KERNEL */

#ifdef _POSIX_THREADS
#pragma weak __select
#endif

int
__select(int nd, fd_set * in, fd_set * out, fd_set * ex,
	struct timeval * tv)
{
	long __res;
	register long d0 asm ("%d0");
	__asm__ volatile ("movel %2,%/d1\n\t"
			  "trap  #0\n\t"
		: "=g" (d0)
		: "0" (SYS_select),"g" ((long) &nd) : "%d0", "%d1");
	__res = d0;
	if (__res >= 0)
		return (int) __res;
	errno = -__res;
	return -1;
}

#include <gnu-stabs.h>
#ifdef weak_alias
weak_alias (__select, select);
#endif

#endif /* PTHREAD_KERNEL */
