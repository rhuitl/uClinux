#include <syscall.h>
#include <signal.h>
#include <errno.h>

extern void ___sig_restore();
extern void ___masksig_restore();

#ifdef PTHREAD_KERNEL

#pragma weak machdep_sys_sigaction = __machdep_sys_sigaction

int
__machdep_sys_sigaction (int sig, struct sigaction *new, struct sigaction *old)
{
  if (new)
    {
      if (new->sa_flags & SA_NOMASK)
	new->sa_restorer = ___sig_restore;
      else
	new->sa_restorer = ___masksig_restore;
    }

  __asm__ ("movel %1,%/d0\n\t"
	   "movel %2,%/d1\n\t"
	   "movel %3,%/d2\n\t"
	   "movel %4,%/d3\n\t"
	   "trap  #0\n\t"
	   "movel %/d0,%0"
	   : "=g" (sig)
	   : "i" (SYS_sigaction), "g" (sig), "g" (new), "g" (old)
	   : "%d0", "%d1", "%d2", "%d3");
  return sig;
}

#else /* PTHREAD_KERNEL */

#ifdef _POSIX_THREADS
#pragma weak __sigaction
#endif

int
__sigaction(int sig,struct sigaction * new, struct sigaction * old)
{
	if (new) {
		if (new->sa_flags & SA_NOMASK)
			new->sa_restorer=___sig_restore;
		else
			new->sa_restorer=___masksig_restore;
	}

	__asm__("movel %1,%/d0\n\t"
		"movel %2,%/d1\n\t"
		"movel %3,%/d2\n\t"
		"movel %4,%/d3\n\t"
		"trap  #0\n\t"
		"movel %/d0,%0"
		: "=g" (sig)
		:"i" (SYS_sigaction), "g" (sig), "g" (new), "g" (old)
		: "%d0", "%d1", "%d2", "%d3");
	if (sig>=0)
		return 0;
	errno = -sig;
	return -1;
}

#include <gnu-stabs.h>
#ifdef weak_alias
weak_alias (__sigaction, sigaction);
#endif

#endif /* PTHREAD_KERNEL */
