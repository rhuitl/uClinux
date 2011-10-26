#include <unistd.h>
#include <sys/syscall.h>

#ifdef PTHREAD_KERNEL
#pragma weak machdep_sys__exit = __machdep_sys__exit

void
__machdep_sys__exit(int exit_code)
#else /* PTHREAD_KERNEL */

#ifdef _POSIX_THREADS
#pragma weak _exit
#endif

void
_exit(int exit_code)
#endif /* PTHREAD_KERNEL */
{
  __asm__ volatile ("moveq %0,%/d0;movel %1,%/d1;trap #0"
                    ::"i" (SYS_exit),"g" (exit_code) : "%d0", "%d1");
}
