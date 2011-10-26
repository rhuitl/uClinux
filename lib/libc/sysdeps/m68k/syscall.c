/* syscall.c - generalized linux system call interface - rick sladkey */

#include <stdarg.h>
#include <syscall.h>
#include <errno.h>

#ifdef PTHREAD_KERNEL

#pragma weak machdep_syscall = __machdep_syscall

int
__machdep_syscall (int number, ...)
{
  register long res asm ("%d0");
  register long d1 asm ("%d1"), d2 asm ("%d2"), d3 asm ("%d3");
  register long d4 asm ("%d4"), d5 asm ("%d5");
  va_list args;

  va_start (args, number);
  d1 = va_arg (args, int);
  d2 = va_arg (args, int);
  d3 = va_arg (args, int);
  d4 = va_arg (args, int);
  d5 = va_arg (args, int);
  va_end (args);
  __asm__ volatile ("trap  #0\n\t"
		    : "=g" (res)
		    : "0" (number), "g" (d1), "g" (d2), "g" (d3), "g" (d4),
		      "g" (d5)
		    : "%d0");
  return res;
}

#else /* PTHREAD_KERNEL */

/* No weak syscall?.  */
#undef _POSIX_THREADS

#ifdef _POSIX_THREADS
#pragma weak syscall
#endif

int
syscall(int number, ...)
{
	long res;
	register long d0 asm("%d0");
	register long d1 asm("%d1"), d2 asm("%d2"), d3 asm("%d3"),
		      d4 asm("%d4"), d5 asm("%d5");
	va_list args;

	va_start(args, number);
	d1 = va_arg(args, int);
	d2 = va_arg(args, int);
	d3 = va_arg(args, int);
	d4 = va_arg(args, int);
	d5 = va_arg(args, int);
	va_end(args);
	__asm__ volatile ("trap  #0\n\t"
		: "=g" (d0)
		: "0" (number), "g" (d1), "g" (d2), "g" (d3), "g" (d4),
                          "g" (d5)
		: "%d0");
	res = d0;
	if (res < 0) {
		errno = -res;
		res = -1;
	}
	return res;
}

#endif /* PTHREAD_KERNEL */
