#include <fcntl.h>
#include <errno.h>
#include <sys/syscall.h>
#include <stdarg.h>

int
__fcntl(int fildes, int cmd, ...)
{
	int res;
	register int d0 asm ("%d0");
	va_list arg;

	va_start(arg,cmd);
	__asm__("movel %2,%/d1\n\t"
                "movel %3,%/d2\n\t"
                "movel %4,%/d3\n\t"
                "trap #0\n\t"
		:"=g" (d0)
		:"0" (SYS_fcntl),"g" (fildes),"g" (cmd), "d" (va_arg(arg,int))
                : "%d0", "%d1", "%d2", "%d3");
	res = d0;
	if (res>=0)
		return res;
	errno = -res;
	va_end (arg);
	return -1;
} /*  */
