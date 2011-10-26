#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

extern void * ___brk_addr;

extern int __init_brk (void);

void *
__sbrk(ptrdiff_t increment)
{
    if (__init_brk () == 0)
    {
	register void * tmp asm ("%d1") = ___brk_addr+increment;
	__asm__ volatile ("movel %1,%/d0\n\t"
			  "trap  #0\n\t"
			  "movel %/d0,%0"
		:"=g" (___brk_addr)
		:"i" (SYS_brk),"g" (tmp) : "%d0");
	if (___brk_addr == tmp)
		return tmp-increment;
	errno = ENOMEM;
    }
    return ((void *) -1);
}

#include <gnu-stabs.h>
#ifdef weak_alias
weak_alias (__sbrk, sbrk);
#endif
