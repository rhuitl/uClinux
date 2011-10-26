#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

extern void * ___brk_addr;

extern int __init_brk (void);

int __brk(void * end_data_seg)
{
    if (__init_brk () == 0)
    {
	__asm__ volatile ("movel %2,%/d1\n\t"
			  "moveq %1,%/d0\n\t"
			  "trap  #0\n\t"
			  "movel %/d0,%0"
		:"=g" (___brk_addr)
		:"i" (SYS_brk),"g" (end_data_seg) : "%d0", "%d1");
	if (___brk_addr == end_data_seg)
		return 0;
	errno = ENOMEM;
    }
    return -1;
}

#include <gnu-stabs.h>
#ifdef weak_alias
weak_alias (__brk, brk);
#endif
