#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <gnu-stabs.h>

void *___brk_addr = 0;

int
__init_brk (void)
{
  if (___brk_addr == 0)
    {
      register void *tmp asm ("%d1") = 0;
      __asm__ volatile ("movel %1,%/d0\n\t"
			"trap #0\n\t"
			"movel %/d0,%0"
			: "=g" (___brk_addr)
			: "i" (SYS_brk), "g" (tmp)
			: "%d0");
      if (___brk_addr == 0)
	{
	  errno = ENOMEM;
	  return -1;
	}
    }
  return 0;
}

weak_alias (___brk_addr, __curbrk);
