
/* Copyright (C) 2000 Lineo Australia */

#include <unistd.h>
#include <errno.h>

extern void *__curbrk;
extern int __init_brk(void);

void *
sbrk(ptrdiff_t increment)
{
    if (__init_brk() == 0) {
		register void *tmp = __curbrk + increment;
		if (brk(tmp) == 0 && __curbrk == tmp)
			return(tmp - increment);
		errno = ENOMEM;
    }
    return((void *) -1);
}

