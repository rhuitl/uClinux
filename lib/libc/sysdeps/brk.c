
/* Copyright (C) 2000 Lineo Australia */

#include <syscall.h>
#include <sys/types.h>
#include <errno.h>
#include <linux/linkage.h>

extern asmlinkage _brk(void *);

void *__curbrk = 0;

int
__init_brk (void)
{
	if (__curbrk == 0) {
		__curbrk = (void *) _brk(0);
		if (__curbrk == (void *) 0) {
			errno = ENOMEM;
			return -1;
		}
    }
	return 0;
}

int
brk(void *end_data_segment)
{
    if (__init_brk() == 0) {
		__curbrk = (void *) _brk(end_data_segment);
		if (__curbrk == end_data_segment)
			return(0);
		errno = ENOMEM;
    }
    return(-1);
}

