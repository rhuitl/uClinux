/*
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/*libc_hidden_proto(nanosleep) need the reloc for cancellation*/

int usleep (__useconds_t usec)
{
    const struct timespec ts = {
	.tv_sec = (long int) (usec / 1000000),
	.tv_nsec = (long int) (usec % 1000000) * 1000ul
    };
    return(nanosleep(&ts, NULL));
}
