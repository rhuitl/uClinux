/*
 * Copyright 1997-2000 by Pawel Krawczyk <kravietz@ceti.pl>
 *
 * See http://www.ceti.com.pl/~kravietz/progs/tacacs.html
 * for details.
 *
 * xalloc.c  Failsafe memory allocation functions.
 *           Taken from excellent glibc.info ;)
 */

#include <syslog.h>
#include <stdlib.h>

void *xcalloc(size_t nmemb, size_t size) {
	register void *val = calloc(nmemb, size);
	if(val == 0) {
		syslog(LOG_ERR, "%s: calloc(%u,%u) failed", __FUNCTION__, 
			(unsigned)nmemb, (unsigned)size);
		exit(1);
	}
	return val;
}

void *xrealloc(void *ptr, size_t size) {
	register void *val = realloc(ptr, size);
	if(val == 0) {
		syslog(LOG_ERR, "%s: realloc(%u) failed", __FUNCTION__, (unsigned)size);
		exit(1);
	}
	return val;
}
