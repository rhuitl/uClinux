/*
**  util.h
*/
#ifndef __UTIL_H__
#define __UTIL_H__

#ifdef WIN32

#define snprintf _snprintf

#else

#include <sys/types.h>

#endif


void *xmalloc(size_t byteSize);
char *xstrdup(const char *str);
void  xshowmem();
void  xfree( void * );

#endif
