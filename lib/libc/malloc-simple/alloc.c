#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>

#undef ABSOLUTELY_SAFE_MALLOC
#if 0
#define ABSOLUTELY_SAFE_MALLOC 1
#endif

#ifdef L_calloc_dbg

void *
calloc_dbg(size_t num, size_t size, char * function, char * file, int line)
{
	void * ptr;
	fprintf(stderr, "calloc of %d bytes at %s @%s:%d = ", num*size, function, file, line);
	ptr = calloc(num,size);
	fprintf(stderr, "%p\n", ptr);
	return ptr;
}

#endif

#ifdef L_malloc_dbg

void *
malloc_dbg(size_t len, char * function, char * file, int line)
{
	void * result;
	fprintf(stderr, "malloc of %d bytes at %s @%s:%d = ", len, function, file, line);
	result = malloc(len);
	fprintf(stderr, "%p\n", result);    
	return result;
}

#endif

#ifdef L_free_dbg

void
free_dbg(void * ptr, char * function, char * file, int line)
{
	fprintf(stderr, "free of %p at %s @%s:%d\n", ptr, function, file, line);
  	free(ptr);
}

#endif


#ifdef L_calloc

void *
calloc(size_t num, size_t size)
{
	void * ptr = malloc(num*size);
	if (ptr)
		memset(ptr, 0, num*size);
	return ptr;
}

#endif

#ifdef L_malloc

void *
malloc(size_t len)
{
#ifdef ABSOLUTELY_SAFE_MALLOC
  void * result = mmap((void *)0, len + sizeof(size_t), PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS, 0, 0);
  if (result == (void*)-1)
    return 0;
    
  * (size_t *) result = len;
  return result + 4;
#else
  void * result = mmap((void *)0, len, PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS, 0, 0);
  if (result == (void*)-1)
    return 0;
    
  return result;
#endif
}

#endif

#ifdef L_free

void
free(void * ptr)
{
#ifdef ABSOLUTELY_SAFE_MALLOC
  size_t s = * (size_t *) (ptr - 4);
  munmap(ptr - 4, s + sizeof(size_t));
#else
  munmap(ptr, 0);
#endif
}

#endif

#ifdef L_realloc

void *
realloc(void * ptr, size_t size)
{
	void * newptr = NULL;

	if (size > 0) {
		newptr = malloc(size);
		if (newptr && ptr)
#ifdef ABSOLUTELY_SAFE_MALLOC
			{
			size_t old = * (size_t *) (ptr - 4);
			memcpy(newptr, ptr, old < size ? old : size);
			}
#else
			memcpy(newptr, ptr, size);
#endif
	}
	if (ptr)
		free(ptr);
	return newptr;
}

#endif
