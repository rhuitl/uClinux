
#ifndef __STRING_H
#define __STRING_H
#include <features.h>
#include <sys/types.h>
#include <stddef.h>

__BEGIN_DECLS

/* Basic string functions */
extern size_t strlen __P ((__const char* __str));

extern char * strcat __P ((char*, __const char*));
extern char * strcpy __P ((char*, __const char*));
extern char * stpcpy __P ((char*, __const char*));
extern int strcmp __P ((__const char*, __const char*));

extern char * strncat __P ((char*, __const char*, size_t));
extern char * strncpy __P ((char*, __const char*, size_t));
extern int strncmp __P ((__const char*, __const char*, size_t));

extern char * strchr __P ((__const char*, int));
extern char * strrchr __P ((__const char*, int));
extern char * strdup __P ((__const char*));
extern char * strndup __P ((__const char*, size_t));

/* Basic mem functions */
extern void * memcpy __P ((void*, __const void*, size_t));
extern void * memccpy __P ((void*, __const void*, int, size_t));
extern void * memchr __P ((__const void*, __const int, size_t));
extern void * memset __P ((void*, int, size_t));
extern int memcmp __P ((__const void*, __const void*, size_t));

#ifndef bcopy
#define bcopy(s, d, n)	memmove((d), (s), (n))
#endif

extern void * memmove __P ((void*, const void*, size_t));

/* Minimal (very!) locale support */

#ifndef L_strcoll /* protect the library code */
static __inline int strcoll(__const char *s1, __const char *s2)
{
	return(strcmp(s1, s2));
}
#endif

#ifndef L_strxfrm /* protect the library code */
static __inline size_t strxfrm(char *dest, __const char *src, size_t n) 
{
	strncpy(dest, src, n);
	return(n);
}
#endif

/* BSDisms */
#ifndef L_index /* protect the library code */
static __inline char *index(__const char *s, int c) { return(strchr(s, c)); }
#endif
#ifndef L_rindex /* protect the library code */
static __inline char *rindex(__const char *s, int c) { return(strrchr(s, c)); }
#endif


/* Other common BSD functions */
extern int strcasecmp __P ((__const char*, __const char*));
extern int strncasecmp __P ((__const char*, __const char*, size_t));
char *strpbrk __P ((__const char *, __const char *));
char *strsep __P ((char **, __const char *));
char *strstr __P ((__const char *, __const char *));
char *strcasestr __P ((__const char *, __const char *));
char *strtok __P ((char *, __const char *));
char *strtok_r __P ((char *, __const char *, char **));
size_t strspn __P ((__const char *, __const char *));
size_t strcspn __P ((__const char *, __const char *));

/* More BSD compatabilty */
extern void bzero(void *s, int n);
#ifndef L_bcmp /* protect the library code */
static __inline int bcmp(__const void *s1, __const void *s2, int n)
{
	return(memcmp(s1, s2, n));
}
#endif

/* Linux silly hour */
char *strfry __P ((char *));

__END_DECLS

#endif
