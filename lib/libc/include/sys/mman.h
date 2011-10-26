#ifndef _SYS_MMAN_H
#define _SYS_MMAN_H

#include <features.h>
#include <sys/types.h>

#define PROT_READ	0x1	/* Page can be read.  */
#define PROT_WRITE	0x2	/* Page can be written.  */
#define PROT_EXEC	0x4	/* Page can be executed.  */
#define PROT_NONE	0x0	/* Page can not be accessed.  */

#define MAP_FILE	0x00	/* The 'normal' way: mapped from file */
#define MAP_SHARED	0x01	/* Share changes.  */
#define MAP_PRIVATE	0x02	/* Changes are private. */
#define MAP_ANONYMOUS	0x20	/* Don't use a file.  */
#define MAP_ANON	MAP_ANONYMOUS	   /* idem */

#ifndef MAP_FAILED
#define MAP_FAILED ((void *)-1)
#endif	/* MAP_FAILED */

__BEGIN_DECLS

extern __ptr_t mmap __P((__ptr_t __addr, size_t __len,
		int __prot, int __flags, int __fd, off_t __off));
extern int munmap __P((__ptr_t __addr, size_t __len));
extern int mprotect __P ((__const __ptr_t __addr, size_t __len, int __prot));

extern int msync __P((__ptr_t __addr, size_t __len, int __flags));

extern int mlock __P((__const __ptr_t __addr, size_t __len));
extern int munlock __P((__const __ptr_t __addr, size_t __len));

extern int mlockall __P((int __flags));
extern int munlockall __P((void));

extern __ptr_t mremap __P((__ptr_t __addr, size_t __old_len,
		size_t __new_len, int __may_move));

__END_DECLS

#endif /* _SYS_MMAN_H */
