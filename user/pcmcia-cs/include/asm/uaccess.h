#ifndef _PCMCIA_UACCESS_H
#define _PCMCIA_UACCESS_H

#include <linux/version.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,1,0))
#include <linux/mm.h>
static inline u_long copy_from_user(void *to, const void *from, u_long n)
{
    int i;
    if ((i = verify_area(VERIFY_READ, from, n)) != 0)
	return i;
    memcpy_fromfs(to, from, n);
    return 0;
}
static inline u_long copy_to_user(void *to, const void *from, u_long n)
{
    int i;
    if ((i = verify_area(VERIFY_WRITE, to, n)) != 0)
	return i;
    memcpy_tofs(to, from, n);
    return 0;
}

#if (!defined(__alpha__) || (LINUX_VERSION_CODE < KERNEL_VERSION(2,0,34)))
#define ioremap(a,b) \
    (((a) < 0x100000) ? (void *)((u_long)(a)) : vremap(a,b))
#define iounmap(v) \
    do { if ((u_long)(v) > 0x100000) vfree(v); } while (0)
#endif
/* This is evil... throw away the built-in get_user in 2.0 */
#include <asm/segment.h>
#undef get_user

#ifdef __alpha__
#define get_user(x, ptr) 	((x) = __get_user((ptr), sizeof(*(ptr))))
#undef get_fs_long
#undef put_fs_long
#define get_fs_long(ptr)	__get_user((ptr), sizeof(int))
#define put_fs_long(x, ptr)	__put_user((x), (ptr), sizeof(int))
#else
#define get_user(x, ptr) \
		((sizeof(*ptr) == 4) ? (x = get_fs_long(ptr)) : \
		 (sizeof(*ptr) == 2) ? (x = get_fs_word(ptr)) : \
		 (x = get_fs_byte(ptr)))
#endif

#else /* 2.1.X */
#include_next <asm/uaccess.h>
#endif

#endif /* _PCMCIA_UACCESS_H */
