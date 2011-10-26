#include <stddef.h>
#include <sys/bitypes.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= 0x020100
#undef __STRICT_ANSI__
#endif
#include <linux/types.h>
#include <gnu/types.h>

/* For user space we always use 16bit dev_t type */
#define	dev_t	__dev_t
