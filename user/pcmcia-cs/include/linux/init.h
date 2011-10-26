#ifndef _COMPAT_INIT_H
#define _COMPAT_INIT_H

#include <linux/version.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,3,0)) && defined(MODULE)
#define __init
#define __initdata
#define __exit
#define __exitdata
#define module_init(x) int init_module(void) { return x(); }
#define module_exit(x) void cleanup_module(void) { x(); }
#else
#include_next <linux/init.h>
#endif

#endif /* _COMPAT_INIT_H */
