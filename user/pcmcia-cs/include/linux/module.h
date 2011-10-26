#ifndef _COMPAT_MODULE_H
#define _COMPAT_MODULE_H

#include <linux/version.h>
#include_next <linux/module.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,1,18))
#define MODULE_PARM(a,b)	extern int __bogus_decl
#define MODULE_AUTHOR(a)	extern int __bogus_decl
#define MODULE_DESCRIPTION(a)	extern int __bogus_decl
#define MODULE_SUPPORTED_DEVICE(a) extern int __bogus_decl
#undef  GET_USE_COUNT
#define GET_USE_COUNT(m)	mod_use_count_
#endif

#endif /* _COMPAT_MODULE_H */
