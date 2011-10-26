#ifndef _COMPAT_PM_H
#define _COMPAT_PM_H

#include <linux/version.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,3,43))

#include <linux/apm_bios.h>

/* This is an ugly hack: it only works in case statements */
#define PM_SUSPEND		APM_SYS_SUSPEND: case APM_USER_SUSPEND
#define PM_RESUME		APM_NORMAL_RESUME: case APM_CRITICAL_RESUME

#define pm_register(a, b, fn)	apm_register_callback(fn)
#define pm_unregister_all(fn)	apm_unregister_callback(fn)

#else

#include_next <linux/pm.h>

#endif

#endif /* _COMPAT_PM_H */
