#ifndef _COMPAT_PROC_FS_H
#define _COMPAT_PROC_FS_H

#include <linux/version.h>
#include_next <linux/proc_fs.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,1,0))

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,3,25))
extern inline struct proc_dir_entry *
create_proc_read_entry(const char *name, mode_t mode,
		       struct proc_dir_entry *base,
		       read_proc_t *read_proc, void *data)
{
    struct proc_dir_entry *res = create_proc_entry(name, mode, base);
    if (res) {
	res->read_proc = read_proc;
	res->data = data;
    }
    return res;
}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,3,29))
#ifndef proc_mkdir
#define proc_mkdir(name, root) create_proc_entry(name, S_IFDIR, root)
#endif
#endif

#endif

#endif /* _COMPAT_PROC_FS_H */
