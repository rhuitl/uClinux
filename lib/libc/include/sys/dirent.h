#ifdef _SYS_DIR_H
#error "Can't include both sys/dir.h and sys/dirent.h"
#define _SYS_DIRENT_H
#endif

#ifndef _SYS_DIRENT_H
#define _SYS_DIRENT_H

#include <features.h>

#include <limits.h>
#include <dirent.h>

#ifndef DIRSIZ
#define DIRSIZ NAME_MAX
#endif

__BEGIN_DECLS

extern int getdents __P((int __fildes, struct dirent *__buf,
			size_t __nbyte));
extern int __getdents __P((int __fildes, struct dirent *__buf,
			size_t __nbyte));

__END_DECLS

#endif
